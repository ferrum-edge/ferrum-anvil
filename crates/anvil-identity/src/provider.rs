//! Application login providers (identity 1).
//!
//! A provider proves *who* is at the keyboard; it never unlocks data. The
//! vault key stays wrapped by the local passphrase / recovery key / OS
//! keychain, and a linked identity only adds an optional "fresh sign-in
//! required" policy on top (enforced in `anvil-app`).
//!
//! Google, GitHub and Facebook each need owner-registered applications
//! (client ids, redirect URIs) and — for GitHub and Facebook, whose code
//! exchange needs a client secret — a minimal broker that holds the secret
//! outside the desktop bundle. None of that exists in this build, so all
//! three report [`Availability::Unavailable`] and refuse to authenticate.
//! No client id, endpoint or issuer assertion is invented here.

use crate::{BrowserOpener, FlowError, FlowObserver, FlowOptions};
use anvil_auth::oauth::BoxFut;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

/// A provider identity verified by a provider flow moments ago.
///
/// Only provider implementations in this crate construct it; it is neither
/// `Clone` nor deserializable, so an IPC payload or UI state cannot forge
/// one and a single proof cannot be replayed into several unlocks.
pub struct VerifiedIdentity {
    provider: String,
    subject: String,
    email: Option<String>,
    authenticated_at: DateTime<Utc>,
}

impl VerifiedIdentity {
    #[cfg_attr(not(any(test, feature = "mock-provider")), allow(dead_code))]
    pub(crate) fn new(provider: &str, subject: String, email: Option<String>, authenticated_at: DateTime<Utc>) -> Self {
        VerifiedIdentity { provider: provider.to_string(), subject, email, authenticated_at }
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }
    /// The provider's stable subject identifier (not an e-mail address).
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    pub fn authenticated_at(&self) -> DateTime<Utc> {
        self.authenticated_at
    }
    pub fn summary(&self) -> IdentitySummary {
        IdentitySummary {
            provider: self.provider.clone(),
            subject: self.subject.clone(),
            email: self.email.clone(),
            authenticated_at: self.authenticated_at,
        }
    }
}

impl std::fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedIdentity")
            .field("provider", &self.provider)
            .field("subject", &self.subject)
            .field("authenticated_at", &self.authenticated_at)
            .finish_non_exhaustive()
    }
}

/// Displayable copy of a verified identity (carries no proof value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentitySummary {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub authenticated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable { reason: String },
}

/// The reason every real provider gives in this build.
pub const UNREGISTERED_REASON: &str = "requires registered OAuth client id / redirect URI / broker (owner action)";

#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    pub id: &'static str,
    pub display_name: &'static str,
    pub availability: Availability,
    /// How this provider authenticates a native desktop app.
    pub native_flow: &'static str,
    /// What the owner must register or deploy before it can be offered.
    pub owner_actions: Vec<&'static str>,
    /// A code-exchange secret exists, so a broker must hold it.
    pub needs_broker: bool,
    /// CI/test provider (never offered by release builds).
    pub test_only: bool,
}

pub trait IdentityProvider: Send + Sync {
    fn info(&self) -> ProviderInfo;

    /// Authenticate in the system browser and return the verified identity.
    fn authenticate<'a>(
        &'a self,
        opener: &'a dyn BrowserOpener,
        observer: &'a dyn FlowObserver,
        opts: &'a FlowOptions,
        cancel: &'a CancellationToken,
    ) -> BoxFut<'a, Result<VerifiedIdentity, FlowError>>;
}

/// Static description of a real provider's native-app requirements.
#[derive(Debug, Clone, Copy)]
pub struct ProviderSpec {
    pub id: &'static str,
    pub display_name: &'static str,
    pub native_flow: &'static str,
    pub owner_actions: &'static [&'static str],
    pub needs_broker: bool,
}

pub const GOOGLE: ProviderSpec = ProviderSpec {
    id: "google",
    display_name: "Google",
    native_flow: "OpenID Connect authorization code + PKCE in the system browser with a loopback IP redirect; \
                  the ID token must be verified (signature against Google's published keys, iss, aud = client id, exp, nonce).",
    owner_actions: &[
        "Create a Google Cloud OAuth client of type 'Desktop app' and configure the OAuth consent screen (openid, email).",
        "Decide where the desktop client's issued client secret lives (Google documents it as non-confidential for installed apps); \
         this build ships none — route the code exchange through the identity broker if it must stay off the device.",
        "Supply the client id to the build/deployment configuration; add ID-token verification and a real-account acceptance test.",
    ],
    needs_broker: false,
};

pub const GITHUB: ProviderSpec = ProviderSpec {
    id: "github",
    display_name: "GitHub",
    native_flow: "OAuth (not OpenID Connect): the web application flow's code exchange requires the client secret, \
                  so a desktop app needs a broker holding it, or the device flow enabled on the app; the account is then \
                  identified by the numeric user id from the authenticated user API.",
    owner_actions: &[
        "Register a GitHub OAuth App or GitHub App with the broker's callback URL (or enable the device flow).",
        "Deploy the minimal identity broker holding the client secret (never in the desktop bundle).",
        "Supply the client id and broker URL to the deployment configuration; add a real-account acceptance test.",
    ],
    needs_broker: true,
};

pub const FACEBOOK: ProviderSpec = ProviderSpec {
    id: "facebook",
    display_name: "Facebook",
    native_flow: "Facebook Login manual flow: the code exchange and token inspection need the app secret, so they run in a \
                  broker; the account is identified by the app-scoped user id.",
    owner_actions: &[
        "Create a Meta app with Facebook Login, register the exact redirect URI(s) and complete any required app review.",
        "Deploy the minimal identity broker holding the app secret (never in the desktop bundle).",
        "Supply the app id and broker URL to the deployment configuration; add a real-account acceptance test.",
    ],
    needs_broker: true,
};

/// A real provider without owner registrations: typed unavailability, no
/// network activity, no success-shaped fallback.
pub struct UnregisteredProvider(pub ProviderSpec);

impl IdentityProvider for UnregisteredProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: self.0.id,
            display_name: self.0.display_name,
            availability: Availability::Unavailable { reason: UNREGISTERED_REASON.into() },
            native_flow: self.0.native_flow,
            owner_actions: self.0.owner_actions.to_vec(),
            needs_broker: self.0.needs_broker,
            test_only: false,
        }
    }

    fn authenticate<'a>(
        &'a self,
        _opener: &'a dyn BrowserOpener,
        observer: &'a dyn FlowObserver,
        _opts: &'a FlowOptions,
        _cancel: &'a CancellationToken,
    ) -> BoxFut<'a, Result<VerifiedIdentity, FlowError>> {
        Box::pin(async move {
            Err(crate::failed(
                observer,
                FlowError::ProviderUnavailable { provider: self.0.display_name.into(), reason: UNREGISTERED_REASON.into() },
            ))
        })
    }
}

/// The application-login providers this build knows about (all unavailable
/// until the owner registrations exist). The CI mock provider is not listed:
/// it needs a fixture issuer and is constructed explicitly by tests.
pub fn builtin_providers() -> Vec<Box<dyn IdentityProvider>> {
    vec![Box::new(UnregisteredProvider(GOOGLE)), Box::new(UnregisteredProvider(GITHUB)), Box::new(UnregisteredProvider(FACEBOOK))]
}

pub fn find_provider(id: &str) -> Option<Box<dyn IdentityProvider>> {
    builtin_providers().into_iter().find(|p| p.info().id.eq_ignore_ascii_case(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn real_providers_are_typed_unavailable_and_never_open_a_browser() {
        let opened = AtomicU32::new(0);
        let opener = |_: &str| -> Result<(), String> {
            opened.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let events = Mutex::new(vec![]);
        let observer = |e: crate::FlowEvent| events.lock().unwrap().push(e);
        let ids: Vec<&str> = builtin_providers().iter().map(|p| p.info().id).collect();
        assert_eq!(ids, ["google", "github", "facebook"]);
        for p in builtin_providers() {
            let info = p.info();
            assert_eq!(info.availability, Availability::Unavailable { reason: UNREGISTERED_REASON.into() });
            assert!(!info.test_only && !info.owner_actions.is_empty());
            let r = p.authenticate(&opener, &observer, &FlowOptions::default(), &CancellationToken::new()).await;
            match r {
                Err(FlowError::ProviderUnavailable { provider, reason }) => {
                    assert_eq!(provider, info.display_name);
                    assert_eq!(reason, UNREGISTERED_REASON);
                }
                other => panic!("{} must be unavailable, got {other:?}", info.id),
            }
        }
        assert_eq!(opened.load(Ordering::SeqCst), 0, "no browser, no network");
        assert!(find_provider("GitHub").is_some() && find_provider("mock").is_none());
        let json = serde_json::to_value(find_provider("google").unwrap().info()).unwrap();
        assert_eq!(json["availability"]["status"], "unavailable");
        assert!(!json.to_string().contains("client_id\":\""), "no invented client ids");
    }
}
