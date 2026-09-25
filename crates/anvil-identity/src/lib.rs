//! Interactive identity flows for Ferrum Anvil.
//!
//! Anvil keeps three identities apart (build plan §8.1, docs/identity.md):
//!
//! 1. **Application identity** — who may unlock Anvil. A linked provider
//!    account ([`provider`]) is an *additional* policy check; it never
//!    derives, wraps or replaces the vault key.
//! 2. **Target-API identity** — the OAuth token Anvil presents to an API.
//!    [`api_oauth::authorize_api`] runs the native-app authorization-code +
//!    PKCE flow (RFC 8252 loopback redirect, RFC 7636 S256) and caches the
//!    token in the engine under the key every send uses.
//! 3. **Gateway-to-backend identity** — not Anvil's to change.
//!
//! This crate does not depend on Tauri: the desktop passes a
//! [`BrowserOpener`] (tauri-plugin-opener, `open`, …) and a [`FlowObserver`]
//! for progress events. Codes, verifiers and tokens are never logged, never
//! part of an event, and are zeroized on drop.
//!
//! Why a separate crate: `anvil-auth` is pure credential generation with no
//! sockets and is a dependency *of* `anvil-engine`; the loopback listener
//! needs a server and the code exchange must go through the engine transport,
//! so it cannot live in `anvil-auth` without a dependency cycle.

pub mod api_oauth;
pub mod flow;
mod loopback;
#[cfg(any(test, feature = "mock-provider"))]
pub mod mock;
pub mod provider;

use serde::Serialize;
use std::time::Duration;

pub use api_oauth::{ApiAuthorization, authorize_api};
pub use flow::{AuthorizationCode, AuthorizationRequest, authorize_in_browser};
pub use provider::{Availability, IdentityProvider, IdentitySummary, ProviderInfo, VerifiedIdentity, builtin_providers, find_provider};

/// Whether the CI-only mock provider is compiled into this build. Release
/// checks assert this is `false`.
pub const MOCK_PROVIDER_COMPILED: bool = cfg!(feature = "mock-provider");

/// Launches the system browser at the authorization URL.
///
/// Implementations must return as soon as the browser was asked to open and
/// must not wait for the user (the loopback listener is only polled after
/// this returns). A failure does not end the flow: the URL is reported in
/// [`FlowEvent::BrowserOpenFailed`] so the user can open it by hand, and the
/// attempt keeps waiting until its timeout or cancellation.
pub trait BrowserOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<(), String>;
}

impl<F> BrowserOpener for F
where
    F: Fn(&str) -> Result<(), String> + Send + Sync,
{
    fn open(&self, url: &str) -> Result<(), String> {
        self(url)
    }
}

/// Receives progress events (e.g. forwarded to the webview as Tauri events).
pub trait FlowObserver: Send + Sync {
    fn event(&self, event: FlowEvent);
}

impl<F> FlowObserver for F
where
    F: Fn(FlowEvent) + Send + Sync,
{
    fn event(&self, event: FlowEvent) {
        self(event)
    }
}

/// Observer that drops every event.
pub struct NoEvents;

impl FlowObserver for NoEvents {
    fn event(&self, _: FlowEvent) {}
}

/// Progress of one interactive authorization attempt. Contains no code,
/// verifier or token — safe to forward to the UI and to logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FlowEvent {
    /// The loopback listener is bound (`http://127.0.0.1:<port>/<path>`).
    ListenerReady {
        redirect_uri: String,
    },
    /// The opener accepted the authorization URL.
    BrowserOpened {
        authorization_url: String,
    },
    /// The opener failed; show `authorization_url` for manual opening.
    BrowserOpenFailed {
        authorization_url: String,
        error: String,
    },
    /// A request reached the listener but was not this attempt's callback.
    CallbackIgnored {
        reason: String,
    },
    /// The bound callback arrived with a matching `state`.
    CallbackAccepted,
    /// Redeeming the code at the token endpoint.
    ExchangingCode,
    /// Verifying the provider identity (application login only).
    VerifyingIdentity,
    Completed,
    Failed {
        kind: FlowErrorKind,
        message: String,
    },
}

/// Per-attempt options.
#[derive(Debug, Clone)]
pub struct FlowOptions {
    /// How long to wait for the browser callback (default 5 minutes).
    pub timeout: Duration,
    /// Loopback callback path (default `/callback`). The port is always
    /// ephemeral; the authorization server must accept any loopback port
    /// (RFC 8252 §7.3).
    pub callback_path: String,
}

impl Default for FlowOptions {
    fn default() -> Self {
        FlowOptions { timeout: Duration::from_secs(300), callback_path: "/callback".into() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowErrorKind {
    Canceled,
    TimedOut,
    CallbackRejected,
    AuthorizationDenied,
    Configuration,
    Listener,
    Exchange,
    ProviderUnavailable,
    Verification,
}

/// Why an interactive attempt ended without a token/identity.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlowError {
    #[error("sign-in was canceled")]
    Canceled,
    #[error("no sign-in response arrived within {} seconds", .0.as_secs())]
    TimedOut(Duration),
    /// The bound callback failed validation (state mismatch, repeated
    /// parameters, missing code). No token exchange was performed.
    #[error("{0}")]
    CallbackRejected(String),
    /// The authorization server answered with an OAuth error (e.g. `access_denied`).
    #[error("the authorization server did not grant access: {0}")]
    AuthorizationDenied(String),
    #[error("{0}")]
    Configuration(String),
    #[error("could not start the loopback listener: {0}")]
    Listener(String),
    #[error("the authorization code could not be redeemed: {0}")]
    Exchange(String),
    #[error("{provider} sign-in is not available in this build: {reason}")]
    ProviderUnavailable { provider: String, reason: String },
    #[error("the provider identity could not be verified: {0}")]
    Verification(String),
}

impl FlowError {
    pub fn kind(&self) -> FlowErrorKind {
        match self {
            FlowError::Canceled => FlowErrorKind::Canceled,
            FlowError::TimedOut(_) => FlowErrorKind::TimedOut,
            FlowError::CallbackRejected(_) => FlowErrorKind::CallbackRejected,
            FlowError::AuthorizationDenied(_) => FlowErrorKind::AuthorizationDenied,
            FlowError::Configuration(_) => FlowErrorKind::Configuration,
            FlowError::Listener(_) => FlowErrorKind::Listener,
            FlowError::Exchange(_) => FlowErrorKind::Exchange,
            FlowError::ProviderUnavailable { .. } => FlowErrorKind::ProviderUnavailable,
            FlowError::Verification(_) => FlowErrorKind::Verification,
        }
    }
}

/// Report a terminal failure to the observer and hand the error back.
pub(crate) fn failed(observer: &dyn FlowObserver, e: FlowError) -> FlowError {
    observer.event(FlowEvent::Failed { kind: e.kind(), message: e.to_string() });
    e
}

/// Interactive flows only talk to `https` issuers, except loopback test
/// issuers over `http`. Codes and verifiers never cross a network in clear.
pub(crate) fn require_secure_endpoint(label: &str, raw: &str) -> Result<url::Url, FlowError> {
    let u = url::Url::parse(raw).map_err(|e| FlowError::Configuration(format!("{label} is not a valid URL: {e}")))?;
    let loopback = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    match u.scheme() {
        "https" => Ok(u),
        "http" if loopback => Ok(u),
        "http" => Err(FlowError::Configuration(format!(
            "{label} must use https for a browser sign-in (plain http is accepted only for a loopback test issuer)"
        ))),
        other => Err(FlowError::Configuration(format!("{label} has unsupported scheme '{other}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_endpoint_policy() {
        assert!(require_secure_endpoint("x", "https://issuer.example/authorize").is_ok());
        assert!(require_secure_endpoint("x", "http://127.0.0.1:9/authorize").is_ok());
        assert!(require_secure_endpoint("x", "http://localhost:9/authorize").is_ok());
        assert!(require_secure_endpoint("x", "http://[::1]:9/authorize").is_ok());
        assert!(require_secure_endpoint("x", "http://issuer.example/authorize").is_err());
        assert!(require_secure_endpoint("x", "javascript:alert(1)").is_err());
    }

    #[test]
    fn events_serialize_without_secrets() {
        let e = FlowEvent::Failed { kind: FlowErrorKind::TimedOut, message: FlowError::TimedOut(Duration::from_secs(300)).to_string() };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "failed");
        assert_eq!(v["kind"], "timed_out");
    }
}
