//! CI/test-only identity provider (`mock-provider` feature, or this crate's
//! own unit tests). It runs the real loopback PKCE flow against a local
//! fixture issuer (`anvil_fixtures::idp`), redeems the code through the
//! engine transport and reads the subject from the issuer's userinfo
//! endpoint with the fresh access token.
//!
//! It refuses any non-loopback endpoint, so even an accidentally enabled
//! feature cannot turn it into a production login.

use crate::flow::{AuthorizationRequest, authorize_in_browser};
use crate::provider::{Availability, IdentityProvider, ProviderInfo, VerifiedIdentity};
use crate::{BrowserOpener, FlowError, FlowEvent, FlowObserver, FlowOptions, failed, require_secure_endpoint};
use anvil_auth::oauth::{BoxFut, OAuthResolved, exchange_code};
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, OAuthGrant};
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_engine::context::MemorySecrets;
use anvil_engine::oauth_http::EngineTokenHttp;
use anvil_engine::{Engine, ExecutionContext};
use anvil_transport::recorder::EventCtx;
use chrono::Utc;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub const MOCK_PROVIDER_ID: &str = "mock";

#[derive(Debug, Clone)]
pub struct MockProviderConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub scope: String,
}

pub struct MockProvider {
    cfg: MockProviderConfig,
    engine: Engine,
}

fn loopback_only(label: &str, raw: &str) -> Result<(), FlowError> {
    let u = require_secure_endpoint(label, raw)?;
    let loopback = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if loopback {
        Ok(())
    } else {
        Err(FlowError::Configuration(format!("the mock provider only talks to a loopback test issuer; {label} is not local")))
    }
}

impl MockProvider {
    pub fn new(cfg: MockProviderConfig) -> Result<MockProvider, FlowError> {
        loopback_only("the authorization URL", &cfg.authorization_endpoint)?;
        loopback_only("the token URL", &cfg.token_endpoint)?;
        loopback_only("the userinfo URL", &cfg.userinfo_endpoint)?;
        Ok(MockProvider { cfg, engine: Engine::new() })
    }

    async fn run(
        &self,
        opener: &dyn BrowserOpener,
        observer: &dyn FlowObserver,
        opts: &FlowOptions,
        cancel: &CancellationToken,
    ) -> Result<VerifiedIdentity, FlowError> {
        let req = AuthorizationRequest {
            authorization_endpoint: &self.cfg.authorization_endpoint,
            client_id: &self.cfg.client_id,
            scope: &self.cfg.scope,
        };
        // Failures of the browser part are reported by `authorize_in_browser`.
        let grant = authorize_in_browser(&req, opener, observer, opts, cancel).await?;
        match self.redeem_and_verify(grant, observer, cancel).await {
            Ok(id) => {
                observer.event(FlowEvent::Completed);
                Ok(id)
            }
            Err(e) => Err(failed(observer, e)),
        }
    }

    async fn redeem_and_verify(
        &self,
        grant: crate::flow::AuthorizationCode,
        observer: &dyn FlowObserver,
        cancel: &CancellationToken,
    ) -> Result<VerifiedIdentity, FlowError> {
        observer.event(FlowEvent::ExchangingCode);
        let ctx = ExecutionContext::standalone(RequestSpec::http("POST", &self.cfg.token_endpoint));
        let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
        let http = EngineTokenHttp { engine: &self.engine, ctx: &ctx, settings: &settings, cancel };
        let resolved = OAuthResolved {
            grant: OAuthGrant::AuthorizationCodePkce,
            token_url: self.cfg.token_endpoint.clone(),
            client_id: self.cfg.client_id.clone(),
            client_secret: Zeroizing::new(String::new()),
            scope: self.cfg.scope.clone(),
            audience: String::new(),
            basic_client_auth: false,
            token_cache_id: None,
            refresh_skew_secs: 30,
        };
        let token = tokio::select! {
            r = exchange_code(&resolved, &grant.code, &grant.verifier, &grant.redirect_uri, &http) => {
                r.map_err(|e| FlowError::Exchange(e.to_string()))?
            }
            _ = cancel.cancelled() => return Err(FlowError::Canceled),
        };
        drop(grant);

        observer.event(FlowEvent::VerifyingIdentity);
        // The access token travels only as an in-memory secret reference, so
        // the engine redacts it from the execution record.
        let secret = SecretRef { id: Id::new(), label: "mock userinfo token".into() };
        let mut spec = RequestSpec::http("GET", &self.cfg.userinfo_endpoint);
        spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: secret.clone() }, prefix: "Bearer".into() };
        let mut ctx = ExecutionContext::standalone(spec);
        ctx.secrets = Arc::new(MemorySecrets([(secret.id, token.access_token.clone())].into_iter().collect()));
        let out = self.engine.execute(&ctx, EventCtx::none(), cancel.clone()).await;
        drop(token);
        if cancel.is_cancelled() {
            return Err(FlowError::Canceled);
        }
        let status = out.record.response.as_ref().map(|r| r.status);
        if status != Some(200) {
            return Err(FlowError::Verification(match status {
                Some(s) => format!("the userinfo endpoint answered HTTP {s}"),
                None => "the userinfo endpoint could not be reached".into(),
            }));
        }
        let body = out.decoded_body.as_ref().unwrap_or(&out.body);
        let v: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| FlowError::Verification("the userinfo response is not JSON".into()))?;
        let sub = v.get("sub").and_then(|s| s.as_str()).filter(|s| !s.is_empty() && s.len() <= 255 && !s.chars().any(char::is_control));
        let Some(sub) = sub else {
            return Err(FlowError::Verification("the userinfo response has no usable subject".into()));
        };
        let email = v.get("email").and_then(|e| e.as_str()).filter(|e| e.len() <= 320).map(str::to_string);
        Ok(VerifiedIdentity::new(MOCK_PROVIDER_ID, sub.to_string(), email, Utc::now()))
    }
}

impl IdentityProvider for MockProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: MOCK_PROVIDER_ID,
            display_name: "Mock issuer (CI only)",
            availability: Availability::Available,
            native_flow: "Authorization code + PKCE against a local fixture issuer; subject from its userinfo endpoint.",
            owner_actions: vec![],
            needs_broker: false,
            test_only: true,
        }
    }

    fn authenticate<'a>(
        &'a self,
        opener: &'a dyn BrowserOpener,
        observer: &'a dyn FlowObserver,
        opts: &'a FlowOptions,
        cancel: &'a CancellationToken,
    ) -> BoxFut<'a, Result<VerifiedIdentity, FlowError>> {
        Box::pin(self.run(opener, observer, opts, cancel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_fixtures::idp::{AuthorizeBehavior, IdpFixture, IdpOptions, simulate_browser};
    use std::sync::Mutex;

    fn cfg(idp: &IdpFixture) -> MockProviderConfig {
        MockProviderConfig {
            authorization_endpoint: idp.authorization_endpoint(),
            token_endpoint: idp.token_endpoint(),
            userinfo_endpoint: idp.userinfo_endpoint(),
            client_id: idp.client_id(),
            scope: "openid email".into(),
        }
    }

    fn browser() -> impl Fn(&str) -> Result<(), String> + Send + Sync {
        |url: &str| {
            let url = url.to_string();
            tokio::spawn(async move {
                let _ = simulate_browser(&url, None).await;
            });
            Ok(())
        }
    }

    #[tokio::test]
    async fn mock_provider_runs_a_real_loopback_flow_and_verifies_the_subject() {
        let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
        let p = MockProvider::new(cfg(&idp)).unwrap();
        assert!(p.info().test_only);
        let events = Mutex::new(vec![]);
        let observer = |e: FlowEvent| events.lock().unwrap().push(e);
        let id = p.authenticate(&browser(), &observer, &FlowOptions::default(), &CancellationToken::new()).await.unwrap();
        assert_eq!(id.provider(), "mock");
        assert_eq!(id.subject(), "fixture-user-1");
        assert_eq!(id.email(), Some("fixture-user-1@idp.anvil.test"));
        assert!((Utc::now() - id.authenticated_at()).num_seconds() < 5);
        assert_eq!(idp.grants_seen(), vec!["authorization_code".to_string()]);
        let ev = events.lock().unwrap().clone();
        assert!(matches!(ev.last(), Some(FlowEvent::Completed)), "{ev:?}");
        assert!(ev.contains(&FlowEvent::VerifyingIdentity));
    }

    #[tokio::test]
    async fn mock_provider_denied_and_non_loopback_config() {
        let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
        idp.set_behavior(AuthorizeBehavior::Deny);
        let p = MockProvider::new(cfg(&idp)).unwrap();
        let r = p.authenticate(&browser(), &crate::NoEvents, &FlowOptions::default(), &CancellationToken::new()).await;
        assert!(matches!(&r, Err(FlowError::AuthorizationDenied(c)) if c == "access_denied"), "{r:?}");
        assert!(idp.grants_seen().is_empty(), "no exchange after a denial");

        let mut remote = cfg(&idp);
        remote.token_endpoint = "https://issuer.example/token".into();
        assert!(matches!(MockProvider::new(remote), Err(FlowError::Configuration(_))));
    }
}
