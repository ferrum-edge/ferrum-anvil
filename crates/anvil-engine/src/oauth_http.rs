//! Token-endpoint HTTP for OAuth acquisition, using the same instrumented
//! transport and the workspace's trust and proxy settings (never a separate
//! client), plus the engine half of the interactive authorization-code + PKCE
//! flow: resolving the profile in effect, redeeming a code through this
//! transport and caching the token under the key the engine sends with.

use crate::Engine;
use crate::context::{ExecutionContext, resolve_sensitive};
use crate::prepare;
use crate::vars::Resolver;
use anvil_auth::AuthError;
use anvil_auth::oauth::{BoxFut, CachedToken, OAuthResolved, TokenHttp};
use anvil_domain::auth::{AuthConfig, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::execution::{AttemptReason, FailureKind, Phase, TransportFailure};
use anvil_domain::settings::{EffectiveSettings, HttpVersionPolicy};
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::HttpPlan;
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub struct EngineTokenHttp<'a> {
    pub engine: &'a Engine,
    pub ctx: &'a ExecutionContext,
    pub settings: &'a EffectiveSettings,
}

impl TokenHttp for EngineTokenHttp<'_> {
    fn post_form<'b>(
        &'b self,
        url: &'b str,
        form: Vec<(String, String)>,
        basic: Option<(String, String)>,
    ) -> BoxFut<'b, Result<(u16, Vec<u8>), String>> {
        Box::pin(async move {
            let mut inferred = vec![];
            let t = prepare::parse_target(url, &["https", "http"], &mut inferred).map_err(|e| e.message)?;
            let body: String = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form.iter()).finish();
            let mut headers = vec![
                (http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/x-www-form-urlencoded")),
                (http::header::ACCEPT, http::HeaderValue::from_static("application/json")),
            ];
            if let Some((u, p)) = basic {
                let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
                let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", enc(&u), enc(&p)));
                headers.push((
                    http::header::AUTHORIZATION,
                    http::HeaderValue::from_str(&format!("Basic {token}")).map_err(|e| e.to_string())?,
                ));
            }
            let tls = if t.scheme == "https" {
                let mut inf = vec![];
                Some(crate::http_exec::tls_for(self.engine, self.ctx, self.settings, &t, &mut inf).map_err(|e| e.message)?.0)
            } else {
                None
            };
            // The token endpoint uses the request's proxy profile (and its
            // NO_PROXY list), exactly like the API request would.
            let proxy = crate::http_exec::proxy_for(self.ctx, self.settings, &t, &mut inferred).map_err(|e| e.message)?;
            let plan = HttpPlan {
                method: http::Method::POST,
                https: t.scheme == "https",
                host: t.host.clone(),
                port: t.port,
                authority: t.authority.clone(),
                request_target: t.request_target(),
                headers,
                body: Bytes::from(body),
                version: HttpVersionPolicy::Auto,
                timeouts: self.settings.timeouts,
                limits: self.settings.limits,
                keepalive: true,
                dns: DnsConfig {
                    resolver: self.settings.resolver.clone(),
                    overrides: self.settings.dns_overrides.clone(),
                    ip_preference: self.settings.ip_preference,
                },
                proxy,
                tls,
                isolation: format!("{}|oauth", self.ctx.isolation),
                display_url: url.to_string(),
            };
            let mut outs = self.engine.http.execute(&plan, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
            let out = outs.pop().ok_or("no attempt")?;
            match (out.response, out.observation.failure) {
                (Some(r), None) => Ok((r.status, out.body.to_vec())),
                (_, Some(f)) => Err(format!("token endpoint {}: {:?} — {}", t.authority, f.kind, f.message)),
                (None, None) => Err("token endpoint returned no response".into()),
            }
        })
    }
}

/// Resolve an OAuth 2 profile's templates and secret references.
pub(crate) fn resolve_oauth(config: &OAuth2Config, ctx: &ExecutionContext, r: &Resolver) -> Result<OAuthResolved, TransportFailure> {
    let fail = |m: String| TransportFailure::new(Phase::Prepare, FailureKind::AuthPreparationFailed, m).with_field("auth");
    let (raw_secret, _) =
        resolve_sensitive(&config.client_secret, ctx.secrets.as_ref()).map_err(|e| fail(format!("auth.client_secret: {e}")))?;
    Ok(OAuthResolved {
        grant: config.grant,
        token_url: r.resolve(&config.token_url, "auth.token_url")?,
        client_id: r.resolve(&config.client_id, "auth.client_id")?,
        client_secret: Zeroizing::new(r.resolve(&raw_secret, "auth.client_secret")?),
        scope: r.resolve(&config.scope, "auth.scope")?,
        audience: r.resolve(&config.audience, "auth.audience")?,
        basic_client_auth: config.client_auth == OAuthClientAuth::BasicHeader,
        refresh_skew_secs: config.refresh_skew_secs as i64,
    })
}

/// Token-cache key: one token per workspace isolation, issuer, client and
/// scope. The interactive sign-in stores its token under this same key.
pub(crate) fn cache_key(ctx: &ExecutionContext, resolved: &OAuthResolved) -> String {
    format!("{}|{}|{}|{}", ctx.isolation, resolved.token_url, resolved.client_id, resolved.scope)
}

/// Typed local failure for a token that could not be obtained before sending.
pub(crate) fn acquisition_failure(cfg: &OAuthResolved, e: AuthError, not_sent: &str) -> TransportFailure {
    match e {
        AuthError::InteractionRequired(m) => {
            TransportFailure::new(Phase::Prepare, FailureKind::OAuthInteractionRequired, format!("{m} {not_sent}")).with_field("auth")
        }
        other => TransportFailure::new(
            Phase::Prepare,
            FailureKind::AuthPreparationFailed,
            format!("OAuth token acquisition from {} failed: {other}. {not_sent}", cfg.token_url),
        )
        .with_field("auth"),
    }
}

fn find_oauth(a: &AuthConfig) -> Option<&OAuth2Config> {
    match a {
        AuthConfig::OAuth2 { config } => Some(config),
        AuthConfig::Multi { profiles } => profiles.iter().find_map(find_oauth),
        _ => None,
    }
}

/// The OAuth 2 profile in effect for an execution context, resolved for an
/// interactive authorization-code + PKCE sign-in.
pub struct InteractiveOAuth {
    /// Where the auth profile was inherited from (`request`, `folder:<name>`, `workspace`).
    pub scope_label: String,
    pub grant: OAuthGrant,
    pub authorization_endpoint: String,
    pub token_url: String,
    pub client_id: String,
    pub scope: String,
    key: String,
    resolved: OAuthResolved,
    settings: EffectiveSettings,
}

impl InteractiveOAuth {
    /// The engine token-cache key (contains no secret).
    pub fn cache_key(&self) -> &str {
        &self.key
    }
}

/// Token metadata safe to show and log (never token values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenSummary {
    pub token_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub refresh_token_available: bool,
}

impl TokenSummary {
    fn of(t: &CachedToken) -> Self {
        TokenSummary { token_type: t.token_type.clone(), expires_at: t.expires_at, refresh_token_available: t.refresh_token.is_some() }
    }
}

/// Resolve the effective OAuth profile of `ctx` for an interactive sign-in.
/// Fails (typed, nothing sent) when the effective auth is not OAuth 2, uses
/// the non-interactive client-credentials grant, or has no authorization URL.
pub fn interactive_oauth(ctx: &ExecutionContext) -> Result<InteractiveOAuth, TransportFailure> {
    let fail = |m: &str| TransportFailure::new(Phase::Prepare, FailureKind::AuthPreparationFailed, m).with_field("auth");
    let (scope_label, auth) = ctx.effective_auth();
    let config = find_oauth(&auth).ok_or_else(|| fail("the effective auth for this request is not an OAuth 2 profile"))?;
    if config.grant == OAuthGrant::ClientCredentials {
        return Err(fail("this OAuth profile uses the client-credentials grant, which needs no browser sign-in"));
    }
    let r = Resolver::new(ctx.var_layers.clone(), ctx.seed);
    let authorization_endpoint = r.resolve(&config.authorization_url, "auth.authorization_url")?;
    if authorization_endpoint.trim().is_empty() {
        return Err(fail("the OAuth profile has no authorization URL; set it to the issuer's authorization endpoint")
            .with_field("auth.authorization_url"));
    }
    let resolved = resolve_oauth(config, ctx, &r)?;
    if resolved.token_url.trim().is_empty() || resolved.client_id.trim().is_empty() {
        return Err(fail("the OAuth profile needs a token URL and a client id"));
    }
    let settings = crate::settings::resolve(&ctx.settings_layers);
    Ok(InteractiveOAuth {
        scope_label,
        grant: resolved.grant,
        authorization_endpoint,
        token_url: resolved.token_url.clone(),
        client_id: resolved.client_id.clone(),
        scope: resolved.scope.clone(),
        key: cache_key(ctx, &resolved),
        resolved,
        settings,
    })
}

/// Redeem an authorization code at the token endpoint through the engine
/// transport (the request's TLS profile, proxy, DNS and timeouts) and cache
/// the token where [`Engine::execute`] will find it.
pub async fn redeem_authorization_code(
    engine: &Engine,
    ctx: &ExecutionContext,
    target: &InteractiveOAuth,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenSummary, AuthError> {
    let http = EngineTokenHttp { engine, ctx, settings: &target.settings };
    engine.tokens.requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let t = anvil_auth::oauth::exchange_code(&target.resolved, code, verifier, redirect_uri, &http).await?;
    let summary = TokenSummary::of(&t);
    engine.tokens.insert(&target.key, t);
    Ok(summary)
}

/// Metadata of the cached token for this profile, if any.
pub fn token_status(engine: &Engine, target: &InteractiveOAuth) -> Option<TokenSummary> {
    engine.tokens.get(&target.key).map(|t| TokenSummary::of(&t))
}

/// Forget the cached token (sign out of the target API in this session).
pub fn forget_token(engine: &Engine, target: &InteractiveOAuth) -> bool {
    engine.tokens.remove(&target.key)
}
