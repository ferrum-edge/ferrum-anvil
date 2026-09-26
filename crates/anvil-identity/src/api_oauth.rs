//! Target-API OAuth sign-in (identity 2): authorization code + PKCE in the
//! system browser, code redeemed through the engine transport with the
//! request's TLS profile, proxy, DNS and timeouts, token cached under the key
//! the engine sends with. Nothing is returned that could reveal the token.

use crate::flow::{AuthorizationRequest, authorize_in_browser};
use crate::{BrowserOpener, FlowError, FlowEvent, FlowObserver, FlowOptions, failed, require_secure_endpoint};
use anvil_auth::AuthError;
use anvil_domain::auth::OAuthGrant;
use anvil_engine::oauth_http::{self, InteractiveOAuth, TokenSummary};
use anvil_engine::{Engine, ExecutionContext};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

/// Result of a completed sign-in: what was authorized, never the token.
#[derive(Debug, Clone, Serialize)]
pub struct ApiAuthorization {
    /// Where the OAuth profile is defined (`request`, `folder:<name>`, `workspace`).
    pub profile_scope: String,
    pub grant: OAuthGrant,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub scope: String,
    pub token: TokenSummary,
}

/// Resolve the OAuth profile in effect for `ctx` for a sign-in (typed error
/// when it is not an interactive OAuth profile).
pub fn target(ctx: &ExecutionContext) -> Result<InteractiveOAuth, FlowError> {
    oauth_http::interactive_oauth(ctx).map_err(|f| FlowError::Configuration(f.message))
}

/// Sign in to the target API of `ctx` and cache the token in `engine`.
///
/// The next [`Engine::execute`] with the same context uses the token, and
/// refreshes it with the issued refresh token when it expires. Cancellation
/// via `cancel` ends the attempt at any point (the listener closes). A lock
/// or sign-out while the attempt runs discards its token.
pub async fn authorize_api(
    engine: &Engine,
    ctx: &ExecutionContext,
    opener: &dyn BrowserOpener,
    observer: &dyn FlowObserver,
    opts: &FlowOptions,
    cancel: &CancellationToken,
) -> Result<ApiAuthorization, FlowError> {
    let t = match target(ctx) {
        Ok(t) => t,
        Err(e) => return Err(failed(observer, e)),
    };
    if let Err(e) = require_secure_endpoint("the token URL", &t.token_url) {
        return Err(failed(observer, e));
    }
    let generation = oauth_http::sign_in_generation(engine, &t);
    let request = AuthorizationRequest { authorization_endpoint: &t.authorization_endpoint, client_id: &t.client_id, scope: &t.scope };
    let grant = authorize_in_browser(&request, opener, observer, opts, cancel).await?;
    observer.event(FlowEvent::ExchangingCode);
    let redeemed = tokio::select! {
        r = oauth_http::redeem_authorization_code(
            engine, ctx, &t, generation, &grant.code, &grant.verifier, &grant.redirect_uri, cancel,
        ) => r,
        _ = cancel.cancelled() => return Err(failed(observer, FlowError::Canceled)),
    };
    drop(grant);
    let token = redeemed.map_err(|e| match e {
        AuthError::Canceled(_) => failed(observer, FlowError::Canceled),
        e => failed(observer, FlowError::Exchange(e.to_string())),
    })?;
    observer.event(FlowEvent::Completed);
    Ok(ApiAuthorization {
        profile_scope: t.scope_label.clone(),
        grant: t.grant,
        authorization_endpoint: t.authorization_endpoint.clone(),
        token_endpoint: t.token_url.clone(),
        client_id: t.client_id.clone(),
        scope: t.scope.clone(),
        token,
    })
}

/// Metadata of the token cached for the profile in effect, if any.
pub fn token_status(engine: &Engine, ctx: &ExecutionContext) -> Result<Option<TokenSummary>, FlowError> {
    Ok(oauth_http::token_status(engine, &target(ctx)?))
}

/// Forget the cached token for the profile in effect (sign out of the API
/// for this session). Returns whether a token was cached.
pub fn sign_out(engine: &Engine, ctx: &ExecutionContext) -> Result<bool, FlowError> {
    Ok(oauth_http::forget_token(engine, &target(ctx)?))
}
