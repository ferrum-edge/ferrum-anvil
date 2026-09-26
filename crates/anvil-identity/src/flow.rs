//! The browser half of an authorization-code + PKCE attempt: loopback
//! listener, authorization URL, system browser, bound callback. Redeeming
//! the code is left to the caller, which knows the transport and where the
//! token belongs (engine cache for target APIs, identity verification for
//! application login).

use crate::loopback::Loopback;
use crate::{BrowserOpener, FlowError, FlowEvent, FlowObserver, FlowOptions, failed, require_secure_endpoint};
use anvil_auth::oauth::{authorization_url, new_attempt};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// What to ask the authorization server for.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest<'a> {
    pub authorization_endpoint: &'a str,
    pub client_id: &'a str,
    pub scope: &'a str,
}

/// A validated callback: the code plus the PKCE verifier and exact redirect
/// URI that must accompany it to the token endpoint. Zeroized on drop.
pub struct AuthorizationCode {
    pub code: Zeroizing<String>,
    pub verifier: Zeroizing<String>,
    pub redirect_uri: String,
}

impl std::fmt::Debug for AuthorizationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationCode").field("redirect_uri", &self.redirect_uri).finish_non_exhaustive()
    }
}

/// Run the browser part of one attempt and return the bound authorization
/// code. Emits [`FlowEvent`]s along the way (and `Failed` on error).
pub async fn authorize_in_browser(
    req: &AuthorizationRequest<'_>,
    opener: &dyn BrowserOpener,
    observer: &dyn FlowObserver,
    opts: &FlowOptions,
    cancel: &CancellationToken,
) -> Result<AuthorizationCode, FlowError> {
    run(req, opener, observer, opts, cancel).await.map_err(|e| failed(observer, e))
}

async fn run(
    req: &AuthorizationRequest<'_>,
    opener: &dyn BrowserOpener,
    observer: &dyn FlowObserver,
    opts: &FlowOptions,
    cancel: &CancellationToken,
) -> Result<AuthorizationCode, FlowError> {
    require_secure_endpoint("the authorization URL", req.authorization_endpoint)?;
    if req.client_id.trim().is_empty() {
        return Err(FlowError::Configuration("a client id is required for a browser sign-in".into()));
    }
    let listener = Loopback::bind(&opts.callback_path).await?;
    let attempt = new_attempt(listener.redirect_uri());
    let url = authorization_url(req.authorization_endpoint, req.client_id, req.scope, &attempt)
        .map_err(|e| FlowError::Configuration(e.to_string()))?;
    observer.event(FlowEvent::ListenerReady { redirect_uri: attempt.redirect_uri.clone() });
    match opener.open(&url) {
        Ok(()) => observer.event(FlowEvent::BrowserOpened { authorization_url: url }),
        Err(error) => observer.event(FlowEvent::BrowserOpenFailed { authorization_url: url, error }),
    }
    let code = listener.wait(attempt.binding_only(), observer, opts.timeout, cancel).await?;
    observer.event(FlowEvent::CallbackAccepted);
    Ok(AuthorizationCode { code, verifier: attempt.verifier.clone(), redirect_uri: attempt.redirect_uri.clone() })
}
