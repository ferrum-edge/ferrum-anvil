//! "Effective request" inspector: everything that would be sent, with the
//! source of each value — without sending anything. Secrets are redacted;
//! per-send values (HMAC nonces, DPoP proofs, JWT iat/exp) are shown as they
//! would be generated for one send and labelled as varying per send.
//! WebSocket, SSE and gRPC requests show the handshake or call their session
//! transport sends; raw TCP and UDP are not previewed.

use crate::Engine;
use crate::context::ExecutionContext;
use crate::http_exec;
use crate::redact::Redactor;
use crate::session_preview::{self, Shape};
use crate::sessions;
use crate::vars::Resolver;
use anvil_auth::ResolvedAuth;
use anvil_diagnostics::FerrumTrust;
use anvil_domain::execution::{HeaderEntry, TransportFailure};
use anvil_domain::request::Protocol;
use anvil_domain::settings::EffectiveSettings;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveRequest {
    pub method: String,
    pub url: String,
    pub destination: String,
    /// The `Host` (HTTP/1.1) or `:authority` (HTTP/2, HTTP/3) sent, which
    /// request signatures cover: an explicit `Host` header, else the URL's.
    pub authority: String,
    pub headers: Vec<HeaderEntry>,
    pub body_bytes: u64,
    pub body_preview: String,
    pub content_type: Option<String>,
    pub auth: String,
    pub auth_varies_per_send: bool,
    pub tls_profile: Option<String>,
    pub tls_verification: bool,
    pub proxy: Option<String>,
    pub ferrum_trust: Option<String>,
    pub settings: EffectiveSettings,
    pub variables_used: Vec<(String, String)>,
    pub inferred: Vec<String>,
    pub lint_warning: Option<String>,
    pub omitted_secrets: usize,
}

/// Whether the credential `auth` sends changes from one send to the next,
/// so the value a preview shows is not the one sent: an HMAC signature, a
/// DPoP proof, a JWT (`iat`/`exp`/`jti`) and a WS-Security header (nonce and
/// created time) are generated for each send, and a JWT-SVID is fetched (or
/// read) and checked when the request is sent. A multi-auth varies when any
/// of its profiles does.
///
/// An OAuth2 access token does not: sends reuse the cached token the
/// preview shows until it nears expiry, and a refresh replaces it then, not
/// on each send.
pub fn auth_varies_per_send(auth: &ResolvedAuth) -> bool {
    match auth {
        ResolvedAuth::Hmac(_)
        | ResolvedAuth::Dpop { .. }
        | ResolvedAuth::Jwt { .. }
        | ResolvedAuth::Wsse { .. }
        | ResolvedAuth::JwtSvid { .. } => true,
        ResolvedAuth::Multi(v) => v.iter().any(auth_varies_per_send),
        ResolvedAuth::None
        | ResolvedAuth::ApiKey { .. }
        | ResolvedAuth::Basic { .. }
        | ResolvedAuth::Bearer { .. }
        | ResolvedAuth::OAuth2 { .. } => false,
    }
}

/// Stands in for a JWT-SVID the preview does not fetch, so the rest of the
/// auth is applied and checked as it will be when the request is sent.
const UNFETCHED_JWT_SVID: &str = "<JWT-SVID fetched when sent>";

fn has_unfetched_jwt_svid(a: &ResolvedAuth) -> bool {
    match a {
        ResolvedAuth::JwtSvid { token, .. } => token.is_empty(),
        ResolvedAuth::Multi(v) => v.iter().any(has_unfetched_jwt_svid),
        _ => false,
    }
}

/// `a` with [`UNFETCHED_JWT_SVID`] as the token of every unfetched JWT-SVID.
fn with_jwt_svid_placeholder(a: &ResolvedAuth) -> ResolvedAuth {
    match a {
        ResolvedAuth::JwtSvid { token, header_name, prefix } if token.is_empty() => ResolvedAuth::JwtSvid {
            token: Zeroizing::new(UNFETCHED_JWT_SVID.to_string()),
            header_name: header_name.clone(),
            prefix: prefix.clone(),
        },
        ResolvedAuth::Multi(v) => ResolvedAuth::Multi(v.iter().map(with_jwt_svid_placeholder).collect()),
        other => other.clone(),
    }
}

impl Engine {
    /// The request a send would make, without sending it. A WebSocket, SSE
    /// or gRPC request shows its handshake or call as the session transport
    /// sends it (method, target, `Host` / `:authority`, headers, body and the
    /// signature over them); raw TCP and UDP have no request to preview.
    pub fn preview(&self, ctx: &ExecutionContext) -> Result<EffectiveRequest, TransportFailure> {
        let schemes = session_preview::schemes(ctx.spec.protocol)?;
        let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
        let prep = http_exec::prepare_all(self, ctx, &resolver, schemes)?;
        let mut inferred = prep.inferred.clone();
        let shape = match ctx.spec.protocol {
            Protocol::Http => Shape::http(&prep),
            // A message that does not fit the schema is refused with an error
            // that may quote it: redacted as the session's failure is.
            _ => Shape::session(ctx, &resolver, &prep, &mut inferred).map_err(|mut f| {
                f.message = Redactor::for_execution(&resolver, &ctx.redaction_names).text(&f.message);
                f
            })?,
        };
        // After the session's messages and metadata are resolved, so the
        // secrets they use are known.
        let mut redactor = Redactor::for_execution(&resolver, &ctx.redaction_names);
        let req = &shape.req;
        // The same authority and signing input as the send path. A session
        // signs for its URL's HTTP counterpart (`wss` as `https`).
        let signable = http_exec::signable_request(&req.method, &sessions::http_target(&req.target), &req.headers, &req.body);
        let mut headers = req.headers.clone();
        let mut target = req.target.clone();
        // The body sent: auth may rewrite it (a WS-Security header block).
        let mut body = req.body.clone();
        let varies = auth_varies_per_send(&prep.auth);
        let auth = if has_unfetched_jwt_svid(&prep.auth) {
            // The preview makes no Workload API call and reads no token file.
            inferred.push(
                "JWT-SVID: fetched from the SPIFFE Workload API (or read from its file) and checked locally when the request is sent"
                    .into(),
            );
            with_jwt_svid_placeholder(&prep.auth)
        } else {
            prep.auth.clone()
        };
        match anvil_auth::apply(&auth, &signable, chrono::Utc::now()) {
            Ok(applied) => {
                for s in applied.secrets.iter().filter(|s| s.as_str() != UNFETCHED_JWT_SVID) {
                    redactor.add_secret(s);
                }
                // The engine refuses an auth header that is not valid on the
                // wire, and a session one it cannot carry: say so rather than
                // show a request that would not be sent.
                if let Some(why) = http_exec::auth_header_problem(&applied).or_else(|| shape.auth_refusal(&applied)) {
                    inferred.push(format!("the request would not be sent: {why}"));
                } else {
                    for (n, v) in applied.set_headers {
                        headers.retain(|(h, _)| !h.eq_ignore_ascii_case(&n));
                        headers.push((n, v));
                    }
                    for (k, v) in applied.append_query {
                        let pair = format!("{}={}", crate::prepare::encode_component(&k), crate::prepare::encode_component(&v));
                        target.query = if target.query.is_empty() { pair } else { format!("{}&{pair}", target.query) };
                    }
                    if let Some(b) = applied.body {
                        body = b.into();
                    }
                    for (k, v) in &applied.facts {
                        inferred.push(redactor.inferred(&format!("auth {k}: {v}")));
                    }
                }
            }
            // The send path fails the request when auth cannot be applied:
            // say so rather than show the request without its credentials.
            Err(e) => inferred.push(format!("the request would not be sent: {}", redactor.text(&e.to_string()))),
        }
        let authority = http_exec::request_authority(&headers, &target);
        shape.transport_headers(&mut headers, &authority);
        let body_preview = if let Some(m) = &shape.message {
            // A gRPC call's message as the JSON it is encoded from; its body
            // size is still that of the framed bytes sent (none yet when the
            // schema comes from server reflection).
            redactor.json_text(m)
        } else {
            let text: String = String::from_utf8_lossy(&body[..body.len().min(64 * 1024)]).into_owned();
            if req.content_type.as_deref().map(|c| c.contains("json")).unwrap_or(false) {
                redactor.json_text(&text)
            } else {
                redactor.text(&text)
            }
        };
        let omitted = resolver.used_secrets.lock().len();
        Ok(EffectiveRequest {
            method: req.method.clone(),
            url: redactor.url(&shape.url(&target)),
            destination: format!("{}:{}", target.host, target.port),
            authority: redactor.text(&authority),
            headers: headers.iter().map(|(n, v)| HeaderEntry { name: n.clone(), value: redactor.header(n, v) }).collect(),
            body_bytes: body.len() as u64,
            body_preview,
            content_type: req.content_type.clone(),
            auth: prep.auth_label.clone(),
            auth_varies_per_send: varies,
            tls_profile: prep.tls_profile_name.clone(),
            tls_verification: prep.tls.as_ref().map(|t| t.verify).unwrap_or(true),
            proxy: prep.proxy.as_ref().map(|p| p.label.clone()),
            ferrum_trust: match &prep.trust {
                FerrumTrust::Trusted { profile_name, compatibility_id, .. } => Some(format!("{profile_name} ({compatibility_id})")),
                FerrumTrust::NotConfigured => None,
            },
            settings: prep.settings.clone(),
            variables_used: resolver.used.lock().clone(),
            inferred,
            lint_warning: prep.http.lint_bypassed.clone(),
            omitted_secrets: omitted,
        })
    }
}
