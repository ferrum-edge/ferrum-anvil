//! "Effective request" inspector: everything that would be sent, with the
//! source of each value — without sending anything. Secrets are redacted;
//! per-send values (HMAC nonces, DPoP proofs, JWT iat/exp) are shown as they
//! would be generated for one send and labelled as varying per send.

use crate::Engine;
use crate::context::ExecutionContext;
use crate::http_exec;
use crate::redact::Redactor;
use crate::vars::Resolver;
use anvil_auth::ResolvedAuth;
use anvil_diagnostics::FerrumTrust;
use anvil_domain::execution::{HeaderEntry, TransportFailure};
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
    pub fn preview(&self, ctx: &ExecutionContext) -> Result<EffectiveRequest, TransportFailure> {
        let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
        let prep = http_exec::prepare_all(self, ctx, &resolver, &["https", "http"])?;
        let mut redactor = Redactor::for_execution(&resolver, &ctx.redaction_names);
        // The same authority and signing input as the send path.
        let signable = http_exec::signable_request(&prep.http.method, &prep.http.target, &prep.http.headers, &prep.http.body);
        let mut headers = prep.http.headers.clone();
        let mut url = prep.http.target.url();
        let varies = matches!(
            prep.auth,
            ResolvedAuth::Hmac(_)
                | ResolvedAuth::Dpop { .. }
                | ResolvedAuth::Jwt { .. }
                | ResolvedAuth::Wsse { .. }
                | ResolvedAuth::JwtSvid { .. }
        );
        let mut inferred = prep.inferred.clone();
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
                // wire: say so rather than show a request that would not be sent.
                if let Some(why) = http_exec::auth_header_problem(&applied) {
                    inferred.push(format!("the request would not be sent: {why}"));
                } else {
                    for (n, v) in applied.set_headers {
                        headers.retain(|(h, _)| !h.eq_ignore_ascii_case(&n));
                        headers.push((n, v));
                    }
                    for (k, v) in applied.append_query {
                        let sep = if url.contains('?') { '&' } else { '?' };
                        url = format!("{url}{sep}{}={}", crate::prepare::encode_component(&k), crate::prepare::encode_component(&v));
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
        let body_preview: String = String::from_utf8_lossy(&prep.http.body[..prep.http.body.len().min(64 * 1024)]).into_owned();
        let body_preview = if prep.http.content_type.as_deref().map(|c| c.contains("json")).unwrap_or(false) {
            redactor.json_text(&body_preview)
        } else {
            redactor.text(&body_preview)
        };
        let omitted = resolver.used_secrets.lock().len();
        Ok(EffectiveRequest {
            method: prep.http.method.clone(),
            url: redactor.url(&url),
            destination: format!("{}:{}", prep.http.target.host, prep.http.target.port),
            authority: redactor.text(&http_exec::request_authority(&headers, &prep.http.target)),
            headers: headers.iter().map(|(n, v)| HeaderEntry { name: n.clone(), value: redactor.header(n, v) }).collect(),
            body_bytes: prep.http.body.len() as u64,
            body_preview,
            content_type: prep.http.content_type.clone(),
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
