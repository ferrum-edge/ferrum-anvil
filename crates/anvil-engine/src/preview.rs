//! "Effective request" inspector: everything that would be sent, with the
//! source of each value — without sending anything. Secrets are redacted;
//! per-send values (HMAC nonces, DPoP proofs, JWT iat/exp) are shown as they
//! would be generated for one send and labelled as varying per send.

use crate::Engine;
use crate::context::ExecutionContext;
use crate::http_exec;
use crate::redact::Redactor;
use crate::vars::Resolver;
use anvil_diagnostics::FerrumTrust;
use anvil_domain::execution::{HeaderEntry, TransportFailure};
use anvil_domain::settings::EffectiveSettings;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveRequest {
    pub method: String,
    pub url: String,
    pub destination: String,
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

fn has_unfetched_jwt_svid(a: &anvil_auth::ResolvedAuth) -> bool {
    match a {
        anvil_auth::ResolvedAuth::JwtSvid { token, .. } => token.is_empty(),
        anvil_auth::ResolvedAuth::Multi(v) => v.iter().any(has_unfetched_jwt_svid),
        _ => false,
    }
}

impl Engine {
    pub fn preview(&self, ctx: &ExecutionContext) -> Result<EffectiveRequest, TransportFailure> {
        let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
        let prep = http_exec::prepare_all(self, ctx, &resolver, &["https", "http"])?;
        let mut redactor = Redactor::new(resolver.used_secrets.lock().clone(), ctx.redaction_names.clone());
        let signable = anvil_auth::SignableRequest {
            method: prep.http.method.clone(),
            scheme: prep.http.target.scheme.clone(),
            authority: prep.http.target.authority.clone(),
            raw_path: prep.http.target.path.clone(),
            raw_query: prep.http.target.query.clone(),
            headers: prep.http.headers.clone(),
            body: prep.http.body.to_vec(),
        };
        let mut headers = prep.http.headers.clone();
        let mut url = prep.http.target.url();
        let varies = matches!(
            prep.auth,
            anvil_auth::ResolvedAuth::Hmac(_)
                | anvil_auth::ResolvedAuth::Dpop { .. }
                | anvil_auth::ResolvedAuth::Jwt { .. }
                | anvil_auth::ResolvedAuth::Wsse { .. }
                | anvil_auth::ResolvedAuth::JwtSvid { .. }
        );
        let mut inferred = prep.inferred.clone();
        if has_unfetched_jwt_svid(&prep.auth) {
            // The preview makes no Workload API call and reads no token file.
            inferred.push(
                "JWT-SVID: fetched from the SPIFFE Workload API (or read from its file) and checked locally when the request is sent"
                    .into(),
            );
        }
        if let Ok(applied) = anvil_auth::apply(&prep.auth, &signable, chrono::Utc::now()) {
            for s in &applied.secrets {
                redactor.add_secret(s);
            }
            for (n, v) in applied.set_headers {
                headers.retain(|(h, _)| !h.eq_ignore_ascii_case(&n));
                headers.push((n, v));
            }
            for (k, v) in applied.append_query {
                let sep = if url.contains('?') { '&' } else { '?' };
                url = format!("{url}{sep}{}={}", crate::prepare::encode_component(&k), crate::prepare::encode_component(&v));
            }
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
