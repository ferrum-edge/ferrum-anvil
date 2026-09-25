//! Interactive browser-login outcomes (AUTH-017).
//!
//! A destination protected by an OIDC / OAuth 2.0 relying party answers a
//! request without a session either by redirecting to the identity
//! provider's authorization endpoint (browser branch) or with an
//! OIDC-realm bearer challenge (API branch). Neither means the API
//! answered: the request stopped at a login step. A login the user
//! completed in the system browser leaves its session cookie in that
//! browser; Anvil never imports browser cookies, so the finding says so and
//! points at the supported paths (an API token, or an explicitly configured
//! and authorized session cookie).
//!
//! Evidence used:
//! * an attempt that followed a redirect to a URL carrying the RFC 6749
//!   §4.1.1 authorization-request parameters (`response_type` and
//!   `client_id`), or a final 3xx whose `Location` carries them;
//! * a 401 whose `WWW-Authenticate` challenge names the `oidc` realm.
//!
//! The observation is typed (URL parameters / challenge parameters); the
//! interpretation that an interactive login is required stays `likely`.

use super::Ctx;
use crate::Draft;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::AttemptReason;

/// `(host, path)` of an OAuth 2.0 authorization request URL, if `url` is one.
fn authorization_request(url: &str) -> Option<(String, String)> {
    let parsed = url::Url::parse(url).ok()?;
    let names: Vec<String> = parsed.query_pairs().map(|(k, _)| k.to_ascii_lowercase()).collect();
    let has = |n: &str| names.iter().any(|k| k == n);
    if !(has("response_type") && has("client_id")) {
        return None;
    }
    let host = match parsed.port() {
        Some(p) => format!("{}:{p}", parsed.host_str().unwrap_or("")),
        None => parsed.host_str().unwrap_or("").to_string(),
    };
    Some((host, parsed.path().to_string()))
}

fn oidc_realm(challenge: &str) -> bool {
    let c = challenge.to_ascii_lowercase();
    c.contains("realm=\"oidc\"") || c.contains("realm=oidc")
}

/// Whether the execution ended at an interactive login step rather than at
/// the API (used to keep the application verdict from reading as success).
pub fn login_redirect(ctx: &Ctx<'_>) -> Option<(u32, String, String)> {
    for a in ctx.input.attempts {
        if matches!(a.reason, AttemptReason::Redirect { .. })
            && let Some((host, path)) = authorization_request(&a.url)
        {
            return Some((a.index, host, path));
        }
    }
    let r = ctx.input.response?;
    if (300..400).contains(&r.status) {
        let base = ctx.final_attempt().map(|a| a.url.clone()).unwrap_or_default();
        for loc in r.header_values("location") {
            let absolute =
                url::Url::parse(&base).ok().and_then(|b| b.join(loc).ok()).map(|u| u.to_string()).unwrap_or_else(|| loc.to_string());
            if let Some((host, path)) = authorization_request(&absolute) {
                return Some((ctx.attempt_index(), host, path));
            }
        }
    }
    None
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let mk = |how: &str| {
        Draft::new(
            "auth.browser_session_required",
            "auth.session",
            Confidence::Likely,
            SourceScope::Unknown,
            Owner::Caller,
            Severity::Error,
        )
        .var("host", ctx.target_host())
        .var("how", how.to_string())
    };
    if let Some((idx, host, path)) = login_redirect(ctx) {
        out.push(
            mk(&format!("redirected this request to an identity provider's authorization endpoint ({host}{path})"))
                .ev_at(E::HttpHeader, "redirect.authorization_endpoint", format!("{host}{path}"), idx)
                .ev_at(E::HttpHeader, "redirect.parameters", "response_type, client_id", idx),
        );
        return;
    }
    let Some(r) = ctx.input.response else { return };
    if r.status != 401 {
        return;
    }
    if let Some(ch) = r.header_values("www-authenticate").into_iter().find(|v| oidc_realm(v)) {
        out.push(mk("answered 401 with an OIDC-realm bearer challenge instead of the API response").ev_at(
            E::HttpHeader,
            "header.www-authenticate",
            ch.to_string(),
            ctx.attempt_index(),
        ));
    }
}
