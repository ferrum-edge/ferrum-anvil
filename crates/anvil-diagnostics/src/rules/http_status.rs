//! Generic HTTP status meaning. These findings state what the status means
//! and — explicitly — that the status alone does not identify which
//! component (gateway, WAF, application, intermediary) produced it.
//!
//! An RFC 9457 problem report in the body is quoted as evidence and in the
//! explanation, because its type, title and detail often separate causes the
//! status cannot (a 503 for draining, a full admission queue or a handler
//! deadline). It never changes the code, confidence, scope or owner: any
//! server on the path can send one.

use super::Ctx;
use crate::Draft;
use crate::facts::ProblemDetails;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Remediation, Severity, SourceScope};

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let Some(r) = ctx.input.response else { return };
    if matches!(ctx.input.protocol, anvil_domain::request::Protocol::Grpc) {
        return; // gRPC semantics are evaluated from grpc-status
    }
    let s = r.status;
    if s < 400 {
        return;
    }
    let idx = ctx.attempt_index();
    let code = match s {
        401 => "http.unauthorized",
        403 => "http.forbidden",
        404 => "http.not_found",
        405 => "http.method_not_allowed",
        407 => "http.proxy_auth_required",
        408 => "http.request_timeout",
        413 => "http.payload_too_large",
        415 => "http.unsupported_media_type",
        429 => "http.too_many_requests",
        400..=499 => "http.client_error",
        502 => "http.bad_gateway",
        503 => "http.service_unavailable",
        504 => "http.gateway_timeout",
        _ => "http.server_error",
    };
    let owner = if s < 500 { Owner::Caller } else { Owner::Unknown };
    let sev = Severity::Error;
    let mut d = Draft::new(code, "http.status", Confidence::Confirmed, SourceScope::Unknown, owner, sev)
        .ev_at(E::HttpStatus, "status", s.to_string(), idx)
        .var("status", s.to_string())
        .var("reason", r.reason.clone().unwrap_or_default())
        .var("host", ctx.target_host());
    for h in ["www-authenticate", "retry-after", "allow", "x-ratelimit-remaining", "ratelimit-remaining"] {
        for v in r.header_values(h) {
            d = d.ev_at(E::HttpHeader, &format!("header.{h}"), v.to_string(), idx);
        }
    }
    if let Some(ra) = r.header_values("retry-after").first() {
        d = d.var("retry_after", format!("The response asks the caller to wait {ra} before retrying."));
    } else {
        d = d.var("retry_after", String::new());
    }
    if let Some(allow) = r.header_values("allow").first() {
        d = d.var("allow", format!("Allowed methods reported by the response: {allow}."));
    } else {
        d = d.var("allow", String::new());
    }
    if let Some(e) = &ctx.body.json_error {
        d = d.ev_at(E::BodyContent, "body.error", e.clone(), idx);
    }
    d = match &ctx.body.problem {
        Some(p) => problem(d, p, s, idx),
        None => d.var("problem", String::new()),
    };
    out.push(d);
}

/// Quotes an RFC 9457 problem report: evidence, a sentence for `{problem}`,
/// what it does not prove, and who to give its identifiers to.
fn problem(mut d: Draft, p: &ProblemDetails, status: u16, idx: u32) -> Draft {
    for (key, value) in [
        ("body.problem.type", &p.type_uri),
        ("body.problem.title", &p.title),
        ("body.problem.detail", &p.detail),
        ("body.problem.instance", &p.instance),
    ] {
        if let Some(v) = value {
            d = d.ev_at(E::BodyContent, key, v.clone(), idx);
        }
    }
    if let Some(n) = p.status {
        d = d.ev_at(E::BodyContent, "body.problem.status", n.to_string(), idx);
    }
    // RFC 9457 §3.1.1: an absent type means `about:blank`, which adds
    // nothing beyond the status.
    let named_type = p.type_uri.as_deref().filter(|t| *t != "about:blank");
    let mut sentence = String::from("The body is an RFC 9457 problem report");
    if let Some(t) = named_type {
        sentence.push_str(&format!(" of type {t}"));
    }
    if let Some(t) = &p.title {
        sentence.push_str(&format!(", titled \"{t}\""));
    }
    if let Some(t) = &p.detail {
        sentence.push_str(&format!(", with detail \"{t}\""));
    }
    // A quoted text that already ends a sentence ends this one too.
    if !sentence.trim_end_matches('"').ends_with(['.', '!', '?']) {
        sentence.push('.');
    }
    if let Some(n) = p.status.filter(|n| *n != status) {
        sentence.push_str(&format!(" It states status {n}, but the response status is {status}."));
        d = d.alt(format!(
            "An intermediary changed the status: the problem report states {n} (RFC 9457 requires the generator to send the same status)."
        ));
    }
    d = d.var("problem", sentence).not_proven(
        "That the problem report is accurate, or which component on the path wrote it: any server can send application/problem+json.",
    );
    let ids = match (named_type, &p.instance) {
        (Some(t), Some(i)) => Some(format!("type ({t}) and instance ({i})")),
        (Some(t), None) => Some(format!("type ({t})")),
        (None, Some(i)) => Some(format!("instance ({i})")),
        (None, None) => None,
    };
    if let Some(ids) = ids {
        d.extra_remediation.push(Remediation {
            text: format!("When you ask the API's owner about this response, quote the problem report's {ids}: they name the condition the server reported."),
            owner: Owner::Caller,
        });
    }
    d
}
