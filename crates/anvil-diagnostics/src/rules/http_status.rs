//! Generic HTTP status meaning. These findings state what the status means
//! and — explicitly — that the status alone does not identify which
//! component (gateway, WAF, application, intermediary) produced it.

use super::Ctx;
use crate::Draft;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};

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
    out.push(d);
}
