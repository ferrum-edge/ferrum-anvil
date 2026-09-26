//! SPIFFE Workload API and JWT-SVID outcomes.
//!
//! Evidence used (typed, from the execution's Workload API evidence):
//! * the failed Workload API call — its RPC, endpoint and typed result
//!   (connect failure, deadline, gRPC status with the server's bounded
//!   message, an answer without an identity) — for a preparation failure of
//!   kind `WorkloadApiUnavailable` / `WorkloadApiDenied` / `WorkloadApiFailed`;
//! * the JWT-SVID's local checks (format, algorithm, subject, audience,
//!   expiry, signature against the trust domain's JWT bundle), whether the
//!   token was refused locally or sent anyway;
//! * a final 401 to a request that carried a JWT-SVID.
//!
//! Every Workload API failure is local: nothing reached the destination, so
//! no rule here blames it. A 401 after a JWT-SVID stays a generic refusal
//! with the local checks as evidence; which check the verifier failed is
//! never claimed, because the public answer does not identify it (Ferrum
//! Edge's `jwks_auth` answers every rejected token with one body).

use super::Ctx;
use crate::Draft;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::FailureKind as K;
use anvil_domain::workload::{
    CheckResult, JwtSvidCheckKind, JwtSvidSummary, WorkloadApiCall, WorkloadCallResult, WorkloadEndpointSource, WorkloadRpc,
};

/// Preparation failure kinds this module words (the generic local rule skips them).
pub fn handles(kind: K) -> bool {
    matches!(kind, K::WorkloadApiUnavailable | K::WorkloadApiDenied | K::WorkloadApiFailed | K::JwtSvidRejectedLocally)
}

fn source_label(s: WorkloadEndpointSource) -> &'static str {
    match s {
        WorkloadEndpointSource::Setting => "from the profile",
        WorkloadEndpointSource::Environment => "from SPIFFE_ENDPOINT_SOCKET",
    }
}

fn answer(r: &WorkloadCallResult) -> String {
    match r {
        WorkloadCallResult::Ok => "OK".into(),
        WorkloadCallResult::Unavailable { detail, .. } => detail.clone(),
        WorkloadCallResult::Timeout { deadline_ms } => format!("no answer within {deadline_ms} ms"),
        WorkloadCallResult::Status { code_name, message, .. } if message.is_empty() => code_name.clone(),
        WorkloadCallResult::Status { code_name, message, .. } => format!("{code_name} (\"{message}\")"),
        WorkloadCallResult::NoIdentity { detail } | WorkloadCallResult::Malformed { detail } => detail.clone(),
    }
}

fn call_evidence(mut d: Draft, c: &WorkloadApiCall) -> Draft {
    d = d
        .ev(E::NativeTransport, "workload_api.rpc", c.rpc.method())
        .ev(E::Configuration, "workload_api.endpoint", c.endpoint.clone())
        .ev(E::Configuration, "workload_api.endpoint_source", source_label(c.endpoint_source))
        .ev(E::LocalValidation, "workload_api.purpose", c.purpose.clone());
    match &c.result {
        WorkloadCallResult::Unavailable { io_error_kind: Some(k), .. } => d = d.ev(E::NativeTransport, "io.error_kind", k.clone()),
        WorkloadCallResult::Timeout { deadline_ms } => d = d.ev(E::NativeTransport, "workload_api.deadline_ms", deadline_ms.to_string()),
        WorkloadCallResult::Status { code, code_name, message } => {
            d = d.ev(E::GrpcStatus, "grpc.status", format!("{code} ({code_name})"));
            if !message.is_empty() {
                d = d.ev(E::GrpcStatus, "grpc.message", message.clone());
            }
        }
        WorkloadCallResult::NoIdentity { detail } | WorkloadCallResult::Malformed { detail } => {
            d = d.ev(E::NativeTransport, "workload_api.answer", detail.clone())
        }
        _ => {}
    }
    if let Some(uid) = c.caller_uid {
        d = d.ev(E::LocalValidation, "process.uid", uid.to_string());
    }
    d.var("rpc", c.rpc.method())
        .var("endpoint", c.endpoint.clone())
        .var("endpoint_source", source_label(c.endpoint_source))
        .var("purpose", c.purpose.clone())
        .var("answer", answer(&c.result))
}

fn local_failures(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let Some(f) = ctx.input.preparation_failure else { return };
    let Some(call) = ctx.input.workload.and_then(|w| w.failed_call()) else { return };
    let d = match f.kind {
        K::WorkloadApiUnavailable => Draft::new(
            "local.workload_api_unavailable",
            "local.workload_api",
            Confidence::Confirmed,
            SourceScope::LocalClient,
            Owner::Caller,
            Severity::Error,
        ),
        K::WorkloadApiDenied => {
            let what = match call.rpc {
                WorkloadRpc::FetchX509Svid => "X.509-SVID",
                WorkloadRpc::FetchJwtSvid => "JWT-SVID",
                WorkloadRpc::FetchJwtBundles => "JWT bundle",
            };
            Draft::new(
                "local.workload_api_denied",
                "local.workload_api",
                Confidence::Confirmed,
                SourceScope::LocalClient,
                Owner::IdentityProvider,
                Severity::Error,
            )
            .var("what", what)
            .var("uid", call.caller_uid.map(|u| format!("uid {u}")).unwrap_or_else(|| "this user".into()))
        }
        K::WorkloadApiFailed => Draft::new(
            "local.workload_api_failed",
            "local.workload_api",
            Confidence::Confirmed,
            SourceScope::LocalClient,
            Owner::Unknown,
            Severity::Error,
        ),
        _ => return,
    };
    out.push(call_evidence(d, call).ev(E::LocalValidation, "failure.kind", format!("{:?}", f.kind)));
}

fn check_detail(j: &JwtSvidSummary, k: JwtSvidCheckKind) -> String {
    j.check(k).map(|c| c.detail.clone()).unwrap_or_default()
}

fn jwt_evidence(mut d: Draft, j: &JwtSvidSummary) -> Draft {
    if let Some(s) = &j.subject {
        d = d.ev(E::LocalValidation, "jwt_svid.sub", s.clone());
    }
    d = d.ev(E::LocalValidation, "jwt_svid.aud", j.audiences.join(", "));
    d = d.ev(E::Configuration, "jwt_svid.requested_audiences", j.requested_audiences.join(", "));
    if let Some(e) = j.expires_at {
        d = d.ev(E::LocalValidation, "jwt_svid.exp", e.to_rfc3339());
    }
    if let Some(a) = &j.algorithm {
        d = d.ev(E::LocalValidation, "jwt_svid.alg", a.clone());
    }
    if let Some(k) = &j.key_id {
        d = d.ev(E::LocalValidation, "jwt_svid.kid", k.clone());
    }
    for c in &j.checks {
        d = d.ev(
            E::LocalValidation,
            &format!("jwt_svid.check.{}", format!("{:?}", c.check).to_lowercase()),
            format!("{:?}: {}", c.result, c.detail),
        );
    }
    d
}

fn jwt_checks(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let Some(j) = ctx.input.workload.and_then(|w| w.jwt_svid.as_ref()) else { return };
    if j.failed_checks().next().is_none() {
        return;
    }
    let refused = ctx.input.preparation_failure.is_some_and(|f| f.kind == K::JwtSvidRejectedLocally);
    // Sent anyway: the checks still stand, as warnings next to the verifier's answer.
    let (severity, outcome) = if refused {
        (Severity::Error, "Anvil did not send the request.")
    } else {
        (Severity::Warning, "The profile asks to send despite failed checks, so it was sent and the verifier's own answer is shown.")
    };
    let failed = |k: JwtSvidCheckKind| j.check(k).is_some_and(|c| c.result == CheckResult::Failed);
    let mk = |code: &str| {
        jwt_evidence(Draft::new(code, "auth.jwt_svid", Confidence::Confirmed, SourceScope::LocalClient, Owner::Caller, severity), j)
            .var("outcome", outcome)
    };
    if failed(JwtSvidCheckKind::Expiry) {
        out.push(
            mk("auth.jwt_svid_expired")
                .var("expires", j.expires_at.map(|e| e.to_rfc3339()).unwrap_or_else(|| "missing".into()))
                .var("detail", check_detail(j, JwtSvidCheckKind::Expiry)),
        );
    }
    if failed(JwtSvidCheckKind::Audience) {
        out.push(
            mk("auth.jwt_svid_audience_mismatch")
                .var("requested", j.requested_audiences.join(", "))
                .var("aud", if j.audiences.is_empty() { "no audience".into() } else { j.audiences.join(", ") }),
        );
    }
    let other: Vec<String> = j
        .failed_checks()
        .filter(|c| !matches!(c.check, JwtSvidCheckKind::Expiry | JwtSvidCheckKind::Audience))
        .map(|c| format!("{}: {}", format!("{:?}", c.check).to_lowercase(), c.detail))
        .collect();
    if !other.is_empty() {
        out.push(mk("auth.jwt_svid_invalid").var("failures", other.join("; ")));
    }
}

fn rejected(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let Some(j) = ctx.input.workload.and_then(|w| w.jwt_svid.as_ref()) else { return };
    let Some(r) = ctx.input.response else { return };
    if r.status != 401 || ctx.input.preparation_failure.is_some() {
        return;
    }
    let idx = ctx.attempt_index();
    let checks: Vec<String> = j
        .checks
        .iter()
        .filter(|c| c.result != CheckResult::NotRun || c.check == JwtSvidCheckKind::Signature)
        .map(|c| {
            let res = match c.result {
                CheckResult::Passed => "passed",
                CheckResult::Failed => "FAILED",
                CheckResult::NotRun => "not run",
            };
            format!("{} {res}", format!("{:?}", c.check).to_lowercase())
        })
        .collect();
    let body = match &ctx.body.json_error {
        Some(e) => format!("Its public answer says \"{e}\"; that text does not identify which check failed."),
        None => "Its public answer does not say why.".to_string(),
    };
    let mut d =
        Draft::new("auth.jwt_svid_rejected", "auth.jwt_svid", Confidence::Unknown, SourceScope::Unknown, Owner::Unknown, Severity::Error)
            .ev_at(E::HttpStatus, "status", "401", idx)
            .var("host", ctx.target_host())
            .var("subject", j.subject.clone().unwrap_or_else(|| "an unknown subject".into()))
            .var("audiences", if j.audiences.is_empty() { "none".into() } else { j.audiences.join(", ") })
            .var("expires", j.expires_at.map(|e| e.to_rfc3339()).unwrap_or_else(|| "no expiry".into()))
            .var("checks", checks.join(", "))
            .var("body", body);
    for v in r.header_values("www-authenticate") {
        d = d.ev_at(E::HttpHeader, "header.www-authenticate", v.to_string(), idx);
    }
    if let Some(e) = &ctx.body.json_error {
        d = d.ev_at(E::BodyContent, "body.error", e.clone(), idx);
    }
    d = jwt_evidence(d, j);
    for c in j.failed_checks() {
        d = d.alt(format!("Anvil's own {} check had failed before sending: {}.", format!("{:?}", c.check).to_lowercase(), c.detail));
    }
    if j.check(JwtSvidCheckKind::Signature).is_some_and(|c| c.result == CheckResult::Passed) {
        d = d.not_proven("That the token's signature is invalid: it verified against the Workload API's JWT bundle.");
    }
    out.push(d);
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    local_failures(ctx, out);
    jwt_checks(ctx, out);
    rejected(ctx, out);
}
