//! Gateway diagnostic references (G01). Findings come only from what the
//! engine's lookup established ([`GatewayDetail`]); the response header alone
//! is never gateway evidence. A record that binds to this response is the only
//! Ferrum evidence that can be `confirmed`, and only when both the request and
//! the lookup travelled over verified TLS or a direct loopback connection.
//! Every other outcome is reported with its own, lower confidence, and the
//! public-marker findings keep theirs for comparison.

use super::Ctx;
use crate::Draft;
use crate::facts::FerrumTrust;
use crate::gateway_detail::{Detail, GatewayDetail, LookupOutcome, Mismatch, RefView, direct_loopback, unknown_error_classes};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};

const RULE: &str = "ferrum.detail";
const REF_KEY: &str = "header.x-ferrum-diagnostic-ref";

/// What a resolved record says happened.
enum Kind {
    /// No detail is recorded: only the gateway's authorship is known.
    Authored,
    /// A plugin, a gateway policy or routing refused the request.
    Rejected,
    /// The gateway classified a failure (an error class or a route timeout).
    Failure,
    /// A backend answered and the gateway relayed its outcome.
    BackendResponse,
}

fn kind(view: &RefView) -> Kind {
    let Some(d) = &view.detail else { return Kind::Authored };
    if d.rejection.is_some() || d.rejection_phase.is_some() {
        Kind::Rejected
    } else if d.error_class.is_some() || d.body_error_class.is_some() || d.route_timeout_phase.is_some() {
        Kind::Failure
    } else if d.backend_dispatch == "backend_response" {
        Kind::BackendResponse
    } else {
        Kind::Authored
    }
}

fn scope_owner(d: Option<&Detail>, kind: &Kind) -> (SourceScope, Owner) {
    let Some(d) = d else { return (SourceScope::Unknown, Owner::GatewayOperator) };
    match kind {
        Kind::Authored => (SourceScope::Unknown, Owner::GatewayOperator),
        Kind::Rejected => match d.rejection.as_ref().map(|r| r.source.as_str()) {
            // A plugin decision may be about the caller's credentials or the
            // operator's policy; a route miss about the URL or the routes.
            Some("plugin" | "routing") => (SourceScope::GatewayAdmission, Owner::Unknown),
            _ => (SourceScope::GatewayAdmission, Owner::GatewayOperator),
        },
        Kind::Failure => match d.error_class.as_deref() {
            Some("client_disconnect") => (SourceScope::ClientToPeer, Owner::Caller),
            Some("request_body_too_large") => (SourceScope::GatewayAdmission, Owner::Caller),
            Some(_) => (SourceScope::GatewayToUpstream, Owner::GatewayOperator),
            None if d.body_error_class.is_some() => (SourceScope::ResponseDelivery, Owner::GatewayOperator),
            None if d.route_timeout_phase.as_deref() == Some("dispatch") => (SourceScope::GatewayToUpstream, Owner::GatewayOperator),
            None => (SourceScope::GatewayAdmission, Owner::Unknown),
        },
        Kind::BackendResponse => (SourceScope::UpstreamApplication, Owner::ApiOwner),
    }
}

/// The refusing policy, from the record's closed labels.
fn rejection_text(d: &Detail) -> String {
    match (&d.rejection, &d.rejection_phase) {
        (Some(r), _) => match (r.source.as_str(), &r.plugin) {
            ("plugin", Some(p)) => format!("the {p} plugin, in its {} phase", r.phase),
            ("plugin", None) => format!("a plugin, in its {} phase", r.phase),
            ("routing", _) => format!("routing ({})", r.phase),
            _ => format!("the gateway policy {}", r.phase),
        },
        (None, Some(p)) => format!("the gateway's admission control ({p})"),
        (None, None) => "the gateway".into(),
    }
}

/// The classified failure, from the record's closed labels.
fn failure_text(d: &Detail) -> String {
    let mut parts = Vec::new();
    if let Some(c) = &d.error_class {
        let tls = d.attempts.iter().rev().find_map(|a| a.tls.as_ref());
        let tls = tls.map(|t| format!(" ({}{})", t.failure, t.reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default()));
        parts.push(format!("error class {c}{}", tls.unwrap_or_default()));
    }
    if let Some(c) = &d.body_error_class {
        parts.push(format!("response body error class {c}"));
    }
    if let Some(p) = &d.route_timeout_phase {
        parts.push(format!("the route's request timeout, in its {p} phase"));
    }
    parts.join(", with ")
}

fn attempt_text(a: &crate::gateway_detail::Attempt) -> String {
    let mut s = format!("{} {}", a.attempt, a.backend_dispatch);
    if let Some(status) = a.status {
        s.push_str(&format!(" {status}"));
    }
    if let Some(c) = &a.error_class {
        s.push_str(&format!(" {c}"));
    }
    s
}

/// How far the request reached a backend, as the gateway recorded it.
fn dispatch_text(d: &Detail) -> String {
    let what = match d.backend_dispatch.as_str() {
        "not_dispatched" => "no backend attempt was made",
        "pre_wire_failure" => "the final attempt failed before any request byte reached a backend",
        "ambiguous_failure" => "the final attempt failed after the request may have reached a backend",
        _ => "a backend answered",
    };
    let mut s = format!("Backend dispatch ({}): {what}.", d.backend_dispatch);
    if !d.attempts.is_empty() {
        let list: Vec<String> = d.attempts.iter().map(attempt_text).collect();
        s.push_str(&format!(" Attempts: {}.", list.join("; ")));
    }
    if d.attempts_omitted > 0 {
        s.push_str(&format!(" {} later attempt(s) are not listed.", d.attempts_omitted));
    }
    s
}

/// The record's fields as gateway-detail evidence.
fn with_record(mut d: Draft, view: &RefView) -> Draft {
    d = d
        .ev(E::GatewayDetail, "detail.ref", view.reference.clone())
        .ev(E::GatewayDetail, "detail.namespace", view.namespace.clone())
        .ev(E::GatewayDetail, "detail.created_at", view.created_at.clone())
        .ev(E::GatewayDetail, "detail.protocol", view.protocol.clone())
        .ev(E::GatewayDetail, "detail.status", view.status.to_string())
        .ev(E::GatewayDetail, "detail.gateway_error", view.gateway_error.clone().unwrap_or_else(|| "none".into()));
    if let Some(r) = &view.replica_id {
        d = d.ev(E::GatewayDetail, "detail.replica_id", r.clone());
    }
    let Some(x) = &view.detail else { return d };
    d = d.ev(E::GatewayDetail, "detail.backend_dispatch", x.backend_dispatch.clone());
    let optional = [
        ("detail.error_class", &x.error_class),
        ("detail.body_error_class", &x.body_error_class),
        ("detail.rejection_phase", &x.rejection_phase),
        ("detail.route_timeout_phase", &x.route_timeout_phase),
        ("detail.proxy_id", &x.proxy_id),
        ("detail.backend_target", &x.backend_target),
    ];
    for (key, value) in optional {
        if let Some(v) = value {
            d = d.ev(E::GatewayDetail, key, v.clone());
        }
    }
    if let Some(r) = &x.rejection {
        let plugin = r.plugin.as_deref().map(|p| format!(" {p}")).unwrap_or_default();
        d = d.ev(E::GatewayDetail, "detail.rejection", format!("{} {}{plugin}", r.source, r.phase));
    }
    if !x.attempts.is_empty() {
        d = d.ev(E::GatewayDetail, "detail.attempts", x.attempts.iter().map(attempt_text).collect::<Vec<_>>().join("; "));
    }
    d.ev(E::GatewayDetail, "detail.duration_bucket", x.duration_bucket.clone())
}

fn resolved(view: &RefView, ceiling: Confidence, status: u16) -> Draft {
    // An error class outside the pinned vocabulary is shown, never confirmed.
    let unknown = unknown_error_classes(view);
    let ceiling = if unknown.is_empty() { ceiling } else { ceiling.min(Confidence::Likely) };
    let k = kind(view);
    let (scope, owner) = scope_owner(view.detail.as_ref(), &k);
    let code = match k {
        Kind::Authored => "ferrum.detail.authored",
        Kind::Rejected => "ferrum.detail.rejected",
        Kind::Failure => "ferrum.detail.failure",
        Kind::BackendResponse => "ferrum.detail.backend_response",
    };
    let mut d = with_record(Draft::new(code, RULE, ceiling, scope, owner, Severity::Error), view)
        .var("status", status.to_string())
        .var("namespace", view.namespace.clone())
        .var("token", view.gateway_error.clone().unwrap_or_else(|| "no X-Gateway-Error value".into()));
    if let Some(x) = &view.detail {
        d = d.var("rejection", rejection_text(x)).var("cause", failure_text(x)).var("dispatch", dispatch_text(x));
        // TRUST-008: the final attempt's dispatch says nothing about earlier ones.
        let reached: Vec<String> =
            x.attempts.iter().filter(|a| a.backend_dispatch != "pre_wire_failure").map(|a| a.attempt.to_string()).collect();
        if !reached.is_empty() && matches!(x.backend_dispatch.as_str(), "not_dispatched" | "pre_wire_failure") {
            d = d.not_proven(format!(
                "That no backend received this request: attempt {} reached a backend before the final attempt failed.",
                reached.join(", ")
            ));
        }
    }
    if !unknown.is_empty() {
        d = d.not_proven(format!(
            "What error class {} means: it is not in the Ferrum Edge vocabulary this Anvil build pins.",
            unknown.join(", ")
        ));
    } else if ceiling < Confidence::Confirmed {
        d = d.not_proven(
            "That only the gateway could have answered this record: the request or its lookup did not use verified TLS or loopback.",
        );
    }
    d
}

fn mismatch(m: &Mismatch) -> Draft {
    Draft::new(
        "ferrum.detail.mismatch",
        RULE,
        Confidence::ConflictingEvidence,
        SourceScope::Unknown,
        Owner::GatewayOperator,
        Severity::Warning,
    )
    .ev(E::HttpStatus, "detail.lookup.status", "200")
    .ev(E::BodyContent, "detail.mismatch", format!("{}: record {}, response {}", m.field, m.record, m.response))
    .var("field", m.field)
    .var("record", m.record.clone())
    .var("response", m.response.clone())
}

fn refused(status: u16, lookup_authenticated: bool) -> Draft {
    // The refusal is observed; whether the gateway sent it depends on the lookup channel.
    let confidence = if lookup_authenticated { Confidence::Confirmed } else { Confidence::Likely };
    Draft::new("ferrum.detail.refused", RULE, confidence, SourceScope::Unknown, Owner::Caller, Severity::Warning)
        .ev(E::HttpStatus, "detail.lookup.status", status.to_string())
        .var("lookup_status", status.to_string())
}

fn unavailable(owner_replica: Option<&str>) -> Draft {
    let mut d = Draft::new("ferrum.detail.unavailable", RULE, Confidence::Unknown, SourceScope::Unknown, Owner::Unknown, Severity::Warning)
        .ev(E::HttpStatus, "detail.lookup.status", "404");
    if let Some(owner) = owner_replica {
        d = d
            .ev(E::HttpHeader, "detail.owner_replica", owner)
            .alt(format!("The gateway named replica {owner} as the one that minted this reference: send the lookup to that replica."));
    }
    d
}

fn rate_limited() -> Draft {
    lookup_failed("the gateway's lookup rate limit refused it (429)").ev(E::HttpStatus, "detail.lookup.status", "429")
}

fn lookup_failed(reason: &str) -> Draft {
    Draft::new("ferrum.detail.lookup_failed", RULE, Confidence::Unknown, SourceScope::Unknown, Owner::Unknown, Severity::Warning)
        .var("reason", reason.to_string())
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let (Some(detail), Some(r)) = (ctx.input.gateway_detail, ctx.input.response) else { return };
    let FerrumTrust::Trusted { channel_authenticated: data_verified, profile_name, .. } = ctx.input.trust else { return };
    let idx = ctx.attempt_index();
    let (reference, endpoint, lookup_authenticated, outcome) = match detail {
        GatewayDetail::Looked { reference, endpoint, channel_authenticated: lookup, outcome } => (reference, endpoint, *lookup, outcome),
        GatewayDetail::InvalidReference { value } => {
            out.push(
                Draft::new(
                    "ferrum.detail.invalid_reference",
                    RULE,
                    Confidence::Unknown,
                    SourceScope::Unknown,
                    Owner::Unknown,
                    Severity::Warning,
                )
                .ev_at(E::HttpHeader, REF_KEY, value.clone(), idx)
                .var("value", value.clone())
                .var("profile", profile_name.clone()),
            );
            return;
        }
        GatewayDetail::NoReference => {
            // Worth a note only on a response the gateway marked as its own error.
            if !r.header_values("x-gateway-error").is_empty() {
                out.push(
                    Draft::new(
                        "ferrum.detail.no_reference",
                        RULE,
                        Confidence::Unknown,
                        SourceScope::Unknown,
                        Owner::GatewayOperator,
                        Severity::Info,
                    )
                    .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
                    .var("status", r.status.to_string())
                    .var("profile", profile_name.clone()),
                );
            }
            return;
        }
    };
    // The record is the gateway's own only when nothing else could have
    // answered on either path: verified TLS, or a direct loopback connection.
    let data_authenticated = *data_verified || ctx.final_attempt().and_then(|a| a.connection.as_ref()).is_some_and(direct_loopback);
    let ceiling = if data_authenticated && lookup_authenticated { Confidence::Confirmed } else { Confidence::Likely };
    let draft = match outcome {
        LookupOutcome::Resolved(view) => resolved(view, ceiling, r.status),
        LookupOutcome::Mismatch(m) => mismatch(m),
        LookupOutcome::Refused { status } => refused(*status, lookup_authenticated),
        LookupOutcome::NotFound { owner_replica } => unavailable(owner_replica.as_deref()),
        LookupOutcome::RateLimited => rate_limited(),
        LookupOutcome::Failed { reason } => lookup_failed(reason),
    };
    out.push(
        draft
            .ev_at(E::HttpHeader, REF_KEY, reference.clone(), idx)
            .ev(E::Configuration, "integration.detail.endpoint", endpoint.clone())
            .var("ref", reference.clone())
            .var("endpoint", endpoint.clone())
            .var("profile", profile_name.clone()),
    );
}

#[cfg(test)]
mod tests {
    use crate::facts::{DiagnosticInput, FerrumTrust};
    use crate::gateway_detail::{GatewayDetail, LookupOutcome, Mismatch, parse_view};
    use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, EvidenceSource, Owner, SourceScope};
    use anvil_domain::execution::*;
    use anvil_domain::outcome::ProtocolStatus;
    use anvil_domain::request::Protocol;

    const REF: &str = "fd1_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f";

    fn response(status: u16, token: Option<&str>) -> ResponseRecord {
        let mut headers = vec![HeaderEntry { name: "x-ferrum-diagnostic-ref".into(), value: REF.into() }];
        if let Some(t) = token {
            headers.push(HeaderEntry { name: "x-gateway-error".into(), value: t.into() });
        }
        ResponseRecord {
            status,
            reason: None,
            http_version: "HTTP/1.1".into(),
            headers,
            trailers: vec![],
            trailers_received: false,
            body: BodyCapture {
                completeness: BodyCompleteness::Complete,
                wire_bytes: 0,
                declared_length: None,
                captured_bytes: 0,
                display_truncated: false,
                content_type: Some("application/json".into()),
                content_encoding: None,
                decoded_bytes: None,
                decoding: None,
                decoding_detail: None,
                blob_sha256: None,
            },
        }
    }

    fn attempt(remote: &str) -> AttemptObservation {
        AttemptObservation {
            index: 0,
            reason: AttemptReason::Initial,
            method: "GET".into(),
            url: "http://gateway.example/orders".into(),
            started_at: chrono::Utc::now(),
            connection: Some(ConnectionObservation {
                id: 1,
                reused: false,
                protocol: Some("http/1.1".into()),
                local_address: None,
                remote_address: Some(remote.into()),
                resolved_addresses: vec![],
                resolution_source: None,
                connect_attempts: vec![],
                via_proxy: None,
                tls: None,
                prior_requests: 0,
                proxy_header: None,
                tunnel: None,
            }),
            phases: vec![],
            dispatch: DispatchState::Sent,
            bytes: ByteCounts::default(),
            response_status: Some(502),
            failure: None,
            duration_us: 1000,
            early_data: None,
        }
    }

    fn diagnose(r: &ResponseRecord, remote: &str, detail: Option<&GatewayDetail>, trusted: bool) -> Vec<DiagnosticFinding> {
        let trust = if trusted {
            FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: "ferrum-edge-0.9.9".into(), channel_authenticated: false }
        } else {
            FerrumTrust::NotConfigured
        };
        let ps = ProtocolStatus::Http { status: r.status, reason: None };
        let attempts = [attempt(remote)];
        crate::diagnose(&DiagnosticInput {
            protocol: Protocol::Http,
            method: "POST",
            preparation_failure: None,
            attempts: &attempts,
            response: Some(r),
            body: br#"{"error":"Bad Gateway"}"#,
            stream: None,
            protocol_status: &ps,
            trust: &trust,
            tls_verification_enabled: true,
            credentials_stripped_on_redirect: false,
            protocol_fallback_from: None,
            workload: None,
            gateway_detail: detail,
            redact: None,
        })
        .findings
    }

    fn record(body: &str) -> GatewayDetail {
        let view = parse_view(body.as_bytes()).expect("valid record");
        looked(LookupOutcome::Resolved(Box::new(view)), true)
    }

    fn looked(outcome: LookupOutcome, channel_authenticated: bool) -> GatewayDetail {
        GatewayDetail::Looked { reference: REF.into(), endpoint: "http://127.0.0.1:18090".into(), channel_authenticated, outcome }
    }

    fn refused_record() -> String {
        let now = chrono::Utc::now().to_rfc3339();
        format!(
            r#"{{"schema_version":"ferrum.diagnostic_ref.v1","ref":"{REF}","namespace":"ferrum","created_at":"{now}","expires_at":"2099-01-01T00:00:00Z","protocol":"http1","status":502,"gateway_error":"connection_failure","detail_available":true,"detail":{{"error_class":"tls_error","body_error_class":null,"rejection_phase":null,"route_timeout_phase":null,"backend_dispatch":"pre_wire_failure","proxy_id":"orders","backend_target":"https://orders.internal:8443","duration_bucket":"lt_1s","attempts":[{{"attempt":1,"backend_dispatch":"backend_response","status":503}},{{"attempt":2,"backend_dispatch":"pre_wire_failure","error_class":"tls_error","tls":{{"failure":"certificate_verification","reason":"expired"}}}}]}}}}"#
        )
    }

    fn find<'a>(f: &'a [DiagnosticFinding], code: &str) -> &'a DiagnosticFinding {
        f.iter().find(|x| x.code == code).unwrap_or_else(|| panic!("no {code}: {:?}", f.iter().map(|x| &x.code).collect::<Vec<_>>()))
    }

    fn detail_findings(f: &[DiagnosticFinding]) -> Vec<&DiagnosticFinding> {
        f.iter().filter(|x| x.code.starts_with("ferrum.detail.")).collect()
    }

    /// A bound record over direct loopback on both legs is the gateway's own
    /// evidence: confirmed, with the record cited as gateway detail, while the
    /// public token keeps its own capped confidence.
    #[test]
    fn a_bound_record_is_confirmed_gateway_evidence() {
        let r = response(502, Some("connection_failure"));
        let f = diagnose(&r, "127.0.0.1:18080", Some(&record(&refused_record())), true);
        let d = find(&f, "ferrum.detail.failure");
        assert_eq!(d.confidence, Confidence::Confirmed);
        assert_eq!(d.scope, SourceScope::GatewayToUpstream);
        assert_eq!(d.owner, Owner::GatewayOperator);
        assert!(d.explanation.contains("tls_error (certificate_verification: expired)"), "{}", d.explanation);
        assert!(d.explanation.contains(REF), "{}", d.explanation);
        let class = d.evidence.iter().find(|e| e.key == "detail.error_class").expect("error class evidence");
        assert_eq!((class.source, class.value.as_str()), (EvidenceSource::GatewayDetail, "tls_error"));
        assert!(d.evidence.iter().any(|e| e.source == EvidenceSource::HttpHeader && e.value == REF));
        // TRUST-008: attempt 1 got a backend response, so the final pre-wire failure proves nothing about side effects.
        assert!(d.does_not_prove.iter().any(|x| x.contains("attempt 1 reached a backend")), "{:?}", d.does_not_prove);
        assert_eq!(find(&f, "ferrum.token.connection_failure").confidence, Confidence::Likely);
    }

    /// Off loopback and without verified TLS, the same record is capped at likely.
    #[test]
    fn an_unauthenticated_path_caps_the_record_at_likely() {
        let r = response(502, Some("connection_failure"));
        let f = diagnose(&r, "192.0.2.10:8080", Some(&record(&refused_record())), true);
        let d = find(&f, "ferrum.detail.failure");
        assert_eq!(d.confidence, Confidence::Likely);
        assert!(d.does_not_prove.iter().any(|x| x.contains("verified TLS")), "{:?}", d.does_not_prove);
        let unauthenticated_lookup = match record(&refused_record()) {
            GatewayDetail::Looked { outcome, .. } => looked(outcome, false),
            other => other,
        };
        let f = diagnose(&r, "127.0.0.1:18080", Some(&unauthenticated_lookup), true);
        assert_eq!(find(&f, "ferrum.detail.failure").confidence, Confidence::Likely);
    }

    /// TRUST-009/010/011: refused, unknown, expired or mismatched lookups never
    /// produce gateway-detail evidence and never raise anything above likely.
    #[test]
    fn failed_lookups_never_raise_confidence() {
        let r = response(502, Some("connection_failure"));
        let mismatch = Mismatch { field: "status", response: "502".into(), record: "503".into() };
        for (outcome, code) in [
            (LookupOutcome::Refused { status: 403 }, "ferrum.detail.refused"),
            (LookupOutcome::NotFound { owner_replica: None }, "ferrum.detail.unavailable"),
            (LookupOutcome::NotFound { owner_replica: Some("1a2b3c4d".into()) }, "ferrum.detail.unavailable"),
            (LookupOutcome::RateLimited, "ferrum.detail.lookup_failed"),
            (LookupOutcome::Failed { reason: "connection refused".into() }, "ferrum.detail.lookup_failed"),
            (LookupOutcome::Mismatch(mismatch), "ferrum.detail.mismatch"),
        ] {
            let f = diagnose(&r, "127.0.0.1:18080", Some(&looked(outcome.clone(), true)), true);
            let d = find(&f, code);
            assert!(d.explanation.contains(REF), "{code}: {}", d.explanation);
            assert!(
                !f.iter().flat_map(|x| &x.evidence).any(|e| e.source == EvidenceSource::GatewayDetail),
                "{outcome:?}: gateway-detail evidence without a bound record"
            );
            assert!(
                !f.iter().any(|x| x.code.starts_with("ferrum.") && x.code != "ferrum.detail.refused" && x.confidence > Confidence::Likely),
                "{outcome:?}: {:?}",
                f.iter().map(|x| (&x.code, x.confidence)).collect::<Vec<_>>()
            );
            assert_eq!(find(&f, "ferrum.token.connection_failure").confidence, Confidence::Likely, "public evidence is kept");
        }
        let hinted = looked(LookupOutcome::NotFound { owner_replica: Some("1a2b3c4d".into()) }, true);
        let f = diagnose(&r, "127.0.0.1:18080", Some(&hinted), true);
        assert!(find(&f, "ferrum.detail.unavailable").alternatives.iter().any(|a| a.contains("1a2b3c4d")));
    }

    #[test]
    fn missing_or_malformed_references_are_reported_not_used() {
        let r = response(502, Some("connection_failure"));
        let f = diagnose(&r, "127.0.0.1:18080", Some(&GatewayDetail::NoReference), true);
        assert_eq!(find(&f, "ferrum.detail.no_reference").confidence, Confidence::Unknown);
        // No note on a response the gateway did not mark.
        let f = diagnose(&response(404, None), "127.0.0.1:18080", Some(&GatewayDetail::NoReference), true);
        assert!(detail_findings(&f).is_empty());
        let invalid = GatewayDetail::InvalidReference { value: "not-a-ref".into() };
        let f = diagnose(&r, "127.0.0.1:18080", Some(&invalid), true);
        assert_eq!(find(&f, "ferrum.detail.invalid_reference").confidence, Confidence::Unknown);
    }

    /// An error class outside the pinned vocabulary is never confirmed.
    #[test]
    fn an_unknown_error_class_is_capped_at_likely() {
        let r = response(502, Some("connection_failure"));
        let f = diagnose(&r, "127.0.0.1:18080", Some(&record(&refused_record().replace("tls_error", "quantum_tunnel_collapse"))), true);
        let d = find(&f, "ferrum.detail.failure");
        assert_eq!(d.confidence, Confidence::Likely);
        assert!(d.does_not_prove.iter().any(|x| x.contains("quantum_tunnel_collapse")), "{:?}", d.does_not_prove);
    }

    /// An untrusted destination never gets a detail finding, even with a lookup outcome.
    #[test]
    fn an_untrusted_destination_gets_no_detail_finding() {
        let r = response(502, Some("connection_failure"));
        let f = diagnose(&r, "127.0.0.1:18080", Some(&record(&refused_record())), false);
        assert!(detail_findings(&f).is_empty());
    }

    #[test]
    fn a_rejection_record_names_the_refusing_policy() {
        let now = chrono::Utc::now().to_rfc3339();
        let body = format!(
            r#"{{"schema_version":"ferrum.diagnostic_ref.v1","ref":"{REF}","namespace":"ferrum","created_at":"{now}","expires_at":"2099-01-01T00:00:00Z","protocol":"http1","status":401,"gateway_error":null,"detail_available":true,"detail":{{"error_class":null,"body_error_class":null,"rejection_phase":null,"route_timeout_phase":null,"backend_dispatch":"not_dispatched","proxy_id":"orders","backend_target":null,"duration_bucket":"lt_10ms","rejection":{{"source":"plugin","phase":"authenticate","plugin":"key_auth"}}}}}}"#
        );
        let f = diagnose(&response(401, None), "127.0.0.1:18080", Some(&record(&body)), true);
        let d = find(&f, "ferrum.detail.rejected");
        assert_eq!(d.confidence, Confidence::Confirmed);
        assert_eq!(d.scope, SourceScope::GatewayAdmission);
        assert!(d.explanation.contains("the key_auth plugin, in its authenticate phase"), "{}", d.explanation);
    }
}
