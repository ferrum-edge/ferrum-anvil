//! Assembles the authoritative [`ExecutionRecord`]: outcome dimensions,
//! diagnosis, assertions, extraction and redaction.

use crate::ExecutionOutput;
use crate::assertions::{self, Observed};
use crate::context::ExecutionContext;
use crate::redact::Redactor;
use crate::vars::Resolver;
use anvil_diagnostics::{DiagnosticInput, FerrumTrust};
use anvil_domain::Id;
use anvil_domain::execution::*;
use anvil_domain::outcome::*;
use anvil_domain::settings::EffectiveSettings;
use anvil_transport::decode::{self, DecodeOutcome};
use anvil_transport::http::AttemptOutput;
use bytes::Bytes;
use chrono::{DateTime, Utc};

pub struct Assembly<'a> {
    pub ctx: &'a ExecutionContext,
    pub started_at: DateTime<Utc>,
    pub prepared_method: String,
    pub prepared_url: String,
    pub prepared_headers: Vec<(String, String)>,
    pub prepared_body: Bytes,
    pub content_type: Option<String>,
    pub auth_label: String,
    pub auth_facts: Vec<(String, String)>,
    pub settings: EffectiveSettings,
    pub tls_profile: Option<String>,
    pub proxy: Option<String>,
    pub tls_verification_enabled: bool,
    pub inferred: Vec<String>,
    pub lint_bypassed: Option<String>,
    pub attempts: Vec<AttemptObservation>,
    pub last: AttemptOutput,
    pub trust: FerrumTrust,
    pub credentials_stripped: bool,
    pub protocol_fallback_from: Option<String>,
    pub redactor: &'a Redactor,
    pub extra_findings: Vec<anvil_diagnostics::Draft>,
    pub stream: Option<StreamTranscript>,
    pub protocol_status_override: Option<ProtocolStatus>,
}

fn redact_attempts(attempts: &mut [AttemptObservation], r: &Redactor) {
    for a in attempts {
        a.url = r.url(&a.url);
        if let Some(f) = &mut a.failure {
            f.message = r.text(&f.message);
        }
        if let Some(t) = a.connection.as_mut().and_then(|c| c.tunnel.as_mut()) {
            if let Some(f) = &mut t.failure {
                f.message = r.text(&f.message);
            }
            if let Some(b) = &mut t.refusal_body {
                *b = r.text(b);
            }
            // A CONNECT-UDP request carries the request's auth headers.
            for h in t.connect_headers.iter_mut().chain(t.response_headers.iter_mut()) {
                h.value = r.header(&h.name, &h.value);
            }
        }
    }
}

pub fn protocol_status_http(resp: Option<&ResponseRecord>) -> ProtocolStatus {
    match resp {
        Some(r) => ProtocolStatus::Http { status: r.status, reason: r.reason.clone() },
        None => ProtocolStatus::None,
    }
}

pub fn assemble(a: Assembly<'_>) -> ExecutionOutput {
    let Assembly { ctx, started_at, mut attempts, last, redactor, .. } = a;
    let response = last.response.clone();
    let raw_body = last.body.clone();
    // Decode for display/assertions; the raw captured bytes stay the evidence.
    let decoded: Option<Bytes> = match &response {
        Some(r) if a.settings.decompress => {
            match decode::decode(r.body.content_encoding.as_deref(), &raw_body, a.settings.limits.max_decoded_bytes) {
                DecodeOutcome::Decoded { bytes, .. } => Some(Bytes::from(bytes)),
                _ => None,
            }
        }
        _ => None,
    };
    let body_for_eval: &[u8] = decoded.as_deref().unwrap_or(&raw_body);
    let mut response = response;
    if let (Some(r), Some(d)) = (response.as_mut(), decoded.as_ref()) {
        r.body.decoded_bytes = Some(d.len() as u64);
    }

    let protocol_status = a.protocol_status_override.clone().unwrap_or_else(|| protocol_status_http(response.as_ref()));
    let final_attempt = attempts.last();
    let transport = if a.stream.is_some() {
        // An opened session (WebSocket, gRPC stream, SSE, TCP, UDP) ends on its
        // own terms — close handshake, stop condition, peer end — so its
        // completion comes from the session outcome, not HTTP body framing.
        match final_attempt.and_then(|x| x.failure.as_ref()) {
            None => TransportState::Completed,
            Some(f) if f.kind == FailureKind::Canceled => TransportState::Canceled,
            Some(_) => TransportState::Incomplete,
        }
    } else {
        match (&response, final_attempt.and_then(|x| x.failure.as_ref())) {
            (None, Some(f)) if f.kind == FailureKind::Canceled => TransportState::Canceled,
            (None, _) => TransportState::Failed,
            (Some(r), _) => match r.body.completeness {
                BodyCompleteness::Complete | BodyCompleteness::NoBody => TransportState::Completed,
                BodyCompleteness::Canceled => TransportState::Canceled,
                BodyCompleteness::Incomplete | BodyCompleteness::StoppedAtLocalLimit => TransportState::Incomplete,
            },
        }
    };
    let transport = match (&protocol_status, transport) {
        (ProtocolStatus::Grpc { source: GrpcStatusSource::Missing, .. }, TransportState::Completed) => TransportState::Incomplete,
        (_, t) => t,
    };

    let diag_input = DiagnosticInput {
        protocol: ctx.spec.protocol,
        method: &a.prepared_method,
        preparation_failure: None,
        attempts: &attempts,
        response: response.as_ref(),
        body: body_for_eval,
        stream: a.stream.as_ref(),
        protocol_status: &protocol_status,
        trust: &a.trust,
        tls_verification_enabled: a.tls_verification_enabled,
        credentials_stripped_on_redirect: a.credentials_stripped,
        protocol_fallback_from: a.protocol_fallback_from.clone(),
    };
    let mut diagnosis = anvil_diagnostics::diagnose(&diag_input);
    for d in a.extra_findings {
        diagnosis.findings.push(anvil_diagnostics::render::render(d));
    }
    let body_complete =
        response.as_ref().map(|r| matches!(r.body.completeness, BodyCompleteness::Complete | BodyCompleteness::NoBody)).unwrap_or(false);
    // A redirect into an interactive login (AUTH-017) never evaluated the API,
    // even when the login page itself answered 200.
    let application = if diagnosis.stopped_at_login {
        ApplicationState::NotEvaluated
    } else {
        anvil_diagnostics::assess_application(ctx.spec.protocol, &protocol_status, &diagnosis.body, body_complete)
    };
    let mut warnings = diagnosis.warnings.clone();
    if let Some(l) = &a.lint_bypassed {
        warnings.push(OutcomeWarning { code: WarningCode::LintBypassed, message: format!("Sent despite a lint error: {l}") });
    }

    let latency_ms = final_attempt.map(|x| x.duration_us / 1000);
    let assertion_results = assertions::evaluate(
        &ctx.spec.assertions,
        &Observed {
            response: response.as_ref(),
            body: body_for_eval,
            latency_ms,
            protocol_status: &protocol_status,
            stream: a.stream.as_ref(),
            findings: &diagnosis.findings,
            transport,
        },
        redactor,
    );
    let assertion_state = if ctx.spec.assertions.iter().all(|x| !x.enabled) {
        AssertionState::NotRun
    } else if assertion_results.iter().all(|r| r.passed) {
        AssertionState::Pass
    } else {
        AssertionState::Fail
    };

    let mut extracted = Vec::new();
    let mut extracted_values = Vec::new();
    for r in assertions::extract(&ctx.spec.extractions, response.as_ref(), body_for_eval) {
        match r {
            Ok((name, value, sensitive)) => {
                extracted.push(name.clone());
                extracted_values.push((name, value, sensitive));
            }
            Err(e) => warnings.push(OutcomeWarning { code: WarningCode::PartialVisibility, message: e }),
        }
    }

    let dispatch = DispatchState::summarize(attempts.iter().map(|x| x.dispatch));
    let summary = summary_line(transport, application, &protocol_status, &diagnosis.findings);
    redact_attempts(&mut attempts, redactor);
    let mut findings = diagnosis.findings;
    for f in &mut findings {
        f.explanation = redactor.text(&f.explanation);
        for e in &mut f.evidence {
            e.value = redactor.text(&e.value);
        }
    }
    if let Some(r) = response.as_mut() {
        r.headers = redactor.headers(&r.headers);
        r.trailers = redactor.headers(&r.trailers);
    }
    let prepared_headers: Vec<HeaderEntry> =
        a.prepared_headers.iter().map(|(n, v)| HeaderEntry { name: n.clone(), value: redactor.header(n, v) }).collect();
    let mut inferred = a.inferred.clone();
    for (k, v) in &a.auth_facts {
        inferred.push(format!("auth {k}: {v}"));
    }
    let record = ExecutionRecord {
        id: Id::new(),
        schema_version: anvil_domain::SCHEMA_VERSION,
        adapter_version: anvil_transport::ADAPTER_VERSION.to_string(),
        catalog_version: anvil_diagnostics::catalog_version_for(&a.trust),
        compatibility_id: match &a.trust {
            FerrumTrust::Trusted { compatibility_id, .. } => Some(compatibility_id.clone()),
            _ => None,
        },
        workspace_id: ctx.workspace_id,
        request_id: ctx.request_id,
        revision_id: ctx.revision_id,
        environment_id: ctx.environment_id,
        started_at,
        finished_at: Utc::now(),
        prepared: PreparedSummary {
            protocol: ctx.spec.protocol,
            method: a.prepared_method.clone(),
            url: redactor.url(&a.prepared_url),
            headers: prepared_headers,
            body_bytes: a.prepared_body.len() as u64,
            body_sha256: if a.prepared_body.is_empty() { None } else { Some(anvil_transport::certs::sha256_hex(&a.prepared_body)) },
            content_type: a.content_type.clone(),
            auth_label: a.auth_label.clone(),
            tls_profile: a.tls_profile.clone(),
            proxy: a.proxy.clone(),
            tls_verification_enabled: a.tls_verification_enabled,
            settings: a.settings.clone(),
            inferred,
            omitted_secrets: vec![],
        },
        attempts,
        response,
        stream: a.stream,
        outcome: ExecutionOutcome {
            transport,
            application,
            assertions: assertion_state,
            completeness: None,
            protocol_status,
            dispatch,
            warnings,
            summary,
        },
        assertion_results,
        extracted,
        findings,
    };
    let mut record = record;
    record.outcome.completeness = record.response.as_ref().map(|r| r.body.completeness);
    ExecutionOutput { record, body: raw_body, decoded_body: decoded, extracted: extracted_values, session_facts: None }
}

pub fn summary_line(
    t: TransportState,
    app: ApplicationState,
    ps: &ProtocolStatus,
    findings: &[anvil_domain::diagnostics::DiagnosticFinding],
) -> String {
    let status = match ps {
        ProtocolStatus::Http { status, reason } => format!("HTTP {status} {}", reason.clone().unwrap_or_default()).trim().to_string(),
        ProtocolStatus::Grpc { grpc_status, .. } => {
            format!("gRPC status {}", grpc_status.map(|g| g.to_string()).unwrap_or_else(|| "missing".into()))
        }
        ProtocolStatus::WebSocket { close_code, .. } => {
            format!("WebSocket close {}", close_code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()))
        }
        ProtocolStatus::Sse { http_status, events, .. } => format!("SSE {http_status}, {events} events"),
        ProtocolStatus::Tcp { bytes_received, .. } => format!("TCP, {bytes_received} bytes received"),
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, .. } => format!("UDP {datagrams_received}/{datagrams_sent} responses"),
        ProtocolStatus::None => "no response".into(),
    };
    let transport = match t {
        TransportState::Completed => "completed",
        TransportState::Failed => "failed",
        TransportState::Incomplete => "incomplete",
        TransportState::Canceled => "canceled",
        TransportState::Unknown => "unknown",
    };
    let application = match app {
        ApplicationState::Success => "success",
        ApplicationState::Failure => "failure",
        ApplicationState::NotEvaluated => "not evaluated",
    };
    let top = findings.iter().find(|f| f.severity >= anvil_domain::diagnostics::Severity::Warning).map(|f| f.title.clone());
    match top {
        Some(t0) => format!("{status} — transport {transport}, application {application}: {t0}"),
        None => format!("{status} — transport {transport}, application {application}"),
    }
}

/// Record for a local preparation failure (nothing was sent).
pub fn local_failure(ctx: &ExecutionContext, resolver: &Resolver, started_at: DateTime<Utc>, f: TransportFailure) -> ExecutionOutput {
    let redactor = Redactor::new(resolver.used_secrets.lock().clone(), ctx.redaction_names.clone());
    let mut f = f;
    f.message = redactor.text(&f.message);
    let ps = ProtocolStatus::None;
    let diag = anvil_diagnostics::diagnose(&DiagnosticInput {
        protocol: ctx.spec.protocol,
        method: &ctx.spec.method,
        preparation_failure: Some(&f),
        attempts: &[],
        response: None,
        body: &[],
        stream: None,
        protocol_status: &ps,
        trust: &FerrumTrust::NotConfigured,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
    });
    let settings = crate::settings::resolve(&ctx.settings_layers);
    let summary = diag.findings.first().map(|x| x.title.clone()).unwrap_or_else(|| "Not sent".into());
    let record = ExecutionRecord {
        id: Id::new(),
        schema_version: anvil_domain::SCHEMA_VERSION,
        adapter_version: anvil_transport::ADAPTER_VERSION.to_string(),
        catalog_version: anvil_diagnostics::catalog_version_for(&FerrumTrust::NotConfigured),
        compatibility_id: None,
        workspace_id: ctx.workspace_id,
        request_id: ctx.request_id,
        revision_id: ctx.revision_id,
        environment_id: ctx.environment_id,
        started_at,
        finished_at: Utc::now(),
        prepared: PreparedSummary {
            protocol: ctx.spec.protocol,
            method: ctx.spec.method.clone(),
            url: redactor.url(&ctx.spec.url),
            headers: vec![],
            body_bytes: 0,
            body_sha256: None,
            content_type: None,
            auth_label: "not prepared".into(),
            tls_profile: None,
            proxy: None,
            tls_verification_enabled: true,
            settings,
            inferred: vec![],
            omitted_secrets: vec![],
        },
        attempts: vec![AttemptObservation {
            index: 0,
            reason: AttemptReason::Initial,
            method: ctx.spec.method.clone(),
            url: redactor.url(&ctx.spec.url),
            started_at,
            connection: None,
            phases: vec![PhaseTiming {
                phase: Phase::Prepare,
                status: PhaseStatus::Failed,
                start_us: Some(0),
                end_us: Some(0),
                detail: f.field.clone(),
            }],
            dispatch: DispatchState::NotDispatched,
            bytes: ByteCounts::default(),
            response_status: None,
            failure: Some(f),
            duration_us: 0,
        }],
        response: None,
        stream: None,
        outcome: ExecutionOutcome {
            transport: TransportState::Failed,
            application: ApplicationState::NotEvaluated,
            assertions: AssertionState::NotRun,
            completeness: None,
            protocol_status: ps,
            dispatch: DispatchState::NotDispatched,
            warnings: diag.warnings,
            summary: format!("Not sent — {summary}"),
        },
        assertion_results: vec![],
        extracted: vec![],
        findings: diag.findings,
    };
    ExecutionOutput { record, body: Bytes::new(), decoded_body: None, extracted: vec![], session_facts: None }
}
