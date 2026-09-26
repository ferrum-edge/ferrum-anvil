//! Scenarios for the `streams` gateway profile: every protocol Anvil
//! advertises, exercised *through the real Ferrum Edge gateway* (HTTP/1.1,
//! HTTP/2 over TLS and h2c, HTTP/3 over the gateway's QUIC listener,
//! WebSocket bootstraps, gRPC call modes and failures, SSE, TCP, TCP+TLS,
//! UDP and DTLS stream proxies).
//!
//! Public-evidence mode: Anvil sees only what a client sees. Fixture logs and
//! the gateway's operator log are independent ground truth and are never
//! given to the engine. A graceful WebSocket close is not a failure; UDP
//! silence is "no response observed"; an HTTP 200 can carry a failed or
//! missing gRPC status.

use crate::fixtures_streams::StreamsFixtures;
use crate::gateway::Gateway;
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::Id;
use anvil_domain::diagnostics::Confidence;
use anvil_domain::execution::{
    AttemptObservation, AttemptReason, Direction, DispatchState, FailureKind, Phase, PhaseStatus, TlsVerification,
};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::{ApplicationState, ClosedBy, GrpcStatusSource, ProtocolStatus, TransportState, WarningCode};
use anvil_domain::request::*;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{HostBinding, TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::GroundTruth;
use anvil_transport::recorder::EventCtx;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub const HTTP: &str = "127.0.0.1:18480";
pub const HTTPS: &str = "127.0.0.1:18443";
const ADMIN_PORT: u16 = 18490;
/// TCP-only relay to 18443 (no QUIC listener behind it).
const UDP_BLOCKED: &str = "127.0.0.1:19420";
/// Every listener of this gateway (HTTP, HTTPS/QUIC, stream proxies).
const GATEWAY_PORTS: &[u16] = &[18480, 18443, 18401, 18402, 18403, 18404, 18405, 18406, 18407, 18408, 18409];

pub struct Env {
    pub engine: Engine,
    pub fx: StreamsFixtures,
    pub gateway: Gateway,
    pub trusted: bool,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<std::path::PathBuf> {
        vec![self.gateway.log_path.clone()]
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

// ------------------------------------------------------------ contexts ---

fn ferrum_profile() -> IntegrationProfile {
    IntegrationProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab streams gateway".into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: GATEWAY_PORTS.iter().map(|p| HostBinding { host: "127.0.0.1".into(), port: Some(*p) }).collect(),
            compatibility_id: "ferrum-edge-0.9.5".into(),
            require_verified_tls: false,
            detail: None,
            console_url: None,
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn tls_profile(root_pem: &str) -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab streams trust".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![root_pem.to_string()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn fast() -> TimeoutOverrides {
    TimeoutOverrides {
        connect_ms: Some(Some(3_000)),
        tls_handshake_ms: Some(Some(3_000)),
        response_headers_ms: Some(Some(8_000)),
        total_ms: Some(Some(20_000)),
        ..Default::default()
    }
}

/// A request context. TLS URLs trust only the per-run lab root (verification on).
fn ctx_with(env: &Env, spec: RequestSpec, root_pem: Option<&str>, version: Option<HttpVersionPolicy>) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    c.isolation = "lab-streams".into();
    if env.trusted {
        c.integrations.push(ferrum_profile());
    }
    let mut run = SettingsOverrides { timeouts: Some(fast()), http_version: version, ..Default::default() };
    if let Some(root) = root_pem {
        let p = tls_profile(root);
        run.tls_profile_id = Some(p.id);
        c.tls_profiles.push(p);
    }
    c.settings_layers.push(("run".into(), run));
    c
}

fn lab_root(env: &Env) -> Option<&str> {
    Some(env.fx.pki.ca.cert.as_str())
}

fn http_ctx(env: &Env, method: &str, url: &str, version: Option<HttpVersionPolicy>) -> ExecutionContext {
    let tls = url.starts_with("https://");
    ctx_with(env, RequestSpec::http(method, url), if tls { lab_root(env) } else { None }, version)
}

fn spec(protocol: Protocol, url: &str) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = protocol;
    s
}

fn ws_ctx(env: &Env, url: &str, bootstrap: WsBootstrap, messages: &[&str], idle_close_ms: u64) -> ExecutionContext {
    let mut s = spec(Protocol::WebSocket, url);
    s.websocket = Some(WsSpec {
        bootstrap,
        subprotocols: vec![],
        messages: messages.iter().map(|m| WsMessage::Text { text: m.to_string() }).collect(),
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms,
    });
    let tls = url.starts_with("wss://");
    ctx_with(env, s, if tls { lab_root(env) } else { None }, None)
}

fn echo_proto() -> AttachmentRef {
    AttachmentRef::LinkedFile { path: crate::gateway::repo_root().join("lab/proto/echo.proto").display().to_string() }
}

fn grpc_ctx(env: &Env, url: &str, method: &str, mode: GrpcMode, messages: &[&str], deadline_ms: Option<u64>) -> ExecutionContext {
    let mut s = spec(Protocol::Grpc, url);
    s.method = "POST".into();
    s.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: method.into(),
        mode,
        schema: GrpcSchemaSource::ProtoFiles { files: vec![echo_proto()] },
        messages: messages.iter().map(|m| m.to_string()).collect(),
        metadata: vec![],
        deadline_ms,
        plaintext: false,
    });
    let tls = url.starts_with("grpcs://") || url.starts_with("https://");
    ctx_with(env, s, if tls { lab_root(env) } else { None }, None)
}

fn sse_ctx(env: &Env, url: &str, max_events: u32, idle_timeout_ms: u64, last_event_id: Option<&str>) -> ExecutionContext {
    let mut s = spec(Protocol::Sse, url);
    s.sse = Some(SseSpec { max_events, idle_timeout_ms, last_event_id: last_event_id.map(|s| s.to_string()), reconnect: false });
    ctx_with(env, s, None, None)
}

fn tcp_ctx(env: &Env, url: &str, framing: TcpFraming, payloads: &[&str], half_close: bool, expect_frames: u32) -> ExecutionContext {
    let tls = url.starts_with("tls://");
    let mut s = spec(Protocol::Tcp, url);
    s.tcp = Some(TcpSpec {
        tls,
        framing,
        payloads: payloads.iter().map(|p| StreamPayload { data: p.to_string(), encoding: PayloadEncoding::Text }).collect(),
        half_close_after_send: half_close,
        read_idle_ms: 2_000,
        max_read_bytes: 64 * 1024,
        expect_frames,
    });
    ctx_with(env, s, if tls { lab_root(env) } else { None }, None)
}

fn udp_ctx(env: &Env, url: &str, datagrams: &[&str], window_ms: u64, root_pem: Option<&str>) -> ExecutionContext {
    let mut s = spec(Protocol::Udp, url);
    s.udp = Some(UdpSpec {
        dtls: url.starts_with("dtls://"),
        datagrams: datagrams.iter().map(|d| StreamPayload { data: d.to_string(), encoding: PayloadEncoding::Text }).collect(),
        response_window_ms: window_ms,
        max_datagrams: 100,
    });
    ctx_with(env, s, root_pem, None)
}

/// Drop pooled HTTP/1.1, HTTP/2 and HTTP/3 connections so a scenario measures
/// fresh handshakes (the untrusted pass would otherwise reuse the trusted
/// pass's connections).
fn fresh_connections(env: &Env) {
    env.engine.http.pool.clear();
    env.engine.h3.clear();
}

async fn send(env: &Env, c: &ExecutionContext) -> ExecutionOutput {
    env.engine.execute(c, EventCtx::none(), CancellationToken::new()).await
}

// ------------------------------------------------------ observation helpers ---

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn last(o: &ExecutionOutput) -> Option<&AttemptObservation> {
    o.record.attempts.last()
}

fn failure_kind(o: &ExecutionOutput) -> Option<FailureKind> {
    last(o).and_then(|a| a.failure.as_ref()).map(|f| f.kind)
}

fn previews(o: &ExecutionOutput, dir: Direction, kind: &str) -> Vec<String> {
    o.record
        .stream
        .as_ref()
        .map(|s| s.messages.iter().filter(|m| m.direction == dir && m.kind == kind).map(|m| m.preview.clone()).collect())
        .unwrap_or_default()
}

fn grpc_status(o: &ExecutionOutput) -> (Option<u16>, Option<i32>, Option<GrpcStatusSource>, String) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Grpc { http_status, grpc_status, grpc_message, source } => {
            (*http_status, *grpc_status, Some(*source), grpc_message.clone().unwrap_or_default())
        }
        _ => (o.record.response.as_ref().map(|r| r.status), None, None, String::new()),
    }
}

fn ws_status(o: &ExecutionOutput) -> (Option<u16>, Option<u16>, Option<ClosedBy>) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { handshake_status, close_code, closed_by, .. } => (*handshake_status, *close_code, Some(*closed_by)),
        _ => (None, None, None),
    }
}

fn tls_verified(o: &ExecutionOutput) -> bool {
    last(o)
        .and_then(|a| a.connection.as_ref())
        .and_then(|c| c.tls.as_ref())
        .map(|t| matches!(t.verification, TlsVerification::Verified))
        .unwrap_or(false)
}

fn header(o: &ExecutionOutput, name: &str) -> Vec<String> {
    o.record.response.as_ref().map(|r| r.header_values(name).iter().map(|s| s.to_string()).collect()).unwrap_or_default()
}

fn outcome_line(o: &ExecutionOutput) -> String {
    format!(
        "transport={:?} application={:?} status={:?} failure={:?} findings={:?}",
        o.record.outcome.transport,
        o.record.outcome.application,
        o.record.outcome.protocol_status,
        failure_kind(o),
        codes(o)
    )
}

fn is_success(o: &ExecutionOutput) -> bool {
    o.record.outcome.transport == TransportState::Completed && o.record.outcome.application == ApplicationState::Success
}

/// New operator-log lines for `proxy_id` since line `from`.
fn op_log(env: &Env, from: usize, proxy_id: &str) -> Vec<String> {
    env.gateway.log_lines().into_iter().skip(from).filter(|l| l.contains(&format!("\"proxy_id\":\"{proxy_id}\""))).take(10).collect()
}

fn op_from(env: &Env) -> usize {
    env.gateway.log_lines().len()
}

/// Operator-side ground truth: the gateway's transaction log recorded `status`.
fn operator_status(c: &mut Checks, lines: &[String], status: u16) {
    let seen: Vec<u64> = lines
        .iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("response_status_code").and_then(|s| s.as_u64()))
        .collect();
    c.add(
        CheckKind::GroundTruth,
        format!("gateway operator log records status {status}"),
        seen.contains(&u64::from(status)),
        format!("{seen:?}"),
    );
}

/// A finding (other than generic HTTP status meanings) that attributes the
/// failure to the client's own TLS leg.
fn no_client_tls_claim(c: &mut Checks, o: &ExecutionOutput) {
    c.absent_prefix(o, "client.tls");
    c.absent_prefix(o, "client.connect");
}

fn datagrams(log: &anvil_fixtures::GroundTruthLog) -> usize {
    log.entries().iter().filter(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })).count()
}

fn bytes_received(log: &anvil_fixtures::GroundTruthLog) -> u64 {
    log.entries()
        .iter()
        .filter_map(|e| match e.event {
            GroundTruth::MessageReceived { bytes } => Some(bytes),
            _ => None,
        })
        .sum()
}

fn fault_applied(log: &anvil_fixtures::GroundTruthLog, fault: &str) -> bool {
    log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: fault.into() })
}

fn connections(log: &anvil_fixtures::GroundTruthLog) -> usize {
    log.entries().iter().filter(|e| matches!(e.event, GroundTruth::ConnectionAccepted { .. })).count()
}

// ------------------------------------------------------------ recoveries ---

async fn grpc_recovery(env: &Env, c: &mut Checks) -> ExecutionOutput {
    let r = send(env, &grpc_ctx(env, &format!("grpc://{HTTP}"), "Unary", GrpcMode::Unary, &[r#"{"message":"recovered"}"#], None)).await;
    let (_, st, _, _) = grpc_status(&r);
    c.add(CheckKind::Recovery, "healthy gRPC route returns grpc-status 0", st == Some(0) && is_success(&r), outcome_line(&r));
    r
}

async fn udp_recovery(env: &Env, c: &mut Checks) -> ExecutionOutput {
    let r = send(env, &udp_ctx(env, "udp://127.0.0.1:18404", &["r0", "r1"], 600, None)).await;
    c.add(
        CheckKind::Recovery,
        "UDP echo through the gateway answers every datagram",
        previews(&r, Direction::Received, "datagram") == vec!["r0", "r1"],
        outcome_line(&r),
    );
    r
}

async fn tcp_recovery(env: &Env, c: &mut Checks) -> ExecutionOutput {
    let r = send(env, &tcp_ctx(env, "tcp://127.0.0.1:18408", TcpFraming::NewlineDelimited, &["ok"], false, 1)).await;
    c.add(CheckKind::Recovery, "TCP echo through the gateway", previews(&r, Direction::Received, "frame") == vec!["ok"], outcome_line(&r));
    r
}

// ----------------------------------------------------------- HTTP family ---

fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = env.fx.echo.log.count_requests();
        let o = send(env, &http_ctx(env, "GET", &format!("http://{HTTP}/proto/http/echo"), None)).await;
        c.success(CheckKind::Diagnosis, &o);
        c.absent_prefix(&o, "ferrum.token");
        c.add(CheckKind::GroundTruth, "backend received the request", env.fx.echo.log.count_requests() > before, "");
        let alt = header(&o, "alt-svc");
        c.add(
            CheckKind::GroundTruth,
            "gateway advertises its HTTP/3 listener (Alt-Svc h3=\":18443\")",
            alt.iter().any(|v| v.contains("h3=\":18443\"")),
            format!("{alt:?}"),
        );
        operator_status(&mut c, &op_log(env, from, "proto-http-echo"), 200);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: op_log(env, from, "proto-http-echo") }
    })
}

fn proto001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let from = op_from(env);
        let url = format!("http://{HTTP}/proto/http/echo?keepalive=1");
        let first = send(env, &http_ctx(env, "GET", &url, Some(HttpVersionPolicy::Http1Only))).await;
        let o = send(env, &http_ctx(env, "GET", &url, Some(HttpVersionPolicy::Http1Only))).await;
        c.success(CheckKind::Diagnosis, &first);
        c.success(CheckKind::Diagnosis, &o);
        let conn = last(&o).and_then(|a| a.connection.clone());
        let first_conn = last(&first).and_then(|a| a.connection.clone());
        c.add(
            CheckKind::Diagnosis,
            "second request is recorded on a reused connection",
            conn.as_ref().map(|x| x.reused && x.prior_requests >= 1).unwrap_or(false),
            format!("{conn:?}"),
        );
        let connect = last(&o).and_then(|a| a.phase(Phase::Connect)).map(|p| p.status);
        let dns = last(&o).and_then(|a| a.phase(Phase::Dns)).map(|p| p.status);
        c.add(
            CheckKind::Diagnosis,
            "no fresh DNS/TCP timing is invented for the reused connection",
            !matches!(connect, Some(PhaseStatus::Completed)) && !matches!(dns, Some(PhaseStatus::Completed)),
            format!("connect={connect:?} dns={dns:?}"),
        );
        c.add(
            CheckKind::GroundTruth,
            "both requests used the same client socket (local address)",
            conn.as_ref().and_then(|x| x.local_address.clone()).is_some()
                && conn.as_ref().and_then(|x| x.local_address.clone()) == first_conn.as_ref().and_then(|x| x.local_address.clone()),
            format!("{:?} vs {:?}", first_conn.and_then(|x| x.local_address), conn.as_ref().and_then(|x| x.local_address.clone())),
        );
        let lines = op_log(env, from, "proto-http-echo");
        c.add(CheckKind::GroundTruth, "gateway logged both requests", lines.len() >= 2, format!("{} lines", lines.len()));
        Outcome { main: Some(o), recovery: Some(first), checks: c, operator_log: lines }
    })
}

fn proto002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let trailers_of = |o: &ExecutionOutput| -> Vec<(String, String)> {
            o.record.response.as_ref().map(|r| r.trailers.iter().map(|h| (h.name.clone(), h.value.clone())).collect()).unwrap_or_default()
        };
        // Through the gateway: h2 over TLS on the client leg and on the upstream leg.
        let mut x = http_ctx(env, "GET", &format!("https://{HTTPS}/proto/h2/trailers"), Some(HttpVersionPolicy::Http2Only));
        x.spec.headers.push(KeyValue::new("te", "trailers"));
        let o = send(env, &x).await;
        c.success(CheckKind::Diagnosis, &o);
        let r = o.record.response.as_ref();
        c.add(
            CheckKind::Diagnosis,
            "response recorded as HTTP/2 over verified TLS (ALPN h2)",
            r.map(|r| r.http_version == "HTTP/2").unwrap_or(false)
                && tls_verified(&o)
                && last(&o).and_then(|a| a.connection.as_ref()).and_then(|x| x.tls.as_ref()).and_then(|t| t.alpn_negotiated.clone())
                    == Some("h2".into()),
            format!("{:?}", r.map(|r| &r.http_version)),
        );
        let got = trailers_of(&o);
        c.add(
            CheckKind::Diagnosis,
            "Anvil reports exactly the trailers that arrived (none are invented)",
            r.map(|r| r.trailers_received == !got.is_empty()).unwrap_or(false)
                && got.iter().all(|(n, v)| (n == "x-checksum" && v == "abc123") || (n == "x-fixture-complete" && v == "true")),
            format!("received={:?} trailers={got:?}", r.map(|r| r.trailers_received)),
        );
        c.add(
            CheckKind::GroundTruth,
            "the h2 backend produced the body and its trailers",
            env.fx.h2_tls.log.requests().iter().any(|(_, p)| p == "/trailers"),
            "",
        );
        let echo = send(env, &http_ctx(env, "GET", &format!("https://{HTTPS}/proto/h2/echo"), Some(HttpVersionPolicy::Http2Only))).await;
        let body = String::from_utf8_lossy(&echo.body).to_string();
        c.add(
            CheckKind::GroundTruth,
            "the gateway's upstream leg was HTTP/2 as well",
            body.contains(r#""version":"HTTP/2.0""#),
            body.chars().take(120).collect::<String>(),
        );
        operator_status(&mut c, &op_log(env, from, "proto002-h2-trailers"), 200);
        // Positive control: directly against the backend, Anvil preserves both trailers.
        let d = send(env, &http_ctx(env, "GET", "https://127.0.0.1:19417/trailers", Some(HttpVersionPolicy::Http2Only))).await;
        let dt = trailers_of(&d);
        c.add(
            CheckKind::Recovery,
            "direct to the backend: trailers preserved after a complete body",
            is_success(&d)
                && d.record.response.as_ref().map(|r| r.trailers_received).unwrap_or(false)
                && dt.contains(&("x-checksum".into(), "abc123".into())),
            format!("{dt:?}"),
        );
        // Recorded observation (not a pass/fail criterion): does 0.9.5 relay plain-HTTP/2 trailers?
        c.add(
            CheckKind::GroundTruth,
            if got.is_empty() {
                "observed: this gateway did not relay the backend's plain-HTTP/2 response trailers"
            } else {
                "observed: this gateway relayed the backend's plain-HTTP/2 response trailers"
            },
            true,
            format!("through gateway: {got:?}; direct: {dt:?}"),
        );
        Outcome { main: Some(o), recovery: Some(d), checks: c, operator_log: op_log(env, from, "proto002-h2-trailers") }
    })
}

fn proto005(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        // Stimulus: cleartext HTTP/2 (prior knowledge) against the gateway's TLS-only port.
        let o = send(env, &http_ctx(env, "GET", &format!("http://{HTTPS}/proto/http/echo"), Some(HttpVersionPolicy::H2c))).await;
        c.add(CheckKind::Diagnosis, "h2c against a TLS listener is not a response", o.record.response.is_none(), outcome_line(&o));
        c.not_success(&o);
        let tls_phase = last(&o).and_then(|a| a.phase(Phase::TlsHandshake)).map(|p| p.status);
        c.add(
            CheckKind::Diagnosis,
            "no TLS handshake is claimed for a cleartext attempt",
            matches!(tls_phase, None | Some(PhaseStatus::NotApplicable))
                && last(&o).and_then(|a| a.connection.as_ref()).map(|x| x.tls.is_none()).unwrap_or(true)
                && !codes(&o).iter().any(|x| x.starts_with("client.tls") || x.starts_with("tls.")),
            format!("tls phase {tls_phase:?}; {:?}", codes(&o)),
        );
        // The TLS listener answers the preface with a TLS alert and/or closes. Anvil's own h2
        // library rejecting those bytes is a protocol mismatch, not the server sending GOAWAY.
        c.has_any(
            &o,
            &["exchange.protocol_error", "exchange.closed_before_response", "exchange.reset_before_response", "exchange.write_failed"],
        );
        c.absent_prefix(&o, "exchange.h2_goaway");
        c.absent_prefix(&o, "ferrum.");
        // Recovery: h2c against the gateway's cleartext listener (which speaks h2c).
        let r = send(env, &http_ctx(env, "GET", &format!("http://{HTTP}/proto/http/echo"), Some(HttpVersionPolicy::H2c))).await;
        c.success(CheckKind::Recovery, &r);
        c.add(
            CheckKind::Recovery,
            "h2c exchange recorded as HTTP/2",
            r.record.response.as_ref().map(|x| x.http_version == "HTTP/2").unwrap_or(false),
            format!("{:?}", r.record.response.as_ref().map(|x| &x.http_version)),
        );
        let body = String::from_utf8_lossy(&r.body).to_string();
        c.add(
            CheckKind::GroundTruth,
            "the gateway's upstream leg stayed HTTP/1.1 (per-leg protocols differ)",
            body.contains("\"version\":\"HTTP/1.1\""),
            body.chars().take(200).collect::<String>(),
        );
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn quic_phases_ok(c: &mut Checks, o: &ExecutionOutput) {
    let a = last(o);
    let conn = a.and_then(|a| a.connection.as_ref());
    c.add(
        CheckKind::Diagnosis,
        "negotiated h3 over QUIC (ALPN h3, verified)",
        conn.and_then(|x| x.protocol.clone()) == Some("h3".into())
            && conn.and_then(|x| x.tls.as_ref()).and_then(|t| t.alpn_negotiated.clone()) == Some("h3".into())
            && tls_verified(o),
        format!("{:?}", conn.map(|x| (&x.protocol, x.tls.as_ref().map(|t| &t.alpn_negotiated)))),
    );
    c.add(
        CheckKind::Diagnosis,
        "QUIC handshake measured; no TCP connect or TCP-TLS phase claimed",
        a.and_then(|a| a.phase(Phase::QuicHandshake)).map(|p| p.status) == Some(PhaseStatus::Completed)
            && a.and_then(|a| a.phase(Phase::Connect)).map(|p| p.status) == Some(PhaseStatus::NotApplicable)
            && a.and_then(|a| a.phase(Phase::TlsHandshake)).is_none(),
        format!("{:?}", a.map(|a| a.phases.iter().map(|p| (p.phase, p.status)).collect::<Vec<_>>())),
    );
}

fn proto006(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let from = op_from(env);
        let before = env.fx.echo.log.count_requests();
        let o = send(env, &http_ctx(env, "GET", &format!("https://{HTTPS}/proto/h3/echo"), Some(HttpVersionPolicy::Http3Only))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(CheckKind::Diagnosis, "single attempt (forced H3 never adds TCP)", o.record.attempts.len() == 1, "");
        quic_phases_ok(&mut c, &o);
        c.add(
            CheckKind::Diagnosis,
            "response recorded as HTTP/3",
            o.record.response.as_ref().map(|r| r.http_version == "HTTP/3").unwrap_or(false),
            "",
        );
        c.add(CheckKind::GroundTruth, "backend received the request relayed from QUIC", env.fx.echo.log.count_requests() > before, "");
        operator_status(&mut c, &op_log(env, from, "proto006-h3-echo"), 200);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: op_log(env, from, "proto006-h3-echo") }
    })
}

fn h3_blocked_ctx(env: &Env, policy: HttpVersionPolicy) -> ExecutionContext {
    let mut x = http_ctx(env, "GET", &format!("https://{UDP_BLOCKED}/proto/h3/echo"), Some(policy));
    let mut t = fast();
    t.tls_handshake_ms = Some(Some(800));
    x.settings_layers.push(("scenario".into(), SettingsOverrides { timeouts: Some(t), ..Default::default() }));
    x
}

fn proto007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let relay_before = env.fx.udp_blocked_path.connections();
        let o = send(env, &h3_blocked_ctx(env, HttpVersionPolicy::Http3Only)).await;
        c.add(
            CheckKind::Diagnosis,
            "forced H3 over a UDP-blocked path fails as a QUIC handshake timeout",
            failure_kind(&o) == Some(FailureKind::QuicHandshakeTimeout) && o.record.attempts.len() == 1,
            outcome_line(&o),
        );
        c.has(&o, "client.quic.handshake_timeout");
        c.add(CheckKind::Diagnosis, "no response is claimed", o.record.response.is_none(), "");
        c.absent_prefix(&o, "ferrum.");
        c.add(
            CheckKind::GroundTruth,
            "no silent TCP fallback: the TCP path to the gateway saw no connection",
            env.fx.udp_blocked_path.connections() == relay_before,
            format!("{} → {}", relay_before, env.fx.udp_blocked_path.connections()),
        );
        // Recovery: forced H3 on the path where UDP reaches the gateway.
        let r = send(env, &http_ctx(env, "GET", &format!("https://{HTTPS}/proto/h3/echo"), Some(HttpVersionPolicy::Http3Only))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn proto008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let from = op_from(env);
        let relay_before = env.fx.udp_blocked_path.connections();
        let o = send(env, &h3_blocked_ctx(env, HttpVersionPolicy::Http3WithFallback)).await;
        c.success(CheckKind::Diagnosis, &o);
        let atts = &o.record.attempts;
        c.add(
            CheckKind::Diagnosis,
            "both attempts recorded: failed H3, then a protocol fallback",
            atts.len() == 2
                && atts[0].failure.as_ref().map(|f| f.kind) == Some(FailureKind::QuicHandshakeTimeout)
                && atts[1].reason == AttemptReason::ProtocolFallback { from: "h3".into() },
            format!("{:?}", atts.iter().map(|a| (&a.reason, a.failure.as_ref().map(|f| f.kind))).collect::<Vec<_>>()),
        );
        c.add(
            CheckKind::Diagnosis,
            "H3 is not claimed for the final response",
            o.record.response.as_ref().map(|r| r.http_version != "HTTP/3").unwrap_or(false),
            format!("{:?}", o.record.response.as_ref().map(|r| &r.http_version)),
        );
        c.has(&o, "client.h3.fallback_used");
        c.add(
            CheckKind::Diagnosis,
            "protocol_fallback warning",
            o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::ProtocolFallback),
            "",
        );
        c.add(
            CheckKind::GroundTruth,
            "the fallback travelled the TCP path to the gateway",
            env.fx.udp_blocked_path.connections() > relay_before,
            "",
        );
        operator_status(&mut c, &op_log(env, from, "proto006-h3-echo"), 200);
        // Recovery / contrast: the same policy where UDP reaches the gateway uses H3 with no fallback.
        let r =
            send(env, &http_ctx(env, "GET", &format!("https://{HTTPS}/proto/h3/echo"), Some(HttpVersionPolicy::Http3WithFallback))).await;
        c.success(CheckKind::Recovery, &r);
        c.add(
            CheckKind::Recovery,
            "automatic policy uses H3 when the QUIC listener is reachable",
            r.record.attempts.len() == 1 && r.record.response.as_ref().map(|x| x.http_version == "HTTP/3").unwrap_or(false),
            format!("{} attempts", r.record.attempts.len()),
        );
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto006-h3-echo") }
    })
}

// ------------------------------------------------------------- WebSocket ---

async fn ws_recovery(env: &Env, c: &mut Checks) -> ExecutionOutput {
    let r = send(env, &ws_ctx(env, &format!("ws://{HTTP}/ws?close_after=1"), WsBootstrap::Http1Upgrade, &["recover"], 3_000)).await;
    c.add(CheckKind::Recovery, "WebSocket echo through the gateway", is_success(&r), outcome_line(&r));
    r
}

fn proto009(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = bytes_received(&env.fx.ws.log);
        let o =
            send(env, &ws_ctx(env, &format!("ws://{HTTP}/ws?close_after=2"), WsBootstrap::Http1Upgrade, &["alpha", "beta"], 3_000)).await;
        let (hs, code, by) = ws_status(&o);
        c.add(
            CheckKind::Diagnosis,
            "101 handshake, backend's Close 1000 relayed, closed by the peer",
            hs == Some(101) && code == Some(1000) && by == Some(ClosedBy::Peer),
            format!("{hs:?} {code:?} {by:?}"),
        );
        c.success(CheckKind::Diagnosis, &o);
        c.has(&o, "ws.closed_normally");
        c.add(
            CheckKind::Diagnosis,
            "a graceful close is not reported as a fault",
            !codes(&o).iter().any(|x| x.starts_with("exchange.") || x == "ws.closed_abnormally") && failure_kind(&o).is_none(),
            format!("{:?}", codes(&o)),
        );
        c.add(
            CheckKind::Diagnosis,
            "echoed messages kept in order",
            previews(&o, Direction::Received, "text") == vec!["alpha", "beta"],
            format!("{:?}", previews(&o, Direction::Received, "text")),
        );
        c.add(CheckKind::GroundTruth, "backend received both messages", bytes_received(&env.fx.ws.log) >= before + 9, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: op_log(env, from, "proto012-ws-echo") }
    })
}

fn proto009_client_close(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        // No close_after: the backend never closes; Anvil ends the session after its idle period.
        let o = send(env, &ws_ctx(env, &format!("ws://{HTTP}/ws"), WsBootstrap::Http1Upgrade, &["only"], 800)).await;
        let (_, code, by) = ws_status(&o);
        c.add(
            CheckKind::Diagnosis,
            "Anvil closed the session (1000, closed_by client)",
            code == Some(1000) && by == Some(ClosedBy::Client),
            format!("{code:?} {by:?}"),
        );
        c.success(CheckKind::Diagnosis, &o);
        let f = o.record.findings.iter().find(|f| f.code == "ws.closed_normally");
        c.add(
            CheckKind::Diagnosis,
            "the close is not attributed to the peer",
            f.map(|f| !f.explanation.to_lowercase().contains("the peer closed")).unwrap_or(false),
            f.map(|f| f.explanation.clone()).unwrap_or_else(|| format!("{:?}", codes(&o))),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn proto010(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(env, &ws_ctx(env, &format!("ws://{HTTP}/ws?abnormal_after=1"), WsBootstrap::Http1Upgrade, &["only"], 3_000)).await;
        c.add(
            CheckKind::GroundTruth,
            "backend dropped the socket without a Close frame",
            fault_applied(&env.fx.ws.log, "ws_abnormal_drop"),
            "",
        );
        let (_, code, by) = ws_status(&o);
        c.not_success(&o);
        c.add(
            CheckKind::Diagnosis,
            "not reported as a normal close",
            !codes(&o).contains(&"ws.closed_normally".to_string()),
            format!("{:?}", codes(&o)),
        );
        match code {
            Some(1006) | None => {
                c.add(
                    CheckKind::Diagnosis,
                    "1006 is a local designation (closed_by abnormal)",
                    by == Some(ClosedBy::Abnormal),
                    format!("{by:?}"),
                );
                c.has(&o, "ws.closed_abnormally");
                c.add(
                    CheckKind::Diagnosis,
                    "transport incomplete",
                    o.record.outcome.transport == TransportState::Incomplete,
                    format!("{:?}", o.record.outcome.transport),
                );
            }
            Some(other) => {
                // The gateway converted the backend's drop into its own Close frame.
                c.add(
                    CheckKind::Diagnosis,
                    format!("gateway-authored close {other} is recorded as a peer close, not a normal one"),
                    by == Some(ClosedBy::Peer) && other != 1000,
                    format!("{by:?}"),
                );
                c.has_any(&o, &["ws.closed_other", "ws.closed_policy"]);
                let f = o.record.findings.iter().find(|f| f.code == "ws.closed_other" || f.code == "ws.closed_policy");
                c.add(
                    CheckKind::Diagnosis,
                    "the close is not pinned on the backend application (the gateway may have authored it)",
                    f.map(|f| {
                        f.does_not_prove.iter().any(|d| d.contains("Which hop")) || f.alternatives.iter().any(|a| a.contains("gateway"))
                    })
                    .unwrap_or(false),
                    format!("{:?}", f.map(|f| (&f.alternatives, &f.does_not_prove))),
                );
            }
        }
        c.add(
            CheckKind::Diagnosis,
            "the message before the drop is kept",
            previews(&o, Direction::Received, "text") == vec!["only"],
            format!("{:?}", previews(&o, Direction::Received, "text")),
        );
        let r = ws_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto012-ws-echo") }
    })
}

fn ws_h2_checks(c: &mut Checks, o: &ExecutionOutput, label: &str) {
    let a = last(o);
    let (hs, code, _) = ws_status(o);
    c.add(
        CheckKind::Diagnosis,
        format!("{label}: extended CONNECT over h2, 200 bootstrap, normal close"),
        a.map(|a| a.method == "CONNECT").unwrap_or(false)
            && a.and_then(|a| a.connection.as_ref()).and_then(|x| x.protocol.clone()) == Some("h2".into())
            && hs == Some(200)
            && code == Some(1000),
        format!("{:?} {hs:?} {code:?}", a.map(|a| &a.method)),
    );
    c.add(
        CheckKind::Diagnosis,
        format!("{label}: echo received"),
        previews(o, Direction::Received, "text") == vec!["over-h2"],
        format!("{:?}", previews(o, Direction::Received, "text")),
    );
    c.add(CheckKind::Diagnosis, format!("{label}: complete success"), is_success(o), outcome_line(o));
}

fn proto012(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = env.fx.ws.log.requests().len();
        let o = send(env, &ws_ctx(env, &format!("wss://{HTTPS}/ws?close_after=1"), WsBootstrap::Http2ExtendedConnect, &["over-h2"], 3_000))
            .await;
        ws_h2_checks(&mut c, &o, "h2 over TLS");
        c.add(CheckKind::Diagnosis, "TLS to the gateway verified", tls_verified(&o), "");
        let h2c =
            send(env, &ws_ctx(env, &format!("ws://{HTTP}/ws?close_after=1"), WsBootstrap::Http2ExtendedConnect, &["over-h2"], 3_000)).await;
        ws_h2_checks(&mut c, &h2c, "h2c");
        let reqs: Vec<(String, String)> = env.fx.ws.log.requests().into_iter().skip(before).collect();
        c.add(
            CheckKind::GroundTruth,
            "the gateway re-originated both sessions as HTTP/1.1 Upgrade (GET) to the backend",
            reqs.iter().filter(|(m, p)| m == "GET" && p.starts_with("/ws")).count() >= 2 && !reqs.iter().any(|(m, _)| m == "CONNECT"),
            format!("{reqs:?}"),
        );
        Outcome { main: Some(o), recovery: Some(h2c), checks: c, operator_log: op_log(env, from, "proto012-ws-echo") }
    })
}

/// PROTO-013: WebSocket over HTTP/3 (RFC 9220) to the gateway's QUIC
/// listener. Anvil waits for the gateway's SETTINGS_ENABLE_CONNECT_PROTOCOL
/// before sending `:protocol = websocket`; the gateway bridges the session to
/// the backend as an HTTP/1.1 Upgrade.
fn proto013(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = env.fx.ws.log.requests().len();
        let o = send(env, &ws_ctx(env, &format!("wss://{HTTPS}/ws?close_after=1"), WsBootstrap::Http3ExtendedConnect, &["over-h3"], 3_000))
            .await;
        quic_phases_ok(&mut c, &o);
        let a = last(&o);
        let (hs, code, by) = ws_status(&o);
        c.add(
            CheckKind::Diagnosis,
            "extended CONNECT over h3, 200 bootstrap, normal close relayed from the backend",
            a.map(|a| a.method == "CONNECT").unwrap_or(false) && hs == Some(200) && code == Some(1000) && by == Some(ClosedBy::Peer),
            format!("{:?} {hs:?} {code:?} {by:?}", a.map(|a| &a.method)),
        );
        c.add(
            CheckKind::Diagnosis,
            "the gateway's SETTINGS enabled extended CONNECT before anything was sent (RFC 9220 §3)",
            a.map(|a| a.phases.iter().any(|p| p.detail.as_deref().map(|d| d.contains("RFC 9220")).unwrap_or(false))).unwrap_or(false),
            "",
        );
        c.add(
            CheckKind::Diagnosis,
            "echo received",
            previews(&o, Direction::Received, "text") == vec!["over-h3"],
            format!("{:?}", previews(&o, Direction::Received, "text")),
        );
        c.add(CheckKind::Diagnosis, "complete success", is_success(&o), outcome_line(&o));
        c.absent_prefix(&o, "ferrum.token");
        let reqs: Vec<(String, String)> = env.fx.ws.log.requests().into_iter().skip(before).collect();
        c.add(
            CheckKind::GroundTruth,
            "the gateway re-originated the session to the backend as an HTTP/1.1 Upgrade (GET /ws)",
            reqs.iter().filter(|(m, p)| m == "GET" && p.starts_with("/ws")).count() == 1 && !reqs.iter().any(|(m, _)| m == "CONNECT"),
            format!("{reqs:?}"),
        );
        let ops = op_log(env, from, "proto012-ws-echo");
        c.add(
            CheckKind::GroundTruth,
            "the gateway's operator log records an RFC 9220 (HTTP/3) WebSocket upgrade",
            ops.iter().any(|l| l.contains("H3 WebSocket (RFC 9220)")),
            format!("{} lines", ops.len()),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: ops }
    })
}

/// PROTO-013 lookalike: the same session to a path that carries TCP but not
/// UDP. It must fail at the QUIC handshake and never fall back to another
/// bootstrap over TCP.
fn proto013_blocked(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let relay_before = env.fx.udp_blocked_path.connections();
        let backend_before = env.fx.ws.log.requests().len();
        let mut x =
            ws_ctx(env, &format!("wss://{UDP_BLOCKED}/ws?close_after=1"), WsBootstrap::Http3ExtendedConnect, &["never sent"], 3_000);
        let mut t = fast();
        t.tls_handshake_ms = Some(Some(800));
        x.settings_layers.push(("scenario".into(), SettingsOverrides { timeouts: Some(t), ..Default::default() }));
        let o = send(env, &x).await;
        c.add(
            CheckKind::Diagnosis,
            "fails as a QUIC handshake timeout in a single attempt, nothing dispatched",
            failure_kind(&o) == Some(FailureKind::QuicHandshakeTimeout)
                && o.record.attempts.len() == 1
                && o.record.outcome.dispatch == DispatchState::NotDispatched,
            outcome_line(&o),
        );
        c.has(&o, "client.quic.handshake_timeout");
        c.add(CheckKind::Diagnosis, "no session or response is claimed", o.record.stream.is_none() && o.record.response.is_none(), "");
        c.absent_prefix(&o, "ferrum.");
        c.add(
            CheckKind::GroundTruth,
            "no fallback: the TCP path saw no connection and the backend no session",
            env.fx.udp_blocked_path.connections() == relay_before && env.fx.ws.log.requests().len() == backend_before,
            format!("relay {} → {}", relay_before, env.fx.udp_blocked_path.connections()),
        );
        let r = send(env, &ws_ctx(env, &format!("wss://{HTTPS}/ws?close_after=1"), WsBootstrap::Http3ExtendedConnect, &["over-h3"], 3_000))
            .await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

// ------------------------------------------------------------------ gRPC ---

fn proto014(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(env, &grpc_ctx(env, &format!("grpc://{HTTP}"), "Unary", GrpcMode::Unary, &[r#"{"message":"x","failWith":5}"#], None))
            .await;
        let (http, st, src, msg) = grpc_status(&o);
        c.add(
            CheckKind::Diagnosis,
            "HTTP 200 carrying grpc-status 5 in trailers",
            http == Some(200) && st == Some(5) && src == Some(GrpcStatusSource::Trailers),
            format!("{http:?} {st:?} {src:?} {msg}"),
        );
        c.add(
            CheckKind::Diagnosis,
            "transport completed, RPC failed (independent dimensions)",
            o.record.outcome.transport == TransportState::Completed && o.record.outcome.application == ApplicationState::Failure,
            outcome_line(&o),
        );
        c.has(&o, "app.grpc_status");
        c.absent_prefix(&o, "ferrum.token");
        c.add(
            CheckKind::GroundTruth,
            "the backend itself returned the status",
            env.fx.grpc.log.requests().iter().any(|(_, p)| p == "/anvil.lab.v1.Echo/Unary"),
            "",
        );
        operator_status(&mut c, &op_log(env, from, "proto014-grpc"), 200);
        let r = grpc_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto014-grpc") }
    })
}

fn proto014_down(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o =
            send(env, &grpc_ctx(env, &format!("grpc://{HTTP}/grpc-down"), "Unary", GrpcMode::Unary, &[r#"{"message":"x"}"#], None)).await;
        let (http, st, src, msg) = grpc_status(&o);
        c.add(
            CheckKind::Diagnosis,
            "HTTP 200 trailers-only with grpc-status 14 (UNAVAILABLE)",
            http == Some(200) && st == Some(14) && src == Some(GrpcStatusSource::TrailersOnly),
            format!("{http:?} {st:?} {src:?} {msg}"),
        );
        c.add(
            CheckKind::Diagnosis,
            "not an RPC success despite HTTP 200",
            o.record.outcome.application == ApplicationState::Failure,
            outcome_line(&o),
        );
        c.has(&o, "app.grpc_status");
        c.absent_prefix(&o, "ferrum.token");
        c.absent_prefix(&o, "client.connect");
        c.no_confirmed_claim(&o, "refused");
        let f = o.record.findings.iter().find(|f| f.code == "app.grpc_status");
        c.add(
            CheckKind::Diagnosis,
            "the origin of a trailers-only status is left open",
            f.map(|f| f.does_not_prove.iter().any(|d| d.contains("Which component"))).unwrap_or(false),
            "",
        );
        c.operator_class(
            &op_log(env, from, "proto014-grpc-down"),
            "proto014-grpc-down",
            &["connection_refused", "connection_pool_error", "request_error"],
        );
        let r = grpc_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto014-grpc-down") }
    })
}

fn proto015(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let msg = format!(r#"{{"message":"hi","failWith":{}}}"#, anvil_fixtures::grpc::ABORT_WITHOUT_STATUS);
        let o = send(env, &grpc_ctx(env, &format!("grpc://{HTTP}"), "Unary", GrpcMode::Unary, &[&msg], None)).await;
        c.add(
            CheckKind::GroundTruth,
            "backend reset the stream before any grpc-status",
            fault_applied(&env.fx.grpc.log, "grpc_abort_before_status"),
            "",
        );
        let (http, st, src, _) = grpc_status(&o);
        c.add(
            CheckKind::Diagnosis,
            "no terminal status: recorded as missing",
            st.is_none() && src == Some(GrpcStatusSource::Missing),
            format!("{http:?} {st:?} {src:?}"),
        );
        c.add(
            CheckKind::Diagnosis,
            "incomplete transport; the RPC is never a success",
            o.record.outcome.transport == TransportState::Incomplete && o.record.outcome.application != ApplicationState::Success,
            outcome_line(&o),
        );
        c.has(&o, "app.grpc_status_missing");
        c.absent_prefix(&o, "ferrum.token");
        let r = grpc_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto014-grpc") }
    })
}

fn proto016(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let url = format!("grpc://{HTTP}");
        let mut check = |label: &str, o: &ExecutionOutput, want: Vec<&str>| {
            let got = previews(o, Direction::Received, "grpc_message");
            c.add(
                CheckKind::Diagnosis,
                format!("{label}: grpc-status 0 and message boundaries"),
                grpc_status(o).1 == Some(0) && is_success(o) && got == want,
                format!("{got:?} / {}", outcome_line(o)),
            );
        };
        let unary = send(env, &grpc_ctx(env, &url, "Unary", GrpcMode::Unary, &[r#"{"message":"one"}"#], None)).await;
        check("unary", &unary, vec![r#"{"message":"one"}"#]);
        let server =
            send(env, &grpc_ctx(env, &url, "ServerStream", GrpcMode::ServerStreaming, &[r#"{"message":"s","count":3}"#], None)).await;
        check("server streaming", &server, vec![r#"{"message":"s"}"#, r#"{"message":"s","index":1}"#, r#"{"message":"s","index":2}"#]);
        let client = send(
            env,
            &grpc_ctx(
                env,
                &url,
                "ClientStream",
                GrpcMode::ClientStreaming,
                &[r#"{"message":"a"}"#, r#"{"message":"b"}"#, r#"{"message":"c"}"#],
                None,
            ),
        )
        .await;
        check("client streaming", &client, vec![r#"{"message":"3 messages; last=c","index":3}"#]);
        let bidi =
            send(env, &grpc_ctx(env, &url, "Bidi", GrpcMode::Bidirectional, &[r#"{"message":"x"}"#, r#"{"message":"y"}"#], None)).await;
        check("bidirectional", &bidi, vec![r#"{"message":"x"}"#, r#"{"message":"y","index":1}"#]);
        let tls = send(env, &grpc_ctx(env, &format!("grpcs://{HTTPS}"), "Unary", GrpcMode::Unary, &[r#"{"message":"tls"}"#], None)).await;
        check("unary over TLS (grpcs, ALPN h2)", &tls, vec![r#"{"message":"tls"}"#]);
        c.add(CheckKind::Diagnosis, "grpcs leg verified", tls_verified(&tls), "");
        let paths: Vec<String> = env.fx.grpc.log.requests().into_iter().map(|(_, p)| p).collect();
        c.add(
            CheckKind::GroundTruth,
            "backend saw all four call modes",
            ["Unary", "ServerStream", "ClientStream", "Bidi"].iter().all(|m| paths.contains(&format!("/anvil.lab.v1.Echo/{m}"))),
            format!("{paths:?}"),
        );
        Outcome { main: Some(bidi), recovery: Some(server), checks: c, operator_log: op_log(env, from, "proto014-grpc") }
    })
}

fn proto016_deadline(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(
            env,
            &grpc_ctx(
                env,
                &format!("grpc://{HTTP}"),
                "ServerStream",
                GrpcMode::ServerStreaming,
                &[r#"{"message":"slow","count":1000}"#],
                Some(300),
            ),
        )
        .await;
        // Both ends enforce the same 300 ms budget and race: either Anvil's local deadline
        // fires, or the gateway's (after DATA it resets the stream with no trailers). Neither
        // path may produce a DEADLINE_EXCEEDED that was not received.
        let f = last(&o).and_then(|a| a.failure.clone());
        let local = f.as_ref().map(|f| f.kind == FailureKind::TotalTimeout && f.deadline_ms == Some(300)).unwrap_or(false);
        let gateway_reset = f.as_ref().map(|f| f.kind == FailureKind::H2StreamReset).unwrap_or(false);
        c.add(
            CheckKind::Diagnosis,
            "the call ended at the 300 ms deadline (Anvil's local deadline, or the gateway's stream reset)",
            local || gateway_reset,
            format!("{f:?}"),
        );
        c.add(
            CheckKind::GroundTruth,
            if local {
                "observed: Anvil's local deadline fired first"
            } else {
                "observed: the gateway enforced grpc-timeout first (RST_STREAM after DATA)"
            },
            true,
            "",
        );
        let (_, st, src, _) = grpc_status(&o);
        c.add(
            CheckKind::Diagnosis,
            "no DEADLINE_EXCEEDED is invented; the status is missing",
            st.is_none() && src == Some(GrpcStatusSource::Missing),
            format!("{st:?} {src:?}"),
        );
        c.has(&o, "app.grpc_status_missing");
        let n = o.record.stream.as_ref().map(|s| s.received_count).unwrap_or(0);
        c.add(CheckKind::Diagnosis, "messages before the deadline are kept", n > 0 && n < 1000, format!("{n}"));
        c.add(CheckKind::Diagnosis, "incomplete, not success", o.record.outcome.transport == TransportState::Incomplete, outcome_line(&o));
        let hdrs = env.fx.grpc.log.last_request_headers().unwrap_or_default();
        c.add(
            CheckKind::GroundTruth,
            "the gateway forwarded the caller's grpc-timeout to the backend",
            hdrs.iter().any(|(n, _)| n == "grpc-timeout"),
            format!("{:?}", hdrs.iter().filter(|(n, _)| n.starts_with("grpc")).collect::<Vec<_>>()),
        );
        let r = grpc_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto014-grpc") }
    })
}

fn up010_grpc(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = env.fx.grpc_slow.log.count_requests();
        let o =
            send(env, &grpc_ctx(env, &format!("grpc://{HTTP}/grpc-slow"), "Unary", GrpcMode::Unary, &[r#"{"message":"x"}"#], None)).await;
        let (http, st, src, msg) = grpc_status(&o);
        c.add(
            CheckKind::Diagnosis,
            "HTTP 200 trailers-only grpc-status 4 (DEADLINE_EXCEEDED) from the gateway's backend timeout",
            http == Some(200) && st == Some(4) && src == Some(GrpcStatusSource::TrailersOnly),
            format!("{http:?} {st:?} {src:?} {msg}"),
        );
        c.add(
            CheckKind::Diagnosis,
            "no local deadline fired (Anvil sent none)",
            failure_kind(&o).is_none(),
            format!("{:?}", failure_kind(&o)),
        );
        c.has(&o, "app.grpc_status");
        c.add(CheckKind::Diagnosis, "RPC failure", o.record.outcome.application == ApplicationState::Failure, outcome_line(&o));
        c.absent_prefix(&o, "ferrum.token");
        c.add(
            CheckKind::GroundTruth,
            "the backend accepted the call and held its headers",
            env.fx.grpc_slow.log.count_requests() > before,
            "",
        );
        c.operator_class(&op_log(env, from, "proto016-grpc-slow"), "proto016-grpc-slow", &["read_write_timeout"]);
        let r = grpc_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto016-grpc-slow") }
    })
}

// ------------------------------------------------------------------- SSE ---

async fn sse_recovery(env: &Env, c: &mut Checks) -> ExecutionOutput {
    let r = send(env, &sse_ctx(env, &format!("http://{HTTP}/sse?count=3&interval=10"), 0, 3_000, None)).await;
    c.add(
        CheckKind::Recovery,
        "complete event stream through the gateway (3 events, peer end)",
        matches!(r.record.outcome.protocol_status, ProtocolStatus::Sse { events: 3, closed_by: ClosedBy::Peer, .. }) && is_success(&r),
        outcome_line(&r),
    );
    r
}

fn proto018(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            c2.cancel();
        });
        let x = sse_ctx(env, &format!("http://{HTTP}/sse?count=500&interval=20"), 0, 5_000, Some("41"));
        let o = env.engine.execute(&x, EventCtx::none(), cancel).await;
        let events = match &o.record.outcome.protocol_status {
            ProtocolStatus::Sse { http_status: 200, events, closed_by: ClosedBy::Client } => *events,
            _ => 0,
        };
        c.add(CheckKind::Diagnosis, "events received before the explicit cancel", events >= 3, outcome_line(&o));
        c.add(CheckKind::Diagnosis, "transport canceled (not failed)", o.record.outcome.transport == TransportState::Canceled, "");
        c.has(&o, "sse.canceled");
        c.add(
            CheckKind::Diagnosis,
            "a cancel is not a backend timeout",
            !codes(&o).iter().any(|x| x.contains("timeout")),
            format!("{:?}", codes(&o)),
        );
        c.absent_prefix(&o, "ferrum.token");
        let hdrs = env.fx.sse.log.last_request_headers().unwrap_or_default();
        c.add(
            CheckKind::GroundTruth,
            "the gateway forwarded Accept: text/event-stream and Last-Event-ID",
            hdrs.iter().any(|(n, v)| n == "accept" && v == "text/event-stream")
                && hdrs.iter().any(|(n, v)| n == "last-event-id" && v == "41"),
            format!("{hdrs:?}"),
        );
        let r = sse_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto018-sse") }
    })
}

fn proto018_idle(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(env, &sse_ctx(env, &format!("http://{HTTP}/sse?count=2&interval=4000"), 0, 800, None)).await;
        c.add(
            CheckKind::Diagnosis,
            "one event, then the idle limit ended the stream (closed_by timeout)",
            matches!(o.record.outcome.protocol_status, ProtocolStatus::Sse { events: 1, closed_by: ClosedBy::Timeout, .. }),
            outcome_line(&o),
        );
        c.has(&o, "sse.idle_timeout");
        c.add(CheckKind::Diagnosis, "not a user cancel", !codes(&o).contains(&"sse.canceled".to_string()), format!("{:?}", codes(&o)));
        c.no_confirmed_claim(&o, "fail");
        c.absent_prefix(&o, "ferrum.token");
        let r = sse_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto018-sse") }
    })
}

fn trust007_sse(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(env, &sse_ctx(env, &format!("http://{HTTP}/sse-abort/?count=3&interval=20"), 0, 5_000, None)).await;
        c.add(
            CheckKind::GroundTruth,
            "backend aborted its event stream after the events",
            fault_applied(&env.fx.sse_abort.log, "sse_abort_mid_stream"),
            "",
        );
        let (events, by) = match &o.record.outcome.protocol_status {
            ProtocolStatus::Sse { events, closed_by, .. } => (*events, Some(*closed_by)),
            _ => (0, None),
        };
        c.add(CheckKind::Diagnosis, "events before the abort are kept", events == 3, format!("{events}"));
        c.add(CheckKind::Diagnosis, "the end is abnormal, not a peer close", by == Some(ClosedBy::Abnormal), format!("{by:?}"));
        c.add(
            CheckKind::Diagnosis,
            "HTTP 200 + truncated stream is incomplete, not success",
            o.record.outcome.transport == TransportState::Incomplete && o.record.outcome.application != ApplicationState::Success,
            outcome_line(&o),
        );
        c.add(
            CheckKind::Diagnosis,
            "no retrospective gateway error is claimed (the status stays 200)",
            o.record.response.as_ref().map(|r| r.status == 200).unwrap_or(false)
                && !codes(&o).iter().any(|x| x.starts_with("ferrum.token")),
            format!("{:?}", codes(&o)),
        );
        let r = sse_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto018-sse-abort") }
    })
}

// ------------------------------------------------------------------- TCP ---

fn tcp_state(o: &ExecutionOutput) -> Option<(u64, u64, bool, ClosedBy)> {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Tcp { bytes_sent, bytes_received, half_closed, closed_by } => {
            Some((*bytes_sent, *bytes_received, *half_closed, *closed_by))
        }
        _ => None,
    }
}

fn proto019(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = bytes_received(&env.fx.tcp_halfclose.log);
        let o = send(env, &tcp_ctx(env, "tcp://127.0.0.1:18401", TcpFraming::None, &["hello"], true, 0)).await;
        let st = tcp_state(&o);
        c.add(
            CheckKind::Diagnosis,
            "5 bytes sent, half-closed, reply received, then the peer's FIN",
            matches!(st, Some((5, n, true, ClosedBy::Peer)) if n > 0),
            format!("{st:?}"),
        );
        c.add(
            CheckKind::Diagnosis,
            "the reply sent after the half-close is preserved",
            previews(&o, Direction::Received, "bytes").concat().contains("received 5 bytes after half-close"),
            format!("{:?}", previews(&o, Direction::Received, "bytes")),
        );
        c.has(&o, "tcp.reply_after_half_close");
        c.add(CheckKind::Diagnosis, "transport completed", o.record.outcome.transport == TransportState::Completed, outcome_line(&o));
        c.add(
            CheckKind::GroundTruth,
            "the backend read 5 bytes and then EOF through the gateway (FIN propagated)",
            bytes_received(&env.fx.tcp_halfclose.log) == before + 5,
            format!("{}", bytes_received(&env.fx.tcp_halfclose.log) - before),
        );
        let r = tcp_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "proto019-tcp-halfclose") }
    })
}

fn proto019_echo(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(env, &tcp_ctx(env, "tcp://127.0.0.1:18408", TcpFraming::NewlineDelimited, &["first", "second"], false, 2)).await;
        c.add(
            CheckKind::Diagnosis,
            "both newline frames echoed; Anvil stopped at expect_frames",
            previews(&o, Direction::Received, "frame") == vec!["first", "second"]
                && matches!(tcp_state(&o), Some((_, _, false, ClosedBy::Client))),
            outcome_line(&o),
        );
        c.add(CheckKind::Diagnosis, "no failure recorded", failure_kind(&o).is_none(), "");
        c.add(CheckKind::GroundTruth, "the backend echo received the frames", bytes_received(&env.fx.tcp_echo.log) >= 13, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: op_log(env, from, "tcp-echo") }
    })
}

fn proto019_tls(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = bytes_received(&env.fx.tcps_echo.log);
        let o = send(env, &tcp_ctx(env, "tls://127.0.0.1:18406", TcpFraming::NewlineDelimited, &["secure-1", "secure-2"], false, 2)).await;
        c.add(
            CheckKind::Diagnosis,
            "frames echoed over TLS terminated by the gateway",
            previews(&o, Direction::Received, "frame") == vec!["secure-1", "secure-2"],
            outcome_line(&o),
        );
        c.add(CheckKind::Diagnosis, "client TLS leg verified against the lab root", tls_verified(&o), "");
        c.add(CheckKind::Diagnosis, "no failure recorded", failure_kind(&o).is_none(), format!("{:?}", failure_kind(&o)));
        c.add(
            CheckKind::GroundTruth,
            "the TLS (tcps) backend received the plaintext frames re-encrypted by the gateway",
            bytes_received(&env.fx.tcps_echo.log) >= before + 18,
            format!("{}", bytes_received(&env.fx.tcps_echo.log) - before),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: op_log(env, from, "tcp-tls-echo") }
    })
}

fn up002_tcp(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(env, &tcp_ctx(env, "tcp://127.0.0.1:18407", TcpFraming::NewlineDelimited, &["hello"], false, 1)).await;
        let st = tcp_state(&o);
        c.add(
            CheckKind::Diagnosis,
            "the gateway accepted the client, then closed without any data",
            matches!(st, Some((_, 0, _, ClosedBy::Peer | ClosedBy::Abnormal))),
            format!("{st:?} / {}", outcome_line(&o)),
        );
        no_client_tls_claim(&mut c, &o);
        c.add(
            CheckKind::Diagnosis,
            "the client leg's TCP connect is not reported as failed",
            last(&o).and_then(|a| a.phase(Phase::Connect)).map(|p| p.status) == Some(PhaseStatus::Completed),
            "",
        );
        c.not_success(&o);
        c.has(&o, "tcp.closed_without_data");
        c.max_confidence(&o, "tcp.closed_without_data", Confidence::Confirmed);
        c.operator_class(&op_log(env, from, "tcp-refused"), "tcp-refused", &["connection_refused"]);
        let r = tcp_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "tcp-refused") }
    })
}

fn up004_tcps(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = connections(&env.fx.tcps_untrusted.log);
        let o = send(env, &tcp_ctx(env, "tls://127.0.0.1:18409", TcpFraming::NewlineDelimited, &["hello"], false, 1)).await;
        c.add(CheckKind::Diagnosis, "the client's TLS handshake with the gateway verified", tls_verified(&o), outcome_line(&o));
        c.add(
            CheckKind::Diagnosis,
            "then the gateway closed without data",
            matches!(tcp_state(&o), Some((_, 0, _, ClosedBy::Peer | ClosedBy::Abnormal))),
            format!("{:?}", tcp_state(&o)),
        );
        no_client_tls_claim(&mut c, &o);
        c.not_success(&o);
        c.has(&o, "tcp.closed_without_data");
        c.add(
            CheckKind::GroundTruth,
            "the gateway did dial the untrusted TLS backend",
            connections(&env.fx.tcps_untrusted.log) > before,
            "",
        );
        c.operator_class(&op_log(env, from, "tcps-untrusted"), "tcps-untrusted", &["tls_error"]);
        // Recovery: the same shape through the tcps route whose backend the gateway trusts.
        let r = send(env, &tcp_ctx(env, "tls://127.0.0.1:18406", TcpFraming::NewlineDelimited, &["ok"], false, 1)).await;
        c.add(
            CheckKind::Recovery,
            "TLS stream with a trusted tcps backend echoes",
            previews(&r, Direction::Received, "frame") == vec!["ok"],
            outcome_line(&r),
        );
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "tcps-untrusted") }
    })
}

// ------------------------------------------------------------- UDP/DTLS ---

fn proto020(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = datagrams(&env.fx.udp_silent.log);
        let o = send(env, &udp_ctx(env, "udp://127.0.0.1:18402", &["are you there?"], 800, None)).await;
        c.add(
            CheckKind::Diagnosis,
            "1 sent, 0 received",
            matches!(o.record.outcome.protocol_status, ProtocolStatus::Udp { datagrams_sent: 1, datagrams_received: 0, .. }),
            outcome_line(&o),
        );
        c.has(&o, "udp.no_response");
        let f = o.record.findings.iter().find(|f| f.code == "udp.no_response");
        c.add(
            CheckKind::Diagnosis,
            "silence is not claimed as delivery or as an outage",
            f.map(|f| f.does_not_prove.iter().any(|d| d.contains("delivered")) && f.does_not_prove.iter().any(|d| d.contains("down")))
                .unwrap_or(false),
            "",
        );
        c.add(CheckKind::Diagnosis, "dispatch may_have_been_sent", o.record.outcome.dispatch == DispatchState::MayHaveBeenSent, "");
        c.add(CheckKind::Diagnosis, "not a success", o.record.outcome.application != ApplicationState::Success, "");
        c.absent_prefix(&o, "ferrum.");
        c.add(
            CheckKind::GroundTruth,
            "the silent backend did receive the relayed datagram",
            datagrams(&env.fx.udp_silent.log) > before,
            "",
        );
        let r = udp_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn proto021(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = datagrams(&env.fx.udp_lossy.log);
        let o = send(env, &udp_ctx(env, "udp://127.0.0.1:18403", &["d0", "d1", "d2", "d3"], 800, None)).await;
        let got = previews(&o, Direction::Received, "datagram");
        c.add(
            CheckKind::Diagnosis,
            "4 sent, 2 received, per-datagram boundaries kept",
            matches!(o.record.outcome.protocol_status, ProtocolStatus::Udp { datagrams_sent: 4, datagrams_received: 2, .. })
                && got.len() == 2,
            format!("{got:?}"),
        );
        c.has(&o, "udp.partial_responses");
        c.absent_prefix(&o, "udp.no_response");
        c.no_confirmed_claim(&o, "lost");
        c.add(
            CheckKind::GroundTruth,
            "the backend received all 4 and answered every other one",
            datagrams(&env.fx.udp_lossy.log) >= before + 4,
            "",
        );
        let r = udp_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn proto022(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = datagrams(&env.fx.udp_echo.log);
        let o = send(env, &udp_ctx(env, "dtls://127.0.0.1:18405", &["secure hello"], 800, lab_root(env))).await;
        let a = last(&o);
        c.add(
            CheckKind::Diagnosis,
            "DTLS handshake with the gateway completed and verified",
            a.and_then(|a| a.phase(Phase::DtlsHandshake)).map(|p| p.status) == Some(PhaseStatus::Completed) && tls_verified(&o),
            outcome_line(&o),
        );
        c.add(CheckKind::Diagnosis, "the TLS adapter was not used", a.and_then(|a| a.phase(Phase::TlsHandshake)).is_none(), "");
        c.add(
            CheckKind::Diagnosis,
            "echo received over DTLS",
            previews(&o, Direction::Received, "datagram") == vec!["secure hello"],
            format!("{:?}", previews(&o, Direction::Received, "datagram")),
        );
        c.add(
            CheckKind::GroundTruth,
            "the plain UDP backend received the decrypted datagram",
            datagrams(&env.fx.udp_echo.log) > before,
            "",
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn proto022_wrong_root(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = datagrams(&env.fx.udp_echo.log);
        let o =
            send(env, &udp_ctx(env, "dtls://127.0.0.1:18405", &["must not arrive"], 800, Some(env.fx.pki.rogue_ca.cert.as_str()))).await;
        let f = last(&o).and_then(|a| a.failure.clone());
        c.add(
            CheckKind::Diagnosis,
            "client-side verification failure in the DTLS handshake",
            f.as_ref().map(|f| f.kind == FailureKind::TlsUntrustedIssuer && f.phase == Phase::DtlsHandshake).unwrap_or(false),
            format!("{f:?}"),
        );
        c.add(CheckKind::Diagnosis, "nothing was dispatched", o.record.outcome.dispatch == DispatchState::NotDispatched, "");
        c.absent_prefix(&o, "client.dtls.handshake_failed");
        c.add(CheckKind::GroundTruth, "no application datagram reached the backend", datagrams(&env.fx.udp_echo.log) == before, "");
        let r = send(env, &udp_ctx(env, "dtls://127.0.0.1:18405", &["recovered"], 800, lab_root(env))).await;
        c.add(
            CheckKind::Recovery,
            "with the correct root the DTLS echo works",
            previews(&r, Direction::Received, "datagram") == vec!["recovered"],
            outcome_line(&r),
        );
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

// ----------------------------------------------------------------- wiring ---

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-STREAMS", title: "Positive control through the streams gateway (HTTP/1.1, Alt-Svc)", run: ctrl },
        Def { id: "PROTO-001", title: "HTTP/1.1 keep-alive reuse through the gateway", run: proto001 },
        Def { id: "PROTO-002", title: "HTTP/2 over TLS end to end: trailers (direct control vs through the gateway)", run: proto002 },
        Def { id: "PROTO-005", title: "h2c against the TLS listener (+ h2c recovery on the cleartext listener)", run: proto005 },
        Def { id: "PROTO-006", title: "Forced HTTP/3 through the gateway's QUIC listener", run: proto006 },
        Def { id: "PROTO-007", title: "Forced HTTP/3 over a UDP-blocked path: no silent TCP", run: proto007 },
        Def { id: "PROTO-008", title: "HTTP/3 automatic fallback to TCP through the gateway", run: proto008 },
        Def { id: "PROTO-009", title: "WebSocket (HTTP/1.1 Upgrade) normal close relayed by the gateway", run: proto009 },
        Def { id: "PROTO-009-client-close", title: "WebSocket closed by Anvil is not attributed to the peer", run: proto009_client_close },
        Def { id: "PROTO-010", title: "WebSocket backend drop without a Close frame", run: proto010 },
        Def { id: "PROTO-012", title: "WebSocket over HTTP/2 extended CONNECT (TLS and h2c)", run: proto012 },
        Def { id: "PROTO-014", title: "gRPC HTTP 200 with an application error status in trailers", run: proto014 },
        Def { id: "PROTO-014-down", title: "gRPC backend down: HTTP 200 trailers-only grpc-status 14", run: proto014_down },
        Def { id: "PROTO-015", title: "gRPC stream reset before any terminal status", run: proto015 },
        Def { id: "PROTO-016", title: "gRPC unary/server/client/bidi (h2c) and unary over TLS", run: proto016 },
        Def { id: "PROTO-016-deadline", title: "gRPC client deadline exceeded through the gateway", run: proto016_deadline },
        Def { id: "UP-010-grpc", title: "gRPC backend header stall: gateway backend deadline", run: up010_grpc },
        Def { id: "PROTO-018", title: "SSE events then explicit cancel", run: proto018 },
        Def { id: "PROTO-018-idle", title: "SSE idle stream (no events within the idle limit)", run: proto018_idle },
        Def { id: "TRUST-007-sse", title: "SSE aborted mid-stream after HTTP 200", run: trust007_sse },
        Def { id: "PROTO-013", title: "WebSocket over HTTP/3 extended CONNECT (RFC 9220)", run: proto013 },
        Def { id: "PROTO-013-blocked", title: "WebSocket over HTTP/3 on a UDP-blocked path: no fallback", run: proto013_blocked },
        Def { id: "PROTO-019", title: "TCP half-close through the stream proxy", run: proto019 },
        Def { id: "PROTO-019-echo", title: "TCP newline-framed echo through the stream proxy", run: proto019_echo },
        Def { id: "PROTO-019-tls", title: "TCP+TLS terminated at the gateway, tcps to the backend", run: proto019_tls },
        Def { id: "UP-002-tcp", title: "TCP stream proxy with its backend refused", run: up002_tcp },
        Def { id: "UP-004-tcps", title: "TLS stream: gateway's tcps leg rejects the backend certificate", run: up004_tcps },
        Def { id: "PROTO-020", title: "UDP silent backend: no response observed", run: proto020 },
        Def { id: "PROTO-021", title: "UDP lossy backend: partial responses", run: proto021 },
        Def { id: "PROTO-022", title: "DTLS terminated at the gateway (verified) to a UDP echo", run: proto022 },
        Def { id: "PROTO-022-wrong-root", title: "DTLS with the wrong trust root fails on the client side", run: proto022_wrong_root },
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "streams",
        about: "Protocols through the gateway: H1/H2/h2c/H3, WebSocket, gRPC, SSE, TCP/TLS, UDP/DTLS (HTTP 18480, HTTPS+QUIC 18443)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let certs = crate::gateway::repo_root().join("lab/.run/streams/certs");
    let fx = StreamsFixtures::start(&certs).await?;
    let gateway =
        Gateway::start("streams", "streams.conf", "streams.yaml", &[("LAB_CERTS", certs.display().to_string())], ADMIN_PORT, &[]).await?;
    // Let the gateway's own backend capability probes finish, then forget them.
    tokio::time::sleep(Duration::from_secs(2)).await;
    fx.clear_logs();
    Ok(Env { engine: Engine::new(), fx, gateway, trusted: true })
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("streams")?;
    let mut env = start().await?;
    let results = harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await;
    let finished = match &results {
        Ok(r) => harness::finish(&ctx, &env, r).map(|_| ()),
        Err(_) => Ok(()),
    };
    env.gateway.stop().await;
    finished?;
    results
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!(
        "streams lab running: HTTP {HTTP} (h1+h2c), HTTPS/H3 {HTTPS}, admin 127.0.0.1:{ADMIN_PORT}; lab CA {}; operator log {}",
        env.fx.certs_dir.join("ca.crt").display(),
        env.gateway.log_path.display()
    );
    println!(
        "routes: /proto/http/* /proto/h2/* /proto/h3/* /ws /anvil.lab.v1.Echo/* /grpc-down/* /grpc-slow/* /sse /sse-abort/*; \
         tcp 18401 (half-close) 18406 (tls->tcps) 18407 (refused) 18408 (echo) 18409 (tls->untrusted tcps); udp 18402 (silent) 18403 (lossy) 18404 (echo); dtls 18405"
    );
    harness::wait_for_shutdown().await?;
    env.gateway.stop().await;
    Ok(())
}
