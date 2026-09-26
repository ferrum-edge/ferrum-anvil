//! Scenarios for the `h3x` gateway profile: server-sent events over HTTP/3
//! and RFC 9298 CONNECT-UDP (MASQUE), both *through the real Ferrum Edge
//! gateway's QUIC listener*.
//!
//! Public-evidence mode: Anvil sees only what a client sees. Fixture logs
//! and the gateway's operator log are independent ground truth, never given
//! to the engine. UDP silence through the tunnel is "no response observed";
//! a proxy refusal is the proxy's answer and never a claim about the target;
//! a missing capability fails before any request is sent.

use crate::fixtures_h3x::H3xFixtures;
use crate::gateway::{Gateway, Instance, Readiness};
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::{AttemptObservation, AttemptReason, Direction, DispatchState, FailureKind, Phase, PhaseStatus};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::{ApplicationState, ClosedBy, MasqueEncoding, MasqueTunnel, ProtocolStatus, TransportState};
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

/// Main gateway (CONNECT-UDP enabled): HTTPS + QUIC.
pub const HTTPS: &str = "127.0.0.1:18843";
/// Second instance, CONNECT-UDP disabled (WebSocket over HTTP/3 still on).
const HTTPS_OFF: &str = "127.0.0.1:18844";
/// Third instance, no extended CONNECT at all.
const HTTPS_NOEXT: &str = "127.0.0.1:18845";
const ADMIN_PORT: u16 = 18890;
/// TCP-only relay to 18843 (no QUIC listener behind it).
const UDP_BLOCKED: &str = "127.0.0.1:19820";
const UDP_ECHO: &str = "127.0.0.1:19805";
const UDP_SILENT: &str = "127.0.0.1:19806";
const UDP_UNLISTED: &str = "127.0.0.1:19807";
/// Every listener of the three gateway instances.
const GATEWAY_PORTS: &[u16] = &[18880, 18843, 18881, 18844, 18882, 18845];
const MASQUE_PROXY_ID: &str = "h3x-masque";

pub struct Env {
    pub engine: Engine,
    pub fx: H3xFixtures,
    pub gateway: Gateway,
    pub gw_off: Gateway,
    pub gw_noext: Gateway,
    pub trusted: bool,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<std::path::PathBuf> {
        vec![self.gateway.log_path.clone(), self.gw_off.log_path.clone(), self.gw_noext.log_path.clone()]
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

// ------------------------------------------------------------ contexts ---

fn ferrum_profile() -> IntegrationProfile {
    IntegrationProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab h3x gateway".into(),
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
        name: "lab h3x trust".into(),
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

/// A request context that trusts only the per-run lab root (verification on).
fn ctx_with(env: &Env, spec: RequestSpec, version: Option<HttpVersionPolicy>, handshake_ms: Option<u64>) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    c.isolation = "lab-h3x".into();
    if env.trusted {
        c.integrations.push(ferrum_profile());
    }
    let p = tls_profile(&env.fx.pki.ca.cert);
    let mut t = fast();
    if let Some(ms) = handshake_ms {
        t.tls_handshake_ms = Some(Some(ms));
    }
    let run = SettingsOverrides { timeouts: Some(t), http_version: version, tls_profile_id: Some(p.id), ..Default::default() };
    c.tls_profiles.push(p);
    c.settings_layers.push(("run".into(), run));
    c
}

fn sse_ctx(env: &Env, url: &str, max_events: u32, idle_timeout_ms: u64, reconnect: bool) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events, idle_timeout_ms, last_event_id: None, reconnect });
    ctx_with(env, s, Some(HttpVersionPolicy::Http3Only), None)
}

struct Masque<'a> {
    target: &'a str,
    proxy: &'a str,
    template: &'a str,
    mode: MasqueDatagramMode,
    datagrams: &'a [&'a str],
    window_ms: u64,
    dtls: bool,
}

impl Default for Masque<'_> {
    fn default() -> Self {
        Masque {
            target: UDP_ECHO,
            proxy: HTTPS,
            template: MASQUE_DEFAULT_TEMPLATE,
            mode: MasqueDatagramMode::Auto,
            datagrams: &["masque-1"],
            window_ms: 800,
            dtls: false,
        }
    }
}

fn masque_ctx(env: &Env, m: Masque<'_>) -> ExecutionContext {
    let scheme = if m.dtls { "dtls" } else { "udp" };
    let mut s = RequestSpec::http("GET", &format!("{scheme}://{}", m.target));
    s.protocol = Protocol::Udp;
    s.udp = Some(UdpSpec {
        dtls: m.dtls,
        datagrams: m.datagrams.iter().map(|d| StreamPayload { data: d.to_string(), encoding: PayloadEncoding::Text }).collect(),
        response_window_ms: m.window_ms,
        max_datagrams: 100,
        masque: Some(MasqueSpec { proxy_url: format!("https://{}", m.proxy), uri_template: m.template.into(), datagrams: m.mode }),
    });
    let handshake = if m.proxy == UDP_BLOCKED { Some(800) } else { None };
    ctx_with(env, s, None, handshake)
}

/// Drop pooled connections so every scenario measures fresh handshakes.
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

fn sse_state(o: &ExecutionOutput) -> Option<(u16, u64, ClosedBy)> {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Sse { http_status, events, closed_by } => Some((*http_status, *events, *closed_by)),
        _ => None,
    }
}

fn tunnel(o: &ExecutionOutput) -> Option<(u64, u64, MasqueTunnel)> {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, masque: Some(m), .. } => {
            Some((*datagrams_sent, *datagrams_received, m.clone()))
        }
        _ => None,
    }
}

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

/// Operator-side ground truth: a gateway log line (for this proxy) mentions `needle`.
fn operator_says(c: &mut Checks, lines: &[String], needle: &str) {
    c.add(
        CheckKind::GroundTruth,
        format!("gateway operator log mentions {needle}"),
        lines.iter().any(|l| l.contains(needle)),
        format!("{} lines", lines.len()),
    );
}

fn datagrams(log: &anvil_fixtures::GroundTruthLog) -> usize {
    log.entries().iter().filter(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })).count()
}

fn fault_applied(log: &anvil_fixtures::GroundTruthLog, fault: &str) -> bool {
    log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: fault.into() })
}

fn quic_phases_ok(c: &mut Checks, a: Option<&AttemptObservation>) {
    let conn = a.and_then(|a| a.connection.as_ref());
    c.add(
        CheckKind::Diagnosis,
        "negotiated h3 over QUIC with a verified certificate",
        conn.and_then(|x| x.protocol.clone()) == Some("h3".into())
            && conn
                .and_then(|x| x.tls.as_ref())
                .map(|t| {
                    t.alpn_negotiated.as_deref() == Some("h3")
                        && matches!(t.verification, anvil_domain::execution::TlsVerification::Verified)
                })
                .unwrap_or(false),
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

/// Every MASQUE finding is about the proxy and never claims the target down.
fn masque_findings_blame_only_the_proxy(c: &mut Checks, o: &ExecutionOutput, target: &str) {
    let bad: Vec<String> = o
        .record
        .findings
        .iter()
        .filter(|f| f.code.starts_with("masque."))
        .filter(|f| {
            f.scope != SourceScope::ForwardProxy
                || !f.does_not_prove.iter().any(|d| d.contains(target))
                || f.title.to_lowercase().contains("down")
        })
        .map(|f| f.code.clone())
        .collect();
    c.add(
        CheckKind::Diagnosis,
        "MASQUE findings are scoped to the proxy and do not claim the target is down",
        bad.is_empty(),
        format!("{bad:?}"),
    );
}

// ------------------------------------------------------------ recoveries ---

async fn sse_recovery(env: &Env, c: &mut Checks) -> ExecutionOutput {
    let r = send(env, &sse_ctx(env, &format!("https://{HTTPS}/sse?count=2&interval=10"), 0, 5_000, false)).await;
    c.add(
        CheckKind::Recovery,
        "SSE over HTTP/3 through the gateway completes (2 events, peer end)",
        is_success(&r) && sse_state(&r).map(|s| s.1 == 2 && s.2 == ClosedBy::Peer).unwrap_or(false),
        outcome_line(&r),
    );
    r
}

async fn masque_recovery(env: &Env, c: &mut Checks) -> ExecutionOutput {
    let r = send(env, &masque_ctx(env, Masque { datagrams: &["recovered"], ..Default::default() })).await;
    c.add(
        CheckKind::Recovery,
        "CONNECT-UDP echo through the gateway answers the datagram",
        previews(&r, Direction::Received, "datagram") == vec!["recovered"],
        outcome_line(&r),
    );
    r
}

// -------------------------------------------------------------- control ---

fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let from = op_from(env);
        let before = env.fx.echo.log.count_requests();
        let mut x = ctx_with(env, RequestSpec::http("GET", &format!("https://{HTTPS}/h3x/echo")), Some(HttpVersionPolicy::Http3Only), None);
        x.spec.headers.push(KeyValue::new("x-lab", "h3x"));
        let o = send(env, &x).await;
        c.success(CheckKind::Diagnosis, &o);
        quic_phases_ok(&mut c, last(&o));
        c.add(
            CheckKind::Diagnosis,
            "response recorded as HTTP/3",
            o.record.response.as_ref().map(|r| r.http_version == "HTTP/3").unwrap_or(false),
            "",
        );
        c.add(CheckKind::GroundTruth, "backend received the request relayed from QUIC", env.fx.echo.log.count_requests() > before, "");
        let lines = op_log(env, from, "h3x-echo");
        operator_status(&mut c, &lines, 200);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

// ------------------------------------------------------------ SSE over H3 ---

fn proto018_h3(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let from = op_from(env);
        let o = send(env, &sse_ctx(env, &format!("https://{HTTPS}/sse?count=5&interval=60"), 0, 5_000, false)).await;
        c.add(
            CheckKind::Diagnosis,
            "5 events over HTTP/3, then the stream ended cleanly (closed by the peer)",
            sse_state(&o) == Some((200, 5, ClosedBy::Peer)),
            outcome_line(&o),
        );
        c.success(CheckKind::Diagnosis, &o);
        quic_phases_ok(&mut c, last(&o));
        c.add(
            CheckKind::Diagnosis,
            "single attempt recorded as HTTP/3",
            o.record.attempts.len() == 1 && o.record.response.as_ref().map(|r| r.http_version == "HTTP/3").unwrap_or(false),
            format!("{} attempts", o.record.attempts.len()),
        );
        let offsets: Vec<u64> = o
            .record
            .stream
            .as_ref()
            .map(|s| s.messages.iter().filter(|m| m.kind == "event").map(|m| m.offset_us).collect())
            .unwrap_or_default();
        let spread_ms = offsets.last().zip(offsets.first()).map(|(l, f)| (l - f) / 1000).unwrap_or(0);
        c.add(
            CheckKind::Diagnosis,
            "events were parsed as they arrived (spread over the backend's intervals, not in one burst)",
            offsets.len() == 5 && spread_ms >= 150,
            format!("first→last event {spread_ms} ms"),
        );
        c.absent_prefix(&o, "ferrum.token");
        let hdrs = env.fx.sse.log.last_request_headers().unwrap_or_default();
        c.add(
            CheckKind::GroundTruth,
            "the gateway forwarded the HTTP/3 request with Accept: text/event-stream",
            hdrs.iter().any(|(n, v)| n == "accept" && v == "text/event-stream"),
            format!("{hdrs:?}"),
        );
        let lines = op_log(env, from, "h3x-sse");
        operator_status(&mut c, &lines, 200);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn proto018_h3_idle(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(env, &sse_ctx(env, &format!("https://{HTTPS}/sse?count=2&interval=4000"), 0, 800, false)).await;
        c.add(
            CheckKind::Diagnosis,
            "one event, then the idle limit ended the stream (closed_by timeout)",
            sse_state(&o).map(|s| s.1 == 1 && s.2 == ClosedBy::Timeout).unwrap_or(false),
            outcome_line(&o),
        );
        c.has(&o, "sse.idle_timeout");
        c.add(CheckKind::Diagnosis, "not a user cancel", !codes(&o).contains(&"sse.canceled".to_string()), format!("{:?}", codes(&o)));
        c.no_confirmed_claim(&o, "fail");
        c.absent_prefix(&o, "ferrum.token");
        let r = sse_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "h3x-sse") }
    })
}

fn proto018_h3_cancel(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            c2.cancel();
        });
        let x = sse_ctx(env, &format!("https://{HTTPS}/sse?count=500&interval=20"), 0, 5_000, false);
        let o = env.engine.execute(&x, EventCtx::none(), cancel).await;
        c.add(
            CheckKind::Diagnosis,
            "events received before the explicit cancel; closed by the client",
            sse_state(&o).map(|s| s.1 >= 3 && s.2 == ClosedBy::Client).unwrap_or(false),
            outcome_line(&o),
        );
        c.add(CheckKind::Diagnosis, "transport canceled (not failed)", o.record.outcome.transport == TransportState::Canceled, "");
        c.has(&o, "sse.canceled");
        c.add(
            CheckKind::Diagnosis,
            "a cancel is not a timeout",
            !codes(&o).iter().any(|x| x.contains("timeout")),
            format!("{:?}", codes(&o)),
        );
        c.absent_prefix(&o, "ferrum.token");
        let r = sse_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "h3x-sse") }
    })
}

fn trust007_sse_h3(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let o = send(env, &sse_ctx(env, &format!("https://{HTTPS}/sse-abort/?count=3&interval=40"), 0, 5_000, false)).await;
        c.add(
            CheckKind::GroundTruth,
            "backend aborted its event stream after the events",
            fault_applied(&env.fx.sse_abort.log, "sse_abort_mid_stream"),
            "",
        );
        let (events, by) = sse_state(&o).map(|s| (s.1, Some(s.2))).unwrap_or((0, None));
        c.add(CheckKind::Diagnosis, "events before the abort are kept", events == 3, format!("{events}"));
        c.add(CheckKind::Diagnosis, "the end is abnormal, not a peer close", by == Some(ClosedBy::Abnormal), format!("{by:?}"));
        c.add(
            CheckKind::Diagnosis,
            "HTTP 200 + reset HTTP/3 stream is incomplete, never success",
            o.record.outcome.transport == TransportState::Incomplete && o.record.outcome.application != ApplicationState::Success,
            outcome_line(&o),
        );
        c.add(
            CheckKind::Diagnosis,
            "the gateway reset the HTTP/3 stream (typed as a body reset)",
            failure_kind(&o) == Some(FailureKind::BodyReset),
            format!("{:?}", last(&o).and_then(|a| a.failure.as_ref()).map(|f| (&f.kind, f.quic_error_code))),
        );
        c.add(
            CheckKind::Diagnosis,
            "no retrospective gateway error is claimed (the status stays 200)",
            o.record.response.as_ref().map(|r| r.status == 200).unwrap_or(false)
                && !codes(&o).iter().any(|x| x.starts_with("ferrum.token")),
            format!("{:?}", codes(&o)),
        );
        let r = sse_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "h3x-sse-abort") }
    })
}

fn proto018_h3_reconnect(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let from = op_from(env);
        let before = env.fx.sse_flaky.log.requests().len();
        let o = send(env, &sse_ctx(env, &format!("https://{HTTPS}/sse-flaky/?interval=40"), 0, 5_000, true)).await;
        let atts = &o.record.attempts;
        c.add(
            CheckKind::Diagnosis,
            "two attempts: an abnormal end, then a reconnection recorded as its own attempt",
            atts.len() == 2
                && atts[0].failure.as_ref().map(|f| f.kind) == Some(FailureKind::BodyReset)
                && matches!(atts[1].reason, AttemptReason::Retry { .. }),
            format!("{:?}", atts.iter().map(|a| (&a.reason, a.failure.as_ref().map(|f| f.kind))).collect::<Vec<_>>()),
        );
        c.add(
            CheckKind::Diagnosis,
            "each attempt measured its own QUIC handshake (a new connection, not a pooled one)",
            atts.len() == 2 && atts.iter().all(|a| a.phase(Phase::QuicHandshake).map(|p| p.status) == Some(PhaseStatus::Completed)),
            "",
        );
        c.add(
            CheckKind::Diagnosis,
            "events 1, 2 then 3 after the reconnect; the stream then ended cleanly",
            sse_state(&o) == Some((200, 3, ClosedBy::Peer)) && is_success(&o),
            outcome_line(&o),
        );
        let ids: Vec<Option<String>> = env
            .fx
            .sse_flaky
            .log
            .entries()
            .iter()
            .filter_map(|e| match &e.event {
                GroundTruth::RequestReceived { headers, .. } => {
                    Some(headers.iter().find(|(n, _)| n == "last-event-id").map(|(_, v)| v.clone()))
                }
                _ => None,
            })
            .skip(before)
            .collect();
        c.add(
            CheckKind::GroundTruth,
            "through the gateway, the backend saw no Last-Event-ID first and Last-Event-ID 2 on the reconnection",
            ids == vec![None, Some("2".to_string())],
            format!("{ids:?}"),
        );
        c.add(CheckKind::GroundTruth, "the backend aborted the first stream", fault_applied(&env.fx.sse_flaky.log, "sse_flaky_abort"), "");
        c.absent_prefix(&o, "ferrum.token");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: op_log(env, from, "h3x-sse-flaky") }
    })
}

fn proto018_h3_blocked(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let relay_before = env.fx.udp_blocked_path.connections();
        let backend_before = env.fx.sse.log.requests().len();
        let mut x = sse_ctx(env, &format!("https://{UDP_BLOCKED}/sse?count=2&interval=10"), 0, 3_000, false);
        x.settings_layers.push((
            "scenario".into(),
            SettingsOverrides {
                timeouts: Some(TimeoutOverrides { tls_handshake_ms: Some(Some(800)), ..Default::default() }),
                ..Default::default()
            },
        ));
        let o = send(env, &x).await;
        c.add(
            CheckKind::Diagnosis,
            "forced HTTP/3 SSE over a UDP-blocked path fails as a QUIC handshake timeout, one attempt, nothing dispatched",
            failure_kind(&o) == Some(FailureKind::QuicHandshakeTimeout)
                && o.record.attempts.len() == 1
                && o.record.outcome.dispatch == DispatchState::NotDispatched,
            outcome_line(&o),
        );
        c.has(&o, "client.quic.handshake_timeout");
        c.add(CheckKind::Diagnosis, "no stream or response is claimed", o.record.stream.is_none() && o.record.response.is_none(), "");
        c.absent_prefix(&o, "ferrum.");
        c.add(
            CheckKind::GroundTruth,
            "no silent TCP fallback: the TCP path saw no connection and the backend no request",
            env.fx.udp_blocked_path.connections() == relay_before && env.fx.sse.log.requests().len() == backend_before,
            format!("relay {} → {}", relay_before, env.fx.udp_blocked_path.connections()),
        );
        let r = sse_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

// ------------------------------------------------------------ CONNECT-UDP ---

fn masque001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let from = op_from(env);
        let before = datagrams(&env.fx.udp_echo.log);
        let o = send(env, &masque_ctx(env, Masque { datagrams: &["m-one", "m-two", "m-three"], ..Default::default() })).await;
        let t = tunnel(&o);
        c.add(
            CheckKind::Diagnosis,
            "3 sent, 3 received through the tunnel, per-datagram boundaries kept",
            t.as_ref().map(|(s, r, _)| (*s, *r)) == Some((3, 3))
                && previews(&o, Direction::Received, "datagram") == vec!["m-one", "m-two", "m-three"],
            outcome_line(&o),
        );
        quic_phases_ok(&mut c, last(&o));
        let m = t.map(|t| t.2);
        c.add(
            CheckKind::Diagnosis,
            "extended CONNECT answered 200; datagrams as DATAGRAM capsules because the gateway does not enable SETTINGS_H3_DATAGRAM",
            m.as_ref()
                .map(|m| {
                    m.connect_status == Some(200)
                        && m.extended_connect == Some(true)
                        && m.h3_datagrams == Some(false)
                        && m.encoding == Some(MasqueEncoding::Capsule)
                        && (m.sent_capsules, m.received_capsules, m.sent_quic_datagrams, m.received_quic_datagrams) == (3, 3, 0, 0)
                })
                .unwrap_or(false),
            format!("{m:?}"),
        );
        c.add(
            CheckKind::Diagnosis,
            "the request was an extended CONNECT to the RFC 9298 default template",
            last(&o).map(|a| a.method == "CONNECT" && a.url.contains("/.well-known/masque/udp/127.0.0.1/19805/")).unwrap_or(false),
            format!("{:?}", last(&o).map(|a| &a.url)),
        );
        c.add(
            CheckKind::Diagnosis,
            "no MASQUE or UDP problem finding for a healthy tunnel",
            !codes(&o).iter().any(|x| x.starts_with("masque.") || x.starts_with("udp.")),
            format!("{:?}", codes(&o)),
        );
        c.add(CheckKind::Diagnosis, "a reply was observed, so dispatch is sent", o.record.outcome.dispatch == DispatchState::Sent, "");
        c.absent_prefix(&o, "ferrum.token");
        c.add(
            CheckKind::GroundTruth,
            "the UDP echo behind the gateway received the 3 datagrams",
            datagrams(&env.fx.udp_echo.log) >= before + 3,
            format!("{before} → {}", datagrams(&env.fx.udp_echo.log)),
        );
        let lines = op_log(env, from, MASQUE_PROXY_ID);
        operator_status(&mut c, &lines, 200);
        operator_says(&mut c, &lines, "CONNECT-UDP (RFC 9298) tunnel established");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn masque002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = datagrams(&env.fx.udp_silent.log);
        let o = send(env, &masque_ctx(env, Masque { target: UDP_SILENT, datagrams: &["anyone there?"], ..Default::default() })).await;
        c.add(
            CheckKind::Diagnosis,
            "the tunnel opened (200); 1 sent, 0 received",
            tunnel(&o).map(|(s, r, m)| (s, r, m.connect_status)) == Some((1, 0, Some(200))),
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
        c.add(CheckKind::Diagnosis, "no MASQUE finding: the proxy did its part", !codes(&o).iter().any(|x| x.starts_with("masque.")), "");
        c.add(CheckKind::Diagnosis, "dispatch may_have_been_sent", o.record.outcome.dispatch == DispatchState::MayHaveBeenSent, "");
        c.add(CheckKind::Diagnosis, "not a success", o.record.outcome.application != ApplicationState::Success, "");
        c.absent_prefix(&o, "ferrum.");
        c.add(
            CheckKind::GroundTruth,
            "the silent target did receive the datagram through the gateway",
            datagrams(&env.fx.udp_silent.log) > before,
            "",
        );
        let r = masque_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, MASQUE_PROXY_ID) }
    })
}

/// A CONNECT-UDP refusal by the proxy: typed, body kept, no datagram sent.
fn refusal_checks(c: &mut Checks, o: &ExecutionOutput, status: u16, body_has: &str, target: &str) {
    c.add(
        CheckKind::Diagnosis,
        format!("the proxy answered the CONNECT-UDP request with {status}; no tunnel, no datagram"),
        failure_kind(o) == Some(FailureKind::MasqueRefused)
            && tunnel(o).map(|(s, r, m)| (s, r, m.connect_status)) == Some((0, 0, Some(status)))
            && o.record.stream.is_none(),
        outcome_line(o),
    );
    c.has(o, "masque.proxy_refused");
    let body = String::from_utf8_lossy(o.decoded_body.as_ref().unwrap_or(&o.body)).to_string();
    c.add(
        CheckKind::Diagnosis,
        "the refusal body is kept as evidence",
        body.contains(body_has),
        body.chars().take(160).collect::<String>(),
    );
    masque_findings_blame_only_the_proxy(c, o, target);
    c.add(CheckKind::Diagnosis, "nothing was dispatched to the target", o.record.outcome.dispatch == DispatchState::NotDispatched, "");
    c.add(
        CheckKind::Diagnosis,
        "a refusal is an application failure, never success",
        o.record.outcome.application == ApplicationState::Failure,
        "",
    );
    c.absent_prefix(o, "udp.no_response");
    if let Some(f) = o.record.findings.iter().find(|f| f.code == "masque.proxy_refused") {
        c.add(
            CheckKind::Diagnosis,
            "masque.proxy_refused is confirmed (the status was observed)",
            f.confidence == Confidence::Confirmed,
            "",
        );
    }
}

fn masque003(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = datagrams(&env.fx.udp_unlisted.log);
        let o = send(env, &masque_ctx(env, Masque { target: UDP_UNLISTED, datagrams: &["not admitted"], ..Default::default() })).await;
        refusal_checks(&mut c, &o, 403, "not an allowed destination", UDP_UNLISTED);
        c.add(
            CheckKind::GroundTruth,
            "the unlisted target (a live echo) received nothing",
            datagrams(&env.fx.udp_unlisted.log) == before,
            "",
        );
        let lines = op_log(env, from, MASQUE_PROXY_ID);
        operator_status(&mut c, &lines, 403);
        operator_says(&mut c, &lines, "connect_udp_target_not_allowed");
        let r = masque_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn masque004(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = datagrams(&env.fx.udp_echo.log);
        let o =
            send(env, &masque_ctx(env, Masque { template: "/.well-known/masque/UDP/{target_host}/{target_port}/", ..Default::default() }))
                .await;
        refusal_checks(&mut c, &o, 400, "does not expand the connect-udp URI template", UDP_ECHO);
        c.add(CheckKind::GroundTruth, "the target received nothing", datagrams(&env.fx.udp_echo.log) == before, "");
        let lines = op_log(env, from, MASQUE_PROXY_ID);
        operator_status(&mut c, &lines, 400);
        operator_says(&mut c, &lines, "template_anchor_missing");
        let r = masque_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn masque005(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = datagrams(&env.fx.udp_echo.log);
        let o = send(env, &masque_ctx(env, Masque { template: "/masque-get-only/udp/{target_host}/{target_port}/", ..Default::default() }))
            .await;
        let status = o.record.response.as_ref().map(|r| r.status).unwrap_or(0);
        c.add(CheckKind::GroundTruth, "the route's method policy refused CONNECT (405)", status == 405, format!("{status}"));
        refusal_checks(&mut c, &o, 405, "", UDP_ECHO);
        c.add(CheckKind::GroundTruth, "the target received nothing", datagrams(&env.fx.udp_echo.log) == before, "");
        let lines = op_log(env, from, "h3x-masque-get-only");
        operator_status(&mut c, &lines, 405);
        let r = masque_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn masque006(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = datagrams(&env.fx.udp_echo.log);
        let off_from = env.gw_off.log_lines().len();
        let o = send(env, &masque_ctx(env, Masque { proxy: HTTPS_OFF, ..Default::default() })).await;
        refusal_checks(&mut c, &o, 501, "CONNECT-UDP over HTTP/3 is disabled", UDP_ECHO);
        c.add(
            CheckKind::Diagnosis,
            "the disabled profile's SETTINGS still enabled extended CONNECT (WebSocket over HTTP/3 is on), so the request was sent",
            tunnel(&o).map(|t| t.2.extended_connect == Some(true)).unwrap_or(false),
            "",
        );
        c.add(CheckKind::GroundTruth, "the target received nothing", datagrams(&env.fx.udp_echo.log) == before, "");
        let off: Vec<String> = env.gw_off.log_lines().into_iter().skip(off_from).filter(|l| l.contains("CONNECT-UDP")).take(5).collect();
        operator_says(&mut c, &off, "profile not available on this gateway");
        let r = masque_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: off }
    })
}

fn masque007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = datagrams(&env.fx.udp_echo.log);
        let lines_before = env.gw_noext.log_lines().len();
        let o = send(env, &masque_ctx(env, Masque { proxy: HTTPS_NOEXT, ..Default::default() })).await;
        c.add(
            CheckKind::Diagnosis,
            "typed failure before any request: the proxy's SETTINGS do not enable extended CONNECT",
            failure_kind(&o) == Some(FailureKind::MasqueUnsupported)
                && tunnel(&o).map(|t| (t.2.extended_connect, t.2.connect_status)) == Some((Some(false), None))
                && o.record.response.is_none(),
            outcome_line(&o),
        );
        c.has(&o, "masque.extended_connect_unavailable");
        masque_findings_blame_only_the_proxy(&mut c, &o, UDP_ECHO);
        quic_phases_ok(&mut c, last(&o));
        c.add(CheckKind::Diagnosis, "nothing was dispatched", o.record.outcome.dispatch == DispatchState::NotDispatched, "");
        c.absent_prefix(&o, "udp.");
        let new_lines: Vec<String> =
            env.gw_noext.log_lines().into_iter().skip(lines_before).filter(|l| l.contains("\"proxy_id\"")).collect();
        c.add(CheckKind::GroundTruth, "the gateway logged no request (none was sent)", new_lines.is_empty(), format!("{new_lines:?}"));
        c.add(CheckKind::GroundTruth, "the target received nothing", datagrams(&env.fx.udp_echo.log) == before, "");
        let r = masque_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn masque008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = datagrams(&env.fx.udp_echo.log);
        let o = send(env, &masque_ctx(env, Masque { mode: MasqueDatagramMode::QuicDatagrams, ..Default::default() })).await;
        c.add(
            CheckKind::Diagnosis,
            "QUIC DATAGRAM frames required, the gateway never negotiates SETTINGS_H3_DATAGRAM: typed failure before the request",
            failure_kind(&o) == Some(FailureKind::MasqueUnsupported)
                && tunnel(&o).map(|t| (t.2.extended_connect, t.2.h3_datagrams, t.2.connect_status))
                    == Some((Some(true), Some(false), None)),
            outcome_line(&o),
        );
        c.has(&o, "masque.no_datagram_support");
        let f = o.record.findings.iter().find(|f| f.code == "masque.no_datagram_support");
        c.add(
            CheckKind::Diagnosis,
            "the evidence names the missing SETTINGS_H3_DATAGRAM",
            f.map(|f| f.evidence.iter().any(|e| e.key == "h3.settings.h3_datagram" && e.value == "not enabled")).unwrap_or(false),
            "",
        );
        masque_findings_blame_only_the_proxy(&mut c, &o, UDP_ECHO);
        c.add(CheckKind::Diagnosis, "nothing was dispatched", o.record.outcome.dispatch == DispatchState::NotDispatched, "");
        let lines = op_log(env, from, MASQUE_PROXY_ID);
        c.add(CheckKind::GroundTruth, "the gateway logged no CONNECT-UDP request", lines.is_empty(), format!("{lines:?}"));
        c.add(CheckKind::GroundTruth, "the target received nothing", datagrams(&env.fx.udp_echo.log) == before, "");
        // Recovery: the automatic mode uses capsules against the same gateway.
        let r = masque_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn masque009(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh_connections(env);
        let relay_before = env.fx.udp_blocked_path.connections();
        let before = datagrams(&env.fx.udp_echo.log);
        let o = send(env, &masque_ctx(env, Masque { proxy: UDP_BLOCKED, ..Default::default() })).await;
        c.add(
            CheckKind::Diagnosis,
            "the MASQUE proxy is unreachable over UDP: a QUIC handshake timeout in one attempt, nothing dispatched",
            failure_kind(&o) == Some(FailureKind::QuicHandshakeTimeout)
                && o.record.attempts.len() == 1
                && o.record.outcome.dispatch == DispatchState::NotDispatched,
            outcome_line(&o),
        );
        c.has(&o, "client.quic.handshake_timeout");
        c.add(
            CheckKind::Diagnosis,
            "no tunnel, response or UDP silence is claimed",
            o.record.stream.is_none()
                && o.record.response.is_none()
                && !codes(&o).iter().any(|x| x.starts_with("udp.") || x.starts_with("masque.")),
            format!("{:?}", codes(&o)),
        );
        c.absent_prefix(&o, "ferrum.");
        c.add(
            CheckKind::GroundTruth,
            "no fallback: the TCP path saw no connection and the target nothing",
            env.fx.udp_blocked_path.connections() == relay_before && datagrams(&env.fx.udp_echo.log) == before,
            format!("relay {} → {}", relay_before, env.fx.udp_blocked_path.connections()),
        );
        let r = masque_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn masque010(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(env);
        let before = datagrams(&env.fx.udp_echo.log);
        let o = send(env, &masque_ctx(env, Masque { dtls: true, ..Default::default() })).await;
        let f = last(&o).and_then(|a| a.failure.clone());
        c.add(
            CheckKind::Diagnosis,
            "DTLS inside the CONNECT-UDP tunnel is refused locally, before any traffic",
            f.as_ref()
                .map(|f| {
                    f.kind == FailureKind::UnsupportedCombination && f.phase == Phase::Prepare && f.field.as_deref() == Some("udp.masque")
                })
                .unwrap_or(false),
            format!("{f:?}"),
        );
        c.has(&o, "local.unsupported_combination");
        c.add(CheckKind::Diagnosis, "nothing was dispatched", o.record.outcome.dispatch == DispatchState::NotDispatched, "");
        let lines = op_log(env, from, MASQUE_PROXY_ID);
        c.add(CheckKind::GroundTruth, "the gateway saw no request", lines.is_empty(), format!("{lines:?}"));
        c.add(CheckKind::GroundTruth, "the target received nothing", datagrams(&env.fx.udp_echo.log) == before, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

// ----------------------------------------------------------------- wiring ---

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-H3X", title: "Positive control: forced HTTP/3 through the gateway's QUIC listener", run: ctrl },
        Def { id: "PROTO-018-h3", title: "SSE over HTTP/3 through the gateway: events parsed as they arrive, peer end", run: proto018_h3 },
        Def { id: "PROTO-018-h3-idle", title: "SSE over HTTP/3: idle stream ends at the idle limit", run: proto018_h3_idle },
        Def { id: "PROTO-018-h3-cancel", title: "SSE over HTTP/3: explicit cancel", run: proto018_h3_cancel },
        Def { id: "TRUST-007-sse-h3", title: "SSE over HTTP/3 aborted mid-stream after HTTP 200", run: trust007_sse_h3 },
        Def {
            id: "PROTO-018-h3-reconnect",
            title: "SSE over HTTP/3: reconnection with Last-Event-ID is a new attempt",
            run: proto018_h3_reconnect,
        },
        Def { id: "PROTO-018-h3-blocked", title: "SSE over forced HTTP/3 on a UDP-blocked path: no fallback", run: proto018_h3_blocked },
        Def { id: "MASQUE-001", title: "CONNECT-UDP echo through the gateway (DATAGRAM capsules)", run: masque001 },
        Def { id: "MASQUE-002", title: "CONNECT-UDP to a silent target: no response observed", run: masque002 },
        Def { id: "MASQUE-003", title: "CONNECT-UDP destination not admitted by the route (403, body kept)", run: masque003 },
        Def { id: "MASQUE-004", title: "CONNECT-UDP path that is not a template expansion (400, body kept)", run: masque004 },
        Def { id: "MASQUE-005", title: "CONNECT-UDP on a route whose method policy excludes CONNECT (405)", run: masque005 },
        Def { id: "MASQUE-006", title: "CONNECT-UDP with the profile disabled on the gateway (501)", run: masque006 },
        Def { id: "MASQUE-007", title: "Proxy without extended CONNECT: typed failure before any request", run: masque007 },
        Def {
            id: "MASQUE-008",
            title: "QUIC DATAGRAM frames required, gateway offers none: typed failure before the request",
            run: masque008,
        },
        Def { id: "MASQUE-009", title: "MASQUE proxy on a UDP-blocked path: QUIC timeout, no fallback", run: masque009 },
        Def { id: "MASQUE-010", title: "DTLS inside the CONNECT-UDP tunnel is refused before traffic", run: masque010 },
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "h3x",
        about: "SSE over HTTP/3 and RFC 9298 CONNECT-UDP through the gateway's QUIC listener (HTTPS+QUIC 18843, 18844, 18845)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn instance(name: &str, conf: &str, admin_port: u16, vars: &[(&str, String)]) -> anyhow::Result<Gateway> {
    Gateway::launch(Instance {
        name,
        mode: "file",
        conf,
        yaml: Some("h3x.yaml"),
        vars,
        admin_port,
        env: &[],
        readiness: Readiness::Ready,
        append_log: false,
    })
    .await
}

async fn start() -> anyhow::Result<Env> {
    let certs = crate::gateway::repo_root().join("lab/.run/h3x/certs");
    let fx = H3xFixtures::start(&certs).await?;
    let vars = [("LAB_CERTS", certs.display().to_string())];
    let gateway = Gateway::start("h3x", "h3x.conf", "h3x.yaml", &vars, ADMIN_PORT, &[]).await?;
    let gw_off = instance("h3x-off", "h3x-off.conf", 18891, &vars).await?;
    let gw_noext = instance("h3x-noext", "h3x-noext.conf", 18892, &vars).await?;
    // Let the gateways' own backend capability probes finish, then forget them.
    tokio::time::sleep(Duration::from_secs(2)).await;
    fx.clear_logs();
    Ok(Env { engine: Engine::new(), fx, gateway, gw_off, gw_noext, trusted: true })
}

async fn stop(env: Env) {
    env.gateway.stop().await;
    env.gw_off.stop().await;
    env.gw_noext.stop().await;
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("h3x")?;
    let mut env = start().await?;
    let results = harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await;
    let finished = match &results {
        Ok(r) => harness::finish(&ctx, &env, r).map(|_| ()),
        Err(_) => Ok(()),
    };
    stop(env).await;
    finished?;
    results
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!(
        "h3x lab running: HTTPS/H3 {HTTPS} (CONNECT-UDP on), {HTTPS_OFF} (CONNECT-UDP off), {HTTPS_NOEXT} (no extended CONNECT), admin 127.0.0.1:{ADMIN_PORT}; lab CA {}; operator log {}",
        env.fx.certs_dir.join("ca.crt").display(),
        env.gateway.log_path.display()
    );
    println!(
        "routes: /h3x/echo /sse /sse-abort/* /sse-flaky/* /.well-known/masque/udp/{{host}}/{{port}}/ (admits udp 127.0.0.1:19805 echo, 19806 silent) /masque-get-only/*; udp 19807 is a live echo that is not admitted; 19820 is a TCP-only path to 18843"
    );
    harness::wait_for_shutdown().await?;
    stop(env).await;
    Ok(())
}
