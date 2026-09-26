//! Scenarios for the `early` gateway profile: TLS 1.3 / QUIC 0-RTT early
//! data *through the real Ferrum Edge gateway*.
//!
//! The gateway (`lab/gateway/early.conf`) admits GET as early data on its
//! HTTP/3 listener (`FERRUM_TLS_EARLY_DATA_METHODS = GET`); a second instance
//! (`early-off.conf`) has early data off. Public-evidence mode: Anvil sees
//! only what a client sees. The HTTP/1.1 echo backend's request log (did the
//! request arrive, with `Early-Data: 1`?) and the gateway's own log (its 425
//! decision) are independent ground truth, never given to the engine.
//!
//! Every scenario starts from an empty ticket cache (`clear_sensitive_state`,
//! the vault-lock path), so the trusted and untrusted passes behave alike.

use crate::gateway::{Gateway, Instance, Readiness};
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::{AttemptReason, EarlyDataNotUsed, EarlyDataObservation, EarlyDataTransport, Phase};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::request::*;
use anvil_domain::settings::{EarlyDataPolicy, HttpVersionPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{HostBinding, TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http::{self, Fixture};
use anvil_fixtures::{GroundTruth, LabPki};
use anvil_transport::recorder::EventCtx;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Early data admitted for GET: HTTPS + QUIC.
pub const HTTPS: &str = "127.0.0.1:17243";
/// Same gateway with early data off.
const HTTPS_OFF: &str = "127.0.0.1:17244";
const ADMIN_PORT: u16 = 17290;
const BACKEND: &str = "127.0.0.1:17301";
const GATEWAY_PORTS: &[u16] = &[17280, 17243, 17281, 17244];
const PATH: &str = "/early/echo";

/// Every field is held so its server keeps running for the whole lab run.
#[allow(dead_code)]
pub struct EarlyFixtures {
    pub pki: LabPki,
    pub certs_dir: PathBuf,
    /// HTTP/1.1 echo backend: its request log is the `Early-Data` ground truth.
    pub backend: Fixture,
}

pub struct Env {
    pub engine: Engine,
    pub fx: EarlyFixtures,
    pub gateway: Gateway,
    pub gw_off: Gateway,
    pub trusted: bool,
    /// One TLS profile for the whole run: tickets never cross profiles.
    tls: TlsProfile,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<PathBuf> {
        vec![self.gateway.log_path.clone(), self.gw_off.log_path.clone()]
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

// ------------------------------------------------------------ contexts ---

fn ferrum_profile() -> IntegrationProfile {
    IntegrationProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab early gateway".into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: GATEWAY_PORTS.iter().map(|p| HostBinding { host: "127.0.0.1".into(), port: Some(*p) }).collect(),
            compatibility_id: crate::gateway::compatibility_id(),
            require_verified_tls: true,
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
        name: "lab early trust".into(),
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

/// A request through the gateway with verified TLS, connection reuse off
/// (0-RTT needs a new connection) and the given early-data policy.
fn ctx(env: &Env, method: &str, https: &str, version: HttpVersionPolicy, early: Option<&[&str]>) -> ExecutionContext {
    let mut s = RequestSpec::http(method, &format!("https://{https}{PATH}"));
    if matches!(method, "PUT" | "POST") {
        s.body = Body::Json { text: r#"{"lab":"early"}"#.into() };
    }
    let mut c = ExecutionContext::standalone(s);
    c.isolation = "lab-early".into();
    if env.trusted {
        c.integrations.push(ferrum_profile());
    }
    c.tls_profiles.push(env.tls.clone());
    c.settings_layers.push((
        "run".into(),
        SettingsOverrides {
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(3_000)),
                tls_handshake_ms: Some(Some(3_000)),
                response_headers_ms: Some(Some(8_000)),
                total_ms: Some(Some(20_000)),
                ..Default::default()
            }),
            http_version: Some(version),
            keepalive: Some(false),
            tls_profile_id: Some(env.tls.id),
            early_data: early.map(|m| EarlyDataPolicy { enabled: true, extra_methods: m.iter().map(|s| s.to_string()).collect() }),
            ..Default::default()
        },
    ));
    c
}

async fn send(env: &Env, c: &ExecutionContext) -> ExecutionOutput {
    env.engine.execute(c, EventCtx::none(), CancellationToken::new()).await
}

/// Forget every ticket and pooled connection (the vault-lock path).
fn fresh(env: &Env) {
    env.engine.clear_sensitive_state();
}

// ------------------------------------------------------ observation helpers ---

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

fn early(o: &ExecutionOutput, attempt: usize) -> Option<EarlyDataObservation> {
    o.record.attempts.get(attempt).and_then(|a| a.early_data.clone())
}

fn line(o: &ExecutionOutput) -> String {
    format!(
        "status={:?} attempts={} early={:?} findings={:?}",
        status(o),
        o.record.attempts.len(),
        o.record.attempts.iter().map(|a| a.early_data.clone()).collect::<Vec<_>>(),
        codes(o)
    )
}

/// `(method, early-data header)` of every backend request since `from`.
fn backend_requests(env: &Env, from: usize) -> Vec<(String, Option<String>)> {
    env.fx
        .backend
        .log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::RequestReceived { method, headers, .. } => {
                Some((method, headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("early-data")).map(|(_, v)| v.clone())))
            }
            _ => None,
        })
        .skip(from)
        .collect()
}

fn backend_count(env: &Env) -> usize {
    backend_requests(env, 0).len()
}

fn gw_from(g: &Gateway) -> usize {
    g.log_lines().len()
}

fn gw_lines(g: &Gateway, from: usize, needle: &str) -> Vec<String> {
    g.log_lines().into_iter().skip(from).filter(|l| l.contains(needle)).take(10).collect()
}

/// The first request of a scenario: no ticket yet, a full handshake that
/// delivers tickets. `allows_early` = what the gateway's tickets should say.
async fn fetch_ticket(env: &Env, c: &mut Checks, https: &str, version: HttpVersionPolicy, allows_early: bool) -> ExecutionOutput {
    let o = send(env, &ctx(env, "GET", https, version, Some(&[]))).await;
    let ed = early(&o, 0);
    c.add(
        CheckKind::Diagnosis,
        "first request: no ticket yet, a full handshake that received session tickets",
        status(&o) == Some(200)
            && ed.as_ref().is_some_and(|e| e.not_used == Some(EarlyDataNotUsed::NoTicket) && !e.offered && e.tickets_received >= 1),
        line(&o),
    );
    c.add(
        CheckKind::GroundTruth,
        format!("the gateway's tickets {} early data", if allows_early { "allow" } else { "do not allow" }),
        ed.as_ref().and_then(|e| e.ticket_max_early_data).map(|m| (m > 0) == allows_early).unwrap_or(false),
        format!("{:?}", ed.and_then(|e| e.ticket_max_early_data)),
    );
    o
}

/// Rounds tried to land a request inside the 0-RTT window. On loopback the
/// resumed handshake can complete while Anvil (a debug build) is still
/// setting up HTTP/3; the request then goes out as ordinary data and the
/// evidence says so (`handshake_completed_first`). Each round starts from an
/// empty ticket cache, and every missed round must agree with the backend.
const EARLY_ROUNDS: usize = 6;

/// One round that did send the request as early data, with the backend and
/// gateway-log positions from just before it.
struct EarlyRound {
    out: ExecutionOutput,
    backend_from: usize,
    log_from: usize,
}

/// Fetch a ticket (the gateway's tickets must allow early data), then send
/// `method` under an early-data policy listing `extra`, until the request
/// itself travelled as 0-RTT early data or the rounds run out.
async fn send_in_0rtt(env: &Env, c: &mut Checks, method: &str, extra: &[&str]) -> Option<EarlyRound> {
    let mut missed = Vec::new();
    for round in 0..EARLY_ROUNDS {
        fresh(env);
        if round == 0 {
            fetch_ticket(env, c, HTTPS, HttpVersionPolicy::Http3Only, true).await;
        } else {
            send(env, &ctx(env, "GET", HTTPS, HttpVersionPolicy::Http3Only, Some(&[]))).await;
        }
        let backend_from = backend_count(env);
        let log_from = gw_from(&env.gateway);
        let out = send(env, &ctx(env, method, HTTPS, HttpVersionPolicy::Http3Only, Some(extra))).await;
        if early(&out, 0).is_some_and(|e| e.offered) {
            c.add(
                CheckKind::Diagnosis,
                "rounds where the handshake finished before the request was written were reported as such, and the backend agreed",
                true,
                format!("{} missed round(s): {missed:?}", missed.len()),
            );
            return Some(EarlyRound { out, backend_from, log_from });
        }
        let reported =
            early(&out, 0).is_some_and(|e| e.not_used == Some(EarlyDataNotUsed::HandshakeCompletedFirst) && e.accepted.is_none());
        let seen = backend_requests(env, backend_from);
        let consistent = reported && seen.iter().all(|(_, e)| e.is_none());
        c.add(
            CheckKind::Diagnosis,
            format!("round {round}: a request that missed the 0-RTT window is not claimed as early data"),
            consistent,
            format!("{} backend={seen:?}", line(&out)),
        );
        missed.push(round);
    }
    c.add(
        CheckKind::GroundTruth,
        format!("the request went out as 0-RTT early data within {EARLY_ROUNDS} rounds"),
        false,
        format!("missed {missed:?}"),
    );
    None
}

fn no_gateway_attribution(c: &mut Checks, o: &ExecutionOutput) {
    c.absent_prefix(o, "ferrum.token");
    c.absent_prefix(o, "ferrum.outcome");
}

// -------------------------------------------------------------- scenarios ---

fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh(env);
        let from = backend_count(env);
        let o = send(env, &ctx(env, "GET", HTTPS, HttpVersionPolicy::Http3Only, None)).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "early data off by default: no early-data evidence, no ticket cache",
            o.record.attempts.iter().all(|a| a.early_data.is_none()) && env.engine.session_tickets_held() == 0,
            line(&o),
        );
        let seen = backend_requests(env, from);
        c.add(
            CheckKind::GroundTruth,
            "the backend received the GET without Early-Data",
            seen == vec![("GET".to_string(), None)],
            format!("{seen:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn early001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let Some(EarlyRound { out: o, backend_from: from, .. }) = send_in_0rtt(env, &mut c, "GET", &[]).await else {
            return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
        };
        let ed = early(&o, 0);
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "second GET: resumed and sent as QUIC 0-RTT early data, which the gateway accepted",
            ed.as_ref().is_some_and(|e| {
                e.transport == EarlyDataTransport::Quic
                    && e.offered
                    && e.accepted == Some(true)
                    && e.resumption_accepted == Some(true)
                    && e.bytes > 0
                    && !e.resent_after_handshake
            }) && o.record.attempts.len() == 1,
            line(&o),
        );
        c.add(
            CheckKind::Diagnosis,
            "the QUIC handshake phase says 0-RTT was accepted",
            o.record.attempts[0]
                .phase(Phase::QuicHandshake)
                .and_then(|p| p.detail.clone())
                .unwrap_or_default()
                .contains("0-RTT early data accepted"),
            "",
        );
        c.has(&o, "early_data.accepted");
        c.scope(&o, "early_data.accepted", SourceScope::ClientToPeer);
        c.add(
            CheckKind::Diagnosis,
            "the accepted finding carries the replay note",
            o.record.findings.iter().any(|f| f.code == "early_data.accepted" && f.does_not_prove.iter().any(|d| d.contains("replayed"))),
            "",
        );
        no_gateway_attribution(&mut c, &o);
        let seen = backend_requests(env, from);
        c.add(
            CheckKind::GroundTruth,
            "the backend saw the 0-RTT GET with `Early-Data: 1` (the ticket-fetching GET before it had none)",
            seen == vec![("GET".to_string(), Some("1".to_string()))]
                && backend_requests(env, from - 1).first().is_some_and(|r| r.1.is_none()),
            format!("{seen:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn early002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        // Anvil's policy allows PUT in early data; the gateway's allows GET only.
        let Some(EarlyRound { out: o, backend_from: from, log_from }) = send_in_0rtt(env, &mut c, "PUT", &["PUT"]).await else {
            return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
        };
        c.success(CheckKind::Recovery, &o);
        let a = &o.record.attempts;
        c.add(
            CheckKind::Diagnosis,
            "the early PUT got 425; one retry after the handshake, on the same connection, got 200",
            a.len() == 2
                && a[0].response_status == Some(425)
                && early(&o, 0).is_some_and(|e| e.offered && e.accepted == Some(true))
                && a[1].reason == AttemptReason::TooEarlyRetry
                && a[1].response_status == Some(200)
                && early(&o, 1).is_some_and(|e| !e.offered && e.not_used == Some(EarlyDataNotUsed::RetryAfterTooEarly))
                && a[0].connection.as_ref().map(|x| x.id) == a[1].connection.as_ref().map(|x| x.id),
            line(&o),
        );
        c.has(&o, "request.too_early");
        c.scope(&o, "request.too_early", SourceScope::Unknown);
        c.add(
            CheckKind::Diagnosis,
            "the 425 finding names the retry outcome",
            o.record
                .findings
                .iter()
                .any(|f| f.code == "request.too_early" && f.explanation.contains("HTTP 200") && f.confidence == Confidence::Confirmed),
            "",
        );
        no_gateway_attribution(&mut c, &o);
        let seen = backend_requests(env, from);
        c.add(
            CheckKind::GroundTruth,
            "the backend saw exactly one PUT (the retry), without Early-Data",
            seen == vec![("PUT".to_string(), None)],
            format!("{seen:?}"),
        );
        let lines = gw_lines(&env.gateway, log_from, "Rejected HTTP/3 0-RTT request");
        c.add(
            CheckKind::GroundTruth,
            "the gateway log records its 0-RTT method refusal",
            lines.iter().any(|l| l.contains("PUT")),
            format!("{} lines", lines.len()),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn early003(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh(env);
        let from = backend_count(env);
        fetch_ticket(env, &mut c, HTTPS_OFF, HttpVersionPolicy::Http3Only, false).await;
        let o = send(env, &ctx(env, "GET", HTTPS_OFF, HttpVersionPolicy::Http3Only, Some(&[]))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "early data off on the gateway: resumed, not offered, delivered after the handshake",
            early(&o, 0).is_some_and(|e| {
                !e.offered
                    && e.resumption_attempted
                    && e.resumption_accepted == Some(true)
                    && e.not_used == Some(EarlyDataNotUsed::TicketWithoutEarlyData)
            }),
            line(&o),
        );
        c.has(&o, "early_data.ticket_without_early_data");
        c.add(
            CheckKind::Diagnosis,
            "no accepted-early-data claim",
            !codes(&o).contains(&"early_data.accepted".to_string()),
            format!("{:?}", codes(&o)),
        );
        no_gateway_attribution(&mut c, &o);
        let seen = backend_requests(env, from);
        c.add(
            CheckKind::GroundTruth,
            "the backend saw both GETs, neither with Early-Data",
            seen == vec![("GET".to_string(), None), ("GET".to_string(), None)],
            format!("{seen:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn early004(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh(env);
        let from = backend_count(env);
        // TLS 1.3 over TCP, HTTP/1.1 only: the gateway's HTTPS listener.
        fetch_ticket(env, &mut c, HTTPS, HttpVersionPolicy::Http1Only, false).await;
        let o = send(env, &ctx(env, "GET", HTTPS, HttpVersionPolicy::Http1Only, Some(&[]))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "the HTTPS listener resumes the TLS 1.3 session but its tickets never allow early data",
            early(&o, 0).is_some_and(|e| {
                e.transport == EarlyDataTransport::Tls
                    && !e.offered
                    && e.resumption_accepted == Some(true)
                    && e.not_used == Some(EarlyDataNotUsed::TicketWithoutEarlyData)
            }),
            line(&o),
        );
        c.add(
            CheckKind::Diagnosis,
            "TLS evidence of the resumed connection (verified on the handshake that issued the ticket)",
            o.record.attempts[0]
                .connection
                .as_ref()
                .and_then(|x| x.tls.as_ref())
                .is_some_and(|t| t.resumed == Some(true) && matches!(t.verification, anvil_domain::execution::TlsVerification::Verified)),
            "",
        );
        c.has(&o, "early_data.ticket_without_early_data");
        no_gateway_attribution(&mut c, &o);
        let seen = backend_requests(env, from);
        c.add(
            CheckKind::GroundTruth,
            "the backend saw both GETs, neither with Early-Data",
            seen == vec![("GET".to_string(), None), ("GET".to_string(), None)],
            format!("{seen:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn early005(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh(env);
        fetch_ticket(env, &mut c, HTTPS, HttpVersionPolicy::Http3Only, true).await;
        let from = backend_count(env);
        let o = send(env, &ctx(env, "POST", HTTPS, HttpVersionPolicy::Http3Only, Some(&[]))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "POST is never early data: resumed, sent after the handshake, reason recorded",
            early(&o, 0).is_some_and(|e| {
                !e.method_eligible && !e.offered && e.resumption_attempted && e.not_used == Some(EarlyDataNotUsed::MethodNotEligible)
            }) && o.record.attempts.len() == 1,
            line(&o),
        );
        c.add(
            CheckKind::Diagnosis,
            "no 425 and no early-data claim",
            !codes(&o).iter().any(|x| x.starts_with("early_data.accepted") || x == "request.too_early"),
            format!("{:?}", codes(&o)),
        );
        let seen = backend_requests(env, from);
        c.add(
            CheckKind::GroundTruth,
            "the backend saw the POST without Early-Data",
            seen == vec![("POST".to_string(), None)],
            format!("{seen:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn early006(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh(env);
        let from = backend_count(env);
        let log_from = gw_from(&env.gateway);
        // Lookalike: a user-set `Early-Data: 1` header on a PUT over the HTTPS
        // (TCP) listener. Nothing travels as early data, yet the gateway's
        // header check answers 425.
        let mut x = ctx(env, "PUT", HTTPS, HttpVersionPolicy::Http1Only, Some(&["PUT"]));
        x.spec.headers.push(KeyValue::new("Early-Data", "1"));
        let o = send(env, &x).await;
        c.not_success(&o);
        let a = &o.record.attempts;
        c.add(
            CheckKind::Diagnosis,
            "425 without early data: retried once after the handshake, never more",
            a.len() == 2
                && a.iter().all(|x| x.response_status == Some(425))
                && a.iter().all(|x| x.early_data.as_ref().is_some_and(|e| !e.offered)),
            line(&o),
        );
        c.add(
            CheckKind::Diagnosis,
            "the 425 finding says the request was not sent as early data and lists the Early-Data header",
            o.record.findings.iter().any(|f| {
                f.code == "request.too_early"
                    && f.explanation.contains("did not send this request as early data")
                    && f.alternatives.iter().any(|x| x.contains("Early-Data: 1"))
            }),
            format!("{:?}", codes(&o)),
        );
        c.scope(&o, "request.too_early", SourceScope::Unknown);
        c.add(CheckKind::Diagnosis, "no accepted-early-data claim", !codes(&o).contains(&"early_data.accepted".to_string()), "");
        c.absent_prefix(&o, "ferrum.token");
        if env.trusted {
            // A declared gateway: the final 425 matches the release catalog's
            // own 0-RTT refusal, capped at likely (the body is spoofable).
            c.has(&o, "ferrum.outcome");
            c.max_confidence(&o, "ferrum.outcome", Confidence::Likely);
            c.add(
                CheckKind::Diagnosis,
                "the trusted match is the catalog's gateway.admission.early_data_rejected",
                o.record
                    .findings
                    .iter()
                    .any(|f| f.code == "ferrum.outcome" && f.evidence.iter().any(|e| e.value == "gateway.admission.early_data_rejected")),
                "",
            );
        }
        c.add(
            CheckKind::GroundTruth,
            "the backend received nothing",
            backend_requests(env, from).is_empty(),
            format!("{:?}", backend_requests(env, from)),
        );
        let lines = gw_lines(&env.gateway, log_from, "Rejected 0-RTT request");
        c.add(
            CheckKind::GroundTruth,
            "the gateway log records its header-based 0-RTT refusal (twice)",
            lines.iter().filter(|l| l.contains("PUT")).count() == 2,
            format!("{} lines", lines.len()),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn early007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        fresh(env);
        fetch_ticket(env, &mut c, HTTPS, HttpVersionPolicy::Http3Only, true).await;
        c.add(CheckKind::Diagnosis, "tickets are held after the first request", env.engine.session_tickets_held() >= 1, "");
        // The vault lock drops every ticket.
        env.engine.clear_sensitive_state();
        c.add(CheckKind::Diagnosis, "the lock cleared the ticket cache", env.engine.session_tickets_held() == 0, "");
        let from = backend_count(env);
        let o = send(env, &ctx(env, "GET", HTTPS, HttpVersionPolicy::Http3Only, Some(&[]))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "after the lock: no ticket, a full handshake, nothing sent early",
            early(&o, 0).is_some_and(|e| e.not_used == Some(EarlyDataNotUsed::NoTicket) && !e.resumption_attempted && !e.offered),
            line(&o),
        );
        let seen = backend_requests(env, from);
        c.add(
            CheckKind::GroundTruth,
            "the backend saw the GET without Early-Data",
            seen == vec![("GET".to_string(), None)],
            format!("{seen:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

// ----------------------------------------------------------------- wiring ---

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-EARLY", title: "Positive control: GET over HTTP/3 through the gateway, early data off by default", run: ctrl },
        Def {
            id: "EARLY-001",
            title: "Second GET resumes into QUIC 0-RTT; the gateway accepts it and marks it Early-Data: 1",
            run: early001,
        },
        Def {
            id: "EARLY-002",
            title: "PUT in 0-RTT outside the gateway's methods: 425, one retry after the handshake, 200",
            run: early002,
        },
        Def {
            id: "EARLY-003",
            title: "Early data off on the gateway: resumption only, the GET is delivered after the handshake",
            run: early003,
        },
        Def { id: "EARLY-004", title: "HTTPS (TCP) listener: TLS 1.3 resumption whose tickets never allow early data", run: early004 },
        Def { id: "EARLY-005", title: "POST is never early data: sent after the handshake with the reason recorded", run: early005 },
        Def {
            id: "EARLY-006",
            title: "Lookalike: a user Early-Data header draws 425 over TCP; retried once, never claimed as early data",
            run: early006,
        },
        Def { id: "EARLY-007", title: "The vault lock clears the ticket cache: the next request is a full handshake", run: early007 },
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "early",
        about: "TLS 1.3 / QUIC 0-RTT early data through the gateway (HTTPS+QUIC 17243 early data for GET, 17244 off)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let certs = crate::gateway::repo_root().join("lab/.run/early/certs");
    let pki = LabPki::generate();
    pki.write_to(&certs)?;
    let fx = EarlyFixtures { backend: http::serve(BACKEND, None).await?, certs_dir: certs.clone(), pki };
    let vars = [("LAB_CERTS", certs.display().to_string())];
    let gateway = Gateway::start("early", "early.conf", "early.yaml", &vars, ADMIN_PORT, &[]).await?;
    let gw_off = Gateway::launch(Instance {
        name: "early-off",
        mode: "file",
        conf: "early-off.conf",
        yaml: Some("early.yaml"),
        vars: &vars,
        admin_port: 17291,
        env: &[],
        readiness: Readiness::Ready,
        append_log: false,
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    fx.backend.log.clear();
    let tls = tls_profile(&fx.pki.ca.cert);
    Ok(Env { engine: Engine::new(), fx, gateway, gw_off, trusted: true, tls })
}

async fn stop(env: Env) {
    env.gateway.stop().await;
    env.gw_off.stop().await;
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("early")?;
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
        "early lab running: HTTPS/H3 {HTTPS} (early data for GET), {HTTPS_OFF} (early data off), admin 127.0.0.1:{ADMIN_PORT}; lab CA {}; operator log {}",
        env.fx.certs_dir.join("ca.crt").display(),
        env.gateway.log_path.display()
    );
    println!("route: {PATH} -> HTTP/1.1 echo backend {BACKEND} (its request log shows Early-Data)");
    harness::wait_for_shutdown().await?;
    stop(env).await;
    Ok(())
}
