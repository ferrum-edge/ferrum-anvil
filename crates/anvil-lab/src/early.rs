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
use crate::scenario::{Check, CheckKind, Checks, ScenarioResult};
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

/// Before v0.9.8 the gateway could classify an HTTP/3 stream accepted before
/// its handshake-complete signal as early data (ferrum-edge#5761, fixed in
/// v0.9.8 by #5775): a request the client sent as 1-RTT on the early-data
/// listener then reaches the backend with `Early-Data: 1`, or draws 425 for a
/// method outside the gateway's list. Timing-dependent; seen on macOS runners.
fn misclassifies_1rtt() -> bool {
    !crate::gateway::release_at_least("v0.9.8")
}

fn misclassified_note() -> String {
    let release = crate::gateway::release_label();
    format!("{release} marked a 1-RTT stream as early data (fixed in v0.9.8, ferrum-edge#5775)")
}

/// Whether the backend saw exactly `method`s sent as 1-RTT through the
/// early-data listener: without `Early-Data`, or with `Early-Data: 1` on
/// releases before v0.9.8. The detail names the gateway misclassification.
fn one_rtt_seen(seen: &[(String, Option<String>)], methods: &[&str]) -> (bool, String) {
    let mark_ok = |e: &Option<String>| e.is_none() || (misclassifies_1rtt() && e.as_deref() == Some("1"));
    let ok = seen.len() == methods.len() && seen.iter().zip(methods).all(|((m, e), want)| m == want && mark_ok(e));
    let marked = seen.iter().any(|(_, e)| e.is_some());
    (ok, if ok && marked { format!("{seen:?}; {}", misclassified_note()) } else { format!("{seen:?}") })
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

/// A scenario's test of the gateway's side of a round that did send the
/// request as early data: `Some(detail)` when the gateway handled it after its
/// own handshake completed, so the window the scenario tests was missed.
type GatewayMissed = fn(&Env, &EarlyRound) -> Option<String>;

/// How the rounds ended.
enum Rounds {
    /// A round sent the request as early data and the gateway's side did not
    /// rule it out: the scenario's checks judge it.
    Early(EarlyRound),
    /// Rounds sent the request as early data, but the gateway handled it after
    /// its handshake every time: a coverage limitation (the reason), never a
    /// pass or a failure. Holds the last such round's output.
    GatewayWindowMissed(ExecutionOutput, String),
    /// No round sent the request as early data (a failed check was added).
    NoEarlyData,
}

/// What one round showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundOutcome {
    /// The handshake finished before the request was written: not early data.
    ClientMissed,
    /// Sent as early data, but the gateway handled it after its handshake.
    GatewayMissed,
    /// Sent as early data, and the gateway's side did not rule the round out.
    Early,
}

/// What the round loop does after the rounds so far.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Try another round.
    Next,
    /// The last round is the one the scenario's checks judge.
    Early,
    /// Out of rounds, the window under test not observed: skip with this reason.
    Skip(String),
    /// Out of rounds, nothing sent as early data: a failure.
    NoEarlyData,
}

fn rounds_of(outcomes: &[RoundOutcome], kind: RoundOutcome) -> Vec<usize> {
    outcomes.iter().enumerate().filter(|(_, o)| **o == kind).map(|(i, _)| i).collect()
}

/// The round loop's decision: judge the first round that sent the request as
/// early data and was not ruled out by the gateway's side; once
/// [`EARLY_ROUNDS`] rounds ran without one, skip when some round was sent as
/// early data (the gateway handled it after its handshake) and fail when none
/// was.
fn decide(outcomes: &[RoundOutcome]) -> Step {
    if outcomes.last() == Some(&RoundOutcome::Early) {
        return Step::Early;
    }
    if outcomes.len() < EARLY_ROUNDS {
        return Step::Next;
    }
    match window_unobserved(&rounds_of(outcomes, RoundOutcome::ClientMissed), &rounds_of(outcomes, RoundOutcome::GatewayMissed)) {
        Some(reason) => Step::Skip(reason),
        None => Step::NoEarlyData,
    }
}

/// Starts every run-time skip reason of this profile, so triage can tell a
/// window that was not observed from a scenario that cannot run at all.
const WINDOW_NOT_OBSERVED: &str = "window not observed: ";

/// Out of rounds: `Some(reason)` when some round did send the request as
/// early data and the gateway handled it after its handshake every time (the
/// window under test was not observed); `None` when no round sent it as early
/// data at all, which stays a failure.
fn window_unobserved(client_missed: &[usize], gateway_missed: &[usize]) -> Option<String> {
    if gateway_missed.is_empty() {
        return None;
    }
    let late = format!("the gateway handled the 0-RTT request after its handshake in round(s) {gateway_missed:?} (RFC 8470 section 6.4)");
    let first = if client_missed.is_empty() {
        String::new()
    } else {
        format!("; the handshake finished before the request was written in round(s) {client_missed:?}")
    };
    Some(format!("{WINDOW_NOT_OBSERVED}{late}{first}: its pre-handshake handling was not exercised within {EARLY_ROUNDS} rounds"))
}

fn missed_rounds_reported(c: &mut Checks, missed: &[usize]) {
    c.add(
        CheckKind::Diagnosis,
        "rounds where the handshake finished before the request was written were reported as such, and the backend agreed",
        true,
        format!("{} missed round(s): {missed:?}", missed.len()),
    );
}

/// Fetch a ticket (the gateway's tickets must allow early data), then send
/// `method` under an early-data policy listing `extra`, until the request
/// itself travelled as 0-RTT early data and `gateway_missed` does not say the
/// gateway handled it after its handshake, or the rounds run out ([`decide`]).
async fn send_in_0rtt(env: &Env, c: &mut Checks, method: &str, extra: &[&str], gateway_missed: GatewayMissed) -> Rounds {
    let mut outcomes = Vec::new();
    let mut last_late = None;
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
        let mut this_round = None;
        if early(&out, 0).is_some_and(|e| e.offered) {
            let r = EarlyRound { out, backend_from, log_from };
            if let Some(detail) = gateway_missed(env, &r) {
                c.add(
                    CheckKind::Diagnosis,
                    format!("round {round}: the gateway handled the 0-RTT {method} after its handshake, as 1-RTT (RFC 8470 section 6.4)"),
                    true,
                    detail,
                );
                last_late = Some(r.out);
                outcomes.push(RoundOutcome::GatewayMissed);
            } else {
                this_round = Some(r);
                outcomes.push(RoundOutcome::Early);
            }
        } else {
            let reported =
                early(&out, 0).is_some_and(|e| e.not_used == Some(EarlyDataNotUsed::HandshakeCompletedFirst) && e.accepted.is_none());
            let seen = backend_requests(env, backend_from);
            let methods: Vec<&str> = seen.iter().map(|(m, _)| m.as_str()).collect();
            let (backend_ok, detail) = one_rtt_seen(&seen, &methods);
            c.add(
                CheckKind::Diagnosis,
                format!("round {round}: a request that missed the 0-RTT window is not claimed as early data"),
                reported && backend_ok,
                format!("{} backend={detail}", line(&out)),
            );
            outcomes.push(RoundOutcome::ClientMissed);
        }
        match decide(&outcomes) {
            Step::Next => {}
            Step::Early => {
                if let Some(r) = this_round {
                    missed_rounds_reported(c, &rounds_of(&outcomes, RoundOutcome::ClientMissed));
                    return Rounds::Early(r);
                }
            }
            Step::Skip(reason) => {
                if let Some(out) = last_late.take() {
                    missed_rounds_reported(c, &rounds_of(&outcomes, RoundOutcome::ClientMissed));
                    return Rounds::GatewayWindowMissed(out, reason);
                }
            }
            Step::NoEarlyData => break,
        }
    }
    c.add(
        CheckKind::GroundTruth,
        format!("the request went out as 0-RTT early data within {EARLY_ROUNDS} rounds"),
        false,
        format!("missed {:?}", rounds_of(&outcomes, RoundOutcome::ClientMissed)),
    );
    Rounds::NoEarlyData
}

/// The gateway log warning for its HTTP/3 0-RTT method refusal.
const H3_REFUSAL: &str = "Rejected HTTP/3 0-RTT request";

/// Where the gateway checked a request that the client sent as accepted
/// 0-RTT data. The client's evidence (offered, accepted by QUIC) does not say:
/// the gateway classifies each stream from its own handshake state when it
/// accepts it, and handles a 0-RTT stream it accepts after its handshake
/// completed as 1-RTT (RFC 8470 section 6.4; the v0.9.8 catalog's note on
/// `gateway.admission.early_data_rejected`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayWindow {
    /// The gateway saw the stream while its handshake was pending: it answered
    /// the first attempt 425, logged its 0-RTT method refusal, or forwarded
    /// the request with `Early-Data: 1`. The scenario's strict checks apply.
    Pending,
    /// The gateway handled the stream after its handshake completed: one 200,
    /// no retry, no `request.too_early`, exactly one backend request of the
    /// method without `Early-Data`, no refusal logged. A missed window.
    Completed,
    /// Neither shape: never a missed window; the strict checks judge (and
    /// fail) it.
    Unexplained,
}

/// The facts that tell the gateway's windows apart: Anvil's attempts and
/// finding, and independent ground truth (backend and gateway logs).
struct RoundFacts<'a> {
    /// The method sent as early data.
    method: &'a str,
    /// The status of each attempt, in order.
    statuses: Vec<Option<u16>>,
    /// Some attempt was Anvil's one retry after `425 Too Early`.
    retried: bool,
    /// Anvil reported `request.too_early`.
    too_early_finding: bool,
    /// `(method, early-data header)` of the backend requests since the request.
    backend: &'a [(String, Option<String>)],
    /// Gateway log lines refusing a 0-RTT request of the method since then.
    refusals: usize,
}

fn gateway_window(f: &RoundFacts) -> GatewayWindow {
    let marked = f.backend.iter().any(|(_, e)| e.is_some());
    if f.statuses.first() == Some(&Some(425)) || f.refusals > 0 || marked {
        return GatewayWindow::Pending;
    }
    let one_rtt = matches!(f.backend, [(m, None)] if m == f.method);
    if f.statuses == [Some(200)] && !f.retried && !f.too_early_finding && one_rtt {
        GatewayWindow::Completed
    } else {
        GatewayWindow::Unexplained
    }
}

fn round_window(env: &Env, r: &EarlyRound, method: &str) -> (GatewayWindow, String) {
    let seen = backend_requests(env, r.backend_from);
    let refusals = gw_lines(&env.gateway, r.log_from, H3_REFUSAL).iter().filter(|l| l.contains(method)).count();
    let a = &r.out.record.attempts;
    let facts = RoundFacts {
        method,
        statuses: a.iter().map(|x| x.response_status).collect(),
        retried: a.iter().any(|x| x.reason == AttemptReason::TooEarlyRetry),
        too_early_finding: codes(&r.out).iter().any(|x| x == "request.too_early"),
        backend: &seen,
        refusals,
    };
    (gateway_window(&facts), format!("{} backend={seen:?} refusals={refusals}", line(&r.out)))
}

/// EARLY-001's gateway side: a 0-RTT GET the gateway handled after its
/// handshake (the backend saw it without `Early-Data`) misses the window.
fn get_handled_after_handshake(env: &Env, r: &EarlyRound) -> Option<String> {
    let (window, detail) = round_window(env, r, "GET");
    (window == GatewayWindow::Completed).then_some(detail)
}

/// EARLY-002's gateway side: a 0-RTT PUT the gateway handled after its
/// handshake misses the window under test.
fn put_handled_after_handshake(env: &Env, r: &EarlyRound) -> Option<String> {
    let (window, detail) = round_window(env, r, "PUT");
    (window == GatewayWindow::Completed).then_some(detail)
}

/// Scenarios whose run-time skip means the window was not observed.
const WINDOW_SCENARIOS: &[&str] = &["EARLY-001", "EARLY-002"];

fn window_skip(r: &ScenarioResult) -> bool {
    r.status == "skipped" && r.skip_reason.as_deref().is_some_and(|s| s.starts_with(WINDOW_NOT_OBSERVED))
}

/// A window scenario skipped in both the trusted and the untrusted pass of
/// one run fails both results: the passes race independently (lab run
/// 36557709775's trusted pass reached the window its untrusted pass missed),
/// so a double skip is a signal, for example a gateway that processes the
/// request before its handshake yet forwards it unmarked and logs nothing,
/// which one round cannot tell from the permitted shape. Returns the indices
/// of the results it changed.
fn fail_double_skips(results: &mut [ScenarioResult]) -> Vec<usize> {
    let mut changed = Vec::new();
    for id in WINDOW_SCENARIOS {
        let untrusted = format!("{id}-untrusted");
        let (Some(t), Some(u)) = (results.iter().position(|r| r.id == *id), results.iter().position(|r| r.id == untrusted)) else {
            continue;
        };
        if !(window_skip(&results[t]) && window_skip(&results[u])) {
            continue;
        }
        for i in [t, u] {
            let r = &mut results[i];
            let detail = r.skip_reason.take().unwrap_or_default();
            r.checks.push(Check {
                name: "the window under test was observed in the trusted or the untrusted pass".into(),
                kind: CheckKind::GroundTruth,
                passed: false,
                detail,
            });
            r.status = "failed".into();
            eprintln!("{:22} failed  skipped in both passes: the window was never observed", r.id);
            changed.push(i);
        }
    }
    changed
}

fn no_gateway_attribution(c: &mut Checks, o: &ExecutionOutput) {
    c.absent_prefix(o, "ferrum.token");
    c.absent_prefix(o, "ferrum.outcome");
}

/// A scenario whose window was not observed within its rounds: neither a pass
/// nor a failure, and still no gateway attribution.
fn window_missed(mut c: Checks, o: ExecutionOutput, reason: String) -> Outcome {
    no_gateway_attribution(&mut c, &o);
    c.skip(reason);
    Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
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
            "early data off by default: no early-data evidence, no ticket kept",
            o.record.attempts.iter().all(|a| a.early_data.is_none()) && env.engine.session_tickets_held() == 0,
            line(&o),
        );
        let (ok, detail) = one_rtt_seen(&backend_requests(env, from), &["GET"]);
        c.add(CheckKind::GroundTruth, "the backend received the GET without Early-Data", ok, detail);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn early001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let EarlyRound { out: o, backend_from: from, .. } = match send_in_0rtt(env, &mut c, "GET", &[], get_handled_after_handshake).await {
            Rounds::Early(r) => r,
            Rounds::GatewayWindowMissed(o, reason) => return window_missed(c, o, reason),
            Rounds::NoEarlyData => return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] },
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
        let before = backend_requests(env, from.saturating_sub(1));
        let (ticket_ok, ticket) = one_rtt_seen(before.get(..1).unwrap_or_default(), &["GET"]);
        c.add(
            CheckKind::GroundTruth,
            "the backend saw the 0-RTT GET with `Early-Data: 1` (the ticket-fetching GET before it had none)",
            seen == vec![("GET".to_string(), Some("1".to_string()))] && ticket_ok,
            format!("{seen:?}; ticket GET {ticket}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn early002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        // Anvil's policy allows PUT in early data; the gateway's allows GET only.
        let r = match send_in_0rtt(env, &mut c, "PUT", &["PUT"], put_handled_after_handshake).await {
            Rounds::Early(r) => r,
            Rounds::GatewayWindowMissed(o, reason) => return window_missed(c, o, reason),
            Rounds::NoEarlyData => return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] },
        };
        let (window, detail) = round_window(env, &r, "PUT");
        c.add(
            CheckKind::GroundTruth,
            "the gateway saw the 0-RTT PUT while its handshake was pending (it answered 425 or logged its refusal)",
            window == GatewayWindow::Pending,
            detail,
        );
        let EarlyRound { out: o, backend_from: from, log_from } = r;
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
        let lines = gw_lines(&env.gateway, log_from, H3_REFUSAL);
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
        let a = &o.record.attempts;
        // Before v0.9.8 the gateway may answer the 1-RTT POST 425; Anvil then
        // retries it once, still not as early data.
        let misclassified = misclassifies_1rtt()
            && a.len() == 2
            && a[0].response_status == Some(425)
            && a[1].reason == AttemptReason::TooEarlyRetry
            && early(&o, 1).is_some_and(|e| !e.offered);
        c.add(
            CheckKind::Diagnosis,
            "POST is never early data: resumed, sent after the handshake, reason recorded",
            early(&o, 0).is_some_and(|e| {
                !e.method_eligible && !e.offered && e.resumption_attempted && e.not_used == Some(EarlyDataNotUsed::MethodNotEligible)
            }) && (a.len() == 1 || misclassified),
            if misclassified { format!("{}; {}", line(&o), misclassified_note()) } else { line(&o) },
        );
        c.add(
            CheckKind::Diagnosis,
            "no 425 and no early-data claim",
            !codes(&o).iter().any(|x| x.starts_with("early_data.accepted") || (x == "request.too_early" && !misclassified)),
            format!("{:?}", codes(&o)),
        );
        let (ok, detail) = one_rtt_seen(&backend_requests(env, from), &["POST"]);
        c.add(CheckKind::GroundTruth, "the backend saw the POST without Early-Data", ok, detail);
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
        let (ok, detail) = one_rtt_seen(&backend_requests(env, from), &["GET"]);
        c.add(CheckKind::GroundTruth, "the backend saw the GET without Early-Data", ok, detail);
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
    let mut results = harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await;
    let finished = match &mut results {
        Ok(r) => {
            let changed = fail_double_skips(r);
            rewrite(&ctx, r, &changed).and_then(|_| harness::finish(&ctx, &env, r).map(|_| ()))
        }
        Err(_) => Ok(()),
    };
    stop(env).await;
    finished?;
    results
}

/// Write the result files of `changed` again (a double skip turned them into failures).
fn rewrite(ctx: &RunCtx, results: &[ScenarioResult], changed: &[usize]) -> anyhow::Result<()> {
    for r in changed.iter().map(|i| &results[*i]) {
        std::fs::write(ctx.out_dir.join(format!("{}.json", r.id)), serde_json::to_vec_pretty(r)?)?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::RoundOutcome::{ClientMissed, Early, GatewayMissed};

    fn req(method: &str, early_data: Option<&str>) -> (String, Option<String>) {
        (method.to_string(), early_data.map(str::to_string))
    }

    fn put(early_data: Option<&str>) -> (String, Option<String>) {
        req("PUT", early_data)
    }

    fn facts<'a>(
        method: &'a str,
        statuses: &[u16],
        retried: bool,
        too_early: bool,
        backend: &'a [(String, Option<String>)],
        refusals: usize,
    ) -> RoundFacts<'a> {
        RoundFacts {
            method,
            statuses: statuses.iter().map(|s| Some(*s)).collect(),
            retried,
            too_early_finding: too_early,
            backend,
            refusals,
        }
    }

    /// Issue #221 (lab run 36557709775, EARLY-002-untrusted on v0.9.8): the
    /// client offered the PUT as 0-RTT and QUIC accepted it, but the gateway
    /// checked the stream after its handshake completed and handled it as
    /// 1-RTT: one 200, no retry, no `request.too_early`, one backend PUT
    /// without `Early-Data`, no refusal logged. A missed window, not a failure.
    #[test]
    fn a_0rtt_put_handled_after_the_handshake_is_a_missed_window() {
        let backend = [put(None)];
        assert_eq!(gateway_window(&facts("PUT", &[200], false, false, &backend, 0)), GatewayWindow::Completed);
    }

    /// The negative path: the gateway saw the stream while its handshake was
    /// pending, answered 425 and logged its refusal; Anvil's one retry after
    /// the handshake got 200 and is the only PUT the backend saw.
    #[test]
    fn a_425_a_refusal_log_or_early_data_shows_the_pending_window() {
        let backend = [put(None)];
        assert_eq!(gateway_window(&facts("PUT", &[425, 200], true, true, &backend, 1)), GatewayWindow::Pending);
        // Any one signal runs the strict checks, which judge the rest.
        assert_eq!(gateway_window(&facts("PUT", &[425], false, true, &[], 0)), GatewayWindow::Pending);
        assert_eq!(gateway_window(&facts("PUT", &[200], false, false, &backend, 1)), GatewayWindow::Pending);
        // A PUT the gateway forwarded as early data: processed before its
        // handshake, so the strict checks run (and fail it: no 425).
        let marked = [put(Some("1"))];
        assert_eq!(gateway_window(&facts("PUT", &[200], false, false, &marked, 0)), GatewayWindow::Pending);
    }

    /// Any other shape is never a missed window: the strict checks run.
    #[test]
    fn other_shapes_are_never_a_missed_window() {
        let one = [put(None)];
        let twice = [put(None), put(None)];
        let get = [req("GET", None)];
        for (f, why) in [
            (facts("PUT", &[200], false, false, &twice, 0), "the backend saw two PUTs"),
            (facts("PUT", &[200], false, false, &[], 0), "the backend saw nothing"),
            (facts("PUT", &[200], false, false, &get, 0), "the backend saw another method"),
            (facts("PUT", &[200, 200], true, false, &one, 0), "a retry without a 425"),
            (facts("PUT", &[200], false, true, &one, 0), "a 425 finding on a 200"),
            (facts("PUT", &[500], false, false, &one, 0), "another status"),
            (facts("PUT", &[], false, false, &one, 0), "no response"),
        ] {
            assert_eq!(gateway_window(&f), GatewayWindow::Unexplained, "{why}");
        }
    }

    /// EARLY-001: a 0-RTT GET the gateway admitted as early data reaches the
    /// backend with `Early-Data: 1` (the pass shape, judged strictly); one it
    /// handled after its handshake reaches it once without the header.
    #[test]
    fn early001_filter_shapes() {
        let unmarked = [req("GET", None)];
        let marked = [req("GET", Some("1"))];
        let twice = [req("GET", None), req("GET", None)];
        assert_eq!(gateway_window(&facts("GET", &[200], false, false, &unmarked, 0)), GatewayWindow::Completed);
        assert_eq!(gateway_window(&facts("GET", &[200], false, false, &marked, 0)), GatewayWindow::Pending);
        assert_eq!(gateway_window(&facts("GET", &[425, 200], true, true, &unmarked, 0)), GatewayWindow::Pending);
        assert_eq!(gateway_window(&facts("GET", &[200, 200], true, false, &unmarked, 0)), GatewayWindow::Unexplained);
        assert_eq!(gateway_window(&facts("GET", &[200], false, false, &twice, 0)), GatewayWindow::Unexplained);
        assert_eq!(gateway_window(&facts("GET", &[200], false, false, &[put(None)], 0)), GatewayWindow::Unexplained);
    }

    /// The round loop: the first round not ruled out is judged, even after
    /// missed windows; running out skips only when some round was sent as
    /// early data, and never sending it as early data fails.
    #[test]
    fn the_round_loop_decides_from_the_rounds_so_far() {
        assert_eq!(decide(&[ClientMissed]), Step::Next);
        assert_eq!(decide(&[GatewayMissed]), Step::Next);
        // A missed window, then an unexplained shape: that round is judged
        // strictly (and fails there), never skipped.
        assert_eq!(decide(&[GatewayMissed, Early]), Step::Early);
        assert_eq!(decide(&[ClientMissed, GatewayMissed, Early]), Step::Early);
        let Step::Skip(reason) = decide(&[GatewayMissed, ClientMissed, GatewayMissed, GatewayMissed, ClientMissed, GatewayMissed]) else {
            panic!("missed windows and client misses must skip");
        };
        assert!(reason.starts_with(WINDOW_NOT_OBSERVED), "{reason}");
        assert!(reason.contains("round(s) [0, 2, 3, 5]") && reason.contains("round(s) [1, 4]"), "{reason}");
        assert_eq!(decide(&[ClientMissed; EARLY_ROUNDS]), Step::NoEarlyData);
        assert!(matches!(decide(&[GatewayMissed; EARLY_ROUNDS]), Step::Skip(_)));
    }

    #[test]
    fn the_skip_reason_is_marked_and_names_only_rounds_that_happened() {
        assert_eq!(window_unobserved(&[0, 1, 2, 3, 4, 5], &[]), None);
        let reason = window_unobserved(&[], &[0, 1, 2, 3, 4, 5]).expect("a coverage limitation");
        assert!(reason.starts_with(WINDOW_NOT_OBSERVED), "{reason}");
        assert!(!reason.contains("before the request was written"), "{reason}");
        assert!(reason.contains("not exercised within 6 rounds"), "{reason}");
        let reason = window_unobserved(&[1], &[0, 2, 3, 4, 5]).expect("a coverage limitation");
        assert!(reason.contains("before the request was written in round(s) [1]"), "{reason}");
    }

    /// The skip reaches the scenario result with its reason.
    #[test]
    fn a_window_skip_reaches_the_result() {
        let mut c = Checks::new();
        c.add(CheckKind::Diagnosis, "round 0: the gateway handled the 0-RTT PUT after its handshake", true, "");
        let Step::Skip(reason) = decide(&[GatewayMissed; EARLY_ROUNDS]) else { panic!("skip") };
        c.skip(reason.clone());
        assert_eq!(c.verdict(), ("skipped", Some(reason)));
    }

    fn result(id: &str, status: &str, reason: Option<&str>) -> ScenarioResult {
        ScenarioResult {
            id: id.into(),
            title: String::new(),
            profile: "early".into(),
            evidence_mode: "public".into(),
            trusted_destination: !id.ends_with("-untrusted"),
            gateway_release: String::new(),
            gateway_source_sha: String::new(),
            gateway_binary_sha256: String::new(),
            platform: String::new(),
            observed: None,
            recovery: None,
            operator_log_evidence: vec![],
            checks: vec![],
            status: status.into(),
            skip_reason: reason.map(str::to_string),
            duration_ms: 0,
        }
    }

    /// A window skipped in both passes of one run fails both results; one
    /// skip, or a skip for another reason, stays a skip.
    #[test]
    fn a_double_window_skip_fails_the_run() {
        let skip = format!("{WINDOW_NOT_OBSERVED}the gateway handled the 0-RTT request after its handshake");
        let mut r = vec![
            result("EARLY-001", "passed", None),
            result("EARLY-002", "skipped", Some(skip.as_str())),
            result("EARLY-001-untrusted", "skipped", Some(skip.as_str())),
            result("EARLY-002-untrusted", "skipped", Some(skip.as_str())),
        ];
        assert_eq!(fail_double_skips(&mut r), vec![1, 3]);
        for i in [1, 3] {
            assert_eq!(r[i].status, "failed");
            assert_eq!(r[i].skip_reason, None);
            assert!(r[i].checks.iter().any(|c| !c.passed && c.detail == skip));
        }
        assert_eq!(r[2].status, "skipped", "one skipped pass stays a skip");

        let mut r = vec![
            result("EARLY-002", "skipped", Some("not supported here")),
            result("EARLY-002-untrusted", "skipped", Some("not supported here")),
        ];
        assert!(fail_double_skips(&mut r).is_empty(), "a static skip is not a window skip");
        let mut r = vec![result("EARLY-002", "skipped", Some(skip.as_str()))];
        assert!(fail_double_skips(&mut r).is_empty(), "no untrusted pass ran");
    }
}
