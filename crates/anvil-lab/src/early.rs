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
//!
//! EARLY-001 and EARLY-002 reach the gateway's HTTP/3 listener through a UDP
//! relay (`fixtures_early.rs`) that holds the client's TLS Finished while its
//! 0-RTT packets pass, so the gateway's handshake stays pending while it
//! handles the 0-RTT request. The relay's hold is ground truth too: a backend
//! request that arrived before the release was processed while the gateway's
//! handshake was pending.

use crate::fixtures_early::{HoldStats, Relay};
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
use std::io::{Read, Seek, SeekFrom};
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
/// The pending-window relay in front of [`HTTPS`]'s QUIC listener.
const RELAY: &str = "127.0.0.1:17302";
/// The gateway's listeners, and the relay that reaches one of them.
const GATEWAY_PORTS: &[u16] = &[17280, 17243, 17281, 17244, 17302];
const PATH: &str = "/early/echo";

/// Every field is held so its server keeps running for the whole lab run.
#[allow(dead_code)]
pub struct EarlyFixtures {
    pub pki: LabPki,
    pub certs_dir: PathBuf,
    /// HTTP/1.1 echo backend: its request log is the `Early-Data` ground truth.
    pub backend: Fixture,
    /// UDP relay to the gateway's QUIC listener that holds the client's
    /// Finished while 0-RTT packets pass (EARLY-001, EARLY-002).
    pub relay: Relay,
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

/// Before v0.9.8 the relay also waits this long after the first gateway
/// datagram relayed to the Finished's client after the release before it
/// lets the client's queued 1-RTT data (EARLY-002's retry) through, so the
/// retry does not reach the gateway in the turn its handshake completes (see
/// [`misclassifies_1rtt`]).
const PRE_098_SETTLE: Duration = Duration::from_millis(20);

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

/// The longest the relay holds the client's Finished when the gateway does
/// not act on the 0-RTT request (see [`send_held`]). A gateway slower than
/// this is judged by what it does after the release.
const HOLD_CAP: Duration = Duration::from_secs(2);

/// How often the backend and gateway logs are read while the Finished is held.
const HOLD_POLL: Duration = Duration::from_millis(2);

/// How the relay's hold of the client's Finished ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Released {
    /// The gateway acted on the 0-RTT request: the backend received a
    /// request of the method, or the gateway logged its refusal of it.
    Acted,
    /// [`HOLD_CAP`] ran out without the gateway acting.
    Cap,
    /// The request finished while the Finished was still held.
    Done,
}

/// What the relay's hold of the client's Finished showed for one round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hold {
    released: Released,
    /// Backend requests of the method since the round's request, counted
    /// before the release: each reached the backend before the gateway could
    /// have the client's Finished, so while its handshake was pending.
    backend_before: usize,
    /// The gateway's refusals of the method read from its log before the
    /// release (not read once a backend request was counted).
    refusals_before: usize,
    /// How long the Finished was held.
    held_for: Duration,
    /// Datagrams queued at the release.
    datagrams: usize,
    /// What the relay did during the hold, read when the request finished.
    relay: HoldStats,
}

/// A check detail for the relay's hold of a round's Finished.
fn held(hold: Option<Hold>) -> String {
    match hold {
        None => "the relay held no Finished".into(),
        Some(h) => format!(
            "held {:?} with {} datagrams queued, released {:?}; before it: {} backend request(s), {} refusal line(s); \
             {} Handshake datagram(s) also carried 1-RTT data, {} unreadable datagram(s) held",
            h.held_for, h.datagrams, h.released, h.backend_before, h.refusals_before, h.relay.coalesced_1rtt, h.relay.unparsed
        ),
    }
}

/// The gateway's HTTP/3 0-RTT refusals of `method` logged since `from`.
fn refusals(env: &Env, from: usize, method: &str) -> usize {
    gw_lines(&env.gateway, from, H3_REFUSAL).iter().filter(|l| l.contains(method)).count()
}

/// Backend requests of `method` since request `from`.
fn backend_of(env: &Env, from: usize, method: &str) -> usize {
    env.fx.backend.log.requests().iter().skip(from).filter(|(m, _)| m == method).count()
}

/// Watches one round's backend and gateway logs while the relay holds the
/// client's Finished, and releases it ([`Watch::poll`]).
struct Watch<'a> {
    env: &'a Env,
    method: &'a str,
    backend_from: usize,
    /// Byte offset of the gateway log read so far: only appended lines are read.
    log_offset: u64,
    refusals: usize,
}

impl<'a> Watch<'a> {
    fn new(env: &'a Env, method: &'a str, backend_from: usize) -> Self {
        let log_offset = std::fs::metadata(&env.gateway.log_path).map(|m| m.len()).unwrap_or(0);
        Watch { env, method, backend_from, log_offset, refusals: 0 }
    }

    /// Count the refusal lines the gateway appended since the last read, up
    /// to its last complete line.
    fn read_log(&mut self) {
        let Ok(mut f) = std::fs::File::open(&self.env.gateway.log_path) else { return };
        let mut buf = Vec::new();
        if f.seek(SeekFrom::Start(self.log_offset)).is_err() || f.read_to_end(&mut buf).is_err() {
            return;
        }
        let Some(end) = buf.iter().rposition(|b| *b == b'\n') else { return };
        let text = String::from_utf8_lossy(&buf[..=end]);
        self.refusals += text.lines().filter(|l| l.contains(H3_REFUSAL) && l.contains(self.method)).count();
        self.log_offset += end as u64 + 1;
    }

    /// Release the held Finished once the gateway acted on the round's
    /// request, once [`HOLD_CAP`] ran out, or (`done`) once the request
    /// finished. `None` while no Finished is held, and while the hold goes on.
    fn poll(&mut self, done: bool) -> Option<Hold> {
        let since = self.env.fx.relay.holding_since()?;
        let backend_before = backend_of(self.env, self.backend_from, self.method);
        if backend_before == 0 {
            self.read_log();
        }
        let held_for = since.elapsed();
        let released = if backend_before > 0 || self.refusals > 0 {
            Released::Acted
        } else if held_for >= HOLD_CAP {
            Released::Cap
        } else if done {
            Released::Done
        } else {
            return None;
        };
        // Counted above, before the release: the relay forwards the Finished
        // only after this call, so a request counted here never came after it.
        let datagrams = self.env.fx.relay.release();
        Some(Hold { released, backend_before, refusals_before: self.refusals, held_for, datagrams, relay: HoldStats::default() })
    }
}

/// Send `c` through the relay with its gate armed: the connection's 0-RTT
/// packets pass while its Finished is held, until `watch` releases it. The
/// release waits for an event (a backend request or the gateway's refusal
/// log), not for a fixed time; only a gateway that does not act on the 0-RTT
/// request within [`HOLD_CAP`] is released by time.
async fn send_held(env: &Env, c: &ExecutionContext, mut watch: Watch<'_>) -> (ExecutionOutput, Option<Hold>) {
    env.fx.relay.arm();
    let request = send(env, c);
    tokio::pin!(request);
    let mut hold = None;
    let out = loop {
        tokio::select! {
            o = &mut request => break o,
            _ = tokio::time::sleep(HOLD_POLL), if hold.is_none() => hold = watch.poll(false),
        }
    };
    let hold = hold.or_else(|| watch.poll(true));
    env.fx.relay.disarm();
    (out, hold.map(|h| Hold { relay: env.fx.relay.stats(), ..h }))
}

/// One round that did send the request as early data, with the backend and
/// gateway-log positions from just before it and the relay's hold.
struct EarlyRound {
    out: ExecutionOutput,
    backend_from: usize,
    log_from: usize,
    hold: Option<Hold>,
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
    /// No round could be judged (a failed check was added). Holds the last
    /// round the gateway handled after its handshake, if any.
    Exhausted(Option<ExecutionOutput>),
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
    /// Out of rounds without one to judge: a failure, never a skip.
    Exhausted,
}

fn rounds_of(outcomes: &[RoundOutcome], kind: RoundOutcome) -> Vec<usize> {
    outcomes.iter().enumerate().filter(|(_, o)| **o == kind).map(|(i, _)| i).collect()
}

/// The round loop's decision: judge the first round that sent the request as
/// early data and was not ruled out by the gateway's side; fail once
/// [`EARLY_ROUNDS`] rounds ran without one.
fn decide(outcomes: &[RoundOutcome]) -> Step {
    if outcomes.last() == Some(&RoundOutcome::Early) {
        Step::Early
    } else if outcomes.len() < EARLY_ROUNDS {
        Step::Next
    } else {
        Step::Exhausted
    }
}

/// Out of rounds: what the rounds showed. With the relay holding the
/// client's Finished, a gateway that handled the 0-RTT request only after its
/// handshake did not act on it for [`HOLD_CAP`], so that is a failure too.
fn exhausted(client_missed: &[usize], gateway_missed: &[usize]) -> String {
    let mut parts = Vec::new();
    if !client_missed.is_empty() {
        parts.push(format!("the handshake finished before the request was written in round(s) {client_missed:?}"));
    }
    if !gateway_missed.is_empty() {
        let late = format!("the gateway handled the 0-RTT request after its handshake in round(s) {gateway_missed:?}");
        parts.push(format!("{late}, not while the relay held the client's Finished (up to {} ms)", HOLD_CAP.as_millis()));
    }
    parts.join("; ")
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
/// `method` under an early-data policy listing `extra`, both through the
/// relay, until the request itself travelled as 0-RTT early data and
/// `gateway_missed` does not say the gateway handled it after its handshake,
/// or the rounds run out ([`decide`]).
async fn send_in_0rtt(env: &Env, c: &mut Checks, method: &str, extra: &[&str], gateway_missed: GatewayMissed) -> Rounds {
    let mut outcomes = Vec::new();
    let mut last_late = None;
    for round in 0..EARLY_ROUNDS {
        fresh(env);
        if round == 0 {
            fetch_ticket(env, c, RELAY, HttpVersionPolicy::Http3Only, true).await;
        } else {
            send(env, &ctx(env, "GET", RELAY, HttpVersionPolicy::Http3Only, Some(&[]))).await;
        }
        let backend_from = backend_count(env);
        let log_from = gw_from(&env.gateway);
        let request = ctx(env, method, RELAY, HttpVersionPolicy::Http3Only, Some(extra));
        let (out, hold) = send_held(env, &request, Watch::new(env, method, backend_from)).await;
        let mut this_round = None;
        if early(&out, 0).is_some_and(|e| e.offered) {
            let r = EarlyRound { out, backend_from, log_from, hold };
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
            Step::Exhausted => break,
        }
    }
    c.add(
        CheckKind::GroundTruth,
        format!(
            "the request went out as 0-RTT early data and the gateway saw it while its handshake was pending, within {EARLY_ROUNDS} rounds"
        ),
        false,
        exhausted(&rounds_of(&outcomes, RoundOutcome::ClientMissed), &rounds_of(&outcomes, RoundOutcome::GatewayMissed)),
    );
    Rounds::Exhausted(last_late)
}

/// The gateway log warning for its HTTP/3 0-RTT method refusal.
const H3_REFUSAL: &str = "Rejected HTTP/3 0-RTT request";

/// Where the gateway checked a request that the client sent as accepted
/// 0-RTT data. The client's evidence (offered, accepted by QUIC) does not say:
/// the gateway classifies each stream from its own handshake state when it
/// accepts it, and handles a 0-RTT stream it accepts after its handshake
/// completed as 1-RTT (RFC 8470 section 6.4; the v0.9.8 catalog's note on
/// `gateway.admission.early_data_rejected`). The relay holds the client's
/// Finished, so the gateway's handshake stays pending while it acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayWindow {
    /// The gateway saw the stream while its handshake was pending: it answered
    /// the first attempt 425, logged its 0-RTT method refusal, forwarded the
    /// request with `Early-Data: 1`, or a backend request arrived before the
    /// relay released the client's Finished. The scenario's strict checks
    /// apply (a PUT at the backend by then fails them).
    Pending,
    /// The relay held the Finished until [`HOLD_CAP`] ran out without the
    /// gateway acting, and the gateway then handled the stream after its
    /// handshake:
    /// one 200, no retry, no `request.too_early`, exactly one backend request
    /// of the method without `Early-Data`, no refusal logged. A missed round.
    Completed,
    /// Neither shape, or a round whose Finished the relay did not hold: never
    /// a missed round; the strict checks judge (and fail) it.
    Unexplained,
}

/// The facts that tell the gateway's windows apart: Anvil's attempts and
/// finding, and independent ground truth (backend and gateway logs, and the
/// relay's hold).
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
    /// The relay's hold of the client's Finished; `None`: nothing was held.
    hold: Option<Hold>,
}

fn gateway_window(f: &RoundFacts) -> GatewayWindow {
    let marked = f.backend.iter().any(|(_, e)| e.is_some());
    let before_release = f.hold.is_some_and(|h| h.backend_before > 0);
    if f.statuses.first() == Some(&Some(425)) || f.refusals > 0 || marked || before_release {
        return GatewayWindow::Pending;
    }
    let one_rtt = matches!(f.backend, [(m, None)] if m == f.method);
    let capped = f.hold.is_some_and(|h| h.released == Released::Cap);
    if capped && f.statuses == [Some(200)] && !f.retried && !f.too_early_finding && one_rtt {
        GatewayWindow::Completed
    } else {
        GatewayWindow::Unexplained
    }
}

fn round_window(env: &Env, r: &EarlyRound, method: &str) -> (GatewayWindow, String) {
    let seen = backend_requests(env, r.backend_from);
    let refusals = refusals(env, r.log_from, method);
    let a = &r.out.record.attempts;
    let facts = RoundFacts {
        method,
        statuses: a.iter().map(|x| x.response_status).collect(),
        retried: a.iter().any(|x| x.reason == AttemptReason::TooEarlyRetry),
        too_early_finding: codes(&r.out).iter().any(|x| x == "request.too_early"),
        backend: &seen,
        refusals,
        hold: r.hold,
    };
    (gateway_window(&facts), format!("{} backend={seen:?} refusals={refusals}; {}", line(&r.out), held(r.hold)))
}

/// EARLY-001: the admitted GET reached the backend before the relay released
/// the Finished; or, for a gateway slower than [`HOLD_CAP`], the hold ran to
/// its cap and the `Early-Data: 1` check decides.
fn get_admitted_in_window(hold: Option<Hold>) -> bool {
    hold.is_some_and(|h| (h.released == Released::Acted && h.backend_before == 1) || h.released == Released::Cap)
}

/// EARLY-002: the gateway refused the 0-RTT PUT while the relay held the
/// Finished, or (a gateway slower than [`HOLD_CAP`]) answered its first
/// attempt 425 and logged its refusal after the release.
fn put_refused_in_window(hold: Option<Hold>, first_status: Option<u16>, refusals: usize) -> bool {
    hold.is_some_and(|h| h.released == Released::Acted || (first_status == Some(425) && refusals > 0))
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
        let r = match send_in_0rtt(env, &mut c, "GET", &[], get_handled_after_handshake).await {
            Rounds::Early(r) => r,
            Rounds::Exhausted(main) => return Outcome { main, recovery: None, checks: c, operator_log: vec![] },
        };
        let EarlyRound { out: o, backend_from: from, hold, .. } = r;
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
        c.add(
            CheckKind::GroundTruth,
            "the backend saw the 0-RTT GET before the relay released the client's Finished (unless the hold ran to its cap): admitted while the handshake was pending",
            get_admitted_in_window(hold),
            held(hold),
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
            Rounds::Exhausted(main) => return Outcome { main, recovery: None, checks: c, operator_log: vec![] },
        };
        let (window, detail) = round_window(env, &r, "PUT");
        c.add(
            CheckKind::GroundTruth,
            "the gateway saw the 0-RTT PUT while its handshake was pending (it answered 425, logged its refusal, or forwarded it with Early-Data: 1)",
            window == GatewayWindow::Pending,
            detail,
        );
        c.add(
            CheckKind::GroundTruth,
            "the gateway refused the 0-RTT PUT while the relay held the client's Finished, or answered it 425 and logged its refusal after the cap",
            put_refused_in_window(r.hold, r.out.record.attempts.first().and_then(|x| x.response_status), refusals(env, r.log_from, "PUT")),
            held(r.hold),
        );
        // The hard failure: a PUT that reached the backend while the
        // gateway's handshake was held pending was processed as early data
        // (the count is of PUTs only).
        c.add(
            CheckKind::GroundTruth,
            "no PUT reached the backend before the relay released the client's Finished",
            r.hold.is_some_and(|h| h.backend_before == 0),
            held(r.hold),
        );
        let EarlyRound { out: o, backend_from: from, log_from, .. } = r;
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
    let fx = EarlyFixtures {
        backend: http::serve(BACKEND, None).await?,
        relay: Relay::start(RELAY, HTTPS, if misclassifies_1rtt() { PRE_098_SETTLE } else { Duration::ZERO }).await?,
        certs_dir: certs.clone(),
        pki,
    };
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
    println!("pending-window relay: UDP {RELAY} -> {HTTPS} (holds the client's Finished only while a lab scenario arms it)");
    harness::wait_for_shutdown().await?;
    stop(env).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::RoundOutcome::{ClientMissed, Early, GatewayMissed};
    use super::*;

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
            hold: Some(CAPPED),
        }
    }

    /// The relay held the Finished for the whole cap: the gateway did not act.
    const CAPPED: Hold = Hold {
        released: Released::Cap,
        backend_before: 0,
        refusals_before: 0,
        held_for: HOLD_CAP,
        datagrams: 4,
        relay: HoldStats { coalesced_1rtt: 0, unparsed: 0 },
    };

    /// The gateway acted: `backend` backend requests and `refusals` refusal
    /// lines before the release.
    fn acted(backend: usize, refusals: usize) -> Option<Hold> {
        Some(Hold {
            released: Released::Acted,
            backend_before: backend,
            refusals_before: refusals,
            held_for: Duration::from_millis(3),
            ..CAPPED
        })
    }

    /// Issue #221 (lab run 36557709775, EARLY-002-untrusted on v0.9.8): the
    /// client offered the PUT as 0-RTT and QUIC accepted it, but the gateway
    /// checked the stream after its handshake completed and handled it as
    /// 1-RTT: one 200, no retry, no `request.too_early`, one backend PUT
    /// without `Early-Data`, no refusal logged. With the relay this shape is a
    /// missed round only when the relay held the Finished for the whole cap
    /// without the gateway acting.
    #[test]
    fn a_0rtt_put_handled_after_the_held_finished_is_a_missed_round() {
        let backend = [put(None)];
        assert_eq!(gateway_window(&facts("PUT", &[200], false, false, &backend, 0)), GatewayWindow::Completed);
        let mut f = facts("PUT", &[200], false, false, &backend, 0);
        f.hold = None;
        assert_eq!(gateway_window(&f), GatewayWindow::Unexplained, "a round the relay did not hold is judged strictly");
        f.hold = Some(Hold { released: Released::Done, ..CAPPED });
        assert_eq!(gateway_window(&f), GatewayWindow::Unexplained, "only a hold that ran to its cap is a missed round");
    }

    /// A correct gateway slower than the cap still passes EARLY-002's hold
    /// check with its 425 and refusal log; EARLY-001 then leaves the verdict
    /// to its `Early-Data: 1` check. Without a hold, or without the gateway's
    /// action, neither passes.
    #[test]
    fn a_gateway_slower_than_the_cap_is_judged_by_what_it_did() {
        assert!(put_refused_in_window(acted(0, 1), Some(425), 1));
        assert!(put_refused_in_window(Some(CAPPED), Some(425), 1));
        assert!(!put_refused_in_window(Some(CAPPED), Some(425), 0), "a 425 without the refusal log");
        assert!(!put_refused_in_window(Some(CAPPED), Some(200), 1));
        assert!(!put_refused_in_window(None, Some(425), 1));
        assert!(get_admitted_in_window(acted(1, 0)));
        assert!(get_admitted_in_window(Some(CAPPED)));
        assert!(!get_admitted_in_window(acted(2, 0)));
        assert!(!get_admitted_in_window(Some(Hold { released: Released::Done, ..CAPPED })));
        assert!(!get_admitted_in_window(None));
    }

    /// Issue #223: a 200 whose backend receipt came before the relay released
    /// the client's Finished was processed while the gateway's handshake was
    /// pending. It is never a missed round: the strict checks judge it, and
    /// EARLY-002 fails it (no 425, a PUT at the backend before the release).
    #[test]
    fn a_backend_receipt_before_the_release_is_the_pending_window() {
        let backend = [put(None)];
        let mut f = facts("PUT", &[200], false, false, &backend, 0);
        f.hold = acted(1, 0);
        assert_eq!(gateway_window(&f), GatewayWindow::Pending);
        // EARLY-001's pass shape: the admitted GET reached the backend, marked,
        // before the release.
        let marked = [req("GET", Some("1"))];
        let mut f = facts("GET", &[200], false, false, &marked, 0);
        f.hold = acted(1, 0);
        assert_eq!(gateway_window(&f), GatewayWindow::Pending);
        // EARLY-002's pass shape: refused while held, the retry reached the
        // backend after the release.
        let mut f = facts("PUT", &[425, 200], true, true, &backend, 1);
        f.hold = acted(0, 1);
        assert_eq!(gateway_window(&f), GatewayWindow::Pending);
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
    /// missed rounds; running out of rounds always fails, never skips.
    #[test]
    fn the_round_loop_decides_from_the_rounds_so_far() {
        assert_eq!(decide(&[ClientMissed]), Step::Next);
        assert_eq!(decide(&[GatewayMissed]), Step::Next);
        // A missed round, then an unexplained shape: that round is judged
        // strictly (and fails there).
        assert_eq!(decide(&[GatewayMissed, Early]), Step::Early);
        assert_eq!(decide(&[ClientMissed, GatewayMissed, Early]), Step::Early);
        assert_eq!(decide(&[GatewayMissed, ClientMissed, GatewayMissed, GatewayMissed, ClientMissed, GatewayMissed]), Step::Exhausted);
        assert_eq!(decide(&[ClientMissed; EARLY_ROUNDS]), Step::Exhausted);
        assert_eq!(decide(&[GatewayMissed; EARLY_ROUNDS]), Step::Exhausted);
        assert_eq!(decide(&[GatewayMissed, ClientMissed, GatewayMissed, GatewayMissed, ClientMissed, Early]), Step::Early);
    }

    #[test]
    fn the_exhausted_detail_names_only_rounds_that_happened() {
        let detail = exhausted(&[0, 1, 2, 3, 4, 5], &[]);
        assert!(detail.contains("before the request was written in round(s) [0, 1, 2, 3, 4, 5]"), "{detail}");
        assert!(!detail.contains("relay"), "{detail}");
        let detail = exhausted(&[], &[0, 1, 2, 3, 4, 5]);
        assert!(!detail.contains("before the request was written"), "{detail}");
        assert!(detail.contains("after its handshake in round(s) [0, 1, 2, 3, 4, 5]"), "{detail}");
        assert!(detail.contains("(up to 2000 ms)"), "{detail}");
        let detail = exhausted(&[1], &[0, 2, 3, 4, 5]);
        assert!(detail.contains("round(s) [1]") && detail.contains("round(s) [0, 2, 3, 4, 5]"), "{detail}");
    }
}
