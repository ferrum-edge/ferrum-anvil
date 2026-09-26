//! Scenarios for the `tls` gateway profile: frontend TLS / mTLS on the real
//! Ferrum Edge listeners (HTTPS 18343 with mandatory client certificates,
//! a TLS-1.2-only HTTPS instance on 18344, TCP+TLS 18302, DTLS 18301) and
//! gateway-to-backend TLS failures observed through the plaintext listener
//! 18380.
//!
//! Evidence rules: frontend TLS failures are Anvil's own client-leg
//! observations (typed rustls/dimpl evidence) and happen before any HTTP;
//! upstream TLS failures are visible to a client only through the coarse
//! `X-Gateway-Error` token, which never proves TLS. Operator-side ground
//! truth (the gateway's `error_class`, fixture handshake logs) is used only
//! to confirm the fault was reached and is never given to the engine.
//!
//! Result ids are the failure-matrix id, optionally followed by
//! `.<variant>`; `X` ids (e.g. `TLS-X01`) are lab extensions with no seed.

use crate::fixtures_tls::TlsFixtures;
use crate::gateway::{self, Gateway};
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::auth::AuthConfig;
use anvil_domain::diagnostics::{Confidence, Owner, SourceScope};
use anvil_domain::execution::{FailureKind, Phase, TlsObservation, TlsVerification};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::WarningCode;
use anvil_domain::request::{PayloadEncoding, Protocol, RequestSpec, StreamPayload, TcpFraming, TcpSpec, UdpSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{DnsOverride, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ClientIdentity, HostBinding, TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::pki::Pem;
use anvil_transport::recorder::EventCtx;
use std::future::Future;
use std::pin::Pin;
use tokio_util::sync::CancellationToken;

pub const PLAIN: &str = "http://127.0.0.1:18380";
pub const HTTPS: &str = "https://localhost:18343";
pub const HTTPS12: &str = "https://localhost:18344";
const WRONG_HOST: &str = "gateway.wrong-name.anvil-lab.test";

type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

// ------------------------------------------------------------ shared helpers
// (also used by the `auth` profile)

/// A trusted Ferrum destination profile for the lab gateway's listeners.
pub fn integration(name: &str, hosts: &[(&str, u16)]) -> IntegrationProfile {
    IntegrationProfile {
        id: anvil_domain::Id::new(),
        workspace_id: anvil_domain::Id::new(),
        name: name.into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: hosts.iter().map(|(h, p)| HostBinding { host: h.to_string(), port: Some(*p) }).collect(),
            compatibility_id: crate::gateway::compatibility_id(),
            require_verified_tls: false,
            detail: None,
            console_url: None,
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

pub fn run_layer(c: &mut ExecutionContext, o: SettingsOverrides) {
    c.settings_layers.push(("run".into(), o));
}

pub async fn send(engine: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    engine.execute(c, EventCtx::none(), CancellationToken::new()).await
}

/// New gateway transaction-log lines since `from` for `proxy_id`.
pub fn op_lines(gw: &Gateway, from: usize, proxy_id: &str) -> Vec<String> {
    gw.log_lines().into_iter().skip(from).filter(|l| l.contains(&format!("\"proxy_id\":\"{proxy_id}\""))).take(20).collect()
}

pub fn final_failure(o: &ExecutionOutput) -> Option<FailureKind> {
    o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind)
}

pub fn tls_obs(o: &ExecutionOutput) -> Option<&TlsObservation> {
    o.record.attempts.last().and_then(|a| a.connection.as_ref()).and_then(|c| c.tls.as_ref())
}

/// No HTTP response exists (a failure before HTTP must not invent a status).
pub fn no_response(c: &mut Checks, o: &ExecutionOutput) {
    c.add(
        CheckKind::Diagnosis,
        "no HTTP status is reported",
        o.record.response.is_none(),
        format!("{:?}", o.record.response.as_ref().map(|r| r.status)),
    );
    c.absent_prefix(o, "http.");
}

pub fn absent_scope(c: &mut Checks, o: &ExecutionOutput, scope: SourceScope) {
    let hits: Vec<String> = o.record.findings.iter().filter(|f| f.scope == scope).map(|f| f.code.clone()).collect();
    c.add(CheckKind::Diagnosis, format!("no finding attributed to {scope:?}"), hits.is_empty(), format!("{hits:?}"));
}

/// `code` present with the given scope and a confidence no higher than `max`.
pub fn has_claim(c: &mut Checks, o: &ExecutionOutput, code: &str, scope: SourceScope, max: Confidence) {
    c.has(o, code);
    c.scope(o, code, scope);
    c.max_confidence(o, code, max);
}

/// Serialized execution record (what history, reports and exports carry)
/// must not contain `needle`.
pub fn record_excludes(c: &mut Checks, o: &ExecutionOutput, needle: &str, what: &str) {
    let text = serde_json::to_string(&o.record).unwrap_or_default();
    c.add(CheckKind::Diagnosis, format!("{what} never appears in the execution record"), !needle.is_empty() && !text.contains(needle), "");
}

/// No finding recommends disabling certificate verification (or any other
/// security control) as a fix.
pub fn never_recommends_bypass(c: &mut Checks, o: &ExecutionOutput) {
    let bad: Vec<String> = o
        .record
        .findings
        .iter()
        .flat_map(|f| f.remediation.iter().map(move |r| (f.code.clone(), r.text.to_lowercase())))
        .filter(|(_, t)| {
            let weakens = ["disable", "turn off", "skip", "bypass", "ignore"].iter().any(|w| t.contains(w));
            let restores = ["back on", "re-enable", "restore"].iter().any(|w| t.contains(w));
            weakens && (t.contains("verif") || t.contains("tls") || t.contains("certificate")) && !restores
        })
        .map(|(code, t)| format!("{code}: {t}"))
        .collect();
    c.add(CheckKind::Diagnosis, "no remediation suggests disabling verification", bad.is_empty(), format!("{bad:?}"));
}

/// No caller-owned remediation tells the user to change their own client
/// certificate (the gateway's backend identity is a different identity).
pub fn no_client_identity_blame(c: &mut Checks, o: &ExecutionOutput) {
    let bad: Vec<String> = o
        .record
        .findings
        .iter()
        .flat_map(|f| f.remediation.iter().map(move |r| (f.code.clone(), r.owner, r.text.to_lowercase())))
        .filter(|(_, owner, t)| *owner == Owner::Caller && t.contains("client certificate"))
        .map(|(code, _, t)| format!("{code}: {t}"))
        .collect();
    c.add(
        CheckKind::Diagnosis,
        "Anvil's own client identity is not blamed for a gateway-to-backend failure",
        bad.is_empty(),
        format!("{bad:?}"),
    );
    c.absent_prefix(o, "client.tls.");
}

// --------------------------------------------------------------------- env

pub struct Env {
    pub engine: Engine,
    pub fx: TlsFixtures,
    pub gw: Gateway,
    pub gw12: Gateway,
    pub trusted: bool,
    /// (certificate label, refused by `ferrum-edge validate`, message).
    pub validity_probe: Vec<(&'static str, bool, String)>,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<std::path::PathBuf> {
        vec![self.gw.log_path.clone(), self.gw12.log_path.clone()]
    }
}

type Def = harness::Def<Env>;

/// Client-side TLS profile for one request.
#[derive(Clone)]
struct Client<'a> {
    roots: Vec<&'a str>,
    system_roots: bool,
    verify: bool,
    identity: Option<(&'a str, &'a str)>,
    min13: bool,
}

impl<'a> Client<'a> {
    fn lab(env: &'a Env, identity: Option<&'a Pem>) -> Self {
        Client {
            roots: vec![&env.fx.pki.frontend_ca.cert],
            system_roots: false,
            verify: true,
            identity: identity.map(|p| (p.cert.as_str(), p.key.as_str())),
            min13: false,
        }
    }
}

fn tls_profile(c: &Client<'_>) -> TlsProfile {
    TlsProfile {
        id: anvil_domain::Id::new(),
        workspace_id: anvil_domain::Id::new(),
        name: "lab tls client".into(),
        verify: c.verify,
        use_system_roots: c.system_roots,
        extra_roots_pem: c.roots.iter().map(|s| s.to_string()).collect(),
        client_identity: c
            .identity
            .map(|(cert, key)| ClientIdentity::Pem { cert_chain_pem: cert.to_string(), private_key_pem: SensitiveValue::template(key) }),
        bindings: vec![],
        min_version: if c.min13 { TlsMinVersion::Tls13 } else { TlsMinVersion::Tls12 },
        server_name_override: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn base(env: &Env, spec: RequestSpec, client: Option<&Client<'_>>, isolation: &str) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    c.isolation = isolation.into();
    // The gateway binds 127.0.0.1 only; pin `localhost` (and the wrong-name
    // host of TLS-002) there so no ::1 attempt adds noise.
    let mut o = SettingsOverrides {
        dns_overrides: vec![
            DnsOverride { host: "localhost".into(), addresses: vec!["127.0.0.1".into()] },
            DnsOverride { host: WRONG_HOST.into(), addresses: vec!["127.0.0.1".into()] },
        ],
        timeouts: Some(TimeoutOverrides { tls_handshake_ms: Some(Some(4_000)), total_ms: Some(Some(20_000)), ..Default::default() }),
        ..Default::default()
    };
    if let Some(cl) = client {
        let p = tls_profile(cl);
        o.tls_profile_id = Some(p.id);
        c.tls_profiles.push(p);
    }
    run_layer(&mut c, o);
    if env.trusted {
        c.integrations.push(integration(
            "lab tls gateway",
            &[("127.0.0.1", 18380), ("localhost", 18343), ("127.0.0.1", 18343), ("localhost", 18344), ("127.0.0.1", 18344)],
        ));
    }
    c
}

fn https(env: &Env, url: &str, client: &Client<'_>) -> ExecutionContext {
    base(env, RequestSpec::http("GET", url), Some(client), "lab-tls")
}

fn plain(env: &Env, path: &str) -> ExecutionContext {
    base(env, RequestSpec::http("GET", &format!("{PLAIN}{path}")), None, "lab-tls")
}

fn tcp_tls(env: &Env, client: &Client<'_>, payload: &str) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", "tls://localhost:18302");
    s.protocol = Protocol::Tcp;
    s.tcp = Some(TcpSpec {
        tls: true,
        framing: TcpFraming::None,
        payloads: vec![StreamPayload { data: payload.into(), encoding: PayloadEncoding::Text }],
        half_close_after_send: false,
        read_idle_ms: 1_000,
        max_read_bytes: 64 * 1024,
        expect_frames: 0,
    });
    base(env, s, Some(client), "lab-tls")
}

fn dtls(env: &Env, client: &Client<'_>, payload: &str) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", "dtls://localhost:18301");
    s.protocol = Protocol::Udp;
    s.udp = Some(UdpSpec {
        dtls: true,
        datagrams: vec![StreamPayload { data: payload.into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 1_000,
        max_datagrams: 10,
    });
    base(env, s, Some(client), "lab-tls")
}

async fn go(env: &Env, c: &ExecutionContext) -> ExecutionOutput {
    send(&env.engine, c).await
}

/// Echo-backend requests since `before` (ground truth: was the backend reached?).
fn echo_since(env: &Env, before: usize) -> usize {
    env.fx.echo.log.count_requests().saturating_sub(before)
}

/// Gateway runtime-log lines since `from` containing `needle` (operator-side
/// ground truth; never shown to the engine).
pub fn log_since(gw: &Gateway, from: usize, needle: &str) -> Vec<String> {
    gw.log_lines().into_iter().skip(from).filter(|l| l.contains(needle)).take(20).collect()
}

/// Frontend TLS refusal ground truth: the backend was not reached, the
/// gateway wrote no transaction line for the route, and its runtime log
/// records the handshake failure with one of `reasons`.
async fn frontend_refused_ground_truth(
    c: &mut Checks,
    env: &Env,
    gw: &Gateway,
    echo_before: usize,
    from: usize,
    proxy: &str,
    reasons: &[&str],
) -> Vec<String> {
    // The gateway logs the refusal asynchronously.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    c.add(CheckKind::GroundTruth, "the echo backend never received the request", echo_since(env, echo_before) == 0, "");
    let lines = op_lines(gw, from, proxy);
    c.add(
        CheckKind::GroundTruth,
        "the gateway logged no transaction for the route (refused before HTTP)",
        lines.is_empty(),
        format!("{lines:?}"),
    );
    let refusals = log_since(gw, from, "Frontend TLS handshake failed");
    c.add(
        CheckKind::GroundTruth,
        format!("gateway log: frontend handshake failed with one of {reasons:?}"),
        refusals.iter().any(|l| reasons.iter().any(|r| l.contains(r))),
        format!("{refusals:?}"),
    );
    refusals
}

async fn recovery_mtls(env: &Env, c: &mut Checks, url: &str) -> ExecutionOutput {
    let good = Client::lab(env, Some(&env.fx.pki.client_good));
    let r = go(env, &https(env, url, &good)).await;
    c.success(CheckKind::Recovery, &r);
    r
}

/// Finding for a TLS 1.3 refusal whose alert was lost to the peer's reset.
const LOST_ALERT: &str = "client.tls.closed_after_certificate_request";

/// TLS 1.3 client-certificate refusal: the alert after the client's flight,
/// or — when the gateway's reset discards it — a close before any response.
fn tls13_refusal_shape(kind: Option<FailureKind>) -> bool {
    matches!(
        kind,
        Some(
            FailureKind::TlsAlertAfterHandshake
                | FailureKind::ClosedBeforeResponse
                | FailureKind::ResetBeforeResponse
                | FailureKind::RequestWriteFailed
        )
    )
}

fn client_leg_tls_failure(c: &mut Checks, o: &ExecutionOutput) {
    no_response(c, o);
    c.absent_prefix(o, "ferrum.");
    absent_scope(c, o, SourceScope::GatewayToUpstream);
    never_recommends_bypass(c, o);
    c.not_success(o);
}

// ------------------------------------------------------------ frontend TLS

fn tls008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let good = Client::lab(env, Some(&env.fx.pki.client_good));
        let o = go(env, &https(env, &format!("{HTTPS}/tls/echo/echo"), &good)).await;
        c.success(CheckKind::Diagnosis, &o);
        let t = tls_obs(&o);
        c.add(
            CheckKind::Diagnosis,
            "gateway certificate verified against the profile's private CA",
            t.map(|t| t.verification == TlsVerification::Verified).unwrap_or(false),
            format!("{:?}", t.map(|t| &t.verification)),
        );
        c.add(
            CheckKind::Diagnosis,
            "selected client identity is recorded (subject only)",
            t.and_then(|t| t.client_certificate_presented.as_ref()).map(|s| s.subject.contains("anvil-lab-client-good")).unwrap_or(false),
            format!("{:?}", t.and_then(|t| t.client_certificate_presented.as_ref()).map(|s| &s.subject)),
        );
        c.add(
            CheckKind::Diagnosis,
            "the gateway's certificate request is recorded",
            t.and_then(|t| t.client_certificate_requested) == Some(true),
            format!("{:?}", t.and_then(|t| t.client_certificate_requested)),
        );
        record_excludes(&mut c, &o, "PRIVATE KEY", "private key PEM");
        let key_line = env.fx.pki.client_good.key.lines().nth(1).unwrap_or("").to_string();
        record_excludes(&mut c, &o, &key_line, "client private key material");
        c.absent_prefix(&o, "client.tls.");
        c.absent_prefix(&o, "ferrum.token");
        c.add(CheckKind::GroundTruth, "the echo backend received the request", echo_since(env, before) >= 1, "");
        let lines = op_lines(&env.gw, from, "tls-frontend-echo");
        c.add(
            CheckKind::GroundTruth,
            "gateway transaction logged with status 200",
            lines.iter().any(|l| l.contains("200")),
            format!("{lines:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn tls008_tls12(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let good = Client::lab(env, Some(&env.fx.pki.client_good));
        let o = go(env, &https(env, &format!("{HTTPS12}/tls/echo/echo"), &good)).await;
        c.success(CheckKind::Diagnosis, &o);
        let v = tls_obs(&o).and_then(|t| t.version.clone()).unwrap_or_default();
        c.add(CheckKind::Diagnosis, "TLS 1.2 was negotiated", v.contains("1_2") || v.contains("1.2"), v);
        c.add(CheckKind::GroundTruth, "the echo backend received the request", echo_since(env, before) >= 1, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn tls001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let mut cl = Client::lab(env, Some(&env.fx.pki.client_good));
        cl.roots = vec![&env.fx.pki.rogue_ca.cert];
        let o = go(env, &https(env, &format!("{HTTPS}/tls/echo/echo"), &cl)).await;
        has_claim(&mut c, &o, "client.tls.untrusted_issuer", SourceScope::ClientToPeer, Confidence::Confirmed);
        client_leg_tls_failure(&mut c, &o);
        // The gateway only sees Anvil's own alert: Anvil refused the gateway.
        let log = frontend_refused_ground_truth(&mut c, env, &env.gw, before, from, "tls-frontend-echo", &["UnknownCA"]).await;
        let r = recovery_mtls(env, &mut c, &format!("{HTTPS}/tls/echo/echo")).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

fn tls002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let good = Client::lab(env, Some(&env.fx.pki.client_good));
        let o = go(env, &https(env, &format!("https://{WRONG_HOST}:18343/tls/echo/echo"), &good)).await;
        has_claim(&mut c, &o, "client.tls.name_mismatch", SourceScope::ClientToPeer, Confidence::Confirmed);
        client_leg_tls_failure(&mut c, &o);
        c.absent_prefix(&o, "auth.");
        let log = frontend_refused_ground_truth(&mut c, env, &env.gw, before, from, "tls-frontend-echo", &["BadCertificate"]).await;
        let r = recovery_mtls(env, &mut c, &format!("{HTTPS}/tls/echo/echo")).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

/// Missing client certificate: TLS 1.3 (18343) and TLS 1.2 (18344) shapes.
fn missing_cert<'a>(env: &'a Env, url: &'static str, gw12: bool) -> Fut<'a> {
    Box::pin(async move {
        let mut c = Checks::new();
        let gw = if gw12 { &env.gw12 } else { &env.gw };
        let proxy = if gw12 { "tls12-frontend-echo" } else { "tls-frontend-echo" };
        let (before, from) = (env.fx.echo.log.count_requests(), gw.log_lines().len());
        let o = go(env, &https(env, url, &Client::lab(env, None))).await;
        c.has_any(&o, &["client.tls.client_cert_required", "client.tls.client_cert_probably_required", LOST_ALERT]);
        c.scope(&o, "client.tls.client_cert_required", SourceScope::ClientToPeer);
        c.max_confidence(&o, "client.tls.client_cert_probably_required", Confidence::Likely);
        c.max_confidence(&o, LOST_ALERT, Confidence::Likely);
        client_leg_tls_failure(&mut c, &o);
        // TLS 1.2: the refusal lands inside the handshake and its alert is
        // always read. TLS 1.3: the client finishes its side first and reads
        // the alert afterwards — unless the gateway's reset discards it.
        let kind = final_failure(&o);
        let shape_ok = if gw12 { kind == Some(FailureKind::TlsAlertReceived) } else { tls13_refusal_shape(kind) };
        c.add(CheckKind::Diagnosis, "refusal shape matches the negotiated TLS version", shape_ok, format!("{kind:?}"));
        let log = frontend_refused_ground_truth(&mut c, env, gw, before, from, proxy, &["peer sent no certificates"]).await;
        let r = recovery_mtls(env, &mut c, url).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

fn tls005(env: &Env) -> Fut<'_> {
    missing_cert(env, "https://localhost:18343/tls/echo/echo", false)
}

fn tls005_tls12(env: &Env) -> Fut<'_> {
    missing_cert(env, "https://localhost:18344/tls/echo/echo", true)
}

fn rogue_cert<'a>(env: &'a Env, url: &'static str, gw12: bool) -> Fut<'a> {
    Box::pin(async move {
        let mut c = Checks::new();
        let gw = if gw12 { &env.gw12 } else { &env.gw };
        let proxy = if gw12 { "tls12-frontend-echo" } else { "tls-frontend-echo" };
        let (before, from) = (env.fx.echo.log.count_requests(), gw.log_lines().len());
        let o = go(env, &https(env, url, &Client::lab(env, Some(&env.fx.pki.client_rogue)))).await;
        c.has_any(&o, &["client.tls.client_cert_rejected", "client.tls.peer_alert", LOST_ALERT]);
        c.max_confidence(&o, "client.tls.client_cert_rejected", Confidence::Likely);
        // Without the alert, the rejection of a presented certificate stays unknown.
        c.max_confidence(&o, LOST_ALERT, Confidence::Unknown);
        let kind = final_failure(&o);
        let shape_ok = if gw12 { kind == Some(FailureKind::TlsAlertReceived) } else { tls13_refusal_shape(kind) };
        c.add(CheckKind::Diagnosis, "refusal shape matches the negotiated TLS version", shape_ok, format!("{kind:?}"));
        c.scope(&o, "client.tls.client_cert_rejected", SourceScope::ClientToPeer);
        c.absent_prefix(&o, "client.tls.client_cert_required");
        client_leg_tls_failure(&mut c, &o);
        let log = frontend_refused_ground_truth(&mut c, env, gw, before, from, proxy, &["UnknownIssuer"]).await;
        let r = recovery_mtls(env, &mut c, url).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

fn tls006(env: &Env) -> Fut<'_> {
    rogue_cert(env, "https://localhost:18343/tls/echo/echo", false)
}

fn tls006_tls12(env: &Env) -> Fut<'_> {
    rogue_cert(env, "https://localhost:18344/tls/echo/echo", true)
}

/// Lookalike: the TLS layer accepts the certificate (valid chain) but the
/// mtls_auth plugin maps no consumer to it — an HTTP 401, not a TLS failure.
fn tls006_lookalike(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let o = go(env, &https(env, &format!("{HTTPS}/tls/mtls-auth/echo"), &Client::lab(env, Some(&env.fx.pki.client_unmapped)))).await;
        c.status_in(&o, &[401]);
        c.has(&o, "http.unauthorized");
        c.absent_prefix(&o, "client.tls.");
        c.add(
            CheckKind::Diagnosis,
            "the TLS handshake is recorded as verified and completed",
            tls_obs(&o).map(|t| t.verification == TlsVerification::Verified).unwrap_or(false),
            "",
        );
        if env.trusted {
            c.max_confidence(&o, "ferrum.outcome", Confidence::Likely);
        }
        c.add(CheckKind::GroundTruth, "the backend was not reached", echo_since(env, before) == 0, "");
        let lines = op_lines(&env.gw, from, "tls-mtls-auth");
        c.add(
            CheckKind::GroundTruth,
            "gateway logged a 401 for the mtls_auth route",
            lines.iter().any(|l| l.contains("401")),
            format!("{lines:?}"),
        );
        let r = go(env, &https(env, &format!("{HTTPS}/tls/mtls-auth/echo"), &Client::lab(env, Some(&env.fx.pki.client_good)))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn tls007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let mut cl = Client::lab(env, None);
        cl.identity = Some((env.fx.pki.client_good.cert.as_str(), env.fx.pki.client_rogue.key.as_str()));
        let o = go(env, &https(env, &format!("{HTTPS}/tls/echo/echo"), &cl)).await;
        has_claim(&mut c, &o, "local.client_identity_key_mismatch", SourceScope::LocalClient, Confidence::Confirmed);
        let networked =
            o.record.attempts.iter().any(|a| a.connection.is_some() || a.failure.as_ref().map(|f| f.phase) != Some(Phase::Prepare));
        c.add(CheckKind::Diagnosis, "the failure is local: no connection was attempted", !networked, format!("{:?}", final_failure(&o)));
        c.absent_prefix(&o, "client.tls.");
        c.absent_prefix(&o, "http.");
        c.add(CheckKind::GroundTruth, "the gateway's backend was never reached", echo_since(env, before) == 0, "");
        let r = recovery_mtls(env, &mut c, &format!("{HTTPS}/tls/echo/echo")).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn tls009(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let o = go(env, &https(env, "https://127.0.0.1:18380/tls/echo/echo", &Client::lab(env, Some(&env.fx.pki.client_good)))).await;
        c.has(&o, "client.tls.not_tls");
        c.max_confidence(&o, "client.tls.not_tls", Confidence::Likely);
        c.absent_prefix(&o, "client.tls.expired");
        c.no_confirmed_claim(&o, "expired");
        client_leg_tls_failure(&mut c, &o);
        c.add(CheckKind::GroundTruth, "the backend was not reached", echo_since(env, before) == 0, "");
        let r = go(env, &plain(env, "/tls/echo/echo")).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn tlsx01(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw12.log_lines().len());
        let mut cl = Client::lab(env, Some(&env.fx.pki.client_good));
        cl.min13 = true;
        let o = go(env, &https(env, &format!("{HTTPS12}/tls/echo/echo"), &cl)).await;
        has_claim(&mut c, &o, "client.tls.version_mismatch", SourceScope::ClientToPeer, Confidence::Confirmed);
        client_leg_tls_failure(&mut c, &o);
        c.absent_prefix(&o, "client.tls.client_cert");
        let log = frontend_refused_ground_truth(
            &mut c,
            env,
            &env.gw12,
            before,
            from,
            "tls12-frontend-echo",
            &["Tls12NotOffered", "incompatible"],
        )
        .await;
        let r = recovery_mtls(env, &mut c, &format!("{HTTPS12}/tls/echo/echo")).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

fn tls013(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let url = format!("{HTTPS}/tls/echo/echo");
        let a = Client::lab(env, Some(&env.fx.pki.client_good));
        let mut b = a.clone();
        b.roots = vec![];
        b.system_roots = true;
        let ra = go(env, &base(env, RequestSpec::http("GET", &url), Some(&a), "lab-tls-ws-a")).await;
        c.success(CheckKind::Diagnosis, &ra);
        let o = go(env, &base(env, RequestSpec::http("GET", &url), Some(&b), "lab-tls-ws-b")).await;
        has_claim(&mut c, &o, "client.tls.untrusted_issuer", SourceScope::ClientToPeer, Confidence::Confirmed);
        client_leg_tls_failure(&mut c, &o);
        let again = go(env, &base(env, RequestSpec::http("GET", &url), Some(&a), "lab-tls-ws-a")).await;
        c.success(CheckKind::Recovery, &again);
        Outcome { main: Some(o), recovery: Some(again), checks: c, operator_log: vec![] }
    })
}

fn tls014(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let url = format!("{HTTPS}/tls/echo/echo");
        let with = Client::lab(env, Some(&env.fx.pki.client_good));
        let without = Client::lab(env, None);
        let ra = go(env, &base(env, RequestSpec::http("GET", &url), Some(&with), "lab-tls-ws-a")).await;
        c.success(CheckKind::Diagnosis, &ra);
        // Another workspace, same host, no identity: must not ride on A's
        // authenticated pooled connection.
        let o = go(env, &base(env, RequestSpec::http("GET", &url), Some(&without), "lab-tls-ws-b")).await;
        c.has_any(&o, &["client.tls.client_cert_required", "client.tls.client_cert_probably_required", LOST_ALERT]);
        let reused = o.record.attempts.last().and_then(|a| a.connection.as_ref()).map(|c| c.reused).unwrap_or(false);
        c.add(CheckKind::Diagnosis, "workspace B did not reuse workspace A's mTLS connection", !reused, "");
        client_leg_tls_failure(&mut c, &o);
        // Same workspace, profile without identity: also a fresh security context.
        let o2 = go(env, &base(env, RequestSpec::http("GET", &url), Some(&without), "lab-tls-ws-a")).await;
        c.add(
            CheckKind::Diagnosis,
            "same workspace with a different profile does not reuse the authenticated connection",
            o2.record.response.is_none(),
            format!("{:?}", o2.record.response.as_ref().map(|r| r.status)),
        );
        let r = go(env, &base(env, RequestSpec::http("GET", &url), Some(&with), "lab-tls-ws-a")).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn bypass_client(env: &Env) -> Client<'_> {
    let mut cl = Client::lab(env, Some(&env.fx.pki.client_good));
    cl.roots = vec![];
    cl.system_roots = true;
    cl.verify = false;
    cl
}

fn tls015(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let url = format!("{HTTPS}/tls/echo/echo");
        let o = go(env, &https(env, &url, &bypass_client(env))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "insecure-TLS warning shown",
            o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::InsecureTls),
            format!("{:?}", o.record.outcome.warnings.iter().map(|w| w.code).collect::<Vec<_>>()),
        );
        has_claim(&mut c, &o, "client.tls.verification_bypassed", SourceScope::ClientToPeer, Confidence::Confirmed);
        let would = tls_obs(&o).map(|t| t.verification.clone());
        c.add(
            CheckKind::Diagnosis,
            "strict verification's verdict (untrusted issuer) is still recorded",
            matches!(would, Some(TlsVerification::Bypassed { would_have_failed: Some(FailureKind::TlsUntrustedIssuer) })),
            format!("{would:?}"),
        );
        never_recommends_bypass(&mut c, &o);
        c.add(CheckKind::Diagnosis, "the record says verification was disabled", !o.record.prepared.tls_verification_enabled, "");
        // The bypass is scoped to that request: the next strict request fails.
        let mut strict = bypass_client(env);
        strict.verify = true;
        let s = go(env, &https(env, &url, &strict)).await;
        c.has(&s, "client.tls.untrusted_issuer");
        never_recommends_bypass(&mut c, &s);
        c.add(
            CheckKind::Diagnosis,
            "no insecure-TLS warning on the strict request",
            !s.record.outcome.warnings.iter().any(|w| w.code == WarningCode::InsecureTls),
            "",
        );
        let r = recovery_mtls(env, &mut c, &url).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn tls016(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let p = go(env, &plain(env, "/tls/echo/echo")).await;
        c.success(CheckKind::Diagnosis, &p);
        c.add(CheckKind::Diagnosis, "plaintext HTTP records no TLS session", tls_obs(&p).is_none(), "");
        c.add(
            CheckKind::Diagnosis,
            "plaintext HTTP carries no insecure-TLS warning (TLS off is not verification off)",
            !p.record.outcome.warnings.iter().any(|w| w.code == WarningCode::InsecureTls),
            "",
        );
        c.absent_prefix(&p, "client.tls.verification_bypassed");
        let o = go(env, &https(env, &format!("{HTTPS}/tls/echo/echo"), &bypass_client(env))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "HTTPS bypass records an encrypted TLS session",
            tls_obs(&o).and_then(|t| t.version.clone()).is_some(),
            "",
        );
        c.add(
            CheckKind::Diagnosis,
            "HTTPS with verification off carries the insecure-TLS warning",
            o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::InsecureTls),
            "",
        );
        Outcome { main: Some(o), recovery: Some(p), checks: c, operator_log: vec![] }
    })
}

/// AUTH-026: a certificate-bound token (cnf.x5t#S256) presented over a
/// connection authenticated with a different — but valid — client
/// certificate. The TLS layer accepts both identities; only the token
/// binding differs, so the refusal is an HTTP 401, never a TLS failure.
fn auth026(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let url = format!("{HTTPS}/tls/bound-token/echo");
        let token = env.fx.bound_token(&env.fx.pki.client_good.cert);
        let with = |cl: &Client<'_>| {
            let mut x = https(env, &url, cl);
            let auth = AuthConfig::Bearer { token: SensitiveValue::template(&token), prefix: "Bearer".into() };
            x.spec.auth = auth.clone();
            x.auth_layers = vec![("request".into(), auth)];
            x
        };
        let bound = go(env, &with(&Client::lab(env, Some(&env.fx.pki.client_good)))).await;
        c.success(CheckKind::Diagnosis, &bound);
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let o = go(env, &with(&Client::lab(env, Some(&env.fx.pki.client_unmapped)))).await;
        c.status_in(&o, &[401]);
        let body = o.decoded_body.as_ref().unwrap_or(&o.body);
        let err =
            serde_json::from_slice::<serde_json::Value>(body).ok().and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from));
        c.add(
            CheckKind::GroundTruth,
            "gateway body error is \"mTLS binding mismatch\"",
            err.as_deref() == Some("mTLS binding mismatch"),
            format!("{err:?}"),
        );
        c.has(&o, "http.unauthorized");
        c.absent_prefix(&o, "client.tls.");
        if env.trusted {
            c.has(&o, "ferrum.outcome");
            c.max_confidence(&o, "ferrum.outcome", Confidence::Likely);
        }
        let prefix_advice: Vec<String> = o
            .record
            .findings
            .iter()
            .flat_map(|f| f.remediation.iter())
            .map(|r| r.text.to_lowercase())
            .filter(|t| t.contains("prefix") || t.contains("bearer spelling"))
            .collect();
        c.add(
            CheckKind::Diagnosis,
            "no advice to change the bearer prefix/spelling",
            prefix_advice.is_empty(),
            format!("{prefix_advice:?}"),
        );
        record_excludes(&mut c, &o, &token, "the bound access token");
        c.add(CheckKind::GroundTruth, "the backend was not reached", echo_since(env, before) == 0, "");
        let lines = op_lines(&env.gw, from, "tls-bound-token");
        c.add(
            CheckKind::GroundTruth,
            "gateway logged a 401 for the bound-token route",
            lines.iter().any(|l| l.contains("401")),
            format!("{lines:?}"),
        );
        // Recovery: a token bound to the certificate actually presented.
        let rebound = env.fx.bound_token(&env.fx.pki.client_unmapped.cert);
        let mut r = https(env, &url, &Client::lab(env, Some(&env.fx.pki.client_unmapped)));
        let auth = AuthConfig::Bearer { token: SensitiveValue::template(&rebound), prefix: "Bearer".into() };
        r.spec.auth = auth.clone();
        r.auth_layers = vec![("request".into(), auth)];
        let r = go(env, &r).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

// ---------------------------------------------------- TCP+TLS and DTLS

fn tls008_tcp(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.tcp_echo.log.entries().len();
        let o = go(env, &tcp_tls(env, &Client::lab(env, Some(&env.fx.pki.client_good)), "anvil-tcp-tls-probe")).await;
        let echoed = o.record.stream.as_ref().map(|s| s.received_bytes).unwrap_or(0);
        c.add(CheckKind::Diagnosis, "the payload was echoed back through the TCP+TLS listener", echoed >= 19, format!("{echoed} bytes"));
        c.add(
            CheckKind::Diagnosis,
            "client identity presented on the stream listener",
            tls_obs(&o).and_then(|t| t.client_certificate_presented.as_ref()).is_some(),
            "",
        );
        c.absent_prefix(&o, "client.tls.");
        c.add(CheckKind::GroundTruth, "the TCP echo backend saw the bytes", env.fx.tcp_echo.log.entries().len() > before, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn tls005_tcp(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.tcp_echo.log.entries().len();
        let o = go(env, &tcp_tls(env, &Client::lab(env, None), "anvil-tcp-tls-probe")).await;
        c.not_success(&o);
        c.has_any(&o, &["client.tls.client_cert_required", "client.tls.client_cert_probably_required"]);
        let echoed = o.record.stream.as_ref().map(|s| s.received_bytes).unwrap_or(0);
        c.add(CheckKind::Diagnosis, "no echoed payload is reported", echoed == 0, format!("{echoed}"));
        absent_scope(&mut c, &o, SourceScope::GatewayToUpstream);
        never_recommends_bypass(&mut c, &o);
        c.add(CheckKind::GroundTruth, "the TCP echo backend was never dialled", env.fx.tcp_echo.log.entries().len() == before, "");
        let r = go(env, &tcp_tls(env, &Client::lab(env, Some(&env.fx.pki.client_good)), "anvil-tcp-tls-recovery")).await;
        c.add(
            CheckKind::Recovery,
            "with the client certificate the payload is echoed",
            r.record.stream.as_ref().map(|s| s.received_bytes).unwrap_or(0) > 0,
            "",
        );
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn dtls_received(o: &ExecutionOutput) -> u64 {
    o.record.stream.as_ref().map(|s| s.received_count).unwrap_or(0)
}

fn proto022(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.udp_echo.log.entries().len();
        let o = go(env, &dtls(env, &Client::lab(env, Some(&env.fx.pki.client_good)), "anvil-dtls-probe")).await;
        c.add(
            CheckKind::Diagnosis,
            "the datagram was echoed through the DTLS listener",
            dtls_received(&o) >= 1,
            format!("{}", dtls_received(&o)),
        );
        c.absent_prefix(&o, "client.dtls.");
        c.absent_prefix(&o, "client.tls.");
        c.add(CheckKind::GroundTruth, "the UDP echo backend received the datagram", env.fx.udp_echo.log.entries().len() > before, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

/// DTLS refusal variants: `identity` None = no configured identity.
fn dtls_refused<'a>(env: &'a Env, identity: Option<&'static str>, rogue_root: bool) -> Fut<'a> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.udp_echo.log.entries().len();
        let mut cl = Client::lab(env, None);
        match identity {
            Some("rogue") => cl.identity = Some((env.fx.pki.client_rogue.cert.as_str(), env.fx.pki.client_rogue.key.as_str())),
            Some(_) => cl.identity = Some((env.fx.pki.client_good.cert.as_str(), env.fx.pki.client_good.key.as_str())),
            None => {}
        }
        if rogue_root {
            cl.roots = vec![&env.fx.pki.rogue_ca.cert];
        }
        let from = env.gw.log_lines().len();
        let o = go(env, &dtls(env, &cl, "anvil-dtls-probe")).await;
        c.not_success(&o);
        c.add(CheckKind::Diagnosis, "no echoed datagram is reported", dtls_received(&o) == 0, format!("{}", dtls_received(&o)));
        if rogue_root {
            has_claim(&mut c, &o, "client.tls.untrusted_issuer", SourceScope::ClientToPeer, Confidence::Confirmed);
        } else {
            // DTLS 1.3 (negotiated by 0.9.5): the gateway checks the client
            // certificate after the client's final flight and sends
            // close_notify; DTLS 1.2 would leave the client retransmitting.
            c.has_any(&o, &["dtls.closed_without_response", "client.dtls.handshake_timeout", "client.dtls.handshake_failed"]);
            c.max_confidence(&o, "client.dtls.handshake_failed", Confidence::Unknown);
            c.absent_prefix(&o, "udp.no_response");
        }
        absent_scope(&mut c, &o, SourceScope::GatewayToUpstream);
        never_recommends_bypass(&mut c, &o);
        c.add(
            CheckKind::GroundTruth,
            "no datagram reached the UDP backend",
            env.fx.udp_echo.log.entries().len() == before,
            format!("{}", env.fx.udp_echo.log.entries().len() - before),
        );
        let mut log = Vec::new();
        if !rogue_root {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            log = log_since(&env.gw, from, "DTLS client certificate verification failed");
            c.add(CheckKind::GroundTruth, "gateway log: DTLS client certificate verification failed", !log.is_empty(), "");
        }
        let r = go(env, &dtls(env, &Client::lab(env, Some(&env.fx.pki.client_good)), "anvil-dtls-recovery")).await;
        c.add(CheckKind::Recovery, "with the right identity and root the datagram is echoed", dtls_received(&r) >= 1, "");
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

fn proto022_nocert(env: &Env) -> Fut<'_> {
    dtls_refused(env, None, false)
}

fn proto022_rogue(env: &Env) -> Fut<'_> {
    dtls_refused(env, Some("rogue"), false)
}

fn proto022_root(env: &Env) -> Fut<'_> {
    dtls_refused(env, Some("good"), true)
}

// ------------------------------------------------------- upstream TLS

fn up_request(env: &Env, path: &str) -> ExecutionContext {
    plain(env, path)
}

/// Common assertions for a gateway-to-backend setup failure.
fn upstream_setup_failure(c: &mut Checks, env: &Env, o: &ExecutionOutput, tokens: &[&str]) {
    c.status_in(o, &[502]);
    c.token_any(o, tokens, env.trusted);
    for t in tokens {
        // `connection_failure` names the gateway-to-backend leg. 0.9.5 also
        // stamps `backend_error` on an application's own 5xx and on some
        // gateway refusals, so that token alone must not claim a leg even
        // though the operator log shows this one was the upstream leg.
        let scope = if *t == "ferrum.token.backend_error" { SourceScope::Unknown } else { SourceScope::GatewayToUpstream };
        c.scope(o, t, scope);
        c.max_confidence(o, t, Confidence::Likely);
    }
    // The coarse token never proves TLS, and Anvil's own leg was fine.
    c.no_confirmed_claim(o, "tls");
    c.no_confirmed_claim(o, "certificate");
    no_client_identity_blame(c, o);
    c.add(
        CheckKind::Diagnosis,
        "Anvil's own connection to the gateway is recorded as plaintext and completed",
        o.record.response.is_some() && tls_obs(o).is_none(),
        "",
    );
}

async fn up_recovery(env: &Env, c: &mut Checks) -> ExecutionOutput {
    let r = go(env, &up_request(env, "/up/tls-trusted/echo")).await;
    c.success(CheckKind::Recovery, &r);
    r
}

fn fixture_saw_failed_handshake(c: &mut Checks, f: &anvil_fixtures::http::Fixture, before: usize) {
    let errs: Vec<String> = f
        .log
        .entries()
        .into_iter()
        .skip(before)
        .filter_map(|e| match e.event {
            anvil_fixtures::GroundTruth::TlsHandshakeFailed { error } => Some(error),
            _ => None,
        })
        .collect();
    c.add(CheckKind::GroundTruth, "the backend fixture saw the gateway's TLS handshake fail", !errs.is_empty(), format!("{errs:?}"));
}

fn ctrl_up(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.trusted.log.count_requests();
        let o = go(env, &up_request(env, "/up/tls-trusted/echo")).await;
        c.success(CheckKind::Diagnosis, &o);
        c.absent_prefix(&o, "ferrum.token");
        c.add(CheckKind::GroundTruth, "the trusted TLS backend received the request", env.fx.trusted.log.count_requests() > before, "");
        // The gateway may reuse a pooled connection, so any completed
        // handshake in the fixture's log counts.
        let ok =
            env.fx.trusted.log.entries().into_iter().any(|e| matches!(e.event, anvil_fixtures::GroundTruth::TlsHandshakeCompleted { .. }));
        c.add(CheckKind::GroundTruth, "the gateway completed TLS to the trusted backend", ok, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

/// UP-004/005 family: the gateway rejects the backend's certificate.
fn up_cert<'a>(env: &'a Env, path: &'static str, proxy: &'static str, which: &'static str) -> Fut<'a> {
    Box::pin(async move {
        let mut c = Checks::new();
        let fx = match which {
            "untrusted" => &env.fx.untrusted,
            "expired" => &env.fx.expired,
            _ => &env.fx.wrong_name,
        };
        let (before, from) = (fx.log.entries().len(), env.gw.log_lines().len());
        let o = go(env, &up_request(env, path)).await;
        upstream_setup_failure(&mut c, env, &o, &["ferrum.token.connection_failure"]);
        let lines = op_lines(&env.gw, from, proxy);
        c.operator_class(&lines, proxy, &["tls_error"]);
        fixture_saw_failed_handshake(&mut c, fx, before);
        let r = up_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn up004(env: &Env) -> Fut<'_> {
    up_cert(env, "/up/tls-untrusted/", "up004-tls-untrusted", "untrusted")
}

fn up004_expired(env: &Env) -> Fut<'_> {
    up_cert(env, "/up/tls-expired/", "up004-tls-expired", "expired")
}

fn up005(env: &Env) -> Fut<'_> {
    up_cert(env, "/up/tls-wrong-name/", "up005-tls-wrong-name", "wrong")
}

fn mtls_missing<'a>(env: &'a Env, path: &'static str, proxy: &'static str, tls12: bool) -> Fut<'a> {
    Box::pin(async move {
        let mut c = Checks::new();
        let fx = if tls12 { &env.fx.mtls12 } else { &env.fx.mtls13 };
        let (before, from) = (fx.log.entries().len(), env.gw.log_lines().len());
        let o = go(env, &up_request(env, path)).await;
        // TLS 1.3 client-certificate rejection on the reqwest pool is reported
        // as either a pre-wire pool cancellation or a post-connect reset.
        upstream_setup_failure(&mut c, env, &o, &["ferrum.token.connection_failure", "ferrum.token.backend_error"]);
        let lines = op_lines(&env.gw, from, proxy);
        c.operator_class(&lines, proxy, &["connection_pool_error", "connection_reset", "tls_error", "connection_closed", "request_error"]);
        fixture_saw_failed_handshake(&mut c, fx, before);
        // Recovery: the gateway presents its own backend identity.
        let r = go(env, &up_request(env, "/up/mtls-ok/echo")).await;
        c.success(CheckKind::Recovery, &r);
        // The recovery request may ride a pooled connection, so look at every
        // handshake the mTLS backend has completed.
        let cn = env.fx.mtls13.log.entries().into_iter().find_map(|e| match e.event {
            anvil_fixtures::GroundTruth::TlsHandshakeCompleted { client_cert_cn, .. } => client_cert_cn,
            _ => None,
        });
        c.add(
            CheckKind::GroundTruth,
            "recovery: the backend saw the gateway's backend identity (not Anvil's)",
            cn.as_deref() == Some("anvil-lab-gateway-backend-client"),
            format!("{cn:?}"),
        );
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn up006(env: &Env) -> Fut<'_> {
    mtls_missing(env, "/up/mtls-missing/", "up006-mtls-missing-h1", false)
}

fn up006_tls12(env: &Env) -> Fut<'_> {
    mtls_missing(env, "/up/mtls-missing-tls12/", "up006-mtls-missing-tls12", true)
}

fn up007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.stall.log.entries().len(), env.gw.log_lines().len());
        let o = go(env, &up_request(env, "/up/tls-stall/")).await;
        upstream_setup_failure(&mut c, env, &o, &["ferrum.token.connection_failure"]);
        c.no_confirmed_claim(&o, "timeout");
        let lines = op_lines(&env.gw, from, "up007-tls-stall");
        c.operator_class(&lines, "up007-tls-stall", &["connection_timeout"]);
        c.add(CheckKind::GroundTruth, "the stalling backend accepted TCP", env.fx.stall.log.entries().len() > before, "");
        let r = up_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn up008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.plain.log.entries().len(), env.gw.log_lines().len());
        let o = go(env, &up_request(env, "/up/scheme-https-to-plain/")).await;
        upstream_setup_failure(&mut c, env, &o, &["ferrum.token.connection_failure"]);
        c.no_confirmed_claim(&o, "expired");
        let lines = op_lines(&env.gw, from, "up008-https-to-plain");
        c.operator_class(&lines, "up008-https-to-plain", &["tls_error"]);
        c.add(CheckKind::GroundTruth, "the plaintext backend received a connection", env.fx.plain.log.entries().len() > before, "");
        c.add(
            CheckKind::GroundTruth,
            "the plaintext backend never received an HTTP request",
            env.fx
                .plain
                .log
                .entries()
                .into_iter()
                .skip(before)
                .all(|e| !matches!(e.event, anvil_fixtures::GroundTruth::RequestReceived { .. })),
            "",
        );
        let r = up_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn up008_http_to_tls(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.tls_for_plain.log.entries().len(), env.gw.log_lines().len());
        let o = go(env, &up_request(env, "/up/scheme-http-to-tls/")).await;
        upstream_setup_failure(&mut c, env, &o, &["ferrum.token.backend_error", "ferrum.token.connection_failure"]);
        c.no_confirmed_claim(&o, "expired");
        let lines = op_lines(&env.gw, from, "up008-http-to-tls");
        c.operator_class(&lines, "up008-http-to-tls", &["request_error", "connection_closed", "connection_reset", "protocol_error"]);
        fixture_saw_failed_handshake(&mut c, &env.fx.tls_for_plain, before);
        let r = up_recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

/// UP-016: repeat the TLS 1.3 backend-mTLS route and check that every
/// public observation stays consistent with the operator-side class
/// (pool cancellation ↔ `connection_failure`, post-connect reset ↔
/// `backend_error`) without Anvil ever claiming the precise cause.
fn up016(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let mut last = None;
        let mut seen = Vec::new();
        let mut consistent = true;
        let mut all_lines = Vec::new();
        for _ in 0..5 {
            let from = env.gw.log_lines().len();
            let o = go(env, &up_request(env, "/up/mtls-missing/")).await;
            // Give the access log a moment to flush.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let lines = op_lines(&env.gw, from, "up006-mtls-missing-h1");
            let class = lines
                .iter()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .find_map(|v| v.get("error_class").and_then(|x| x.as_str()).map(|s| s.to_string()))
                .unwrap_or_default();
            let token = o
                .record
                .response
                .as_ref()
                .and_then(|r| r.header_values("x-gateway-error").first().map(|s| s.to_string()))
                .unwrap_or_default();
            let expected = match class.as_str() {
                "connection_pool_error" | "tls_error" => "connection_failure",
                "connection_reset" | "connection_closed" | "request_error" => "backend_error",
                _ => "",
            };
            consistent &= !expected.is_empty() && token == expected;
            seen.push(format!("{class}->{token}"));
            c.no_confirmed_claim(&o, "tls");
            c.no_confirmed_claim(&o, "certificate");
            c.absent_prefix(&o, "client.tls.");
            all_lines.extend(lines);
            last = Some(o);
        }
        c.add(CheckKind::GroundTruth, "every public token matches the operator-side class mapping", consistent, format!("{seen:?}"));
        let o = last.expect("five attempts");
        c.status_in(&o, &[502]);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: all_lines }
    })
}

// ------------------------------------------------------------ registry

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "TLS-008", title: "Valid frontend mTLS (TLS 1.3 listener)", run: tls008 },
        Def { id: "TLS-008.tls12", title: "Valid frontend mTLS (TLS 1.2-only listener)", run: tls008_tls12 },
        Def { id: "TLS-001", title: "Gateway certificate from a root the client does not trust", run: tls001 },
        Def { id: "TLS-002", title: "Gateway certificate does not match the requested host name", run: tls002 },
        Def { id: "TLS-005", title: "mTLS required, no client certificate (TLS 1.3)", run: tls005 },
        Def { id: "TLS-005.tls12", title: "mTLS required, no client certificate (TLS 1.2)", run: tls005_tls12 },
        Def { id: "TLS-006", title: "Client certificate from a rogue CA (TLS 1.3)", run: tls006 },
        Def { id: "TLS-006.tls12", title: "Client certificate from a rogue CA (TLS 1.2)", run: tls006_tls12 },
        Def { id: "TLS-006.lookalike", title: "Certificate accepted by TLS but unmapped by mtls_auth (HTTP 401)", run: tls006_lookalike },
        Def { id: "TLS-007", title: "Client certificate / private key mismatch (local)", run: tls007 },
        Def { id: "TLS-009", title: "HTTPS sent to the gateway's plaintext listener", run: tls009 },
        Def { id: "TLS-X01", title: "Client requires TLS 1.3, gateway listener allows only TLS 1.2", run: tlsx01 },
        Def { id: "TLS-013", title: "Private CA scoped to one workspace", run: tls013 },
        Def { id: "TLS-014", title: "mTLS connection not reused across security contexts", run: tls014 },
        Def { id: "TLS-015", title: "Verification bypass is scoped and warned", run: tls015 },
        Def { id: "TLS-016", title: "TLS off versus verification off", run: tls016 },
        Def { id: "AUTH-026", title: "Certificate-bound token presented with another valid client certificate", run: auth026 },
        Def { id: "TLS-008.tcp", title: "Valid mTLS on the TCP+TLS stream listener", run: tls008_tcp },
        Def { id: "TLS-005.tcp", title: "No client certificate on the TCP+TLS stream listener", run: tls005_tcp },
        Def { id: "PROTO-022", title: "DTLS listener with valid client identity", run: proto022 },
        Def { id: "PROTO-022.nocert", title: "DTLS listener, no configured client identity", run: proto022_nocert },
        Def { id: "PROTO-022.rogue", title: "DTLS listener, client identity from a rogue CA", run: proto022_rogue },
        Def { id: "PROTO-022.root", title: "DTLS listener, client trusts the wrong root", run: proto022_root },
        Def { id: "CTRL-UP-TLS", title: "Positive control: gateway TLS to a trusted backend", run: ctrl_up },
        Def { id: "UP-004", title: "Backend certificate not trusted by the gateway", run: up004 },
        Def { id: "UP-004.expired", title: "Backend certificate expired", run: up004_expired },
        Def { id: "UP-005", title: "Backend certificate name mismatch", run: up005 },
        Def { id: "UP-006", title: "Backend requires a client certificate the gateway lacks (TLS 1.3)", run: up006 },
        Def { id: "UP-006.tls12", title: "Backend requires a client certificate the gateway lacks (TLS 1.2)", run: up006_tls12 },
        Def { id: "UP-007", title: "Backend TLS handshake stall", run: up007 },
        Def { id: "UP-008", title: "Gateway speaks TLS to a plaintext backend", run: up008 },
        Def { id: "UP-008.http-to-tls", title: "Gateway speaks plaintext to a TLS backend", run: up008_http_to_tls },
        Def { id: "UP-016", title: "Backend mTLS rejection class stays consistent and unclaimed", run: up016 },
    ]
}

/// Registered scenarios this environment cannot run, with the reason.
fn skips(env_probe: &[(&'static str, bool, String)]) -> Vec<(&'static str, &'static str, String)> {
    let probe = |label: &str| {
        env_probe
            .iter()
            .find(|(l, _, _)| *l == label)
            .map(|(_, refused, msg)| {
                if *refused {
                    format!("the live `ferrum-edge validate` refused it: {msg}")
                } else {
                    format!("NOTE: `ferrum-edge validate` accepted it ({msg}); a dedicated instance would be needed")
                }
            })
            .unwrap_or_else(|| "the refusal probe did not run".into())
    };
    let release = crate::gateway::release_label();
    vec![
        (
            "TLS-003",
            "Expired gateway certificate",
            format!(
                "infeasible on {release}: the gateway refuses to start with an expired frontend certificate ({}), so no client can observe one from it. Expired-certificate handling is exercised on the upstream leg by UP-004.expired and on the client leg by anvil-transport tests.",
                probe("expired")
            ),
        ),
        (
            "TLS-004",
            "Not-yet-valid gateway certificate",
            format!(
                "infeasible on {release}: the gateway refuses to start with a not-yet-valid frontend certificate ({}). Client-side not-yet-valid classification is covered by anvil-transport tests.",
                probe("future")
            ),
        ),
        (
            "TLS-010",
            "Frontend TLS handshake stall",
            format!("infeasible against the real gateway: the {release} frontend always answers a ClientHello (its handshake timeout only closes clients that stall). A client-leg stall needs a non-gateway fault fixture; UP-007 covers the stall on the gateway-to-backend leg."),
        ),
        (
            "TLS-011",
            "Unadorned handshake reset",
            format!("infeasible against the real gateway: {release} ends every frontend handshake refusal with a TLS alert; a bare reset needs a client-leg fault fixture that would not be the gateway."),
        ),
        (
            "TLS-012",
            "ALPN mismatch",
            format!("infeasible against the real gateway: every {release} TLS listener (HTTPS and TCP+TLS share one rustls ServerConfig) offers h2, http/1.1 and acme-tls/1 (src/tls/mod.rs), and every Anvil HTTP-family policy offers h2 and/or http/1.1, so there is never an ALPN gap to observe."),
        ),
        (
            "TLS-017",
            "TLS through a forward proxy",
            "out of this profile: needs a forward-proxy fixture in front of the gateway; the gateway plays no part in the proxy CONNECT leg.".into(),
        ),
        (
            "TLS-018",
            "Redirect certificate boundary",
            "out of this profile: the gateway only relays a backend redirect; the certificate-boundary decision is Anvil's redirect policy, covered by engine tests.".into(),
        ),
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "tls",
        about: "Frontend TLS/mTLS (HTTPS 18343/18344, TCP+TLS 18302, DTLS 18301) and gateway-to-backend TLS (HTTP 18380)",
        scenarios: || {
            let mut v: Vec<(&'static str, &'static str)> = all().into_iter().map(|d| (d.id, d.title)).collect();
            v.extend(skips(&[]).into_iter().map(|(id, title, _)| (id, title)));
            v
        },
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

/// Run `ferrum-edge validate` on the TLS-1.2 instance config with a
/// different frontend certificate (operator-side check for TLS-003/004).
async fn validate_with_cert(certs: &std::path::Path, cert_file: &str) -> (bool, String) {
    let Ok((bin, _)) = gateway::binary() else { return (false, "gateway binary unavailable".into()) };
    let root = gateway::repo_root();
    let dir = root.join("lab/.run/tls-validity");
    if std::fs::create_dir_all(&dir).is_err() {
        return (false, "cannot create run dir".into());
    }
    let read = |n: &str| std::fs::read_to_string(root.join("lab/gateway").join(n)).unwrap_or_default();
    let vars = [("LAB_CERTS", certs.display().to_string())];
    let conf = gateway::render(&read("tls.tls12.conf"), &vars)
        .replace("/gateway-server.pem", &format!("/{cert_file}.pem"))
        .replace("/gateway-server.key", &format!("/{cert_file}.key"));
    let yaml = gateway::render(&read("tls.tls12.yaml"), &vars);
    let (cp, yp) = (dir.join(format!("{cert_file}.conf")), dir.join(format!("{cert_file}.yaml")));
    if std::fs::write(&cp, conf).is_err() || std::fs::write(&yp, yaml).is_err() {
        return (false, "cannot write probe config".into());
    }
    let out = tokio::process::Command::new(&bin)
        .args(["validate", "-m", "file", "-s"])
        .arg(&cp)
        .arg("-c")
        .arg(&yp)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.display().to_string())
        .current_dir(&dir)
        .output()
        .await;
    match out {
        Ok(o) => {
            let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            let line = text.lines().find(|l| l.contains("Validation error")).or_else(|| text.lines().last()).unwrap_or("");
            let msg = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| v.pointer("/fields/message").and_then(|m| m.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| line.to_string())
                .replace(&certs.display().to_string(), "<run>/certs")
                .trim()
                .to_string();
            (!o.status.success(), msg)
        }
        Err(e) => (false, format!("validate did not run: {e}")),
    }
}

async fn start() -> anyhow::Result<Env> {
    let certs = gateway::repo_root().join("lab/.run/tls/certs");
    let fx = TlsFixtures::start(certs.clone()).await?;
    let vars = [("LAB_CERTS", certs.display().to_string())];
    let gw = Gateway::start("tls", "tls.conf", "tls.yaml", &vars, 18390, &[]).await?;
    let gw12 = match Gateway::start("tls-tls12", "tls.tls12.conf", "tls.tls12.yaml", &vars, 18391, &[]).await {
        Ok(g) => g,
        Err(e) => {
            gw.stop().await;
            return Err(e);
        }
    };
    let mut probe = Vec::new();
    for (label, file) in [("expired", "gateway-server-expired"), ("future", "gateway-server-future")] {
        let (refused, msg) = validate_with_cert(&certs, file).await;
        probe.push((label, refused, msg));
    }
    // Let the gateways' startup capability probes to the fixtures settle.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    Ok(Env { engine: Engine::new(), fx, gw, gw12, trusted: true, validity_probe: probe })
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("tls")?;
    let mut env = start().await?;
    let res = harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await;
    let mut results = match res {
        Ok(r) => r,
        Err(e) => {
            env.gw.stop().await;
            env.gw12.stop().await;
            return Err(e);
        }
    };
    for (id, title, reason) in skips(&env.validity_probe) {
        if args.only.is_empty() || args.only.iter().any(|s| s.eq_ignore_ascii_case(id)) {
            eprintln!("{id:22} skipped {title}\n    — {reason}");
            results.push(ctx.skipped(id, title, &reason));
        }
    }
    let fin = harness::finish(&ctx, &env, &results);
    env.gw.stop().await;
    env.gw12.stop().await;
    fin?;
    Ok(results)
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!(
        "tls lab running: HTTPS {HTTPS} (mTLS required, TLS 1.2–1.3), {HTTPS12} (mTLS, TLS 1.2 only), plaintext {PLAIN}, TCP+TLS localhost:18302, DTLS localhost:18301"
    );
    println!("certificates (per run, lab-only): {}", env.fx.certs_dir.display());
    println!("operator logs: {} and {}", env.gw.log_path.display(), env.gw12.log_path.display());
    harness::wait_for_shutdown().await?;
    env.gw.stop().await;
    env.gw12.stop().await;
    Ok(())
}
