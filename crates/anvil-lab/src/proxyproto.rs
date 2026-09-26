//! Scenarios for the `proxyproto` gateway profile: Anvil acting as the load
//! balancer in front of Ferrum Edge stream listeners configured with
//! `stream_proxy_protocol: true` (PROXY v1/v2 on tcp / tcp+TLS, the v2
//! `DGRAM` envelope on udp / dtls, and the authenticated envelope).
//!
//! Two gateway instances run side by side because the datagram secret is
//! process-global: `proxyproto` (address-trust posture, streams on `[::]`)
//! and `proxyproto-auth` (`FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`, streams on
//! 127.0.0.1). Ground truth is the gateway's operator log (the stream
//! transaction summary's `client_ip`, the PROXY warnings and datagram drop
//! reasons) and the fixtures behind the gateway; neither is ever given to the
//! engine. A close or silence alone never yields a confirmed PROXY claim.

use crate::fixtures_proxyproto::ProxyProtoFixtures;
use crate::gateway::{self, Gateway};
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::Id;
use anvil_domain::diagnostics::Confidence;
use anvil_domain::execution::{AttemptObservation, Direction, FailureKind, Phase, PhaseStatus, TlsVerification};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::proxy_protocol::*;
use anvil_domain::request::*;
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{HostBinding, TlsMinVersion, TlsProfile};
use anvil_engine::context::MemorySecrets;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::proxy_protocol::{ProxyEvent, ProxyFixture};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const ADMIN_PORT: u16 = 18990;
const AUTH_ADMIN_PORT: u16 = 18991;
const TCP: &str = "127.0.0.1:18901";
const TCP_TLS: &str = "127.0.0.1:18902";
const UDP: &str = "127.0.0.1:18903";
const DTLS: &str = "127.0.0.1:18904";
const UDP_AUTH: &str = "127.0.0.1:18911";
const DTLS_AUTH: &str = "127.0.0.1:18912";
const GATEWAY_PORTS: &[u16] = &[18980, 18981, 18901, 18902, 18903, 18904, 18982, 18983, 18911, 18912];
/// Ferrum rate-limits datagram-drop warnings to one per second per listener;
/// drop scenarios wait this long first so their own reason is logged.
const DROP_LOG_GAP: Duration = Duration::from_millis(1_100);

pub struct Env {
    pub engine: Engine,
    pub fx: ProxyProtoFixtures,
    pub gateway: Gateway,
    pub auth_gateway: Gateway,
    pub trusted: bool,
    /// The datagram secret, known only to the gateway process and to Anvil's in-memory vault.
    secret: Zeroizing<String>,
    secret_ref: SecretRef,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<std::path::PathBuf> {
        vec![self.gateway.log_path.clone(), self.auth_gateway.log_path.clone()]
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

// ------------------------------------------------------------ contexts ---

fn ferrum_profile() -> IntegrationProfile {
    IntegrationProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab proxyproto gateway".into(),
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

fn ctx_with(env: &Env, spec: RequestSpec, tls: bool) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    c.isolation = "lab-proxyproto".into();
    if env.trusted {
        c.integrations.push(ferrum_profile());
    }
    let mut run = SettingsOverrides {
        timeouts: Some(TimeoutOverrides {
            connect_ms: Some(Some(3_000)),
            tls_handshake_ms: Some(Some(3_000)),
            total_ms: Some(Some(20_000)),
            ..Default::default()
        }),
        ..Default::default()
    };
    if tls {
        let p = TlsProfile {
            id: Id::new(),
            workspace_id: Id::new(),
            name: "lab proxyproto trust".into(),
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![env.fx.pki.ca.cert.clone()],
            client_identity: None,
            bindings: vec![],
            min_version: TlsMinVersion::Tls12,
            server_name_override: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        run.tls_profile_id = Some(p.id);
        c.tls_profiles.push(p);
    }
    c.settings_layers.push(("run".into(), run));
    let mut vault = HashMap::new();
    vault.insert(env.secret_ref.id, env.secret.clone());
    c.secrets = Arc::new(MemorySecrets(vault));
    c
}

fn header(version: ProxyHeaderVersion, source: Option<&str>) -> ProxyHeaderSpec {
    ProxyHeaderSpec {
        version,
        command: ProxyCommand::Proxy,
        family: ProxyAddressFamily::Auto,
        source: source.map(str::to_string),
        destination: None,
        authority: None,
        tlvs: vec![],
        raw_hex: None,
    }
}

fn tcp_ctx(env: &Env, url: &str, payload: &str, h: Option<ProxyHeaderSpec>) -> ExecutionContext {
    let tls = url.starts_with("tls://");
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Tcp;
    s.tcp = Some(TcpSpec {
        tls,
        framing: TcpFraming::NewlineDelimited,
        payloads: vec![StreamPayload { data: payload.into(), encoding: PayloadEncoding::Text }],
        half_close_after_send: false,
        read_idle_ms: 1_500,
        max_read_bytes: 64 * 1024,
        expect_frames: 1,
        proxy_protocol: h,
    });
    ctx_with(env, s, tls)
}

fn envelope(source: Option<&str>, auth: Option<DatagramAuthSpec>) -> DatagramEnvelopeSpec {
    DatagramEnvelopeSpec {
        command: ProxyCommand::Proxy,
        family: ProxyAddressFamily::Auto,
        source: source.map(str::to_string),
        destination: None,
        authentication: auth,
    }
}

fn udp_ctx(env: &Env, url: &str, payload: &str, e: Option<DatagramEnvelopeSpec>) -> ExecutionContext {
    let dtls = url.starts_with("dtls://");
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Udp;
    s.udp = Some(UdpSpec {
        dtls,
        datagrams: vec![StreamPayload { data: payload.into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 800,
        max_datagrams: 10,
        proxy_protocol: e,
    });
    ctx_with(env, s, dtls)
}

/// Authentication with the vault secret for the listener `bind:port`.
fn vault_auth(env: &Env, sender_id: u32, bind: &str) -> DatagramAuthSpec {
    DatagramAuthSpec {
        secret: SensitiveValue::Secret { secret: env.secret_ref.clone() },
        listener_protocol: None,
        listener_bind_address: bind.into(),
        listener_port: None,
        sender_id,
        epoch: None,
        first_sequence: 0,
        timestamp_offset_ms: 0,
    }
}

async fn send(env: &Env, c: &ExecutionContext) -> ExecutionOutput {
    env.engine.execute(c, anvil_transport::recorder::EventCtx::none(), CancellationToken::new()).await
}

// ------------------------------------------------------ observation helpers ---

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn last(o: &ExecutionOutput) -> Option<&AttemptObservation> {
    o.record.attempts.last()
}

fn sent_header(o: &ExecutionOutput) -> Option<ProxyHeaderObservation> {
    last(o).and_then(|a| a.connection.as_ref()).and_then(|c| c.proxy_header.clone())
}

fn previews(o: &ExecutionOutput, kind: &str) -> Vec<String> {
    o.record
        .stream
        .as_ref()
        .map(|s| s.messages.iter().filter(|m| m.direction == Direction::Received && m.kind == kind).map(|m| m.preview.clone()).collect())
        .unwrap_or_default()
}

fn outcome_line(o: &ExecutionOutput) -> String {
    format!(
        "status={:?} failure={:?} findings={:?}",
        o.record.outcome.protocol_status,
        last(o).and_then(|a| a.failure.as_ref()).map(|f| (f.kind, f.phase)),
        codes(o)
    )
}

fn alternatives(o: &ExecutionOutput, code: &str) -> Vec<String> {
    o.record.findings.iter().find(|f| f.code == code).map(|f| f.alternatives.clone()).unwrap_or_default()
}

fn local_addr(o: &ExecutionOutput) -> Option<SocketAddr> {
    last(o).and_then(|a| a.connection.as_ref()).and_then(|c| c.local_address.as_deref()).and_then(|a| a.parse().ok())
}

fn op_from(g: &Gateway) -> usize {
    g.log_lines().len()
}

/// New operator-log lines for `proxy_id` since line `from`.
fn op_log(g: &Gateway, from: usize, proxy_id: &str) -> Vec<String> {
    g.log_lines().into_iter().skip(from).filter(|l| l.contains(&format!("\"proxy_id\":\"{proxy_id}\""))).take(20).collect()
}

/// Poll the operator log (bounded) until a line for `proxy_id` contains every `needle`.
async fn wait_op(g: &Gateway, from: usize, proxy_id: &str, needles: &[&str], max: Duration) -> Option<String> {
    let start = Instant::now();
    loop {
        if let Some(l) = op_log(g, from, proxy_id).into_iter().find(|l| needles.iter().all(|n| l.contains(n))) {
            return Some(l);
        }
        if start.elapsed() > max {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn op_check(c: &mut Checks, g: &Gateway, from: usize, proxy_id: &str, needles: &[&str], what: &str, max: Duration) -> Vec<String> {
    let hit = wait_op(g, from, proxy_id, needles, max).await;
    c.add(
        CheckKind::GroundTruth,
        format!("gateway operator log: {what}"),
        hit.is_some(),
        hit.clone().unwrap_or_else(|| format!("no line with {needles:?}")),
    );
    op_log(g, from, proxy_id)
}

/// The header the gateway re-advertised to the TCP backend, after `before` events.
fn backend_header(f: &ProxyFixture, before: usize) -> Option<(Option<SocketAddr>, Option<SocketAddr>)> {
    f.log.events().into_iter().skip(before).find_map(|e| match e {
        ProxyEvent::Header { source, destination, .. } => Some((source, destination)),
        _ => None,
    })
}

fn backend_payloads(f: &ProxyFixture, before: usize) -> Vec<Vec<u8>> {
    f.log
        .events()
        .into_iter()
        .skip(before)
        .filter_map(|e| match e {
            ProxyEvent::Datagram { payload, .. } => Some(payload),
            _ => None,
        })
        .collect()
}

fn backend_stream(f: &ProxyFixture, before: usize) -> Vec<u8> {
    f.log
        .events()
        .into_iter()
        .skip(before)
        .filter_map(|e| match e {
            ProxyEvent::StreamData { bytes } => Some(bytes),
            _ => None,
        })
        .flatten()
        .collect()
}

fn no_proxy_confirmed(c: &mut Checks, o: &ExecutionOutput) {
    let bad: Vec<String> = o
        .record
        .findings
        .iter()
        .filter(|f| f.confidence == Confidence::Confirmed && (f.code.contains("proxy") || f.explanation.contains("PROXY")))
        .map(|f| f.code.clone())
        .collect();
    c.add(CheckKind::Diagnosis, "no confirmed PROXY-protocol claim", bad.is_empty(), format!("{bad:?}"));
}

fn tcp_closed_without_data(c: &mut Checks, o: &ExecutionOutput) {
    c.add(
        CheckKind::Diagnosis,
        "the gateway accepted the connection and closed it without data",
        matches!(
            o.record.outcome.protocol_status,
            ProtocolStatus::Tcp { bytes_received: 0, closed_by: ClosedBy::Peer | ClosedBy::Abnormal, .. }
        ),
        outcome_line(o),
    );
}

fn header_phase(c: &mut Checks, o: &ExecutionOutput, before_tls: bool) {
    let a = last(o);
    let p = a.and_then(|a| a.phase(Phase::ProxyProtocolHeader));
    c.add(
        CheckKind::Diagnosis,
        "the proxy_protocol_header phase completed after connect",
        p.map(|p| p.status) == Some(PhaseStatus::Completed)
            && a.and_then(|a| a.phase(Phase::Connect)).and_then(|x| x.end_us) <= p.and_then(|p| p.start_us),
        format!("{:?}", p.map(|p| (&p.status, &p.detail))),
    );
    if before_tls {
        let tls = a.and_then(|a| a.phase(Phase::TlsHandshake)).and_then(|t| t.start_us);
        c.add(
            CheckKind::Diagnosis,
            "the header was written before the TLS ClientHello",
            p.and_then(|p| p.end_us) <= tls,
            format!("{tls:?}"),
        );
    }
}

fn echoed(c: &mut Checks, o: &ExecutionOutput, kind: &str, want: &str) {
    c.add(
        CheckKind::Diagnosis,
        format!("{want:?} echoed through the gateway"),
        previews(o, kind) == vec![want.to_string()],
        outcome_line(o),
    );
}

fn no_response(c: &mut Checks, o: &ExecutionOutput) {
    c.add(
        CheckKind::Diagnosis,
        "no response observed",
        matches!(o.record.outcome.protocol_status, ProtocolStatus::Udp { datagrams_received: 0, .. }),
        outcome_line(o),
    );
    c.has(o, "udp.no_response");
    c.add(
        CheckKind::Diagnosis,
        "udp.no_response lists the envelope drop only as an alternative",
        alternatives(o, "udp.no_response").iter().any(|a| a.contains("dropped the PROXY v2 envelope")),
        format!("{:?}", alternatives(o, "udp.no_response")),
    );
    no_proxy_confirmed(c, o);
}

// ------------------------------------------------------------------ TCP ---

/// Accepted header with an explicit forwarded client: operator log and backend both see it.
async fn tcp_accepted(
    env: &Env,
    c: &mut Checks,
    url: &str,
    proxy_id: &str,
    h: ProxyHeaderSpec,
    source: &str,
    backend: &ProxyFixture,
) -> (ExecutionOutput, Vec<String>) {
    let from = op_from(&env.gateway);
    let before = backend.log.events().len();
    let payload = format!("pp-{proxy_id}");
    let tls = url.starts_with("tls://");
    let o = send(env, &tcp_ctx(env, url, &payload, Some(h))).await;
    echoed(c, &o, "frame", &payload);
    header_phase(c, &o, tls);
    if tls {
        c.add(
            CheckKind::Diagnosis,
            "the client TLS leg verified against the lab root",
            last(&o)
                .and_then(|a| a.connection.as_ref())
                .and_then(|x| x.tls.as_ref())
                .map(|t| t.verification == TlsVerification::Verified)
                .unwrap_or(false),
            "",
        );
    }
    c.absent_prefix(&o, "tcp.");
    let ip = source.rsplit_once(':').map(|(ip, _)| ip.trim_matches(['[', ']'])).unwrap_or(source);
    let lines = op_check(
        c,
        &env.gateway,
        from,
        proxy_id,
        &[&format!("\"client_ip\":\"{ip}\"")],
        &format!("client_ip {ip}"),
        Duration::from_secs(4),
    )
    .await;
    let bh = backend_header(backend, before);
    c.add(
        CheckKind::GroundTruth,
        format!("the backend received the gateway's PROXY v2 header naming {source}"),
        bh.and_then(|(s, _)| s).map(|s| s.to_string()) == Some(source.to_string()),
        format!("{bh:?}"),
    );
    c.add(
        CheckKind::GroundTruth,
        "the backend received the stream (without Anvil's header bytes)",
        backend_stream(backend, before) == format!("{payload}\n").into_bytes(),
        String::from_utf8_lossy(&backend_stream(backend, before)).into_owned(),
    );
    (o, lines)
}

fn pp001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let mut h = header(ProxyHeaderVersion::V1, Some("203.0.113.7:40001"));
        h.destination = Some(TCP.into());
        let (o, lines) = tcp_accepted(env, &mut c, &format!("tcp://{TCP}"), "pp-tcp", h, "203.0.113.7:40001", &env.fx.tcp_backend).await;
        let text = sent_header(&o).and_then(|h| h.text);
        c.add(
            CheckKind::Diagnosis,
            "evidence records the exact v1 line",
            text.as_deref() == Some("PROXY TCP4 203.0.113.7 127.0.0.1 40001 18901"),
            format!("{text:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let mut h = header(ProxyHeaderVersion::V2, Some("198.51.100.23:40002"));
        h.authority = Some("pp.anvil.test".into());
        let (o, lines) = tcp_accepted(env, &mut c, &format!("tcp://{TCP}"), "pp-tcp", h, "198.51.100.23:40002", &env.fx.tcp_backend).await;
        let h = sent_header(&o);
        c.add(
            CheckKind::Diagnosis,
            "evidence records the v2 bytes (AF_INET + STREAM) and the authority TLV",
            h.as_ref()
                .map(|h| h.hex.starts_with("0d0a0d0a000d0a515549540a2111") && h.tlvs.iter().any(|t| t.contains("pp.anvil.test")))
                .unwrap_or(false),
            format!("{h:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp002_socket(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(&env.gateway);
        let before = env.fx.tcp_backend.log.events().len();
        let o = send(env, &tcp_ctx(env, &format!("tcp://{TCP}"), "pp-socket", Some(header(ProxyHeaderVersion::V2, None)))).await;
        echoed(&mut c, &o, "frame", "pp-socket");
        header_phase(&mut c, &o, false);
        let h = sent_header(&o);
        let local = local_addr(&o);
        c.add(
            CheckKind::Diagnosis,
            "the declared source is the real local socket address",
            h.as_ref().and_then(|h| h.source.clone()) == local.map(|l| l.to_string())
                && h.as_ref().and_then(|h| h.source_origin) == Some(AddressOrigin::Socket),
            format!("{h:?} local={local:?}"),
        );
        let bh = backend_header(&env.fx.tcp_backend, before);
        c.add(
            CheckKind::GroundTruth,
            "the gateway re-advertised exactly Anvil's socket address (ip and port)",
            bh.and_then(|(s, _)| s) == local,
            format!("{bh:?} local={local:?}"),
        );
        let lines =
            op_check(&mut c, &env.gateway, from, "pp-tcp", &["\"client_ip\":\"127.0.0.1\""], "client_ip 127.0.0.1", Duration::from_secs(4))
                .await;
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp003(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(&env.gateway);
        let before = env.fx.tcp_backend.log.events().len();
        let o = send(env, &tcp_ctx(env, &format!("tcp://{TCP}"), "no-header", None)).await;
        tcp_closed_without_data(&mut c, &o);
        c.has(&o, "tcp.closed_without_data");
        c.add(
            CheckKind::Diagnosis,
            "'the listener may require PROXY protocol' is offered as an alternative",
            alternatives(&o, "tcp.closed_without_data").iter().any(|a| a.contains("may require a PROXY protocol header")),
            format!("{:?}", alternatives(&o, "tcp.closed_without_data")),
        );
        c.absent_prefix(&o, "tcp.proxy_header");
        no_proxy_confirmed(&mut c, &o);
        c.absent_prefix(&o, "client.");
        let lines = op_check(
            &mut c,
            &env.gateway,
            from,
            "pp-tcp",
            &["did not start with a valid PROXY header"],
            "invalid PROXY header warning",
            Duration::from_secs(2),
        )
        .await;
        c.add(CheckKind::GroundTruth, "the backend saw no connection", env.fx.tcp_backend.log.events().len() == before, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp004(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(&env.gateway);
        let before = env.fx.tcp_backend.log.events().len();
        let mut h = header(ProxyHeaderVersion::Raw, None);
        h.raw_hex = Some(hex::encode(b"PROXY TCP4 not-an-ip 127.0.0.1 40004 18901\r\n"));
        let o = send(env, &tcp_ctx(env, &format!("tcp://{TCP}"), "malformed", Some(h))).await;
        tcp_closed_without_data(&mut c, &o);
        let sh = sent_header(&o);
        c.add(
            CheckKind::Diagnosis,
            "Anvil sent the raw bytes and recorded them as malformed",
            sh.as_ref().map(|h| !h.well_formed && h.hex == hex::encode(b"PROXY TCP4 not-an-ip 127.0.0.1 40004 18901\r\n")).unwrap_or(false),
            format!("{sh:?}"),
        );
        c.has(&o, "tcp.proxy_header_maybe_rejected");
        c.max_confidence(&o, "tcp.proxy_header_maybe_rejected", Confidence::Likely);
        no_proxy_confirmed(&mut c, &o);
        let lines = op_check(
            &mut c,
            &env.gateway,
            from,
            "pp-tcp",
            &["did not start with a valid PROXY header", "invalid src IP"],
            "invalid header (invalid src IP)",
            Duration::from_secs(2),
        )
        .await;
        c.add(CheckKind::GroundTruth, "the backend saw no connection", env.fx.tcp_backend.log.events().len() == before, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

/// LOCAL / UNKNOWN: the gateway keeps the balancer's socket peer as the client.
async fn peer_semantics(env: &Env, h: ProxyHeaderSpec, payload: &str) -> Outcome {
    let mut c = Checks::new();
    let from = op_from(&env.gateway);
    let before = env.fx.tcp_backend.log.events().len();
    let o = send(env, &tcp_ctx(env, &format!("tcp://{TCP}"), payload, Some(h))).await;
    echoed(&mut c, &o, "frame", payload);
    header_phase(&mut c, &o, false);
    let local = local_addr(&o);
    let bh = backend_header(&env.fx.tcp_backend, before);
    c.add(
        CheckKind::GroundTruth,
        "the gateway used the socket peer (Anvil's address and port) as the client",
        bh.and_then(|(s, _)| s) == local,
        format!("{bh:?} local={local:?}"),
    );
    let lines = op_check(
        &mut c,
        &env.gateway,
        from,
        "pp-tcp",
        &["\"client_ip\":\"127.0.0.1\""],
        "client_ip is the socket peer 127.0.0.1",
        Duration::from_secs(4),
    )
    .await;
    Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
}

fn pp005(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut h = header(ProxyHeaderVersion::V2, Some("203.0.113.55:40005"));
        h.command = ProxyCommand::Local;
        let mut o = peer_semantics(env, h, "pp-local").await;
        let sh = o.main.as_ref().and_then(sent_header);
        o.checks.add(
            CheckKind::Diagnosis,
            "LOCAL was sent without addresses (0x20, AF_UNSPEC)",
            sh.as_ref().map(|h| h.hex == "0d0a0d0a000d0a515549540a20000000" && h.command == Some(ProxyCommand::Local)).unwrap_or(false),
            format!("{sh:?}"),
        );
        o
    })
}

fn pp005_unknown(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut h = header(ProxyHeaderVersion::V1, None);
        h.family = ProxyAddressFamily::Unspec;
        let mut o = peer_semantics(env, h, "pp-unknown").await;
        let sh = o.main.as_ref().and_then(sent_header);
        o.checks.add(
            CheckKind::Diagnosis,
            "v1 UNKNOWN was sent",
            sh.as_ref().and_then(|h| h.text.clone()).as_deref() == Some("PROXY UNKNOWN"),
            format!("{sh:?}"),
        );
        o
    })
}

fn pp006(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(&env.gateway);
        let before = env.fx.tcp_backend.log.events().len();
        let o =
            send(env, &tcp_ctx(env, "tcp://[::1]:18901", "untrusted", Some(header(ProxyHeaderVersion::V2, Some("203.0.113.66:40006")))))
                .await;
        c.add(
            CheckKind::Diagnosis,
            "Anvil connected from ::1 (outside FERRUM_TRUSTED_PROXIES) and wrote the header",
            local_addr(&o).map(|a| a.ip().to_string()) == Some("::1".into())
                && last(&o).and_then(|a| a.phase(Phase::ProxyProtocolHeader)).map(|p| p.status) == Some(PhaseStatus::Completed),
            format!("{:?}", local_addr(&o)),
        );
        tcp_closed_without_data(&mut c, &o);
        c.has(&o, "tcp.proxy_header_maybe_rejected");
        c.max_confidence(&o, "tcp.proxy_header_maybe_rejected", Confidence::Unknown);
        c.add(
            CheckKind::Diagnosis,
            "an untrusted source is named as one possible reason",
            alternatives(&o, "tcp.proxy_header_maybe_rejected").iter().any(|a| a.contains("FERRUM_TRUSTED_PROXIES")),
            "",
        );
        no_proxy_confirmed(&mut c, &o);
        let lines = op_check(
            &mut c,
            &env.gateway,
            from,
            "pp-tcp",
            &["not in FERRUM_TRUSTED_PROXIES", "[::1]"],
            "untrusted peer [::1] closed",
            Duration::from_secs(2),
        )
        .await;
        c.add(CheckKind::GroundTruth, "the backend saw no connection", env.fx.tcp_backend.log.events().len() == before, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let h = header(ProxyHeaderVersion::V2, Some("203.0.113.77:40007"));
        let (o, lines) =
            tcp_accepted(env, &mut c, &format!("tls://{TCP_TLS}"), "pp-tcp-tls", h, "203.0.113.77:40007", &env.fx.tls_backend).await;
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = op_from(&env.gateway);
        let o = send(env, &tcp_ctx(env, &format!("tls://{TCP_TLS}"), "no-header", None)).await;
        let f = last(&o).and_then(|a| a.failure.clone());
        c.add(
            CheckKind::Diagnosis,
            "the TLS handshake ended with the peer closing (no alert)",
            f.as_ref()
                .map(|f| matches!(f.kind, FailureKind::TlsPeerClosed | FailureKind::TlsReset) && f.phase == Phase::TlsHandshake)
                .unwrap_or(false),
            format!("{f:?}"),
        );
        c.has(&o, "client.tls.connection_closed");
        c.max_confidence(&o, "client.tls.connection_closed", Confidence::Unknown);
        c.add(
            CheckKind::Diagnosis,
            "'the listener may require PROXY protocol' is offered as an alternative",
            alternatives(&o, "client.tls.connection_closed").iter().any(|a| a.contains("may require a PROXY protocol header")),
            format!("{:?}", alternatives(&o, "client.tls.connection_closed")),
        );
        c.absent_prefix(&o, "tcp.proxy_header");
        no_proxy_confirmed(&mut c, &o);
        let lines = op_check(
            &mut c,
            &env.gateway,
            from,
            "pp-tcp-tls",
            &["did not start with a valid PROXY header"],
            "invalid PROXY header warning (the ClientHello)",
            Duration::from_secs(2),
        )
        .await;
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

// ------------------------------------------------------------- datagram ---

/// Accepted envelope: echo, backend payload exact, operator-log client_ip.
#[allow(clippy::too_many_arguments)]
async fn dgram_accepted(
    env: &Env,
    c: &mut Checks,
    g: &Gateway,
    url: &str,
    proxy_id: &str,
    e: DatagramEnvelopeSpec,
    client_ip: &str,
    backend: &ProxyFixture,
) -> (ExecutionOutput, Vec<String>) {
    let from = op_from(g);
    let before = backend.log.events().len();
    let payload = format!("pp-{proxy_id}");
    let o = send(env, &udp_ctx(env, url, &payload, Some(e))).await;
    echoed(c, &o, "datagram", &payload);
    let h = sent_header(&o);
    c.add(
        CheckKind::Diagnosis,
        "evidence records the envelope and the number of datagrams wrapped",
        h.as_ref().map(|h| h.format == ProxyHeaderFormat::V2Datagram && h.datagrams >= 1).unwrap_or(false),
        format!("{h:?}"),
    );
    c.add(
        CheckKind::GroundTruth,
        "the backend received exactly the payload (the gateway stripped the envelope)",
        backend_payloads(backend, before) == vec![payload.clone().into_bytes()],
        format!("{:?}", backend_payloads(backend, before).iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect::<Vec<_>>()),
    );
    let lines = op_check(
        c,
        g,
        from,
        proxy_id,
        &[&format!("\"client_ip\":\"{client_ip}\"")],
        &format!("session summary client_ip {client_ip}"),
        Duration::from_secs(8),
    )
    .await;
    (o, lines)
}

/// Dropped envelope: silence only, the gateway's drop reason as ground truth.
async fn dgram_dropped(
    env: &Env,
    g: &Gateway,
    url: &str,
    proxy_id: &str,
    e: Option<DatagramEnvelopeSpec>,
    reason: &str,
    backend: &ProxyFixture,
) -> Outcome {
    tokio::time::sleep(DROP_LOG_GAP).await;
    let mut c = Checks::new();
    let from = op_from(g);
    let before = backend.log.events().len();
    let enveloped = e.is_some();
    let o = send(env, &udp_ctx(env, url, "must-be-dropped-by-the-gateway", e)).await;
    if url.starts_with("dtls://") {
        let f = last(&o).and_then(|a| a.failure.clone());
        c.add(
            CheckKind::Diagnosis,
            "the DTLS handshake got no answer",
            f.as_ref().map(|f| f.kind) == Some(FailureKind::DtlsHandshakeTimeout),
            format!("{f:?}"),
        );
        c.has(&o, "client.dtls.handshake_timeout");
        no_proxy_confirmed(&mut c, &o);
    } else if enveloped {
        no_response(&mut c, &o);
    } else {
        c.add(
            CheckKind::Diagnosis,
            "no response observed",
            matches!(o.record.outcome.protocol_status, ProtocolStatus::Udp { datagrams_received: 0, .. }),
            outcome_line(&o),
        );
        c.has(&o, "udp.no_response");
        no_proxy_confirmed(&mut c, &o);
    }
    let lines = op_check(
        &mut c,
        g,
        from,
        proxy_id,
        &[&format!("\"reason\":\"{reason}\"")],
        &format!("datagram dropped: {reason}"),
        Duration::from_secs(2),
    )
    .await;
    c.add(CheckKind::GroundTruth, "the backend received nothing", backend.log.events().len() == before, "");
    Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
}

fn pp009(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (o, lines) = dgram_accepted(
            env,
            &mut c,
            &env.gateway,
            &format!("udp://{UDP}"),
            "pp-udp",
            envelope(Some("203.0.113.99:5099"), None),
            "203.0.113.99",
            &env.fx.udp_backend,
        )
        .await;
        let h = sent_header(&o);
        c.add(
            CheckKind::Diagnosis,
            "unauthenticated AF_INET + DGRAM envelope (0x21 0x12, 12-byte block)",
            h.as_ref().map(|h| h.hex.get(24..32) == Some("2112000c") && !h.authenticated).unwrap_or(false),
            format!("{h:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp010(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        dgram_dropped(env, &env.gateway, &format!("udp://{UDP}"), "pp-udp", None, "invalid_signature", &env.fx.udp_backend).await
    })
}

fn pp011(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let e = envelope(Some("203.0.113.111:5111"), Some(vault_auth(env, 11, "127.0.0.1")));
        let (o, lines) = dgram_accepted(
            env,
            &mut c,
            &env.auth_gateway,
            &format!("udp://{UDP_AUTH}"),
            "pp-udp-auth",
            e,
            "203.0.113.111",
            &env.fx.udp_auth_backend,
        )
        .await;
        let h = sent_header(&o);
        c.add(
            CheckKind::Diagnosis,
            "authenticated for listener 'udp 127.0.0.1:18911' with tag and freshness TLVs",
            h.as_ref()
                .map(|h| {
                    h.authenticated
                        && h.listener_binding.as_deref() == Some("udp 127.0.0.1:18911")
                        && h.tlvs.len() == 2
                        && h.hex.ends_with("‹tag›")
                })
                .unwrap_or(false),
            format!("{h:?}"),
        );
        let json = serde_json::to_string(&o.record).unwrap_or_default();
        c.add(CheckKind::Diagnosis, "the secret appears nowhere in the record", !json.contains(env.secret.as_str()), "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp012(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut a = vault_auth(env, 12, "127.0.0.1");
        a.secret = SensitiveValue::template(gateway::random_secret());
        dgram_dropped(
            env,
            &env.auth_gateway,
            &format!("udp://{UDP_AUTH}"),
            "pp-udp-auth",
            Some(envelope(Some("203.0.113.112:5112"), Some(a))),
            "authentication_tag_mismatch",
            &env.fx.udp_auth_backend,
        )
        .await
    })
}

fn pp013(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        tokio::time::sleep(DROP_LOG_GAP).await;
        let mut a = vault_auth(env, 13, "127.0.0.1");
        a.epoch = Some(anvil_transport::proxy_protocol::unix_now_millis());
        let e = envelope(Some("203.0.113.113:5113"), Some(a));
        let before = env.fx.udp_auth_backend.log.events().len();
        let first = send(env, &udp_ctx(env, &format!("udp://{UDP_AUTH}"), "first", Some(e.clone()))).await;
        let mut o = dgram_dropped(
            env,
            &env.auth_gateway,
            &format!("udp://{UDP_AUTH}"),
            "pp-udp-auth",
            Some(e),
            "replay_duplicate",
            &env.fx.udp_auth_backend,
        )
        .await;
        o.checks.add(
            CheckKind::Recovery,
            "the first use of (sender 13, epoch, sequence 0) was accepted",
            previews(&first, "datagram") == vec!["first"],
            outcome_line(&first),
        );
        o.checks.add(
            CheckKind::GroundTruth,
            "the backend received only the first datagram",
            backend_payloads(&env.fx.udp_auth_backend, before) == vec![b"first".to_vec()],
            "",
        );
        o.recovery = Some(first);
        o
    })
}

fn pp014(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut a = vault_auth(env, 14, "127.0.0.1");
        a.timestamp_offset_ms = -60_000;
        dgram_dropped(
            env,
            &env.auth_gateway,
            &format!("udp://{UDP_AUTH}"),
            "pp-udp-auth",
            Some(envelope(Some("203.0.113.114:5114"), Some(a))),
            "freshness_outside_horizon",
            &env.fx.udp_auth_backend,
        )
        .await
    })
}

fn pp015(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        // The gateway bound 127.0.0.1; a tag minted for the wildcard identity must not verify.
        let a = vault_auth(env, 15, "0.0.0.0");
        dgram_dropped(
            env,
            &env.auth_gateway,
            &format!("udp://{UDP_AUTH}"),
            "pp-udp-auth",
            Some(envelope(Some("203.0.113.115:5115"), Some(a))),
            "authentication_tag_mismatch",
            &env.fx.udp_auth_backend,
        )
        .await
    })
}

fn pp016(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (o, lines) = dgram_accepted(
            env,
            &mut c,
            &env.gateway,
            &format!("dtls://{DTLS}"),
            "pp-dtls",
            envelope(Some("203.0.113.116:5116"), None),
            "203.0.113.116",
            &env.fx.dtls_backend,
        )
        .await;
        let h = sent_header(&o);
        c.add(
            CheckKind::Diagnosis,
            "the DTLS handshake completed with every datagram (handshake included) wrapped",
            last(&o).and_then(|a| a.phase(Phase::DtlsHandshake)).map(|p| p.status) == Some(PhaseStatus::Completed)
                && h.as_ref().map(|h| h.datagrams >= 3).unwrap_or(false),
            format!("datagrams={:?}", h.map(|h| h.datagrams)),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp017(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        dgram_dropped(env, &env.gateway, &format!("dtls://{DTLS}"), "pp-dtls", None, "invalid_signature", &env.fx.dtls_backend).await
    })
}

fn pp018(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let e = envelope(Some("203.0.113.118:5118"), Some(vault_auth(env, 18, "127.0.0.1")));
        let (o, lines) = dgram_accepted(
            env,
            &mut c,
            &env.auth_gateway,
            &format!("dtls://{DTLS_AUTH}"),
            "pp-dtls-auth",
            e,
            "203.0.113.118",
            &env.fx.dtls_auth_backend,
        )
        .await;
        let h = sent_header(&o);
        c.add(
            CheckKind::Diagnosis,
            "authenticated for the DTLS-terminating identity 'dtls 127.0.0.1:18912'",
            h.as_ref().map(|h| h.listener_binding.as_deref() == Some("dtls 127.0.0.1:18912") && h.datagrams >= 3).unwrap_or(false),
            format!("{h:?}"),
        );
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: lines }
    })
}

fn pp019(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        dgram_dropped(
            env,
            &env.gateway,
            "udp://[::1]:18903",
            "pp-udp",
            Some(envelope(Some("203.0.113.119:5119"), None)),
            "untrusted_peer",
            &env.fx.udp_backend,
        )
        .await
    })
}

// ----------------------------------------------------------------- wiring ---

/// Scenarios that need the gateway's dual-stack `[::]` bind (a `::1` peer).
const NEEDS_DUAL_STACK: &[&str] = &["PP-006", "PP-019"];

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "PP-001", title: "TCP PROXY v1 accepted: the forwarded client reaches the gateway log and the backend", run: pp001 },
        Def { id: "PP-002", title: "TCP PROXY v2 (authority TLV) accepted", run: pp002 },
        Def { id: "PP-002-socket", title: "TCP PROXY v2 with the real socket addresses", run: pp002_socket },
        Def { id: "PP-003", title: "No header: immediate close; PROXY only as an alternative", run: pp003 },
        Def { id: "PP-004", title: "Malformed (raw) header closed: possibly rejected, likely at most", run: pp004 },
        Def { id: "PP-005", title: "PROXY v2 LOCAL: the balancer's socket peer is the client", run: pp005 },
        Def { id: "PP-005-unknown", title: "PROXY v1 UNKNOWN: the balancer's socket peer is the client", run: pp005_unknown },
        Def { id: "PP-006", title: "Untrusted peer (::1): closed; untrusted source only an alternative", run: pp006 },
        Def { id: "PP-007", title: "TCP+TLS: PROXY v2 before the ClientHello, TLS terminated by the gateway", run: pp007 },
        Def { id: "PP-008", title: "TCP+TLS without header: closed during the handshake; PROXY only as an alternative", run: pp008 },
        Def { id: "PP-009", title: "UDP PROXY v2 DGRAM envelope accepted", run: pp009 },
        Def { id: "PP-010", title: "UDP without envelope: dropped, no response observed only", run: pp010 },
        Def { id: "PP-011", title: "Authenticated envelope (vault secret, tag + freshness) accepted", run: pp011 },
        Def { id: "PP-012", title: "Authenticated envelope with the wrong secret dropped", run: pp012 },
        Def { id: "PP-013", title: "Replayed sequence dropped (first use accepted)", run: pp013 },
        Def { id: "PP-014", title: "Stale timestamp (outside the 30 s horizon) dropped", run: pp014 },
        Def { id: "PP-015", title: "Tag minted for another listener identity dropped", run: pp015 },
        Def { id: "PP-016", title: "DTLS with the envelope on every datagram (handshake included)", run: pp016 },
        Def { id: "PP-017", title: "DTLS without envelope: handshake datagrams dropped, no answer", run: pp017 },
        Def { id: "PP-018", title: "Authenticated envelope on the DTLS-terminating listener", run: pp018 },
        Def { id: "PP-019", title: "UDP envelope from an untrusted peer (::1) dropped", run: pp019 },
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "proxyproto",
        about: "PROXY protocol v1/v2 and the datagram envelope into stream listeners (streams 18901-18912)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let certs = gateway::repo_root().join("lab/.run/proxyproto/certs");
    let fx = ProxyProtoFixtures::start(&certs).await?;
    let vars = [("LAB_CERTS", certs.display().to_string())];
    let gateway = Gateway::start("proxyproto", "proxyproto.conf", "proxyproto.yaml", &vars, ADMIN_PORT, &[]).await?;
    let secret = Zeroizing::new(gateway::random_secret());
    let auth_gateway = match Gateway::start(
        "proxyproto-auth",
        "proxyproto-auth.conf",
        "proxyproto-auth.yaml",
        &vars,
        AUTH_ADMIN_PORT,
        &[("FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET", secret.to_string())],
    )
    .await
    {
        Ok(g) => g,
        Err(e) => {
            gateway.stop().await;
            return Err(e);
        }
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    fx.clear_logs();
    Ok(Env {
        engine: Engine::new(),
        fx,
        gateway,
        auth_gateway,
        trusted: true,
        secret,
        secret_ref: SecretRef { id: Id::new(), label: "lab datagram secret".into() },
    })
}

/// Whether the TCP listener accepts an IPv6 loopback peer (dual-stack `[::]` bind).
fn dual_stack() -> bool {
    std::net::TcpStream::connect_timeout(&"[::1]:18901".parse().expect("addr"), Duration::from_secs(1)).is_ok()
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("proxyproto")?;
    let mut env = start().await?;
    let dual = dual_stack();
    let mut skipped = Vec::new();
    let defs: Vec<Def> = all()
        .into_iter()
        .filter(|d| {
            let keep = dual || !NEEDS_DUAL_STACK.contains(&d.id);
            if !keep && (args.only.is_empty() || args.only.iter().any(|s| s.eq_ignore_ascii_case(d.id))) {
                skipped.push(ctx.skipped(d.id, d.title, "the gateway's stream listener did not accept an IPv6 loopback (::1) peer, so no untrusted peer can be arranged on this host (127.0.0.2 needs a loopback alias)"));
            }
            keep
        })
        .collect();
    let results = match harness::run_defs(&ctx, &mut env, defs, &args.only, args.untrusted_pass).await {
        Ok(mut r) => {
            r.extend(skipped);
            harness::finish(&ctx, &env, &r).map(|_| r)
        }
        Err(e) => Err(e),
    };
    env.gateway.stop().await;
    env.auth_gateway.stop().await;
    results
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!(
        "proxyproto lab running: tcp {TCP} (PROXY required), tls {TCP_TLS}, udp {UDP}, dtls {DTLS} (envelope, address trust; streams bound to [::]); \
         authenticated udp {UDP_AUTH} / dtls {DTLS_AUTH} (listener identities 'udp 127.0.0.1:18911' / 'dtls 127.0.0.1:18912'); trusted proxies 127.0.0.1/32; \
         lab CA {}; operator logs {} and {}",
        env.fx.certs_dir.join("ca.crt").display(),
        env.gateway.log_path.display(),
        env.auth_gateway.log_path.display()
    );
    println!(
        "the datagram secret is random per run and is not printed; authenticated scenarios run only through `anvil-lab run proxyproto`"
    );
    harness::wait_for_shutdown().await?;
    env.gateway.stop().await;
    env.auth_gateway.stop().await;
    Ok(())
}
