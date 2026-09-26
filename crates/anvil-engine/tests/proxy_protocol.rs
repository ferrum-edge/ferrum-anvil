//! PROXY protocol through the engine against local receivers that parse the
//! header / envelope independently (`anvil_fixtures::proxy_protocol`, written
//! from Ferrum Edge v0.9.7's receive semantics). The receivers' logs are
//! ground truth only; they are never fed to the diagnostic engine.

use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, DiagnosticFinding};
use anvil_domain::execution::*;
use anvil_domain::outcome::*;
use anvil_domain::proxy_protocol::*;
use anvil_domain::request::*;
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::{ProxySelection, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ProxyKind, ProxyProfile, TlsMinVersion, TlsProfile};
use anvil_engine::context::MemorySecrets;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::dtls::{self as fxdtls, DtlsServerOptions};
use anvil_fixtures::proxy_protocol::{self as pp, DatagramAuth, DatagramGate, ProxyEvent};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const SECRET: &str = "anvil-pp-test-secret-0123456789abcdef";

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn localhost() -> Vec<IpAddr> {
    vec!["127.0.0.1".parse().unwrap()]
}

fn fast() -> SettingsOverrides {
    SettingsOverrides {
        timeouts: Some(TimeoutOverrides {
            connect_ms: Some(Some(3_000)),
            tls_handshake_ms: Some(Some(3_000)),
            total_ms: Some(Some(20_000)),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn trust_profile() -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn ctx(mut spec: RequestSpec, tls: bool) -> ExecutionContext {
    spec.settings = fast();
    let mut c = ExecutionContext::standalone(spec);
    if tls {
        let p = trust_profile();
        c.settings_layers.push(("run".into(), SettingsOverrides { tls_profile_id: Some(p.id), ..Default::default() }));
        c.tls_profiles.push(p);
    }
    c
}

fn header(version: ProxyHeaderVersion) -> ProxyHeaderSpec {
    ProxyHeaderSpec {
        version,
        command: ProxyCommand::Proxy,
        family: ProxyAddressFamily::Auto,
        source: None,
        destination: None,
        authority: None,
        tlvs: vec![],
        raw_hex: None,
    }
}

fn tcp_spec(url: &str, payload: &str, h: Option<ProxyHeaderSpec>) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Tcp;
    s.tcp = Some(TcpSpec {
        tls: url.starts_with("tls://"),
        framing: TcpFraming::NewlineDelimited,
        payloads: vec![StreamPayload { data: payload.into(), encoding: PayloadEncoding::Text }],
        half_close_after_send: false,
        read_idle_ms: 1_500,
        max_read_bytes: 4096,
        expect_frames: 1,
        proxy_protocol: h,
    });
    s
}

fn udp_spec(url: &str, datagrams: &[&str], env: Option<DatagramEnvelopeSpec>) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Udp;
    s.udp = Some(UdpSpec {
        dtls: url.starts_with("dtls://"),
        datagrams: datagrams.iter().map(|d| StreamPayload { data: d.to_string(), encoding: PayloadEncoding::Text }).collect(),
        response_window_ms: 500,
        max_datagrams: 10,
        proxy_protocol: env,
    });
    s
}

fn envelope(auth: Option<DatagramAuthSpec>) -> DatagramEnvelopeSpec {
    DatagramEnvelopeSpec {
        command: ProxyCommand::Proxy,
        family: ProxyAddressFamily::Auto,
        source: Some("203.0.113.9:5000".into()),
        destination: None,
        authentication: auth,
    }
}

fn vault_ref() -> (SecretRef, MemorySecrets) {
    let r = SecretRef { id: Id::new(), label: "datagram secret".into() };
    let mut m = HashMap::new();
    m.insert(r.id, Zeroizing::new(SECRET.to_string()));
    (r, MemorySecrets(m))
}

fn auth(secret: SensitiveValue, bind: &str, port: Option<u16>) -> DatagramAuthSpec {
    DatagramAuthSpec {
        secret,
        listener_protocol: None,
        listener_bind_address: bind.into(),
        listener_port: port,
        sender_id: 7,
        epoch: None,
        first_sequence: 0,
        timestamp_offset_ms: 0,
    }
}

async fn run(c: &ExecutionContext) -> ExecutionOutput {
    Engine::new().execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("missing {code}; have {:?}", codes(o)))
}

fn last(o: &ExecutionOutput) -> &AttemptObservation {
    o.record.attempts.last().expect("attempt")
}

fn observed(o: &ExecutionOutput) -> ProxyHeaderObservation {
    last(o).connection.as_ref().and_then(|c| c.proxy_header.clone()).expect("proxy header evidence")
}

fn received(o: &ExecutionOutput, kind: &str) -> Vec<String> {
    o.record
        .stream
        .as_ref()
        .map(|s| s.messages.iter().filter(|m| m.direction == Direction::Received && m.kind == kind).map(|m| m.preview.clone()).collect())
        .unwrap_or_default()
}

fn no_confirmed_proxy_claim(o: &ExecutionOutput) {
    for f in &o.record.findings {
        assert!(
            !(f.confidence == Confidence::Confirmed && (f.code.contains("proxy") || f.explanation.contains("PROXY"))),
            "confirmed PROXY claim: {} {}",
            f.code,
            f.explanation
        );
    }
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn tls_opts() -> TlsServerOptions {
    let mut o = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    o.alpn = vec![];
    o
}

// ------------------------------------------------------------------ TCP ---

#[tokio::test]
async fn v1_header_is_written_first_and_the_receiver_sees_the_declared_client() {
    init();
    let f = pp::tcp_echo("127.0.0.1:0", localhost(), None).await.unwrap();
    let mut h = header(ProxyHeaderVersion::V1);
    h.source = Some("203.0.113.7:40001".into());
    h.destination = Some("{{dst}}".into());
    let mut c = ctx(tcp_spec(&format!("tcp://{}", f.addr), "hello", Some(h)), false);
    c.var_layers.push(anvil_engine::vars::VarLayer {
        label: "run".into(),
        vars: vec![anvil_engine::vars::VarEntry { name: "dst".into(), value: "198.51.100.1:443".into(), secret: false }],
    });
    let o = run(&c).await;
    assert_eq!(received(&o, "frame"), vec!["hello"], "{:?}", codes(&o));
    let heads = f.log.headers();
    assert_eq!(heads.len(), 1);
    match &heads[0] {
        ProxyEvent::Header { v2, local, source, destination, tlvs, .. } => {
            assert!(!v2 && !local && tlvs.is_empty());
            assert_eq!(*source, Some(sa("203.0.113.7:40001")));
            assert_eq!(*destination, Some(sa("198.51.100.1:443")));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(f.log.stream_bytes(), b"hello\n", "the header is not part of the payload");
    let a = last(&o);
    let p = a.phase(Phase::ProxyProtocolHeader).expect("phase");
    assert_eq!(p.status, PhaseStatus::Completed);
    assert!(p.detail.as_deref().unwrap_or("").contains("PROXY v1 TCP4 203.0.113.7:40001 → 198.51.100.1:443 (47 bytes)"), "{:?}", p.detail);
    let (connect, header_at) = (a.phase(Phase::Connect).unwrap().end_us.unwrap(), p.start_us.unwrap());
    assert!(header_at >= connect, "written after connect");
    let h = observed(&o);
    assert_eq!(h.text.as_deref(), Some("PROXY TCP4 203.0.113.7 198.51.100.1 40001 443"));
    assert_eq!(h.hex, hex::encode(b"PROXY TCP4 203.0.113.7 198.51.100.1 40001 443\r\n"));
    assert_eq!(h.length, 47);
    let t = o.record.stream.as_ref().unwrap();
    assert_eq!(t.messages[0].kind, "proxy_protocol_header");
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Tcp { bytes_sent: 6, .. }), "payload bytes only");
    assert!(codes(&o).iter().all(|c| !c.contains("proxy")));
}

#[tokio::test]
async fn v2_defaults_to_the_real_socket_addresses() {
    init();
    let f = pp::tcp_echo("127.0.0.1:0", localhost(), None).await.unwrap();
    let o = run(&ctx(tcp_spec(&format!("tcp://{}", f.addr), "x", Some(header(ProxyHeaderVersion::V2))), false)).await;
    assert_eq!(received(&o, "frame"), vec!["x"]);
    let conn = last(&o).connection.clone().unwrap();
    let h = observed(&o);
    assert_eq!(h.source.as_deref(), conn.local_address.as_deref());
    assert_eq!(h.destination.as_deref(), conn.remote_address.as_deref());
    assert_eq!(h.source_origin, Some(AddressOrigin::Socket));
    assert_eq!((h.family.as_str(), h.length), ("AF_INET", 28));
    match &f.log.headers()[0] {
        ProxyEvent::Header { v2, source, destination, .. } => {
            assert!(*v2);
            assert_eq!(source.map(|s| s.to_string()), conn.local_address);
            assert_eq!(*destination, Some(f.addr));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn v2_header_precedes_the_tls_client_hello_and_carries_the_authority_tlv() {
    init();
    let f = pp::tcp_echo("127.0.0.1:0", localhost(), Some(tls_opts())).await.unwrap();
    let mut h = header(ProxyHeaderVersion::V2);
    h.source = Some("[2001:db8::7]:4242".into());
    h.authority = Some("api.anvil.test".into());
    let o = run(&ctx(tcp_spec(&format!("tls://127.0.0.1:{}", f.addr.port()), "secure", Some(h)), true)).await;
    assert_eq!(received(&o, "frame"), vec!["secure"], "{:?} {:?}", codes(&o), last(&o).failure);
    let a = last(&o);
    let (hp, tls) = (a.phase(Phase::ProxyProtocolHeader).unwrap(), a.phase(Phase::TlsHandshake).unwrap());
    assert!(hp.end_us.unwrap() <= tls.start_us.unwrap(), "header before the ClientHello");
    match &f.log.headers()[0] {
        ProxyEvent::Header { source, tlvs, .. } => {
            assert_eq!(*source, Some(sa("[2001:db8::7]:4242")));
            assert_eq!(tlvs, &vec![(0x02u8, b"api.anvil.test".to_vec())]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(observed(&o).family, "AF_INET6", "mixed pair promoted to AF_INET6");
}

#[tokio::test]
async fn local_and_unknown_headers_carry_no_client() {
    init();
    let f = pp::tcp_echo("127.0.0.1:0", localhost(), None).await.unwrap();
    let mut local = header(ProxyHeaderVersion::V2);
    local.command = ProxyCommand::Local;
    let o = run(&ctx(tcp_spec(&format!("tcp://{}", f.addr), "a", Some(local)), false)).await;
    assert_eq!(received(&o, "frame"), vec!["a"]);
    let mut unknown = header(ProxyHeaderVersion::V1);
    unknown.family = ProxyAddressFamily::Unspec;
    let o2 = run(&ctx(tcp_spec(&format!("tcp://{}", f.addr), "b", Some(unknown)), false)).await;
    assert_eq!(received(&o2, "frame"), vec!["b"]);
    let heads = f.log.headers();
    assert!(matches!(heads[0], ProxyEvent::Header { v2: true, local: true, source: None, .. }), "{heads:?}");
    assert!(matches!(heads[1], ProxyEvent::Header { v2: false, local: false, source: None, .. }), "{heads:?}");
    assert_eq!(observed(&o2).hex, hex::encode(b"PROXY UNKNOWN\r\n"));
}

#[tokio::test]
async fn a_missing_header_is_closed_and_only_an_alternative_is_offered() {
    init();
    let f = pp::tcp_echo("127.0.0.1:0", localhost(), None).await.unwrap();
    let o = run(&ctx(tcp_spec(&format!("tcp://{}", f.addr), "hello", None), false)).await;
    assert!(matches!(
        o.record.outcome.protocol_status,
        ProtocolStatus::Tcp { bytes_received: 0, closed_by: ClosedBy::Peer | ClosedBy::Abnormal, .. }
    ));
    let d = finding(&o, "tcp.closed_without_data");
    assert!(d.alternatives.iter().any(|a| a.contains("may require a PROXY protocol header")), "{:?}", d.alternatives);
    assert!(!codes(&o).contains(&"tcp.proxy_header_maybe_rejected".to_string()));
    no_confirmed_proxy_claim(&o);
    assert_eq!(f.log.rejections(), vec!["invalid PROXY signature".to_string()]);
}

#[tokio::test]
async fn a_malformed_raw_header_is_sent_verbatim_and_likely_rejected() {
    init();
    let f = pp::tcp_echo("127.0.0.1:0", localhost(), None).await.unwrap();
    let mut h = header(ProxyHeaderVersion::Raw);
    h.raw_hex = Some(hex::encode(b"PROXY TCP4 not-an-ip 5.6.7.8 100 200\r\n"));
    let o = run(&ctx(tcp_spec(&format!("tcp://{}", f.addr), "hello", Some(h)), false)).await;
    let obs = observed(&o);
    assert!(!obs.well_formed);
    assert!(obs.problem.as_deref().unwrap_or("").contains("invalid source IP"), "{:?}", obs.problem);
    let d = finding(&o, "tcp.proxy_header_maybe_rejected");
    assert_eq!(d.confidence, Confidence::Likely);
    no_confirmed_proxy_claim(&o);
    assert_eq!(f.log.rejections(), vec!["invalid v1 source IP".to_string()]);
}

#[tokio::test]
async fn an_untrusted_peer_is_closed_and_the_header_is_only_possibly_rejected() {
    init();
    let f = pp::tcp_echo("127.0.0.1:0", vec!["10.9.9.9".parse().unwrap()], None).await.unwrap();
    let o = run(&ctx(tcp_spec(&format!("tcp://{}", f.addr), "hello", Some(header(ProxyHeaderVersion::V2))), false)).await;
    let d = finding(&o, "tcp.proxy_header_maybe_rejected");
    assert_eq!(d.confidence, Confidence::Unknown);
    assert!(d.alternatives.iter().any(|a| a.contains("trusted proxy")));
    assert!(finding(&o, "tcp.closed_without_data").alternatives.iter().all(|a| !a.contains("may require")));
    no_confirmed_proxy_claim(&o);
    assert_eq!(f.log.rejections(), vec!["untrusted peer".to_string()]);
}

#[tokio::test]
async fn impossible_headers_are_refused_before_any_traffic() {
    init();
    let f = pp::tcp_echo("127.0.0.1:0", localhost(), None).await.unwrap();
    let url = format!("tcp://{}", f.addr);
    let mut v1_local = header(ProxyHeaderVersion::V1);
    v1_local.command = ProxyCommand::Local;
    let mut bad_addr = header(ProxyHeaderVersion::V2);
    bad_addr.source = Some("not-an-address".into());
    let mut v1_mixed = header(ProxyHeaderVersion::V1);
    v1_mixed.source = Some("[2001:db8::1]:1".into());
    v1_mixed.destination = Some("10.0.0.1:2".into());
    let mut empty_raw = header(ProxyHeaderVersion::Raw);
    empty_raw.raw_hex = Some(String::new());
    for (h, kind) in [
        (v1_local, FailureKind::UnsupportedCombination),
        (bad_addr, FailureKind::BodySerialization),
        (v1_mixed, FailureKind::UnsupportedCombination),
        (empty_raw, FailureKind::BodySerialization),
    ] {
        let o = run(&ctx(tcp_spec(&url, "x", Some(h)), false)).await;
        let a = last(&o);
        assert_eq!(a.failure.as_ref().map(|f| f.kind), Some(kind), "{:?}", a.failure);
        assert!(a.phase(Phase::Connect).is_none(), "nothing was connected");
    }
    // Through a forward proxy, default addresses would describe the proxy hop.
    let proxy = ProxyProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "fwd".into(),
        kind: ProxyKind::Http,
        address: "127.0.0.1:9".into(),
        username: None,
        password: None,
        no_proxy: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let mut c = ctx(tcp_spec(&url, "x", Some(header(ProxyHeaderVersion::V2))), false);
    c.settings_layers
        .push(("run".into(), SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id: proxy.id }), ..Default::default() }));
    c.proxy_profiles.push(proxy);
    let o = run(&c).await;
    assert_eq!(last(&o).failure.as_ref().map(|f| f.kind), Some(FailureKind::UnsupportedCombination));
    assert!(f.log.events().is_empty(), "the receiver saw nothing");
}

// ------------------------------------------------------------- datagram ---

#[tokio::test]
async fn unauthenticated_envelopes_are_echoed_and_bare_datagrams_dropped() {
    init();
    let f = pp::udp_echo("127.0.0.1:0", DatagramGate::new(localhost(), None, None)).await.unwrap();
    let url = format!("udp://{}", f.addr);
    let o = run(&ctx(udp_spec(&url, &["one", "two"], Some(envelope(None))), false)).await;
    let mut got = received(&o, "datagram");
    got.sort();
    assert_eq!(got, vec!["one", "two"], "{:?}", codes(&o));
    let dgs = f.log.datagrams();
    assert_eq!(dgs.len(), 2);
    for d in &dgs {
        let ProxyEvent::Datagram { source, payload, authenticated, .. } = d else { unreachable!() };
        assert_eq!(*source, Some(sa("203.0.113.9:5000")));
        assert!(payload == b"one" || payload == b"two", "the receiver strips exactly the envelope");
        assert!(!authenticated);
    }
    let h = observed(&o);
    assert_eq!((h.format, h.datagrams, h.length, h.authenticated), (ProxyHeaderFormat::V2Datagram, 2, 28, false));
    assert_eq!(&h.hex[24..32], "2112000c", "ver/cmd 0x21, AF_INET+DGRAM 0x12, len 12");
    // Without the envelope the receiver drops silently: no response observed only.
    let bare = run(&ctx(udp_spec(&url, &["bare"], None), false)).await;
    assert!(received(&bare, "datagram").is_empty());
    let d = finding(&bare, "udp.no_response");
    assert!(d.alternatives.iter().all(|a| !a.contains("envelope")));
    no_confirmed_proxy_claim(&bare);
    assert_eq!(f.log.rejections(), vec!["truncated_header".to_string()], "4 bytes: shorter than the 16-byte header");
}

#[tokio::test]
async fn authenticated_envelopes_verify_and_bad_ones_are_dropped_silently() {
    init();
    let (secret_ref, vault) = vault_ref();
    let gate = |port| {
        DatagramGate::new(
            localhost(),
            Some(DatagramAuth { secret: SECRET.as_bytes().to_vec(), protocol_tag: 1, bind_addr: "127.0.0.1".parse().unwrap(), port }),
            Some(port),
        )
    };
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    drop(sock);
    let f = pp::udp_echo(&format!("127.0.0.1:{port}"), gate(port)).await.unwrap();
    let url = format!("udp://127.0.0.1:{port}");
    let vaulted = SensitiveValue::Secret { secret: secret_ref };
    let send = |a: DatagramAuthSpec, payload: &'static str| {
        let mut c = ctx(udp_spec(&url, &[payload], Some(envelope(Some(a)))), false);
        c.secrets = Arc::new(vault.clone());
        c
    };
    // Accepted.
    let good = run(&send(auth(vaulted.clone(), "127.0.0.1", None), "ok")).await;
    assert_eq!(received(&good, "datagram"), vec!["ok"], "{:?}", codes(&good));
    let h = observed(&good);
    assert!(h.authenticated);
    assert_eq!(h.listener_binding.as_deref(), Some(format!("udp 127.0.0.1:{port}").as_str()));
    assert_eq!((h.length, h.first_sequence, h.last_sequence), (16 + 12 + 32 + 35, Some(0), Some(0)));
    let json = serde_json::to_string(&good.record).unwrap();
    assert!(!json.contains(SECRET), "the secret is never recorded");
    // Replay: the same epoch and sequence twice.
    // (Another sender: sender 7's epoch is already "now" in milliseconds, so a
    // pinned small epoch would be refused as stale rather than as a replay.)
    let mut pinned = auth(vaulted.clone(), "127.0.0.1", None);
    pinned.sender_id = 8;
    pinned.epoch = Some(42);
    let first = run(&send(pinned.clone(), "first")).await;
    assert_eq!(received(&first, "datagram"), vec!["first"]);
    let replay = run(&send(pinned, "replay")).await;
    assert!(received(&replay, "datagram").is_empty());
    let d = finding(&replay, "udp.no_response");
    assert!(d.alternatives.iter().any(|a| a.contains("dropped the PROXY v2 envelope")), "{:?}", d.alternatives);
    no_confirmed_proxy_claim(&replay);
    // Stale timestamp, wrong secret (template literal), wrong listener identity.
    let mut stale = auth(vaulted.clone(), "127.0.0.1", None);
    stale.timestamp_offset_ms = -60_000;
    let wrong_secret = auth(SensitiveValue::template("a-different-secret-of-sufficient-length!"), "127.0.0.1", None);
    let wrong_listener = auth(vaulted.clone(), "0.0.0.0", None);
    for (a, why) in [(stale, "stale"), (wrong_secret, "wrong secret"), (wrong_listener, "wrong listener")] {
        let o = run(&send(a, "nope")).await;
        assert!(received(&o, "datagram").is_empty(), "{why}");
        no_confirmed_proxy_claim(&o);
        assert!(!serde_json::to_string(&o.record).unwrap().contains("a-different-secret"), "{why}: template secrets are redacted too");
    }
    assert_eq!(
        f.log.rejections(),
        vec!["replay_duplicate", "freshness_outside_horizon", "authentication_tag_mismatch", "authentication_tag_mismatch"],
    );
    // A short secret is refused before any datagram.
    let short = run(&send(auth(SensitiveValue::template("short"), "127.0.0.1", None), "x")).await;
    assert_eq!(last(&short).failure.as_ref().map(|f| f.kind), Some(FailureKind::BodySerialization));
    assert!(!last(&short).failure.as_ref().unwrap().message.contains("5"), "neither value nor length is reported");
    assert_eq!(f.log.events().len(), 6, "2 accepted + 4 dropped; the refused run sent nothing");
}

#[tokio::test]
async fn dtls_envelopes_wrap_every_datagram_including_the_handshake() {
    init();
    let server = fxdtls::serve(
        "127.0.0.1:0",
        DtlsServerOptions { cert_pem: pki().server.cert.clone(), key_pem: pki().server.key.clone(), client_ca_pem: None },
    )
    .await
    .unwrap();
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    drop(sock);
    let gate = DatagramGate::new(
        localhost(),
        Some(DatagramAuth { secret: SECRET.as_bytes().to_vec(), protocol_tag: 2, bind_addr: "127.0.0.1".parse().unwrap(), port }),
        Some(port),
    );
    let relay = pp::udp_relay(&format!("127.0.0.1:{port}"), server.addr, gate).await.unwrap();
    let a = auth(SensitiveValue::template(SECRET), "127.0.0.1", None);
    let o = run(&ctx(udp_spec(&format!("dtls://127.0.0.1:{port}"), &["secure hello"], Some(envelope(Some(a)))), true)).await;
    assert_eq!(received(&o, "datagram"), vec!["secure hello"], "{:?} {:?}", codes(&o), last(&o).failure);
    assert_eq!(last(&o).phase(Phase::DtlsHandshake).unwrap().status, PhaseStatus::Completed);
    let h = observed(&o);
    assert_eq!(h.listener_binding.as_deref(), Some(format!("dtls 127.0.0.1:{port}").as_str()), "DTLS boundary by default");
    // The final close_notify may still be in flight to the relay.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let seen = relay.log.datagrams();
    assert!(seen.len() >= 3, "handshake flights and data were all wrapped: {}", seen.len());
    assert_eq!(h.datagrams as usize, seen.len() + relay.log.rejections().len());
    assert!(relay.log.rejections().is_empty(), "{:?}", relay.log.rejections());
    let seqs: Vec<u64> = seen.iter().filter_map(|e| if let ProxyEvent::Datagram { sequence, .. } = e { *sequence } else { None }).collect();
    assert_eq!(seqs, (0..seqs.len() as u64).collect::<Vec<_>>(), "one sequence per datagram, in order");
    assert_eq!(server.completed_handshakes().len(), 1);
}
