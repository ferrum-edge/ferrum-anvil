//! Per-protocol load units (LOAD-013) against real loopback fixtures: HTTP/3
//! (forced and automatic fallback), unary and server-streaming gRPC (native
//! over HTTP/2 and HTTP/3, gRPC-Web over HTTP/1.1), SSE, WebSocket, TCP
//! framed exchanges and DTLS. UDP datagram accounting (LOAD-013 itself) is in
//! `load_scenarios.rs`. Every report must balance its unit ledger and its
//! protocol denominators, reopen with a verified integrity hash and render
//! offline. Fixture ground truth confirms what actually reached the server.

use anvil_domain::Id;
use anvil_domain::load::*;
use anvil_domain::outcome::ClosedBy;
use anvil_domain::request::*;
use anvil_domain::settings::{HttpVersionPolicy, ProxySelection, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ProxyKind, ProxyProfile, TlsMinVersion, TlsProfile};
use anvil_engine::ExecutionContext;
use anvil_engine::context::MemoryAttachments;
use anvil_fixtures::dtls::{self as fxdtls, DtlsServerOptions};
use anvil_fixtures::http as fx;
use anvil_fixtures::streams::{self, TcpMode};
use anvil_fixtures::{GroundTruth, GroundTruthLog, LabPki, TlsServerOptions, h3server};
use anvil_load::report::{check_balance, check_protocol_balance, check_request_balance};
use anvil_load::{Dataset, DatasetFormat, LoadController, LoadError, LoadJob, LoadRun, RefusalCode, RunOptions, WorkerJob};
use bytes::Bytes;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    anvil_transport::init();
    anvil_fixtures::init();
    SERIAL.lock().await
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

fn lab_profile() -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab ca".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn layer(c: &mut ExecutionContext, o: SettingsOverrides) {
    c.settings_layers.push(("workspace".into(), o));
}

fn lab_trust(c: &mut ExecutionContext) {
    let p = lab_profile();
    layer(c, SettingsOverrides { tls_profile_id: Some(p.id), ..Default::default() });
    c.tls_profiles.push(p);
}

fn version(c: &mut ExecutionContext, v: HttpVersionPolicy) {
    layer(c, SettingsOverrides { http_version: Some(v), ..Default::default() });
}

fn ctx(protocol: Protocol, url: &str) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = protocol;
    let mut c = ExecutionContext::standalone(s);
    c.isolation = "load-protocols".into();
    layer(
        &mut c,
        SettingsOverrides {
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(3_000)),
                tls_handshake_ms: Some(Some(3_000)),
                response_headers_ms: Some(Some(5_000)),
                total_ms: Some(Some(20_000)),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    c
}

fn plan(workload: Workload, chain: Vec<Id>, mode: ConnectionMode) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "protocol plan".into(),
        workload,
        chain,
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: mode,
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn iterations(n: u64, c: u64) -> Workload {
    Workload::Iterations { iterations: n, concurrency: c }
}

fn opts() -> RunOptions {
    RunOptions { acknowledged: true, graceful_stop_ms: 5_000, cancel_drain_ms: 1_000, progress_interval_ms: 250, ..Default::default() }
}

/// Every report: balanced ledgers, balanced protocol denominators, a
/// verified round trip, an inert offline HTML rendering and CSV rows.
fn check_report(r: &LoadReport) {
    check_balance(&r.counts).unwrap_or_else(|e| panic!("iteration ledger: {e}: {:?}", r.counts));
    check_request_balance(&r.requests).unwrap_or_else(|e| panic!("unit ledger: {e}: {:?}", r.requests));
    check_protocol_balance(r).unwrap_or_else(|e| panic!("protocol denominators: {e}: {:#?}", r.protocol_metrics));
    let p = r.protocol_metrics.as_ref().expect("protocol metrics");
    assert_eq!(p.version, PROTOCOL_METRICS_VERSION);
    let json = anvil_load::report::to_json(r);
    let (back, integrity) = anvil_load::report::open_json(&json).unwrap();
    assert_eq!(integrity, anvil_load::report::Integrity::Verified);
    assert_eq!(&back, r, "protocol metrics survive the round trip");
    let html = anvil_load::html::to_html(&back);
    assert!(html.contains("Protocol: ") && html.contains(&p.semantics.completed_means.replace('\'', "&#39;")));
    assert!(!html.to_ascii_lowercase().contains("<script"));
    let kind = serde_json::to_value(p.unit).unwrap().as_str().unwrap().to_string();
    assert!(anvil_load::report::summary_csv(&back).contains(&format!("unit,kind,{kind}")));
}

async fn run(p: LoadPlan, requests: Vec<(Id, ExecutionContext)>, dataset: Option<Dataset>) -> LoadReport {
    let job = LoadJob { requests: requests.into_iter().collect(), dataset };
    let r = LoadRun::prepare(p, job, opts()).expect("valid plan").execute(CancellationToken::new(), None).await;
    check_report(&r);
    r
}

async fn run_one(p: LoadPlan, c: ExecutionContext) -> LoadReport {
    let id = p.chain[0];
    run(p, vec![(id, c)], None).await
}

fn proto(r: &LoadReport) -> &ProtocolLoadMetrics {
    r.protocol_metrics.as_ref().unwrap()
}

fn count(log: &GroundTruthLog, f: impl Fn(&GroundTruth) -> bool) -> usize {
    log.entries().iter().filter(|e| f(&e.event)).count()
}

fn accepted(log: &GroundTruthLog) -> usize {
    count(log, |e| matches!(e, GroundTruth::ConnectionAccepted { .. }))
}

fn requests_to(log: &GroundTruthLog, prefix: &str) -> usize {
    count(log, |e| matches!(e, GroundTruth::RequestReceived { path, .. } if path.starts_with(prefix)))
}

// ----------------------------------------------------------------- HTTP/3

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_h3_forced_reuses_quic_per_virtual_user_and_never_falls_back() {
    let _g = serial().await;
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    for (mode, max_conns) in [(ConnectionMode::Persistent, 2usize), (ConnectionMode::Fresh, 20)] {
        let before = f.connections();
        let mut c = ctx(Protocol::Http, &f.url("/"));
        lab_trust(&mut c);
        version(&mut c, HttpVersionPolicy::Http3Only);
        let id = Id::new();
        let r = run_one(plan(iterations(20, 2), vec![id], mode), c).await;
        let conns = f.connections() - before;
        assert_eq!(r.requests.completed, 20, "{:?}", r.failure_categories);
        assert_eq!(r.protocols, vec![("h3".to_string(), 20)]);
        let h = proto(&r).http.clone().unwrap();
        assert_eq!((h.units_over_h3, h.protocol_fallback_attempts, h.units_with_fallback), (20, 0, 0), "forced HTTP/3 never falls back");
        assert!(conns <= max_conns && conns >= 1, "{mode:?}: {conns} QUIC connections");
        assert_eq!(r.requests.connections_opened as usize, conns, "engine evidence matches the fixture's QUIC connections");
        assert_eq!(r.requests.connections_opened + r.requests.connections_reused, 20);
        if mode == ConnectionMode::Fresh {
            assert_eq!(conns, 20);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_h3_automatic_fallback_attempts_are_counted_separately() {
    let _g = serial().await;
    // A TCP-only TLS server: HTTP/3 times out, then each request falls back.
    let f = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let mut c = ctx(Protocol::Http, &f.url("/"));
    lab_trust(&mut c);
    version(&mut c, HttpVersionPolicy::Http3WithFallback);
    layer(
        &mut c,
        SettingsOverrides {
            timeouts: Some(TimeoutOverrides { tls_handshake_ms: Some(Some(600)), ..Default::default() }),
            ..Default::default()
        },
    );
    let id = Id::new();
    let r = run_one(plan(iterations(4, 4), vec![id], ConnectionMode::Persistent), c).await;
    assert_eq!(r.requests.started, 4, "a fallback is an attempt inside a request, not another request");
    assert_eq!(r.requests.completed, 4);
    assert_eq!(requests_to(&f.log, "/"), 4, "each request reached the server exactly once");
    let h = proto(&r).http.clone().unwrap();
    assert_eq!((h.protocol_fallback_attempts, h.units_with_fallback, h.units_over_h3), (4, 4, 0));
    assert!(r.protocols.iter().all(|(p, _)| p != "h3"), "HTTP/3 is not claimed: {:?}", r.protocols);
    assert!(r.latency_success.min_us >= 550_000, "the failed HTTP/3 attempt is part of the latency: {:?}", r.latency_success);
    assert!(r.notes.iter().any(|n| n.contains("needed an HTTP/3 → TCP fallback (4 extra attempt(s))")), "{:?}", r.notes);
}

// ------------------------------------------------------------------- gRPC

fn echo_attachment() -> (AttachmentRef, MemoryAttachments) {
    let proto = anvil_fixtures::grpc::ECHO_PROTO;
    let sha = anvil_transport::certs::sha256_hex(proto.as_bytes());
    let store = MemoryAttachments(HashMap::from([(sha.clone(), Bytes::from_static(proto.as_bytes()))]));
    (AttachmentRef::Stored { sha256: sha, size: proto.len() as u64, file_name: "echo.proto".into(), media_type: None }, store)
}

fn grpc_ctx(url: &str, method: &str, mode: GrpcMode, message: &str, wire: GrpcWire) -> ExecutionContext {
    let (att, store) = echo_attachment();
    let mut c = ctx(Protocol::Grpc, url);
    c.spec.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: method.into(),
        mode,
        schema: GrpcSchemaSource::ProtoFiles { files: vec![att] },
        messages: vec![message.into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire,
    });
    c.attachments = Arc::new(store);
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_grpc_unary_ledger_separates_ok_codes_and_missing_status_on_pooled_channels() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    // Dataset rows choose the fixture's outcome per call: OK, PERMISSION_DENIED,
    // NOT_FOUND, or -1 = a reply and then a stream reset before any status.
    let data = || Dataset::parse(DatasetFormat::Csv, b"fail\n0\n0\n0\n7\n5\n-1\n".to_vec()).unwrap();
    let url = format!("grpc://{}", f.addr);
    let msg = r#"{"message":"m{{anvil.iteration}}","failWith":{{fail}}}"#;
    for (mode, conns) in [(ConnectionMode::Persistent, 1usize..=3), (ConnectionMode::Fresh, 30..=30)] {
        f.log.clear();
        let id = Id::new();
        let mut p = plan(iterations(30, 3), vec![id], mode);
        p.dataset_id = Some(Id::new());
        let r = run(p, vec![(id, grpc_ctx(&url, "Unary", GrpcMode::Unary, msg, GrpcWire::Grpc))], Some(data())).await;
        let g = proto(&r).grpc.clone().unwrap();
        assert_eq!(proto(&r).unit, LoadUnitKind::GrpcCall);
        assert_eq!(g.status_codes, vec![(0, 15), (5, 5), (7, 5)], "{:?}", r.failure_categories);
        assert_eq!((g.ok, g.non_ok, g.missing_status), (15, 10, 5));
        assert_eq!(r.requests.completed, 25, "a call completes only with a terminal status");
        assert_eq!(r.requests.application_failures, 10, "non-OK codes are application failures, not transport failures");
        assert_eq!(r.requests.transport_failures, 5, "a missing status is incomplete, never a success");
        assert_eq!(r.latency_success.count, 15, "percentiles cover OK calls only");
        assert_eq!(requests_to(&f.log, "/anvil.lab.v1.Echo/Unary"), 30, "every call reached the fixture once");
        let accepted = accepted(&f.log);
        assert!(conns.contains(&accepted), "{mode:?}: {accepted} connections");
        assert_eq!(r.requests.connections_opened as usize, accepted, "channel evidence matches ground truth");
        assert_eq!(r.requests.connections_opened + r.requests.connections_reused, 30);
        let app: u64 = r.failure_categories.iter().filter(|c| c.category.starts_with("application_failure")).map(|c| c.count).sum();
        assert_eq!(app, 10, "{:?}", r.failure_categories);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_grpc_web_over_http1_and_grpc_over_h3_reuse_channels() {
    let _g = serial().await;
    // gRPC-Web in cleartext runs over HTTP/1.1: one call at a time per pooled connection.
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let c = grpc_ctx(&format!("http://{}", f.addr), "Unary", GrpcMode::Unary, r#"{"message":"web"}"#, GrpcWire::GrpcWeb);
    let id = Id::new();
    let r = run_one(plan(iterations(20, 2), vec![id], ConnectionMode::Persistent), c).await;
    assert_eq!(proto(&r).grpc.as_ref().unwrap().ok, 20, "{:?}", r.failure_categories);
    assert_eq!(r.protocols, vec![("http/1.1".to_string(), 20)]);
    let n = accepted(&f.log);
    assert!((1..=2).contains(&n), "{n} HTTP/1.1 connections for 2 virtual users");
    assert_eq!(r.requests.connections_reused, 20 - n as u64);

    // Native gRPC over HTTP/3: one pooled QUIC connection per virtual user.
    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let mut c = grpc_ctx(&format!("grpcs://127.0.0.1:{}", h3.addr.port()), "Unary", GrpcMode::Unary, r#"{"message":"q"}"#, GrpcWire::Grpc);
    lab_trust(&mut c);
    version(&mut c, HttpVersionPolicy::Http3Only);
    let id = Id::new();
    let r = run_one(plan(iterations(20, 2), vec![id], ConnectionMode::Persistent), c).await;
    let g = proto(&r).grpc.clone().unwrap();
    assert_eq!((g.ok, g.protocol_fallback_attempts), (20, 0), "{:?}", r.failure_categories);
    assert_eq!(r.protocols, vec![("h3".to_string(), 20)]);
    assert!((1..=2).contains(&h3.connections()), "{} QUIC connections", h3.connections());
    assert_eq!(r.requests.connections_opened as usize, h3.connections());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_grpc_server_streams_count_messages_and_deadlines() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let url = format!("grpc://{}", f.addr);
    let c = grpc_ctx(&url, "ServerStream", GrpcMode::ServerStreaming, r#"{"message":"s","count":4}"#, GrpcWire::Grpc);
    let id = Id::new();
    let r = run_one(plan(iterations(12, 3), vec![id], ConnectionMode::Persistent), c).await;
    let p = proto(&r);
    assert_eq!(p.unit, LoadUnitKind::GrpcStream);
    let s = p.stream.clone().unwrap();
    assert_eq!((s.opened, s.messages_received, s.with_messages), (12, 48, 12));
    assert_eq!(s.time_to_first_message.count, 12);
    assert!(s.time_to_first_message.max_us <= r.latency_success.max_us, "first message precedes the end of its stream");
    assert_eq!(p.grpc.as_ref().unwrap().status_codes, vec![(0, 12)]);
    assert_eq!(r.latency_success.count, 12);

    // A stream still running when its gRPC deadline elapses: the status is
    // unknown (never DEADLINE_EXCEEDED), the stream is a censored timeout.
    let mut c = grpc_ctx(&url, "ServerStream", GrpcMode::ServerStreaming, r#"{"message":"s","count":1000}"#, GrpcWire::Grpc);
    c.spec.grpc.as_mut().unwrap().deadline_ms = Some(80);
    let id = Id::new();
    let r = run_one(plan(iterations(6, 3), vec![id], ConnectionMode::Persistent), c).await;
    let p = proto(&r);
    let (g, s) = (p.grpc.clone().unwrap(), p.stream.clone().unwrap());
    assert_eq!(r.requests.timeouts, 6);
    assert!(g.status_codes.is_empty() && g.missing_status == 6, "{g:?}");
    assert_eq!(s.opened, 6);
    assert!(s.messages_received >= 6, "messages that did arrive are still counted: {s:?}");
    assert_eq!(r.latency_success.count, 0);
    assert_eq!(r.timeouts_censored.count, 6);
    assert!(r.notes.iter().any(|n| n.contains("not DEADLINE_EXCEEDED")), "{:?}", r.notes);
    assert!(anvil_load::html::to_html(&r).contains("<div class=\"value\">—</div>"), "no successful stream → no percentile");
}

// -------------------------------------------------------------------- SSE

fn sse_ctx(url: &str, max_events: u32) -> ExecutionContext {
    let mut c = ctx(Protocol::Sse, url);
    c.spec.sse = Some(SseSpec { max_events, idle_timeout_ms: 2_000, last_event_id: None, reconnect: false });
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_sse_streams_follow_the_request_stop_conditions() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    // A chain of two stream units per iteration: one stops at max_events,
    // one is ended by the server.
    let (a, b) = (Id::new(), Id::new());
    let r = run(
        plan(iterations(6, 2), vec![a, b], ConnectionMode::Persistent),
        vec![(a, sse_ctx(&f.url("/sse?count=20&interval=5"), 3)), (b, sse_ctx(&f.url("/sse?count=2&interval=5"), 0))],
        None,
    )
    .await;
    let p = proto(&r);
    assert_eq!(p.unit, LoadUnitKind::SseStream);
    let s = p.stream.clone().unwrap();
    assert_eq!((r.requests.started, r.requests.completed), (12, 12));
    assert_eq!((s.opened, s.messages_received, s.with_messages), (12, 6 * 3 + 6 * 2, 12));
    let by = |c: ClosedBy| s.ended_by.iter().find(|x| x.closed_by == c).map(|x| x.count).unwrap_or(0);
    assert_eq!((by(ClosedBy::Client), by(ClosedBy::Peer)), (6, 6), "{:?}", s.ended_by);
    assert_eq!(s.time_to_first_message.count, 12);
    assert_eq!(accepted(&f.log), 12, "each stream is its own connection, whatever the connection mode");

    // An error status: the stream never opens; it completes as an application failure.
    let id = Id::new();
    let r = run_one(plan(iterations(3, 1), vec![id], ConnectionMode::Persistent), sse_ctx(&f.url("/status/503"), 0)).await;
    let s = proto(&r).stream.clone().unwrap();
    assert_eq!((s.opened, r.requests.completed, r.requests.application_failures), (0, 3, 3));
    assert_eq!(r.latency_success.count, 0);
}

// -------------------------------------------------------------- WebSocket

fn ws_ctx(url: &str, messages: &[&str], expect: u32, idle_ms: u64) -> ExecutionContext {
    let mut c = ctx(Protocol::WebSocket, url);
    c.spec.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: messages.iter().map(|m| WsMessage::Text { text: m.to_string() }).collect(),
        expect_messages: expect,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: idle_ms,
        permessage_deflate: Default::default(),
    });
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_websocket_sessions_messages_rtt_and_close_codes() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let ws = format!("ws://{}/ws", f.addr);
    let id = Id::new();
    let r = run_one(plan(iterations(10, 2), vec![id], ConnectionMode::Persistent), ws_ctx(&ws, &["a", "b", "c"], 3, 2_000)).await;
    let w = proto(&r).websocket.clone().unwrap();
    assert_eq!((w.opened, w.handshake_rejected, w.not_opened, w.closed_cleanly), (10, 0, 0, 10));
    assert_eq!((w.messages_sent, w.messages_received), (30, 30));
    assert_eq!(count(&f.log, |e| matches!(e, GroundTruth::MessageReceived { .. })), 30, "ground truth: every scripted message arrived");
    assert!(w.rtt_defined);
    assert_eq!((w.rtt_pairs, w.rtt_unpaired_sessions), (30, 0));
    assert!(w.rtt.p99_us <= r.latency_success.max_us, "a round trip fits inside its session");
    assert_eq!(w.close_codes, vec![ClosedCount { closed_by: ClosedBy::Client, code: Some(1000), count: 10 }]);
    assert_eq!(r.latency_success.count, 10);
    assert_eq!(accepted(&f.log), 10, "a session is its own connection");

    // Without expect_messages there is no pairing, so no RTT is claimed.
    let id = Id::new();
    let r = run_one(plan(iterations(4, 2), vec![id], ConnectionMode::Persistent), ws_ctx(&ws, &["x"], 0, 250)).await;
    let w = proto(&r).websocket.clone().unwrap();
    assert!(!w.rtt_defined && w.rtt_pairs == 0 && w.rtt.count == 0);
    assert!(r.notes.iter().any(|n| n.contains("No round-trip time is reported")));
    assert!(anvil_load::html::to_html(&r).contains("Round-trip time: not defined"));

    // A rejected handshake (the server answered) vs a session that ends abnormally.
    let (rej, abn) = (Id::new(), Id::new());
    let mut p = plan(iterations(8, 2), vec![], ConnectionMode::Persistent);
    p.mix = vec![WeightedStep { request_id: rej, weight: 1 }, WeightedStep { request_id: abn, weight: 1 }];
    let want_rejected = (0..8).filter(|i| anvil_load::executor::pick_weighted(1, &[1, 2], *i) == 0).count() as u64;
    let r = run(
        p,
        vec![
            (rej, ws_ctx(&format!("ws://{}/status/403", f.addr), &["x"], 1, 2_000)),
            (abn, ws_ctx(&format!("ws://{}/ws?abnormal_after=1", f.addr), &["a", "b"], 2, 2_000)),
        ],
        None,
    )
    .await;
    let w = proto(&r).websocket.clone().unwrap();
    assert_eq!(w.handshake_rejected, want_rejected);
    assert_eq!(w.opened, 8 - want_rejected);
    assert_eq!(w.closed_cleanly, 0, "an abnormal end is not a clean close");
    assert_eq!(r.requests.transport_failures, 8 - want_rejected, "1006 after open is an incomplete session");
    assert!(w.close_codes.iter().all(|c| c.closed_by == ClosedBy::Abnormal && c.code == Some(1006)), "{:?}", w.close_codes);
    let want: Vec<(u16, u64)> = [(101, 8 - want_rejected), (403, want_rejected)].into_iter().filter(|(_, n)| *n > 0).collect();
    assert_eq!(r.status_distribution, want);
    assert_eq!(r.latency_success.count, 0);
}

// ------------------------------------------------------------------- TCP

fn tcp_ctx(addr: std::net::SocketAddr, framing: TcpFraming, payloads: &[&str], expect: u32, half_close: bool) -> ExecutionContext {
    let mut c = ctx(Protocol::Tcp, &format!("tcp://{addr}"));
    c.spec.tcp = Some(TcpSpec {
        tls: false,
        framing,
        payloads: payloads.iter().map(|p| StreamPayload { data: p.to_string(), encoding: PayloadEncoding::Text }).collect(),
        half_close_after_send: half_close,
        read_idle_ms: 300,
        max_read_bytes: 1024 * 1024,
        expect_frames: expect,
        proxy_protocol: None,
    });
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_tcp_framed_exchanges_expectations_partial_frames_and_peer_closes() {
    let _g = serial().await;
    let echo = streams::tcp("127.0.0.1:0", TcpMode::Echo, None).await.unwrap();
    let id = Id::new();
    let c = tcp_ctx(echo.addr, TcpFraming::NewlineDelimited, &["ping", "pong"], 2, false);
    let r = run_one(plan(iterations(10, 2), vec![id], ConnectionMode::Persistent), c).await;
    let t = proto(&r).tcp.clone().unwrap();
    assert_eq!((t.connected, t.frames_sent, t.frames_received), (10, 20, 20));
    assert_eq!((t.expected_frames, t.expectation_met, t.expectation_short), (Some(2), 10, 0));
    assert_eq!((t.payload_bytes_sent, t.payload_bytes_received), (100, 100));
    assert_eq!(accepted(&echo.log), 10, "each exchange is its own connection");
    assert_eq!(r.latency_success.count, 10);

    // Fewer replies than expected: completed at the transport level, failed as an exchange.
    let c = tcp_ctx(echo.addr, TcpFraming::NewlineDelimited, &["ping", "pong"], 3, false);
    let id = Id::new();
    let r = run_one(plan(iterations(4, 2), vec![id], ConnectionMode::Persistent), c).await;
    let t = proto(&r).tcp.clone().unwrap();
    assert_eq!((t.expectation_met, t.expectation_short), (0, 4));
    assert_eq!((r.requests.completed, r.requests.application_failures, r.latency_success.count), (4, 4, 0));
    assert!(r.failure_categories[0].category.contains("tcp.expected_frames_not_received"), "{:?}", r.failure_categories);

    // The peer replies after our half-close with bytes that are not a whole
    // u16-prefixed frame, then closes: a partial frame and a peer close.
    let half = streams::tcp("127.0.0.1:0", TcpMode::ReplyAfterHalfClose, None).await.unwrap();
    let c = tcp_ctx(half.addr, TcpFraming::LengthPrefixedU16, &["x"], 0, true);
    let id = Id::new();
    let r = run_one(plan(iterations(4, 2), vec![id], ConnectionMode::Persistent), c).await;
    let t = proto(&r).tcp.clone().unwrap();
    assert_eq!((t.partial_frames, t.peer_closes, t.frames_received), (4, 4, 0));
    assert_eq!(r.requests.completed, 4);
}

// ------------------------------------------------------------------- DTLS

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_dtls_handshakes_are_measured_as_their_own_phase() {
    let _g = serial().await;
    let f = fxdtls::serve(
        "127.0.0.1:0",
        DtlsServerOptions { cert_pem: pki().server.cert.clone(), key_pem: pki().server.key.clone(), client_ca_pem: None },
    )
    .await
    .unwrap();
    let mut c = ctx(Protocol::Udp, &f.url());
    c.spec.udp = Some(UdpSpec {
        dtls: true,
        datagrams: vec![StreamPayload { data: "secure hello".into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 300,
        max_datagrams: 1,
        masque: None,
        proxy_protocol: None,
    });
    lab_trust(&mut c);
    let id = Id::new();
    let r = run_one(plan(iterations(5, 1), vec![id], ConnectionMode::Persistent), c).await;
    let p = proto(&r);
    assert_eq!(p.unit, LoadUnitKind::DtlsExchange);
    let d = p.datagram.clone().unwrap();
    let h = d.dtls_handshakes.clone().unwrap();
    assert_eq!((h.attempted, h.completed, h.failed, h.timed_out, h.duration.count), (5, 5, 0, 0, 5));
    assert_eq!(f.completed_handshakes().len(), 5, "ground truth: five handshakes completed");
    assert_eq!((d.datagrams_sent, d.datagrams_received, d.echoed_payloads, d.exchanges_with_response), (5, 5, 5, 5));
    assert_eq!(r.latency_success.count, 5, "time to first response of every responding exchange");
}

// ---------------------------------------------------- refusals and policy

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_013_unsupported_combinations_are_refused_typed_before_traffic() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let url = format!("grpc://{}", f.addr);
    let refused = |p: LoadPlan, reqs: Vec<(Id, ExecutionContext)>| {
        let job = LoadJob { requests: reqs.into_iter().collect(), dataset: None };
        match LoadRun::prepare(p, job, opts()) {
            Err(LoadError::Refused(r)) => r,
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("must be refused"),
        }
    };
    let one = |c: ExecutionContext, mode: ConnectionMode| {
        let id = Id::new();
        (plan(iterations(1, 1), vec![id], mode), vec![(id, c)])
    };
    // A UDP or DTLS request through a mesh HBONE proxy profile.
    let via_hbone = |url: &str| {
        let mut c = ctx(Protocol::Udp, url);
        let pid = Id::new();
        c.proxy_profiles.push(ProxyProfile {
            id: pid,
            workspace_id: Id::new(),
            name: "mesh".into(),
            kind: ProxyKind::Hbone,
            address: "127.0.0.1:15008".into(),
            username: None,
            password: None,
            no_proxy: String::new(),
            tls_profile_id: None,
            hbone: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        layer(&mut c, SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id: pid }), ..Default::default() });
        c
    };
    let cases: Vec<(RefusalCode, ExecutionContext, ConnectionMode)> = vec![
        (
            RefusalCode::GrpcClientStreaming,
            grpc_ctx(&url, "ClientStream", GrpcMode::ClientStreaming, "{}", GrpcWire::Grpc),
            ConnectionMode::Persistent,
        ),
        (RefusalCode::GrpcBidirectional, grpc_ctx(&url, "Bidi", GrpcMode::Bidirectional, "{}", GrpcWire::Grpc), ConnectionMode::Persistent),
        (
            RefusalCode::GrpcReflection,
            {
                let mut c = grpc_ctx(&url, "Unary", GrpcMode::Unary, "{}", GrpcWire::Grpc);
                c.spec.grpc.as_mut().unwrap().schema = GrpcSchemaSource::Reflection;
                c
            },
            ConnectionMode::Persistent,
        ),
        (
            RefusalCode::SseReconnect,
            {
                let mut c = sse_ctx(&f.url("/sse"), 1);
                c.spec.sse.as_mut().unwrap().reconnect = true;
                c
            },
            ConnectionMode::Persistent,
        ),
        (
            RefusalCode::UdpMasque,
            {
                let mut c = ctx(Protocol::Udp, "udp://127.0.0.1:9");
                c.spec.udp = Some(UdpSpec {
                    dtls: false,
                    datagrams: vec![],
                    response_window_ms: 100,
                    max_datagrams: 1,
                    masque: Some(MasqueSpec {
                        proxy_url: "https://127.0.0.1:9".into(),
                        uri_template: MASQUE_DEFAULT_TEMPLATE.into(),
                        datagrams: Default::default(),
                    }),
                    proxy_protocol: None,
                });
                c
            },
            ConnectionMode::Fresh,
        ),
        (
            RefusalCode::HbonePersistent,
            {
                let mut c = ctx(Protocol::Http, &f.url("/"));
                let pid = Id::new();
                c.proxy_profiles.push(ProxyProfile {
                    id: pid,
                    workspace_id: Id::new(),
                    name: "mesh".into(),
                    kind: ProxyKind::Hbone,
                    address: "127.0.0.1:15008".into(),
                    username: None,
                    password: None,
                    no_proxy: String::new(),
                    tls_profile_id: None,
                    hbone: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                });
                layer(&mut c, SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id: pid }), ..Default::default() });
                c
            },
            ConnectionMode::Persistent,
        ),
        (RefusalCode::UdpHbone, via_hbone("udp://127.0.0.1:9"), ConnectionMode::Fresh),
        // DTLS through HBONE is refused the same way: its handshake would run
        // in a fresh tunnel per exchange.
        (RefusalCode::UdpHbone, via_hbone("dtls://127.0.0.1:9"), ConnectionMode::Fresh),
    ];
    for (code, c, mode) in cases {
        let (p, reqs) = one(c, mode);
        let r = refused(p, reqs);
        assert_eq!(r.code, code, "{}", r.message);
        assert!(r.to_string().contains("LOAD-013"));
    }
    let (p, reqs) = one(via_hbone("dtls://127.0.0.1:9"), ConnectionMode::Fresh);
    let r = refused(p, reqs);
    assert!(r.message.starts_with("DTLS through an HBONE tunnel"), "{}", r.message);
    // One plan, one unit kind: mixing HTTP requests with WebSocket sessions is refused.
    let (a, b) = (Id::new(), Id::new());
    let r = refused(
        plan(iterations(1, 1), vec![a, b], ConnectionMode::Persistent),
        vec![(a, ctx(Protocol::Http, &f.url("/"))), (b, ws_ctx(&format!("ws://{}/ws", f.addr), &["x"], 1, 500))],
    );
    assert_eq!(r.code, RefusalCode::MixedUnitKinds);
    assert!(r.message.contains("HTTP requests") && r.message.contains("WebSocket sessions"), "{}", r.message);
    assert!(f.log.entries().is_empty(), "nothing was sent for any refused plan");
}

/// A short open-workload job per protocol, for the worker-process checks.
fn protocol_jobs(http: &fx::Fixture, tcp: std::net::SocketAddr) -> Vec<(LoadUnitKind, ExecutionContext)> {
    let grpc = format!("grpc://{}", http.addr);
    vec![
        (LoadUnitKind::HttpRequest, ctx(Protocol::Http, &http.url("/delay-headers/20"))),
        (LoadUnitKind::GrpcCall, grpc_ctx(&grpc, "Unary", GrpcMode::Unary, r#"{"message":"w"}"#, GrpcWire::Grpc)),
        (
            LoadUnitKind::GrpcStream,
            grpc_ctx(&grpc, "ServerStream", GrpcMode::ServerStreaming, r#"{"message":"w","count":3}"#, GrpcWire::Grpc),
        ),
        (LoadUnitKind::SseStream, sse_ctx(&http.url("/sse?count=3&interval=10"), 0)),
        (LoadUnitKind::WebsocketSession, ws_ctx(&format!("ws://{}/ws", http.addr), &["a"], 1, 1_000)),
        (LoadUnitKind::TcpExchange, tcp_ctx(tcp, TcpFraming::NewlineDelimited, &["hi"], 1, false)),
        (LoadUnitKind::UdpExchange, {
            let mut c = ctx(Protocol::Udp, "udp://127.0.0.1:9");
            c.spec.url = format!("udp://{}", tcp); // no UDP listener there: silence or ICMP, never a claim
            c.spec.udp = Some(UdpSpec {
                dtls: false,
                datagrams: vec![StreamPayload { data: "u".into(), encoding: PayloadEncoding::Text }],
                response_window_ms: 50,
                max_datagrams: 1,
                masque: None,
                proxy_protocol: None,
            });
            c
        }),
    ]
}

const WORKER: &str = env!("CARGO_BIN_EXE_anvil-load-worker");

/// Authorization acknowledgement, lock-stops-run and the partial report hold
/// for every protocol, through the real worker process.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_protocol_needs_acknowledgement_and_stops_on_lock_with_a_partial_report() {
    let _g = serial().await;
    let http = fx::serve("127.0.0.1:0", None).await.unwrap();
    let tcp = streams::tcp("127.0.0.1:0", TcpMode::Echo, None).await.unwrap();
    for (kind, c) in protocol_jobs(&http, tcp.addr) {
        let id = Id::new();
        let p = plan(
            Workload::OpenArrivalRate {
                stages: vec![Stage { duration_secs: 0, target: 10 }, Stage { duration_secs: 8, target: 10 }],
                max_in_flight: 8,
            },
            vec![id],
            ConnectionMode::Persistent,
        );
        let job = LoadJob { requests: HashMap::from([(id, c)]), dataset: None };
        assert!(
            matches!(
                LoadRun::prepare(p.clone(), LoadJob { requests: job.requests.clone(), dataset: None }, RunOptions::default()),
                Err(LoadError::NotAcknowledged)
            ),
            "{kind:?}: an unacknowledged run never starts"
        );
        let wj = WorkerJob::from_load_job(&p, &job, opts()).unwrap();
        let mut ctl = LoadController::spawn(WORKER.as_ref(), &wj).await.unwrap();
        for _ in 0..3 {
            tokio::time::timeout(Duration::from_secs(5), ctl.next_progress()).await.expect("progress in time").expect("worker alive");
        }
        ctl.cancel_for_lock().await;
        let r = ctl.wait().await.unwrap();
        assert_eq!(r.completion, RunCompletion::StoppedByLock, "{kind:?}");
        assert!(r.partial);
        check_report(&r);
        assert_eq!(proto(&r).unit, kind);
        assert!(r.requests.started > 0 && r.requests.started < 80, "{kind:?}: {:?}", r.requests);
        assert!(r.notes.iter().any(|n| n.contains("vault locked")));
    }
    // No hidden traffic after the last lock.
    let before = http.log.entries().len() + tcp.log.entries().len();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(http.log.entries().len() + tcp.log.entries().len(), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_reports_compare_only_within_one_protocol() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let ws = format!("ws://{}/ws", f.addr);
    let mut runs = Vec::new();
    let id = Id::new();
    for _ in 0..2 {
        runs.push(run_one(plan(iterations(4, 2), vec![id], ConnectionMode::Persistent), ws_ctx(&ws, &["a", "b"], 2, 1_000)).await);
    }
    let c = anvil_load::compare(&runs[0], &runs[1]);
    assert!(c.compatible, "{:?}", c.differences);
    let anvil_load::compare::LatencyComparison::Comparable { deltas } = &c.latency else { panic!("{:?}", c.latency) };
    assert!(deltas.iter().any(|d| d.metric == "messages received per opened session"), "{deltas:?}");
    assert!(deltas.iter().any(|d| d.metric == "round trip p50 (µs)"));

    let id = Id::new();
    let tcp = streams::tcp("127.0.0.1:0", TcpMode::Echo, None).await.unwrap();
    let t = run_one(
        plan(iterations(4, 2), vec![id], ConnectionMode::Persistent),
        tcp_ctx(tcp.addr, TcpFraming::NewlineDelimited, &["x"], 1, false),
    )
    .await;
    let c = anvil_load::compare(&runs[0], &t);
    assert!(!c.compatible);
    assert!(c.summary.starts_with("Refused"), "{}", c.summary);
    assert_eq!(c.differences.len(), 1);
    assert_eq!(c.differences[0].aspect, "load unit");

    // Tampering with a protocol denominator breaks the integrity seal.
    let json = anvil_load::report::to_json(&runs[0]);
    let tampered = json.replacen("\"messages_received\": 8", "\"messages_received\": 9", 1);
    assert_ne!(json, tampered, "the WebSocket block carries messages_received");
    assert!(anvil_load::report::open_json(&tampered).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_schema_attachments_travel_to_the_worker_job() {
    let _g = serial().await;
    let c = grpc_ctx("grpc://127.0.0.1:9", "Unary", GrpcMode::Unary, "{}", GrpcWire::Grpc);
    let id = Id::new();
    let p = plan(iterations(1, 1), vec![id], ConnectionMode::Persistent);
    let job = LoadJob { requests: HashMap::from([(id, c)]), dataset: None };
    let wj = WorkerJob::from_load_job(&p, &job, opts()).unwrap();
    assert_eq!(wj.attachments.len(), 1, "the .proto file the call needs is scoped into the job");
    let (_, lj, _) = wj.into_load_job().unwrap();
    assert!(LoadRun::prepare(p, lj, opts()).is_ok());
}
