//! What a workspace delete ([`Engine::clear_isolation`]) clears stays cleared
//! when an execution of that workspace that was in flight goes on afterwards:
//! it pools no connection (HTTP/1.1, HTTP/2, HTTP/3), keeps no session ticket
//! (TLS over TCP, QUIC) and returns no gRPC channel, while another
//! workspace's execution in flight across the same delete keeps all of them.
//! A gRPC channel in use at a lock is not kept either, and the lock check
//! ([`Engine::session_tickets_held`]) counts the tickets held by prepared TLS
//! configurations. A gate (`anvil_fixtures::gate`) holds the request until
//! the test has deleted the workspace.

use anvil_domain::Id;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::{GrpcMode, GrpcSchemaSource, GrpcSpec, GrpcWire, Protocol, RequestSpec};
use anvil_domain::settings::{EarlyDataPolicy, HttpVersionPolicy, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::early_data::{self, EarlyMode};
use anvil_fixtures::gate::{self, Gate};
use anvil_fixtures::{LabPki, TlsServerOptions, h3server, http as fx};
use anvil_transport::grpc::Channels;
use anvil_transport::recorder::EventCtx;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

fn get(url: &str) -> ExecutionContext {
    ExecutionContext::standalone(RequestSpec::http("GET", url))
}

fn in_workspace(mut c: ExecutionContext, isolation: &str) -> ExecutionContext {
    c.isolation = isolation.into();
    c
}

fn with(mut c: ExecutionContext, o: SettingsOverrides) -> ExecutionContext {
    c.settings_layers.push(("run".into(), o));
    c
}

fn with_version(c: ExecutionContext, version: HttpVersionPolicy) -> ExecutionContext {
    with(c, SettingsOverrides { http_version: Some(version), ..Default::default() })
}

/// Under the early-data opt-in, with connection reuse off (0-RTT needs a
/// new connection): the session tickets are the only thing kept.
fn early(c: ExecutionContext) -> ExecutionContext {
    let policy = EarlyDataPolicy { enabled: true, extra_methods: vec![] };
    with(c, SettingsOverrides { early_data: Some(policy), keepalive: Some(false), ..Default::default() })
}

/// Trust the lab CA (a TLS profile selected for every hop).
fn lab_trust(mut c: ExecutionContext) -> ExecutionContext {
    let p = TlsProfile {
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
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let id = p.id;
    c.tls_profiles.push(p);
    c.settings_layers.push(("trust".into(), SettingsOverrides { tls_profile_id: Some(id), ..Default::default() }));
    c
}

/// A GET held on its first hop (plain HTTP through `gate`) that is then
/// redirected to `to`: whatever it opens there, it opens after the test acted.
fn redirected(gate: &Gate, to: &str) -> ExecutionContext {
    let to: String = url::form_urlencoded::byte_serialize(to.as_bytes()).collect();
    get(&format!("http://{}/redirect?to={to}", gate.addr.unwrap()))
}

/// A unary gRPC call (schema by server reflection).
fn grpc_call(url: &str) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Grpc;
    s.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: "Unary".into(),
        mode: GrpcMode::Unary,
        schema: GrpcSchemaSource::Reflection,
        messages: vec![r#"{"message":"hi"}"#.into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    ExecutionContext::standalone(s)
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn spawn(e: &Arc<Engine>, c: &ExecutionContext) -> JoinHandle<ExecutionOutput> {
    let (e, c) = (e.clone(), c.clone());
    tokio::spawn(async move { run(&e, &c).await })
}

async fn connected(gate: &Gate) {
    tokio::time::timeout(Duration::from_secs(10), gate.held()).await.expect("the request never connected");
}

/// Run `c` while `gate` holds its connection, delete workspace-a meanwhile,
/// then let the connection through.
async fn across_a_delete(e: &Arc<Engine>, c: &ExecutionContext, gate: &Gate) -> ExecutionOutput {
    let task = spawn(e, c);
    connected(gate).await;
    e.clear_isolation("workspace-a");
    gate.release();
    task.await.unwrap()
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

fn http_version(o: &ExecutionOutput) -> Option<&str> {
    o.record.response.as_ref().map(|r| r.http_version.as_str())
}

/// Whether the execution's last attempt used a pooled connection.
fn reused(o: &ExecutionOutput) -> bool {
    o.record.attempts.last().and_then(|a| a.connection.as_ref()).is_some_and(|c| c.reused)
}

fn grpc_ok(o: &ExecutionOutput) {
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Grpc { grpc_status, .. } => assert_eq!(*grpc_status, Some(0), "{failure:?}"),
        other => panic!("not gRPC: {other:?}; failure: {failure:?}"),
    }
}

#[tokio::test]
async fn a_connection_in_use_at_its_workspace_delete_is_not_pooled_and_other_workspaces_keep_theirs() {
    init();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    for version in [HttpVersionPolicy::Http1Only, HttpVersionPolicy::H2c] {
        let e = Arc::new(Engine::new());
        let (a, b) = (gate::tcp(api.addr, 0).await.unwrap(), gate::tcp(api.addr, 0).await.unwrap());
        let in_a = in_workspace(with_version(get(&format!("http://{}/echo", a.addr.unwrap())), version), "workspace-a");
        let in_b = in_workspace(with_version(get(&format!("http://{}/echo", b.addr.unwrap())), version), "workspace-b");
        let (task_a, task_b) = (spawn(&e, &in_a), spawn(&e, &in_b));
        connected(&a).await;
        connected(&b).await;
        e.clear_isolation("workspace-a");
        a.release();
        b.release();
        assert_eq!(status(&task_a.await.unwrap()), Some(200), "{version:?}");
        assert_eq!(status(&task_b.await.unwrap()), Some(200), "{version:?}");
        assert_eq!(e.http.pool.stats().connections, 1, "{version:?}: only workspace-b's connection is pooled");

        // The pooled connection is workspace-b's; workspace-a's next request
        // (after the delete) opens its own, and it is pooled again.
        assert!(reused(&run(&e, &in_b).await), "{version:?}: workspace-b's connection was not kept");
        assert!(!reused(&run(&e, &in_a).await), "{version:?}: workspace-a's connection was pooled after its delete");
        assert_eq!(e.http.pool.stats().connections, 2, "{version:?}");
    }
}

/// QUIC cannot pass the TCP gate, so the execution is held on its first hop
/// and redirected to the HTTP/3 fixture after the delete: the QUIC
/// connection it then opens is its own only, unless its workspace is another.
#[tokio::test]
async fn an_http3_connection_of_an_execution_that_spans_its_workspace_delete_is_not_pooled() {
    init();
    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Arc::new(Engine::new());
    for (workspace, pooled) in [("workspace-a", 0), ("workspace-b", 1)] {
        let gate = gate::tcp(api.addr, 0).await.unwrap();
        let c = in_workspace(lab_trust(with_version(redirected(&gate, &h3.url("/echo")), HttpVersionPolicy::Http3WithFallback)), workspace);
        let o = across_a_delete(&e, &c, &gate).await;
        let failures: Vec<_> = o.record.attempts.iter().map(|a| a.failure.as_ref().map(|f| f.kind)).collect();
        assert_eq!(status(&o), Some(200), "{workspace}: {failures:?}");
        assert_eq!(http_version(&o), Some("HTTP/3"), "{workspace}");
        assert_eq!(e.h3.pool_stats().connections, pooled, "{workspace}: QUIC connections pooled after workspace-a's delete");
    }
}

/// Held on a plain-HTTP first hop and redirected to the early-data fixture
/// after the delete, so the TLS or QUIC handshake (and the tickets it
/// receives) happen after it.
#[tokio::test]
async fn session_tickets_received_after_the_workspace_delete_are_not_kept() {
    init();
    let tcp = early_data::serve_tls("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.unwrap();
    let quic = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.unwrap();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    for (to, version) in [(tcp.url("/echo"), HttpVersionPolicy::Http1Only), (quic.url("/echo"), HttpVersionPolicy::Http3WithFallback)] {
        let e = Arc::new(Engine::new());
        for (workspace, kept) in [("workspace-a", false), ("workspace-b", true)] {
            let gate = gate::tcp(api.addr, 0).await.unwrap();
            let c = in_workspace(early(lab_trust(with_version(redirected(&gate, &to), version))), workspace);
            let o = across_a_delete(&e, &c, &gate).await;
            let failures: Vec<_> = o.record.attempts.iter().map(|a| a.failure.as_ref().map(|f| f.kind)).collect();
            assert_eq!(status(&o), Some(200), "{version:?} {workspace}: {failures:?}");
            let ed = o.record.attempts.last().and_then(|a| a.early_data.clone()).expect("early-data evidence");
            assert!(ed.tickets_received >= 1, "{version:?} {workspace}: the fixture issues tickets: {ed:?}");
            assert_eq!(e.early_data_tickets_held() >= 1, kept, "{version:?} {workspace}: tickets kept after workspace-a's delete");
        }
    }
}

#[tokio::test]
async fn a_grpc_channel_in_use_at_its_workspace_delete_or_at_a_lock_is_not_kept() {
    init();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut e = Engine::new();
    e.grpc_channels = Some(Arc::new(Channels::new()));
    let e = Arc::new(e);
    let channels = e.grpc_channels.clone().unwrap();
    let call = |gate: &Gate, workspace: &str| in_workspace(grpc_call(&format!("grpc://{}", gate.addr.unwrap())), workspace);

    // Workspace delete: workspace-b's call, in flight across the same
    // delete, keeps its channel; workspace-a's does not.
    let (a, b) = (gate::tcp(api.addr, 0).await.unwrap(), gate::tcp(api.addr, 0).await.unwrap());
    let (task_a, task_b) = (spawn(&e, &call(&a, "workspace-a")), spawn(&e, &call(&b, "workspace-b")));
    connected(&a).await;
    connected(&b).await;
    e.clear_isolation("workspace-a");
    a.release();
    b.release();
    grpc_ok(&task_a.await.unwrap());
    grpc_ok(&task_b.await.unwrap());
    assert_eq!(channels.len(), 1, "only workspace-b's channel is kept");

    // Channels never cross workspaces: to the same destination, workspace-b
    // reuses its channel and workspace-a opens its own.
    let o = run(&e, &call(&b, "workspace-b")).await;
    grpc_ok(&o);
    assert!(reused(&o), "workspace-b's channel was not kept");
    let o = run(&e, &call(&b, "workspace-a")).await;
    grpc_ok(&o);
    assert!(!reused(&o), "workspace-a used workspace-b's channel");
    assert_eq!(channels.len(), 2);

    // Lock: a call in flight at the lock does not keep its channel.
    let g = gate::tcp(api.addr, 0).await.unwrap();
    let task = spawn(&e, &call(&g, "workspace-b"));
    connected(&g).await;
    e.clear_sensitive_state();
    assert_eq!(channels.len(), 0);
    g.release();
    grpc_ok(&task.await.unwrap());
    assert_eq!(channels.len(), 0, "the channel in use at the lock was kept");

    // After unlock, channels are kept again.
    grpc_ok(&run(&e, &call(&g, "workspace-b")).await);
    assert_eq!(channels.len(), 1);
}

#[tokio::test]
async fn the_lock_check_counts_the_session_tickets_of_prepared_tls_configurations() {
    init();
    let fx = early_data::serve_tls("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.unwrap();
    let e = Engine::new();
    // Without the early-data opt-in: no 0-RTT ticket cache, but the prepared
    // TLS configuration's session store keeps the tickets the server sends.
    let o = run(&e, &lab_trust(get(&fx.url("/echo")))).await;
    assert_eq!(status(&o), Some(200));
    assert!(o.record.attempts[0].early_data.is_none());
    assert_eq!(e.early_data_tickets_held(), 0);
    assert_eq!(e.prepared_tls_len(), 1);
    assert!(e.session_tickets_held() >= 1, "the prepared TLS configuration's tickets are not counted");
    e.clear_sensitive_state();
    assert_eq!(e.session_tickets_held(), 0, "the lock left tickets behind");
}
