//! What a lock ([`Engine::clear_sensitive_state`]) clears stays cleared when
//! a response that was in flight arrives afterwards: its cookies are not
//! stored, and no connection or TLS material of its execution is kept
//! (HTTP/1.1, HTTP/2 and HTTP/3). A gate (`anvil_fixtures::gate`) holds the
//! request until the test has locked.

use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::gate::{self, Gate};
use anvil_fixtures::{LabPki, TlsServerOptions, h3server, http as fx};
use anvil_transport::recorder::EventCtx;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
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

fn with_version(mut c: ExecutionContext, version: HttpVersionPolicy) -> ExecutionContext {
    c.settings_layers.push(("run".into(), SettingsOverrides { http_version: Some(version), ..Default::default() }));
    c
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

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

/// Run `c` while `gate` holds its connection, lock the engine meanwhile
/// (without canceling anything), then let the connection through.
async fn across_a_lock(e: &Arc<Engine>, c: &ExecutionContext, gate: &Gate) -> ExecutionOutput {
    let task = {
        let (e, c) = (e.clone(), c.clone());
        tokio::spawn(async move { run(&e, &c).await })
    };
    tokio::time::timeout(Duration::from_secs(10), gate.held()).await.expect("the request never connected");
    e.clear_sensitive_state();
    gate.release();
    task.await.unwrap()
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

fn http_version(o: &ExecutionOutput) -> Option<&str> {
    o.record.response.as_ref().map(|r| r.http_version.as_str())
}

fn cookie_seen(f: &fx::Fixture) -> Option<String> {
    f.log.last_request_headers()?.into_iter().find(|(n, _)| n.eq_ignore_ascii_case("cookie")).map(|(_, v)| v)
}

#[tokio::test]
async fn a_response_that_arrives_after_a_lock_leaves_no_cookie_and_no_pooled_connection() {
    init();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let gate = gate::tcp(api.addr, 0).await.unwrap();
    let base = format!("http://{}", gate.addr.unwrap());
    let e = Arc::new(Engine::new());
    let o = across_a_lock(&e, &get(&format!("{base}/set-cookie?name=sid&value=before-lock")), &gate).await;
    // Not canceled: the request completes, and its answer set the cookie
    // (the record keeps the cookie's name, not its value).
    assert_eq!(status(&o), Some(200));
    let set_cookie = o.record.response.as_ref().unwrap().header_values("set-cookie").join("; ");
    assert!(set_cookie.starts_with("sid="), "{set_cookie}");
    assert_eq!(e.http.pool.stats().connections, 0, "the connection in use at the lock was pooled again");

    // The next request (a new connection, not held) carries nothing from before the lock.
    let o = run(&e, &get(&format!("{base}/echo"))).await;
    assert_eq!(status(&o), Some(200));
    assert_eq!(cookie_seen(&api), None, "the cookie of the answer that arrived after the lock was kept");

    // After unlock, connections and cookies are kept again.
    assert_eq!(e.http.pool.stats().connections, 1);
    assert_eq!(status(&run(&e, &get(&format!("{base}/set-cookie?name=sid&value=after-unlock"))).await), Some(200));
    assert_eq!(status(&run(&e, &get(&format!("{base}/echo"))).await), Some(200));
    assert_eq!(cookie_seen(&api).as_deref(), Some("sid=after-unlock"));
    assert_eq!(e.http.pool.stats().connections, 1, "one connection, reused");
}

#[tokio::test]
async fn an_http2_connection_in_use_at_a_lock_is_closed_when_its_request_ends() {
    init();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let gate = gate::tcp(api.addr, 0).await.unwrap();
    let e = Arc::new(Engine::new());
    let c = with_version(get(&format!("http://{}/echo", gate.addr.unwrap())), HttpVersionPolicy::H2c);
    let o = across_a_lock(&e, &c, &gate).await;
    assert_eq!(status(&o), Some(200));
    assert_eq!(http_version(&o), Some("HTTP/2"));
    assert_eq!(e.http.pool.stats().connections, 0, "the HTTP/2 connection in use at the lock was pooled again");

    // After unlock, the HTTP/2 connection is kept again.
    let o = run(&e, &c).await;
    assert_eq!(status(&o), Some(200));
    assert_eq!(http_version(&o), Some("HTTP/2"));
    assert_eq!(e.http.pool.stats().connections, 1);
}

/// QUIC cannot pass the TCP gate, so the execution is held on its first hop
/// (plain HTTP over TCP, after HTTP/3 declined the `http://` URL) and its
/// redirect leads to the HTTP/3 fixture after the lock: the QUIC connection
/// it then opens, and the TLS material it prepares, are its own only.
#[tokio::test]
async fn an_http3_connection_of_an_execution_that_spans_a_lock_is_not_pooled() {
    init();
    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let gate = gate::tcp(api.addr, 0).await.unwrap();
    let e = Arc::new(Engine::new());
    let to: String = url::form_urlencoded::byte_serialize(h3.url("/echo").as_bytes()).collect();
    let held = format!("http://{}/redirect?to={to}", gate.addr.unwrap());
    let o = across_a_lock(&e, &lab_trust(with_version(get(&held), HttpVersionPolicy::Http3WithFallback)), &gate).await;
    let failures: Vec<_> = o.record.attempts.iter().map(|a| a.failure.as_ref().map(|f| f.kind)).collect();
    assert_eq!(status(&o), Some(200), "{failures:?}");
    assert_eq!(http_version(&o), Some("HTTP/3"));
    assert_eq!(h3.connections(), 1);
    assert_eq!(e.h3.pool_stats().connections, 0, "the QUIC connection opened after the lock was pooled");
    assert_eq!(e.http.pool.stats().connections, 0, "the connection in use at the lock was pooled again");
    assert_eq!(e.prepared_tls_len(), 0, "TLS material prepared after the lock was cached");

    // After unlock, the QUIC connection and the TLS material are kept again.
    let c = lab_trust(with_version(get(&h3.url("/echo")), HttpVersionPolicy::Http3Only));
    let o = run(&e, &c).await;
    assert_eq!(status(&o), Some(200));
    assert_eq!(http_version(&o), Some("HTTP/3"));
    assert_eq!(e.h3.pool_stats().connections, 1);
    assert_eq!(e.prepared_tls_len(), 1);
}
