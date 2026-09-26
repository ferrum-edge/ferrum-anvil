//! The HTTP/3 (QUIC) connection pool against real local QUIC servers: a
//! global idle cap closing the longest-idle connection first, idle expiry
//! that does not wait for the same destination to be used again, and
//! connections kept while they carry requests.

use anvil_domain::execution::*;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::dns::DnsConfig;
use anvil_transport::h3::{H3Transport, PoolLimits, PoolStats};
use anvil_transport::http::{AttemptOutput, EarlyDataIntent, HttpPlan};
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{self, TlsSettings};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// `H3_NO_ERROR` (RFC 9114 §8.1): the code Anvil closes its QUIC connections with.
const H3_NO_ERROR: u64 = 0x100;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn trust_lab() -> TlsSettings {
    TlsSettings { verify: true, use_system_roots: false, extra_roots_pem: vec![pki().ca.cert.clone()], ..Default::default() }
}

fn plan(addr: SocketAddr, path: &str) -> HttpPlan {
    let host = addr.ip().to_string();
    HttpPlan {
        proxy_header: None,
        proxy_header_withheld: None,
        method: http::Method::GET,
        https: true,
        authority: addr.to_string(),
        host,
        port: addr.port(),
        request_target: path.to_string(),
        headers: vec![],
        body: Bytes::new(),
        version: HttpVersionPolicy::Http3Only,
        timeouts: Timeouts {
            dns_ms: Some(2000),
            connect_ms: Some(5000),
            tls_handshake_ms: Some(5000),
            request_write_ms: Some(5000),
            response_headers_ms: Some(10_000),
            body_idle_ms: Some(5000),
            total_ms: Some(20_000),
        },
        limits: Limits::default(),
        keepalive: true,
        dns: DnsConfig::default(),
        proxy: None,
        tls: Some(Arc::new(tls::prepare(&trust_lab()).expect("tls profile"))),
        isolation: "pool-test".into(),
        display_url: format!("https://{addr}{path}"),
        early_data: EarlyDataIntent::Off,
    }
}

async fn run(t: &H3Transport, p: &HttpPlan) -> AttemptOutput {
    let o = t.execute(p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert!(o.observation.failure.is_none(), "{:?}", o.observation.failure);
    assert_eq!(o.observation.response_status, Some(200));
    o
}

fn reused(o: &AttemptOutput) -> bool {
    o.observation.connection.as_ref().unwrap().reused
}

/// Poll `cond` until it holds or `within` elapses.
async fn eventually(within: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

/// An HTTP/3 origin that counts the QUIC connections it accepted and the
/// ones the client closed with `H3_NO_ERROR`. `/delay/{ms}` answers after
/// `ms` milliseconds, any other path at once.
struct Origin {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
}

impl Origin {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn closed(&self) -> usize {
        self.closed.load(Ordering::SeqCst)
    }
}

async fn origin() -> Origin {
    origin_with(None).await
}

/// [`origin`] advertising `SETTINGS_MAX_FIELD_SECTION_SIZE` when given.
async fn origin_with(max_field_section_size: Option<u64>) -> Origin {
    let mut opts = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    opts.alpn = vec!["h3".into()];
    opts.tls13_only = true;
    let server_tls = quinn::crypto::rustls::QuicServerConfig::try_from(anvil_fixtures::tlsserver::server_config(&opts).unwrap()).unwrap();
    let server = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(server_tls)), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let (a, c) = (accepted.clone(), closed.clone());
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let (a, c) = (a.clone(), c.clone());
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                a.fetch_add(1, Ordering::SeqCst);
                let quic = conn.clone();
                let mut builder = h3::server::builder();
                if let Some(max) = max_field_section_size {
                    builder.max_field_section_size(max);
                }
                let Ok(mut h3c) = builder.build::<_, Bytes>(h3_quinn::Connection::new(conn)).await else { return };
                while let Ok(Some(resolver)) = h3c.accept().await {
                    tokio::spawn(async move {
                        let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                        if let Some(ms) = req.uri().path().strip_prefix("/delay/").and_then(|ms| ms.parse().ok()) {
                            tokio::time::sleep(Duration::from_millis(ms)).await;
                        }
                        let resp = http::Response::builder().status(200).body(()).unwrap();
                        if stream.send_response(resp).await.is_ok() {
                            let _ = stream.send_data(Bytes::from_static(b"ok")).await;
                            let _ = stream.finish().await;
                        }
                    });
                }
                // Read how the connection ended while `h3c` is still alive:
                // dropping it closes the connection locally, and quinn then
                // reports `LocallyClosed` instead of the client's close.
                if let quinn::ConnectionError::ApplicationClosed(close) = quic.closed().await
                    && u64::from(close.error_code) == H3_NO_ERROR
                {
                    c.fetch_add(1, Ordering::SeqCst);
                }
                drop(h3c);
            });
        }
    });
    Origin { addr, accepted, closed }
}

#[tokio::test]
async fn idle_quic_connections_expire_without_their_destination_being_used_again() {
    init();
    let t = H3Transport::with_pool_limits(PoolLimits { idle_ttl: Duration::from_secs(3), ..PoolLimits::default() });
    let mut origins = Vec::new();
    for _ in 0..4 {
        origins.push(origin().await);
    }
    for o in &origins {
        run(&t, &plan(o.addr, "/")).await;
    }
    assert_eq!(t.pool_stats(), PoolStats { connections: 4, idle: 4 });

    // Nothing is sent again: the sweep alone closes every idle connection.
    let all_closed = eventually(Duration::from_secs(15), || origins.iter().all(|o| o.closed() == 1)).await;
    assert!(all_closed, "idle connections still open after the TTL: {:?}", origins.iter().map(Origin::closed).collect::<Vec<_>>());
    assert_eq!(t.pool_stats(), PoolStats::default(), "expired connections and their keys are removed");
}

#[tokio::test]
async fn global_idle_cap_closes_the_longest_idle_quic_connection_first() {
    init();
    let t = H3Transport::with_pool_limits(PoolLimits { max_idle_total: 2, idle_ttl: Duration::from_secs(60) });
    let mut origins = Vec::new();
    for _ in 0..4 {
        origins.push(origin().await);
    }
    for o in &origins {
        run(&t, &plan(o.addr, "/")).await;
    }
    assert_eq!(t.pool_stats(), PoolStats { connections: 2, idle: 2 });

    // The two oldest were closed; the two newest stay open and pooled.
    let evicted = eventually(Duration::from_secs(5), || origins[0].closed() == 1 && origins[1].closed() == 1).await;
    assert!(evicted, "the longest-idle connections were not closed");
    assert_eq!((origins[2].closed(), origins[3].closed()), (0, 0));

    let again = run(&t, &plan(origins[3].addr, "/")).await;
    assert!(reused(&again), "a connection kept under the cap is reused");
    assert_eq!(origins[3].accepted(), 1);

    let reopened = run(&t, &plan(origins[0].addr, "/")).await;
    assert!(!reused(&reopened), "an evicted destination gets a new connection");
    assert_eq!(origins[0].accepted(), 2);

    // Origin 2 is now the longest idle and makes room for origin 0.
    assert!(eventually(Duration::from_secs(5), || origins[2].closed() == 1).await);
    assert_eq!((origins[0].closed(), origins[3].closed()), (1, 0));
    assert_eq!(t.pool_stats(), PoolStats { connections: 2, idle: 2 });
}

#[tokio::test]
async fn a_quic_connection_carrying_a_request_is_not_expired() {
    init();
    let o = origin().await;
    let t = H3Transport::with_pool_limits(PoolLimits { idle_ttl: Duration::from_secs(1), ..PoolLimits::default() });
    run(&t, &plan(o.addr, "/")).await;
    assert_eq!(t.pool_stats(), PoolStats { connections: 1, idle: 1 });

    // A request outlasting the TTL shares the pooled connection; the sweep
    // runs meanwhile and must leave the busy connection alone.
    let slow = plan(o.addr, "/delay/3000");
    let (done, during) = tokio::join!(run(&t, &slow), async {
        tokio::time::sleep(Duration::from_millis(2000)).await;
        t.pool_stats()
    });
    assert!(reused(&done));
    assert_eq!(&done.body[..], b"ok");
    assert_eq!(during, PoolStats { connections: 1, idle: 0 });
    assert_eq!((o.accepted(), o.closed()), (1, 0));

    // Idle once the request ended, then expired like any other.
    assert!(eventually(Duration::from_secs(10), || o.closed() == 1).await, "the connection was not closed after the TTL");
    assert_eq!(t.pool_stats(), PoolStats::default());
}

#[tokio::test]
async fn clearing_an_isolation_closes_only_its_pooled_quic_connections() {
    init();
    let o = origin().await;
    let t = H3Transport::new();
    let mut other = plan(o.addr, "/");
    other.isolation = "other".into();
    run(&t, &plan(o.addr, "/")).await;
    run(&t, &other).await;
    assert_eq!(t.pool_stats(), PoolStats { connections: 2, idle: 2 });

    t.clear_isolation("pool-test");
    assert!(eventually(Duration::from_secs(5), || o.closed() == 1).await, "the cleared connection was not closed");
    assert_eq!(t.pool_stats(), PoolStats { connections: 1, idle: 1 });
    assert!(reused(&run(&t, &other).await), "the other isolation keeps its connection");
    assert_eq!((o.accepted(), o.closed()), (2, 1));
}

#[tokio::test]
async fn a_request_that_cannot_be_written_evicts_and_closes_its_quic_connection() {
    init();
    let o = origin_with(Some(1024)).await;
    let t = H3Transport::new();
    run(&t, &plan(o.addr, "/")).await;
    assert_eq!(t.pool_stats(), PoolStats { connections: 1, idle: 1 });
    // The server's SETTINGS arrived with the first response; let the
    // connection's HTTP/3 driver take them in.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Headers over the server's SETTINGS_MAX_FIELD_SECTION_SIZE are refused
    // before a stream opens: the write fails on the pooled connection.
    let mut big = plan(o.addr, "/");
    big.headers.push((http::HeaderName::from_static("x-big"), http::HeaderValue::from_str(&"a".repeat(4096)).unwrap()));
    let failed = t.execute(&big, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(failed.observation.failure.as_ref().map(|f| f.kind), Some(FailureKind::RequestWriteFailed));
    assert!(reused(&failed));
    assert_eq!(t.pool_stats(), PoolStats::default(), "the connection is evicted");
    assert!(eventually(Duration::from_secs(5), || o.closed() == 1).await, "the evicted connection was not closed");

    let again = run(&t, &plan(o.addr, "/")).await;
    assert!(!reused(&again), "the next request opens a new connection");
    assert_eq!((o.accepted(), o.closed()), (2, 1));
}
