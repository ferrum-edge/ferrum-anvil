//! The idle connection pool against real loopback sockets: a global idle
//! cap closing the longest-idle connection first, idle expiry that does not
//! wait for the same destination to be used again, no empty keys left
//! behind, and HTTP/2 connections kept while they carry requests.

use anvil_domain::execution::*;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::http as fxhttp;
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::{AttemptOutput, EarlyDataIntent, HttpPlan, HttpTransport, PoolLimits, PoolStats};
use anvil_transport::recorder::EventCtx;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn plan(url: &str) -> HttpPlan {
    let u = url::Url::parse(url).unwrap();
    let host = u.host_str().unwrap().to_string();
    let port = u.port_or_known_default().unwrap();
    HttpPlan {
        proxy_header: None,
        proxy_header_withheld: None,
        method: http::Method::GET,
        https: false,
        authority: format!("{host}:{port}"),
        host,
        port,
        request_target: u.path().to_string(),
        headers: vec![],
        body: Bytes::new(),
        version: HttpVersionPolicy::Http1Only,
        timeouts: Timeouts {
            dns_ms: Some(2000),
            connect_ms: Some(5000),
            tls_handshake_ms: Some(2000),
            request_write_ms: Some(5000),
            response_headers_ms: Some(10_000),
            body_idle_ms: Some(5000),
            total_ms: Some(20_000),
        },
        limits: Limits::default(),
        keepalive: true,
        dns: DnsConfig::default(),
        proxy: None,
        tls: None,
        isolation: "pool-test".into(),
        display_url: url.into(),
        early_data: EarlyDataIntent::Off,
    }
}

async fn run(t: &HttpTransport, p: &HttpPlan) -> AttemptOutput {
    let mut outs = t.execute(p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    let o = outs.pop().unwrap();
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

/// A keep-alive HTTP/1.1 origin that counts the connections it accepted and
/// the ones the client closed.
struct Origin {
    url: String,
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

/// Start an origin. With `close_on` = n, the n-th request on a connection is
/// answered with `connection: close` and the connection is then closed.
async fn origin(close_on: Option<usize>) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let (a, c) = (accepted.clone(), closed.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            a.fetch_add(1, Ordering::SeqCst);
            let c = c.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut served = 0;
                'conn: loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    // Requests carry no body: each ends with its header block.
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        served += 1;
                        let close = close_on == Some(served);
                        let resp: &[u8] = if close {
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
                        } else {
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"
                        };
                        if stream.write_all(resp).await.is_err() || close {
                            break 'conn;
                        }
                    }
                }
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Origin { url, accepted, closed }
}

#[tokio::test]
async fn idle_connections_expire_without_their_destination_being_used_again() {
    init();
    let t = HttpTransport::with_pool_limits(PoolLimits { idle_ttl: Duration::from_millis(1500), ..PoolLimits::default() });
    let mut origins = Vec::new();
    for _ in 0..4 {
        origins.push(origin(None).await);
    }
    for o in &origins {
        run(&t, &plan(&o.url)).await;
    }
    assert_eq!(t.pool.stats(), PoolStats { keys: 4, connections: 4, idle: 4 });

    // Nothing is sent again: the sweep alone closes every idle socket.
    let all_closed = eventually(Duration::from_secs(10), || origins.iter().all(|o| o.closed() == 1)).await;
    assert!(all_closed, "idle sockets still open after the TTL: {:?}", origins.iter().map(Origin::closed).collect::<Vec<_>>());
    assert_eq!(t.pool.stats(), PoolStats::default(), "expired entries and their keys are removed");
}

#[tokio::test]
async fn global_idle_cap_closes_the_longest_idle_connection_first() {
    init();
    let limits = PoolLimits { max_idle_per_key: 8, max_idle_total: 2, idle_ttl: Duration::from_secs(60) };
    let t = HttpTransport::with_pool_limits(limits);
    let mut origins = Vec::new();
    for _ in 0..4 {
        origins.push(origin(None).await);
    }
    for o in &origins {
        run(&t, &plan(&o.url)).await;
    }
    assert_eq!(t.pool.stats(), PoolStats { keys: 2, connections: 2, idle: 2 });

    // The two oldest were closed; the two newest stay open and pooled.
    let evicted = eventually(Duration::from_secs(5), || origins[0].closed() == 1 && origins[1].closed() == 1).await;
    assert!(evicted, "the longest-idle connections were not closed");
    assert_eq!((origins[2].closed(), origins[3].closed()), (0, 0));

    let again = run(&t, &plan(&origins[3].url)).await;
    assert!(reused(&again), "a connection kept under the cap is reused");
    assert_eq!(origins[3].accepted(), 1);

    let reopened = run(&t, &plan(&origins[0].url)).await;
    assert!(!reused(&reopened), "an evicted destination gets a new connection");
    assert_eq!(origins[0].accepted(), 2);

    // Origin 2 is now the longest idle and makes room for origin 0.
    assert!(eventually(Duration::from_secs(5), || origins[2].closed() == 1).await);
    assert_eq!(origins[3].closed(), 0);
    assert_eq!(t.pool.stats(), PoolStats { keys: 2, connections: 2, idle: 2 });
}

#[tokio::test]
async fn a_key_whose_last_connection_left_the_pool_is_removed() {
    init();
    let t = HttpTransport::new();
    let o = origin(Some(2)).await;
    let p = plan(&o.url);
    run(&t, &p).await;
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 });

    // The reuse takes the only connection out; the server then closes it.
    let second = run(&t, &p).await;
    assert!(reused(&second));
    assert_eq!(t.pool.stats(), PoolStats::default());
}

#[tokio::test]
async fn an_http2_connection_carrying_a_request_is_not_expired() {
    init();
    let fx = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let t = HttpTransport::with_pool_limits(PoolLimits { idle_ttl: Duration::from_secs(1), ..PoolLimits::default() });
    let mut p = plan(&fx.url("/status/200"));
    p.version = HttpVersionPolicy::H2c;
    run(&t, &p).await;
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 });

    // A request outlasting the TTL shares the pooled connection; the sweep
    // runs meanwhile and must leave the busy connection alone.
    let mut slow = plan(&fx.url("/delay-headers/3000"));
    slow.version = HttpVersionPolicy::H2c;
    let (done, during) = tokio::join!(run(&t, &slow), async {
        tokio::time::sleep(Duration::from_millis(2000)).await;
        t.pool.stats()
    });
    assert!(reused(&done));
    assert_eq!(&done.body[..], b"delayed\n");
    assert_eq!(during, PoolStats { keys: 1, connections: 1, idle: 0 });

    // Idle once the request ended, then expired like any other.
    assert!(eventually(Duration::from_secs(10), || t.pool.stats() == PoolStats::default()).await);
}
