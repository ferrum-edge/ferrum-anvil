//! The idle connection pool against real loopback sockets: a global idle
//! cap closing the longest-idle connection first, idle expiry that does not
//! wait for the same destination to be used again (also after the pool
//! emptied once), a full key closing its longest-idle connection, no empty
//! keys left behind, HTTP/2 connections kept while they carry requests, and
//! the connection kept for the retry after `425 Too Early` expiring.

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
use tokio::sync::Notify;
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

fn conn_id(o: &AttemptOutput) -> u64 {
    o.observation.connection.as_ref().unwrap().id
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
/// the ones the client closed. `/too-early` is answered with
/// `425 Too Early`; `/hold` signals `held` and is answered once `release` is
/// signaled; any other path at once with 200.
struct Origin {
    url: String,
    accepted: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    held: Arc<Notify>,
    release: Arc<Notify>,
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
    origin_with(close_on, false).await
}

/// Start an origin that closes the socket after answering `425` without
/// advertising `connection: close`.
async fn origin_closes_after_425() -> Origin {
    origin_with(None, true).await
}

async fn origin_with(close_on: Option<usize>, close_after_425: bool) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let (held, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let (a, c, h, r) = (accepted.clone(), closed.clone(), held.clone(), release.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            a.fetch_add(1, Ordering::SeqCst);
            let (c, h, r) = (c.clone(), h.clone(), r.clone());
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
                        let head: Vec<u8> = buf.drain(..end + 4).collect();
                        served += 1;
                        if head.starts_with(b"GET /hold ") {
                            h.notify_one();
                            r.notified().await;
                        }
                        let status = if head.starts_with(b"GET /too-early ") { "425 Too Early" } else { "200 OK" };
                        let close = close_on == Some(served);
                        let connection = if close { "connection: close\r\n" } else { "" };
                        let resp = format!("HTTP/1.1 {status}\r\ncontent-length: 2\r\n{connection}\r\nok");
                        if stream.write_all(resp.as_bytes()).await.is_err() || close || (close_after_425 && status == "425 Too Early") {
                            break 'conn;
                        }
                    }
                }
                drop(stream);
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Origin { url, accepted, closed, held, release }
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
    let mut slow = plan(&fx.url("/delay-headers/5000"));
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

#[tokio::test]
async fn idle_connections_still_expire_after_the_pool_emptied_once() {
    init();
    let t = HttpTransport::with_pool_limits(PoolLimits { idle_ttl: Duration::from_millis(600), ..PoolLimits::default() });
    let first = origin(None).await;
    run(&t, &plan(&first.url)).await;
    assert!(eventually(Duration::from_secs(10), || first.closed() == 1).await, "the first idle socket was left open");
    assert_eq!(t.pool.stats(), PoolStats::default());

    // The sweep stopped with the pool empty; the next pooled connection
    // starts it again, so this one is closed after the TTL as well.
    let second = origin(None).await;
    run(&t, &plan(&second.url)).await;
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 });
    assert!(eventually(Duration::from_secs(10), || second.closed() == 1).await, "the second idle socket was left open");
    assert_eq!(t.pool.stats(), PoolStats::default());
}

#[tokio::test]
async fn a_full_key_closes_its_longest_idle_connection_not_the_returned_one() {
    init();
    let t = HttpTransport::with_pool_limits(PoolLimits { max_idle_per_key: 1, ..PoolLimits::default() });
    let o = origin(None).await;
    let hold = plan(&format!("{}hold", o.url));

    // The held request keeps its connection busy, so the other opens a
    // second one and returns it to the pool first.
    let (held, first_back) = tokio::join!(run(&t, &hold), async {
        o.held.notified().await;
        let fast = run(&t, &plan(&o.url)).await;
        o.release.notify_one();
        fast
    });
    assert_ne!(conn_id(&held), conn_id(&first_back));
    assert_eq!(o.accepted(), 2);

    // The key holds one: the connection idle longest was closed and the one
    // returned last was kept.
    assert!(eventually(Duration::from_secs(5), || o.closed() == 1).await, "no connection was closed for the per-key cap");
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 });
    let again = run(&t, &plan(&o.url)).await;
    assert!(reused(&again));
    assert_eq!(conn_id(&again), conn_id(&held), "the freshest connection is the one kept");
    assert_eq!(o.accepted(), 2);
}

/// Send `p` (early data asked for) to `/too-early`: the connection that
/// answered is kept for the retry, not pooled for reuse.
async fn answer_425(t: &HttpTransport, p: &HttpPlan) -> AttemptOutput {
    let out = t.execute(p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await.pop().unwrap();
    assert!(out.observation.failure.is_none(), "{:?}", out.observation.failure);
    assert_eq!(out.observation.response_status, Some(425));
    assert_eq!(t.pool.stats(), PoolStats::default(), "connection reuse is off: nothing is pooled for reuse");
    out
}

#[tokio::test]
async fn the_connection_kept_for_the_retry_after_425_expires() {
    init();
    let ttl = Duration::from_secs(30);
    let t = HttpTransport::with_pool_limits(PoolLimits { idle_ttl: ttl, ..PoolLimits::default() });
    let o = origin(None).await;
    let mut p = plan(&format!("{}too-early", o.url));
    p.keepalive = false;
    p.early_data = EarlyDataIntent::Send;

    // A sweep 9 s later keeps it: the retry goes out on the kept connection.
    let first = answer_425(&t, &p).await;
    t.sweep_pool_at(Instant::now() + Duration::from_secs(9));
    let mut retry = p.clone();
    retry.early_data = EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly);
    let again = t.execute(&retry, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await.pop().unwrap();
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert!(reused(&again), "the retry opened a new connection");
    assert_eq!(conn_id(&again), conn_id(&first));
    assert_eq!(o.accepted(), 1);
    // Connection reuse is off: it is closed once the retry is done.
    assert!(eventually(Duration::from_secs(5), || o.closed() == 1).await, "the connection was left open after the retry");

    // No retry is sent this time: a sweep 11 s later expires it even though
    // the normal idle TTL is 30 s. A subsequent retry must use a new socket.
    let second = answer_425(&t, &p).await;
    t.sweep_pool_at(Instant::now() + Duration::from_secs(11));
    retry.early_data = EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly);
    let after_expiry = t.execute(&retry, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await.pop().unwrap();
    assert!(after_expiry.observation.failure.is_none(), "{:?}", after_expiry.observation.failure);
    assert_eq!(after_expiry.observation.response_status, Some(425));
    assert!(!reused(&after_expiry), "the retry reused a connection kept beyond 10 seconds");
    assert_ne!(conn_id(&after_expiry), conn_id(&second));
    assert_eq!(o.accepted(), 3);
}

#[tokio::test]
async fn a_closed_connection_kept_for_a_425_retry_is_replaced() {
    init();
    let t = HttpTransport::new();
    let o = origin_closes_after_425().await;
    let mut p = plan(&format!("{}too-early", o.url));
    p.keepalive = false;
    p.early_data = EarlyDataIntent::Send;

    let first = answer_425(&t, &p).await;
    assert!(eventually(Duration::from_secs(5), || o.closed() == 1).await, "the origin did not close the first socket");

    let mut retry = p.clone();
    retry.early_data = EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly);
    let again = t.execute(&retry, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await.pop().unwrap();
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert_eq!(again.observation.response_status, Some(425));
    assert!(!reused(&again), "the retry reused the connection closed by the origin");
    assert_ne!(conn_id(&again), conn_id(&first));
    assert_eq!(o.accepted(), 2);
}
