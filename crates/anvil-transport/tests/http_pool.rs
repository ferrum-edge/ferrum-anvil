//! The idle connection pool against real loopback sockets: a global idle
//! cap closing the longest-idle connection first, idle expiry that does not
//! wait for the same destination to be used again (also after the pool
//! emptied once), a full key closing its longest-idle connection, no empty
//! keys left behind, HTTP/2 connections kept while they carry requests, the
//! connection kept for the retry after `425 Too Early` expiring, and a reused
//! connection the peer closed under a request: sent once more on a new one
//! only when that is safe.

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
use tokio::net::{TcpListener, TcpStream};
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
        fence: None,
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

    // The client may or may not have seen the close yet. Either the dead
    // connection is dropped when the retry takes it, or the retry fails on
    // it before any response. It is then sent once more on a new connection:
    // by the transport when none of it was written, else by the caller, as
    // the engine does.
    let mut retry = p.clone();
    retry.early_data = EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly);
    let e = t.execute_attempt(&retry, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    let mut outs = e.outputs;
    if let Some(after) = e.resend_on_new_connection {
        assert_eq!(outs.len(), 1, "the transport sent again a request that may have been written");
        outs.extend(resend(&t, &retry, after).await);
    }
    let again = outs.pop().unwrap();
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert_eq!(again.observation.response_status, Some(425));
    assert!(!reused(&again), "the retry ended on the connection closed by the origin");
    assert_ne!(conn_id(&again), conn_id(&first));
    assert_eq!(o.accepted(), 2);
    if let Some(on_closed) = outs.pop() {
        assert!(outs.is_empty(), "sent again at most once");
        assert!(reused(&on_closed));
        assert_eq!(conn_id(&on_closed), conn_id(&first));
        let f = on_closed.observation.failure.as_ref().expect("the closed connection failed the retry");
        assert!(closed_under_request(f.kind), "{f:?}");
        assert_eq!(again.observation.reason, AttemptReason::ReusedConnectionClosed { after: f.kind });
    }
}

/// Send `p` once more as the engine does after a reused connection was
/// closed under it with `after`: a new attempt, which takes a new connection.
async fn resend(t: &HttpTransport, p: &HttpPlan, after: FailureKind) -> Vec<AttemptOutput> {
    let reason = AttemptReason::ReusedConnectionClosed { after };
    t.execute(p, 1, reason, &EventCtx::none(), &CancellationToken::new()).await
}

/// A connection closed or reset under a request before its response head.
fn closed_under_request(kind: FailureKind) -> bool {
    matches!(kind, FailureKind::ClosedBeforeResponse | FailureKind::ResetBeforeResponse | FailureKind::RequestWriteFailed)
}

/// How a scripted origin answers one request.
#[derive(Clone, Copy)]
enum Reply {
    Ok,
    TooEarly,
    /// Read the whole request, then close the connection without answering:
    /// the origin's close crosses the request on a reused connection.
    Close,
}

/// A keep-alive HTTP/1.1 origin whose first connection answers its requests
/// as scripted; any other request is answered with 200. Request bodies are
/// read by their `content-length`.
struct Scripted {
    url: String,
    accepted: Arc<AtomicUsize>,
    /// Request lines received over all connections, in order.
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Scripted {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

async fn scripted_origin(first: Vec<Reply>) -> Scripted {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (a, r) = (accepted.clone(), requests.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let script = if a.fetch_add(1, Ordering::SeqCst) == 0 { first.clone() } else { Vec::new() };
            let r = r.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                for n in 0.. {
                    let Some(line) = read_request(&mut stream, &mut buf).await else { return };
                    r.lock().unwrap().push(line);
                    let status = match script.get(n).copied().unwrap_or(Reply::Ok) {
                        Reply::Ok => "200 OK",
                        Reply::TooEarly => "425 Too Early",
                        Reply::Close => return,
                    };
                    let resp = format!("HTTP/1.1 {status}\r\ncontent-length: 2\r\n\r\nok");
                    if stream.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Scripted { url, accepted, requests }
}

/// Read one request (its head and `content-length` body) from `stream`:
/// its request line, or `None` once the client closed the connection.
async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let len = head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                buf.drain(..end + 4 + len);
                return head.lines().next().map(str::to_string);
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

#[tokio::test]
async fn an_idempotent_request_on_a_pooled_connection_closed_under_it_is_left_to_the_caller_to_resend() {
    init();
    let t = HttpTransport::new();
    let o = scripted_origin(vec![Reply::Ok, Reply::Close]).await;
    let p = plan(&o.url);
    let first = run(&t, &p).await;
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 });

    // The pooled connection looks alive when it is checked out; the origin
    // reads the request on it and closes the connection without answering.
    // It may have received the request with its per-send auth (a nonce, a
    // proof), so the transport does not send the same request again.
    let e = t.execute_attempt(&p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the transport sent the written GET again");
    let on_closed = &e.outputs[0];
    assert!(reused(on_closed));
    assert_eq!(conn_id(on_closed), conn_id(&first));
    assert!(on_closed.response.is_none());
    assert_eq!(on_closed.observation.dispatch, DispatchState::MayHaveBeenSent);
    let f = on_closed.observation.failure.as_ref().expect("the closed connection failed the request");
    assert!(closed_under_request(f.kind), "{f:?}");
    assert!(f.message.contains("was found closed before any response; the GET request may have been received"), "{}", f.message);
    assert_eq!(e.resend_on_new_connection, Some(f.kind), "the caller may send it again, signed again");
    assert_eq!(o.accepted(), 1);

    // The caller's resend goes out on a new connection.
    let outs = resend(&t, &p, f.kind).await;
    assert_eq!(outs.len(), 1);
    let again = &outs[0];
    assert_eq!(again.observation.index, 1);
    assert_eq!(again.observation.reason, AttemptReason::ReusedConnectionClosed { after: f.kind });
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert_eq!(again.observation.response_status, Some(200));
    assert!(!reused(again), "sent again on a new connection");
    assert_ne!(conn_id(again), conn_id(&first));
    assert_eq!(o.accepted(), 2);
    assert_eq!(o.requests(), ["GET / HTTP/1.1"; 3]);
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 }, "the new connection is pooled");
}

#[tokio::test]
async fn a_written_non_idempotent_request_on_a_pooled_connection_closed_under_it_is_not_sent_again() {
    init();
    let t = HttpTransport::new();
    let o = scripted_origin(vec![Reply::Ok, Reply::Close]).await;
    let first = run(&t, &plan(&o.url)).await;
    let mut post = plan(&format!("{}orders", o.url));
    post.method = http::Method::POST;
    post.body = Bytes::from_static(b"{\"order\":1}");

    // The origin read the whole POST before closing: it may have acted on
    // it, so the failure is reported and nobody is told to send it again.
    let e = t.execute_attempt(&post, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the POST was sent again");
    assert_eq!(e.resend_on_new_connection, None, "the caller was told it may send the POST again");
    let a = &e.outputs[0];
    assert!(reused(a));
    assert_eq!(conn_id(a), conn_id(&first));
    assert!(a.response.is_none());
    assert_eq!(a.observation.dispatch, DispatchState::MayHaveBeenSent);
    let f = a.observation.failure.as_ref().expect("the closed connection failed the request");
    assert!(closed_under_request(f.kind), "{f:?}");
    assert!(f.message.contains("not sent again: the POST request was written and is not idempotent"), "{}", f.message);
    assert_eq!(o.accepted(), 1, "no new connection was opened");
    assert_eq!(o.requests(), ["GET / HTTP/1.1", "POST /orders HTTP/1.1"]);
}

#[tokio::test]
async fn the_retry_after_425_on_a_connection_closed_under_it_is_left_to_the_caller_to_resend() {
    init();
    let t = HttpTransport::new();
    // The kept connection is still open when the retry takes it; the origin
    // reads the retry and closes it without answering.
    let o = scripted_origin(vec![Reply::TooEarly, Reply::Close]).await;
    let mut p = plan(&format!("{}submit", o.url));
    p.keepalive = false;
    p.early_data = EarlyDataIntent::Send;
    let first = answer_425(&t, &p).await;

    let mut retry = p.clone();
    retry.early_data = EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly);
    let e = t.execute_attempt(&retry, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the transport sent the written retry again");
    let on_closed = &e.outputs[0];
    assert!(reused(on_closed));
    assert_eq!(conn_id(on_closed), conn_id(&first));
    assert_eq!(on_closed.observation.dispatch, DispatchState::MayHaveBeenSent);
    let f = on_closed.observation.failure.as_ref().expect("the closed connection failed the retry");
    assert!(closed_under_request(f.kind), "{f:?}");
    assert_eq!(e.resend_on_new_connection, Some(f.kind));

    let outs = resend(&t, &retry, f.kind).await;
    assert_eq!(outs.len(), 1);
    let again = &outs[0];
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert_eq!(again.observation.response_status, Some(200));
    assert!(!reused(again));
    assert_eq!(o.accepted(), 2);
    assert_eq!(o.requests(), ["GET /submit HTTP/1.1"; 3]);
}

#[tokio::test]
async fn a_written_post_retried_after_425_on_a_connection_closed_under_it_is_not_sent_again() {
    init();
    let t = HttpTransport::new();
    let o = scripted_origin(vec![Reply::TooEarly, Reply::Close]).await;
    let mut p = plan(&format!("{}submit", o.url));
    p.method = http::Method::POST;
    p.body = Bytes::from_static(b"payload");
    p.keepalive = false;
    p.early_data = EarlyDataIntent::Send;
    let first = answer_425(&t, &p).await;

    // The 425 answered the earlier request, not the retry: a written POST
    // is not sent again because it is the retry after 425.
    let mut retry = p.clone();
    retry.early_data = EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly);
    let e = t.execute_attempt(&retry, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the POST was sent again");
    assert_eq!(e.resend_on_new_connection, None, "the caller was told it may send the POST again");
    let a = &e.outputs[0];
    assert!(reused(a));
    assert_eq!(conn_id(a), conn_id(&first));
    assert_eq!(a.observation.dispatch, DispatchState::MayHaveBeenSent);
    let f = a.observation.failure.as_ref().expect("the closed connection failed the retry");
    assert!(closed_under_request(f.kind), "{f:?}");
    assert!(f.message.contains("not sent again: the POST request was written and is not idempotent"), "{}", f.message);
    assert_eq!(o.accepted(), 1, "no new connection was opened");
    assert_eq!(o.requests(), ["POST /submit HTTP/1.1"; 2]);
}

#[tokio::test]
async fn a_resend_after_a_closed_connection_takes_neither_the_kept_nor_a_pooled_connection() {
    init();
    let t = HttpTransport::new();
    let o = scripted_origin(vec![Reply::TooEarly]).await;

    // A connection is kept for the retry after 425: the resend of that retry
    // does not take it.
    let mut p = plan(&format!("{}submit", o.url));
    p.keepalive = false;
    p.early_data = EarlyDataIntent::Send;
    let first = answer_425(&t, &p).await;
    let mut retry = p.clone();
    retry.early_data = EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly);
    let outs = resend(&t, &retry, FailureKind::ClosedBeforeResponse).await;
    assert_eq!(outs.len(), 1);
    let a = &outs[0];
    assert!(a.observation.failure.is_none(), "{:?}", a.observation.failure);
    assert_eq!(a.observation.response_status, Some(200));
    assert!(!reused(a), "the resend took the connection kept after 425");
    assert_ne!(conn_id(a), conn_id(&first));
    assert_eq!(o.accepted(), 2);

    // An idle connection is pooled for reuse: the resend does not take it.
    let q = plan(&o.url);
    let pooled = run(&t, &q).await;
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 });
    let outs = resend(&t, &q, FailureKind::ClosedBeforeResponse).await;
    assert_eq!(outs.len(), 1);
    let b = &outs[0];
    assert!(b.observation.failure.is_none(), "{:?}", b.observation.failure);
    assert!(!reused(b), "the resend took a pooled connection");
    assert_ne!(conn_id(b), conn_id(&pooled));
    assert_eq!(o.accepted(), 4);
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 2, idle: 2 }, "both are pooled");
}
