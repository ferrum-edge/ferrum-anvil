//! A request that fails before any response on a reused pooled QUIC
//! connection, against a real local HTTP/3 server that checks per-send auth
//! for replays (`anvil_fixtures::replay_guard`, which answers a repeated
//! `authorization` with 401). The transport never sends such a request again
//! as it is once some of it may have left: the server may have seen its
//! per-send auth. It leaves it to the caller to sign again and send once
//! more on a new connection when that is safe: whatever the method when the
//! server rejected it unprocessed (`H3_REQUEST_REJECTED`), only an idempotent
//! one when the connection closed under it. A pooled connection whose peer
//! sent `GOAWAY` is not reused. Where nothing of the request left, the
//! transport sends it again at once; that race cannot be produced on purpose
//! and is covered by the unit tests in `h3.rs`.

use anvil_domain::execution::*;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::replay_guard::{self, H3Script, ReplayFixture, Unanswered};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::dns::DnsConfig;
use anvil_transport::h3::{H3Transport, PoolStats};
use anvil_transport::http::{AttemptOutput, EarlyDataIntent, HttpPlan};
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{self, TlsSettings};
use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// `H3_REQUEST_REJECTED` (RFC 9114 §8.1).
const H3_REQUEST_REJECTED: u64 = 0x10b;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

async fn origin(script: H3Script) -> ReplayFixture {
    let tls = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    replay_guard::serve_h3(tls, script).await.unwrap()
}

/// A `method` of `url` over forced HTTP/3 with connection reuse, trusting
/// the lab CA, whose `authorization` header is `auth` (the per-send value
/// the origin checks for replays).
fn plan(url: &str, method: http::Method, auth: &str) -> HttpPlan {
    let u = url::Url::parse(url).unwrap();
    let host = u.host_str().unwrap().to_string();
    let port = u.port_or_known_default().unwrap();
    let trust = TlsSettings { verify: true, use_system_roots: false, extra_roots_pem: vec![pki().ca.cert.clone()], ..Default::default() };
    let body = if method == http::Method::GET { Bytes::new() } else { Bytes::from_static(b"{\"order\":1}") };
    HttpPlan {
        proxy_header: None,
        proxy_header_withheld: None,
        method,
        https: true,
        authority: format!("{host}:{port}"),
        host,
        port,
        request_target: u.path().to_string(),
        headers: vec![(HeaderName::from_static("authorization"), HeaderValue::from_str(auth).unwrap())],
        body,
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
        tls: Some(Arc::new(tls::prepare(&trust).expect("tls profile"))),
        isolation: "h3-resend-test".into(),
        display_url: url.into(),
        early_data: EarlyDataIntent::Off,
        fence: None,
    }
}

fn get(o: &ReplayFixture, auth: &str) -> HttpPlan {
    plan(&o.url("/echo"), http::Method::GET, auth)
}

fn post(o: &ReplayFixture, auth: &str) -> HttpPlan {
    plan(&o.url("/orders"), http::Method::POST, auth)
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

fn conn_id(o: &AttemptOutput) -> u64 {
    o.observation.connection.as_ref().unwrap().id
}

/// Send `p` once more as the engine does after a reused connection failed
/// it with `after`: a new attempt, which takes a new connection.
async fn resend(t: &H3Transport, p: &HttpPlan, after: FailureKind) -> AttemptOutput {
    let e = t.execute_attempt(p, 1, AttemptReason::ReusedConnectionClosed { after }, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1);
    assert_eq!(e.resend_on_new_connection, None);
    e.outputs.into_iter().next().unwrap()
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

#[tokio::test]
async fn an_idempotent_request_on_a_pooled_quic_connection_closed_under_it_is_left_to_the_caller_to_resend() {
    init();
    let o = origin(H3Script::SecondOnReuse(Unanswered::ConnectionClosed)).await;
    let t = H3Transport::new();
    let first = run(&t, &get(&o, "nonce-1")).await;
    assert_eq!(t.pool_stats(), PoolStats { connections: 1, idle: 1 });

    // The origin reads the GET on the pooled connection, then closes the
    // connection without answering. It may have received the request with
    // its per-send auth, so the transport does not send it again as it is.
    let p = get(&o, "nonce-2");
    let e = t.execute_attempt(&p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the transport sent the written GET again as it was");
    let on_closed = &e.outputs[0];
    assert!(reused(on_closed));
    assert_eq!(conn_id(on_closed), conn_id(&first));
    assert!(on_closed.response.is_none());
    assert_eq!(on_closed.observation.dispatch, DispatchState::MayHaveBeenSent);
    let f = on_closed.observation.failure.as_ref().expect("the closed connection failed the GET");
    assert!(f.message.contains("was found closed before any response; the GET request may have been received"), "{}", f.message);
    assert_eq!(e.resend_on_new_connection, Some(f.kind), "the caller may sign the GET again and send it once more");
    assert_eq!(o.quic_connections(), 1);

    // The caller's resend, signed again, goes out on a new connection.
    let again = resend(&t, &get(&o, "nonce-3"), f.kind).await;
    assert_eq!(again.observation.reason, AttemptReason::ReusedConnectionClosed { after: f.kind });
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert_eq!(again.observation.response_status, Some(200), "the origin saw the per-send value again: {:?}", o.received());
    assert!(!reused(&again), "sent again on the closed connection");
    assert_eq!(o.quic_connections(), 2);
    let seen = o.received();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert!(seen.iter().all(|r| r.protocol == "h3" && r.method == "GET" && !r.replayed), "{seen:?}");
}

#[tokio::test]
async fn a_written_post_on_a_pooled_quic_connection_closed_under_it_is_not_sent_again() {
    init();
    let o = origin(H3Script::SecondOnReuse(Unanswered::ConnectionClosed)).await;
    let t = H3Transport::new();
    let first = run(&t, &get(&o, "nonce-1")).await;

    // The origin read the whole POST before closing: it may have acted on
    // it, so the failure is reported and nobody is told to send it again.
    let e = t.execute_attempt(&post(&o, "nonce-2"), 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the POST was sent again");
    assert_eq!(e.resend_on_new_connection, None, "the caller was told it may send the POST again");
    let a = &e.outputs[0];
    assert!(reused(a));
    assert_eq!(conn_id(a), conn_id(&first));
    assert!(a.response.is_none());
    assert_eq!(a.observation.dispatch, DispatchState::MayHaveBeenSent);
    let f = a.observation.failure.as_ref().expect("the closed connection failed the POST");
    assert!(f.message.contains("not sent again: the POST request was written and is not idempotent"), "{}", f.message);
    assert_eq!(o.quic_connections(), 1, "no new connection was opened");
    let seen = o.received();
    assert_eq!(seen.iter().map(|r| r.method.as_str()).collect::<Vec<_>>(), ["GET", "POST"]);
}

#[tokio::test]
async fn a_post_the_server_rejected_on_a_pooled_quic_connection_is_left_to_the_caller_to_resend() {
    init();
    let o = origin(H3Script::SecondOnReuse(Unanswered::Rejected)).await;
    let t = H3Transport::new();
    let first = run(&t, &get(&o, "nonce-1")).await;

    // The origin reads the whole POST, then resets its stream with
    // H3_REQUEST_REJECTED: it did not process it (RFC 9114 §4.1.1), so it
    // may be sent again whatever its method, but it saw its per-send auth.
    let e = t.execute_attempt(&post(&o, "nonce-2"), 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the transport sent the rejected POST again as it was");
    let a = &e.outputs[0];
    assert!(reused(a));
    assert_eq!(conn_id(a), conn_id(&first));
    assert!(a.response.is_none());
    assert_eq!(a.observation.dispatch, DispatchState::NotDispatched, "the server said it did not process the POST");
    let f = a.observation.failure.as_ref().expect("the rejection failed the POST");
    assert_eq!(f.quic_error_code, Some(H3_REQUEST_REJECTED), "{f:?}");
    assert!(f.message.contains("rejected the POST request unprocessed (H3_REQUEST_REJECTED)"), "{}", f.message);
    assert_eq!(e.resend_on_new_connection, Some(f.kind), "the caller may sign the POST again and send it once more");

    // The caller's resend, signed again, goes out on a new connection and
    // is answered: its per-send value is new.
    let again = resend(&t, &post(&o, "nonce-3"), f.kind).await;
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert_eq!(again.observation.response_status, Some(200), "{:?}", o.received());
    assert!(!reused(&again), "sent again on the connection that rejected it");
    assert_eq!(o.quic_connections(), 2);
    let seen = o.received();
    assert_eq!(seen.iter().map(|r| r.method.as_str()).collect::<Vec<_>>(), ["GET", "POST", "POST"]);
    assert!(seen.iter().all(|r| !r.replayed), "{seen:?}");
}

#[tokio::test]
async fn a_pooled_quic_connection_whose_peer_sent_goaway_is_not_reused() {
    init();
    let o = origin(H3Script::GoAwayAfterFirst).await;
    let t = H3Transport::new();
    run(&t, &get(&o, "nonce-1")).await;

    // Once the client has taken in the GOAWAY, the pool gives the
    // connection up: it takes no new request (RFC 9114 §5.2).
    let dropped = eventually(Duration::from_secs(5), || {
        t.sweep_pool_at(Instant::now());
        t.pool_stats() == PoolStats::default()
    })
    .await;
    assert!(dropped, "a draining connection stayed pooled: {:?}", t.pool_stats());

    let e = t.execute_attempt(&get(&o, "nonce-2"), 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the request was tried on the draining connection first");
    let a = &e.outputs[0];
    assert!(a.observation.failure.is_none(), "{:?}", a.observation.failure);
    assert_eq!(a.observation.response_status, Some(200));
    assert!(!reused(a));
    assert_eq!(o.quic_connections(), 2);
}
