//! HTTP/2 requests the peer provably did not process (RFC 9113 §8.7): one
//! whose stream it refused with `REFUSED_STREAM`, and one whose stream is
//! above the last-stream-id of its graceful `GOAWAY`. Both reached the peer
//! whole on a reused pooled connection, so the transport does not send them
//! again as they are (the peer saw their per-send auth), and leaves them to
//! the caller to sign again and send once more, whatever the method: a
//! `POST` included. The caller's resend takes a new connection. Real loopback
//! sockets against a frame-level h2c origin.

use anvil_domain::execution::*;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::h2_refuse::{self, Refusal};
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::{AttemptOutput, EarlyDataIntent, HttpPlan, HttpTransport, PoolStats};
use anvil_transport::recorder::EventCtx;
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

/// A cleartext HTTP/2 (prior knowledge) `GET` of `url`, with connection reuse.
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
        version: HttpVersionPolicy::H2c,
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
        isolation: "refused-test".into(),
        display_url: url.into(),
        early_data: EarlyDataIntent::Off,
        fence: None,
    }
}

async fn run(t: &HttpTransport, p: &HttpPlan) -> AttemptOutput {
    let mut outs = t.execute(p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(outs.len(), 1);
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

/// The first `GET` leaves its connection pooled. A `POST` goes out on it
/// whole and the origin refuses it as `refusal` says: the transport reports
/// the typed failure (`kind`, HTTP/2 error `code`) as not processed, and
/// leaves the resend to the caller, whose resend takes a new connection.
async fn refused_post_is_left_to_the_caller(refusal: Refusal, kind: FailureKind, code: u32) {
    init();
    let o = h2_refuse::serve(refusal).await.unwrap();
    let t = HttpTransport::new();
    let first = run(&t, &plan(&o.url("/"))).await;
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 });

    let mut post = plan(&o.url("/orders"));
    post.method = http::Method::POST;
    post.body = Bytes::from_static(b"{\"order\":1}");
    let e = t.execute_attempt(&post, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(e.outputs.len(), 1, "the transport sent the refused POST again as it was");
    let a = &e.outputs[0];
    assert!(reused(a));
    assert_eq!(conn_id(a), conn_id(&first));
    assert!(a.response.is_none());
    assert_eq!(a.observation.dispatch, DispatchState::NotDispatched, "the peer said it did not process the POST");
    let f = a.observation.failure.as_ref().expect("the refusal failed the POST");
    assert_eq!(f.kind, kind, "{f:?}");
    assert_eq!(f.h2_error_code, Some(code), "{f:?}");
    assert!(f.message.contains("refused the POST request without processing it"), "{}", f.message);
    assert_eq!(e.resend_on_new_connection, Some(kind), "the caller may sign the POST again and send it once more");
    assert_eq!((o.connections(), o.requests()), (1, 2));

    // The caller's resend (as the engine sends it, signed again) takes a new
    // connection.
    let reason = AttemptReason::ReusedConnectionClosed { after: kind };
    let outs = t.execute(&post, 1, reason.clone(), &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(outs.len(), 1);
    let again = &outs[0];
    assert_eq!(again.observation.reason, reason);
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert_eq!(again.observation.response_status, Some(200));
    assert!(!reused(again), "sent again on the connection that refused it");
    assert_ne!(conn_id(again), conn_id(&first));
    assert_eq!((o.connections(), o.requests()), (2, 3));
}

#[tokio::test]
async fn a_post_refused_with_refused_stream_on_a_pooled_connection_is_left_to_the_caller_to_resend() {
    refused_post_is_left_to_the_caller(Refusal::RefusedStream, FailureKind::H2RefusedStream, 0x7).await;
}

#[tokio::test]
async fn a_post_above_the_last_stream_id_of_a_graceful_goaway_is_left_to_the_caller_to_resend() {
    refused_post_is_left_to_the_caller(Refusal::GoAway, FailureKind::H2GoAway, 0x0).await;
}
