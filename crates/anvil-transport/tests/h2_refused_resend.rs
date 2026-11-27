//! HTTP/2 requests the peer provably did not process (RFC 9113 §8.7): one
//! whose stream it refused with `REFUSED_STREAM`, and one whose stream is
//! above the last-stream-id of its graceful `GOAWAY`. Both reached the peer
//! whole on a reused pooled connection, so the transport does not send them
//! again as they are (the peer saw their per-send auth), and leaves them to
//! the caller to sign again and send once more, whatever the method: a
//! `POST` included. The caller's resend takes a new connection. With several
//! streams in flight when one graceful `GOAWAY` arrives, each stream gets its
//! own fate: only the one above the last-stream-id is called unprocessed.
//! Real loopback sockets against a frame-level h2c origin.

use anvil_domain::execution::*;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::h2_refuse::{self, IN_FLIGHT, Refusal, RefusingOrigin};
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::{AttemptOutput, EarlyDataIntent, HttpExecution, HttpPlan, HttpTransport, PoolStats};
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

// The POSTs below are sent three at once.
const _: () = assert!(IN_FLIGHT == 3);

/// PROTO-004 with several streams in flight. The first `GET` leaves its
/// connection pooled; [`IN_FLIGHT`] `POST`s then go out on it at once, each
/// whole, before the origin sends one graceful `GOAWAY` as `refusal` says.
/// Returns the origin, the transport, the pooled connection's id and each
/// `POST`'s plan with its execution.
async fn posts_in_flight_at_goaway(refusal: Refusal) -> (RefusingOrigin, HttpTransport, u64, Vec<(HttpPlan, HttpExecution)>) {
    init();
    let o = h2_refuse::serve(refusal).await.unwrap();
    let t = HttpTransport::new();
    let first = run(&t, &plan(&o.url("/"))).await;
    assert_eq!(t.pool.stats(), PoolStats { keys: 1, connections: 1, idle: 1 });

    let posts: Vec<HttpPlan> = (1..=IN_FLIGHT)
        .map(|n| {
            let mut post = plan(&o.url(&format!("/orders/{n}")));
            post.method = http::Method::POST;
            post.body = Bytes::from(format!("{{\"order\":{n}}}"));
            post
        })
        .collect();
    let (cancel, events) = (CancellationToken::new(), EventCtx::none());
    let (a, b, c) = tokio::join!(
        t.execute_attempt(&posts[0], 0, AttemptReason::Initial, &events, &cancel),
        t.execute_attempt(&posts[1], 0, AttemptReason::Initial, &events, &cancel),
        t.execute_attempt(&posts[2], 0, AttemptReason::Initial, &events, &cancel),
    );
    let executions: Vec<(HttpPlan, HttpExecution)> = posts.into_iter().zip([a, b, c]).collect();
    for (_, e) in &executions {
        assert_eq!(e.outputs.len(), 1, "the transport sent a POST again as it was");
        assert!(reused(&e.outputs[0]), "every POST shared the pooled connection");
        assert_eq!(conn_id(&e.outputs[0]), conn_id(&first));
    }
    assert_eq!((o.connections(), o.requests()), (1, 1 + IN_FLIGHT), "every POST reached the origin whole, on one connection");
    let id = conn_id(&first);
    (o, t, id, executions)
}

/// The caller sends the one `POST` the origin did not process once more (as
/// the engine does, signed again): it takes a new connection and succeeds.
async fn resend_takes_a_new_connection(t: &HttpTransport, post: &HttpPlan, kind: FailureKind, pooled: u64) {
    let reason = AttemptReason::ReusedConnectionClosed { after: kind };
    let outs = t.execute(post, 1, reason.clone(), &EventCtx::none(), &CancellationToken::new()).await;
    assert_eq!(outs.len(), 1);
    let again = &outs[0];
    assert_eq!(again.observation.reason, reason);
    assert!(again.observation.failure.is_none(), "{:?}", again.observation.failure);
    assert_eq!(again.observation.response_status, Some(200));
    assert!(!reused(again), "sent again on the connection that sent the GOAWAY");
    assert_ne!(conn_id(again), pooled);
}

/// Ground truth: whether the origin held `post` on a stream above its
/// `GOAWAY`'s last-stream-id (the fixture names each held request by its
/// body, unique per `POST`).
fn above_last_stream(o: &RefusingOrigin, post: &HttpPlan) -> bool {
    let last = o.goaway_last_stream().expect("the origin sent its GOAWAY");
    let held = o.held();
    assert_eq!(held.len(), IN_FLIGHT, "{held:?}");
    let h = held.iter().find(|h| h.body == post.body.as_ref()).unwrap_or_else(|| panic!("the origin held no {:?}: {held:?}", post.body));
    h.stream > last
}

/// The one `POST` above the `GOAWAY`'s last-stream-id: typed as a graceful
/// `GOAWAY`, not processed, and left to the caller to send again.
fn assert_unprocessed(e: &HttpExecution) {
    let a = &e.outputs[0];
    assert!(a.response.is_none());
    assert_eq!(a.observation.dispatch, DispatchState::NotDispatched, "the peer said it did not process this POST");
    let f = a.observation.failure.as_ref().expect("the GOAWAY failed this POST");
    assert_eq!(f.kind, FailureKind::H2GoAway, "{f:?}");
    assert_eq!(f.h2_error_code, Some(0x0), "{f:?}");
    assert!(f.message.contains("refused the POST request without processing it"), "{}", f.message);
    assert_eq!(e.resend_on_new_connection, Some(FailureKind::H2GoAway));
}

/// A graceful `GOAWAY` while three `POST`s are in flight, its last-stream-id
/// the middle one: the two at or below it are answered `200` on the same
/// connection; only the one above it is called unprocessed and left to the
/// caller, whose resend takes a new connection.
#[tokio::test]
async fn proto_004_a_graceful_goaway_amid_streams_fails_only_the_streams_above_its_last_stream_id() {
    let (o, t, pooled, executions) = posts_in_flight_at_goaway(Refusal::GoAwayAmidStreams).await;
    // Split by the origin's own record of which stream carried which POST.
    let (answered, refused): (Vec<_>, Vec<_>) = executions.iter().partition(|(p, _)| !above_last_stream(&o, p));
    assert_eq!(answered.len(), IN_FLIGHT - 1, "two streams at or below the last-stream-id");
    for (_, e) in &answered {
        let a = &e.outputs[0];
        assert_eq!(a.observation.response_status, Some(200), "a POST the origin processed was answered");
        assert!(a.observation.failure.is_none(), "{:?}", a.observation.failure);
        assert_eq!(a.observation.dispatch, DispatchState::Sent);
        assert_eq!(e.resend_on_new_connection, None);
    }
    assert_eq!(refused.len(), 1);
    let (post, e) = refused[0];
    assert_unprocessed(e);
    resend_takes_a_new_connection(&t, post, FailureKind::H2GoAway, pooled).await;
    assert_eq!((o.connections(), o.requests()), (2, 2 + IN_FLIGHT));
}

/// The same `GOAWAY`, then the origin closes the connection without
/// answering: the two `POST`s at or below the last-stream-id may have been
/// processed, so neither is called unprocessed nor sent again, while the one
/// above it is left to the caller, whose resend takes a new connection.
#[tokio::test]
async fn proto_004_a_goaway_amid_streams_then_close_keeps_the_streams_at_or_below_its_last_stream_id_uncertain() {
    let (o, t, pooled, executions) = posts_in_flight_at_goaway(Refusal::GoAwayAmidStreamsThenClose).await;
    // Split by the origin's own record of which stream carried which POST.
    let (refused, uncertain): (Vec<_>, Vec<_>) = executions.iter().partition(|(p, _)| above_last_stream(&o, p));
    assert_eq!(refused.len(), 1, "one stream above the last-stream-id: {:?}", outcomes(&executions));
    assert_eq!(uncertain.len(), IN_FLIGHT - 1);
    for (_, e) in &uncertain {
        let a = &e.outputs[0];
        assert!(a.response.is_none());
        assert_ne!(a.observation.dispatch, DispatchState::NotDispatched, "a POST the origin may have processed is not called unprocessed");
        let f = a.observation.failure.as_ref().expect("the close failed this POST");
        // The close after the GOAWAY cuts these streams short: an I/O end,
        // never the GOAWAY's own error (which would call them unprocessed).
        assert!(!matches!(f.kind, FailureKind::H2GoAway | FailureKind::H2RefusedStream), "{f:?}");
        assert_eq!(e.resend_on_new_connection, None, "a POST the origin may have processed is never sent again");
    }
    let (post, e) = refused[0];
    assert_unprocessed(e);
    resend_takes_a_new_connection(&t, post, FailureKind::H2GoAway, pooled).await;
    assert_eq!((o.connections(), o.requests()), (2, 2 + IN_FLIGHT));
}

/// Each `POST`'s dispatch and failure kind, for assertion messages.
fn outcomes(executions: &[(HttpPlan, HttpExecution)]) -> Vec<(DispatchState, Option<FailureKind>)> {
    executions
        .iter()
        .map(|(_, e)| {
            let o = &e.outputs[0].observation;
            (o.dispatch, o.failure.as_ref().map(|f| f.kind))
        })
        .collect()
}
