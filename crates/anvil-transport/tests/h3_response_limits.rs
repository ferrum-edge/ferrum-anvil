//! HTTP/3 responses against the client's own limits, from a raw local QUIC
//! origin (`anvil_fixtures::h3raw`) that sends what a conforming server
//! library would not.
//!
//! * Response headers and trailers are bounded by `max_response_header_bytes`
//!   on every HTTP/3 connection (pooled, session and MASQUE): the client
//!   advertises it, refuses a HEADERS frame that declares more before
//!   buffering it, and refuses a decoded section over it.
//! * The total deadline, the body idle deadline and cancellation end the
//!   response in every phase: a body dripped past `total_ms`, and trailers
//!   whose stream never ends. The client stops the stream when it gives up.

use anvil_domain::Id;
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::*;
use anvil_domain::request::MasqueDatagramMode;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::h3raw::{self, ACCEPT_RANGES_BYTES, Answer, DATA, ETAG, End, HEADERS, RawH3, STATUS_200};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::dns::DnsConfig;
use anvil_transport::h3::H3Transport;
use anvil_transport::http::{AttemptOutput, EarlyDataIntent, HttpPlan};
use anvil_transport::recorder::{EventCtx, EventFn};
use anvil_transport::session::TranscriptLimits;
use anvil_transport::tls::{self, PreparedTls, TlsSettings};
use anvil_transport::{masque, sse};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// The header limit these tests configure (the default is 256 KiB).
const LIMIT: u64 = 16 * 1024;
/// `H3_REQUEST_CANCELLED` (RFC 9114 §8.1).
const H3_REQUEST_CANCELLED: u64 = 0x10c;
/// Longer than any of these responses may take once the fix holds; without
/// it they wait for the peer (or a 10 s response-header deadline).
const GIVE_UP: Duration = Duration::from_secs(8);

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn client_tls() -> Arc<PreparedTls> {
    let settings =
        TlsSettings { verify: true, use_system_roots: false, extra_roots_pem: vec![pki().ca.cert.clone()], ..Default::default() };
    Arc::new(tls::prepare(&settings).expect("tls profile"))
}

async fn origin(answers: Vec<Answer>) -> RawH3 {
    let tls = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    h3raw::serve(tls, answers).await.expect("raw HTTP/3 origin")
}

fn limits() -> Limits {
    Limits { max_response_header_bytes: LIMIT, ..Limits::default() }
}

fn timeouts() -> Timeouts {
    Timeouts {
        dns_ms: Some(2_000),
        connect_ms: Some(5_000),
        tls_handshake_ms: Some(5_000),
        request_write_ms: Some(5_000),
        response_headers_ms: Some(10_000),
        body_idle_ms: Some(30_000),
        total_ms: Some(60_000),
    }
}

fn plan(addr: SocketAddr) -> HttpPlan {
    HttpPlan {
        proxy_header: None,
        proxy_header_withheld: None,
        method: http::Method::GET,
        https: true,
        authority: addr.to_string(),
        host: addr.ip().to_string(),
        port: addr.port(),
        request_target: "/".into(),
        headers: vec![],
        body: Bytes::new(),
        version: HttpVersionPolicy::Http3Only,
        timeouts: timeouts(),
        limits: limits(),
        keepalive: true,
        dns: DnsConfig::default(),
        proxy: None,
        tls: Some(client_tls()),
        isolation: "h3-limits".into(),
        display_url: format!("https://{addr}/"),
        early_data: EarlyDataIntent::Off,
        fence: None,
    }
}

async fn send(t: &H3Transport, p: &HttpPlan, cancel: &CancellationToken) -> AttemptOutput {
    send_with(t, p, &EventCtx::none(), cancel).await
}

async fn send_with(t: &H3Transport, p: &HttpPlan, events: &EventCtx, cancel: &CancellationToken) -> AttemptOutput {
    let run = t.execute(p, 0, AttemptReason::Initial, events, cancel);
    tokio::time::timeout(GIVE_UP, run).await.expect("the HTTP/3 request did not end")
}

fn failure(o: &AttemptOutput) -> (FailureKind, Phase) {
    let f = o.observation.failure.as_ref().expect("the attempt failed");
    (f.kind, f.phase)
}

// ---- answers ----

fn headers(lines: &[u8]) -> Vec<u8> {
    h3raw::frame(HEADERS, &h3raw::field_section(lines))
}

/// `:status: 200`.
fn ok_head() -> Vec<u8> {
    headers(&[h3raw::indexed(STATUS_200)])
}

/// A HEADERS frame that declares 1 MiB and brings 32 KiB of it: more than
/// the limit, and never complete.
fn endless_headers() -> Vec<u8> {
    let mut out = h3raw::frame_header(HEADERS, 1 << 20);
    out.extend(std::iter::repeat_n(h3raw::indexed(ACCEPT_RANGES_BYTES), 32 * 1024));
    out
}

/// A small HEADERS frame whose field section decodes to about 50 KB: a
/// thousand one-byte references to `accept-ranges: bytes` (50 bytes each
/// as RFC 9114 counts them).
fn inflated_lines() -> Vec<u8> {
    vec![h3raw::indexed(ACCEPT_RANGES_BYTES); 1000]
}

fn answer(parts: &[Vec<u8>], end: End) -> Answer {
    Answer { bytes: parts.concat(), end }
}

// ---- response headers and trailers are bounded ----

#[tokio::test]
async fn a_headers_frame_declared_over_the_limit_is_refused_before_it_is_buffered() {
    init();
    let o = origin(vec![answer(&[endless_headers()], End::Hold), answer(&[ok_head(), h3raw::frame(DATA, b"ok")], End::Finish)]).await;
    let t = H3Transport::new();
    let p = plan(o.addr);

    let refused = send(&t, &p, &CancellationToken::new()).await;
    assert_eq!(failure(&refused), (FailureKind::ResponseHeadersTooLarge, Phase::AwaitResponseHeaders));
    assert_eq!(refused.observation.dispatch, DispatchState::Sent, "the server answered");
    assert!(refused.response.is_none());
    assert_eq!(o.first_stop(Duration::from_secs(5)).await, Some(H3_REQUEST_CANCELLED), "the response stream is stopped");
    assert_eq!(o.first_advertised(Duration::from_secs(5)).await, Some(LIMIT), "the limit is advertised in SETTINGS");

    // Only the stream was refused: the pooled connection serves the next request.
    let next = send(&t, &p, &CancellationToken::new()).await;
    assert!(next.observation.failure.is_none(), "{:?}", next.observation.failure);
    assert!(next.observation.connection.as_ref().is_some_and(|c| c.reused));
    assert_eq!(&next.body[..], b"ok");
}

#[tokio::test]
async fn a_small_headers_frame_that_decodes_over_the_limit_is_refused() {
    init();
    let mut lines = vec![h3raw::indexed(STATUS_200)];
    lines.extend(inflated_lines());
    let o = origin(vec![answer(&[headers(&lines), h3raw::frame(DATA, b"ok")], End::Finish)]).await;
    let encoded = headers(&lines).len() as u64;
    assert!(encoded < LIMIT, "the encoded frame ({encoded} bytes) passes the encoded bound");

    let out = send(&H3Transport::new(), &plan(o.addr), &CancellationToken::new()).await;
    assert_eq!(failure(&out), (FailureKind::ResponseHeadersTooLarge, Phase::AwaitResponseHeaders));
    assert!(out.response.is_none(), "no header of the section is kept");
}

#[tokio::test]
async fn trailers_over_the_limit_are_refused_encoded_or_decoded() {
    init();
    let endless = answer(&[ok_head(), h3raw::frame(DATA, b"ok"), endless_headers()], End::Hold);
    let inflated = answer(&[ok_head(), h3raw::frame(DATA, b"ok"), headers(&inflated_lines())], End::Finish);
    for (what, a) in [("declared", endless), ("decoded", inflated)] {
        let o = origin(vec![a]).await;
        let out = send(&H3Transport::new(), &plan(o.addr), &CancellationToken::new()).await;
        assert_eq!(failure(&out), (FailureKind::ResponseHeadersTooLarge, Phase::ResponseBody), "{what}");
        let r = out.response.as_ref().expect("the response head was kept");
        assert_eq!(r.status, 200);
        assert!(!r.trailers_received && r.trailers.is_empty(), "{what}");
        assert_eq!(r.body.completeness, BodyCompleteness::Incomplete, "{what}");
    }
}

#[tokio::test]
async fn headers_and_trailers_under_the_limit_are_received() {
    init();
    let mut lines = vec![h3raw::indexed(STATUS_200)];
    let etag = vec![b'e'; 8_000];
    h3raw::literal(&mut lines, ETAG, &etag);
    let trailer = headers(&[h3raw::indexed(ACCEPT_RANGES_BYTES)]);
    let o = origin(vec![answer(&[headers(&lines), h3raw::frame(DATA, b"ok"), trailer], End::Finish)]).await;

    let out = send(&H3Transport::new(), &plan(o.addr), &CancellationToken::new()).await;
    assert!(out.observation.failure.is_none(), "{:?}", out.observation.failure);
    let r = out.response.as_ref().unwrap();
    assert!(r.headers.iter().any(|h| h.name == "etag" && h.value.len() == etag.len()));
    assert!(r.trailers_received);
    assert!(r.trailers.iter().any(|h| h.name == "accept-ranges" && h.value == "bytes"));
    assert_eq!(r.body.completeness, BodyCompleteness::Complete);
    assert_eq!(&out.body[..], b"ok");
}

#[tokio::test]
async fn a_header_limit_of_zero_or_u64_max_is_clamped_to_what_http3_can_advertise() {
    init();
    // The raw limit comes from settings layers and imports: 0 is floored
    // like HTTP/1's buffer, and u64::MAX (over a SETTINGS varint) is capped
    // instead of panicking in h3's encoder.
    for (configured, advertised) in [(0, 8192), (u64::MAX, (1 << 62) - 1)] {
        let o = origin(vec![answer(&[ok_head(), h3raw::frame(DATA, b"ok")], End::Finish)]).await;
        let mut p = plan(o.addr);
        p.limits.max_response_header_bytes = configured;
        let out = send(&H3Transport::new(), &p, &CancellationToken::new()).await;
        assert!(out.observation.failure.is_none(), "{configured}: {:?}", out.observation.failure);
        assert_eq!(&out.body[..], b"ok", "{configured}");
        assert_eq!(o.first_advertised(Duration::from_secs(5)).await, Some(advertised), "{configured}");
    }
}

#[tokio::test]
async fn a_pooled_connection_is_reused_only_under_the_header_limit_it_was_opened_with() {
    init();
    let o = origin(vec![answer(&[ok_head(), h3raw::frame(DATA, b"ok")], End::Finish)]).await;
    let t = H3Transport::new();
    let mut large = plan(o.addr);
    large.limits.max_response_header_bytes = 4 * LIMIT;
    let small = plan(o.addr);

    let mut reused = vec![];
    for p in [&large, &small, &small] {
        let out = send(&t, p, &CancellationToken::new()).await;
        assert!(out.observation.failure.is_none(), "{:?}", out.observation.failure);
        reused.push(out.observation.connection.as_ref().is_some_and(|c| c.reused));
    }
    assert_eq!(reused, [false, false, true], "a smaller limit opens its own connection");
    // Each connection advertised its own limit (recorded as its control
    // stream is read, so wait for the second one).
    for _ in 0..500 {
        if o.advertised().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut advertised = o.advertised();
    advertised.sort();
    assert_eq!(advertised, [LIMIT, 4 * LIMIT]);
}

#[tokio::test]
async fn sessions_and_masque_advertise_the_header_limit_and_refuse_larger_headers() {
    init();
    // Server-sent events over HTTP/3.
    let o = origin(vec![answer(&[endless_headers()], End::Hold)]).await;
    let sse_plan = sse::SsePlan {
        proxy_header: None,
        method: http::Method::GET,
        https: true,
        host: o.addr.ip().to_string(),
        port: o.addr.port(),
        authority: o.addr.to_string(),
        request_target: "/sse".into(),
        headers: vec![],
        sign: None,
        body: Bytes::new(),
        version: HttpVersionPolicy::Http3Only,
        timeouts: timeouts(),
        limits: limits(),
        dns: DnsConfig::default(),
        proxy: None,
        tls: Some(client_tls()),
        display_url: format!("https://{}/sse", o.addr),
        max_events: 0,
        idle_timeout_ms: 3_000,
        last_event_id: None,
        reconnect: false,
        max_reconnects: 0,
        transcript: TranscriptLimits::default(),
        redact: None,
    };
    let (events, cancel) = (EventCtx::none(), CancellationToken::new());
    let run = sse::run(&sse_plan, &events, &cancel, None);
    let out = tokio::time::timeout(GIVE_UP, run).await.expect("the event stream did not end");
    let f = out.attempts[0].observation.failure.as_ref().expect("the event stream failed");
    assert_eq!((f.kind, f.phase), (FailureKind::ResponseHeadersTooLarge, Phase::AwaitResponseHeaders));
    assert_eq!(o.first_advertised(Duration::from_secs(5)).await, Some(LIMIT));

    // The CONNECT-UDP request to a MASQUE proxy.
    let proxy = origin(vec![answer(&[endless_headers()], End::Hold)]).await;
    let masque_plan = masque::MasquePlan {
        tunnel: masque::MasqueTunnelPlan {
            proxy_host: proxy.addr.ip().to_string(),
            proxy_port: proxy.addr.port(),
            proxy_authority: proxy.addr.to_string(),
            request_target: "/.well-known/masque/udp/127.0.0.1/9/".into(),
            target: "127.0.0.1:9".into(),
            headers: vec![],
            mode: MasqueDatagramMode::Auto,
            tls: client_tls(),
            dns: DnsConfig::default(),
            timeouts: timeouts(),
            limits: limits(),
            display_url: format!("https://{}/.well-known/masque/udp/127.0.0.1/9/", proxy.addr),
        },
        datagrams: vec![],
        response_window_ms: 100,
        max_datagrams: 1,
        transcript: TranscriptLimits::default(),
        redact: None,
    };
    let run = masque::run(&masque_plan, &events, &cancel, None);
    let out = tokio::time::timeout(GIVE_UP, run).await.expect("the MASQUE session did not end");
    let f = out.attempts[0].observation.failure.as_ref().expect("the tunnel was not opened");
    assert_eq!((f.kind, f.phase), (FailureKind::ResponseHeadersTooLarge, Phase::AwaitResponseHeaders));
    assert_eq!(proxy.first_advertised(Duration::from_secs(5)).await, Some(LIMIT));
}

// ---- deadlines and cancellation hold through the whole response ----

#[tokio::test]
async fn a_body_dripped_past_the_total_deadline_stops_at_it() {
    init();
    let o = origin(vec![answer(&[ok_head(), h3raw::frame(DATA, b"x")], End::Drip(Duration::from_millis(50)))]).await;
    let mut p = plan(o.addr);
    // Each byte arrives well within the idle deadline.
    p.timeouts.body_idle_ms = Some(1_000);
    p.timeouts.total_ms = Some(1_500);

    let out = send(&H3Transport::new(), &p, &CancellationToken::new()).await;
    assert_eq!(failure(&out), (FailureKind::TotalTimeout, Phase::ResponseBody));
    assert_eq!(out.observation.failure.as_ref().unwrap().deadline_ms, Some(1_500));
    let r = out.response.as_ref().unwrap();
    assert_eq!(r.body.completeness, BodyCompleteness::Incomplete);
    assert!(r.body.wire_bytes > 1, "the body was read until the deadline");
    assert_eq!(out.observation.phase(Phase::ResponseBody).unwrap().status, PhaseStatus::TimedOut);
    assert_eq!(o.first_stop(Duration::from_secs(5)).await, Some(H3_REQUEST_CANCELLED));
}

/// Headers, a body and trailers, then the stream stays open.
fn trailers_without_end() -> Vec<Answer> {
    let trailer = headers(&[h3raw::indexed(ACCEPT_RANGES_BYTES)]);
    vec![answer(&[ok_head(), h3raw::frame(DATA, b"ok"), trailer], End::Hold)]
}

#[tokio::test]
async fn trailers_without_the_end_of_the_stream_end_on_cancel() {
    init();
    let o = Arc::new(origin(trailers_without_end()).await);
    // Cancel once the client has the response head and the origin has written
    // everything up to the trailers (one write), rather than after a guess.
    let head = Arc::new(Notify::new());
    let seen = head.clone();
    let sink: EventFn = Arc::new(move |ev: ExecutionEvent| {
        if matches!(ev, ExecutionEvent::ResponseHead { .. }) {
            seen.notify_one();
        }
    });
    let events = EventCtx { execution_id: Id::nil(), sink: Some(sink) };
    let cancel = CancellationToken::new();
    let (c, origin_ref) = (cancel.clone(), o.clone());
    tokio::spawn(async move {
        head.notified().await;
        assert!(origin_ref.wrote(1, GIVE_UP).await, "the origin wrote its answer");
        c.cancel();
    });

    let out = send_with(&H3Transport::new(), &plan(o.addr), &events, &cancel).await;
    assert_eq!(failure(&out), (FailureKind::Canceled, Phase::ResponseBody));
    let r = out.response.as_ref().unwrap();
    assert_eq!(r.body.completeness, BodyCompleteness::Canceled);
    assert_eq!(&out.body[..], b"ok");
    assert_eq!(out.observation.phase(Phase::ResponseBody).unwrap().status, PhaseStatus::Canceled);
    assert_eq!(o.first_stop(Duration::from_secs(5)).await, Some(H3_REQUEST_CANCELLED));
}

#[tokio::test]
async fn trailers_without_the_end_of_the_stream_end_at_the_idle_and_total_deadlines() {
    init();
    let o = origin(trailers_without_end()).await;
    let mut idle = plan(o.addr);
    idle.timeouts.body_idle_ms = Some(500);
    let mut total = plan(o.addr);
    total.timeouts.total_ms = Some(1_500);

    for (p, kind, deadline) in [(idle, FailureKind::BodyIdleTimeout, 500), (total, FailureKind::TotalTimeout, 1_500)] {
        let out = send(&H3Transport::new(), &p, &CancellationToken::new()).await;
        assert_eq!(failure(&out), (kind, Phase::ResponseBody));
        assert_eq!(out.observation.failure.as_ref().unwrap().deadline_ms, Some(deadline));
        assert_eq!(out.response.as_ref().unwrap().body.completeness, BodyCompleteness::Incomplete);
    }
    assert_eq!(o.first_stop(Duration::from_secs(5)).await, Some(H3_REQUEST_CANCELLED));
}
