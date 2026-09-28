//! A request on a reused pooled connection that the server closes as the
//! request goes out may have been received. When its method is idempotent it
//! is sent once more on a new connection, signed again: a new HMAC nonce, a
//! new DPoP proof `jti`. The origin answers a nonce or `jti` it has already
//! received with 401, as a gateway that checks for replays does. The resend
//! is not a retry: it happens with retries set to 0 and has its own reason.
//! A written POST is not sent again, unless the HTTP/2 peer refused it
//! unprocessed (`REFUSED_STREAM`, or a stream above the last-stream-id of
//! its graceful `GOAWAY`): then it too is signed again and sent once more.
//! Real loopback sockets, no mocks.

use anvil_domain::auth::{AuthConfig, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile};
use anvil_domain::execution::*;
use anvil_domain::request::{Body, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, RetryPolicy, SettingsOverrides};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::h2_refuse::{self, Refusal};
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn hmac() -> AuthConfig {
    AuthConfig::Hmac {
        config: HmacConfig {
            profile: HmacProfile::FerrumV2,
            username: "resend-client".into(),
            secret: SensitiveValue::template("audit-only-hmac-secret-4m8r"),
            algorithm: HmacAlgorithm::HmacSha256,
            digest_header: Default::default(),
            namespace: String::new(),
            allow_unsafe_legacy: false,
        },
    }
}

fn dpop() -> AuthConfig {
    AuthConfig::Dpop {
        config: DpopConfig {
            access_token: SensitiveValue::template("audit-only-dpop-token-6t2n"),
            private_key_pem: SensitiveValue::template(anvil_auth::dpop::generate_key_pem().unwrap()),
            dpop_scheme: true,
            handle_nonce_challenge: false,
        },
    }
}

/// A `method` of `url` with `auth`, and retries set to 0.
fn ctx(method: &str, url: &str, auth: AuthConfig) -> ExecutionContext {
    let mut s = RequestSpec::http(method, url);
    s.auth = auth;
    let mut c = ExecutionContext::standalone(s);
    let retries = RetryPolicy { max_retries: 0, backoff_ms: 0, only_safe: true };
    c.settings_layers.push(("run".into(), SettingsOverrides { retries: Some(retries), ..Default::default() }));
    c
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

fn reused(a: &AttemptObservation) -> bool {
    a.connection.as_ref().expect("no connection").reused
}

/// The per-send value of a request that the origin checks for replays.
#[derive(Clone, Copy)]
enum PerSend {
    /// The `nonce` of an HMAC `Authorization` header.
    HmacNonce,
    /// The `jti` of a `DPoP` proof.
    DpopJti,
}

/// The value of header `name` in a request head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).filter_map(|l| l.split_once(':')).find(|(n, _)| n.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim())
}

/// The per-send value in a request head, or "" when it has none.
fn per_send(head: &str, kind: PerSend) -> String {
    let value = match kind {
        PerSend::HmacNonce => header(head, "authorization").and_then(|a| {
            let start = a.find("nonce=\"")? + "nonce=\"".len();
            let len = a[start..].find('"')?;
            Some(a[start..start + len].to_string())
        }),
        PerSend::DpopJti => header(head, "dpop").and_then(|proof| {
            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(proof.split('.').nth(1)?).ok()?;
            let claims: serde_json::Value = serde_json::from_slice(&claims).ok()?;
            claims["jti"].as_str().map(str::to_string)
        }),
    };
    value.unwrap_or_default()
}

/// A keep-alive HTTP/1.1 origin. Its first connection answers the first
/// request, then reads the second and closes without answering. A request
/// whose per-send value was already received is answered `401`; any other
/// `200`.
struct Origin {
    url: String,
    accepted: Arc<AtomicUsize>,
    /// (request line, per-send value) of every request received, in order.
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

impl Origin {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().clone()
    }
}

async fn origin(kind: PerSend) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/echo", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (a, s) = (accepted.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let first = a.fetch_add(1, Ordering::SeqCst) == 0;
            let s = s.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                for n in 0.. {
                    let Some(head) = read_request(&mut stream, &mut buf).await else { return };
                    let value = per_send(&head, kind);
                    let replayed = {
                        let mut s = s.lock().unwrap();
                        let replayed = s.iter().any(|(_, v)| *v == value);
                        s.push((head.lines().next().unwrap_or_default().to_string(), value));
                        replayed
                    };
                    if first && n == 1 {
                        return;
                    }
                    let status = if replayed { "401 Unauthorized" } else { "200 OK" };
                    let resp = format!("HTTP/1.1 {status}\r\ncontent-length: 2\r\n\r\nok");
                    if stream.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Origin { url, accepted, seen }
}

/// Read one request (its head and `content-length` body) from `stream`: its
/// head, or `None` once the client closed the connection.
async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let len = header(&head, "content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
            if buf.len() >= end + 4 + len {
                buf.drain(..end + 4 + len);
                return Some(head);
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The first GET leaves its connection pooled. The second goes out on it,
/// the origin reads it and closes the connection, and the engine signs it
/// again and sends it once more on a new connection, which the origin
/// accepts only with a per-send value it has not seen.
async fn resent_signed_again(auth: AuthConfig, kind: PerSend) {
    init();
    let o = origin(kind).await;
    let e = Engine::new();
    let c = ctx("GET", &o.url, auth);
    let first = run(&e, &c).await;
    assert_eq!(status(&first), Some(200), "{:?}", first.record.attempts.last().and_then(|a| a.failure.as_ref()));

    let out = run(&e, &c).await;
    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 2, "{:?}", atts.iter().map(|a| (&a.reason, &a.failure)).collect::<Vec<_>>());
    let on_closed = &atts[0];
    assert!(reused(on_closed));
    assert!(on_closed.response_status.is_none());
    assert_eq!(on_closed.dispatch, DispatchState::MayHaveBeenSent);
    let f = on_closed.failure.as_ref().expect("the closed connection failed the request");
    assert!(f.message.contains("the GET request may have been received"), "{}", f.message);
    assert!(f.message.contains("sent once more on a new connection as attempt 1, with its auth applied again"), "{}", f.message);

    let again = &atts[1];
    assert_eq!(again.reason, AttemptReason::ReusedConnectionClosed { after: f.kind }, "not recorded as a retry");
    assert!(!reused(again), "sent again on a reused connection");
    assert_eq!(status(&out), Some(200), "the origin saw the per-send value again: {:?}", o.seen());
    assert_eq!(o.accepted(), 2);

    let seen = o.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert!(seen.iter().all(|(line, v)| line == "GET /echo HTTP/1.1" && !v.is_empty()), "{seen:?}");
    let distinct: HashSet<&String> = seen.iter().map(|(_, v)| v).collect();
    assert_eq!(distinct.len(), 3, "a per-send value was sent twice: {seen:?}");
}

#[tokio::test]
async fn an_hmac_signed_get_is_resent_with_a_new_nonce_after_its_pooled_connection_closed() {
    resent_signed_again(hmac(), PerSend::HmacNonce).await;
}

#[tokio::test]
async fn a_dpop_get_is_resent_with_a_new_proof_after_its_pooled_connection_closed() {
    resent_signed_again(dpop(), PerSend::DpopJti).await;
}

#[tokio::test]
async fn a_written_post_on_a_pooled_connection_closed_under_it_is_not_sent_again() {
    init();
    let o = origin(PerSend::HmacNonce).await;
    let e = Engine::new();
    let first = run(&e, &ctx("GET", &o.url, hmac())).await;
    assert_eq!(status(&first), Some(200), "{:?}", first.record.attempts.last().and_then(|a| a.failure.as_ref()));

    let out = run(&e, &ctx("POST", &o.url, hmac())).await;
    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 1, "the POST was sent again: {:?}", atts.iter().map(|a| &a.reason).collect::<Vec<_>>());
    let a = &atts[0];
    assert!(reused(a));
    assert_eq!(a.dispatch, DispatchState::MayHaveBeenSent);
    let f = a.failure.as_ref().expect("the closed connection failed the request");
    assert!(f.message.contains("not sent again: the POST request was written and is not idempotent"), "{}", f.message);
    assert!(out.record.response.is_none());
    assert_eq!(o.accepted(), 1, "no new connection was opened");
    assert_eq!(o.seen().len(), 2);
}

/// Over cleartext HTTP/2, the first GET leaves its connection pooled. A
/// signed POST goes out on it whole and the peer refuses it as `refusal`
/// says, without processing it. The engine signs the POST again and sends it
/// once more on a new connection.
async fn refused_post_resent_signed_again(refusal: Refusal, kind: FailureKind) {
    init();
    let o = h2_refuse::serve(refusal).await.unwrap();
    let e = Engine::new();
    let h2c = |mut c: ExecutionContext| {
        let version = SettingsOverrides { http_version: Some(HttpVersionPolicy::H2c), ..Default::default() };
        c.settings_layers.push(("h2c".into(), version));
        c
    };
    let first = run(&e, &h2c(ctx("GET", &o.url("/echo"), hmac()))).await;
    assert_eq!(status(&first), Some(200), "{:?}", first.record.attempts.last().and_then(|a| a.failure.as_ref()));

    let mut post = ctx("POST", &o.url("/orders"), hmac());
    post.spec.body = Body::Json { text: r#"{"order":1}"#.into() };
    let out = run(&e, &h2c(post)).await;
    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 2, "{:?}", atts.iter().map(|a| (&a.reason, &a.failure)).collect::<Vec<_>>());
    let refused = &atts[0];
    assert!(reused(refused));
    assert_eq!(refused.dispatch, DispatchState::NotDispatched, "the peer said it did not process the POST");
    let f = refused.failure.as_ref().expect("the refusal failed the POST");
    assert_eq!(f.kind, kind, "{f:?}");
    assert!(f.message.contains("refused the POST request without processing it"), "{}", f.message);
    assert!(f.message.contains("sent once more on a new connection as attempt 1, with its auth applied again"), "{}", f.message);

    let again = &atts[1];
    assert_eq!(again.reason, AttemptReason::ReusedConnectionClosed { after: kind }, "not recorded as a retry");
    assert!(!reused(again), "sent again on the connection that refused it");
    assert_eq!(status(&out), Some(200));
    assert_eq!((o.connections(), o.requests()), (2, 3));
}

#[tokio::test]
async fn a_post_refused_with_refused_stream_is_resent_signed_again_on_a_new_connection() {
    refused_post_resent_signed_again(Refusal::RefusedStream, FailureKind::H2RefusedStream).await;
}

#[tokio::test]
async fn a_post_above_the_last_stream_id_of_a_graceful_goaway_is_resent_signed_again_on_a_new_connection() {
    refused_post_resent_signed_again(Refusal::GoAway, FailureKind::H2GoAway).await;
}
