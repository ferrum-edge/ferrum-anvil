//! RFC 8252 §7.3 loopback redirect listener for one authorization attempt.
//!
//! * binds `127.0.0.1` on an ephemeral port (never `0.0.0.0`, never a fixed
//!   port), so only local processes can reach it and every attempt gets a
//!   fresh redirect URI;
//! * accepts exactly one callback on the bound path: the first such request
//!   is validated against the attempt (origin, path, `state`) and decides
//!   the attempt; every later or unrelated request (other paths, other Host
//!   headers such as a DNS-rebinding page, favicon probes) gets a static
//!   page and is ignored;
//! * answers with fixed HTML — no scripts, no reflected query values — and
//!   headers that forbid caching, framing, referrers and sniffing;
//! * stops at the deadline or on cancellation; the port closes when the
//!   attempt ends.

use crate::{FlowError, FlowEvent, FlowObserver};
use anvil_auth::AuthError;
use anvil_auth::oauth::{PkceAttempt, validate_callback};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const PAGE_DONE: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Ferrum Anvil</title></head>\
<body><h1>Sign-in received</h1><p>You can close this tab and return to Ferrum Anvil.</p></body></html>";
const PAGE_FAILED: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Ferrum Anvil</title></head>\
<body><h1>Sign-in was not completed</h1><p>Return to Ferrum Anvil to see what happened and try again. You can close this tab.</p></body></html>";
const PAGE_HANDLED: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Ferrum Anvil</title></head>\
<body><p>This sign-in attempt was already handled. You can close this tab.</p></body></html>";
const PAGE_NOT_FOUND: &str =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Not found</title></head><body><p>Not found.</p></body></html>";

/// Per-connection budget; a stalled local client cannot hold a task forever.
const CONNECTION_BUDGET: Duration = Duration::from_secs(15);

enum Outcome {
    Code(Zeroizing<String>),
    Rejected(FlowError),
    Ignored(&'static str),
}

pub(crate) struct Loopback {
    listener: TcpListener,
    port: u16,
    path: String,
    redirect_uri: String,
}

impl Loopback {
    pub(crate) async fn bind(callback_path: &str) -> Result<Loopback, FlowError> {
        let path = if callback_path.starts_with('/') { callback_path.to_string() } else { format!("/{callback_path}") };
        if path.contains(['?', '#']) || path.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(FlowError::Configuration("the loopback callback path must be a plain path".into()));
        }
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.map_err(|e| FlowError::Listener(e.to_string()))?;
        let port = listener.local_addr().map_err(|e| FlowError::Listener(e.to_string()))?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}{path}");
        Ok(Loopback { listener, port, path, redirect_uri })
    }

    pub(crate) fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Wait for this attempt's callback. `binding` must be
    /// [`PkceAttempt::binding_only`] — the verifier never enters the listener.
    pub(crate) async fn wait(
        self,
        binding: PkceAttempt,
        observer: &dyn FlowObserver,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<Zeroizing<String>, FlowError> {
        let (tx, mut rx) = mpsc::channel::<Outcome>(16);
        let consumed = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared { binding, port: self.port, path: self.path.clone(), consumed });
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(FlowError::Canceled),
                _ = &mut deadline => return Err(FlowError::TimedOut(timeout)),
                Some(o) = rx.recv() => match o {
                    Outcome::Code(code) => return Ok(code),
                    Outcome::Rejected(e) => return Err(e),
                    Outcome::Ignored(reason) => observer.event(FlowEvent::CallbackIgnored { reason: reason.to_string() }),
                },
                r = self.listener.accept() => {
                    let Ok((stream, peer)) = r else { continue };
                    if !peer.ip().is_loopback() {
                        continue; // unreachable for a 127.0.0.1 bind; defence in depth
                    }
                    let (shared, tx) = (shared.clone(), tx.clone());
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| {
                            let (shared, tx) = (shared.clone(), tx.clone());
                            async move {
                                let (resp, outcome) = shared.handle(&req);
                                let _ = tx.send(outcome).await;
                                Ok::<_, Infallible>(resp)
                            }
                        });
                        let conn = hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(stream), svc);
                        let _ = tokio::time::timeout(CONNECTION_BUDGET, conn).await;
                    });
                }
            }
        }
    }
}

struct Shared {
    binding: PkceAttempt,
    port: u16,
    path: String,
    consumed: Arc<AtomicBool>,
}

impl Shared {
    fn handle(&self, req: &Request<Incoming>) -> (Response<Full<Bytes>>, Outcome) {
        if req.method() != Method::GET {
            return (
                page(StatusCode::METHOD_NOT_ALLOWED, PAGE_NOT_FOUND),
                Outcome::Ignored("a non-GET request reached the loopback listener"),
            );
        }
        // A page on another origin (DNS rebinding) reaches 127.0.0.1 with its
        // own Host name; only the exact loopback authority is ours.
        let expected_host = format!("127.0.0.1:{}", self.port);
        let host = req.headers().get(http::header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
        if !host.eq_ignore_ascii_case(&expected_host) {
            return (
                page(StatusCode::BAD_REQUEST, PAGE_NOT_FOUND),
                Outcome::Ignored("a request for another host name reached the loopback listener"),
            );
        }
        if req.uri().path() != self.path {
            return (
                page(StatusCode::NOT_FOUND, PAGE_NOT_FOUND),
                Outcome::Ignored("a request for an unexpected path reached the loopback listener"),
            );
        }
        if self.consumed.swap(true, Ordering::SeqCst) {
            return (
                page(StatusCode::CONFLICT, PAGE_HANDLED),
                Outcome::Ignored("a second callback arrived for an attempt that was already decided"),
            );
        }
        let target = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let full = Zeroizing::new(format!("http://{expected_host}{target}"));
        match validate_callback(&self.binding, &full) {
            Ok(code) => (page(StatusCode::OK, PAGE_DONE), Outcome::Code(code)),
            Err(AuthError::Acquisition(m)) => {
                let code = m.strip_prefix("authorization server returned error: ").unwrap_or(&m).to_string();
                (page(StatusCode::OK, PAGE_FAILED), Outcome::Rejected(FlowError::AuthorizationDenied(code)))
            }
            Err(e) => (page(StatusCode::BAD_REQUEST, PAGE_FAILED), Outcome::Rejected(FlowError::CallbackRejected(e.to_string()))),
        }
    }
}

fn page(status: StatusCode, html: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .header("content-security-policy", "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        .header("referrer-policy", "no-referrer")
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .header("connection", "close")
        .body(Full::new(Bytes::from_static(html.as_bytes())))
        .expect("static response")
}
