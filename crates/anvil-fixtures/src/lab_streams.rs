//! Fixtures for the gateway lab's `streams` and `cpdp` profiles: faults that
//! must sit *behind* (or in front of) a real gateway and that the generic
//! fixtures cannot produce.
//!
//! * [`relay`]: a TCP relay with a controllable cut (partition) — used as a
//!   UDP-less path to an HTTPS/HTTP-3 listener and between a data plane and
//!   its control plane.
//! * [`delayed_grpc`]: the `anvil.lab.v1.Echo` gRPC service over h2c/HTTP/1
//!   that holds every response's headers for a fixed delay (a backend that
//!   accepted the call but is slow to answer).
//! * [`sse_abort`]: an event stream that sends a few events and then aborts
//!   the response body mid-stream (no terminal chunk / stream reset).
//! * [`sse_flaky`]: an event stream that aborts unless the request carries
//!   `Last-Event-ID`, then resumes after it (SSE reconnection, `h3x` profile).
//!
//! Ground truth goes to each fixture's [`GroundTruthLog`]; it is never given
//! to the diagnostic engine.

use crate::http::FxBody;
use crate::log::{GroundTruth, GroundTruthLog};
use bytes::Bytes;
use futures::SinkExt;
use http::{Request, Response};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

// ------------------------------------------------------------------ relay ---

/// A TCP relay `bind -> target`. [`TcpRelay::cut`] tears down every relayed
/// connection and, until [`TcpRelay::heal`], closes each new connection as
/// soon as it is accepted without forwarding anything — a partition that
/// rejects traffic (like a firewall REJECT), while the target keeps running.
pub struct TcpRelay {
    pub addr: SocketAddr,
    pub target: SocketAddr,
    pub log: GroundTruthLog,
    state: Arc<RelayState>,
    cancel: CancellationToken,
}

struct RelayState {
    cut: Mutex<bool>,
    /// Cancels the current generation of relayed connections.
    generation: Mutex<CancellationToken>,
}

impl TcpRelay {
    pub fn cut(&self) {
        *self.state.cut.lock() = true;
        self.state.rotate();
        self.log.push(GroundTruth::FaultApplied { fault: "relay_cut".into() });
    }

    pub fn heal(&self) {
        *self.state.cut.lock() = false;
        self.state.rotate();
        self.log.push(GroundTruth::FaultApplied { fault: "relay_healed".into() });
    }

    pub fn is_cut(&self) -> bool {
        *self.state.cut.lock()
    }

    /// Connections accepted so far (relayed or rejected).
    pub fn connections(&self) -> usize {
        self.log.entries().iter().filter(|e| matches!(e.event, GroundTruth::ConnectionAccepted { .. })).count()
    }
}

impl RelayState {
    fn rotate(&self) {
        let mut g = self.generation.lock();
        g.cancel();
        *g = CancellationToken::new();
    }
}

impl Drop for TcpRelay {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.state.generation.lock().cancel();
    }
}

pub async fn relay(bind: &str, target: SocketAddr) -> anyhow::Result<TcpRelay> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let state = Arc::new(RelayState { cut: Mutex::new(false), generation: Mutex::new(CancellationToken::new()) });
    let (l2, c2, s2) = (log.clone(), cancel.clone(), state.clone());
    tokio::spawn(async move {
        loop {
            let (client, peer) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
            let generation = s2.generation.lock().clone();
            let cut = *s2.cut.lock();
            let log = l2.clone();
            tokio::spawn(async move {
                if cut {
                    log.push(GroundTruth::FaultApplied { fault: "relay_rejected".into() });
                    drop(client);
                    return;
                }
                let upstream = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(target)).await {
                    Ok(Ok(s)) => s,
                    _ => {
                        log.push(GroundTruth::FaultApplied { fault: "relay_target_unreachable".into() });
                        return;
                    }
                };
                let _ = client.set_nodelay(true);
                let _ = upstream.set_nodelay(true);
                let (mut c, mut u) = (client, upstream);
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut c, &mut u) => {}
                    _ = generation.cancelled() => {}
                }
            });
        }
    });
    Ok(TcpRelay { addr, target, log, state, cancel })
}

// ---------------------------------------------------------- delayed gRPC ---

/// A fixture HTTP server (h2c prior knowledge or HTTP/1.1).
pub struct SlowFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    cancel: CancellationToken,
}

impl Drop for SlowFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn serve_with<F, Fut>(bind: &str, handler: F) -> anyhow::Result<SlowFixture>
where
    F: Fn(Request<Incoming>, GroundTruthLog) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<FxBody>> + Send + 'static,
{
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let _ = stream.set_nodelay(true);
            l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
            let (log, cancel, handler) = (l2.clone(), c2.clone(), handler.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let (log, handler) = (log.clone(), handler.clone());
                    async move { Ok::<_, Infallible>(handler(req, log).await) }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                let conn = builder.serve_connection(TokioIo::new(stream), svc);
                tokio::select! {
                    _ = conn => {}
                    _ = cancel.cancelled() => {}
                }
            });
        }
    });
    Ok(SlowFixture { addr, log, cancel })
}

fn request_received(req: &Request<Incoming>, log: &GroundTruthLog) {
    let headers: Vec<(String, String)> =
        req.headers().iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    log.push(GroundTruth::RequestReceived {
        method: req.method().to_string(),
        path: req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default(),
        body_bytes: 0,
        headers,
    });
}

/// `anvil.lab.v1.Echo` whose response headers are held for `delay`.
pub async fn delayed_grpc(bind: &str, delay: Duration) -> anyhow::Result<SlowFixture> {
    serve_with(bind, move |req: Request<Incoming>, log: GroundTruthLog| async move {
        request_received(&req, &log);
        if req.uri().path().starts_with("/anvil.lab.v1.") {
            log.push(GroundTruth::FaultApplied { fault: format!("grpc_headers_delayed_{}ms", delay.as_millis()) });
            tokio::time::sleep(delay).await;
            crate::grpc::handle(req, log).await
        } else {
            Response::builder().status(404).body(full("no fixture route\n")).expect("static response")
        }
    })
    .await
}

// ------------------------------------------------------------- SSE abort ---

/// `GET /…?count=N&interval=MS`: `N` events (default 3), then the body is
/// aborted without a clean end of stream.
pub async fn sse_abort(bind: &str) -> anyhow::Result<SlowFixture> {
    serve_with(bind, |req: Request<Incoming>, log: GroundTruthLog| async move {
        request_received(&req, &log);
        let qs: Vec<(String, String)> =
            req.uri().query().map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect()).unwrap_or_default();
        let get = |k: &str| qs.iter().find(|(n, _)| n == k).and_then(|(_, v)| v.parse::<u64>().ok());
        let count = get("count").unwrap_or(3).min(1000);
        let interval = get("interval").unwrap_or(30).min(10_000);
        let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(16);
        let body: FxBody = BodyExt::boxed(StreamBody::new(rx));
        tokio::spawn(async move {
            for i in 0..count {
                let ev = format!("id: {i}\nevent: tick\ndata: {{\"n\":{i}}}\n\n");
                if tx.send(Ok(Frame::data(Bytes::from(ev)))).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(interval)).await;
            }
            log.push(GroundTruth::FaultApplied { fault: "sse_abort_mid_stream".into() });
            let _ = tx.send(Err(std::io::Error::other("fixture aborts the event stream"))).await;
        });
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .body(body)
            .expect("static response")
    })
    .await
}

fn full(b: &'static str) -> FxBody {
    http_body_util::Full::new(Bytes::from_static(b.as_bytes())).map_err(|e: Infallible| match e {}).boxed()
}

// ------------------------------------------------------------- SSE flaky ---

/// `GET /…?interval=MS` for SSE reconnection through a gateway. Without a
/// `Last-Event-ID`: `retry: 50`, events 1 and 2, then the body is aborted.
/// With `Last-Event-ID: N`: event N+1 and a clean end of stream. The request
/// headers (including `Last-Event-ID`) are recorded as ground truth.
pub async fn sse_flaky(bind: &str) -> anyhow::Result<SlowFixture> {
    serve_with(bind, |req: Request<Incoming>, log: GroundTruthLog| async move {
        request_received(&req, &log);
        let interval = req
            .uri()
            .query()
            .map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect::<Vec<(String, String)>>())
            .unwrap_or_default()
            .into_iter()
            .find(|(n, _)| n == "interval")
            .and_then(|(_, v)| v.parse::<u64>().ok())
            .unwrap_or(30)
            .min(10_000);
        let last: Option<u64> = req.headers().get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse().ok());
        let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(16);
        let body: FxBody = BodyExt::boxed(StreamBody::new(rx));
        tokio::spawn(async move {
            let event = |i: u64| Bytes::from(format!("id: {i}\nevent: tick\ndata: {{\"n\":{i}}}\n\n"));
            match last {
                None => {
                    let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"retry: 50\n")))).await;
                    for i in 1..=2 {
                        if tx.send(Ok(Frame::data(event(i)))).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(interval)).await;
                    }
                    log.push(GroundTruth::FaultApplied { fault: "sse_flaky_abort".into() });
                    let _ = tx.send(Err(std::io::Error::other("fixture aborts the event stream"))).await;
                }
                Some(n) => {
                    let _ = tx.send(Ok(Frame::data(event(n + 1)))).await;
                }
            }
        });
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .body(body)
            .expect("static response")
    })
    .await
}
