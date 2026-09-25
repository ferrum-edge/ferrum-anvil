//! A strictly HTTP/1.1 fixture server (no h2c, no TLS).
//!
//! Ferrum Edge probes plain-HTTP backends with an h2c prior-knowledge
//! connection at startup (`FERRUM_POOL_WARMUP_ENABLED=false` does not stop the
//! capability probe). The general fixture in [`crate::http`] speaks h2c, so
//! the probe succeeds and the gateway keeps that connection in its direct-H2
//! pool. Where a scenario needs the gateway's reqwest HTTP/1.1 lane — and an
//! exact count of physical backend connections, as with a DestinationRule
//! `maxConnections` ceiling — the backend must refuse h2c the way a
//! plain HTTP/1.1 application server does.
//!
//! Routes: `/` (200), `/delay-headers/{ms}` (wait, then 200),
//! `/status/{code}?body=…` (arbitrary status, JSON body).

use crate::log::{GroundTruth, GroundTruthLog};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub struct Http1Fixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    cancel: CancellationToken,
}

impl Drop for Http1Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn reply(status: u16, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

async fn route(req: Request<Incoming>, log: GroundTruthLog) -> Response<Full<Bytes>> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let target = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| path.clone());
    let query: Vec<(String, String)> = req
        .uri()
        .query()
        .map(|q| url::form_urlencoded::parse(q.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect())
        .unwrap_or_default();
    let headers = req.headers().iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    let body_len = Limited::new(req.into_body(), 1024 * 1024).collect().await.map(|b| b.to_bytes().len()).unwrap_or(0);
    log.push(GroundTruth::RequestReceived { method, path: target, body_bytes: body_len as u64, headers });
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let resp = match segs.as_slice() {
        ["delay-headers", ms] => {
            let ms: u64 = ms.parse::<u64>().unwrap_or(0).min(60_000);
            tokio::time::sleep(Duration::from_millis(ms)).await;
            reply(200, format!("{{\"delayed_ms\":{ms},\"source\":\"fixture-backend\"}}"))
        }
        ["status", code] => {
            let code = code.parse::<u16>().ok().filter(|c| (200..=599).contains(c)).unwrap_or(500);
            let body = query
                .iter()
                .find(|(k, _)| k == "body")
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| format!("{{\"status\":{code},\"source\":\"fixture-backend\"}}"));
            reply(code, body)
        }
        _ => reply(200, "{\"source\":\"fixture-backend\"}".into()),
    };
    log.push(GroundTruth::ResponseStarted { status: resp.status().as_u16() });
    resp
}

/// Start the HTTP/1.1-only fixture. An h2c preface is answered as a
/// malformed HTTP/1.1 request, exactly like an ordinary HTTP/1.1 server.
pub async fn serve(bind: &str) -> anyhow::Result<Http1Fixture> {
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
            let (log, cancel) = (l2.clone(), c2.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let log = log.clone();
                    async move { Ok::<_, Infallible>(route(req, log).await) }
                });
                let conn = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc);
                tokio::select! {
                    _ = conn => {}
                    _ = cancel.cancelled() => {}
                }
            });
        }
    });
    Ok(Http1Fixture { addr, log, cancel })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn raw(addr: SocketAddr, bytes: &[u8]) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(bytes).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn serves_http1_and_rejects_the_h2c_preface() {
        let f = serve("127.0.0.1:0").await.unwrap();
        let ok = raw(f.addr, b"GET /status/503?body=%7B%7D HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        assert!(ok.starts_with("HTTP/1.1 503"), "{ok}");
        let h2c = raw(f.addr, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
        assert!(!h2c.contains("\0\0"), "no HTTP/2 SETTINGS frame is sent back: {h2c:?}");
        assert_eq!(f.log.count_requests(), 1, "the preface is not a request");
    }
}
