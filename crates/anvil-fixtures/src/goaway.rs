//! HTTP/2 (h2c, prior knowledge) fixture that shuts its first connection
//! down with GOAWAY while a request stream is in flight. Later connections
//! answer normally, so a safe retry on a new connection can succeed.

use crate::log::{GroundTruth, GroundTruthLog};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub struct GoAwayFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    /// Streams accepted per connection, in order (ground truth).
    pub streams_seen: Arc<AtomicUsize>,
    cancel: CancellationToken,
}

impl Drop for GoAwayFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl GoAwayFixture {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

pub async fn serve(bind: &str) -> anyhow::Result<GoAwayFixture> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let streams_seen = Arc::new(AtomicUsize::new(0));
    let conns = Arc::new(AtomicUsize::new(0));
    let (l2, c2, s2) = (log.clone(), cancel.clone(), streams_seen.clone());
    tokio::spawn(async move {
        loop {
            let (sock, peer) = tokio::select! {
                _ = c2.cancelled() => return,
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
            };
            l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
            let nth = conns.fetch_add(1, Ordering::SeqCst);
            let (log, seen) = (l2.clone(), s2.clone());
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::handshake(sock).await else { return };
                if nth == 0 {
                    // First connection: accept one request stream, then GOAWAY
                    // (NO_ERROR) and close without answering it.
                    if let Some(Ok((req, _respond))) = conn.accept().await {
                        seen.fetch_add(1, Ordering::SeqCst);
                        log.push(GroundTruth::RequestReceived {
                            method: req.method().to_string(),
                            path: req.uri().path().to_string(),
                            body_bytes: 0,
                            headers: vec![],
                        });
                        // Read the whole request (drive the connection while
                        // doing so) so the client is waiting for headers when
                        // the GOAWAY arrives, then shut down without answering.
                        let mut body = req.into_body();
                        let read = async {
                            while let Some(chunk) = body.data().await {
                                if let Ok(c) = chunk {
                                    let _ = body.flow_control().release_capacity(c.len());
                                }
                            }
                        };
                        tokio::select! {
                            _ = read => {}
                            _ = std::future::poll_fn(|cx| conn.poll_closed(cx)) => return,
                        }
                        conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                        let _ =
                            tokio::time::timeout(std::time::Duration::from_secs(2), std::future::poll_fn(|cx| conn.poll_closed(cx))).await;
                    }
                    return;
                }
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    seen.fetch_add(1, Ordering::SeqCst);
                    log.push(GroundTruth::RequestReceived {
                        method: req.method().to_string(),
                        path: req.uri().path().to_string(),
                        body_bytes: 0,
                        headers: vec![],
                    });
                    let resp = http::Response::builder().status(200).header("content-type", "text/plain").body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from_static(b"ok after goaway"), true);
                    }
                }
            });
        }
    });
    Ok(GoAwayFixture { addr, log, streams_seen, cancel })
}
