//! Protocol-faithful mocks for gateway policy dependencies: an OPA decision
//! API and an OpenAI-style chat-completions provider.
//!
//! They exercise the gateway's *adapter* behaviour against a controlled local
//! dependency (lab/test use only). They say nothing about the availability of
//! any real policy service or AI provider.
//!
//! * OPA: `POST /v1/data/{policy_path}` with `{"input": …}` answers
//!   `{"result": true}` when the last path segment is `allow`, `{"result":
//!   false}` for `deny`, and `{}` (undefined decision) otherwise. While
//!   [`OpaMock::set_failing`] is on, every query answers HTTP 500.
//! * AI provider: `POST …/chat/completions` answers a `chat.completion`
//!   object echoing the requested `model`, with fixed `usage` (see
//!   [`AiProviderMock::set_usage`]) and `reply` text. `…/error/{status}`
//!   answers an OpenAI-style error envelope with that status.

use crate::log::{GroundTruth, GroundTruthLog};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const MAX_BODY: usize = 1024 * 1024;

/// One decision query the OPA mock answered (ground truth; never shown to
/// the diagnostic engine).
#[derive(Debug, Clone)]
pub struct OpaQuery {
    pub policy_path: String,
    pub input: serde_json::Value,
    pub status: u16,
}

#[derive(Default)]
struct OpaState {
    queries: Mutex<Vec<OpaQuery>>,
    failing: Mutex<bool>,
}

pub struct OpaMock {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    state: Arc<OpaState>,
    cancel: CancellationToken,
}

impl Drop for OpaMock {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl OpaMock {
    pub fn queries(&self) -> Vec<OpaQuery> {
        self.state.queries.lock().clone()
    }

    pub fn query_count(&self) -> usize {
        self.state.queries.lock().len()
    }

    /// Answer every decision query with HTTP 500 while `true`.
    pub fn set_failing(&self, failing: bool) {
        *self.state.failing.lock() = failing;
    }
}

/// One chat-completion (or error) the AI provider mock answered.
#[derive(Debug, Clone)]
pub struct AiCall {
    pub path: String,
    pub model: Option<String>,
    pub status: u16,
    pub total_tokens: u64,
}

struct AiState {
    calls: Mutex<Vec<AiCall>>,
    usage: Mutex<(u64, u64)>,
    reply: Mutex<String>,
}

pub struct AiProviderMock {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    state: Arc<AiState>,
    cancel: CancellationToken,
}

impl Drop for AiProviderMock {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl AiProviderMock {
    pub fn calls(&self) -> Vec<AiCall> {
        self.state.calls.lock().clone()
    }

    pub fn call_count(&self) -> usize {
        self.state.calls.lock().len()
    }

    /// Token usage reported on every successful completion (prompt, completion).
    pub fn set_usage(&self, prompt: u64, completion: u64) {
        *self.state.usage.lock() = (prompt, completion);
    }

    /// Assistant message text returned on successful completions.
    pub fn set_reply(&self, reply: &str) {
        *self.state.reply.lock() = reply.to_string();
    }
}

fn json(status: u16, v: &serde_json::Value, extra: &[(&str, &str)]) -> Response<Full<Bytes>> {
    let mut b = Response::builder().status(status).header("content-type", "application/json");
    for (k, val) in extra {
        b = b.header(*k, *val);
    }
    b.body(Full::new(Bytes::from(serde_json::to_vec(v).unwrap_or_default()))).unwrap()
}

async fn read_body(req: Request<Incoming>) -> (String, String, Vec<(String, String)>, Option<Bytes>) {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let headers = req.headers().iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    let body = Limited::new(req.into_body(), MAX_BODY).collect().await.ok().map(|b| b.to_bytes());
    (method, path, headers, body)
}

async fn accept_loop<F, Fut>(listener: TcpListener, log: GroundTruthLog, cancel: CancellationToken, handler: F)
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
            _ = cancel.cancelled() => break,
        };
        let _ = stream.set_nodelay(true);
        log.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
        let (handler, cancel) = (handler.clone(), cancel.clone());
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let h = handler.clone();
                async move { Ok::<_, Infallible>(h(req).await) }
            });
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection(TokioIo::new(stream), svc);
            tokio::select! {
                _ = conn => {}
                _ = cancel.cancelled() => {}
            }
        });
    }
}

/// Start the OPA decision-API mock.
pub async fn serve_opa(bind: &str) -> anyhow::Result<OpaMock> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let state = Arc::new(OpaState::default());
    let cancel = CancellationToken::new();
    let (l2, s2) = (log.clone(), state.clone());
    let handler = move |req: Request<Incoming>| {
        let (log, state) = (l2.clone(), s2.clone());
        async move {
            let (method, path, headers, body) = read_body(req).await;
            let body = body.unwrap_or_default();
            log.push(GroundTruth::RequestReceived { method: method.clone(), path: path.clone(), body_bytes: body.len() as u64, headers });
            let Some(policy_path) = path.strip_prefix("/v1/data/").map(|p| p.to_string()).filter(|_| method == "POST") else {
                log.push(GroundTruth::ResponseStarted { status: 404 });
                return json(404, &serde_json::json!({"code": "resource_not_found", "message": "unknown fixture path"}), &[]);
            };
            let input = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("input").cloned())
                .unwrap_or(serde_json::Value::Null);
            let (status, answer) = if *state.failing.lock() {
                (500, serde_json::json!({"code": "internal_error", "message": "fixture policy engine failure"}))
            } else {
                match policy_path.rsplit('/').next() {
                    Some("allow") => (200, serde_json::json!({"result": true})),
                    Some("deny") => (200, serde_json::json!({"result": false})),
                    _ => (200, serde_json::json!({})),
                }
            };
            state.queries.lock().push(OpaQuery { policy_path, input, status });
            log.push(GroundTruth::ResponseStarted { status });
            json(status, &answer, &[])
        }
    };
    tokio::spawn(accept_loop(listener, log.clone(), cancel.clone(), handler));
    Ok(OpaMock { addr, log, state, cancel })
}

/// Start the OpenAI-style provider mock.
pub async fn serve_ai_provider(bind: &str) -> anyhow::Result<AiProviderMock> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let state = Arc::new(AiState {
        calls: Mutex::new(vec![]),
        usage: Mutex::new((20, 10)),
        reply: Mutex::new("Hello from the Anvil lab provider mock.".into()),
    });
    let cancel = CancellationToken::new();
    let (l2, s2) = (log.clone(), state.clone());
    let handler = move |req: Request<Incoming>| {
        let (log, state) = (l2.clone(), s2.clone());
        async move {
            let (method, path, headers, body) = read_body(req).await;
            let body = body.unwrap_or_default();
            log.push(GroundTruth::RequestReceived { method: method.clone(), path: path.clone(), body_bytes: body.len() as u64, headers });
            let model = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(String::from));
            let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            let (status, resp, total) = match segs.as_slice() {
                [.., "error", code] => {
                    let status: u16 = code.parse().ok().filter(|s| (400..=599).contains(s)).unwrap_or(500);
                    let (kind, code, message) = match status {
                        429 => ("requests", "rate_limit_exceeded", "Rate limit reached for requests. Please try again in 1s."),
                        503 => ("server_error", "overloaded", "The provider is currently overloaded. Please retry."),
                        _ => ("server_error", "internal_error", "The provider had an error while processing your request."),
                    };
                    let v = serde_json::json!({"error": {"message": message, "type": kind, "param": null, "code": code}});
                    let extra: &[(&str, &str)] = if status == 429 { &[("retry-after", "1")] } else { &[] };
                    (status, json(status, &v, extra), 0)
                }
                [.., "chat", "completions"] if method == "POST" => {
                    let (p, c) = *state.usage.lock();
                    let reply = state.reply.lock().clone();
                    let v = serde_json::json!({
                        "id": "chatcmpl-anvil-lab",
                        "object": "chat.completion",
                        "created": 1_790_000_000u64,
                        "model": model.clone().unwrap_or_else(|| "unknown".into()),
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c},
                    });
                    (200, json(200, &v, &[]), p + c)
                }
                _ => (
                    404,
                    json(404, &serde_json::json!({"error": {"message": "unknown fixture route", "type": "invalid_request_error"}}), &[]),
                    0,
                ),
            };
            state.calls.lock().push(AiCall { path, model, status, total_tokens: total });
            log.push(GroundTruth::ResponseStarted { status });
            resp
        }
    };
    tokio::spawn(accept_loop(listener, log.clone(), cancel.clone(), handler));
    Ok(AiProviderMock { addr, log, state, cancel })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn post(addr: SocketAddr, path: &str, body: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn opa_mock_answers_by_policy_name_and_records_input() {
        let m = serve_opa("127.0.0.1:0").await.unwrap();
        assert!(post(m.addr, "/v1/data/lab/allow", r#"{"input":{"a":1}}"#).await.ends_with(r#"{"result":true}"#));
        assert!(post(m.addr, "/v1/data/lab/deny", r#"{"input":{}}"#).await.ends_with(r#"{"result":false}"#));
        m.set_failing(true);
        assert!(post(m.addr, "/v1/data/lab/allow", r#"{"input":{}}"#).await.starts_with("HTTP/1.1 500"));
        let q = m.queries();
        assert_eq!(q.len(), 3);
        assert_eq!(q[0].input, serde_json::json!({"a": 1}));
    }

    #[tokio::test]
    async fn ai_mock_reports_usage_and_provider_errors() {
        let m = serve_ai_provider("127.0.0.1:0").await.unwrap();
        m.set_usage(25, 5);
        let ok = post(m.addr, "/v1/chat/completions", r#"{"model":"gpt-4","messages":[]}"#).await;
        assert!(ok.contains(r#""total_tokens":30"#) && ok.contains(r#""model":"gpt-4""#), "{ok}");
        let e = post(m.addr, "/v1/error/429", "{}").await;
        assert!(e.starts_with("HTTP/1.1 429") && e.contains("rate_limit_exceeded"), "{e}");
        assert_eq!(m.call_count(), 2);
    }
}
