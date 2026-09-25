//! Local identity-provider fixture for the real-gateway auth lab: a JWKS
//! document, an RFC 7662 token-introspection endpoint and an RFC 6749
//! client-credentials token endpoint, with controllable outage modes.
//!
//! It is protocol-faithful for the gateway plugins that consume it
//! (`jwks_auth`, `oauth2_introspection`) and for Anvil's OAuth client; it
//! verifies adapter behaviour, not any real provider's availability. Keys and
//! tokens are minted by the lab per run; nothing here is a real credential.
//!
//! Routes:
//! * `GET /.well-known/jwks.json` — the configured JWKS document
//! * `POST /introspect` — `token=<t>` form; known tokens answer their stored
//!   claims (with `active: true`), unknown tokens `{"active": false}`
//! * `POST /oauth/token` — `grant_type=client_credentials` (Basic or form
//!   client authentication); issues an opaque token that `/introspect` knows

use crate::log::{GroundTruth, GroundTruthLog};
use base64::Engine;
use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// How the fixture answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IdpMode {
    #[default]
    Up,
    /// Every endpoint answers 503 (provider outage).
    Down,
    /// Every endpoint holds the request for 30 s (provider timeout).
    Stall,
}

pub struct IdpState {
    pub jwks: Mutex<serde_json::Value>,
    /// token → introspection claims (without `active`).
    pub tokens: Mutex<HashMap<String, serde_json::Value>>,
    pub mode: Mutex<IdpMode>,
    pub client_id: String,
    pub client_secret: String,
    /// Claims attached to tokens issued by `/oauth/token`.
    pub issued_claims: Mutex<serde_json::Value>,
    pub jwks_fetches: AtomicU64,
    pub introspections: AtomicU64,
    pub token_requests: AtomicU64,
}

pub struct IdpFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    pub state: Arc<IdpState>,
    cancel: CancellationToken,
}

impl Drop for IdpFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl IdpFixture {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub fn set_mode(&self, m: IdpMode) {
        *self.state.mode.lock() = m;
    }

    /// Register an opaque token with its introspection claims.
    pub fn register_token(&self, token: &str, claims: serde_json::Value) {
        self.state.tokens.lock().insert(token.to_string(), claims);
    }

    pub fn jwks_fetches(&self) -> u64 {
        self.state.jwks_fetches.load(Ordering::SeqCst)
    }

    pub fn introspections(&self) -> u64 {
        self.state.introspections.load(Ordering::SeqCst)
    }

    pub fn token_requests(&self) -> u64 {
        self.state.token_requests.load(Ordering::SeqCst)
    }
}

type Body = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn json(status: u16, v: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(serde_json::to_vec(&v).unwrap_or_default())).boxed())
        .expect("response")
}

/// Start the IdP. `jwks` is served verbatim; `client_id`/`client_secret`
/// authenticate `/oauth/token`.
pub async fn serve(bind: &str, jwks: serde_json::Value, client_id: &str, client_secret: &str) -> anyhow::Result<IdpFixture> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let state = Arc::new(IdpState {
        jwks: Mutex::new(jwks),
        tokens: Mutex::new(HashMap::new()),
        mode: Mutex::new(IdpMode::Up),
        client_id: client_id.into(),
        client_secret: client_secret.into(),
        issued_claims: Mutex::new(serde_json::json!({})),
        jwks_fetches: AtomicU64::new(0),
        introspections: AtomicU64::new(0),
        token_requests: AtomicU64::new(0),
    });
    let cancel = CancellationToken::new();
    let (l2, s2, c2) = (log.clone(), state.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
            let (log, state, cancel) = (l2.clone(), s2.clone(), c2.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let (log, state) = (log.clone(), state.clone());
                    async move { Ok::<_, Infallible>(route(req, log, state).await) }
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
    Ok(IdpFixture { addr, log, state, cancel })
}

async fn route(req: Request<Incoming>, log: GroundTruthLog, state: Arc<IdpState>) -> Response<Body> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Header names only: authorization values are credentials.
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(n, v)| {
            let value =
                if n == http::header::AUTHORIZATION { "‹redacted›".to_string() } else { String::from_utf8_lossy(v.as_bytes()).into() };
            (n.as_str().to_string(), value)
        })
        .collect();
    let basic = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|d| String::from_utf8(d).ok());
    let body = match Limited::new(req.into_body(), 64 * 1024).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return json(413, serde_json::json!({"error": "request too large"})),
    };
    log.push(GroundTruth::RequestReceived { method: method.to_string(), path: path.clone(), body_bytes: body.len() as u64, headers });
    let mode = *state.mode.lock();
    let counter = match path.as_str() {
        "/.well-known/jwks.json" => Some(&state.jwks_fetches),
        "/introspect" => Some(&state.introspections),
        "/oauth/token" => Some(&state.token_requests),
        _ => None,
    };
    if let Some(c) = counter {
        c.fetch_add(1, Ordering::SeqCst);
    }
    match mode {
        IdpMode::Down => {
            log.push(GroundTruth::FaultApplied { fault: "idp_down_503".into() });
            return json(503, serde_json::json!({"error": "temporarily_unavailable"}));
        }
        IdpMode::Stall => {
            log.push(GroundTruth::FaultApplied { fault: "idp_stall".into() });
            tokio::time::sleep(Duration::from_secs(30)).await;
            return json(503, serde_json::json!({"error": "temporarily_unavailable"}));
        }
        IdpMode::Up => {}
    }
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let resp = match (method, path.as_str()) {
        (Method::GET, "/.well-known/jwks.json") => json(200, state.jwks.lock().clone()),
        (Method::POST, "/introspect") => {
            let token = form.get("token").cloned().unwrap_or_default();
            match state.tokens.lock().get(&token) {
                Some(claims) => {
                    let mut v = claims.clone();
                    if let Some(o) = v.as_object_mut() {
                        o.insert("active".into(), true.into());
                    }
                    json(200, v)
                }
                None => json(200, serde_json::json!({"active": false})),
            }
        }
        (Method::POST, "/oauth/token") => {
            let (cid, csec) = match basic.as_deref().and_then(|s| s.split_once(':')) {
                Some((a, b)) => (a.to_string(), b.to_string()),
                None => (form.get("client_id").cloned().unwrap_or_default(), form.get("client_secret").cloned().unwrap_or_default()),
            };
            if form.get("grant_type").map(String::as_str) != Some("client_credentials") {
                json(400, serde_json::json!({"error": "unsupported_grant_type"}))
            } else if cid != state.client_id || csec != state.client_secret {
                json(401, serde_json::json!({"error": "invalid_client"}))
            } else {
                let mut b = [0u8; 16];
                rand_fill(&mut b);
                let token = format!("idp-at-{}", hex_lower(&b));
                let mut claims = state.issued_claims.lock().clone();
                if let Some(o) = claims.as_object_mut() {
                    o.insert("client_id".into(), cid.into());
                    o.insert("token_type".into(), "bearer".into());
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                    o.insert("exp".into(), (now + 300).into());
                }
                state.tokens.lock().insert(token.clone(), claims);
                json(200, serde_json::json!({"access_token": token, "token_type": "Bearer", "expires_in": 300}))
            }
        }
        _ => json(404, serde_json::json!({"error": "no idp route", "path": path})),
    };
    log.push(GroundTruth::ResponseStarted { status: resp.status().as_u16() });
    resp
}

fn rand_fill(b: &mut [u8]) {
    // Uniqueness, not secrecy: lab tokens only need to differ per issue.
    static C: AtomicU64 = AtomicU64::new(1);
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
        ^ C.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let mut x = seed | 1;
    for byte in b.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *byte = x as u8;
    }
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
