//! Fixture OAuth 2.0 authorization server and protected API for the
//! interactive authorization-code + PKCE flow (lab/test use only).
//!
//! * `GET /authorize` — validates the public client, the RFC 8252 loopback
//!   redirect (`http://127.0.0.1:<any port>/…`), `state` and an S256
//!   challenge, then answers with a 302 back to the loopback redirect. The
//!   "user" always approves as the configured subject unless a different
//!   [`AuthorizeBehavior`] is selected.
//! * `POST /token` — `authorization_code` (single-use code bound to client,
//!   redirect URI and PKCE challenge) and `refresh_token`. The fixture client
//!   is public, so `client_credentials` is refused — and every grant type seen
//!   is recorded so tests can prove which grants a client attempted.
//! * `GET /api/resource` — protected API: 200 only with a live bearer token
//!   issued here, otherwise 401 `invalid_token`.
//! * `GET /userinfo` — the subject/email bound to a live bearer token.
//!
//! [`simulate_browser`] plays the part of the system browser: it follows the
//! authorization redirect to the loopback listener exactly like a browser
//! navigation would.

use crate::tlsserver::{TlsServerOptions, server_config};
use base64::Engine;
use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use sha2::Digest;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

type Body = BoxBody<Bytes, Infallible>;

/// What the fixture "user" does at the authorization endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeBehavior {
    /// Approve and redirect back with `code` and the original `state`.
    Approve,
    /// Redirect back with a valid code but a different `state` (CSRF / mix-up).
    ForgeState,
    /// Redirect back with `error=access_denied`.
    Deny,
    /// Show a page and never redirect (the user walks away → client timeout).
    NoRedirect,
}

#[derive(Debug, Clone)]
pub struct IdpOptions {
    /// The registered public client id.
    pub client_id: String,
    /// Subject the fixture user authenticates as.
    pub subject: String,
    pub email: Option<String>,
    pub access_token_ttl_secs: u64,
    pub issue_refresh_tokens: bool,
    pub tls: Option<TlsServerOptions>,
}

impl Default for IdpOptions {
    fn default() -> Self {
        IdpOptions {
            client_id: "anvil-fixture-public-client".into(),
            subject: "fixture-user-1".into(),
            email: Some("fixture-user-1@idp.anvil.test".into()),
            access_token_ttl_secs: 3600,
            issue_refresh_tokens: true,
            tls: None,
        }
    }
}

struct IssuedCode {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    scope: String,
    issued: Instant,
}

struct AccessToken {
    expires: Instant,
    scope: String,
}

#[derive(Default)]
struct IdpState {
    client_id: String,
    subject: Mutex<String>,
    email: Mutex<Option<String>>,
    ttl_secs: Mutex<u64>,
    issue_refresh: bool,
    behavior: Mutex<Option<AuthorizeBehavior>>,
    token_endpoint_down: Mutex<bool>,
    codes: Mutex<HashMap<String, IssuedCode>>,
    access: Mutex<HashMap<String, AccessToken>>,
    refresh: Mutex<HashMap<String, String>>, // refresh token -> scope
    grants_seen: Mutex<Vec<String>>,
    authorize_requests: Mutex<u64>,
    api_requests: Mutex<(u64, u64)>, // (total, authorized)
    counter: std::sync::atomic::AtomicU64,
}

pub struct IdpFixture {
    pub addr: SocketAddr,
    pub tls: bool,
    state: Arc<IdpState>,
    cancel: CancellationToken,
}

impl Drop for IdpFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl IdpFixture {
    pub async fn start(opts: IdpOptions) -> anyhow::Result<IdpFixture> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(IdpState {
            client_id: opts.client_id,
            subject: Mutex::new(opts.subject),
            email: Mutex::new(opts.email),
            ttl_secs: Mutex::new(opts.access_token_ttl_secs),
            issue_refresh: opts.issue_refresh_tokens,
            ..Default::default()
        });
        let cancel = CancellationToken::new();
        let acceptor = match &opts.tls {
            Some(o) => Some(tokio_rustls::TlsAcceptor::from(server_config(o)?)),
            None => None,
        };
        let (s2, c2) = (state.clone(), cancel.clone());
        tokio::spawn(async move {
            loop {
                let (stream, _) = tokio::select! {
                    r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                    _ = c2.cancelled() => break,
                };
                let (state, acceptor, cancel) = (s2.clone(), acceptor.clone(), c2.clone());
                tokio::spawn(async move {
                    match acceptor {
                        Some(acc) => {
                            if let Ok(tls) = acc.accept(stream).await {
                                serve_conn(TokioIo::new(tls), state, cancel).await;
                            }
                        }
                        None => serve_conn(TokioIo::new(stream), state, cancel).await,
                    }
                });
            }
        });
        Ok(IdpFixture { addr, tls: opts.tls.is_some(), state, cancel })
    }

    pub fn url(&self, path: &str) -> String {
        // The lab server certificate carries 127.0.0.1 as an IP SAN.
        format!("{}://{}{path}", if self.tls { "https" } else { "http" }, self.addr)
    }

    pub fn client_id(&self) -> String {
        self.state.client_id.clone()
    }
    pub fn authorization_endpoint(&self) -> String {
        self.url("/authorize")
    }
    pub fn token_endpoint(&self) -> String {
        self.url("/token")
    }
    pub fn userinfo_endpoint(&self) -> String {
        self.url("/userinfo")
    }
    pub fn api_url(&self) -> String {
        self.url("/api/resource")
    }

    pub fn set_behavior(&self, b: AuthorizeBehavior) {
        *self.state.behavior.lock() = Some(b);
    }
    pub fn set_subject(&self, subject: &str, email: Option<&str>) {
        *self.state.subject.lock() = subject.to_string();
        *self.state.email.lock() = email.map(str::to_string);
    }
    pub fn set_access_token_ttl(&self, secs: u64) {
        *self.state.ttl_secs.lock() = secs;
    }
    pub fn set_token_endpoint_down(&self, down: bool) {
        *self.state.token_endpoint_down.lock() = down;
    }
    /// Revoke every refresh token (the next refresh gets `invalid_grant`).
    pub fn revoke_refresh_tokens(&self) {
        self.state.refresh.lock().clear();
    }
    /// Expire every access token now (without touching refresh tokens).
    pub fn expire_access_tokens(&self) {
        let now = Instant::now();
        for t in self.state.access.lock().values_mut() {
            t.expires = now;
        }
    }
    /// `grant_type` of every token request received, in order.
    pub fn grants_seen(&self) -> Vec<String> {
        self.state.grants_seen.lock().clone()
    }
    pub fn authorize_requests(&self) -> u64 {
        *self.state.authorize_requests.lock()
    }
    /// (total, authorized) protected-API requests.
    pub fn api_requests(&self) -> (u64, u64) {
        *self.state.api_requests.lock()
    }
    /// Whether this exact access token is live (tests compare against tokens
    /// they never print).
    pub fn is_live_access_token(&self, token: &str) -> bool {
        self.state.access.lock().get(token).map(|t| t.expires > Instant::now()).unwrap_or(false)
    }
}

async fn serve_conn<I>(io: I, state: Arc<IdpState>, cancel: CancellationToken)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(route(req, state).await) }
    });
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let conn = builder.serve_connection(io, svc);
    tokio::select! {
        _ = conn => {}
        _ = cancel.cancelled() => {}
    }
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).boxed()
}

fn json(status: u16, v: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(full(serde_json::to_vec(&v).unwrap_or_default()))
        .unwrap()
}

fn new_secret(state: &IdpState, prefix: &str) -> String {
    let n = state.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let digest = sha2::Sha256::digest(format!("{prefix}|{n}|{t}|{:p}", state as *const _).as_bytes());
    format!("{prefix}-{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..18]))
}

fn s256(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()))
}

/// RFC 8252 §7.3: loopback IP redirect, any port, http scheme.
fn loopback_redirect(uri: &str) -> Option<url::Url> {
    let u = url::Url::parse(uri).ok()?;
    let host_ok = matches!(u.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(u.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    (u.scheme() == "http" && host_ok && u.port().is_some() && u.fragment().is_none()).then_some(u)
}

fn bearer(req: &Request<Incoming>) -> Option<String> {
    req.headers().get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).map(str::to_string)
}

fn live_token(state: &IdpState, token: Option<&str>) -> Option<String> {
    let t = token?;
    let access = state.access.lock();
    let a = access.get(t)?;
    (a.expires > Instant::now()).then(|| a.scope.clone())
}

async fn route(req: Request<Incoming>, state: Arc<IdpState>) -> Response<Body> {
    let path = req.uri().path().to_string();
    let qs: HashMap<String, String> =
        req.uri().query().map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect()).unwrap_or_default();
    match (req.method().clone(), path.as_str()) {
        (Method::GET, "/authorize") => authorize(&state, &qs),
        (Method::POST, "/token") => {
            let basic = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
            let body = match Limited::new(req.into_body(), 64 * 1024).collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => return json(413, serde_json::json!({"error": "invalid_request"})),
            };
            token(&state, basic.as_deref(), &body)
        }
        (Method::GET, "/api/resource") => {
            let t = bearer(&req);
            let scope = live_token(&state, t.as_deref());
            let mut c = state.api_requests.lock();
            c.0 += 1;
            match scope {
                Some(scope) => {
                    c.1 += 1;
                    json(200, serde_json::json!({"resource": "fixture", "sub": *state.subject.lock(), "scope": scope}))
                }
                None => Response::builder()
                    .status(401)
                    .header("www-authenticate", "Bearer error=\"invalid_token\"")
                    .header("content-type", "application/json")
                    .body(full("{\"error\":\"invalid_token\"}"))
                    .unwrap(),
            }
        }
        (Method::GET, "/userinfo") => match live_token(&state, bearer(&req).as_deref()) {
            Some(_) => json(200, serde_json::json!({"sub": *state.subject.lock(), "email": *state.email.lock()})),
            None => json(401, serde_json::json!({"error": "invalid_token"})),
        },
        _ => json(404, serde_json::json!({"error": "no fixture route"})),
    }
}

fn authorize(state: &IdpState, qs: &HashMap<String, String>) -> Response<Body> {
    *state.authorize_requests.lock() += 1;
    let get = |k: &str| qs.get(k).map(String::as_str).unwrap_or("");
    // Errors before the redirect URI is trusted are shown, never redirected (RFC 6749 §4.1.2.1).
    if get("client_id") != state.client_id {
        return json(400, serde_json::json!({"error": "unauthorized_client"}));
    }
    let Some(redirect) = loopback_redirect(get("redirect_uri")) else {
        return json(
            400,
            serde_json::json!({"error": "invalid_request", "error_description": "redirect_uri must be an http loopback IP URI"}),
        );
    };
    let back = |params: &[(&str, &str)]| {
        let mut u = redirect.clone();
        {
            let mut q = u.query_pairs_mut();
            for (k, v) in params {
                q.append_pair(k, v);
            }
        }
        Response::builder().status(302).header("location", u.to_string()).header("cache-control", "no-store").body(full("")).unwrap()
    };
    let st = get("state");
    if get("response_type") != "code" || st.is_empty() {
        return back(&[("error", "invalid_request"), ("state", st)]);
    }
    if get("code_challenge_method") != "S256" || get("code_challenge").len() < 43 {
        return back(&[("error", "invalid_request"), ("state", st)]);
    }
    let behavior = state.behavior.lock().unwrap_or(AuthorizeBehavior::Approve);
    match behavior {
        AuthorizeBehavior::NoRedirect => {
            Response::builder().status(200).header("content-type", "text/html").body(full("<p>Waiting for the user…</p>")).unwrap()
        }
        AuthorizeBehavior::Deny => back(&[("error", "access_denied"), ("state", st)]),
        AuthorizeBehavior::Approve | AuthorizeBehavior::ForgeState => {
            let code = new_secret(state, "fx-code");
            state.codes.lock().insert(
                code.clone(),
                IssuedCode {
                    client_id: state.client_id.clone(),
                    redirect_uri: get("redirect_uri").to_string(),
                    challenge: get("code_challenge").to_string(),
                    scope: get("scope").to_string(),
                    issued: Instant::now(),
                },
            );
            let forged;
            let returned_state = if behavior == AuthorizeBehavior::ForgeState {
                forged = format!("forged-{}", new_secret(state, "st"));
                forged.as_str()
            } else {
                st
            };
            back(&[("code", code.as_str()), ("state", returned_state)])
        }
    }
}

fn issue(state: &IdpState, scope: &str, with_refresh: bool) -> Response<Body> {
    let access = new_secret(state, "fx-at");
    let ttl = *state.ttl_secs.lock();
    state
        .access
        .lock()
        .insert(access.clone(), AccessToken { expires: Instant::now() + Duration::from_secs(ttl), scope: scope.to_string() });
    let mut body = serde_json::json!({"access_token": access, "token_type": "Bearer", "expires_in": ttl, "scope": scope});
    if with_refresh {
        let rt = new_secret(state, "fx-rt");
        state.refresh.lock().insert(rt.clone(), scope.to_string());
        body["refresh_token"] = serde_json::Value::String(rt);
    }
    json(200, body)
}

fn token(state: &IdpState, basic: Option<&str>, body: &[u8]) -> Response<Body> {
    let form: HashMap<String, String> = url::form_urlencoded::parse(body).into_owned().collect();
    let grant = form.get("grant_type").cloned().unwrap_or_default();
    state.grants_seen.lock().push(grant.clone());
    if *state.token_endpoint_down.lock() {
        return json(503, serde_json::json!({"error": "temporarily_unavailable"}));
    }
    let basic_client = basic
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|d| String::from_utf8(d).ok())
        .and_then(|s| s.split_once(':').map(|(a, _)| a.to_string()));
    let client_id = basic_client.or_else(|| form.get("client_id").cloned()).unwrap_or_default();
    if client_id != state.client_id {
        return json(401, serde_json::json!({"error": "invalid_client"}));
    }
    match grant.as_str() {
        "authorization_code" => {
            let code = form.get("code").cloned().unwrap_or_default();
            // Single use: removed whether or not the rest matches.
            let Some(c) = state.codes.lock().remove(&code) else {
                return json(400, serde_json::json!({"error": "invalid_grant", "error_description": "unknown or reused code"}));
            };
            let verifier = form.get("code_verifier").map(String::as_str).unwrap_or("");
            if c.client_id != client_id
                || form.get("redirect_uri").map(String::as_str) != Some(c.redirect_uri.as_str())
                || s256(verifier) != c.challenge
                || c.issued.elapsed() > Duration::from_secs(600)
            {
                return json(400, serde_json::json!({"error": "invalid_grant", "error_description": "PKCE, redirect or client mismatch"}));
            }
            issue(state, &c.scope, state.issue_refresh)
        }
        "refresh_token" => {
            let rt = form.get("refresh_token").cloned().unwrap_or_default();
            let scope = state.refresh.lock().get(&rt).cloned();
            match scope {
                // No rotation: the client keeps using its refresh token (RFC 6749 §6).
                Some(scope) => issue(state, &scope, false),
                None => json(400, serde_json::json!({"error": "invalid_grant"})),
            }
        }
        _ => json(
            400,
            serde_json::json!({"error": "unauthorized_client", "error_description": "public client: only authorization_code and refresh_token"}),
        ),
    }
}

// ------------------------------------------------------------------ simulated browser

/// One navigation chain, as a browser would follow it.
#[derive(Debug, Clone)]
pub struct BrowserVisit {
    /// Every URL requested, in order.
    pub hops: Vec<String>,
    pub final_status: u16,
    pub final_headers: Vec<(String, String)>,
    pub final_body: String,
}

impl BrowserVisit {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.final_headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// GET `url` and follow up to five redirects like a browser tab would.
/// `trust_ca_pem` is the root for https hops (the lab CA).
pub async fn simulate_browser(url: &str, trust_ca_pem: Option<&str>) -> anyhow::Result<BrowserVisit> {
    let mut current = url::Url::parse(url)?;
    let mut hops = Vec::new();
    for _ in 0..6 {
        hops.push(current.to_string());
        let (status, headers, body) = get_once(&current, trust_ca_pem).await?;
        if (300..400).contains(&status)
            && let Some(loc) = headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("location")).map(|(_, v)| v.clone())
        {
            current = current.join(&loc)?;
            continue;
        }
        return Ok(BrowserVisit { hops, final_status: status, final_headers: headers, final_body: body });
    }
    anyhow::bail!("too many redirects")
}

/// Raw single request (HTTP/1.1, `Connection: close`) — also used by tests
/// to play a stray or hostile local client against a loopback listener.
pub async fn raw_get(url: &str, host_header: Option<&str>) -> anyhow::Result<(u16, Vec<(String, String)>, String)> {
    let u = url::Url::parse(url)?;
    let host = u.host_str().ok_or_else(|| anyhow::anyhow!("no host"))?.trim_matches(['[', ']']).to_string();
    let port = u.port_or_known_default().unwrap_or(80);
    let mut s: Box<dyn Io> = Box::new(TcpStream::connect((host.as_str(), port)).await?);
    let target = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    };
    let authority = host_header.map(str::to_string).unwrap_or_else(|| format!("{}:{port}", u.host_str().unwrap_or_default()));
    request(&mut s, &target, &authority).await
}

async fn get_once(u: &url::Url, trust_ca_pem: Option<&str>) -> anyhow::Result<(u16, Vec<(String, String)>, String)> {
    let host = u.host_str().ok_or_else(|| anyhow::anyhow!("no host"))?.trim_matches(['[', ']']).to_string();
    let port = u.port_or_known_default().unwrap_or(80);
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let mut s: Box<dyn Io> = if u.scheme() == "https" {
        let mut roots = rustls::RootCertStore::empty();
        for c in crate::tlsserver::certs(trust_ca_pem.unwrap_or_default()) {
            roots.add(c)?;
        }
        let cfg = rustls::ClientConfig::builder_with_provider(crate::tlsserver::provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls_pki_types::ServerName::try_from(host.clone())?;
        Box::new(tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?)
    } else {
        Box::new(tcp)
    };
    let target = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    };
    let authority = match u.port() {
        Some(p) => format!("{}:{p}", u.host_str().unwrap_or_default()),
        None => u.host_str().unwrap_or_default().to_string(),
    };
    request(&mut s, &target, &authority).await
}

async fn request(s: &mut Box<dyn Io>, target: &str, authority: &str) -> anyhow::Result<(u16, Vec<(String, String)>, String)> {
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: anvil-fixture-browser\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.take(1 << 20).read_to_end(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).unwrap_or(0);
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(n, v)| (n.trim().to_string(), v.trim().to_string())).collect();
    Ok((status, headers, body.to_string()))
}
