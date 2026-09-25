//! Anvil's shared execution engine.
//!
//! The same code prepares and executes a request for the desktop app, the
//! CLI, the collection runner and load workers, so "manual Send succeeds but
//! load sends different bytes" cannot happen by construction.

pub mod assertions;
pub mod context;
mod h3_exec;
pub mod http_exec;
pub mod lint;
mod local_checks;
mod oauth_http;
mod pkcs12;
pub mod prepare;
pub mod record;
pub mod redact;
pub mod settings;
pub mod vars;

use anvil_domain::execution::{ExecutionRecord, ResponseRecord, TransportFailure};
use anvil_domain::request::Protocol;
use anvil_transport::http::HttpTransport;
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{PreparedTls, TlsSettings};
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub use context::ExecutionContext;

/// Result of one execution.
#[derive(Debug, Clone)]
pub struct ExecutionOutput {
    pub record: ExecutionRecord,
    /// Raw captured response bytes (bounded by the capture limit).
    pub body: Bytes,
    /// Decoded (decompressed) bytes when a content-coding was applied.
    pub decoded_body: Option<Bytes>,
    /// Iteration-local extracted variables: (name, value, sensitive).
    pub extracted: Vec<(String, String, bool)>,
}

pub struct Engine {
    pub http: HttpTransport,
    pub h3: anvil_transport::h3::H3Transport,
    pub tokens: Arc<anvil_auth::oauth::TokenCache>,
    tls: Mutex<HashMap<String, Arc<PreparedTls>>>,
    cookies: Mutex<HashMap<String, cookie_store::CookieStore>>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        anvil_transport::init();
        Engine {
            http: HttpTransport::new(),
            h3: anvil_transport::h3::H3Transport::new(),
            tokens: Arc::new(anvil_auth::oauth::TokenCache::new()),
            tls: Mutex::new(HashMap::new()),
            cookies: Mutex::new(HashMap::new()),
        }
    }

    /// Execute a request of any supported protocol.
    pub async fn execute(&self, ctx: &ExecutionContext, events: EventCtx, cancel: CancellationToken) -> ExecutionOutput {
        match ctx.spec.protocol {
            Protocol::Http => http_exec::execute(self, ctx, events, cancel).await,
            _ => {
                let resolver = vars::Resolver::new(ctx.var_layers.clone(), ctx.seed);
                let f = TransportFailure::new(
                    anvil_domain::execution::Phase::Prepare,
                    anvil_domain::execution::FailureKind::UnsupportedCombination,
                    format!("{:?} execution is handled by its session adapter", ctx.spec.protocol),
                );
                record::local_failure(ctx, &resolver, chrono::Utc::now(), f)
            }
        }
    }

    /// Validated TLS material, cached by profile key.
    pub fn prepared_tls(&self, key: &str, s: &TlsSettings) -> Result<Arc<PreparedTls>, TransportFailure> {
        if let Some(p) = self.tls.lock().get(key) {
            return Ok(p.clone());
        }
        let p = Arc::new(anvil_transport::tls::prepare(s)?);
        self.tls.lock().insert(key.to_string(), p.clone());
        Ok(p)
    }

    pub fn cookie_header(&self, isolation: &str, t: &prepare::Target) -> Option<String> {
        let url = url::Url::parse(&t.url()).ok()?;
        let jars = self.cookies.lock();
        let jar = jars.get(isolation)?;
        let pairs: Vec<String> = jar.get_request_values(&url).map(|(n, v)| format!("{n}={v}")).collect();
        if pairs.is_empty() { None } else { Some(pairs.join("; ")) }
    }

    pub fn store_cookies(&self, isolation: &str, t: &prepare::Target, r: &ResponseRecord) {
        let Ok(url) = url::Url::parse(&t.url()) else { return };
        let mut jars = self.cookies.lock();
        let jar = jars.entry(isolation.to_string()).or_default();
        for v in r.header_values("set-cookie") {
            let _ = jar.parse(v, &url);
        }
    }

    /// Clear every per-session sensitive cache (on vault lock, workspace
    /// close or explicit reset): pooled authenticated connections, tokens,
    /// cookies and prepared client identities.
    pub fn clear_sensitive_state(&self) {
        self.http.pool.clear();
        self.h3.clear();
        self.tokens.clear();
        self.tls.lock().clear();
        self.cookies.lock().clear();
    }

    pub fn clear_isolation(&self, isolation: &str) {
        self.http.pool.clear_isolation(isolation);
        self.cookies.lock().remove(isolation);
    }
}
