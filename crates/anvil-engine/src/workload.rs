//! SPIFFE Workload API sources for one execution.
//!
//! * **X.509-SVID client identities.** Before preparation, every TLS profile
//!   the request will use (its own TLS profile for a TLS URL, and the TLS
//!   profile of an HTTPS/HBONE proxy) whose identity comes from the Workload
//!   API is materialized: the SVID is fetched (`FetchX509SVID`) — or taken
//!   from the in-memory cache until half its lifetime has passed, the point
//!   at which SPIFFE agents rotate — and the profile is presented to the
//!   rest of the engine as an ordinary PEM identity. With `trust_bundle`, the
//!   SVID's own trust-domain bundle joins the profile's trust anchors;
//!   federated bundles are recorded, never trusted.
//! * **JWT-SVIDs.** In the same step, for protocols whose auth is sent
//!   (HTTP, WebSocket, gRPC, SSE, a MASQUE CONNECT), the JWT-SVID auth
//!   profile's token is fetched (`FetchJWTSVID`, cached until half its
//!   lifetime and never within 30 s of expiry), read from a variable or read
//!   from a file, and checked locally: format, algorithm, subject, audience,
//!   expiry and — when enabled — the signature against the trust domain's
//!   JWT bundle (`FetchJWTBundles`, cached for 5 minutes). A failed check
//!   stops the request before anything is sent, unless the profile
//!   explicitly asks to send anyway. The checked token is then handed to the
//!   ordinary auth step as a value.
//!
//! Every Workload API call, the SVIDs used (public data) and the JWT-SVID
//! checks become [`WorkloadApiEvidence`] in the record. Private keys and
//! tokens live only in `Zeroizing` memory and in the cache, which the engine
//! clears on lock ([`crate::Engine::clear_sensitive_state`]). Calls use the
//! request's connect timeout (5 s when unset) as their deadline.

use crate::context::{ExecutionContext, SecretResolver, resolve_sensitive};
use crate::prepare;
use crate::vars::Resolver;
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::tls::{ClientIdentity, ProxyKind, TlsProfile};
use anvil_domain::workload::*;
use anvil_transport::workload_api::{self as wapi, CallError, Endpoint, EndpointError, X509Fetch};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// How long fetched JWT bundles are reused.
const JWT_BUNDLE_TTL_SECS: i64 = 300;
/// A JWT-SVID is re-fetched when less than this much lifetime remains.
const JWT_REFRESH_MARGIN_SECS: i64 = 30;
/// Largest JWT-SVID file read.
const MAX_TOKEN_FILE_BYTES: u64 = 16 * 1024;

struct CachedX509 {
    fetch: Arc<X509Fetch>,
    refresh_after: DateTime<Utc>,
}

struct CachedJwt {
    token: Zeroizing<String>,
    refresh_after: DateTime<Utc>,
}

struct CachedBundles {
    bundles: Arc<BTreeMap<String, Vec<u8>>>,
    refresh_after: DateTime<Utc>,
}

/// In-memory Workload API material (SVIDs with their private keys, JWT-SVIDs,
/// JWT bundles). Never persisted; cleared on lock.
#[derive(Default)]
pub struct WorkloadCache {
    x509: Mutex<HashMap<String, CachedX509>>,
    jwt: Mutex<HashMap<String, CachedJwt>>,
    bundles: Mutex<HashMap<String, CachedBundles>>,
}

impl WorkloadCache {
    pub fn clear(&self) {
        self.x509.lock().clear();
        self.jwt.lock().clear();
        self.bundles.lock().clear();
    }

    /// Number of cached entries (X.509, JWT, bundles), for tests and status.
    pub fn len(&self) -> (usize, usize, usize) {
        (self.x509.lock().len(), self.jwt.lock().len(), self.bundles.lock().len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == (0, 0, 0)
    }
}

/// Key material and tokens obtained from the Workload API for one execution,
/// handed to the ordinary preparation as secret references that only this
/// resolver knows. The values stay in `Zeroizing` buffers; the context the
/// engine prepares with never holds them as plain strings.
struct EphemeralSecrets {
    inner: Arc<dyn SecretResolver>,
    values: HashMap<Id, Zeroizing<String>>,
}

impl SecretResolver for EphemeralSecrets {
    fn resolve(&self, r: &SecretRef) -> Result<Zeroizing<String>, String> {
        match self.values.get(&r.id) {
            Some(v) => Ok(v.clone()),
            None => self.inner.resolve(r),
        }
    }
}

type Ephemeral = HashMap<Id, Zeroizing<String>>;

fn ephemeral(values: &mut Ephemeral, label: &str, value: Zeroizing<String>) -> SensitiveValue {
    let id = Id::new();
    values.insert(id, value);
    SensitiveValue::Secret { secret: SecretRef { id, label: label.to_string() } }
}

fn deadline(ctx: &ExecutionContext) -> Duration {
    let s = crate::settings::resolve(&ctx.settings_layers);
    let ms = s.timeouts.connect_ms.unwrap_or(wapi::DEFAULT_TIMEOUT.as_millis() as u64).clamp(100, 30_000);
    Duration::from_millis(ms)
}

fn endpoint_failure(e: EndpointError, field: &str, config_kind: FailureKind) -> TransportFailure {
    let kind = match e {
        EndpointError::Unsupported(_) => FailureKind::UnsupportedCombination,
        _ => config_kind,
    };
    TransportFailure::new(Phase::Prepare, kind, e.to_string()).with_field(field)
}

/// The uid this process presents in a Unix socket's peer credentials (what a
/// Workload API server attests), read from a connected socket pair.
async fn own_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        let (a, _b) = tokio::net::UnixStream::pair().ok()?;
        a.peer_cred().ok().map(|c| c.uid())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

async fn call_record(
    rpc: WorkloadRpc,
    endpoint: &Endpoint,
    purpose: &str,
    cached: bool,
    duration: Option<Duration>,
    error: Option<&CallError>,
) -> WorkloadApiCall {
    let result = error.map(CallError::to_result).unwrap_or(WorkloadCallResult::Ok);
    let caller_uid = match error {
        Some(CallError::Status { code: 7, .. }) | Some(CallError::NoIdentity(_)) => own_uid().await,
        _ => None,
    };
    WorkloadApiCall {
        rpc,
        endpoint: endpoint.uri.clone(),
        endpoint_source: endpoint.source,
        purpose: purpose.to_string(),
        cached,
        duration_us: duration.map(|d| d.as_micros() as u64),
        caller_uid,
        result,
    }
}

/// The typed failure for a Workload API call that did not deliver.
fn call_failure(rpc: WorkloadRpc, endpoint: &Endpoint, e: &CallError, field: &str) -> TransportFailure {
    let kind = match e {
        CallError::Unavailable { .. } | CallError::Timeout { .. } => FailureKind::WorkloadApiUnavailable,
        CallError::Status { code: 7, .. } | CallError::NoIdentity(_) => FailureKind::WorkloadApiDenied,
        CallError::Status { .. } | CallError::Malformed(_) => FailureKind::WorkloadApiFailed,
    };
    let mut f = TransportFailure::new(Phase::Prepare, kind, format!("{} at {}: {e}", rpc.method(), endpoint.uri)).with_field(field);
    if let CallError::Timeout { deadline_ms } = e {
        f.deadline_ms = Some(*deadline_ms);
    }
    if let CallError::Unavailable { io_error_kind, .. } = e {
        f.io_error_kind = io_error_kind.clone();
    }
    f
}

// ------------------------------------------------------------- X.509 ---

fn is_tls_scheme(s: &str) -> bool {
    matches!(s, "https" | "wss" | "grpcs" | "tls" | "dtls")
}

/// `(scheme, host, port)` the request's own TLS profile applies to, from a
/// throwaway resolver so counters and random helpers of the real
/// preparation are not advanced.
fn tls_target(ctx: &ExecutionContext) -> Option<(String, String, u16)> {
    let r = Resolver::new(ctx.var_layers.clone(), ctx.seed);
    let mut inferred = vec![];
    let all = ["https", "http", "wss", "ws", "grpcs", "grpc", "tls", "tcp", "dtls", "udp"];
    let url = r.resolve(&ctx.spec.url, "url").ok()?;
    let t = prepare::parse_target(&url, &all, &mut inferred).ok()?;
    if t.scheme == "udp"
        && let Some(m) = ctx.spec.udp.as_ref().and_then(|u| u.masque.as_ref())
    {
        let proxy = r.resolve(&m.proxy_url, "udp.masque.proxy_url").ok()?;
        let p = prepare::parse_target(&proxy, &["https"], &mut inferred).ok()?;
        return Some((p.scheme, p.host, p.port));
    }
    Some((t.scheme, t.host, t.port))
}

fn bound(p: &TlsProfile, host: &str, port: u16) -> bool {
    let t = prepare::Target {
        scheme: "https".into(),
        host: host.to_string(),
        port,
        authority: String::new(),
        path: "/".into(),
        query: String::new(),
    };
    crate::http_exec::binding_matches(&p.bindings, &t)
}

/// TLS profiles this request will present a Workload API identity from:
/// `(profile id, host, port)`.
fn needed_profiles(ctx: &ExecutionContext) -> Vec<(anvil_domain::Id, String, u16)> {
    let settings = crate::settings::resolve(&ctx.settings_layers);
    let wants = |id: anvil_domain::Id| {
        ctx.tls_profiles.iter().find(|p| p.id == id).filter(|p| matches!(p.client_identity, Some(ClientIdentity::WorkloadApi { .. })))
    };
    let mut out = vec![];
    let target = tls_target(ctx);
    // (UDP through a MASQUE proxy maps to the proxy's https origin above.)
    if let (Some(id), Some((scheme, host, port))) = (settings.tls_profile_id, target.as_ref())
        && is_tls_scheme(scheme)
        && let Some(p) = wants(id)
        && bound(p, host, *port)
    {
        out.push((id, host.clone(), *port));
    }
    if let Some(pid) = settings.proxy_profile_id
        && let Some(proxy) = ctx.proxy_profiles.iter().find(|p| p.id == pid)
        && matches!(proxy.kind, ProxyKind::Https | ProxyKind::Hbone)
        && let Some(tid) = proxy.tls_profile_id
        && let Some(p) = wants(tid)
        && !target.as_ref().is_some_and(|(_, h, port)| anvil_transport::net::no_proxy_matches(&proxy.no_proxy, h, *port))
        && let Some((host, port)) = proxy.address.rsplit_once(':').and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p)))
    {
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        if bound(p, &host, port) && !out.iter().any(|(i, ..)| *i == tid) {
            out.push((tid, host, port));
        }
    }
    out
}

async fn x509_for(
    engine: &crate::Engine,
    endpoint: &Endpoint,
    timeout: Duration,
    purpose: &str,
    ev: &mut WorkloadApiEvidence,
) -> Result<Arc<X509Fetch>, TransportFailure> {
    let key = endpoint.uri.clone();
    let now = Utc::now();
    if let Some(c) = engine.workload.x509.lock().get(&key)
        && now < c.refresh_after
    {
        let fetch = c.fetch.clone();
        ev.calls.push(WorkloadApiCall {
            rpc: WorkloadRpc::FetchX509Svid,
            endpoint: endpoint.uri.clone(),
            endpoint_source: endpoint.source,
            purpose: purpose.to_string(),
            cached: true,
            duration_us: None,
            caller_uid: None,
            result: WorkloadCallResult::Ok,
        });
        return Ok(fetch);
    }
    let client = wapi::WorkloadClient::new(endpoint.clone(), timeout);
    let timed = client.fetch_x509_svids().await;
    match timed.result {
        Ok(fetch) => {
            ev.calls.push(call_record(WorkloadRpc::FetchX509Svid, endpoint, purpose, false, Some(timed.duration), None).await);
            // Re-fetch at half the shortest SVID lifetime (SPIFFE rotation).
            let refresh_after = fetch.svids.iter().map(|s| s.not_before + (s.not_after - s.not_before) / 2).min().unwrap_or(now).max(now);
            let fetch = Arc::new(fetch);
            engine.workload.x509.lock().insert(key, CachedX509 { fetch: fetch.clone(), refresh_after });
            Ok(fetch)
        }
        Err(e) => {
            ev.calls.push(call_record(WorkloadRpc::FetchX509Svid, endpoint, purpose, false, Some(timed.duration), Some(&e)).await);
            Err(call_failure(WorkloadRpc::FetchX509Svid, endpoint, &e, "tls.client_identity"))
        }
    }
}

/// Fetch every Workload API client identity the request needs and return a
/// context in which those profiles carry the fetched PEM identity (and,
/// with `trust_bundle`, the SVID's trust-domain bundle as extra roots).
/// `None` when the request needs none.
async fn materialize_tls(
    engine: &crate::Engine,
    ctx: &ExecutionContext,
    ev: &mut WorkloadApiEvidence,
    values: &mut Ephemeral,
) -> Result<Option<ExecutionContext>, TransportFailure> {
    let needed = needed_profiles(ctx);
    if needed.is_empty() {
        return Ok(None);
    }
    let timeout = deadline(ctx);
    let mut out = ctx.clone();
    for (id, _host, _port) in needed {
        let Some(p) = out.tls_profiles.iter_mut().find(|p| p.id == id) else { continue };
        let Some(ClientIdentity::WorkloadApi { endpoint, spiffe_id, trust_bundle }) = p.client_identity.clone() else { continue };
        let purpose = format!("TLS profile '{}' client identity", p.name);
        let endpoint = wapi::resolve_endpoint(&endpoint)
            .map_err(|e| endpoint_failure(e, "tls.client_identity.endpoint", FailureKind::TlsProfileInvalid))?;
        let fetch = x509_for(engine, &endpoint, timeout, &purpose, ev).await?;
        let want = spiffe_id.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let svid = match want {
            Some(w) => fetch.svids.iter().find(|s| s.spiffe_id == w),
            None => fetch.svids.first(),
        };
        let Some(svid) = svid else {
            let offered = fetch.svids.iter().map(|s| s.spiffe_id.clone()).collect::<Vec<_>>();
            let e = CallError::NoIdentity(format!(
                "the Workload API holds no X.509-SVID for {} (it returned {})",
                want.unwrap_or_default(),
                offered.join(", ")
            ));
            if let Some(last) = ev.calls.last_mut() {
                last.result = e.to_result();
            }
            return Err(call_failure(WorkloadRpc::FetchX509Svid, &endpoint, &e, "tls.client_identity.spiffe_id"));
        };
        let refresh_after = engine.workload.x509.lock().get(&endpoint.uri).map(|c| c.refresh_after);
        ev.x509_svids.push(X509SvidSummary {
            tls_profile: p.name.clone(),
            spiffe_id: svid.spiffe_id.clone(),
            certificate: anvil_transport::certs::summarize_der(&svid.leaf_der),
            chain_length: svid.chain_length as u32,
            hint: Some(svid.hint.clone()).filter(|h| !h.is_empty()),
            offered_spiffe_ids: fetch.svids.iter().map(|s| s.spiffe_id.clone()).collect(),
            bundle_trusted: trust_bundle && !svid.bundle_pem.is_empty(),
            bundle_certificates: svid.bundle_pem.len() as u32,
            federated_trust_domains: fetch.federated_trust_domains.clone(),
            refresh_after,
        });
        if trust_bundle {
            p.extra_roots_pem.extend(svid.bundle_pem.iter().cloned());
        }
        p.client_identity = Some(ClientIdentity::Pem {
            cert_chain_pem: svid.cert_chain_pem.clone(),
            private_key_pem: ephemeral(values, "SPIFFE Workload API X.509-SVID key", svid.private_key_pem.clone()),
        });
    }
    Ok(Some(out))
}

// --------------------------------------------------------------- JWT ---

/// A JWT-SVID auth profile with its templates resolved.
#[derive(Clone)]
struct JwtSvidPlan {
    pub source: JwtSvidSourceKind,
    pub token: Option<Zeroizing<String>>,
    pub file: Option<String>,
    pub audiences: Vec<String>,
    pub endpoint: String,
    pub spiffe_id: Option<String>,
    pub verify_with_bundles: bool,
    pub send_despite_failed_checks: bool,
}

fn resolve_plan(c: &JwtSvidConfig, ctx: &ExecutionContext, r: &Resolver) -> Result<JwtSvidPlan, TransportFailure> {
    let fail = |m: String, field: &str| TransportFailure::new(Phase::Prepare, FailureKind::AuthPreparationFailed, m).with_field(field);
    let mut audiences = Vec::new();
    for (i, a) in c.audiences.iter().enumerate() {
        let v = r.resolve(a, &format!("auth.jwt_svid.audiences[{i}]"))?;
        let v = v.trim();
        if !v.is_empty() && !audiences.iter().any(|x: &String| x == v) {
            audiences.push(v.to_string());
        }
    }
    if audiences.is_empty() {
        return Err(fail(
            "a JWT-SVID profile needs at least one audience (the verifier's expected audience)".into(),
            "auth.jwt_svid.audiences",
        ));
    }
    if audiences.iter().any(|a| a.chars().any(char::is_control)) {
        return Err(fail("a JWT-SVID audience contains control characters".into(), "auth.jwt_svid.audiences"));
    }
    let spiffe_id = match c.spiffe_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            let v = r.resolve(s, "auth.jwt_svid.spiffe_id")?;
            anvil_transport::spiffe::parse_id(&v).map_err(|e| fail(e, "auth.jwt_svid.spiffe_id"))?;
            Some(v)
        }
        None => None,
    };
    let (source, token, file) = match &c.source {
        JwtSvidSource::WorkloadApi => (JwtSvidSourceKind::WorkloadApi, None, None),
        JwtSvidSource::Value { token } => {
            let (raw, _) = resolve_sensitive(token, ctx.secrets.as_ref())
                .map_err(|e| fail(format!("auth.jwt_svid.token: {e}"), "auth.jwt_svid.token"))?;
            let v = r.resolve(&raw, "auth.jwt_svid.token")?;
            (JwtSvidSourceKind::Value, Some(Zeroizing::new(v.trim().to_string())), None)
        }
        JwtSvidSource::File { path } => {
            let p = r.resolve(path, "auth.jwt_svid.path")?;
            if p.trim().is_empty() {
                return Err(fail("the JWT-SVID file path is empty".into(), "auth.jwt_svid.path"));
            }
            (JwtSvidSourceKind::File, None, Some(p.trim().to_string()))
        }
    };
    let header_ok = http::HeaderName::from_bytes(c.header_name.trim().as_bytes()).is_ok();
    if !header_ok {
        return Err(fail(format!("'{}' is not a valid header name", c.header_name), "auth.jwt_svid.header_name"));
    }
    Ok(JwtSvidPlan {
        source,
        token,
        file,
        audiences,
        endpoint: r.resolve(&c.endpoint, "auth.jwt_svid.endpoint")?,
        spiffe_id,
        verify_with_bundles: c.verify_with_bundles,
        send_despite_failed_checks: c.send_despite_failed_checks,
    })
}

fn read_token_file(path: &str) -> Result<Zeroizing<String>, TransportFailure> {
    use std::io::Read;
    let fail = |m: String| TransportFailure::new(Phase::Prepare, FailureKind::AuthPreparationFailed, m).with_field("auth.jwt_svid.path");
    let unreadable = |e: std::io::Error| fail(format!("the JWT-SVID file {path} is not readable: {e}"));
    let not_regular = || fail(format!("the JWT-SVID file {path} is not a regular file"));
    let too_large = || fail(format!("the JWT-SVID file {path} is larger than {MAX_TOKEN_FILE_BYTES} bytes"));
    // A cheap filter only: the path can change before the open below.
    // Links are followed: a Kubernetes projected token is a rotating link.
    let found = std::fs::metadata(path).map_err(unreadable)?;
    if !found.is_file() {
        return Err(not_regular());
    }
    let file = open_token_file(path).map_err(unreadable)?;
    // The checks that count are on the opened handle, not on the path.
    let meta = file.metadata().map_err(unreadable)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > MAX_TOKEN_FILE_BYTES {
        return Err(too_large());
    }
    let mut raw = Zeroizing::new(String::new());
    file.take(MAX_TOKEN_FILE_BYTES + 1).read_to_string(&mut raw).map_err(unreadable)?;
    // Bounded even if the file grows while it is read.
    if raw.len() as u64 > MAX_TOKEN_FILE_BYTES {
        return Err(too_large());
    }
    Ok(Zeroizing::new(raw.trim().to_string()))
}

/// Open a token file for reading, following links. A FIFO or device swapped
/// in at the path (or at a link's target) never blocks the open: on Unix the
/// file is opened non-blocking (which does not change how a regular file
/// reads) and never as a controlling terminal. The caller checks the type of
/// the opened handle.
fn open_token_file(path: &str) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    options.open(path)
}

fn ts(v: Option<&serde_json::Value>) -> Option<i64> {
    v.and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
}

fn when(t: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(t, 0)
}

fn audience_claim(v: Option<&serde_json::Value>) -> Option<Vec<String>> {
    match v? {
        serde_json::Value::String(s) => Some(vec![s.clone()]),
        serde_json::Value::Array(a) => a.iter().map(|x| x.as_str().map(String::from)).collect(),
        _ => None,
    }
}

fn check(kind: JwtSvidCheckKind, result: CheckResult, detail: impl Into<String>) -> JwtSvidCheck {
    JwtSvidCheck { check: kind, result, detail: detail.into() }
}

/// Local JWT-SVID checks (SPIFFE JWT-SVID specification §3-§4). `bundles`
/// (trust domain → JWKS) enables the signature check. Pure, for testing.
pub fn check_jwt_svid(
    token: &str,
    requested: &[String],
    expected_subject: Option<&str>,
    bundles: Option<&BTreeMap<String, Vec<u8>>>,
    source: JwtSvidSourceKind,
    now: DateTime<Utc>,
) -> JwtSvidSummary {
    use CheckResult::*;
    use JwtSvidCheckKind as K;
    let mut s = JwtSvidSummary {
        source,
        requested_audiences: requested.to_vec(),
        subject: None,
        audiences: vec![],
        algorithm: None,
        key_id: None,
        issued_at: None,
        not_before: None,
        expires_at: None,
        has_issuer: false,
        checks: vec![],
        sent_despite_failed_checks: false,
    };
    let decoded = match anvil_auth::jwt_svid::decode(token) {
        Ok(d) => {
            s.checks.push(check(K::Format, Passed, "compact JWS with JSON header and claims"));
            d
        }
        Err(e) => {
            s.checks.push(check(K::Format, Failed, e));
            for k in [K::Algorithm, K::Subject, K::Audience, K::Expiry, K::Signature] {
                s.checks.push(check(k, NotRun, "the token could not be decoded"));
            }
            return s;
        }
    };
    s.algorithm = decoded.alg().map(String::from);
    s.key_id = decoded.kid().map(String::from);
    s.has_issuer = decoded.claims.contains_key("iss");
    let c = &decoded.claims;
    s.issued_at = ts(c.get("iat")).and_then(when);
    s.not_before = ts(c.get("nbf")).and_then(when);
    match anvil_auth::jwt_svid::algorithm_problem(decoded.alg()) {
        None => s.checks.push(check(K::Algorithm, Passed, format!("alg {}", decoded.alg().unwrap_or_default()))),
        Some(p) => s.checks.push(check(K::Algorithm, Failed, p)),
    }
    let sub = c.get("sub").and_then(|v| v.as_str()).map(String::from);
    s.subject = sub.clone();
    match sub.as_deref().map(anvil_transport::spiffe::parse_id) {
        None => s.checks.push(check(K::Subject, Failed, "the token has no sub claim")),
        Some(Err(e)) => s.checks.push(check(K::Subject, Failed, format!("sub is not a SPIFFE ID: {e}"))),
        Some(Ok(id)) if id.path.is_empty() => {
            s.checks.push(check(K::Subject, Failed, format!("sub {} names a trust domain, not a workload", id.as_uri())))
        }
        Some(Ok(id)) => match expected_subject {
            Some(want) if want != id.as_uri() => {
                s.checks.push(check(K::Subject, Failed, format!("sub is {}, not the configured {want}", id.as_uri())))
            }
            _ => s.checks.push(check(K::Subject, Passed, format!("sub {} is a workload SPIFFE ID", id.as_uri()))),
        },
    }
    match audience_claim(c.get("aud")) {
        None => s.checks.push(check(K::Audience, Failed, "the token has no usable aud claim")),
        Some(aud) => {
            let missing: Vec<&String> = requested.iter().filter(|r| !aud.contains(r)).collect();
            s.audiences = aud.clone();
            if missing.is_empty() {
                s.checks.push(check(K::Audience, Passed, format!("aud {aud:?} includes every requested audience")));
            } else {
                s.checks.push(check(K::Audience, Failed, format!("aud {aud:?} does not include {missing:?}")));
            }
        }
    }
    match ts(c.get("exp")) {
        None => s.checks.push(check(K::Expiry, Failed, "the token has no exp claim")),
        Some(exp) => {
            s.expires_at = when(exp);
            let left = exp - now.timestamp();
            if left <= 0 {
                s.checks.push(check(K::Expiry, Failed, format!("exp is {}s in the past by this machine's clock", -left)));
            } else if let Some(nbf) = ts(c.get("nbf")).filter(|n| *n > now.timestamp()) {
                s.checks.push(check(K::Expiry, Failed, format!("nbf is {}s in the future by this machine's clock", nbf - now.timestamp())));
            } else {
                s.checks.push(check(K::Expiry, Passed, format!("expires in {left}s by this machine's clock")));
            }
        }
    }
    match bundles {
        None => s.checks.push(check(K::Signature, NotRun, "bundle verification is off")),
        Some(b) => {
            let td = sub.as_deref().and_then(|x| anvil_transport::spiffe::parse_id(x).ok()).map(|id| id.trust_domain);
            match td.as_ref().and_then(|t| b.get(t).map(|j| (t, j))) {
                None => s.checks.push(check(
                    K::Signature,
                    Failed,
                    format!(
                        "no JWT bundle for the token's trust domain {} (the Workload API returned bundles for {})",
                        td.clone().unwrap_or_else(|| "?".into()),
                        b.keys().cloned().collect::<Vec<_>>().join(", ")
                    ),
                )),
                Some((t, jwks)) => match anvil_auth::jwt_svid::verify_signature(token, jwks) {
                    Ok(kid) => s.checks.push(check(K::Signature, Passed, format!("verified with key {kid} of the {t} JWT bundle"))),
                    Err(e) => s.checks.push(check(K::Signature, Failed, format!("{t} JWT bundle: {e}"))),
                },
            }
        }
    }
    s
}

async fn bundles_for(
    engine: &crate::Engine,
    endpoint: &Endpoint,
    timeout: Duration,
    ev: &mut WorkloadApiEvidence,
) -> Result<Arc<BTreeMap<String, Vec<u8>>>, TransportFailure> {
    let now = Utc::now();
    let purpose = "JWT-SVID signature check";
    if let Some(c) = engine.workload.bundles.lock().get(&endpoint.uri)
        && now < c.refresh_after
    {
        let b = c.bundles.clone();
        ev.calls.push(WorkloadApiCall {
            rpc: WorkloadRpc::FetchJwtBundles,
            endpoint: endpoint.uri.clone(),
            endpoint_source: endpoint.source,
            purpose: purpose.into(),
            cached: true,
            duration_us: None,
            caller_uid: None,
            result: WorkloadCallResult::Ok,
        });
        return Ok(b);
    }
    let timed = wapi::WorkloadClient::new(endpoint.clone(), timeout).fetch_jwt_bundles().await;
    match timed.result {
        Ok(b) => {
            ev.calls.push(call_record(WorkloadRpc::FetchJwtBundles, endpoint, purpose, false, Some(timed.duration), None).await);
            let b = Arc::new(b);
            engine.workload.bundles.lock().insert(
                endpoint.uri.clone(),
                CachedBundles { bundles: b.clone(), refresh_after: now + ChronoDuration::seconds(JWT_BUNDLE_TTL_SECS) },
            );
            Ok(b)
        }
        Err(e) => {
            ev.calls.push(call_record(WorkloadRpc::FetchJwtBundles, endpoint, purpose, false, Some(timed.duration), Some(&e)).await);
            Err(call_failure(WorkloadRpc::FetchJwtBundles, endpoint, &e, "auth.jwt_svid.verify_with_bundles"))
        }
    }
}

/// Obtain and check the JWT-SVID for this request. The checks are recorded
/// in `ev.jwt_svid`; a failed check is a local refusal unless the profile
/// sends anyway.
async fn acquire_jwt_svid(
    engine: &crate::Engine,
    ctx: &ExecutionContext,
    plan: &JwtSvidPlan,
    ev: &mut WorkloadApiEvidence,
) -> Result<Zeroizing<String>, TransportFailure> {
    let timeout = deadline(ctx);
    let needs_endpoint = plan.source == JwtSvidSourceKind::WorkloadApi || plan.verify_with_bundles;
    let endpoint = if needs_endpoint {
        Some(
            wapi::resolve_endpoint(&plan.endpoint)
                .map_err(|e| endpoint_failure(e, "auth.jwt_svid.endpoint", FailureKind::AuthPreparationFailed))?,
        )
    } else {
        None
    };
    let token = match plan.source {
        JwtSvidSourceKind::Value => plan.token.clone().unwrap_or_default(),
        JwtSvidSourceKind::File => read_token_file(plan.file.as_deref().unwrap_or_default())?,
        JwtSvidSourceKind::WorkloadApi => {
            let endpoint = endpoint.as_ref().expect("resolved above");
            let key = format!("{}|{}|{}", endpoint.uri, plan.spiffe_id.clone().unwrap_or_default(), plan.audiences.join("\u{1f}"));
            let now = Utc::now();
            let cached = engine.workload.jwt.lock().get(&key).filter(|c| now < c.refresh_after).map(|c| c.token.clone());
            match cached {
                Some(t) => {
                    ev.calls.push(WorkloadApiCall {
                        rpc: WorkloadRpc::FetchJwtSvid,
                        endpoint: endpoint.uri.clone(),
                        endpoint_source: endpoint.source,
                        purpose: "JWT-SVID auth".into(),
                        cached: true,
                        duration_us: None,
                        caller_uid: None,
                        result: WorkloadCallResult::Ok,
                    });
                    t
                }
                None => {
                    let timed = wapi::WorkloadClient::new(endpoint.clone(), timeout)
                        .fetch_jwt_svid(&plan.audiences, plan.spiffe_id.as_deref())
                        .await;
                    match timed.result {
                        Ok(f) => {
                            ev.calls.push(
                                call_record(WorkloadRpc::FetchJwtSvid, endpoint, "JWT-SVID auth", false, Some(timed.duration), None).await,
                            );
                            let claims = anvil_auth::jwt_svid::decode(&f.token).ok().map(|d| d.claims);
                            let exp = claims.as_ref().and_then(|c| ts(c.get("exp")));
                            let iat = claims.as_ref().and_then(|c| ts(c.get("iat"))).unwrap_or(now.timestamp());
                            if let Some(exp) = exp {
                                // Reuse until half its lifetime, and never within the margin.
                                let refresh = (iat + (exp - iat) / 2).min(exp - JWT_REFRESH_MARGIN_SECS);
                                if let Some(r) = when(refresh).filter(|r| *r > now) {
                                    engine.workload.jwt.lock().insert(key, CachedJwt { token: f.token.clone(), refresh_after: r });
                                }
                            }
                            f.token
                        }
                        Err(e) => {
                            ev.calls.push(
                                call_record(WorkloadRpc::FetchJwtSvid, endpoint, "JWT-SVID auth", false, Some(timed.duration), Some(&e))
                                    .await,
                            );
                            return Err(call_failure(WorkloadRpc::FetchJwtSvid, endpoint, &e, "auth.jwt_svid"));
                        }
                    }
                }
            }
        }
    };
    let bundles = match (&endpoint, plan.verify_with_bundles) {
        (Some(e), true) => Some(bundles_for(engine, e, timeout, ev).await?),
        _ => None,
    };
    // With the Workload API source the configured ID was requested; the
    // token must then carry it too.
    let mut summary = check_jwt_svid(&token, &plan.audiences, plan.spiffe_id.as_deref(), bundles.as_deref(), plan.source, Utc::now());
    let failed: Vec<String> = summary.failed_checks().map(|c| format!("{:?}: {}", c.check, c.detail).to_lowercase()).collect();
    if !failed.is_empty() {
        if !plan.send_despite_failed_checks {
            ev.jwt_svid = Some(summary);
            return Err(TransportFailure::new(
                Phase::Prepare,
                FailureKind::JwtSvidRejectedLocally,
                format!("the JWT-SVID failed Anvil's local checks and was not sent ({})", failed.join("; ")),
            )
            .with_field("auth.jwt_svid"));
        }
        summary.sent_despite_failed_checks = true;
    }
    ev.jwt_svid = Some(summary);
    Ok(token)
}

// ----------------------------------------------------------- entry point ---

/// Protocols whose auth headers are sent (and so need a JWT-SVID): HTTP,
/// WebSocket, gRPC, SSE, and UDP through a MASQUE proxy (its CONNECT).
fn auth_is_sent(ctx: &ExecutionContext) -> bool {
    use anvil_domain::request::Protocol;
    match ctx.spec.protocol {
        Protocol::Http | Protocol::WebSocket | Protocol::Grpc | Protocol::Sse => true,
        Protocol::Udp => ctx.spec.udp.as_ref().is_some_and(|u| u.masque.is_some()),
        Protocol::Tcp => false,
    }
}

fn count_jwt_svid(a: &AuthConfig) -> usize {
    match a {
        AuthConfig::JwtSvid { .. } => 1,
        AuthConfig::Multi { profiles } => profiles.iter().map(count_jwt_svid).sum(),
        _ => 0,
    }
}

fn find_jwt_svid(a: &AuthConfig) -> Option<&JwtSvidConfig> {
    match a {
        AuthConfig::JwtSvid { config } => Some(config),
        AuthConfig::Multi { profiles } => profiles.iter().find_map(find_jwt_svid),
        _ => None,
    }
}

/// Replace the JWT-SVID source with the acquired, checked token.
fn install_token(a: &mut AuthConfig, token: &SensitiveValue) {
    match a {
        AuthConfig::JwtSvid { config } => config.source = JwtSvidSource::Value { token: token.clone() },
        AuthConfig::Multi { profiles } => profiles.iter_mut().for_each(|p| install_token(p, token)),
        _ => {}
    }
}

/// Everything the Workload API contributes before a request is prepared:
/// X.509-SVID client identities and the checked JWT-SVID. Returns the
/// context to prepare with (`None`: the original one) and the evidence,
/// which is also returned when the step fails.
pub(crate) async fn prepare(
    engine: &crate::Engine,
    ctx: &ExecutionContext,
    r: &Resolver,
) -> (Result<Option<ExecutionContext>, TransportFailure>, WorkloadApiEvidence) {
    let mut ev = WorkloadApiEvidence::default();
    let result = prepare_inner(engine, ctx, r, &mut ev).await;
    (result, ev)
}

async fn prepare_inner(
    engine: &crate::Engine,
    ctx: &ExecutionContext,
    r: &Resolver,
    ev: &mut WorkloadApiEvidence,
) -> Result<Option<ExecutionContext>, TransportFailure> {
    let mut values = Ephemeral::new();
    let mut out = materialize_tls(engine, ctx, ev, &mut values).await?;
    if auth_is_sent(ctx)
        // The layer `ExecutionContext::effective_auth` selects.
        && let Some(layer) = ctx.auth_layers.iter().rposition(|(_, a)| !matches!(a, AuthConfig::Inherit))
    {
        let auth = &ctx.auth_layers[layer].1;
        if count_jwt_svid(auth) > 1 {
            return Err(TransportFailure::new(
                Phase::Prepare,
                FailureKind::UnsupportedCombination,
                "one request can carry one JWT-SVID auth profile; the multi-auth set holds several",
            )
            .with_field("auth"));
        }
        if let Some(config) = find_jwt_svid(auth) {
            let base = out.as_ref().unwrap_or(ctx);
            let plan = resolve_plan(config, base, r)?;
            let token = acquire_jwt_svid(engine, base, &plan, ev).await?;
            let token = ephemeral(&mut values, "SPIFFE JWT-SVID", token);
            let mut c = out.unwrap_or_else(|| ctx.clone());
            install_token(&mut c.auth_layers[layer].1, &token);
            out = Some(c);
        }
    }
    if let Some(c) = out.as_mut()
        && !values.is_empty()
    {
        c.secrets = Arc::new(EphemeralSecrets { inner: c.secrets.clone(), values });
    }
    Ok(out)
}

// ----------------------------------------------------------------- probe ---

/// One SVID a probe saw (public data only).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbedSvid {
    pub spiffe_id: String,
    pub not_after: DateTime<Utc>,
    pub chain_length: u32,
    pub bundle_certificates: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// One trust domain's JWT bundle a probe saw.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbedJwtBundle {
    pub trust_domain: String,
    pub key_ids: Vec<String>,
}

/// What a Workload API endpoint serves to this process: the answer to "can
/// Anvil get an identity here?", without keeping or showing any secret.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkloadProbe {
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_source: Option<WorkloadEndpointSource>,
    /// The endpoint setting could not be used (not configured, invalid, or
    /// unsupported on this platform); nothing was dialed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_error: Option<String>,
    pub calls: Vec<WorkloadApiCall>,
    pub x509_svids: Vec<ProbedSvid>,
    pub federated_trust_domains: Vec<String>,
    pub jwt_bundles: Vec<ProbedJwtBundle>,
    /// With an audience: the JWT-SVID's decoded claims and local checks
    /// (the token itself is discarded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_svid: Option<JwtSvidSummary>,
}

/// Ask the Workload API at `endpoint` (empty: `SPIFFE_ENDPOINT_SOCKET`) for
/// its X.509-SVIDs and JWT bundles and, with `audience`, a JWT-SVID checked
/// against those bundles. Nothing is cached; keys and tokens are dropped.
pub async fn probe(endpoint: &str, audience: Option<&str>, timeout: Duration) -> WorkloadProbe {
    let mut p = WorkloadProbe {
        endpoint: endpoint.trim().to_string(),
        endpoint_source: None,
        endpoint_error: None,
        calls: vec![],
        x509_svids: vec![],
        federated_trust_domains: vec![],
        jwt_bundles: vec![],
        jwt_svid: None,
    };
    let ep = match wapi::resolve_endpoint(endpoint) {
        Ok(e) => e,
        Err(e) => {
            p.endpoint_error = Some(e.to_string());
            return p;
        }
    };
    p.endpoint = ep.uri.clone();
    p.endpoint_source = Some(ep.source);
    let client = wapi::WorkloadClient::new(ep.clone(), timeout);
    let purpose = "Workload API probe";
    let x = client.fetch_x509_svids().await;
    p.calls.push(call_record(WorkloadRpc::FetchX509Svid, &ep, purpose, false, Some(x.duration), x.result.as_ref().err()).await);
    if let Ok(f) = &x.result {
        p.x509_svids = f
            .svids
            .iter()
            .map(|s| ProbedSvid {
                spiffe_id: s.spiffe_id.clone(),
                not_after: s.not_after,
                chain_length: s.chain_length as u32,
                bundle_certificates: s.bundle_pem.len() as u32,
                hint: Some(s.hint.clone()).filter(|h| !h.is_empty()),
            })
            .collect();
        p.federated_trust_domains = f.federated_trust_domains.clone();
    }
    drop(x);
    let b = client.fetch_jwt_bundles().await;
    p.calls.push(call_record(WorkloadRpc::FetchJwtBundles, &ep, purpose, false, Some(b.duration), b.result.as_ref().err()).await);
    let bundles = b.result.ok();
    if let Some(bs) = &bundles {
        p.jwt_bundles = bs
            .iter()
            .map(|(td, jwks)| ProbedJwtBundle {
                trust_domain: td.clone(),
                key_ids: serde_json::from_slice::<serde_json::Value>(jwks)
                    .ok()
                    .and_then(|v| v.get("keys").and_then(|k| k.as_array()).cloned())
                    .unwrap_or_default()
                    .iter()
                    .map(|k| k.get("kid").and_then(|v| v.as_str()).unwrap_or("-").to_string())
                    .collect(),
            })
            .collect();
    }
    if let Some(aud) = audience.map(str::trim).filter(|a| !a.is_empty()) {
        let j = client.fetch_jwt_svid(&[aud.to_string()], None).await;
        p.calls.push(call_record(WorkloadRpc::FetchJwtSvid, &ep, purpose, false, Some(j.duration), j.result.as_ref().err()).await);
        if let Ok(t) = j.result {
            p.jwt_svid =
                Some(check_jwt_svid(&t.token, &[aud.to_string()], None, bundles.as_ref(), JwtSvidSourceKind::WorkloadApi, Utc::now()));
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("anvil-token-file-{}-{name}", Id::new()))
    }

    #[test]
    fn token_file_is_read_and_trimmed() {
        let p = temp_path("ok");
        std::fs::write(&p, "  a.b.c\n").unwrap();
        let token = read_token_file(p.to_str().unwrap());
        std::fs::remove_file(&p).unwrap();
        assert_eq!(token.unwrap().as_str(), "a.b.c");
    }

    #[test]
    fn oversized_token_file_is_refused() {
        let p = temp_path("large");
        std::fs::write(&p, vec![b'a'; MAX_TOKEN_FILE_BYTES as usize + 1]).unwrap();
        let err = read_token_file(p.to_str().unwrap()).unwrap_err();
        std::fs::remove_file(&p).unwrap();
        assert!(err.message.contains("is larger than"), "{}", err.message);
    }

    #[test]
    fn directory_is_not_read_as_a_token_file() {
        let p = temp_path("dir");
        std::fs::create_dir(&p).unwrap();
        let err = read_token_file(p.to_str().unwrap()).unwrap_err();
        std::fs::remove_dir(&p).unwrap();
        assert!(err.message.contains("is not a regular file"), "{}", err.message);
    }

    #[cfg(unix)]
    #[test]
    fn device_is_not_read_as_a_token_file() {
        let err = read_token_file("/dev/zero").unwrap_err();
        assert!(err.message.contains("is not a regular file"), "{}", err.message);
    }

    #[cfg(unix)]
    #[test]
    fn link_is_followed_to_a_token_file() {
        let target = temp_path("target");
        std::fs::write(&target, "a.b.c\n").unwrap();
        let link = temp_path("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let token = read_token_file(link.to_str().unwrap());
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&target).unwrap();
        assert_eq!(token.unwrap().as_str(), "a.b.c");
    }

    /// The Kubernetes projected-volume layout: `token` links through `..data`,
    /// which is re-pointed at a new directory when the token rotates.
    #[cfg(unix)]
    #[test]
    fn rotated_projected_token_is_read_through_its_links() {
        let root = temp_path("projected");
        std::fs::create_dir(&root).unwrap();
        for (dir, token) in [("..v1", "a.b.c"), ("..v2", "d.e.f")] {
            std::fs::create_dir(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("token"), token).unwrap();
        }
        std::os::unix::fs::symlink("..v1", root.join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/token", root.join("token")).unwrap();
        let path = root.join("token").to_str().unwrap().to_string();
        let first = read_token_file(&path);
        std::os::unix::fs::symlink("..v2", root.join("..data_tmp")).unwrap();
        std::fs::rename(root.join("..data_tmp"), root.join("..data")).unwrap();
        let second = read_token_file(&path);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(first.unwrap().as_str(), "a.b.c");
        assert_eq!(second.unwrap().as_str(), "d.e.f");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_refused_without_blocking() {
        let p = temp_path("fifo");
        mkfifo(&p);
        let path = p.to_str().unwrap().to_string();
        let err = within_seconds(move || read_token_file(&path)).unwrap_err();
        std::fs::remove_file(&p).unwrap();
        assert!(err.message.contains("is not a regular file"), "{}", err.message);
    }

    /// A FIFO swapped in after the path check: the open itself does not block,
    /// and the opened handle is not a regular file.
    #[cfg(unix)]
    #[test]
    fn fifo_open_does_not_block() {
        let p = temp_path("fifo-open");
        mkfifo(&p);
        let path = p.to_str().unwrap().to_string();
        let opened = within_seconds(move || open_token_file(&path).and_then(|f| f.metadata()).map(|m| m.is_file()));
        std::fs::remove_file(&p).unwrap();
        assert!(!opened.unwrap());
    }

    /// A link to a FIFO: the open follows it without blocking, the opened
    /// handle is not a regular file, and the read refuses it.
    #[cfg(unix)]
    #[test]
    fn link_to_fifo_is_refused_without_blocking() {
        let fifo = temp_path("link-fifo");
        mkfifo(&fifo);
        let link = temp_path("link-to-fifo");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();
        let path = link.to_str().unwrap().to_string();
        let opened = within_seconds(move || open_token_file(&path).and_then(|f| f.metadata()).map(|m| m.is_file()));
        let path = link.to_str().unwrap().to_string();
        let read = within_seconds(move || read_token_file(&path));
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&fifo).unwrap();
        assert!(!opened.unwrap());
        let err = read.unwrap_err();
        assert!(err.message.contains("is not a regular file"), "{}", err.message);
    }

    /// Runs `f` on its own thread, failing the test instead of hanging if it blocks.
    #[cfg(unix)]
    fn within_seconds<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(30)).expect("the open blocked")
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn mkfifo(path: &std::path::Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a NUL-terminated string that outlives the call.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo {}: {}", path.display(), std::io::Error::last_os_error());
    }
}
