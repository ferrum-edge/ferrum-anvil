//! Scenarios for the `auth` gateway profile: every authentication family
//! Ferrum Edge 0.9.5 offers that a loopback lab can drive for real
//! (key_auth, basic_auth, jwt_auth, jwks_auth, DPoP, hmac_auth v2,
//! oauth2_introspection, ldap_auth, multi-auth, access_control), through
//! HTTP 18180, with a local identity provider and LDAP directory.
//!
//! Public-evidence mode: the destination is a trusted Ferrum profile over
//! plain HTTP, so every marker/body-derived claim is capped at `likely`.
//! Gateway 401/403/5xx auth rejections carry no `X-Gateway-Error`; the
//! only gateway-specific public signal is the body literal (plus
//! `WWW-Authenticate` on some), which a backend can reproduce byte for byte
//! (AUTH-X04/X05 check exactly that lookalike). Ground truth comes from the
//! gateway's transaction log, the echo backend and the IdP/LDAP fixtures,
//! and is never given to the engine.
//!
//! Result ids are the failure-matrix id, optionally followed by
//! `.<variant>`; `X` ids (e.g. `AUTH-X01`) are lab extensions with no seed.

use crate::fixtures_auth::{self, AUDIENCE, AuthFixtures, ISSUER, ISSUER_KID, OAUTH_CLIENT_ID, ROTATED_KID};
use crate::gateway::Gateway;
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use crate::tls::{absent_scope, integration, op_lines, record_excludes, send};
use anvil_auth::{HmacParams, SignableRequest};
use anvil_domain::auth::{
    AuthConfig, BodyDigestHeader, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile, JwtAlgorithm, JwtClaims, KeyLocation, OAuth2Config,
    OAuthClientAuth, OAuthGrant,
};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::Phase;
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::gateway_idp::IdpMode;
use std::future::Future;
use std::pin::Pin;
use zeroize::Zeroizing;

pub const GATEWAY: &str = "http://127.0.0.1:18180";
const AUTHORITY: &str = "127.0.0.1:18180";

type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

pub struct Env {
    pub engine: Engine,
    pub fx: AuthFixtures,
    pub gw: Gateway,
    pub trusted: bool,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<std::path::PathBuf> {
        vec![self.gw.log_path.clone()]
    }
}

type Def = harness::Def<Env>;

// ---------------------------------------------------------------- helpers

fn ctx(env: &Env, method: &str, path: &str, auth: AuthConfig) -> ExecutionContext {
    let mut spec = RequestSpec::http(method, &format!("{GATEWAY}{path}"));
    spec.auth = auth;
    let mut c = ExecutionContext::standalone(spec);
    c.isolation = "lab-auth".into();
    if env.trusted {
        c.integrations.push(integration("lab auth gateway", &[("127.0.0.1", 18180)]));
    }
    c
}

/// Add a request header marked sensitive (credential material).
fn secret_header(c: &mut ExecutionContext, name: &str, value: &str) {
    let mut kv = KeyValue::new(name, value);
    kv.sensitive = true;
    c.spec.headers.push(kv);
}

fn with_body(c: &mut ExecutionContext, text: &str) {
    c.spec.body = Body::Raw { text: text.into(), content_type: Some("application/json".into()) };
}

fn tv(s: &str) -> SensitiveValue {
    SensitiveValue::template(s)
}

fn api_key(name: &str, value: &str) -> AuthConfig {
    AuthConfig::ApiKey { name: name.into(), value: tv(value), location: KeyLocation::Header }
}

fn bearer(token: &str) -> AuthConfig {
    AuthConfig::Bearer { token: tv(token), prefix: "Bearer".into() }
}

fn basic(user: &str, pw: &str) -> AuthConfig {
    AuthConfig::Basic { username: user.into(), password: tv(pw) }
}

fn hmac_cfg(env: &Env) -> AuthConfig {
    AuthConfig::Hmac {
        config: HmacConfig {
            profile: HmacProfile::FerrumV2,
            username: "alice".into(),
            secret: tv(&env.fx.secrets.alice_hmac_secret),
            algorithm: HmacAlgorithm::HmacSha256,
            digest_header: BodyDigestHeader::ContentDigest,
            namespace: String::new(),
            allow_unsafe_legacy: false,
        },
    }
}

fn jwt_helper(env: &Env, consumer: Option<&str>) -> AuthConfig {
    AuthConfig::Jwt {
        algorithm: JwtAlgorithm::HS256,
        signing_key: tv(&env.fx.secrets.alice_jwt_secret),
        claims: JwtClaims {
            sub: Some("alice".into()),
            expires_in_secs: Some(300),
            extra_json: consumer.map(|c| format!(r#"{{"anvil_consumer":"{c}"}}"#)).unwrap_or_default(),
            ..Default::default()
        },
        kid: None,
        header_name: "Authorization".into(),
        prefix: "Bearer".into(),
    }
}

async fn go(env: &Env, c: &ExecutionContext) -> ExecutionOutput {
    send(&env.engine, c).await
}

fn body_error(o: &ExecutionOutput) -> String {
    let b = o.decoded_body.as_ref().unwrap_or(&o.body);
    serde_json::from_slice::<serde_json::Value>(b)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| String::from_utf8_lossy(&b[..b.len().min(120)]).into_owned())
}

fn header(o: &ExecutionOutput, name: &str) -> Option<String> {
    o.record.response.as_ref().and_then(|r| r.header_values(name).first().map(|s| s.to_string()))
}

/// Independent ground-truth probe: a minimal raw HTTP/1.1 request, read in
/// full. Execution records redact `WWW-Authenticate` (its name contains
/// "auth"), so challenge values are checked here instead. Never given to the
/// engine.
async fn raw_challenge(path: &str, headers: &[(&str, String)]) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::TcpStream::connect(AUTHORITY)).await.ok()?.ok()?;
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {AUTHORITY}\r\nConnection: close\r\n");
    for (n, v) in headers {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut buf)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    head.lines().find_map(|l| {
        l.split_once(':').filter(|(n, _)| n.trim().eq_ignore_ascii_case("www-authenticate")).map(|(_, v)| v.trim().to_string())
    })
}

fn challenge_is(c: &mut Checks, got: Option<String>, want: &str) {
    c.add(
        CheckKind::GroundTruth,
        format!("gateway challenge contains `{want}`"),
        got.as_deref().map(|v| v.contains(want)).unwrap_or(false),
        format!("{got:?}"),
    );
}

/// Ground truth that the stimulus produced the audited public signal.
fn signal(c: &mut Checks, o: &ExecutionOutput, status: u16, error: &str) {
    c.status_in(o, &[status]);
    let got = body_error(o);
    c.add(CheckKind::GroundTruth, format!("gateway body error is \"{error}\""), got == error, got);
}

/// Trusted: a gateway-outcome claim exists and stays ≤ likely. Untrusted:
/// the harness asserts no `ferrum.outcome*` finding at all.
fn gateway_outcome(c: &mut Checks, env: &Env, o: &ExecutionOutput) {
    if env.trusted {
        c.has_any(o, &["ferrum.outcome", "ferrum.outcome_ambiguous"]);
        c.max_confidence(o, "ferrum.outcome", Confidence::Likely);
        c.max_confidence(o, "ferrum.outcome_ambiguous", Confidence::Unknown);
    }
}

/// No finding may be confirmed while its title or explanation asserts `term`.
fn no_confirmed_text(c: &mut Checks, o: &ExecutionOutput, term: &str) {
    let t = term.to_lowercase();
    let bad: Vec<String> = o
        .record
        .findings
        .iter()
        .filter(|f| {
            f.confidence == Confidence::Confirmed && (f.title.to_lowercase().contains(&t) || f.explanation.to_lowercase().contains(&t))
        })
        .map(|f| f.code.clone())
        .collect();
    c.add(CheckKind::Diagnosis, format!("no confirmed claim mentioning '{term}'"), bad.is_empty(), format!("{bad:?}"));
}

/// The backend never received the request.
fn backend_untouched(c: &mut Checks, env: &Env, before: usize) {
    let n = env.fx.echo.log.count_requests().saturating_sub(before);
    c.add(CheckKind::GroundTruth, "the backend never received the request", n == 0, format!("{n}"));
}

fn backend_reached(c: &mut Checks, env: &Env, before: usize) {
    let n = env.fx.echo.log.count_requests().saturating_sub(before);
    c.add(CheckKind::GroundTruth, "the backend received the request", n >= 1, format!("{n}"));
}

/// Gateway transaction log shows this proxy answered `status`.
fn logged(c: &mut Checks, env: &Env, from: usize, proxy: &str, status: u16) -> Vec<String> {
    let lines = op_lines(&env.gw, from, proxy);
    let ok = lines.iter().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).any(|v| {
        ["response_status_code", "status_code", "status"].iter().any(|k| v.get(*k).and_then(|s| s.as_u64()) == Some(status as u64))
    });
    c.add(CheckKind::GroundTruth, format!("gateway transaction log: {proxy} answered {status}"), ok, format!("{lines:?}"));
    lines
}

/// Local credential failure: nothing reached the network.
fn local_only(c: &mut Checks, o: &ExecutionOutput, code: &str) {
    c.has(o, code);
    c.scope(o, code, SourceScope::LocalClient);
    let networked = o.record.attempts.iter().any(|a| a.connection.is_some() || a.failure.as_ref().map(|f| f.phase) != Some(Phase::Prepare));
    c.add(CheckKind::Diagnosis, "the failure is local: nothing was sent", !networked, "");
    c.absent_prefix(o, "http.");
    c.absent_prefix(o, "ferrum.");
}

fn signable(method: &str, path: &str, query: &str, body: &[u8]) -> SignableRequest {
    SignableRequest {
        method: method.into(),
        scheme: "http".into(),
        authority: AUTHORITY.into(),
        raw_path: path.into(),
        raw_query: query.into(),
        headers: vec![],
        body: body.to_vec(),
    }
}

fn hmac_params(env: &Env) -> HmacParams {
    HmacParams {
        profile: HmacProfile::FerrumV2,
        username: "alice".into(),
        secret: Zeroizing::new(env.fx.secrets.alice_hmac_secret.clone()),
        algorithm: HmacAlgorithm::HmacSha256,
        digest_header: BodyDigestHeader::ContentDigest,
        namespace: String::new(),
        allow_unsafe_legacy: false,
    }
}

/// A captured signed request: the headers a signer produced for one exact
/// request (the stimulus for replay / mutation / reordering).
fn captured_hmac(env: &Env, method: &str, path: &str, query: &str, body: &[u8], date: &str) -> Vec<(String, String)> {
    anvil_auth::hmac_sig::sign_with(&hmac_params(env), &signable(method, path, query, body), date, anvil_auth::hmac_sig::fresh_nonce())
        .expect("lab signer")
        .headers
}

fn manual(env: &Env, method: &str, target: &str, headers: &[(String, String)], body: Option<&str>) -> ExecutionContext {
    let mut c = ctx(env, method, target, AuthConfig::None);
    for (n, v) in headers {
        secret_header(&mut c, n, v);
    }
    if let Some(b) = body {
        with_body(&mut c, b);
    }
    c
}

fn now_http_date(offset_secs: i64) -> String {
    let t = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
    httpdate::fmt_http_date(t.into())
}

// ------------------------------------------------------------ key / basic

fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let key = env.fx.secrets.alice_key.clone();
        let o = go(env, &ctx(env, "GET", "/auth/key/echo", api_key("X-Lab-Api-Key", &key))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.absent_prefix(&o, "ferrum.");
        backend_reached(&mut c, env, before);
        let hdrs = env.fx.echo.log.last_request_headers().unwrap_or_default();
        c.add(
            CheckKind::GroundTruth,
            "hide_credentials: the backend never saw the API key",
            !hdrs.iter().any(|(n, v)| n.eq_ignore_ascii_case("x-lab-api-key") || v.contains(&key)),
            "",
        );
        record_excludes(&mut c, &o, &key, "the API key");
        let log = logged(&mut c, env, from, "auth001-key-auth", 200);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: log }
    })
}

fn auth001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let key = env.fx.secrets.alice_key.clone();
        // Right secret, wrong header name: the gateway sees no credential.
        let o = go(env, &ctx(env, "GET", "/auth/key/echo", api_key("X-API-Key", &key))).await;
        signal(&mut c, &o, 401, "Authentication required");
        let ch = raw_challenge("/auth/key/echo", &[("X-API-Key", key.clone())]).await;
        c.add(
            CheckKind::GroundTruth,
            "fallback challenge WWW-Authenticate: ferrum-edge",
            ch.as_deref() == Some("ferrum-edge"),
            format!("{ch:?}"),
        );
        c.has(&o, "http.unauthorized");
        gateway_outcome(&mut c, env, &o);
        c.absent_prefix(&o, "client.tls.");
        record_excludes(&mut c, &o, &key, "the API key");
        // Wrong secret under the right name.
        let wrong = go(env, &ctx(env, "GET", "/auth/key/echo", api_key("X-Lab-Api-Key", "not-a-lab-key"))).await;
        signal(&mut c, &wrong, 401, "Invalid API key");
        gateway_outcome(&mut c, env, &wrong);
        backend_untouched(&mut c, env, before);
        let log = logged(&mut c, env, from, "auth001-key-auth", 401);
        let r = go(env, &ctx(env, "GET", "/auth/key/echo", api_key("X-Lab-Api-Key", &key))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

fn auth002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let key = env.fx.secrets.alice_key.clone();
        let q = AuthConfig::ApiKey { name: "api_key".into(), value: tv(&key), location: KeyLocation::Query };
        let o = go(env, &ctx(env, "GET", "/auth/key-query/echo", q)).await;
        c.success(CheckKind::Diagnosis, &o);
        record_excludes(&mut c, &o, &key, "the query-string API key");
        let sent = o.record.attempts.last().map(|a| a.url.clone()).unwrap_or_default();
        c.add(
            CheckKind::Diagnosis,
            "the recorded attempt URL keeps the parameter name but not its value",
            sent.contains("api_key=") && !sent.contains(&key),
            sent,
        );
        let wrong = go(
            env,
            &ctx(
                env,
                "GET",
                "/auth/key-query/echo",
                AuthConfig::ApiKey { name: "api_key".into(), value: tv("nope"), location: KeyLocation::Query },
            ),
        )
        .await;
        signal(&mut c, &wrong, 401, "Invalid API key");
        Outcome { main: Some(o), recovery: Some(wrong), checks: c, operator_log: vec![] }
    })
}

fn auth003(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let o = go(env, &ctx(env, "GET", "/auth/basic/echo", basic("alice", "wrong-password"))).await;
        signal(&mut c, &o, 401, "Invalid credentials");
        let wrong = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:wrong-password");
        challenge_is(
            &mut c,
            raw_challenge("/auth/basic/echo", &[("Authorization", format!("Basic {wrong}"))]).await,
            "Basic realm=\"ferrum-edge\"",
        );
        c.has(&o, "http.unauthorized");
        gateway_outcome(&mut c, env, &o);
        c.absent_prefix(&o, "client.tls.");
        no_confirmed_text(&mut c, &o, "tls");
        backend_untouched(&mut c, env, before);
        record_excludes(&mut c, &o, "wrong-password", "the Basic password");
        let log = logged(&mut c, env, from, "auth003-basic-auth", 401);
        let r = go(env, &ctx(env, "GET", "/auth/basic/echo", basic("alice", &env.fx.secrets.alice_password))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

// ------------------------------------------------------------------- JWT

fn auth004(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let secret = env.fx.secrets.alice_jwt_secret.clone();
        let expired = env.fx.hs256(&secret, -120, None, serde_json::json!({"anvil_consumer": "alice"}));
        let o = go(env, &ctx(env, "GET", "/auth/jwt/echo", bearer(&expired))).await;
        signal(&mut c, &o, 401, "Invalid JWT token");
        // Local decode says "expired" as likely; the server's verdict is separate.
        c.has(&o, "auth.token_expired_locally");
        c.scope(&o, "auth.token_expired_locally", SourceScope::LocalClient);
        c.max_confidence(&o, "auth.token_expired_locally", Confidence::Likely);
        c.has(&o, "http.unauthorized");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "signature is valid");
        backend_untouched(&mut c, env, before);
        record_excludes(&mut c, &o, &expired, "the bearer token");
        let fresh = env.fx.hs256(&secret, 300, None, serde_json::json!({"anvil_consumer": "alice"}));
        let r = go(env, &ctx(env, "GET", "/auth/jwt/echo", bearer(&fresh))).await;
        c.success(CheckKind::Recovery, &r);
        c.absent_prefix(&r, "auth.token_expired_locally");
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth005(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let secret = env.fx.secrets.alice_jwt_secret.clone();
        let future = env.fx.hs256(&secret, 600, Some(300), serde_json::json!({"anvil_consumer": "alice"}));
        let o = go(env, &ctx(env, "GET", "/auth/jwt/echo", bearer(&future))).await;
        signal(&mut c, &o, 401, "Invalid JWT token");
        c.has(&o, "auth.token_not_yet_valid_locally");
        c.max_confidence(&o, "auth.token_not_yet_valid_locally", Confidence::Likely);
        no_confirmed_text(&mut c, &o, "clock");
        gateway_outcome(&mut c, env, &o);
        let fresh = env.fx.hs256(&secret, 300, Some(-5), serde_json::json!({"anvil_consumer": "alice"}));
        let r = go(env, &ctx(env, "GET", "/auth/jwt/echo", bearer(&fresh))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth006(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let forged = env.fx.hs256("an-unrelated-secret-0123456789abcdef", 300, None, serde_json::json!({"anvil_consumer": "alice"}));
        let o = go(env, &ctx(env, "GET", "/auth/jwt/echo", bearer(&forged))).await;
        signal(&mut c, &o, 401, "Invalid JWT token");
        // Anvil holds no verification key: no local signature verdict at all.
        c.absent_prefix(&o, "auth.");
        no_confirmed_text(&mut c, &o, "signature");
        gateway_outcome(&mut c, env, &o);
        let r = go(env, &ctx(env, "GET", "/auth/jwt/echo", jwt_helper(env, Some("alice")))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        // Valid signature, but only `sub`: the configured claim is anvil_consumer.
        let o = go(env, &ctx(env, "GET", "/auth/jwt/echo", jwt_helper(env, None))).await;
        signal(&mut c, &o, 401, "JWT missing identity claim");
        gateway_outcome(&mut c, env, &o);
        c.absent_prefix(&o, "auth.token_expired_locally");
        let nobody = go(env, &ctx(env, "GET", "/auth/jwt/echo", jwt_helper(env, Some("nobody")))).await;
        signal(&mut c, &nobody, 401, "Invalid JWT token");
        let r = go(env, &ctx(env, "GET", "/auth/jwt/echo", jwt_helper(env, Some("alice")))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, fetches) = (env.fx.echo.log.count_requests(), env.fx.idp.jwks_fetches());
        let t = env.fx.issuer_token(&env.fx.rotated_key, ROTATED_KID, ISSUER, AUDIENCE, 300, serde_json::Value::Null);
        let o = go(env, &ctx(env, "GET", "/auth/jwks/echo", bearer(&t))).await;
        signal(&mut c, &o, 401, "Invalid or unrecognized JWT");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "malicious");
        c.absent_prefix(&o, "auth.");
        backend_untouched(&mut c, env, before);
        let r = go(env, &ctx(env, "GET", "/auth/jwks/echo", bearer(&env.fx.good_token()))).await;
        c.success(CheckKind::Recovery, &r);
        let log = vec![format!("idp jwks fetches during scenario: {}", env.fx.idp.jwks_fetches() - fetches)];
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

fn auth009(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let bad_iss = env.fx.issuer_token(
            &env.fx.issuer_key,
            ISSUER_KID,
            "https://other-idp.anvil-lab.invalid",
            AUDIENCE,
            300,
            serde_json::Value::Null,
        );
        let o = go(env, &ctx(env, "GET", "/auth/jwks/echo", bearer(&bad_iss))).await;
        signal(&mut c, &o, 401, "Invalid or unrecognized JWT");
        gateway_outcome(&mut c, env, &o);
        let bad_aud = env.fx.issuer_token(&env.fx.issuer_key, ISSUER_KID, ISSUER, "some-other-api", 300, serde_json::Value::Null);
        let a = go(env, &ctx(env, "GET", "/auth/jwks/echo", bearer(&bad_aud))).await;
        signal(&mut c, &a, 401, "Invalid or unrecognized JWT");
        for x in [&o, &a] {
            let widen: Vec<String> = x
                .record
                .findings
                .iter()
                .flat_map(|f| f.remediation.iter())
                .map(|r| r.text.to_lowercase())
                .filter(|t| t.contains("audience") && (t.contains("disable") || t.contains("remove")))
                .collect();
            c.add(CheckKind::Diagnosis, "never suggests disabling audience/issuer validation", widen.is_empty(), format!("{widen:?}"));
        }
        let r = go(env, &ctx(env, "GET", "/auth/jwks/echo", bearer(&env.fx.good_token()))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth010(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let none = fixtures_auth::alg_none_token(
            serde_json::json!({"sub": "alice", "anvil_consumer": "alice", "exp": chrono::Utc::now().timestamp() + 300}),
        );
        let o = go(env, &ctx(env, "GET", "/auth/jwt/echo", bearer(&none))).await;
        signal(&mut c, &o, 401, "Invalid JWT token");
        no_confirmed_text(&mut c, &o, "verified");
        gateway_outcome(&mut c, env, &o);
        // HS256 presented to the asymmetric JWKS route (algorithm confusion).
        let hs = env.fx.hs256(&env.fx.secrets.alice_jwt_secret, 300, None, serde_json::json!({"iss": ISSUER, "aud": AUDIENCE}));
        let j = go(env, &ctx(env, "GET", "/auth/jwks/echo", bearer(&hs))).await;
        signal(&mut c, &j, 401, "Invalid or unrecognized JWT");
        no_confirmed_text(&mut c, &j, "verified");
        let n2 = fixtures_auth::alg_none_token(
            serde_json::json!({"sub": "alice", "iss": ISSUER, "aud": AUDIENCE, "exp": chrono::Utc::now().timestamp() + 300}),
        );
        let j2 = go(env, &ctx(env, "GET", "/auth/jwks/echo", bearer(&n2))).await;
        signal(&mut c, &j2, 401, "Invalid or unrecognized JWT");
        let r = go(env, &ctx(env, "GET", "/auth/jwks/echo", bearer(&env.fx.good_token()))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

/// Identity-provider outage: after the JWKS host goes away and the cached
/// keys pass `jwks_max_stale_seconds`, a valid token gets the same 401 as a
/// bad one. Anvil must keep both explanations open.
fn authx03(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let t = env.fx.good_token();
        let base = go(env, &ctx(env, "GET", "/auth/jwks-outage/echo", bearer(&t))).await;
        c.add(
            CheckKind::GroundTruth,
            "before the outage the token is accepted",
            base.record.response.as_ref().map(|r| r.status) == Some(200),
            "",
        );
        env.fx.idp_outage.set_mode(IdpMode::Down);
        let failed_before = env.fx.idp_outage.log.entries().len();
        // max_stale is 2 s and the store refreshes every second.
        tokio::time::sleep(std::time::Duration::from_millis(4_000)).await;
        let o = go(env, &ctx(env, "GET", "/auth/jwks-outage/echo", bearer(&t))).await;
        let refusals = env
            .fx
            .idp_outage
            .log
            .entries()
            .into_iter()
            .skip(failed_before)
            .filter(|e| matches!(&e.event, anvil_fixtures::GroundTruth::FaultApplied { fault } if fault == "idp_down_503"))
            .count();
        env.fx.idp_outage.set_mode(IdpMode::Up);
        c.add(
            CheckKind::GroundTruth,
            "the gateway's JWKS refreshes hit the outage",
            refusals >= 1,
            format!("{refusals} refused refreshes"),
        );
        signal(&mut c, &o, 401, "Invalid or unrecognized JWT");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "invalid");
        no_confirmed_text(&mut c, &o, "unavailable");
        c.absent_prefix(&o, "auth.");
        if env.trusted {
            let open = o.record.findings.iter().filter(|f| f.code == "ferrum.outcome").any(|f| {
                f.does_not_prove
                    .iter()
                    .chain(f.alternatives.iter())
                    .any(|t| t.contains("IdP") || t.contains("JWKS") || t.contains("dependency"))
            });
            c.add(CheckKind::Diagnosis, "the identity-provider explanation stays open", open, "");
        }
        // Recovery: the provider is back, the next refresh restores the keys.
        let mut r = None;
        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
            let x = go(env, &ctx(env, "GET", "/auth/jwks-outage/echo", bearer(&t))).await;
            let ok = x.record.response.as_ref().map(|s| s.status) == Some(200);
            r = Some(x);
            if ok {
                break;
            }
        }
        let r = r.expect("recovery attempts");
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

// --------------------------------------------------- OAuth2 / introspection

fn oauth_cc(env: &Env) -> AuthConfig {
    AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::ClientCredentials,
            token_url: env.fx.idp.url("/oauth/token"),
            authorization_url: String::new(),
            client_id: OAUTH_CLIENT_ID.into(),
            client_secret: tv(&env.fx.secrets.oauth_client_secret),
            scope: String::new(),
            audience: String::new(),
            client_auth: OAuthClientAuth::BasicHeader,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    }
}

fn auth015(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        env.engine.tokens.clear();
        let (before, from, tokens) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len(), env.fx.idp.token_requests());
        env.fx.idp.set_mode(IdpMode::Down);
        let o = go(env, &ctx(env, "GET", "/auth/introspect/echo", oauth_cc(env))).await;
        env.fx.idp.set_mode(IdpMode::Up);
        local_only(&mut c, &o, "local.auth_preparation_failed");
        c.absent_prefix(&o, "auth.");
        c.add(CheckKind::GroundTruth, "Anvil did ask the token endpoint", env.fx.idp.token_requests() > tokens, "");
        backend_untouched(&mut c, env, before);
        let lines = op_lines(&env.gw, from, "authx01-introspect");
        c.add(CheckKind::GroundTruth, "the gateway never saw the API request", lines.is_empty(), format!("{lines:?}"));
        let r = go(env, &ctx(env, "GET", "/auth/introspect/echo", oauth_cc(env))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: lines }
    })
}

fn auth016(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        env.engine.tokens.clear();
        let (from, tokens, intro) = (env.gw.log_lines().len(), env.fx.idp.token_requests(), env.fx.idp.introspections());
        let o = go(env, &ctx(env, "GET", "/auth/introspect/echo", oauth_cc(env))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(CheckKind::GroundTruth, "one client-credentials token request", env.fx.idp.token_requests() == tokens + 1, "");
        c.add(CheckKind::GroundTruth, "the gateway introspected the token at the IdP", env.fx.idp.introspections() > intro, "");
        record_excludes(&mut c, &o, &env.fx.secrets.oauth_client_secret, "the OAuth client secret");
        let again = go(env, &ctx(env, "GET", "/auth/introspect/echo", oauth_cc(env))).await;
        c.success(CheckKind::Diagnosis, &again);
        c.add(CheckKind::Diagnosis, "the cached token is reused (no second token request)", env.fx.idp.token_requests() == tokens + 1, "");
        let log = logged(&mut c, env, from, "authx01-introspect", 200);
        Outcome { main: Some(o), recovery: Some(again), checks: c, operator_log: log }
    })
}

fn authx01(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, intro) = (env.fx.echo.log.count_requests(), env.fx.idp.introspections());
        let o = go(env, &ctx(env, "GET", "/auth/introspect/echo", bearer("idp-at-never-issued-0000"))).await;
        signal(&mut c, &o, 401, "Inactive token");
        challenge_is(
            &mut c,
            raw_challenge("/auth/introspect/echo", &[("Authorization", "Bearer idp-at-never-issued-0000".into())]).await,
            "error=\"invalid_token\"",
        );
        c.add(
            CheckKind::GroundTruth,
            "the gateway asked the IdP (credential rejected by the IdP)",
            env.fx.idp.introspections() > intro,
            "",
        );
        c.has(&o, "http.unauthorized");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "unavailable");
        c.absent_prefix(&o, "http.service_unavailable");
        backend_untouched(&mut c, env, before);
        let good = "idp-at-lab-registered-0001";
        env.fx.idp.register_token(
            good,
            serde_json::json!({"username": "alice", "sub": "alice", "iss": ISSUER, "aud": AUDIENCE, "token_type": "bearer"}),
        );
        let r = go(env, &ctx(env, "GET", "/auth/introspect/echo", bearer(good))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn authx02(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let good = "idp-at-lab-registered-0002";
        env.fx.idp.register_token(
            good,
            serde_json::json!({"username": "alice", "sub": "alice", "iss": ISSUER, "aud": AUDIENCE, "token_type": "bearer"}),
        );
        // Introspection endpoint refused (nothing listens on 19104).
        let o = go(env, &ctx(env, "GET", "/auth/introspect-down/echo", bearer(good))).await;
        signal(&mut c, &o, 503, "Token introspection unavailable");
        let ch = raw_challenge("/auth/introspect-down/echo", &[("Authorization", format!("Bearer {good}"))]).await;
        c.add(CheckKind::GroundTruth, "no WWW-Authenticate challenge on the dependency failure", ch.is_none(), format!("{ch:?}"));
        c.has(&o, "http.service_unavailable");
        c.absent_prefix(&o, "http.unauthorized");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "invalid");
        c.absent_prefix(&o, "ferrum.token");
        backend_untouched(&mut c, env, before);
        // Variant: the IdP itself answers 503 — the same public signal.
        env.fx.idp.set_mode(IdpMode::Down);
        let v = go(env, &ctx(env, "GET", "/auth/introspect/echo", bearer(good))).await;
        env.fx.idp.set_mode(IdpMode::Up);
        signal(&mut c, &v, 503, "Token introspection unavailable");
        // Recovery: the same credential through the reachable IdP.
        let r = go(env, &ctx(env, "GET", "/auth/introspect/echo", bearer(good))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

// ------------------------------------------------------------------ HMAC

fn auth018(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gw.log_lines().len();
        let o = go(env, &ctx(env, "GET", "/auth/hmac/echo", hmac_cfg(env))).await;
        c.success(CheckKind::Diagnosis, &o);
        let mut post = ctx(env, "POST", "/auth/hmac/echo", hmac_cfg(env));
        with_body(&mut post, r#"{"order":42}"#);
        let p = go(env, &post).await;
        c.success(CheckKind::Diagnosis, &p);
        let nonce = |x: &ExecutionOutput| x.record.prepared.inferred.iter().find(|i| i.starts_with("auth hmac.nonce")).cloned();
        c.add(CheckKind::Diagnosis, "each send used its own nonce", nonce(&o).is_some() && nonce(&o) != nonce(&p), "");
        record_excludes(&mut c, &o, &env.fx.secrets.alice_hmac_secret, "the HMAC secret");
        let log = logged(&mut c, env, from, "auth018-hmac", 200);
        Outcome { main: Some(o), recovery: Some(p), checks: c, operator_log: log }
    })
}

fn auth018_skew(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let h = captured_hmac(env, "GET", "/auth/hmac/echo", "", b"", &now_http_date(-600));
        let o = go(env, &manual(env, "GET", "/auth/hmac/echo", &h, None)).await;
        signal(&mut c, &o, 401, "Missing or expired Date header");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "clock");
        let r = go(env, &ctx(env, "GET", "/auth/hmac/echo", hmac_cfg(env))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth019(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let h = captured_hmac(env, "POST", "/auth/hmac/echo", "", br#"{"amount":1}"#, &now_http_date(0));
        let o = go(env, &manual(env, "POST", "/auth/hmac/echo", &h, Some(r#"{"amount":1000}"#))).await;
        signal(&mut c, &o, 401, "Digest header does not match request body");
        gateway_outcome(&mut c, env, &o);
        backend_untouched(&mut c, env, before);
        // Anvil signs the final bytes, so the same edit re-signs correctly.
        let mut fixed = ctx(env, "POST", "/auth/hmac/echo", hmac_cfg(env));
        with_body(&mut fixed, r#"{"amount":1000}"#);
        let r = go(env, &fixed).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth020(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let h = captured_hmac(env, "GET", "/auth/hmac/echo", "", b"", &now_http_date(0));
        let first = go(env, &manual(env, "GET", "/auth/hmac/echo", &h, None)).await;
        c.add(
            CheckKind::GroundTruth,
            "the captured signed request is accepted once",
            first.record.response.as_ref().map(|r| r.status) == Some(200),
            "",
        );
        let before = env.fx.echo.log.count_requests();
        let o = go(env, &manual(env, "GET", "/auth/hmac/echo", &h, None)).await;
        signal(&mut c, &o, 401, "Signed request has already been used");
        gateway_outcome(&mut c, env, &o);
        backend_untouched(&mut c, env, before);
        // Anvil's own signer never reuses a nonce, even back to back.
        let mut ok = true;
        for _ in 0..3 {
            let r = go(env, &ctx(env, "GET", "/auth/hmac/echo", hmac_cfg(env))).await;
            ok &= r.record.response.as_ref().map(|x| x.status) == Some(200);
        }
        c.add(CheckKind::Recovery, "three fresh signed sends are all accepted", ok, "");
        let r = go(env, &ctx(env, "GET", "/auth/hmac/echo", hmac_cfg(env))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth021(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (path, query) = ("/auth/hmac/echo/a;b=c/x:y@z", "b=2&a=1&a=0&empty=&z=%41");
        let before = env.fx.echo.log.count_requests();
        let o = go(env, &ctx(env, "GET", &format!("{path}?{query}"), hmac_cfg(env))).await;
        c.success(CheckKind::Diagnosis, &o);
        let target = env.fx.echo.log.requests().into_iter().skip(before).map(|(_, p)| p).next().unwrap_or_default();
        c.add(CheckKind::GroundTruth, "the raw query reached the backend byte for byte", target.ends_with(&format!("?{query}")), target);
        // Signed for one parameter order, sent with another.
        let h = captured_hmac(env, "GET", path, "a=1&b=2", b"", &now_http_date(0));
        let bad = go(env, &manual(env, "GET", &format!("{path}?b=2&a=1"), &h, None)).await;
        signal(&mut c, &bad, 401, "Invalid credentials");
        gateway_outcome(&mut c, env, &bad);
        Outcome { main: Some(o), recovery: Some(bad), checks: c, operator_log: vec![] }
    })
}

fn auth022(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let body = br#"{"x":1}"#;
        let mut h = captured_hmac(env, "POST", "/auth/hmac/echo", "", body, &now_http_date(0));
        let (_, legacy) = anvil_auth::digest::header(BodyDigestHeader::LegacyDigest, anvil_auth::digest::DigestAlg::Sha256, body);
        h.push(("Digest".into(), legacy));
        let o = go(env, &manual(env, "POST", "/auth/hmac/echo", &h, Some(r#"{"x":1}"#))).await;
        signal(&mut c, &o, 401, "Ambiguous Digest and Content-Digest headers");
        gateway_outcome(&mut c, env, &o);
        // Anvil refuses to sign a request that already carries a digest header.
        let from = env.gw.log_lines().len();
        let mut local = ctx(env, "POST", "/auth/hmac/echo", hmac_cfg(env));
        with_body(&mut local, r#"{"x":1}"#);
        local.spec.headers.push(KeyValue::new("Digest", "sha-256=AAAA"));
        let l = go(env, &local).await;
        local_only(&mut c, &l, "local.auth_preparation_failed");
        c.add(
            CheckKind::GroundTruth,
            "the locally refused request never reached the gateway",
            op_lines(&env.gw, from, "auth018-hmac").is_empty(),
            "",
        );
        let mut r = ctx(env, "POST", "/auth/hmac/echo", hmac_cfg(env));
        with_body(&mut r, r#"{"x":1}"#);
        let r = go(env, &r).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(l), checks: c, operator_log: vec![] }
    })
}

fn auth023(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gw.log_lines().len();
        let mut cfg = hmac_cfg(env);
        if let AuthConfig::Hmac { config } = &mut cfg {
            config.profile = HmacProfile::FerrumV1Legacy;
        }
        let o = go(env, &ctx(env, "GET", "/auth/hmac/echo", cfg)).await;
        local_only(&mut c, &o, "local.auth_preparation_failed");
        c.add(CheckKind::GroundTruth, "nothing reached the gateway", op_lines(&env.gw, from, "auth018-hmac").is_empty(), "");
        let r = go(env, &ctx(env, "GET", "/auth/hmac/echo", hmac_cfg(env))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

// ------------------------------------------------------------------ DPoP

fn dpop_cfg(token: &str, key: &str) -> AuthConfig {
    AuthConfig::Dpop {
        config: DpopConfig { access_token: tv(token), private_key_pem: tv(key), dpop_scheme: true, handle_nonce_challenge: true },
    }
}

fn manual_proof(key: &str, method: &str, path: &str, token: &str) -> String {
    let htu = anvil_auth::dpop::htu("http", AUTHORITY, path).expect("htu");
    anvil_auth::dpop::proof(key, method, &htu, Some(token), None, chrono::Utc::now()).expect("proof").jwt
}

fn auth024(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let key = env.fx.dpop_key.clone();
        let token = env.fx.dpop_bound_token(&key);
        let o = go(env, &ctx(env, "GET", "/auth/dpop", dpop_cfg(&token, &key))).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(
            CheckKind::Diagnosis,
            "the proof binding (jkt/htu/jti) is recorded without the key",
            o.record.prepared.inferred.iter().any(|i| i.starts_with("auth dpop.jkt")),
            "",
        );
        record_excludes(&mut c, &o, "PRIVATE KEY", "the DPoP private key");
        // Negative controls, each a distinct gateway verdict.
        let dp = |proof: Option<String>| {
            let mut h = vec![("Authorization".to_string(), format!("DPoP {token}"))];
            if let Some(p) = proof {
                h.push(("DPoP".into(), p));
            }
            h
        };
        let missing = go(env, &manual(env, "GET", "/auth/dpop", &dp(None), None)).await;
        signal(&mut c, &missing, 401, "DPoP proof required");
        gateway_outcome(&mut c, env, &missing);
        let wrong_url = go(env, &manual(env, "GET", "/auth/dpop", &dp(Some(manual_proof(&key, "GET", "/auth/other", &token))), None)).await;
        c.status_in(&wrong_url, &[401]);
        // 0.9.5 reports an htu for another path as either literal.
        let e = body_error(&wrong_url);
        c.add(CheckKind::GroundTruth, "a proof for another URL is rejected", e == "DPoP URL mismatch" || e == "DPoP validation failed", e);
        gateway_outcome(&mut c, env, &wrong_url);
        let wrong_key =
            go(env, &manual(env, "GET", "/auth/dpop", &dp(Some(manual_proof(&env.fx.other_dpop_key, "GET", "/auth/dpop", &token))), None))
                .await;
        c.status_in(&wrong_key, &[401]);
        c.add(
            CheckKind::GroundTruth,
            "a proof from an unbound key is rejected",
            body_error(&wrong_key).starts_with("DPoP"),
            body_error(&wrong_key),
        );
        let r = go(env, &ctx(env, "GET", "/auth/dpop", dpop_cfg(&token, &key))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth025(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let key = env.fx.dpop_key.clone();
        let token = env.fx.dpop_bound_token(&key);
        let h = vec![
            ("Authorization".to_string(), format!("DPoP {token}")),
            ("DPoP".to_string(), manual_proof(&key, "GET", "/auth/dpop", &token)),
        ];
        let first = go(env, &manual(env, "GET", "/auth/dpop", &h, None)).await;
        c.add(
            CheckKind::GroundTruth,
            "the captured proof is accepted once",
            first.record.response.as_ref().map(|r| r.status) == Some(200),
            "",
        );
        let o = go(env, &manual(env, "GET", "/auth/dpop", &h, None)).await;
        signal(&mut c, &o, 401, "DPoP replay");
        gateway_outcome(&mut c, env, &o);
        c.add(CheckKind::GroundTruth, "0.9.5 sends no DPoP-Nonce challenge", header(&o, "dpop-nonce").is_none(), "");
        c.add(
            CheckKind::Diagnosis,
            "no automatic retry loop (one attempt)",
            o.record.attempts.len() == 1,
            format!("{}", o.record.attempts.len()),
        );
        let mut ok = true;
        for _ in 0..3 {
            let r = go(env, &ctx(env, "GET", "/auth/dpop", dpop_cfg(&token, &key))).await;
            ok &= r.record.response.as_ref().map(|x| x.status) == Some(200);
        }
        c.add(CheckKind::Recovery, "fresh proofs per send are all accepted", ok, "");
        Outcome { main: Some(o), recovery: Some(first), checks: c, operator_log: vec![] }
    })
}

// ------------------------------------------------------------------ LDAP

fn auth027(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, rej) = (env.fx.echo.log.count_requests(), env.fx.ldap.binds_rejected.load(std::sync::atomic::Ordering::SeqCst));
        let o = go(env, &ctx(env, "GET", "/auth/ldap/echo", basic("alice", "not-the-directory-password"))).await;
        signal(&mut c, &o, 401, "LDAP authentication failed");
        c.add(
            CheckKind::GroundTruth,
            "the directory rejected the bind (invalid credentials)",
            env.fx.ldap.binds_rejected.load(std::sync::atomic::Ordering::SeqCst) > rej,
            "",
        );
        c.has(&o, "http.unauthorized");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "unavailable");
        no_confirmed_text(&mut c, &o, "unreachable");
        backend_untouched(&mut c, env, before);
        let r = go(env, &ctx(env, "GET", "/auth/ldap/echo", basic("alice", &env.fx.secrets.alice_ldap_password))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth028(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let pw = env.fx.secrets.alice_ldap_password.clone();
        let o = go(env, &ctx(env, "GET", "/auth/ldap-down/echo", basic("alice", &pw))).await;
        signal(&mut c, &o, 500, "LDAP authentication temporarily unavailable");
        c.absent_prefix(&o, "http.unauthorized");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "password");
        no_confirmed_text(&mut c, &o, "invalid");
        backend_untouched(&mut c, env, before);
        let log = logged(&mut c, env, from, "auth028-ldap-down", 500);
        // The same credentials succeed where the directory is reachable.
        let r = go(env, &ctx(env, "GET", "/auth/ldap/echo", basic("alice", &pw))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

// ------------------------------------------------------ multi-auth / ACL

fn auth032(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let bob = env.fx.secrets.bob_key.clone();
        let only_bob = go(env, &ctx(env, "GET", "/auth/multi/echo", api_key("X-Lab-Api-Key", &bob))).await;
        c.success(CheckKind::Diagnosis, &only_bob);
        // Two valid identities: the first successful mechanism (jwt, alice)
        // wins and is judged alone — privileges are not combined.
        let before = env.fx.echo.log.count_requests();
        let both = AuthConfig::Multi { profiles: vec![jwt_helper(env, Some("alice")), api_key("X-Lab-Api-Key", &bob)] };
        let o = go(env, &ctx(env, "GET", "/auth/multi/echo", both)).await;
        signal(&mut c, &o, 403, "Consumer is not allowed");
        c.has(&o, "http.forbidden");
        gateway_outcome(&mut c, env, &o);
        c.absent_prefix(&o, "http.unauthorized");
        backend_untouched(&mut c, env, before);
        c.add(
            CheckKind::Diagnosis,
            "both presented profiles are listed in the record",
            o.record.prepared.auth_label.contains("multi"),
            o.record.prepared.auth_label.clone(),
        );
        // An invalid JWT does not block a valid key in multi mode.
        let bad_jwt = AuthConfig::Multi { profiles: vec![bearer("not.a.jwt"), api_key("X-Lab-Api-Key", &bob)] };
        let mixed = go(env, &ctx(env, "GET", "/auth/multi/echo", bad_jwt)).await;
        c.add(
            CheckKind::GroundTruth,
            "multi mode: a later valid mechanism wins over an earlier rejection",
            mixed.record.response.as_ref().map(|r| r.status) == Some(200),
            "",
        );
        let none = go(env, &ctx(env, "GET", "/auth/multi/echo", api_key("X-Lab-Api-Key", "nobody-key"))).await;
        signal(&mut c, &none, 401, "Invalid API key");
        Outcome { main: Some(o), recovery: Some(only_bob), checks: c, operator_log: vec![] }
    })
}

fn gw011(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let o = go(env, &ctx(env, "GET", "/gw/acl/echo", api_key("X-Lab-Api-Key", &env.fx.secrets.alice_key))).await;
        signal(&mut c, &o, 403, "Consumer is not allowed");
        c.has(&o, "http.forbidden");
        c.absent_prefix(&o, "http.unauthorized");
        gateway_outcome(&mut c, env, &o);
        no_confirmed_text(&mut c, &o, "password");
        let waf = o.record.findings.iter().any(|f| f.confidence >= Confidence::Likely && f.title.to_lowercase().contains("waf"));
        c.add(CheckKind::Diagnosis, "the ACL 403 is not called a WAF block", !waf, "");
        backend_untouched(&mut c, env, before);
        let log = logged(&mut c, env, from, "gw011-acl", 403);
        let r = go(env, &ctx(env, "GET", "/gw/acl/echo", api_key("X-Lab-Api-Key", &env.fx.secrets.bob_key))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

// ------------------------------------------------ backend 401 lookalikes

/// The response is the backend's own; nothing may attribute it to a gateway
/// authentication plugin.
fn not_gateway_auth(c: &mut Checks, o: &ExecutionOutput) {
    c.has(o, "http.unauthorized");
    c.absent_prefix(o, "ferrum.outcome");
    let bad: Vec<String> = o
        .record
        .findings
        .iter()
        .filter(|f| f.scope == SourceScope::GatewayAdmission && f.confidence >= Confidence::Likely)
        .map(|f| f.code.clone())
        .collect();
    c.add(CheckKind::Diagnosis, "no likely/confirmed gateway-admission claim", bad.is_empty(), format!("{bad:?}"));
}

fn has_relay(c: &mut Checks, o: &ExecutionOutput) {
    c.has(o, "ferrum.relayed_backend_response");
    c.scope(o, "ferrum.relayed_backend_response", SourceScope::UpstreamApplication);
    c.max_confidence(o, "ferrum.relayed_backend_response", Confidence::Likely);
}

fn authx04(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        let body: String = url::form_urlencoded::byte_serialize(br#"{"error":"Invalid API key"}"#).collect();
        // Valid gateway credential; the application answers a byte-identical 401.
        let o =
            go(env, &ctx(env, "GET", &format!("/auth/key/status/401?body={body}"), api_key("X-Lab-Api-Key", &env.fx.secrets.alice_key)))
                .await;
        signal(&mut c, &o, 401, "Invalid API key");
        not_gateway_auth(&mut c, &o);
        if env.trusted {
            has_relay(&mut c, &o);
        }
        backend_reached(&mut c, env, before);
        let log = logged(&mut c, env, from, "auth001-key-auth", 401);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: log }
    })
}

fn authx05(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let body: String = url::form_urlencoded::byte_serialize(br#"{"error":"Authentication required"}"#).collect();
        let o =
            go(env, &ctx(env, "GET", &format!("/auth/open/status/401?body={body}&header=WWW-Authenticate:ferrum-edge"), AuthConfig::None))
                .await;
        signal(&mut c, &o, 401, "Authentication required");
        let ch = raw_challenge(&format!("/auth/open/status/401?body={body}&header=WWW-Authenticate:ferrum-edge"), &[]).await;
        c.add(
            CheckKind::GroundTruth,
            "the backend sent the gateway's fallback challenge itself",
            ch.as_deref() == Some("ferrum-edge"),
            format!("{ch:?}"),
        );
        not_gateway_auth(&mut c, &o);
        absent_scope(&mut c, &o, SourceScope::GatewayAdmission);
        if env.trusted {
            has_relay(&mut c, &o);
        }
        backend_reached(&mut c, env, before);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

// -------------------------------------------------------------- registry

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-AUTH", title: "Positive control: valid API key, credential hidden from backend", run: ctrl },
        Def { id: "AUTH-001", title: "API key under the wrong header name, wrong key, then recovery", run: auth001 },
        Def { id: "AUTH-002", title: "API key in the query string is redacted", run: auth002 },
        Def { id: "AUTH-003", title: "Basic credentials rejected, then accepted", run: auth003 },
        Def { id: "AUTH-004", title: "Expired JWT: local decode vs gateway verdict", run: auth004 },
        Def { id: "AUTH-005", title: "JWT not yet valid (nbf in the future)", run: auth005 },
        Def { id: "AUTH-006", title: "JWT signed with the wrong secret", run: auth006 },
        Def { id: "AUTH-007", title: "JWT without the configured consumer claim", run: auth007 },
        Def { id: "AUTH-008", title: "JWKS: token signed by an unpublished key (unknown kid)", run: auth008 },
        Def { id: "AUTH-009", title: "JWKS: issuer and audience mismatch", run: auth009 },
        Def { id: "AUTH-010", title: "JWT algorithm confusion (alg none, HS256 on a JWKS route)", run: auth010 },
        Def { id: "AUTH-X03", title: "JWKS provider outage past max-stale: same 401 as a bad token", run: authx03 },
        Def { id: "AUTH-015", title: "OAuth token endpoint outage: API request never sent", run: auth015 },
        Def { id: "AUTH-016", title: "OAuth client credentials + gateway token introspection", run: auth016 },
        Def { id: "AUTH-X01", title: "Introspection: IdP says the token is inactive (credential rejected)", run: authx01 },
        Def { id: "AUTH-X02", title: "Introspection endpoint unavailable (dependency failure)", run: authx02 },
        Def { id: "AUTH-018", title: "HMAC v2 signed GET and POST", run: auth018 },
        Def { id: "AUTH-018.skew", title: "HMAC Date header outside the clock-skew window", run: auth018_skew },
        Def { id: "AUTH-019", title: "HMAC body changed after signing", run: auth019 },
        Def { id: "AUTH-020", title: "HMAC replayed signed request", run: auth020 },
        Def { id: "AUTH-021", title: "HMAC raw path and order-sensitive query", run: auth021 },
        Def { id: "AUTH-022", title: "HMAC with both Digest and Content-Digest", run: auth022 },
        Def { id: "AUTH-023", title: "HMAC legacy v1 profile stays disabled without opt-in", run: auth023 },
        Def { id: "AUTH-024", title: "DPoP-bound access token and proof binding", run: auth024 },
        Def { id: "AUTH-025", title: "DPoP proof replay", run: auth025 },
        Def { id: "AUTH-027", title: "LDAP directory rejects the credentials", run: auth027 },
        Def { id: "AUTH-028", title: "LDAP directory unreachable", run: auth028 },
        Def { id: "AUTH-032", title: "Multi-auth identity selection and ACL", run: auth032 },
        Def { id: "GW-011", title: "ACL denial for an authenticated consumer", run: gw011 },
        Def { id: "AUTH-X04", title: "Backend 401 byte-identical to key_auth's rejection", run: authx04 },
        Def { id: "AUTH-X05", title: "Backend 401 with the gateway's fallback challenge", run: authx05 },
    ]
}

fn skips() -> Vec<(&'static str, &'static str, &'static str)> {
    let client_only = "client-side OAuth flow with no gateway leg (external browser, loopback redirect, state/PKCE, refresh single-flight); covered by anvil-auth unit tests, not a live-gateway scenario";
    vec![
        ("AUTH-011", "OAuth PKCE round trip", client_only),
        ("AUTH-012", "OAuth state mismatch", client_only),
        ("AUTH-013", "OAuth redirect spoof", client_only),
        ("AUTH-014", "OAuth refresh race", client_only),
        (
            "AUTH-017",
            "OIDC browser session",
            "needs an interactive system-browser session with the oidc_relying_party plugin; the lab has no browser driver, and Anvil never imports browser cookies automatically",
        ),
        (
            "AUTH-025.nonce",
            "DPoP server-nonce challenge",
            "infeasible on Ferrum Edge 0.9.5: jwks_auth implements no DPoP-Nonce / use_dpop_nonce challenge (audit §5.4); AUTH-025 covers the replay half live",
        ),
        (
            "AUTH-029",
            "SOAP UsernameToken",
            "soap_ws_security exists in 0.9.5 but this lab pass has no signed-SOAP/UsernameToken fixture set; not covered yet",
        ),
        (
            "AUTH-030",
            "SOAP XML signature",
            "soap_ws_security exists in 0.9.5 but this lab pass has no audited XML-signature fixture; not covered yet",
        ),
        ("AUTH-031", "SOAP SAML assertion", "needs a trusted SAML issuer fixture; Anvil never mints assertions; not covered yet"),
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "auth",
        about: "Authentication families, IdP/LDAP dependencies, multi-auth and ACL (HTTP 18180)",
        scenarios: || {
            let mut v: Vec<(&'static str, &'static str)> = all().into_iter().map(|d| (d.id, d.title)).collect();
            v.extend(skips().into_iter().map(|(id, title, _)| (id, title)));
            v
        },
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let fx = AuthFixtures::start().await?;
    let vars = fx.secrets.template_vars();
    let vars: Vec<(&str, String)> = vars.iter().map(|(k, v)| (*k, v.clone())).collect();
    let gw = Gateway::start(
        "auth",
        "auth.conf",
        "auth.yaml",
        &vars,
        18190,
        &[("FERRUM_BASIC_AUTH_HMAC_SECRET", fx.secrets.basic_hmac_secret.clone())],
    )
    .await?;
    // Let the gateway's JWKS fetch and backend capability probe settle.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    Ok(Env { engine: Engine::new(), fx, gw, trusted: true })
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("auth")?;
    let mut env = start().await?;
    let mut results = match harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await {
        Ok(r) => r,
        Err(e) => {
            env.gw.stop().await;
            return Err(e);
        }
    };
    for (id, title, reason) in skips() {
        if args.only.is_empty() || args.only.iter().any(|s| s.eq_ignore_ascii_case(id)) {
            eprintln!("{id:22} skipped {title}\n    — {reason}");
            results.push(ctx.skipped(id, title, reason));
        }
    }
    let fin = harness::finish(&ctx, &env, &results);
    env.gw.stop().await;
    fin?;
    Ok(results)
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!("auth lab running: gateway {GATEWAY} (admin 127.0.0.1:18190); IdP {}; LDAP ldap://127.0.0.1:19106", env.fx.idp.url("/"));
    println!("operator log: {}", env.gw.log_path.display());
    println!("per-run credentials are in lab/.run/auth/auth.yaml (lab-only, regenerated each start)");
    harness::wait_for_shutdown().await?;
    env.gw.stop().await;
    Ok(())
}
