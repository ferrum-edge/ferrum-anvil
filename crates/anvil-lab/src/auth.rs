//! Scenarios for the `auth` gateway profile: every authentication family
//! Ferrum Edge 0.9.5 offers that a loopback lab can drive for real
//! (key_auth, basic_auth, jwt_auth, jwks_auth, DPoP, hmac_auth v2,
//! oauth2_introspection, ldap_auth, multi-auth, access_control,
//! soap_ws_security UsernameToken / X.509 signature / SAML, and the
//! oidc_relying_party browser session), through
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
use crate::fixtures_auth_soap::{SamlSpec, Signer};
use crate::gateway::Gateway;
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use crate::tls::{absent_scope, integration, op_lines, record_excludes, send};
use anvil_auth::{HmacParams, SignableRequest};
use anvil_domain::auth::{
    AuthConfig, BodyDigestHeader, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile, JwtAlgorithm, JwtClaims, KeyLocation, OAuth2Config,
    OAuthClientAuth, OAuthGrant, WsseConfig, WssePasswordType,
};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::Phase;
use anvil_domain::request::{Body, KeyValue, RequestSpec, SoapVersion};
use anvil_domain::secret::SensitiveValue;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::gateway_idp::IdpMode;
use sha2::Digest as _;
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

// ------------------------------------------------- SOAP WS-Security (0.9.5)

const SOAP_ENVELOPE: &str = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:Ping xmlns:m="urn:anvil:lab:soap">anvil-lab-ping</m:Ping></soap:Body></soap:Envelope>"#;

fn soap_ctx(env: &Env, path: &str, auth: AuthConfig, envelope: &str) -> ExecutionContext {
    let mut c = ctx(env, "POST", path, auth);
    c.spec.body = Body::Soap { version: SoapVersion::Soap11, envelope: envelope.into(), action: Some("urn:anvil:lab:soap#Ping".into()) };
    c
}

fn wsse(_env: &Env, password: &str, ptype: WssePasswordType, ttl: Option<u32>, saml: Option<&str>) -> AuthConfig {
    AuthConfig::Wsse {
        config: WsseConfig {
            username: "alice".into(),
            password: tv(password),
            password_type: ptype,
            timestamp_ttl_secs: ttl,
            saml_assertion: saml.map(tv),
        },
    }
}

/// A WS-Security envelope as Anvil's own signer produced it for one send
/// (the captured request for replay / expiry stimuli, sent back raw).
fn captured_wsse(env: &Env, ptype: WssePasswordType, ttl: u32) -> String {
    let bytes = anvil_auth::wsse::insert_security(
        SOAP_ENVELOPE.as_bytes(),
        "alice",
        &env.fx.secrets.soap_alice_password,
        ptype,
        Some(ttl),
        None,
        chrono::Utc::now(),
    )
    .expect("lab wsse capture");
    String::from_utf8(bytes).expect("utf-8 envelope")
}

/// The request body the echo backend received (it reflects it in `body`).
fn echoed_body(o: &ExecutionOutput) -> String {
    let b = o.decoded_body.as_ref().unwrap_or(&o.body);
    serde_json::from_slice::<serde_json::Value>(b)
        .ok()
        .and_then(|v| v.get("body").and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_default()
}

/// Shared checks for a gateway WS-Security rejection: a generic 401, no
/// confirmed claim about the credential, never a TLS finding, gateway
/// attribution capped at likely, no secret in the record.
fn soap_rejection(c: &mut Checks, env: &Env, o: &ExecutionOutput, error: &str) {
    signal(c, o, 401, error);
    c.has(o, "http.unauthorized");
    c.absent_prefix(o, "client.tls.");
    c.absent_prefix(o, "auth.browser_session_required");
    for term in ["password", "signature", "certificate", "expired", "saml", "replay"] {
        no_confirmed_text(c, o, term);
    }
    c.max_confidence(o, "ferrum.outcome", Confidence::Likely);
    if !env.trusted {
        c.absent_prefix(o, "ferrum.");
    }
    record_excludes(c, o, &env.fx.secrets.soap_alice_password, "the WS-Security password");
}

fn auth029(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let pw = env.fx.secrets.soap_alice_password.clone();
        let (before, from) = (env.fx.echo.log.count_requests(), env.gw.log_lines().len());
        // Accepted control: PasswordDigest built by Anvil at send time.
        let ok =
            go(env, &soap_ctx(env, "/soap/digest/echo", wsse(env, &pw, WssePasswordType::PasswordDigest, Some(60), None), SOAP_ENVELOPE))
                .await;
        c.success(CheckKind::Diagnosis, &ok);
        c.add(CheckKind::Diagnosis, "PasswordDigest never puts the password on the wire", !echoed_body(&ok).contains(&pw), "");
        record_excludes(&mut c, &ok, &pw, "the WS-Security password");
        // Wrong password.
        let wrong = go(
            env,
            &soap_ctx(
                env,
                "/soap/digest/echo",
                wsse(env, "not-the-password", WssePasswordType::PasswordDigest, Some(60), None),
                SOAP_ENVELOPE,
            ),
        )
        .await;
        soap_rejection(&mut c, env, &wrong, "WS-Security: invalid credentials");
        record_excludes(&mut c, &wrong, "not-the-password", "the wrong password");
        // Replay: the identical captured envelope, twice (raw bytes; Anvil's
        // own signer would never reuse a nonce).
        let captured = captured_wsse(env, WssePasswordType::PasswordDigest, 60);
        let first = go(env, &soap_ctx(env, "/soap/digest/echo", AuthConfig::None, &captured)).await;
        c.add(
            CheckKind::GroundTruth,
            "the captured envelope is accepted once",
            first.record.response.as_ref().map(|r| r.status) == Some(200),
            "",
        );
        c.add(
            CheckKind::Diagnosis,
            "Anvil sent the captured bytes verbatim",
            first.record.prepared.body_sha256.as_deref() == Some(&hex::encode(sha2::Sha256::digest(captured.as_bytes()))),
            "",
        );
        let before_replay = env.fx.echo.log.count_requests();
        let o = go(env, &soap_ctx(env, "/soap/digest/echo", AuthConfig::None, &captured)).await;
        soap_rejection(&mut c, env, &o, "WS-Security: nonce replay detected");
        gateway_outcome(&mut c, env, &o);
        backend_untouched(&mut c, env, before_replay);
        // Recovery: Anvil generates a fresh nonce and Created per send.
        let mut all_ok = true;
        for _ in 0..3 {
            let r = go(
                env,
                &soap_ctx(env, "/soap/digest/echo", wsse(env, &pw, WssePasswordType::PasswordDigest, Some(60), None), SOAP_ENVELOPE),
            )
            .await;
            all_ok &= r.record.response.as_ref().map(|x| x.status) == Some(200);
        }
        c.add(CheckKind::Recovery, "three fresh Anvil envelopes in a row are all accepted", all_ok, "");
        c.add(CheckKind::GroundTruth, "the backend received the accepted requests", env.fx.echo.log.count_requests() >= before + 5, "");
        let log = logged(&mut c, env, from, "auth029-soap-digest", 401);
        Outcome { main: Some(o), recovery: Some(ok), checks: c, operator_log: log }
    })
}

fn auth029_text(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let pw = env.fx.secrets.soap_alice_password.clone();
        let o =
            go(env, &soap_ctx(env, "/soap/text/echo", wsse(env, &pw, WssePasswordType::PasswordText, Some(60), None), SOAP_ENVELOPE)).await;
        c.success(CheckKind::Diagnosis, &o);
        record_excludes(&mut c, &o, &pw, "the PasswordText password");
        let got = echoed_body(&o);
        c.add(
            CheckKind::GroundTruth,
            "remove_credential: the backend received the envelope without the password",
            !got.is_empty() && !got.contains(&pw) && got.contains("anvil-lab-ping"),
            "",
        );
        // Lookalike: the right password presented as PasswordText to the
        // PasswordDigest route is a profile mismatch, not a wrong password.
        let m = go(env, &soap_ctx(env, "/soap/digest/echo", wsse(env, &pw, WssePasswordType::PasswordText, Some(60), None), SOAP_ENVELOPE))
            .await;
        soap_rejection(&mut c, env, &m, "WS-Security: Password Type does not match the configured password_type");
        let r =
            go(env, &soap_ctx(env, "/soap/text/echo", wsse(env, &pw, WssePasswordType::PasswordText, Some(60), None), SOAP_ENVELOPE)).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn auth029_expired(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let pw = env.fx.secrets.soap_alice_password.clone();
        // An envelope Anvil generated with a 1 s Timestamp lifetime, sent
        // after it lapsed (the route allows 2 s of clock skew).
        let captured = captured_wsse(env, WssePasswordType::PasswordDigest, 1);
        tokio::time::sleep(std::time::Duration::from_millis(4_200)).await;
        let before = env.fx.echo.log.count_requests();
        let o = go(env, &soap_ctx(env, "/soap/digest/echo", AuthConfig::None, &captured)).await;
        soap_rejection(&mut c, env, &o, "WS-Security: Timestamp has expired");
        backend_untouched(&mut c, env, before);
        let r =
            go(env, &soap_ctx(env, "/soap/digest/echo", wsse(env, &pw, WssePasswordType::PasswordDigest, Some(60), None), SOAP_ENVELOPE))
                .await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

/// Whether the host can produce the signed-XML fixtures (reason otherwise).
fn soap_signing_unavailable(env: &Env) -> Option<String> {
    env.fx.soap.tools.signing_unavailable()
}

fn signed(env: &Env, signer: &Signer, payload: &str) -> String {
    env.fx.soap.signed_envelope(signer, payload, chrono::Utc::now(), 60).expect("lab signed envelope")
}

fn auth030(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let soap = &env.fx.soap;
        let envelope = signed(env, &soap.soap_signer, "order-42");
        let before = env.fx.echo.log.count_requests();
        let ok = go(env, &soap_ctx(env, "/soap/x509/echo", AuthConfig::None, &envelope)).await;
        c.success(CheckKind::Diagnosis, &ok);
        c.add(
            CheckKind::Diagnosis,
            "Anvil sent the signed envelope byte for byte (no re-serialization)",
            ok.record.prepared.body_sha256.as_deref() == Some(&hex::encode(sha2::Sha256::digest(envelope.as_bytes()))),
            "",
        );
        c.add(CheckKind::GroundTruth, "the backend received exactly the signed bytes", echoed_body(&ok) == envelope, "");
        backend_reached(&mut c, env, before);
        // Tampered signed element: the Body changes after signing.
        let tampered = signed(env, &soap.soap_signer, "order-42").replace("order-42", "order-99");
        let before = env.fx.echo.log.count_requests();
        let o = go(env, &soap_ctx(env, "/soap/x509/echo", AuthConfig::None, &tampered)).await;
        soap_rejection(&mut c, env, &o, "WS-Security: Reference digest mismatch");
        backend_untouched(&mut c, env, before);
        // Untrusted key: a valid signature by a certificate the route does not trust.
        let rogue = go(env, &soap_ctx(env, "/soap/x509/echo", AuthConfig::None, &signed(env, &soap.rogue, "order-42"))).await;
        soap_rejection(&mut c, env, &rogue, "WS-Security: signing certificate is not trusted");
        // Recovery: a freshly signed, untouched envelope.
        let r = go(env, &soap_ctx(env, "/soap/x509/echo", AuthConfig::None, &signed(env, &soap.soap_signer, "order-43"))).await;
        c.success(CheckKind::Recovery, &r);
        let log = vec![format!(
            "lab signer: {}; route trusts {} (per-run throwaway RSA-2048)",
            soap.tools.versions,
            soap.soap_signer.cert_path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default()
        )];
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

fn saml_spec(issuer: &str, audience: &str, not_before_offset: i64, lifetime: i64) -> SamlSpec {
    let now = chrono::Utc::now();
    SamlSpec {
        issuer: issuer.into(),
        name_id: "alice".into(),
        audience: audience.into(),
        recipient: SAML_RECIPIENT.into(),
        not_before: now + chrono::Duration::seconds(not_before_offset),
        not_on_or_after: now + chrono::Duration::seconds(not_before_offset + lifetime),
    }
}

const SAML_ISSUER: &str = "https://saml-idp.anvil-lab.invalid";
const SAML_AUDIENCE: &str = "urn:anvil:lab:soap-service";
const SAML_RECIPIENT: &str = "http://127.0.0.1:18180/soap/saml";

fn assertion(env: &Env, signer: &Signer, spec: &SamlSpec) -> String {
    env.fx.soap.saml_assertion(signer, spec).expect("lab SAML assertion")
}

/// Anvil's WS-Security auth: a fresh PasswordDigest UsernameToken plus the
/// user-supplied assertion embedded verbatim.
fn saml_send(env: &Env, a: &str) -> ExecutionContext {
    let pw = env.fx.secrets.soap_alice_password.clone();
    soap_ctx(env, "/soap/saml/echo", wsse(env, &pw, WssePasswordType::PasswordDigest, Some(60), Some(a)), SOAP_ENVELOPE)
}

fn auth031(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let idp = &env.fx.soap.saml_idp;
        let good = assertion(env, idp, &saml_spec(SAML_ISSUER, SAML_AUDIENCE, -5, 120));
        let ok = go(env, &saml_send(env, &good)).await;
        c.success(CheckKind::Diagnosis, &ok);
        c.add(CheckKind::GroundTruth, "the backend received the assertion byte for byte", echoed_body(&ok).contains(&good), "");
        let sig_value = good.split("<ds:SignatureValue>").nth(1).and_then(|x| x.split('<').next()).unwrap_or("").to_string();
        record_excludes(&mut c, &ok, &sig_value, "the assertion signature (bearer credential)");
        // Replay: the same assertion again, with a fresh UsernameToken.
        let o = go(env, &saml_send(env, &good)).await;
        soap_rejection(&mut c, env, &o, "WS-Security: SAML assertion has already been used");
        gateway_outcome(&mut c, env, &o);
        let wrong_aud =
            go(env, &saml_send(env, &assertion(env, idp, &saml_spec(SAML_ISSUER, "urn:anvil:lab:another-service", -5, 120)))).await;
        soap_rejection(&mut c, env, &wrong_aud, "WS-Security: SAML AudienceRestriction does not admit this service");
        let expired = go(env, &saml_send(env, &assertion(env, idp, &saml_spec(SAML_ISSUER, SAML_AUDIENCE, -600, 200)))).await;
        soap_rejection(&mut c, env, &expired, "WS-Security: SAML Assertion has expired");
        let issuer =
            go(env, &saml_send(env, &assertion(env, idp, &saml_spec("https://rogue-idp.anvil-lab.invalid", SAML_AUDIENCE, -5, 120)))).await;
        soap_rejection(&mut c, env, &issuer, "WS-Security: SAML Issuer is not trusted");
        let key = go(env, &saml_send(env, &assertion(env, &env.fx.soap.rogue, &saml_spec(SAML_ISSUER, SAML_AUDIENCE, -5, 120)))).await;
        soap_rejection(&mut c, env, &key, "WS-Security: SAML signing certificate is not trusted");
        let r = go(env, &saml_send(env, &assertion(env, idp, &saml_spec(SAML_ISSUER, SAML_AUDIENCE, -5, 120)))).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![format!("lab signer: {}", env.fx.soap.tools.versions)] }
    })
}

// ------------------------------------------------- OIDC browser session

/// A minimal raw HTTP/1.1 exchange (the lab's "system browser" and ground
/// truth probe; never given to the engine). Returns status, headers, body.
async fn raw_http(
    addr: &str,
    method: &str,
    target: &str,
    headers: &[(&str, String)],
    body: &str,
) -> Option<(u16, Vec<(String, String)>, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await.ok()?.ok()?;
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (n, v) in headers {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), s.read_to_end(&mut buf)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let hs = lines.filter_map(|l| l.split_once(':').map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))).collect();
    Some((status, hs, rest.to_string()))
}

fn hdr<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// `name=value` pairs of every Set-Cookie.
fn set_cookies(h: &[(String, String)]) -> Vec<String> {
    h.iter().filter(|(n, _)| n == "set-cookie").filter_map(|(_, v)| v.split(';').next().map(|x| x.trim().to_string())).collect()
}

/// The system browser logging in: gateway → IdP login page → credentials →
/// callback → session cookie. Returns (session cookie, trace) or an error.
async fn browser_login(env: &Env) -> Result<(String, Vec<String>), String> {
    let mut trace = Vec::new();
    let html = [("Accept", "text/html".to_string())];
    // Discovery is fetched in the background after the gateway starts.
    let mut first = None;
    for _ in 0..40 {
        let r = raw_http(AUTHORITY, "GET", "/auth/oidc/echo", &html, "").await.ok_or("gateway unreachable")?;
        if r.0 != 503 {
            first = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let (st, h, _) = first.ok_or("OIDC discovery never became available")?;
    trace.push(format!("browser GET /auth/oidc/echo -> {st}"));
    let location = hdr(&h, "location").ok_or(format!("no redirect ({st})"))?.to_string();
    let correlation = set_cookies(&h);
    let authz = url::Url::parse(&location).map_err(|e| e.to_string())?;
    let idp_addr = format!("{}:{}", authz.host_str().unwrap_or(""), authz.port().unwrap_or(80));
    let target = format!("{}?{}", authz.path(), authz.query().unwrap_or(""));
    let (st, _, page) = raw_http(&idp_addr, "GET", &target, &html, "").await.ok_or("IdP unreachable")?;
    trace.push(format!("browser GET IdP {} -> {st} ({} bytes of login page)", authz.path(), page.len()));
    let mut form: Vec<(String, String)> = authz.query_pairs().into_owned().collect();
    form.push(("username".into(), "alice".into()));
    form.push(("password".into(), env.fx.secrets.oidc_alice_password.clone()));
    let body: String = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
    let (st, h, _) =
        raw_http(&idp_addr, "POST", "/authorize/login", &[("Content-Type", "application/x-www-form-urlencoded".into())], &body)
            .await
            .ok_or("IdP login unreachable")?;
    trace.push(format!("browser POST IdP /authorize/login -> {st}"));
    let callback = url::Url::parse(hdr(&h, "location").ok_or(format!("login did not redirect ({st})"))?).map_err(|e| e.to_string())?;
    let target = format!("{}?{}", callback.path(), callback.query().unwrap_or(""));
    let (st, h, b) = raw_http(AUTHORITY, "GET", &target, &[("Cookie", correlation.join("; "))], "").await.ok_or("callback unreachable")?;
    trace.push(format!("browser GET {} -> {st}", callback.path()));
    let session =
        set_cookies(&h).into_iter().find(|c| c.contains("session") && !c.ends_with('=')).ok_or(format!("no session cookie ({st}: {b})"))?;
    let (st, _, _) =
        raw_http(AUTHORITY, "GET", "/auth/oidc/echo", &[("Cookie", session.clone())], "").await.ok_or("gateway unreachable")?;
    trace.push(format!("browser GET /auth/oidc/echo with its session -> {st}"));
    if st != 200 {
        return Err(format!("the browser session was not accepted ({st})"));
    }
    Ok((session, trace))
}

fn login_finding(c: &mut Checks, o: &ExecutionOutput) {
    c.has(o, "auth.browser_session_required");
    c.max_confidence(o, "auth.browser_session_required", Confidence::Likely);
    let f = o.record.findings.iter().find(|f| f.code == "auth.browser_session_required");
    let explains = f.map(|f| f.explanation.contains("does not read or import browser cookies")).unwrap_or(false);
    c.add(CheckKind::Diagnosis, "explains that the browser's session is not available to Anvil", explains, "");
    c.add(
        CheckKind::Diagnosis,
        "not reported as a successful API exchange",
        o.record.outcome.application != anvil_domain::outcome::ApplicationState::Success,
        format!("{:?}", o.record.outcome.application),
    );
    c.absent_prefix(o, "client.tls.");
}

fn auth017(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gw.log_lines().len();
        // Ground truth first: a real browser-style login succeeds.
        let (session, trace) = match browser_login(env).await {
            Ok(x) => x,
            Err(e) => {
                c.add(CheckKind::GroundTruth, "the lab browser completed the OIDC login", false, e);
                return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
            }
        };
        c.add(CheckKind::GroundTruth, "the lab browser completed the OIDC login and holds a session", true, trace.join("; "));
        let before = env.fx.echo.log.count_requests();
        // (a) An API-style request from Anvil: the browser's session is not shared.
        let o = go(env, &ctx(env, "GET", "/auth/oidc/echo", AuthConfig::None)).await;
        c.status_in(&o, &[401]);
        login_finding(&mut c, &o);
        c.has(&o, "http.unauthorized");
        c.add(
            CheckKind::Diagnosis,
            "Anvil sent no Cookie (browser cookies are never imported)",
            !o.record.prepared.headers.iter().any(|h| h.name.eq_ignore_ascii_case("cookie")),
            "",
        );
        // (b) A browser-shaped request: Anvil follows the redirect to the
        // login page without credentials and never submits it.
        let (pages, submissions) = (env.fx.idp.login_pages(), env.fx.idp.login_submissions());
        let mut html = ctx(env, "GET", "/auth/oidc/echo", AuthConfig::None);
        html.spec.headers.push(KeyValue::new("Accept", "text/html"));
        let b = go(env, &html).await;
        login_finding(&mut c, &b);
        c.add(
            CheckKind::Diagnosis,
            "the followed login page is recorded as not evaluated, not success",
            b.record.outcome.application == anvil_domain::outcome::ApplicationState::NotEvaluated,
            format!("{:?}", b.record.outcome.application),
        );
        c.add(CheckKind::GroundTruth, "Anvil reached the IdP login page", env.fx.idp.login_pages() > pages, "");
        c.add(CheckKind::GroundTruth, "Anvil never submitted IdP credentials", env.fx.idp.login_submissions() == submissions, "");
        let idp_auth = env.fx.idp.log.entries().into_iter().rev().find_map(|e| match e.event {
            anvil_fixtures::GroundTruth::RequestReceived { path, headers, .. } if path == "/authorize" => Some(headers),
            _ => None,
        });
        c.add(
            CheckKind::GroundTruth,
            "the redirect to the IdP carried no Authorization or Cookie header",
            idp_auth
                .map(|h| !h.iter().any(|(n, _)| n.eq_ignore_ascii_case("authorization") || n.eq_ignore_ascii_case("cookie")))
                .unwrap_or(false),
            "",
        );
        backend_untouched(&mut c, env, before);
        let log = op_lines(&env.gw, from, "auth017-oidc");
        // Recovery (supported path): the user explicitly configures the
        // authorized session cookie as a secret on the request.
        let mut explicit = ctx(env, "GET", "/auth/oidc/echo", AuthConfig::None);
        secret_header(&mut explicit, "Cookie", &session);
        let r = go(env, &explicit).await;
        c.success(CheckKind::Recovery, &r);
        c.absent_prefix(&r, "auth.browser_session_required");
        let value = session.split_once('=').map(|(_, v)| v.to_string()).unwrap_or_default();
        record_excludes(&mut c, &r, &value, "the session cookie value");
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

/// Lookalikes: an ordinary backend redirect and a plain bearer challenge are
/// not browser-login challenges.
fn auth017_lookalike(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let o = go(env, &ctx(env, "GET", "/auth/open/redirect?to=/ok/echo%3Fclient_id%3Dabc", AuthConfig::None)).await;
        c.success(CheckKind::Diagnosis, &o);
        c.absent_prefix(&o, "auth.browser_session_required");
        let body: String = url::form_urlencoded::byte_serialize(br#"{"error":"invalid token"}"#).collect();
        let b =
            go(env, &ctx(env, "GET", &format!("/auth/open/status/401?body={body}&header=WWW-Authenticate:Bearer"), AuthConfig::None)).await;
        c.status_in(&b, &[401]);
        c.has(&b, "http.unauthorized");
        c.absent_prefix(&b, "auth.browser_session_required");
        Outcome { main: Some(o), recovery: Some(b), checks: c, operator_log: vec![] }
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
        Def { id: "AUTH-029", title: "SOAP UsernameToken digest: accepted, wrong password, replayed nonce", run: auth029 },
        Def { id: "AUTH-029.text", title: "SOAP UsernameToken PasswordText; profile-mismatch lookalike", run: auth029_text },
        Def { id: "AUTH-029.expired", title: "SOAP Timestamp expired before it reached the gateway", run: auth029_expired },
        Def { id: "AUTH-030", title: "SOAP X.509 signature: verbatim signed envelope, tampered body, untrusted key", run: auth030 },
        Def { id: "AUTH-031", title: "SOAP SAML assertion: replay, audience, expiry, issuer and key trust", run: auth031 },
        Def { id: "AUTH-017", title: "OIDC browser session is not Anvil's session", run: auth017 },
        Def {
            id: "AUTH-017.lookalike",
            title: "Ordinary redirect and plain bearer challenge are not browser logins",
            run: auth017_lookalike,
        },
    ]
}

/// Scenarios that need the lab's XML signer (xmllint + openssl).
const SIGNED_XML: &[&str] = &["AUTH-030", "AUTH-031"];

fn skips() -> Vec<(&'static str, &'static str, &'static str)> {
    let client_only = "client-side OAuth flow with no gateway leg (external browser, loopback redirect, state/PKCE, refresh single-flight); covered by anvil-auth unit tests and the anvil-identity fixture-IdP tests (tests/api_oauth.rs), not a live-gateway scenario";
    vec![
        ("AUTH-011", "OAuth PKCE round trip", client_only),
        ("AUTH-012", "OAuth state mismatch", client_only),
        ("AUTH-013", "OAuth redirect spoof", client_only),
        ("AUTH-014", "OAuth refresh race", client_only),
        (
            "AUTH-025.nonce",
            "DPoP server-nonce challenge",
            "infeasible on Ferrum Edge 0.9.5: jwks_auth implements no DPoP-Nonce / use_dpop_nonce challenge (audit §5.4); AUTH-025 covers the replay half live",
        ),
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
    let soap_dir = crate::gateway::repo_root().join("lab/.run/auth/soap");
    let fx = AuthFixtures::start(soap_dir.clone()).await?;
    let vars = fx.secrets.template_vars();
    let mut vars: Vec<(&str, String)> = vars.iter().map(|(k, v)| (*k, v.clone())).collect();
    vars.push(("LAB_SOAP", soap_dir.display().to_string()));
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
    // Signed-XML fixtures need an audited canonicalizer on the host.
    let unsigned = soap_signing_unavailable(&env);
    let defs: Vec<Def> = all().into_iter().filter(|d| unsigned.is_none() || !SIGNED_XML.contains(&d.id)).collect();
    let mut results = match harness::run_defs(&ctx, &mut env, defs, &args.only, args.untrusted_pass).await {
        Ok(r) => r,
        Err(e) => {
            env.gw.stop().await;
            return Err(e);
        }
    };
    if let Some(reason) = &unsigned {
        for d in all().into_iter().filter(|d| SIGNED_XML.contains(&d.id)) {
            if args.only.is_empty() || args.only.iter().any(|s| s.eq_ignore_ascii_case(d.id)) {
                eprintln!("{:22} skipped {}\n    — {reason}", d.id, d.title);
                results.push(ctx.skipped(d.id, d.title, reason));
            }
        }
    }
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
