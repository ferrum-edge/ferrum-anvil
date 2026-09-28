//! The effective-request preview resolves the `Host` / `:authority` exactly as
//! the send path does: an explicit `Host` header wins over the URL's
//! authority, and an HMAC signature covers that value. Each case compares the
//! preview with what the fixture received (HTTP/1.1 `Host`, HTTP/2
//! `:authority`) and verifies the received signature over the preview's
//! authority. A DPoP proof in the preview is bound to that authority, a
//! `Host` an auth profile sets is the one shown, and a preview whose auth
//! cannot be applied says the request would not be sent. Auth that changes
//! per send is reported as varying, alone or in a multi-auth.

use anvil_auth::{HmacParams, ResolvedAuth, hmac_sig};
use anvil_domain::auth::{AuthConfig, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile, KeyLocation};
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides};
use anvil_domain::workload::{JwtSvidConfig, JwtSvidSource};
use anvil_engine::preview::{EffectiveRequest, auth_varies_per_send};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const HOST: &str = "api.example.test:8443";
const USERNAME: &str = "preview-client";
const SECRET: &str = "audit-only-hmac-secret-7q1v";

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn hmac() -> AuthConfig {
    AuthConfig::Hmac {
        config: HmacConfig {
            profile: HmacProfile::FerrumV2,
            username: USERNAME.into(),
            secret: SensitiveValue::template(SECRET),
            algorithm: HmacAlgorithm::HmacSha256,
            digest_header: Default::default(),
            namespace: String::new(),
            allow_unsafe_legacy: false,
        },
    }
}

/// A GET of `/echo` with `auth`, and `host` as an explicit `Host` header.
/// The context takes its auth layer from the spec when it is built, so the
/// auth is set here: changing `spec.auth` afterwards changes nothing sent.
fn ctx_with(f: &fx::Fixture, host: Option<&str>, version: HttpVersionPolicy, auth: AuthConfig) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", &f.url("/echo"));
    if let Some(h) = host {
        s.headers.push(KeyValue::new("Host", h));
    }
    s.auth = auth;
    let mut c = ExecutionContext::standalone(s);
    c.settings_layers.push(("run".into(), SettingsOverrides { http_version: Some(version), ..Default::default() }));
    c
}

/// An HMAC-signed GET of `/echo`, with `host` as an explicit `Host` header.
fn ctx(f: &fx::Fixture, host: Option<&str>, version: HttpVersionPolicy) -> ExecutionContext {
    ctx_with(f, host, version, hmac())
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// The value of `key="…"` in an HMAC `Authorization` header.
fn auth_param<'a>(authorization: &'a str, key: &str) -> &'a str {
    let start = authorization.find(&format!("{key}=\"")).unwrap_or_else(|| panic!("no {key} in {authorization}")) + key.len() + 2;
    let len = authorization[start..].find('"').expect("unterminated auth-param");
    &authorization[start..start + len]
}

/// Whether the HMAC signature the fixture received covers `authority`.
fn signed_for(received: &[(String, String)], authority: &str) -> bool {
    let authorization = header(received, "authorization").expect("no Authorization received");
    let ss = hmac_sig::signing_string(
        HmacProfile::FerrumV2,
        "ferrum",
        USERNAME,
        authority,
        "GET",
        "/echo",
        "",
        header(received, "date").expect("no Date received"),
        header(received, "content-digest").expect("no Content-Digest received"),
        Some(auth_param(authorization, "nonce")),
    );
    let mac = hmac_sig::mac(HmacAlgorithm::HmacSha256, SECRET.as_bytes(), ss.as_bytes());
    auth_param(authorization, "signature") == base64::engine::general_purpose::STANDARD.encode(mac)
}

/// Send `c` and return the preview, the headers the fixture received and
/// the authority it received (`:authority`, else `Host`).
async fn preview_and_send(e: &Engine, f: &fx::Fixture, c: &ExecutionContext) -> (EffectiveRequest, Vec<(String, String)>, String) {
    let p = e.preview(c).unwrap();
    assert!(!p.inferred.iter().any(|i| i.starts_with("the request would not be sent")), "{:?}", p.inferred);
    let o = run(e, c).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    let received = f.log.last_request_headers().expect("the fixture received no request");
    let echo: serde_json::Value = serde_json::from_slice(&o.body).expect("the echo body is JSON");
    let authority = match echo["authority"].as_str() {
        Some(a) => a.to_string(),
        None => header(&received, "host").expect("no Host received").to_string(),
    };
    (p, received, authority)
}

#[tokio::test]
async fn http1_preview_uses_an_explicit_host_header_as_sent_and_signed() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let (p, received, authority) = preview_and_send(&e, &f, &ctx(&f, Some(HOST), HttpVersionPolicy::Http1Only)).await;
    assert_eq!(header(&received, "host"), Some(HOST), "{received:?}");
    assert_eq!(authority, HOST);
    assert_eq!(p.authority, authority, "the preview's Host differs from the one sent");
    assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("host") && h.value == HOST), "{:?}", p.headers);
    assert_eq!(p.destination, f.addr.to_string(), "the connection still goes to the URL's host");
    assert!(signed_for(&received, &p.authority), "the signature does not cover the preview's authority");
    assert!(!signed_for(&received, &f.addr.to_string()), "the signature covers the URL's authority, not the Host sent");
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains(SECRET), "the preview holds the secret: {json}");
}

#[tokio::test]
async fn h2c_preview_uses_an_explicit_host_header_as_the_authority_sent_and_signed() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let (p, received, authority) = preview_and_send(&e, &f, &ctx(&f, Some(HOST), HttpVersionPolicy::H2c)).await;
    assert_eq!(authority, HOST, "the :authority sent");
    assert_eq!(p.authority, authority, "the preview's authority differs from the one sent");
    assert!(signed_for(&received, &p.authority), "the signature does not cover the preview's authority");
    assert!(!signed_for(&received, &f.addr.to_string()), "the signature covers the URL's authority, not the one sent");
}

#[tokio::test]
async fn without_a_host_header_the_preview_and_the_send_use_the_url_authority() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    for version in [HttpVersionPolicy::Http1Only, HttpVersionPolicy::H2c] {
        let (p, received, authority) = preview_and_send(&e, &f, &ctx(&f, None, version)).await;
        assert_eq!(authority, f.addr.to_string(), "{version:?}");
        assert_eq!(p.authority, authority, "{version:?}");
        assert!(signed_for(&received, &p.authority), "{version:?}");
    }
}

#[tokio::test]
async fn preview_says_a_request_whose_auth_cannot_be_applied_would_not_be_sent() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // HMAC signing computes the body digest itself and refuses a manual one.
    let mut c = ctx(&f, None, HttpVersionPolicy::Http1Only);
    c.spec.headers.push(KeyValue::new("Content-Digest", "sha-256=:AAAA:"));
    let p = e.preview(&c).unwrap();
    let note = p.inferred.iter().find(|i| i.starts_with("the request would not be sent: ")).expect("no note");
    assert!(note.contains("Content-Digest"), "the note says why: {note}");
    assert!(!p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("authorization")), "{:?}", p.headers);
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains(SECRET), "the preview holds the secret: {json}");

    // The send path refuses it the same way and sends nothing.
    let o = run(&e, &c).await;
    assert!(o.record.response.is_none());
    assert_eq!(f.log.count_requests(), 0, "a request reached the server: {:?}", f.log.requests());
}

#[tokio::test]
async fn preview_binds_the_dpop_proof_to_an_explicit_host_header() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let dpop = AuthConfig::Dpop {
        config: DpopConfig {
            access_token: SensitiveValue::template("audit-only-dpop-token-3k9w"),
            private_key_pem: SensitiveValue::template(anvil_auth::dpop::generate_key_pem().unwrap()),
            dpop_scheme: true,
            handle_nonce_challenge: true,
        },
    };
    let c = ctx_with(&f, Some(HOST), HttpVersionPolicy::Http1Only, dpop);
    let p = e.preview(&c).unwrap();
    assert!(p.auth.starts_with("dpop"), "{}", p.auth);
    assert_eq!(p.authority, HOST);
    let htu = p.inferred.iter().find_map(|i| i.strip_prefix("auth dpop.htu: ")).unwrap_or_else(|| panic!("{:?}", p.inferred));
    assert_eq!(htu, format!("http://{HOST}/echo"), "the proof is not bound to the Host sent");
}

#[tokio::test]
async fn preview_authority_is_a_host_header_an_auth_profile_sets() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let api_key = AuthConfig::ApiKey { name: "Host".into(), value: SensitiveValue::template(HOST), location: KeyLocation::Header };
    let c = ctx_with(&f, None, HttpVersionPolicy::Http1Only, api_key);
    let p = e.preview(&c).unwrap();
    assert!(!p.inferred.iter().any(|i| i.starts_with("the request would not be sent")), "{:?}", p.inferred);
    assert_ne!(p.authority, f.addr.to_string(), "the preview shows the URL's authority, not the Host the auth profile sets");
    let host = p.headers.iter().find(|h| h.name.eq_ignore_ascii_case("host")).unwrap_or_else(|| panic!("no Host: {:?}", p.headers));
    assert_eq!(p.authority, host.value, "the preview's authority differs from its Host header");
    // An API key's value is a credential and stays redacted.
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains(HOST), "the preview holds the API key: {json}");

    let o = run(&e, &c).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    let received = f.log.last_request_headers().expect("the fixture received no request");
    assert_eq!(header(&received, "host"), Some(HOST), "{received:?}");
}

#[tokio::test]
async fn preview_reports_an_auth_error_beside_an_unfetched_jwt_svid() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let svid = AuthConfig::JwtSvid {
        config: JwtSvidConfig {
            source: JwtSvidSource::WorkloadApi,
            audiences: vec!["spiffe://anvil.test/gateway".into()],
            endpoint: "unix:///nonexistent/anvil-preview-agent.sock".into(),
            spiffe_id: None,
            verify_with_bundles: false,
            send_despite_failed_checks: false,
            header_name: "X-Workload-Token".into(),
            prefix: String::new(),
        },
    };
    // HMAC signing computes the body digest itself and refuses a manual one.
    let mut c = ctx_with(&f, None, HttpVersionPolicy::Http1Only, AuthConfig::Multi { profiles: vec![svid, hmac()] });
    c.spec.headers.push(KeyValue::new("Content-Digest", "sha-256=:AAAA:"));
    let p = e.preview(&c).unwrap();
    assert!(p.inferred.iter().any(|i| i.starts_with("JWT-SVID: ")), "{:?}", p.inferred);
    let note = p.inferred.iter().find(|i| i.starts_with("the request would not be sent: ")).unwrap_or_else(|| panic!("{:?}", p.inferred));
    assert!(note.contains("Content-Digest"), "the note says why: {note}");
    assert!(!p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("authorization")), "{:?}", p.headers);
}

fn bearer() -> AuthConfig {
    AuthConfig::Bearer { token: SensitiveValue::template("audit-only-bearer-token-2d6x"), prefix: "Bearer".into() }
}

fn api_key() -> AuthConfig {
    AuthConfig::ApiKey {
        name: "X-Api-Key".into(),
        value: SensitiveValue::template("audit-only-api-key-4m8p"),
        location: KeyLocation::Header,
    }
}

fn resolved_hmac() -> ResolvedAuth {
    ResolvedAuth::Hmac(HmacParams {
        profile: HmacProfile::FerrumV2,
        username: USERNAME.into(),
        secret: Zeroizing::new(SECRET.into()),
        algorithm: HmacAlgorithm::HmacSha256,
        digest_header: Default::default(),
        namespace: String::new(),
        allow_unsafe_legacy: false,
    })
}

fn resolved_bearer() -> ResolvedAuth {
    ResolvedAuth::Bearer { token: Zeroizing::new("audit-only-bearer-token-2d6x".into()), prefix: "Bearer".into() }
}

fn resolved_api_key() -> ResolvedAuth {
    ResolvedAuth::ApiKey {
        name: "X-Api-Key".into(),
        value: Zeroizing::new("audit-only-api-key-4m8p".into()),
        location: KeyLocation::Header,
    }
}

#[test]
fn auth_varies_per_send_for_a_multi_auth_with_a_per_send_profile() {
    assert!(auth_varies_per_send(&resolved_hmac()));
    assert!(!auth_varies_per_send(&ResolvedAuth::None));
    assert!(!auth_varies_per_send(&resolved_bearer()));
    assert!(!auth_varies_per_send(&resolved_api_key()));
    // A cached OAuth2 token is sent unchanged until it is refreshed.
    let oauth = ResolvedAuth::OAuth2 { access_token: Zeroizing::new("audit-only-oauth-token-9c2f".into()), token_type: "Bearer".into() };
    assert!(!auth_varies_per_send(&oauth));

    assert!(auth_varies_per_send(&ResolvedAuth::Multi(vec![resolved_bearer(), resolved_hmac()])));
    assert!(auth_varies_per_send(&ResolvedAuth::Multi(vec![resolved_hmac(), resolved_api_key()])));
    assert!(!auth_varies_per_send(&ResolvedAuth::Multi(vec![resolved_bearer(), resolved_api_key()])));
    assert!(!auth_varies_per_send(&ResolvedAuth::Multi(vec![])));
    // Nested sets are searched too.
    let nested = ResolvedAuth::Multi(vec![resolved_api_key(), ResolvedAuth::Multi(vec![resolved_bearer(), resolved_hmac()])]);
    assert!(auth_varies_per_send(&nested));
    let nested = ResolvedAuth::Multi(vec![resolved_api_key(), ResolvedAuth::Multi(vec![resolved_bearer(), oauth])]);
    assert!(!auth_varies_per_send(&nested));
}

#[tokio::test]
async fn preview_says_a_multi_auth_with_hmac_varies_per_send() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let c = ctx_with(&f, None, HttpVersionPolicy::Http1Only, AuthConfig::Multi { profiles: vec![api_key(), hmac()] });
    let p = e.preview(&c).unwrap();
    assert!(!p.inferred.iter().any(|i| i.starts_with("the request would not be sent")), "{:?}", p.inferred);
    assert!(p.auth_varies_per_send, "{}", p.auth);

    let c = ctx_with(&f, None, HttpVersionPolicy::Http1Only, AuthConfig::Multi { profiles: vec![bearer(), api_key()] });
    let p = e.preview(&c).unwrap();
    assert!(!p.inferred.iter().any(|i| i.starts_with("the request would not be sent")), "{:?}", p.inferred);
    assert!(!p.auth_varies_per_send, "a bearer token and an API key are sent as shown: {}", p.auth);
}
