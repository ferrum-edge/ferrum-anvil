//! Redirect hops: every hop is evaluated for its own target. Credentials
//! configured for the original origin stay there, the proxy route (NO_PROXY)
//! is decided for the new host, and Ferrum attribution comes from the origin
//! that produced the final response. Fixture logs are independent ground truth.
//! Dummy credential values use the `tok-SENSITIVE-` canary prefix.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::*;
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{ProxySelection, RedirectPolicy, SettingsOverrides};
use anvil_domain::tls::{ClientIdentity, HostBinding, ProxyKind, ProxyProfile, TlsProfile};
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_fixtures::log::GroundTruth;
use anvil_fixtures::{ClientAuth, LabPki, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

async fn run(engine: &Engine, ctx: &ExecutionContext) -> ExecutionOutput {
    engine.execute(ctx, EventCtx::none(), CancellationToken::new()).await
}

fn ctx_for(url: &str) -> ExecutionContext {
    ExecutionContext::standalone(RequestSpec::http("GET", url))
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

/// `(request target, headers)` of every request the fixture received, in order.
fn received(f: &fx::Fixture) -> Vec<(String, Vec<(String, String)>)> {
    f.log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::RequestReceived { path, headers, .. } => Some((path, headers)),
            _ => None,
        })
        .collect()
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

fn stripped_warning(o: &ExecutionOutput) -> bool {
    o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::CredentialsStrippedOnRedirect)
}

fn settings(ctx: &mut ExecutionContext, s: SettingsOverrides) {
    ctx.settings_layers.push(("run".into(), s));
}

fn inferred(o: &ExecutionOutput) -> &[String] {
    &o.record.prepared.inferred
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

/// Lab server certificate (valid for 127.0.0.1); optionally asks for a client
/// certificate without requiring one, so the log shows whether one was sent.
fn tls_options(ask_client_cert: bool) -> TlsServerOptions {
    let mut o = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    if ask_client_cert {
        o.client_auth = ClientAuth::Optional { ca_pem: pki().client_ca.cert.clone() };
    }
    o
}

/// Selects a TLS profile named `lab` that trusts the lab root and, with
/// `client_cert`, presents `client_a`. It has no host bindings.
fn lab_tls(ctx: &mut ExecutionContext, client_cert: bool) {
    let identity = client_cert.then(|| ClientIdentity::Pem {
        cert_chain_pem: pki().client_a.cert.clone(),
        private_key_pem: SensitiveValue::template(pki().client_a.key.clone()),
    });
    let p = TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: identity,
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let id = p.id;
    ctx.tls_profiles.push(p);
    settings(ctx, SettingsOverrides { tls_profile_id: Some(id), ..Default::default() });
}

/// The client certificate CN of every completed TLS handshake, in order.
fn client_cert_cns(f: &fx::Fixture) -> Vec<Option<String>> {
    f.log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::TlsHandshakeCompleted { client_cert_cn, .. } => Some(client_cert_cn),
            _ => None,
        })
        .collect()
}

/// Credentials configured by hand: a known credential header name, a custom
/// header marked sensitive, a header whose value holds a secret variable, a
/// manual cookie, and one ordinary header that may follow any redirect.
fn with_configured_credentials(ctx: &mut ExecutionContext) {
    ctx.var_layers = vec![VarLayer {
        label: "environment:lab".into(),
        vars: vec![VarEntry { name: "tenant_key".into(), value: "tok-SENSITIVE-tenant-5a4b3c".into(), secret: true }],
    }];
    ctx.spec.headers.push(KeyValue::new("X-API-Key", "tok-SENSITIVE-api-key-1a2b3c"));
    let mut custom = KeyValue::new("X-Custom", "tok-SENSITIVE-custom-4d5e6f");
    custom.sensitive = true;
    ctx.spec.headers.push(custom);
    ctx.spec.headers.push(KeyValue::new("X-Tenant", "t-{{tenant_key}}"));
    ctx.spec.headers.push(KeyValue::new("Cookie", "sid=tok-SENSITIVE-cookie-7g8h9i"));
    ctx.spec.headers.push(KeyValue::new("X-Master-Key", "tok-SENSITIVE-master-9s8t7u"));
    ctx.spec.headers.push(KeyValue::new(LONG_TOKEN_HEADER, "tok-SENSITIVE-long-name-2v3w4x"));
    ctx.spec.headers.push(KeyValue::new("X-Plain", "visible"));
}

/// A credential name longer than the redactor's 48-character name limit.
const LONG_TOKEN_HEADER: &str = "X-Vendor-Specific-Upstream-Gateway-Routing-Session-Token";

const CREDENTIAL_HEADERS: [&str; 6] = ["X-API-Key", "X-Custom", "X-Tenant", "Cookie", "X-Master-Key", LONG_TOKEN_HEADER];

/// The note naming the configured headers withheld on a redirect: names
/// only, never values.
fn assert_withheld_note(o: &ExecutionOutput) {
    let note = inferred(o).iter().find(|i| i.starts_with("credential headers withheld")).expect("withheld headers are named");
    for h in CREDENTIAL_HEADERS {
        assert!(note.contains(h), "{h} is named: {note}");
    }
    assert!(!note.contains("X-Plain") && !note.contains("tok-SENSITIVE"), "{note}");
}

#[tokio::test]
async fn cross_origin_redirect_withholds_configured_credential_headers() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // A host change on the same listener, then a port change.
    for (label, dest, next) in [("host", &a, a.url_host("localhost", "/echo")), ("port", &b, b.url("/echo"))] {
        a.log.clear();
        b.log.clear();
        let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}&status=302", url_encode(&next))));
        with_configured_credentials(&mut ctx);
        let o = run(&e, &ctx).await;
        assert_eq!(o.record.attempts.len(), 2, "{label}");
        assert_eq!(o.record.response.as_ref().unwrap().status, 200, "{label}");
        let on_a = received(&a);
        for h in CREDENTIAL_HEADERS {
            assert!(has_header(&on_a[0].1, h), "{label}: ground truth: {h} was sent to the configured origin");
        }
        let (_, last) = received(dest).pop().unwrap();
        for h in CREDENTIAL_HEADERS {
            assert!(!has_header(&last, h), "{label}: {h} must not follow a redirect to another origin");
        }
        assert!(last.iter().any(|(n, v)| n == "x-plain" && v == "visible"), "{label}: ordinary headers still follow");
        assert!(stripped_warning(&o), "{label}");
        assert_withheld_note(&o);
    }
}

#[tokio::test]
async fn same_origin_redirect_keeps_configured_credentials() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}&status=307", url_encode("/echo"))));
    with_configured_credentials(&mut ctx);
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    let reqs = received(&a);
    assert_eq!(reqs.len(), 2);
    for h in CREDENTIAL_HEADERS {
        assert!(has_header(&reqs[1].1, h), "{h} stays with its own origin");
    }
    assert!(!stripped_warning(&o));
}

#[tokio::test]
async fn credentials_stay_withheld_on_later_hops_back_to_the_original_origin() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // A -> A (same origin) -> B -> A.
    let back = a.url("/echo");
    let via_b = b.url(&format!("/redirect?to={}", url_encode(&back)));
    let same = format!("/redirect?to={}", url_encode(&via_b));
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&same))));
    with_configured_credentials(&mut ctx);
    ctx.auth_layers = vec![(
        "request".into(),
        AuthConfig::Bearer { token: SensitiveValue::template("tok-SENSITIVE-bearer-0j1k2l"), prefix: "Bearer".into() },
    )];
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 4);
    let on_a = received(&a);
    assert_eq!(on_a.len(), 3);
    for h in CREDENTIAL_HEADERS.iter().chain(&["authorization"]) {
        assert!(has_header(&on_a[0].1, h) && has_header(&on_a[1].1, h), "{h} is sent until the origin changes");
        assert!(!has_header(&on_a[2].1, h), "{h} is not restored after the chain has left the origin");
    }
    let on_b = received(&b);
    assert_eq!(on_b.len(), 1);
    for h in CREDENTIAL_HEADERS.iter().chain(&["authorization"]) {
        assert!(!has_header(&on_b[0].1, h), "{h} never reaches the other origin");
    }
}

#[tokio::test]
async fn api_key_auth_in_query_and_cookie_is_not_applied_after_an_origin_change() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url("/echo")))));
    ctx.auth_layers = vec![(
        "request".into(),
        AuthConfig::Multi {
            profiles: vec![
                AuthConfig::ApiKey {
                    name: "api_key".into(),
                    value: SensitiveValue::template("tok-SENSITIVE-query-3m4n5o"),
                    location: KeyLocation::Query,
                },
                AuthConfig::ApiKey {
                    name: "session_key".into(),
                    value: SensitiveValue::template("tok-SENSITIVE-cookie-key-6p7q8r"),
                    location: KeyLocation::Cookie,
                },
            ],
        },
    )];
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    let (first_target, first_headers) = received(&a).remove(0);
    assert!(first_target.contains("tok-SENSITIVE-query-3m4n5o"), "ground truth: the key went to the configured origin");
    assert!(has_header(&first_headers, "cookie"));
    let (target, headers) = received(&b).remove(0);
    assert!(!target.contains("api_key") && !target.contains("tok-SENSITIVE-query"), "{target}");
    assert!(!has_header(&headers, "cookie"));
    assert!(stripped_warning(&o));
}

#[tokio::test]
async fn explicit_cross_origin_forwarding_forwards_configured_credentials() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url("/echo")))));
    with_configured_credentials(&mut ctx);
    settings(
        &mut ctx,
        SettingsOverrides {
            redirects: Some(RedirectPolicy { follow: true, max: 10, forward_credentials_cross_origin: true }),
            ..Default::default()
        },
    );
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    let (_, headers) = received(&b).remove(0);
    for h in CREDENTIAL_HEADERS {
        assert!(has_header(&headers, h), "{h} is forwarded when the policy explicitly allows it");
    }
    assert!(!stripped_warning(&o));
}

fn post(ctx: &mut ExecutionContext, text: &str) {
    ctx.spec.method = "POST".into();
    ctx.spec.body = Body::Raw { text: text.into(), content_type: None };
}

#[tokio::test]
async fn redirect_that_would_resend_a_secret_body_to_another_origin_is_not_followed() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    for status in [307u16, 308] {
        a.log.clear();
        let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}&status={status}", url_encode(&b.url("/echo")))));
        with_configured_credentials(&mut ctx);
        post(&mut ctx, "tenant=t-{{tenant_key}}&note=hello");
        let o = run(&e, &ctx).await;
        assert_eq!(o.record.attempts.len(), 1, "{status}");
        assert_eq!(o.record.response.as_ref().unwrap().status, status, "the redirect response stays the final response");
        assert_eq!(a.log.count_requests(), 1, "{status}");
        assert_eq!(b.log.count_requests(), 0, "{status}: ground truth: the body never reached the other origin");
        assert!(inferred(&o).iter().any(|i| i.contains("not followed") && i.contains("body holding a secret")), "{:?}", inferred(&o));
        assert!(!stripped_warning(&o), "nothing was sent without its credentials");
    }

    // A body without a secret follows the 307, without the credential headers.
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}&status=307", url_encode(&b.url("/echo")))));
    with_configured_credentials(&mut ctx);
    post(&mut ctx, "note=hello");
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(b.log.count_requests(), 1);
    assert!(stripped_warning(&o));
}

#[tokio::test]
async fn secret_body_follows_a_same_origin_redirect() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}&status=307", url_encode("/echo"))));
    with_configured_credentials(&mut ctx);
    post(&mut ctx, "tenant=t-{{tenant_key}}");
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(a.log.count_requests(), 2);
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
}

// --------------------------------------------------------- scheme / TLS ---

/// One port that speaks both schemes: a TLS client hello is relayed to
/// `tls_backend` (a TLS fixture, whose log is the ground truth for that leg);
/// plain HTTP gets `plain_response` (with `{addr}` replaced by this port's
/// address) and its request head is recorded.
struct DualScheme {
    addr: std::net::SocketAddr,
    plain_heads: Arc<Mutex<Vec<String>>>,
}

impl DualScheme {
    fn plain_heads(&self) -> Vec<String> {
        self.plain_heads.lock().unwrap().clone()
    }
}

async fn dual_scheme(tls_backend: std::net::SocketAddr, plain_response: &str) -> DualScheme {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let response = plain_response.replace("{addr}", &addr.to_string());
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let seen = seen.clone();
            let response = response.clone();
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if !matches!(s.peek(&mut first).await, Ok(1)) {
                    return;
                }
                // 0x16: a TLS handshake record.
                if first[0] == 0x16 {
                    if let Ok(mut upstream) = tokio::net::TcpStream::connect(tls_backend).await {
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut upstream).await;
                    }
                    return;
                }
                let head = read_head(&mut s).await;
                seen.lock().unwrap().push(head);
                let _ = s.write_all(response.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    DualScheme { addr, plain_heads: heads }
}

/// Whether a recorded HTTP/1 request head carries header `name`.
fn head_has(head: &str, name: &str) -> bool {
    head.lines().skip(1).any(|l| l.split_once(':').is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name)))
}

#[tokio::test]
async fn https_to_http_on_the_same_host_and_port_withholds_credentials() {
    init();
    let a = fx::serve("127.0.0.1:0", Some(tls_options(false))).await.unwrap();
    let dual = dual_scheme(a.addr, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
    let e = Engine::new();
    let plain = format!("http://{}/echo", dual.addr);
    let mut ctx = ctx_for(&format!("https://{}/redirect?to={}", dual.addr, url_encode(&plain)));
    with_configured_credentials(&mut ctx);
    lab_tls(&mut ctx, false);
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2, "{:?}", codes(&o));
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
    let on_a = received(&a);
    assert_eq!(on_a.len(), 1);
    for h in CREDENTIAL_HEADERS {
        assert!(has_header(&on_a[0].1, h), "ground truth: {h} was sent over https");
    }
    let heads = dual.plain_heads();
    assert_eq!(heads.len(), 1);
    for h in CREDENTIAL_HEADERS {
        assert!(!head_has(&heads[0], h), "{h} must not follow a change to http: {}", heads[0]);
    }
    assert!(head_has(&heads[0], "x-plain"), "ordinary headers still follow");
    assert!(stripped_warning(&o));
    assert_withheld_note(&o);
    // The record's TLS summary describes the hop that produced the response.
    assert_eq!(o.record.prepared.tls_profile, None);
}

#[tokio::test]
async fn http_to_https_on_the_same_host_and_port_withholds_credentials() {
    init();
    let a = fx::serve("127.0.0.1:0", Some(tls_options(false))).await.unwrap();
    let redirect = "HTTP/1.1 302 Found\r\nLocation: https://{addr}/echo\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let dual = dual_scheme(a.addr, redirect).await;
    let e = Engine::new();
    let mut ctx = ctx_for(&format!("http://{}/start", dual.addr));
    with_configured_credentials(&mut ctx);
    lab_tls(&mut ctx, false);
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2, "{:?}", codes(&o));
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
    let heads = dual.plain_heads();
    assert_eq!(heads.len(), 1);
    for h in CREDENTIAL_HEADERS {
        assert!(head_has(&heads[0], h), "ground truth: {h} was sent over http");
    }
    let on_a = received(&a);
    assert_eq!(on_a.len(), 1);
    for h in CREDENTIAL_HEADERS {
        assert!(!has_header(&on_a[0].1, h), "{h} must not follow a change to https");
    }
    assert!(has_header(&on_a[0].1, "x-plain"), "ordinary headers still follow");
    assert!(stripped_warning(&o));
    assert_withheld_note(&o);
    assert_eq!(o.record.prepared.tls_profile.as_deref(), Some("lab"), "the TLS summary describes the final hop");
    assert!(o.record.prepared.tls_verification_enabled);
}

#[tokio::test]
async fn client_certificate_is_not_presented_to_another_origin() {
    init();
    let a = fx::serve("127.0.0.1:0", Some(tls_options(true))).await.unwrap();
    let b = fx::serve("127.0.0.1:0", Some(tls_options(true))).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url("/echo")))));
    lab_tls(&mut ctx, true);
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2, "{:?}", codes(&o));
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
    let on_a = client_cert_cns(&a);
    assert!(!on_a.is_empty() && on_a.iter().all(Option::is_some), "ground truth: the configured origin got the certificate: {on_a:?}");
    let on_b = client_cert_cns(&b);
    assert!(!on_b.is_empty() && on_b.iter().all(Option::is_none), "the other origin must not get it: {on_b:?}");
}

#[tokio::test]
async fn https_redirect_whose_tls_settings_cannot_be_prepared_is_not_followed() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", Some(tls_options(false))).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url("/echo")))));
    // The selected TLS profile no longer exists: the plain-HTTP request needs
    // no TLS settings, the https redirect target does.
    settings(&mut ctx, SettingsOverrides { tls_profile_id: Some(Id::new()), ..Default::default() });
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 1);
    assert_eq!(o.record.response.as_ref().unwrap().status, 302, "the redirect response stays the final response");
    assert!(b.log.entries().is_empty(), "ground truth: the https target was never contacted");
    assert!(inferred(&o).iter().any(|i| i.contains("not followed") && i.contains("TLS settings")), "{:?}", inferred(&o));
}

// ---------------------------------------------------------------- proxy ---

/// A forward-proxy stand-in on loopback: it records the request line of every
/// connection and answers with a fixed response, so a test sees whether (and
/// for which URL) the client routed through the proxy.
struct ProxySentinel {
    addr: std::net::SocketAddr,
    lines: Arc<Mutex<Vec<String>>>,
}

impl ProxySentinel {
    fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

async fn proxy_sentinel(response: String) -> ProxySentinel {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = lines.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let seen = seen.clone();
            let response = response.clone();
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let line = head.lines().next().unwrap_or("").to_string();
                seen.lock().unwrap().push(line);
                let _ = s.write_all(response.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    ProxySentinel { addr, lines }
}

/// Reads an HTTP/1 request head (up to the blank line).
async fn read_head(s: &mut tokio::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 64 * 1024 {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn with_proxy(ctx: &mut ExecutionContext, address: &str, no_proxy: &str) {
    let p = ProxyProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "fwd".into(),
        kind: ProxyKind::Http,
        address: address.into(),
        username: None,
        password: None,
        no_proxy: no_proxy.into(),
        tls_profile_id: None,
        hbone: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let id = p.id;
    ctx.proxy_profiles.push(p);
    settings(ctx, SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id }), ..Default::default() });
}

fn via_proxy(o: &ExecutionOutput, attempt: usize) -> Option<String> {
    o.record.attempts[attempt].connection.as_ref().and_then(|c| c.via_proxy.clone())
}

#[tokio::test]
async fn redirect_from_a_no_proxy_origin_to_another_origin_uses_the_proxy() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let proxy = proxy_sentinel("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied".into()).await;
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url("/echo")))));
    with_proxy(&mut ctx, &proxy.addr.to_string(), &a.addr.to_string());
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(a.log.count_requests(), 1, "the NO_PROXY origin is reached directly");
    assert!(via_proxy(&o, 0).is_none());
    assert_eq!(b.log.count_requests(), 0, "ground truth: the non-exempt destination was not contacted directly");
    assert_eq!(proxy.lines(), vec![format!("GET {} HTTP/1.1", b.url("/echo"))]);
    assert!(via_proxy(&o, 1).is_some(), "the attempt records its proxy route");
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
}

#[tokio::test]
async fn redirect_from_a_proxied_origin_to_a_no_proxy_origin_goes_direct() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    // The proxy itself answers the first request with the redirect.
    let redirect = format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", b.url("/echo"));
    let proxy = proxy_sentinel(redirect).await;
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url("/start"));
    with_proxy(&mut ctx, &proxy.addr.to_string(), &b.addr.to_string());
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(proxy.lines(), vec![format!("GET {} HTTP/1.1", a.url("/start"))], "only the first hop is proxied");
    assert_eq!(a.log.count_requests(), 0);
    assert!(via_proxy(&o, 0).is_some());
    assert_eq!(b.log.count_requests(), 1, "the NO_PROXY destination is reached directly");
    assert!(via_proxy(&o, 1).is_none());
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
}

#[tokio::test]
async fn http_to_https_on_the_same_host_is_tunnelled_through_the_proxy() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    // The proxy answers the plain request with a redirect to https on the
    // same host and port; the https hop needs a CONNECT tunnel.
    let redirect = format!("HTTP/1.1 302 Found\r\nLocation: https://{}/echo\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", a.addr);
    let proxy = proxy_sentinel(redirect).await;
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url("/start"));
    with_proxy(&mut ctx, &proxy.addr.to_string(), "");
    let o = run(&e, &ctx).await;
    assert!(o.record.attempts.len() >= 2, "the redirect was followed: {:?}", codes(&o));
    let lines = proxy.lines();
    assert_eq!(lines.first(), Some(&format!("GET {} HTTP/1.1", a.url("/start"))), "{lines:?}");
    let connect = format!("CONNECT {} HTTP/1.1", a.addr);
    assert!(lines.len() >= 2 && lines[1..].iter().all(|l| *l == connect), "the https hop is tunnelled: {lines:?}");
    assert!(a.log.entries().is_empty(), "ground truth: the destination was never contacted directly");
}

#[tokio::test]
async fn redirect_whose_proxy_route_cannot_be_prepared_is_not_followed() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url("/echo")))));
    // The original origin is exempt, so the broken proxy address only matters
    // for the redirect target.
    with_proxy(&mut ctx, "not a proxy address", &a.addr.to_string());
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 1);
    assert_eq!(o.record.response.as_ref().unwrap().status, 302, "the redirect response stays the final response");
    assert_eq!(b.log.count_requests(), 0, "nothing is sent directly instead");
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("not followed")), "{:?}", o.record.prepared.inferred);
}

// ---------------------------------------------------------------- trust ---

fn gateway(ctx: &mut ExecutionContext, name: &str, host: &str, port: u16, compatibility_id: &str, require_verified_tls: bool) {
    ctx.integrations.push(IntegrationProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: name.into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: vec![HostBinding { host: host.into(), port: Some(port) }],
            compatibility_id: compatibility_id.into(),
            require_verified_tls,
            detail: None,
            console_url: None,
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
}

const MARKED: &str = "/status/502?header=X-Gateway-Error:connection_failure";

#[tokio::test]
async fn redirect_to_an_unbound_origin_is_not_attributed_to_the_gateway() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url(MARKED)))));
    gateway(&mut ctx, "gateway a", "127.0.0.1", a.addr.port(), "ferrum-edge-0.9.7", false);
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(b.log.count_requests(), 1);
    let c = codes(&o);
    assert!(!c.iter().any(|x| x.starts_with("ferrum.token.")), "no gateway attribution from an unbound origin: {c:?}");
    assert!(c.contains(&"ferrum.marker.unverified".to_string()), "{c:?}");
    assert_eq!(o.record.compatibility_id, None);
}

#[tokio::test]
async fn redirect_between_bound_gateways_uses_the_final_origins_profile() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url(MARKED)))));
    gateway(&mut ctx, "gateway a", "127.0.0.1", a.addr.port(), "ferrum-edge-0.9.5", false);
    gateway(&mut ctx, "gateway b", "127.0.0.1", b.addr.port(), "ferrum-edge-0.9.7", false);
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(o.record.compatibility_id.as_deref(), Some("ferrum-edge-0.9.7"));
    assert!(codes(&o).contains(&"ferrum.token.connection_failure".to_string()), "{:?}", codes(&o));

    // The final origin's own TLS requirement applies: gateway b requires
    // verified TLS, and this hop was plain HTTP.
    let mut strict = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&b.url(MARKED)))));
    gateway(&mut strict, "gateway a", "127.0.0.1", a.addr.port(), "ferrum-edge-0.9.5", false);
    gateway(&mut strict, "gateway b", "127.0.0.1", b.addr.port(), "ferrum-edge-0.9.7", true);
    let o = run(&e, &strict).await;
    let c = codes(&o);
    assert!(!c.iter().any(|x| x.starts_with("ferrum.token.")), "{c:?}");
    assert!(c.contains(&"ferrum.marker.unverified".to_string()), "{c:?}");
}

#[tokio::test]
async fn redirect_back_to_the_bound_origin_keeps_its_attribution() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // A -> B (unbound) -> A.
    let via_b = b.url(&format!("/redirect?to={}", url_encode(&a.url(MARKED))));
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={}", url_encode(&via_b))));
    gateway(&mut ctx, "gateway a", "127.0.0.1", a.addr.port(), "ferrum-edge-0.9.7", false);
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 3);
    assert_eq!(o.record.compatibility_id.as_deref(), Some("ferrum-edge-0.9.7"));
    assert!(codes(&o).contains(&"ferrum.token.connection_failure".to_string()), "{:?}", codes(&o));
}
