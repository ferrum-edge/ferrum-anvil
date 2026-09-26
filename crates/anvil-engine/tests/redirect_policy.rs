//! Redirect hops: every hop is evaluated for its own target. Credentials
//! configured for the original origin stay there, the proxy route (NO_PROXY)
//! is decided for the new host, and Ferrum attribution comes from the origin
//! that produced the final response. Fixture logs are independent ground truth.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::*;
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{ProxySelection, RedirectPolicy, SettingsOverrides};
use anvil_domain::tls::{HostBinding, ProxyKind, ProxyProfile};
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_fixtures::log::GroundTruth;
use anvil_transport::recorder::EventCtx;
use std::sync::{Arc, Mutex};
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

/// Credentials configured by hand: a known credential header name, a custom
/// header marked sensitive, a header whose value holds a secret variable, a
/// manual cookie, and one ordinary header that may follow any redirect.
fn with_configured_credentials(ctx: &mut ExecutionContext) {
    ctx.var_layers = vec![VarLayer {
        label: "environment:lab".into(),
        vars: vec![VarEntry { name: "tenant_key".into(), value: "TENANT-SECRET-5a4b3c".into(), secret: true }],
    }];
    ctx.spec.headers.push(KeyValue::new("X-API-Key", "DUMMY-API-KEY-1a2b3c"));
    let mut custom = KeyValue::new("X-Custom", "DUMMY-CUSTOM-KEY-4d5e6f");
    custom.sensitive = true;
    ctx.spec.headers.push(custom);
    ctx.spec.headers.push(KeyValue::new("X-Tenant", "t-{{tenant_key}}"));
    ctx.spec.headers.push(KeyValue::new("Cookie", "sid=DUMMY-COOKIE-7g8h9i"));
    ctx.spec.headers.push(KeyValue::new("X-Plain", "visible"));
}

const CREDENTIAL_HEADERS: [&str; 4] = ["x-api-key", "x-custom", "x-tenant", "cookie"];

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
    ctx.auth_layers =
        vec![("request".into(), AuthConfig::Bearer { token: SensitiveValue::template("DUMMY-BEARER-0j1k2l"), prefix: "Bearer".into() })];
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
                    value: SensitiveValue::template("DUMMY-QUERY-KEY-3m4n5o"),
                    location: KeyLocation::Query,
                },
                AuthConfig::ApiKey {
                    name: "session_key".into(),
                    value: SensitiveValue::template("DUMMY-COOKIE-KEY-6p7q8r"),
                    location: KeyLocation::Cookie,
                },
            ],
        },
    )];
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    let (first_target, first_headers) = received(&a).remove(0);
    assert!(first_target.contains("DUMMY-QUERY-KEY-3m4n5o"), "ground truth: the key went to the configured origin");
    assert!(has_header(&first_headers, "cookie"));
    let (target, headers) = received(&b).remove(0);
    assert!(!target.contains("api_key") && !target.contains("DUMMY-QUERY-KEY"), "{target}");
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
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 64 * 1024 {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string();
                seen.lock().unwrap().push(line);
                let _ = s.write_all(response.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    ProxySentinel { addr, lines }
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
