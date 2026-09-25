//! Failure-matrix cases for local preparation, client-leg deadlines, TLS
//! trust scoping, proxies, body encodings and diagnostic trust. Real sockets
//! and the shared engine; fixture ground truth is only used to check that a
//! condition was (or was not) reached.

use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::{DispatchState, FailureKind, TlsVerification};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::TransportState;
use anvil_domain::request::{AttachmentRef, Body, RequestSpec};
use anvil_domain::settings::{ProxySelection, ResolverMode, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{HostBinding, ProxyKind, ProxyProfile, TlsProfile};
use anvil_domain::{Id, outcome::ApplicationState};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_fixtures::pki::LabPki;
use anvil_fixtures::raw::{self, RawMode};
use anvil_fixtures::tlsserver::TlsServerOptions;
use anvil_transport::recorder::EventCtx;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

async fn run(ctx: &ExecutionContext) -> ExecutionOutput {
    Engine::new().execute(ctx, EventCtx::none(), CancellationToken::new()).await
}

fn ctx(spec: RequestSpec) -> ExecutionContext {
    ExecutionContext::standalone(spec)
}

fn with_settings(mut c: ExecutionContext, s: SettingsOverrides) -> ExecutionContext {
    c.settings_layers.push(("run".into(), s));
    c
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn has(o: &ExecutionOutput, code: &str) -> bool {
    o.record.findings.iter().any(|f| f.code == code)
}

fn last_failure(o: &ExecutionOutput) -> FailureKind {
    o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind).unwrap_or_else(|| panic!("no failure: {:?}", codes(o)))
}

fn tls_profile(name: &str, roots: Vec<String>, verify: bool) -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: name.into(),
        verify,
        use_system_roots: false,
        extra_roots_pem: roots,
        client_identity: None,
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn select_tls(mut c: ExecutionContext, p: TlsProfile) -> ExecutionContext {
    let id = p.id;
    c.tls_profiles.push(p);
    with_settings(c, SettingsOverrides { tls_profile_id: Some(id), ..Default::default() })
}

async fn tls_fixture(server: &anvil_fixtures::pki::Pem) -> fx::Fixture {
    let o = TlsServerOptions::new(server.chain_with(&pki().ca), server.key.clone());
    fx::serve("127.0.0.1:0", Some(o)).await.unwrap()
}

#[tokio::test]
async fn local_004_missing_attachment_is_local_and_nothing_is_sent() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut spec = RequestSpec::http("POST", &f.url("/echo"));
    spec.body = Body::Binary {
        attachment: AttachmentRef::Stored { sha256: "0".repeat(64), size: 10, file_name: "moved.bin".into(), media_type: None },
        content_type: Some("application/octet-stream".into()),
    };
    let o = run(&ctx(spec)).await;
    assert_eq!(last_failure(&o), FailureKind::MissingAttachment);
    assert!(has(&o, "local.missing_attachment"), "{:?}", codes(&o));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert_eq!(f.log.count_requests(), 0, "no request reached the destination");
    assert!(!codes(&o).iter().any(|c| c.starts_with("http.") || c.starts_with("ferrum.")), "no destination blamed");
}

#[tokio::test]
async fn local_006_invalid_proxy_configuration_is_explained_locally() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let p = ProxyProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "broken proxy".into(),
        kind: ProxyKind::Http,
        address: "not a proxy address".into(),
        username: None,
        password: None,
        no_proxy: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let pid = p.id;
    let mut c = ctx(RequestSpec::http("GET", &f.url("/")));
    c.proxy_profiles.push(p);
    let c = with_settings(c, SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id: pid }), ..Default::default() });
    let o = run(&c).await;
    assert_eq!(last_failure(&o), FailureKind::ProxyConfigInvalid);
    assert!(has(&o, "local.proxy_config_invalid"), "{:?}", codes(&o));
    assert_eq!(f.log.count_requests(), 0);
    assert!(!codes(&o).iter().any(|c| c.starts_with("ferrum.")), "never 'Ferrum backend is down'");
}

#[tokio::test]
async fn local_008_resolver_deadline_is_local_and_cause_beyond_resolver_unknown() {
    init();
    let dns = anvil_fixtures::dns::serve("127.0.0.1:0", anvil_fixtures::dns::DnsMode::Silent).await.unwrap();
    let c = with_settings(
        ctx(RequestSpec::http("GET", "http://api.anvil-lab.test/")),
        SettingsOverrides {
            resolver: Some(ResolverMode::Custom { nameservers: vec![dns.addr.to_string()] }),
            timeouts: Some(TimeoutOverrides { dns_ms: Some(Some(400)), ..Default::default() }),
            ..Default::default()
        },
    );
    let o = run(&c).await;
    assert_eq!(last_failure(&o), FailureKind::DnsTimeout);
    let f = o.record.findings.iter().find(|f| f.code == "client.dns.timeout").unwrap_or_else(|| panic!("{:?}", codes(&o)));
    // Name resolution is part of the caller's leg; nothing about the destination is claimed.
    assert!(matches!(f.scope, SourceScope::LocalClient | SourceScope::ClientToPeer), "{:?}", f.scope);
    assert!(f.confidence != Confidence::Confirmed || !f.explanation.to_lowercase().contains("outage"), "no definite outage claim");
    assert!(!f.does_not_prove.is_empty(), "states what the timeout does not prove");
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
}

#[tokio::test]
async fn local_010_connect_deadline_does_not_claim_firewall_or_backend() {
    init();
    // TEST-NET-1 (RFC 5737) is not routed; connects stall or are refused by
    // the local network stack. Either way nothing reached a server.
    let c = with_settings(
        ctx(RequestSpec::http("GET", "http://192.0.2.1:9/")),
        SettingsOverrides { timeouts: Some(TimeoutOverrides { connect_ms: Some(Some(400)), ..Default::default() }), ..Default::default() },
    );
    let o = run(&c).await;
    let k = last_failure(&o);
    assert!(matches!(k, FailureKind::ConnectTimeout | FailureKind::NetworkUnreachable | FailureKind::HostUnreachable), "{k:?}");
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.response.is_none(), "no invented HTTP headers");
    for f in &o.record.findings {
        assert!(!(f.confidence == Confidence::Confirmed && f.explanation.to_lowercase().contains("firewall")), "{}", f.code);
        assert!(!f.code.starts_with("ferrum.") && !f.code.starts_with("http."), "{}", f.code);
    }
}

#[tokio::test]
async fn tls_013_private_ca_trust_is_scoped_to_its_profile() {
    init();
    let f = tls_fixture(&pki().server).await;
    let url = f.url_host("localhost", "/");
    // Workspace A: profile trusting the private CA → verified.
    let a = run(&select_tls(ctx(RequestSpec::http("GET", &url)), tls_profile("A private CA", vec![pki().ca.cert.clone()], true))).await;
    assert_eq!(a.record.outcome.transport, TransportState::Completed, "{:?}", codes(&a));
    // Workspace B afterwards: no profile → the same server is untrusted; the
    // CA was never installed globally or cached across profiles.
    let b = run(&ctx(RequestSpec::http("GET", &url))).await;
    assert_eq!(last_failure(&b), FailureKind::TlsUntrustedIssuer, "{:?}", codes(&b));
    assert!(has(&b, "client.tls.untrusted_issuer"), "{:?}", codes(&b));
    let b2 =
        run(&select_tls(ctx(RequestSpec::http("GET", &url)), tls_profile("B other CA", vec![pki().rogue_ca.cert.clone()], true))).await;
    assert_eq!(last_failure(&b2), FailureKind::TlsUntrustedIssuer);
}

#[tokio::test]
async fn tls_016_tls_off_and_verification_off_are_distinct() {
    init();
    let plain = fx::serve("127.0.0.1:0", None).await.unwrap();
    let off = run(&ctx(RequestSpec::http("GET", &plain.url("/")))).await;
    let conn = off.record.attempts[0].connection.as_ref().unwrap();
    assert!(conn.tls.is_none(), "plain HTTP has no TLS at all");
    assert!(!has(&off, "client.tls.verification_bypassed"));

    let untrusted = tls_fixture(&pki().server_untrusted).await;
    let bypass =
        run(&select_tls(ctx(RequestSpec::http("GET", &untrusted.url_host("localhost", "/"))), tls_profile("lab bypass", vec![], false)))
            .await;
    assert_eq!(bypass.record.outcome.transport, TransportState::Completed);
    let tls = bypass.record.attempts[0].connection.as_ref().unwrap().tls.as_ref().expect("encrypted");
    assert!(matches!(tls.verification, TlsVerification::Bypassed { .. }), "{:?}", tls.verification);
    assert!(!bypass.record.prepared.tls_verification_enabled);
    assert!(has(&bypass, "client.tls.verification_bypassed"), "{:?}", codes(&bypass));
    assert!(
        bypass.record.outcome.warnings.iter().any(|w| w.code == anvil_domain::outcome::WarningCode::InsecureTls),
        "persistent insecure-TLS warning on the record"
    );
}

#[tokio::test]
async fn tls_017_https_through_a_rejecting_proxy_is_attributed_to_the_proxy_leg() {
    init();
    let proxy =
        raw::serve("127.0.0.1:0", RawMode::Exact { response: b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n".to_vec() }, None)
            .await
            .unwrap();
    let p = ProxyProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "corporate proxy".into(),
        kind: ProxyKind::Http,
        address: proxy.addr.to_string(),
        username: None,
        password: None,
        no_proxy: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let pid = p.id;
    let mut c = ctx(RequestSpec::http("GET", "https://api.example.com/v1/x"));
    c.proxy_profiles.push(p);
    let c = with_settings(c, SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id: pid }), ..Default::default() });
    let o = run(&c).await;
    assert_eq!(last_failure(&o), FailureKind::ProxyTunnelRejected);
    let f = o.record.findings.iter().find(|f| f.code.starts_with("proxy.")).unwrap_or_else(|| panic!("{:?}", codes(&o)));
    assert_eq!(f.scope, SourceScope::ForwardProxy);
    assert!(!codes(&o).iter().any(|c| c.starts_with("client.tls.")), "not an upstream TLS rejection: {:?}", codes(&o));
}

#[tokio::test]
async fn proto_025_compressed_and_binary_bodies_keep_original_bytes_and_sizes() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let gz = run(&ctx(RequestSpec::http("GET", &f.url("/gzip")))).await;
    let b = &gz.record.response.as_ref().unwrap().body;
    assert_eq!(b.content_encoding.as_deref(), Some("gzip"));
    let decoded = b.decoded_bytes.expect("decoded size reported");
    assert!(decoded > b.wire_bytes, "decoded {decoded} vs wire {}", b.wire_bytes);
    assert_eq!(gz.body.len() as u64, b.captured_bytes.min(b.wire_bytes), "raw captured bytes are the wire bytes");
    assert!(gz.decoded_body.as_ref().is_some_and(|d| d.len() as u64 == decoded));

    let bin = run(&ctx(RequestSpec::http("GET", &f.url("/binary")))).await;
    assert_eq!(&bin.body[..], &[0xff, 0xfe, 0x00, 0x01, 0x80, 0x81, 0xc3, 0x28], "non-UTF-8 bytes preserved exactly");
    assert_eq!(bin.record.response.as_ref().unwrap().body.wire_bytes, 8, "byte count, not character count");
}

fn trust(c: &mut ExecutionContext, port: u16) {
    c.integrations.push(IntegrationProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab gateway".into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: vec![HostBinding { host: "127.0.0.1".into(), port: Some(port) }],
            compatibility_id: "ferrum-edge-0.9.5".into(),
            require_verified_tls: false,
            detail: None,
            console_url: None,
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
}

#[tokio::test]
async fn trust_002_stripped_marker_lowers_confidence_and_keeps_http_result() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut c = ctx(RequestSpec::http("GET", &f.url("/status/502")));
    trust(&mut c, f.addr.port());
    let o = run(&c).await;
    assert_eq!(o.record.response.as_ref().unwrap().status, 502, "observed HTTP result preserved");
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);
    assert!(has(&o, "ferrum.marker.absent"), "{:?}", codes(&o));
    for f in &o.record.findings {
        assert!(
            !(f.scope == SourceScope::UpstreamApplication && f.confidence == Confidence::Confirmed),
            "missing header never proves upstream origin: {}",
            f.code
        );
        assert!(!f.code.starts_with("ferrum.token."), "no token without a marker");
    }
}

#[tokio::test]
async fn trust_008_whole_request_stays_uncertain_when_an_earlier_attempt_may_have_processed() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    // A closed port for the redirect target: the final attempt is never dispatched.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let target = format!("http://{closed}/after");
    let url = f.url(&format!("/redirect?status=307&to={}", url::form_urlencoded::byte_serialize(target.as_bytes()).collect::<String>()));
    let mut spec = RequestSpec::http("POST", &url);
    spec.body = Body::Json { text: r#"{"transfer": 100}"#.into() };
    let o = run(&ctx(spec)).await;
    assert!(o.record.attempts.len() >= 2, "redirect followed: {:?}", o.record.attempts.iter().map(|a| &a.url).collect::<Vec<_>>());
    assert_eq!(o.record.attempts.last().unwrap().dispatch, DispatchState::NotDispatched);
    assert!(has(&o, "request.earlier_attempt_may_have_processed"), "{:?}", codes(&o));
    assert_ne!(o.record.outcome.dispatch, DispatchState::NotDispatched, "final not-dispatched does not prove no side effects");
}

/// PROTO-004: a server GOAWAY while a stream is in flight. The POST is not
/// replayed (its processing stays uncertain); an idempotent GET with retries
/// enabled is retried on a new connection; nothing is blamed on TLS.
#[tokio::test]
async fn proto_004_goaway_keeps_per_stream_retry_ambiguity() {
    init();
    use anvil_domain::settings::{HttpVersionPolicy, RetryPolicy};
    let retries = SettingsOverrides {
        http_version: Some(HttpVersionPolicy::H2c),
        retries: Some(RetryPolicy { max_retries: 1, backoff_ms: 10, only_safe: true }),
        ..Default::default()
    };

    let f = anvil_fixtures::goaway::serve("127.0.0.1:0").await.unwrap();
    let mut spec = RequestSpec::http("POST", &f.url("/orders"));
    spec.body = Body::Json { text: r#"{"qty": 1}"#.into() };
    let post = run(&with_settings(ctx(spec), retries.clone())).await;
    assert_eq!(post.record.attempts.len(), 1, "a possibly processed POST is never replayed automatically");
    // A GOAWAY whose last-stream-id covers this stream lets it finish; the
    // server then closing surfaces as "closed before response".
    assert!(matches!(last_failure(&post), FailureKind::H2GoAway | FailureKind::ClosedBeforeResponse), "{:?}", codes(&post));
    assert_ne!(post.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(has(&post, "exchange.h2_goaway") || has(&post, "exchange.closed_before_response"), "{:?}", codes(&post));
    assert!(has(&post, "request.processing_uncertain"), "processing stays uncertain: {:?}", codes(&post));
    assert!(!codes(&post).iter().any(|c| c.starts_with("client.tls.")), "GOAWAY is not a TLS failure");
    assert_eq!(f.streams_seen.load(std::sync::atomic::Ordering::SeqCst), 1, "the server saw the POST exactly once");

    let g = anvil_fixtures::goaway::serve("127.0.0.1:0").await.unwrap();
    let get = run(&with_settings(ctx(RequestSpec::http("GET", &g.url("/status"))), retries)).await;
    assert_eq!(get.record.attempts.len(), 2, "idempotent GET retried on a new connection");
    assert_eq!(get.record.response.as_ref().map(|r| r.status), Some(200));
    assert_eq!(get.record.outcome.transport, TransportState::Completed);
}
