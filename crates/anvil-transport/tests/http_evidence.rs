//! Native transport evidence against real local sockets (no mocks).
//! Scenario IDs from the failure matrix are kept in test names.

use anvil_domain::execution::*;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::http as fxhttp;
use anvil_fixtures::raw::{self, RawMode};
use anvil_fixtures::{ClientAuth, LabPki, TlsServerOptions};
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::{AttemptOutput, HttpPlan, HttpTransport};
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{self, ClientIdentityMaterial, TlsSettings};
use bytes::Bytes;
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn trust_lab() -> TlsSettings {
    TlsSettings { verify: true, use_system_roots: false, extra_roots_pem: vec![pki().ca.cert.clone()], ..Default::default() }
}

fn plan(url: &str, tls: Option<TlsSettings>) -> HttpPlan {
    let u = url::Url::parse(url).unwrap();
    let https = u.scheme() == "https";
    let host = u.host_str().unwrap().to_string();
    let port = u.port_or_known_default().unwrap();
    let authority = match u.port() {
        Some(p) => format!("{}:{}", host, p),
        None => host.clone(),
    };
    let target = format!("{}{}", u.path(), u.query().map(|q| format!("?{q}")).unwrap_or_default());
    HttpPlan {
        method: http::Method::GET,
        https,
        host,
        port,
        authority,
        request_target: target,
        headers: vec![],
        body: Bytes::new(),
        version: HttpVersionPolicy::Auto,
        timeouts: Timeouts {
            dns_ms: Some(2000),
            connect_ms: Some(2000),
            tls_handshake_ms: Some(1500),
            request_write_ms: Some(2000),
            response_headers_ms: Some(1500),
            body_idle_ms: Some(1000),
            total_ms: Some(8000),
        },
        limits: Limits::default(),
        keepalive: true,
        dns: DnsConfig::default(),
        proxy: None,
        tls: if https { Some(Arc::new(tls::prepare(&tls.unwrap_or_else(trust_lab)).expect("tls profile"))) } else { None },
        isolation: "test".into(),
        display_url: url.into(),
    }
}

async fn run(t: &HttpTransport, p: &HttpPlan) -> AttemptOutput {
    let mut outs = t.execute(p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    outs.pop().unwrap()
}

fn failure(o: &AttemptOutput) -> &TransportFailure {
    o.observation.failure.as_ref().unwrap_or_else(|| panic!("expected failure, got status {:?}", o.observation.response_status))
}

fn phase_status(o: &AttemptOutput, p: Phase) -> Option<PhaseStatus> {
    o.observation.phase(p).map(|x| x.status)
}

async fn tls_fixture(cert: &anvil_fixtures::pki::Pem, auth: ClientAuth) -> fxhttp::Fixture {
    let mut o = TlsServerOptions::new(cert.chain_with(&pki().ca), cert.key.clone());
    o.client_auth = auth;
    fxhttp::serve("127.0.0.1:0", Some(o)).await.unwrap()
}

#[tokio::test]
async fn positive_control_http1_evidence_and_keepalive_reuse_proto_001() {
    init();
    let fx = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let t = HttpTransport::new();
    let p = plan(&fx.url("/status/200"), None);
    let a = run(&t, &p).await;
    assert!(a.observation.failure.is_none(), "{:?}", a.observation.failure);
    assert_eq!(a.observation.response_status, Some(200));
    assert_eq!(a.observation.dispatch, DispatchState::Sent);
    let c = a.observation.connection.as_ref().unwrap();
    assert!(!c.reused);
    assert_eq!(c.protocol.as_deref(), Some("http/1.1"));
    assert_eq!(phase_status(&a, Phase::Connect), Some(PhaseStatus::Completed));
    assert_eq!(phase_status(&a, Phase::Dns), Some(PhaseStatus::NotApplicable), "IP literal must not show a DNS measurement");
    assert_eq!(a.response.as_ref().unwrap().body.completeness, BodyCompleteness::Complete);

    // Second request reuses the connection: DNS/connect are `reused`, never a fresh 0 ms.
    let b = run(&t, &p).await;
    let c = b.observation.connection.as_ref().unwrap();
    assert!(c.reused, "second request should reuse the pooled connection");
    assert_eq!(phase_status(&b, Phase::Connect), Some(PhaseStatus::Reused));
    assert!(b.observation.phase(Phase::Connect).unwrap().duration_us().is_none());
    assert_eq!(fx.log.count_requests(), 2);
}

#[tokio::test]
async fn local_009_connection_refused_is_client_leg_and_not_dispatched() {
    init();
    // Bind then drop to obtain a closed port.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let t = HttpTransport::new();
    let a = run(&t, &plan(&format!("http://127.0.0.1:{port}/"), None)).await;
    let f = failure(&a);
    assert_eq!(f.kind, FailureKind::ConnectRefused);
    assert_eq!(f.phase, Phase::Connect);
    assert_eq!(a.observation.dispatch, DispatchState::NotDispatched);
    assert!(a.response.is_none());
}

#[tokio::test]
async fn tls_001_untrusted_root_is_confirmed_by_verifier() {
    init();
    let fx = tls_fixture(&pki().server_untrusted, ClientAuth::None).await;
    let a = run(&HttpTransport::new(), &plan(&fx.url("/"), None)).await;
    let f = failure(&a);
    assert_eq!(f.kind, FailureKind::TlsUntrustedIssuer);
    assert_eq!(a.observation.dispatch, DispatchState::NotDispatched);
    let tls = a.observation.connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert!(matches!(tls.verification, TlsVerification::Failed { problem: FailureKind::TlsUntrustedIssuer, .. }));
    assert!(!tls.peer_certificates.is_empty(), "presented chain is evidence even on failure");
}

#[tokio::test]
async fn tls_002_hostname_mismatch() {
    init();
    let fx = tls_fixture(&pki().server_wrong_name, ClientAuth::None).await;
    let a = run(&HttpTransport::new(), &plan(&fx.url_host("localhost", "/"), None)).await;
    assert_eq!(failure(&a).kind, FailureKind::TlsNameMismatch);
}

#[tokio::test]
async fn tls_003_expired_and_tls_004_not_yet_valid() {
    init();
    let fx = tls_fixture(&pki().server_expired, ClientAuth::None).await;
    let a = run(&HttpTransport::new(), &plan(&fx.url_host("localhost", "/"), None)).await;
    assert_eq!(failure(&a).kind, FailureKind::TlsExpired);
    let fx2 = tls_fixture(&pki().server_not_yet_valid, ClientAuth::None).await;
    let b = run(&HttpTransport::new(), &plan(&fx2.url_host("localhost", "/"), None)).await;
    assert_eq!(failure(&b).kind, FailureKind::TlsNotYetValid);
}

#[tokio::test]
async fn tls_005_missing_client_certificate_records_request_evidence() {
    init();
    let fx = tls_fixture(&pki().server, ClientAuth::Required { ca_pem: pki().client_ca.cert.clone() }).await;
    let a = run(&HttpTransport::new(), &plan(&fx.url_host("localhost", "/"), None)).await;
    let f = failure(&a);
    assert!(
        matches!(f.kind, FailureKind::TlsAlertAfterHandshake | FailureKind::TlsAlertReceived),
        "TLS 1.3 client-cert rejection surfaces as a peer alert, got {:?} ({})",
        f.kind,
        f.message
    );
    assert_eq!(f.tls_alert.as_deref(), Some("certificate_required"));
    let tls = a.observation.connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.client_certificate_requested, Some(true));
    assert!(tls.client_certificate_presented.is_none());
    assert!(a.response.is_none(), "no HTTP response exists");
}

#[tokio::test]
async fn tls_006_rejected_client_certificate_and_tls_008_valid_mtls() {
    init();
    let fx = tls_fixture(&pki().server, ClientAuth::Required { ca_pem: pki().client_ca.cert.clone() }).await;
    let mut bad = trust_lab();
    bad.client_identity = Some(ClientIdentityMaterial {
        cert_chain_pem: pki().client_rogue.cert.clone(),
        private_key_pem: Zeroizing::new(pki().client_rogue.key.clone()),
    });
    let a = run(&HttpTransport::new(), &plan(&fx.url_host("localhost", "/"), Some(bad))).await;
    let f = failure(&a);
    assert!(matches!(f.kind, FailureKind::TlsAlertAfterHandshake | FailureKind::TlsAlertReceived), "{:?}", f);
    let tls = a.observation.connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert!(tls.client_certificate_presented.is_some());

    let mut good = trust_lab();
    good.client_identity = Some(ClientIdentityMaterial {
        cert_chain_pem: pki().client_a.cert.clone(),
        private_key_pem: Zeroizing::new(pki().client_a.key.clone()),
    });
    let b = run(&HttpTransport::new(), &plan(&fx.url_host("localhost", "/echo"), Some(good))).await;
    assert!(b.observation.failure.is_none(), "{:?}", b.observation.failure);
    let presented = b.observation.connection.as_ref().unwrap().tls.as_ref().unwrap().client_certificate_presented.as_ref().unwrap();
    assert!(presented.subject.contains("anvil-client-a"));
    let dbg = format!("{:?}", b.observation);
    assert!(!dbg.contains("PRIVATE KEY"), "private key material must never appear in evidence");
}

#[tokio::test]
async fn tls_007_key_mismatch_is_local_validation() {
    init();
    let mut s = trust_lab();
    s.client_identity = Some(ClientIdentityMaterial {
        cert_chain_pem: pki().client_a.cert.clone(),
        private_key_pem: Zeroizing::new(pki().client_b.key.clone()),
    });
    match tls::prepare(&s) {
        Err(f) => {
            assert_eq!(f.kind, FailureKind::ClientIdentityKeyMismatch);
            assert_eq!(f.phase, Phase::Prepare);
        }
        Ok(_) => panic!("mismatched key must fail locally"),
    }
}

#[tokio::test]
async fn local_005_unreadable_private_key_is_local() {
    init();
    let mut s = trust_lab();
    s.client_identity = Some(ClientIdentityMaterial {
        cert_chain_pem: pki().client_a.cert.clone(),
        private_key_pem: Zeroizing::new("-----BEGIN PRIVATE KEY-----\nnot base64!\n-----END PRIVATE KEY-----\n".into()),
    });
    let f = tls::prepare(&s).err().expect("must fail");
    assert_eq!(f.kind, FailureKind::ClientIdentityInvalid);
}

#[tokio::test]
async fn tls_009_https_to_plaintext_port_is_protocol_mismatch() {
    init();
    let fx = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let a = run(&HttpTransport::new(), &plan(&format!("https://localhost:{}/", fx.addr.port()), None)).await;
    let f = failure(&a);
    assert_eq!(f.kind, FailureKind::TlsProtocolMismatch, "{}", f.message);
    assert_eq!(f.phase, Phase::TlsHandshake);
}

#[tokio::test]
async fn tls_010_handshake_stall_hits_tls_deadline() {
    init();
    let fx = raw::serve("127.0.0.1:0", RawMode::AcceptStall, None).await.unwrap();
    let a = run(&HttpTransport::new(), &plan(&format!("https://localhost:{}/", fx.addr.port()), None)).await;
    let f = failure(&a);
    assert_eq!(f.kind, FailureKind::TlsHandshakeTimeout);
    assert_eq!(f.deadline_ms, Some(1500));
    assert_eq!(phase_status(&a, Phase::TlsHandshake), Some(PhaseStatus::TimedOut));
    assert_eq!(phase_status(&a, Phase::Connect), Some(PhaseStatus::Completed));
}

#[tokio::test]
async fn tls_011_reset_during_handshake_is_not_attributed_to_certs() {
    init();
    let fx = raw::serve("127.0.0.1:0", RawMode::AcceptReset, None).await.unwrap();
    let a = run(&HttpTransport::new(), &plan(&format!("https://localhost:{}/", fx.addr.port()), None)).await;
    let f = failure(&a);
    assert!(matches!(f.kind, FailureKind::TlsReset | FailureKind::TlsPeerClosed), "{:?} {}", f.kind, f.message);
    assert!(f.tls_alert.is_none());
}

#[tokio::test]
async fn tls_015_verification_bypass_is_scoped_and_records_would_fail() {
    init();
    let fx = tls_fixture(&pki().server_untrusted, ClientAuth::None).await;
    let mut bypass = trust_lab();
    bypass.verify = false;
    let t = HttpTransport::new();
    let a = run(&t, &plan(&fx.url_host("localhost", "/"), Some(bypass))).await;
    assert!(a.observation.failure.is_none());
    let v = &a.observation.connection.as_ref().unwrap().tls.as_ref().unwrap().verification;
    assert_eq!(*v, TlsVerification::Bypassed { would_have_failed: Some(FailureKind::TlsUntrustedIssuer) });
    // Same transport, strict profile: must fail (no pooled bypassed connection reused).
    let b = run(&t, &plan(&fx.url_host("localhost", "/"), None)).await;
    assert_eq!(failure(&b).kind, FailureKind::TlsUntrustedIssuer);
}

#[tokio::test]
async fn tls_014_mtls_pool_isolation_between_profiles() {
    init();
    let fx = tls_fixture(&pki().server, ClientAuth::Optional { ca_pem: pki().client_ca.cert.clone() }).await;
    let t = HttpTransport::new();
    let mut a_prof = trust_lab();
    a_prof.client_identity = Some(ClientIdentityMaterial {
        cert_chain_pem: pki().client_a.cert.clone(),
        private_key_pem: Zeroizing::new(pki().client_a.key.clone()),
    });
    let a = run(&t, &plan(&fx.url_host("localhost", "/"), Some(a_prof))).await;
    assert!(a.observation.failure.is_none());
    // Unauthenticated profile must not reuse the connection that presented client A.
    let b = run(&t, &plan(&fx.url_host("localhost", "/"), None)).await;
    assert!(!b.observation.connection.as_ref().unwrap().reused);
    let cns: Vec<Option<String>> = fx
        .log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            anvil_fixtures::GroundTruth::TlsHandshakeCompleted { client_cert_cn, .. } => Some(client_cert_cn),
            _ => None,
        })
        .collect();
    assert_eq!(cns.len(), 2);
    assert_eq!(cns[0].as_deref(), Some("anvil-client-a"));
    assert_eq!(cns[1], None);
}

#[tokio::test]
async fn up_011_body_idle_stall_after_200_is_incomplete_not_success() {
    init();
    let fx = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let a = run(&HttpTransport::new(), &plan(&fx.url("/stall-body/5000"), None)).await;
    assert_eq!(a.observation.response_status, Some(200));
    let f = failure(&a);
    assert_eq!(f.kind, FailureKind::BodyIdleTimeout);
    assert_eq!(a.response.as_ref().unwrap().body.completeness, BodyCompleteness::Incomplete);
    assert_eq!(a.observation.dispatch, DispatchState::Sent);
}

#[tokio::test]
async fn up_013_short_content_length_is_incomplete() {
    init();
    let fx = raw::serve("127.0.0.1:0", RawMode::ShortBody { declared: 100, sent: 10 }, None).await.unwrap();
    let a = run(&HttpTransport::new(), &plan(&fx.url(false, "/"), None)).await;
    assert_eq!(a.observation.response_status, Some(200));
    assert_eq!(failure(&a).kind, FailureKind::BodyIncomplete);
    let body = &a.response.as_ref().unwrap().body;
    assert_eq!(body.completeness, BodyCompleteness::Incomplete);
    assert_eq!(body.wire_bytes, 10);
    assert_eq!(body.declared_length, Some(100));
}

#[tokio::test]
async fn up_012_reset_mid_body() {
    init();
    let fx = raw::serve("127.0.0.1:0", RawMode::ResetMidBody { sent: 2048 }, None).await.unwrap();
    let a = run(&HttpTransport::new(), &plan(&fx.url(false, "/"), None)).await;
    assert_eq!(a.observation.response_status, Some(200));
    assert!(matches!(failure(&a).kind, FailureKind::BodyReset | FailureKind::BodyIncomplete), "{:?}", failure(&a));
    assert_eq!(a.response.as_ref().unwrap().body.completeness, BodyCompleteness::Incomplete);
}

#[tokio::test]
async fn reset_after_request_may_have_been_sent() {
    init();
    let fx = raw::serve("127.0.0.1:0", RawMode::ResetAfterRequest, None).await.unwrap();
    let mut p = plan(&fx.url(false, "/"), None);
    p.method = http::Method::POST;
    p.body = Bytes::from_static(b"{\"order\":1}");
    let a = run(&HttpTransport::new(), &p).await;
    let f = failure(&a);
    assert!(matches!(f.kind, FailureKind::ResetBeforeResponse | FailureKind::ClosedBeforeResponse), "{:?}", f);
    assert_eq!(a.observation.dispatch, DispatchState::MayHaveBeenSent, "bytes left the client; processing is possible");
    assert!(fx.log.count_requests() >= 1, "ground truth: the fixture did read the request");
}

#[tokio::test]
async fn headers_timeout_distinct_from_body_timeout() {
    init();
    let fx = raw::serve("127.0.0.1:0", RawMode::ReadThenStall, None).await.unwrap();
    let a = run(&HttpTransport::new(), &plan(&fx.url(false, "/"), None)).await;
    assert_eq!(failure(&a).kind, FailureKind::ResponseHeadersTimeout);
    assert_eq!(a.observation.dispatch, DispatchState::MayHaveBeenSent);
}

#[tokio::test]
async fn local_012_display_cap_is_not_a_wire_failure() {
    init();
    let fx = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = plan(&fx.url("/bytes/300000"), None);
    p.limits.capture_bytes = 1000;
    let a = run(&HttpTransport::new(), &p).await;
    assert!(a.observation.failure.is_none());
    let body = &a.response.as_ref().unwrap().body;
    assert_eq!(body.completeness, BodyCompleteness::Complete);
    assert!(body.display_truncated);
    assert_eq!(body.wire_bytes, 300000);
    assert_eq!(body.captured_bytes, 1000);
}

#[tokio::test]
async fn local_limit_stops_reading_and_says_so() {
    init();
    let fx = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = plan(&fx.url("/bytes/500000"), None);
    p.limits.max_response_bytes = 100_000;
    let a = run(&HttpTransport::new(), &p).await;
    assert_eq!(failure(&a).kind, FailureKind::ResponseTooLargeLocal);
    assert_eq!(a.response.as_ref().unwrap().body.completeness, BodyCompleteness::StoppedAtLocalLimit);
}

#[tokio::test]
async fn proto_002_http2_trailers_preserved() {
    init();
    let fx = tls_fixture(&pki().server, ClientAuth::None).await;
    let mut p = plan(&fx.url_host("localhost", "/trailers"), None);
    p.version = HttpVersionPolicy::Http2Only;
    let a = run(&HttpTransport::new(), &p).await;
    assert!(a.observation.failure.is_none(), "{:?}", a.observation.failure);
    assert_eq!(a.observation.connection.as_ref().unwrap().protocol.as_deref(), Some("h2"));
    let r = a.response.as_ref().unwrap();
    assert!(r.trailers_received);
    assert_eq!(r.trailer_values("x-checksum"), vec!["abc123"]);
}

#[tokio::test]
async fn proto_003_http2_stream_reset_scoped_to_stream() {
    init();
    let fx = tls_fixture(&pki().server, ClientAuth::None).await;
    let t = HttpTransport::new();
    let mut p = plan(&fx.url_host("localhost", "/body-error"), None);
    p.version = HttpVersionPolicy::Http2Only;
    let a = run(&t, &p).await;
    let f = failure(&a);
    assert_eq!(f.kind, FailureKind::H2StreamReset, "{}", f.message);
    assert!(f.h2_error_code.is_some());
    // The multiplexed connection stays usable for an unrelated stream.
    let mut p2 = plan(&fx.url_host("localhost", "/status/200"), None);
    p2.version = HttpVersionPolicy::Http2Only;
    let b = run(&t, &p2).await;
    assert!(b.observation.failure.is_none());
    assert!(b.observation.connection.as_ref().unwrap().reused);
}

#[tokio::test]
async fn proto_005_h2c_against_http1_only_peer_fails_cleanly() {
    init();
    let fx = raw::serve(
        "127.0.0.1:0",
        RawMode::Exact { response: b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec() },
        None,
    )
    .await
    .unwrap();
    let mut p = plan(&fx.url(false, "/"), None);
    p.version = HttpVersionPolicy::H2c;
    let a = run(&HttpTransport::new(), &p).await;
    let f = failure(&a);
    assert!(a.observation.connection.as_ref().unwrap().tls.is_none(), "no TLS handshake occurred for h2c");
    // The HTTP/1 answer is not HTTP/2: Anvil's own h2 library rejects it. That
    // local detection must not be reported as the peer sending GOAWAY.
    assert!(
        matches!(f.kind, FailureKind::HttpProtocolError | FailureKind::ClosedBeforeResponse | FailureKind::ResetBeforeResponse),
        "{:?}",
        f
    );
}

#[tokio::test]
async fn proto_005_h2c_against_a_tls_listener_is_a_protocol_mismatch_not_a_peer_goaway() {
    init();
    // A TLS listener answers the cleartext HTTP/2 preface with a TLS alert record.
    let fx = fxhttp::serve("127.0.0.1:0", Some(TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())))
        .await
        .unwrap();
    let mut p = plan(&format!("http://127.0.0.1:{}/", fx.addr.port()), None);
    p.version = HttpVersionPolicy::H2c;
    let a = run(&HttpTransport::new(), &p).await;
    let f = failure(&a);
    assert!(a.observation.connection.as_ref().unwrap().tls.is_none(), "no TLS handshake occurred for h2c");
    assert_ne!(f.kind, FailureKind::H2GoAway, "a locally detected bad frame is not the peer's GOAWAY: {f:?}");
    assert!(
        matches!(f.kind, FailureKind::HttpProtocolError | FailureKind::ClosedBeforeResponse | FailureKind::ResetBeforeResponse),
        "{f:?}"
    );
    assert_eq!(fx.log.count_requests(), 0);
}

#[tokio::test]
async fn tls_012_http2_only_refuses_http1_alpn() {
    init();
    let mut o = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    o.alpn = vec!["http/1.1".into()];
    let fx = fxhttp::serve("127.0.0.1:0", Some(o)).await.unwrap();
    let mut p = plan(&fx.url_host("localhost", "/"), None);
    p.version = HttpVersionPolicy::Http2Only;
    let a = run(&HttpTransport::new(), &p).await;
    assert_eq!(failure(&a).kind, FailureKind::TlsAlpnMismatch);
    assert_eq!(fx.log.count_requests(), 0, "no silent HTTP/1.1 fallback");
}

#[tokio::test]
async fn local_011_cancel_during_upload_is_canceled_with_dispatch_uncertainty() {
    init();
    let fx = raw::serve("127.0.0.1:0", RawMode::ReadThenStall, None).await.unwrap();
    let mut p = plan(&fx.url(false, "/upload"), None);
    p.method = http::Method::POST;
    p.body = Bytes::from(vec![b'u'; 1024]);
    let t = HttpTransport::new();
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        c2.cancel();
    });
    let outs = t.execute(&p, 0, AttemptReason::Initial, &EventCtx::none(), &cancel).await;
    let a = outs.last().unwrap();
    assert_eq!(a.observation.failure.as_ref().unwrap().kind, FailureKind::Canceled);
    assert_eq!(a.observation.dispatch, DispatchState::MayHaveBeenSent);
}

#[tokio::test]
async fn local_007_nxdomain_via_custom_resolver_is_typed() {
    init();
    // `.invalid` is reserved (RFC 6761) and never resolves.
    let mut p = plan("http://anvil-does-not-exist.invalid/", None);
    p.timeouts.dns_ms = Some(3000);
    let a = run(&HttpTransport::new(), &p).await;
    let f = failure(&a);
    assert_eq!(f.phase, Phase::Dns);
    assert!(
        matches!(f.kind, FailureKind::DnsNoSuchHost | FailureKind::DnsNoRecords | FailureKind::DnsServerFailure | FailureKind::DnsTimeout),
        "{:?}",
        f
    );
    assert_eq!(a.observation.dispatch, DispatchState::NotDispatched);
}

#[tokio::test]
async fn dns_override_skips_resolution() {
    init();
    let fx = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = plan(&format!("http://api.anvil.test:{}/status/200", fx.addr.port()), None);
    p.dns.overrides = vec![anvil_domain::settings::DnsOverride { host: "api.anvil.test".into(), addresses: vec!["127.0.0.1".into()] }];
    let a = run(&HttpTransport::new(), &p).await;
    assert!(a.observation.failure.is_none(), "{:?}", a.observation.failure);
    assert_eq!(a.observation.connection.as_ref().unwrap().resolution_source.as_deref(), Some("override"));
    let hdrs = fx.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "host" && v.starts_with("api.anvil.test")), "Host header keeps the requested authority");
}

#[tokio::test]
async fn stale_pooled_connection_redispatch_is_recorded_as_separate_attempt() {
    init();
    // Server closes after each response (Connection: close is honored), so the
    // pool must never hand out a dead connection; if hyper proves the request
    // was unsent on a reused connection, a second attempt is recorded.
    let fx = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let t = HttpTransport::new();
    let p = plan(&fx.url("/status/200"), None);
    for _ in 0..5 {
        let outs = t.execute(&p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
        let last = outs.last().unwrap();
        assert!(last.observation.failure.is_none());
        for o in &outs[..outs.len() - 1] {
            assert_eq!(o.observation.dispatch, DispatchState::NotDispatched);
        }
    }
}
