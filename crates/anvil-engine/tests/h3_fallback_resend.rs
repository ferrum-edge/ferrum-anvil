//! The automatic HTTP/3 policy falls back to TCP after an HTTP/3 attempt that
//! failed without a response only when sending the request again is safe:
//! nothing of it was sent over HTTP/3, or its method is idempotent. The TCP
//! attempt is signed again: a new HMAC nonce, a new DPoP proof `jti`. The
//! destination serves HTTP/3 and TCP on one port; over HTTP/3 it reads each
//! request and resets its stream without answering, and over TCP it answers
//! a per-send value it has already received with 401, as a gateway that
//! checks for replays does. A written POST is not sent again. Real loopback
//! sockets, no mocks.
//!
//! The decision itself is also tested directly: a dispatch state of
//! `unknown` cannot be produced on purpose by a real server, and it must
//! count as possibly received.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile};
use anvil_domain::execution::*;
use anvil_domain::outcome::WarningCode;
use anvil_domain::request::{Body, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, RetryPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::h3_exec::{H3Fallback, tcp_fallback};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::replay_guard::{self, Received, ReplayFixture};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use std::collections::HashSet;
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

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

fn hmac() -> AuthConfig {
    AuthConfig::Hmac {
        config: HmacConfig {
            profile: HmacProfile::FerrumV2,
            username: "fallback-client".into(),
            secret: SensitiveValue::template("audit-only-hmac-secret-7q3w"),
            algorithm: HmacAlgorithm::HmacSha256,
            digest_header: Default::default(),
            namespace: String::new(),
            allow_unsafe_legacy: false,
        },
    }
}

fn dpop() -> AuthConfig {
    AuthConfig::Dpop {
        config: DpopConfig {
            access_token: SensitiveValue::template("audit-only-dpop-token-9k5d"),
            private_key_pem: SensitiveValue::template(anvil_auth::dpop::generate_key_pem().unwrap()),
            dpop_scheme: true,
            handle_nonce_challenge: false,
        },
    }
}

/// A `method` of `url` with `auth` and a body, over HTTP/3 with fallback to
/// TCP, trusting the lab CA, and retries set to 0.
fn ctx(method: &str, url: &str, auth: AuthConfig) -> ExecutionContext {
    let mut s = RequestSpec::http(method, url);
    s.auth = auth;
    if method != "GET" {
        s.body = Body::Json { text: r#"{"n":1}"#.into() };
    }
    let mut c = ExecutionContext::standalone(s);
    let p = TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let id = p.id;
    c.tls_profiles.push(p);
    c.settings_layers.push((
        "run".into(),
        SettingsOverrides {
            tls_profile_id: Some(id),
            http_version: Some(HttpVersionPolicy::Http3WithFallback),
            retries: Some(RetryPolicy { max_retries: 0, backoff_ms: 0, only_safe: true }),
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(2_000)),
                tls_handshake_ms: Some(Some(700)),
                response_headers_ms: Some(Some(4_000)),
                total_ms: Some(Some(15_000)),
                ..Default::default()
            }),
            ..Default::default()
        },
    ));
    c
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

fn fell_back(o: &ExecutionOutput) -> bool {
    o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::ProtocolFallback)
}

/// The per-send value of a request that the destination checks for replays.
#[derive(Clone, Copy)]
enum PerSend {
    /// The `nonce` of an HMAC `Authorization` header.
    HmacNonce,
    /// The `jti` of a `DPoP` proof.
    DpopJti,
}

/// The per-send value of a received request, or "" when it has none.
fn per_send(r: &Received, kind: PerSend) -> String {
    let value = match kind {
        PerSend::HmacNonce => {
            let a = &r.authorization;
            a.find("nonce=\"").and_then(|i| {
                let start = i + "nonce=\"".len();
                let len = a[start..].find('"')?;
                Some(a[start..start + len].to_string())
            })
        }
        PerSend::DpopJti => r.dpop.split('.').nth(1).and_then(|c| {
            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(c).ok()?;
            let claims: serde_json::Value = serde_json::from_slice(&claims).ok()?;
            claims["jti"].as_str().map(str::to_string)
        }),
    };
    value.unwrap_or_default()
}

async fn with_quic() -> ReplayFixture {
    replay_guard::serve(server_tls(), true).await.unwrap()
}

/// A GET that reached the destination over HTTP/3 and got no response is
/// sent again over TCP, signed again: the destination accepts it only with a
/// per-send value it has not seen.
async fn get_resent_over_tcp_signed_again(auth: AuthConfig, kind: PerSend) {
    init();
    let o = with_quic().await;
    let out = run(&Engine::new(), &ctx("GET", &o.url("/echo"), auth)).await;
    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 2, "{:?}", atts.iter().map(|a| (&a.reason, &a.failure)).collect::<Vec<_>>());

    let h3 = &atts[0];
    assert_eq!(h3.connection.as_ref().and_then(|c| c.protocol.as_deref()), Some("h3"));
    assert!(h3.response_status.is_none());
    assert_eq!(h3.dispatch, DispatchState::MayHaveBeenSent);
    let f = h3.failure.as_ref().expect("the reset stream failed the HTTP/3 attempt");
    assert!(
        f.message.contains("the GET request may have been received; being idempotent, it was sent over TCP as attempt 1, signed again"),
        "{}",
        f.message
    );

    let tcp = &atts[1];
    assert_eq!(tcp.reason, AttemptReason::ProtocolFallback { from: "h3".into() });
    assert_ne!(tcp.connection.as_ref().and_then(|c| c.protocol.as_deref()), Some("h3"));
    assert_eq!(status(&out), Some(200), "the destination saw the per-send value again: {:?}", o.received());
    assert!(fell_back(&out));

    let seen = o.received();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].protocol, "h3");
    assert_ne!(seen[1].protocol, "h3");
    assert!(seen.iter().all(|r| r.method == "GET" && !r.replayed), "{seen:?}");
    let values: Vec<String> = seen.iter().map(|r| per_send(r, kind)).collect();
    assert!(values.iter().all(|v| !v.is_empty()), "{values:?}");
    let distinct: HashSet<&String> = values.iter().collect();
    assert_eq!(distinct.len(), 2, "a per-send value was sent twice: {values:?}");
}

#[tokio::test]
async fn an_hmac_signed_get_that_failed_over_http3_is_sent_over_tcp_with_a_new_nonce() {
    get_resent_over_tcp_signed_again(hmac(), PerSend::HmacNonce).await;
}

#[tokio::test]
async fn a_dpop_get_that_failed_over_http3_is_sent_over_tcp_with_a_new_proof() {
    get_resent_over_tcp_signed_again(dpop(), PerSend::DpopJti).await;
}

#[tokio::test]
async fn a_written_post_that_failed_over_http3_is_not_sent_over_tcp() {
    init();
    let o = with_quic().await;
    let out = run(&Engine::new(), &ctx("POST", &o.url("/echo"), hmac())).await;
    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 1, "the POST was sent again: {:?}", atts.iter().map(|a| &a.reason).collect::<Vec<_>>());
    let a = &atts[0];
    assert_eq!(a.connection.as_ref().and_then(|c| c.protocol.as_deref()), Some("h3"));
    assert_eq!(a.dispatch, DispatchState::MayHaveBeenSent);
    let f = a.failure.as_ref().expect("the reset stream failed the HTTP/3 attempt");
    assert!(
        f.message.contains("not sent again over TCP: the POST request may have been received over HTTP/3 and is not idempotent"),
        "{}",
        f.message
    );
    assert!(out.record.response.is_none());
    assert!(!fell_back(&out));

    let seen = o.received();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!((seen[0].protocol.as_str(), seen[0].method.as_str()), ("h3", "POST"));
}

#[tokio::test]
async fn a_post_that_failed_over_http3_before_it_was_sent_is_sent_over_tcp() {
    init();
    // No QUIC listener: the handshake gets no answer, and nothing of the
    // request was sent over HTTP/3.
    let o = replay_guard::serve(server_tls(), false).await.unwrap();
    let out = run(&Engine::new(), &ctx("POST", &o.url("/echo"), hmac())).await;
    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 2, "{:?}", atts.iter().map(|a| (&a.reason, &a.failure)).collect::<Vec<_>>());

    let h3 = &atts[0];
    assert_eq!(h3.dispatch, DispatchState::NotDispatched);
    let f = h3.failure.as_ref().expect("the HTTP/3 attempt failed");
    assert_eq!(f.kind, FailureKind::QuicHandshakeTimeout);
    assert!(!f.message.contains("may have been received"), "{}", f.message);

    assert_eq!(atts[1].reason, AttemptReason::ProtocolFallback { from: "h3".into() });
    assert_eq!(status(&out), Some(200));
    assert!(fell_back(&out));

    let seen = o.received();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method, "POST");
    assert_ne!(seen[0].protocol, "h3");
    assert!(!per_send(&seen[0], PerSend::HmacNonce).is_empty());
}

#[test]
fn the_tcp_fallback_is_made_only_when_sending_again_is_safe() {
    let auto = HttpVersionPolicy::Http3WithFallback;
    // Nothing was sent over HTTP/3: any method falls back.
    for m in ["GET", "POST", "PATCH", "CONNECT"] {
        assert_eq!(tcp_fallback(auto, true, DispatchState::NotDispatched, m, false), H3Fallback::Tcp, "{m}");
    }
    // It may have been received (`unknown` counts as that): only an
    // idempotent method falls back.
    for d in [DispatchState::MayHaveBeenSent, DispatchState::Unknown] {
        for m in ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "get"] {
            assert_eq!(tcp_fallback(auto, true, d, m, false), H3Fallback::Tcp, "{d:?} {m}");
        }
        for m in ["POST", "PATCH", "CONNECT", "LOCK"] {
            assert_eq!(tcp_fallback(auto, true, d, m, false), H3Fallback::NotResent, "{d:?} {m}");
        }
    }
    // Forced HTTP/3, another policy, a response, or a canceled execution: no fallback.
    for policy in [HttpVersionPolicy::Http3Only, HttpVersionPolicy::Auto] {
        assert_eq!(tcp_fallback(policy, true, DispatchState::NotDispatched, "GET", false), H3Fallback::None, "{policy:?}");
    }
    assert_eq!(tcp_fallback(auto, false, DispatchState::Sent, "GET", false), H3Fallback::None);
    assert_eq!(tcp_fallback(auto, true, DispatchState::NotDispatched, "GET", true), H3Fallback::None);
}
