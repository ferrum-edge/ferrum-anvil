//! A request that fails before any response on a reused pooled QUIC
//! connection is sent once more on a new connection when that is safe,
//! signed again: a new HMAC nonce, a new DPoP proof `jti`. The destination
//! (`anvil_fixtures::replay_guard`) answers a per-send value it has already
//! received with 401, as a gateway that checks for replays does, and leaves
//! the request that reuses its first QUIC connection unanswered: it rejects
//! it unprocessed (`H3_REQUEST_REJECTED`), which allows a resend whatever the
//! method, or closes the connection under it, which allows one only for an
//! idempotent method. The resend is not a retry: it happens with retries set
//! to 0 and has its own reason. Forced HTTP/3, so no TCP fallback follows.
//! Real loopback sockets, no mocks.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile};
use anvil_domain::execution::*;
use anvil_domain::request::{Body, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, RetryPolicy, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::replay_guard::{self, H3Script, Received, ReplayFixture, Unanswered};
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

async fn origin(script: H3Script) -> ReplayFixture {
    let tls = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    replay_guard::serve_h3(tls, script).await.unwrap()
}

fn hmac() -> AuthConfig {
    AuthConfig::Hmac {
        config: HmacConfig {
            profile: HmacProfile::FerrumV2,
            username: "h3-resend-client".into(),
            secret: SensitiveValue::template("audit-only-hmac-secret-2v8p"),
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
            access_token: SensitiveValue::template("audit-only-dpop-token-5h1c"),
            private_key_pem: SensitiveValue::template(anvil_auth::dpop::generate_key_pem().unwrap()),
            dpop_scheme: true,
            handle_nonce_challenge: false,
        },
    }
}

/// A `method` of `url` with `auth` (and a body unless a GET), over forced
/// HTTP/3, trusting the lab CA, and retries set to 0.
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
            http_version: Some(HttpVersionPolicy::Http3Only),
            retries: Some(RetryPolicy { max_retries: 0, backoff_ms: 0, only_safe: true }),
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

fn reused(a: &AttemptObservation) -> bool {
    a.connection.as_ref().expect("no connection").reused
}

fn protocol(a: &AttemptObservation) -> Option<&str> {
    a.connection.as_ref().and_then(|c| c.protocol.as_deref())
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

/// Every request the destination received was `method`s over HTTP/3, none
/// a replay, each with its own per-send value.
fn all_signed_apart(o: &ReplayFixture, methods: &[&str], kind: PerSend) {
    let seen = o.received();
    assert_eq!(seen.iter().map(|r| r.method.as_str()).collect::<Vec<_>>(), methods, "{seen:?}");
    assert!(seen.iter().all(|r| r.protocol == "h3" && !r.replayed), "{seen:?}");
    let values: Vec<String> = seen.iter().map(|r| per_send(r, kind)).collect();
    assert!(values.iter().all(|v| !v.is_empty()), "{values:?}");
    let distinct: HashSet<&String> = values.iter().collect();
    assert_eq!(distinct.len(), values.len(), "a per-send value was sent twice: {values:?}");
}

/// The first request leaves its QUIC connection pooled; `method`, the second,
/// goes out on it and is left unanswered as `script` says. The engine signs
/// it again and sends it once more on a new connection, which the
/// destination accepts only with a per-send value it has not seen.
async fn resent_signed_again(script: H3Script, method: &str, auth: AuthConfig, kind: PerSend) -> ExecutionOutput {
    init();
    let o = origin(script).await;
    let e = Engine::new();
    let first = run(&e, &ctx("GET", &o.url("/echo"), auth.clone())).await;
    assert_eq!(status(&first), Some(200), "{:?}", first.record.attempts.last().and_then(|a| a.failure.as_ref()));

    let out = run(&e, &ctx(method, &o.url("/echo"), auth)).await;
    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 2, "{:?}", atts.iter().map(|a| (&a.reason, &a.failure)).collect::<Vec<_>>());
    let unanswered = &atts[0];
    assert_eq!(protocol(unanswered), Some("h3"));
    assert!(reused(unanswered));
    assert!(unanswered.response_status.is_none());
    let f = unanswered.failure.as_ref().expect("the reused connection failed the request");
    assert!(f.message.contains("sent once more on a new connection as attempt 1, with its auth applied again"), "{}", f.message);

    let again = &atts[1];
    assert_eq!(again.reason, AttemptReason::ReusedConnectionClosed { after: f.kind }, "not recorded as a retry");
    assert_eq!(protocol(again), Some("h3"));
    assert!(!reused(again), "sent again on the reused connection");
    assert_eq!(status(&out), Some(200), "the destination saw the per-send value again: {:?}", o.received());
    assert_eq!(o.quic_connections(), 2);
    all_signed_apart(&o, &["GET", method, method], kind);
    out
}

#[tokio::test]
async fn an_hmac_signed_get_is_resent_with_a_new_nonce_after_its_pooled_quic_connection_closed() {
    let script = H3Script::SecondOnReuse(Unanswered::ConnectionClosed);
    let out = resent_signed_again(script, "GET", hmac(), PerSend::HmacNonce).await;
    let first = &out.record.attempts[0];
    assert_eq!(first.dispatch, DispatchState::MayHaveBeenSent);
    let f = first.failure.as_ref().unwrap();
    assert!(f.message.contains("was found closed before any response; the GET request may have been received"), "{}", f.message);
}

#[tokio::test]
async fn an_hmac_signed_post_the_server_rejected_is_resent_with_a_new_nonce() {
    let script = H3Script::SecondOnReuse(Unanswered::Rejected);
    let out = resent_signed_again(script, "POST", hmac(), PerSend::HmacNonce).await;
    let first = &out.record.attempts[0];
    assert_eq!(first.dispatch, DispatchState::NotDispatched, "the server said it did not process the POST");
    let f = first.failure.as_ref().unwrap();
    assert!(f.message.contains("rejected the POST request unprocessed (H3_REQUEST_REJECTED)"), "{}", f.message);
}

#[tokio::test]
async fn a_dpop_post_the_server_rejected_is_resent_with_a_new_proof() {
    let script = H3Script::SecondOnReuse(Unanswered::Rejected);
    resent_signed_again(script, "POST", dpop(), PerSend::DpopJti).await;
}

#[tokio::test]
async fn a_written_post_on_a_pooled_quic_connection_closed_under_it_is_not_sent_again() {
    init();
    let o = origin(H3Script::SecondOnReuse(Unanswered::ConnectionClosed)).await;
    let e = Engine::new();
    let first = run(&e, &ctx("GET", &o.url("/echo"), hmac())).await;
    assert_eq!(status(&first), Some(200), "{:?}", first.record.attempts.last().and_then(|a| a.failure.as_ref()));

    let out = run(&e, &ctx("POST", &o.url("/echo"), hmac())).await;
    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 1, "the POST was sent again: {:?}", atts.iter().map(|a| &a.reason).collect::<Vec<_>>());
    let a = &atts[0];
    assert!(reused(a));
    assert_eq!(a.dispatch, DispatchState::MayHaveBeenSent);
    let f = a.failure.as_ref().expect("the closed connection failed the POST");
    assert!(f.message.contains("not sent again: the POST request was written and is not idempotent"), "{}", f.message);
    assert!(out.record.response.is_none());
    assert_eq!(o.quic_connections(), 1, "no new connection was opened");
    assert_eq!(o.received().iter().map(|r| r.method.as_str()).collect::<Vec<_>>(), ["GET", "POST"]);
}
