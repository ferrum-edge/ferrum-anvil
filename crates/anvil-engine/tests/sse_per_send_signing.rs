//! Every send of an event stream is signed afresh: the initial send, the
//! TCP fallback after HTTP/3 and each reconnection carry a new HMAC nonce or
//! DPoP proof `jti`, never an earlier send's. The destination serves HTTP/3
//! and TCP on one port and answers a per-send value it has already received
//! with 401, as a gateway that checks for replays does. Over HTTP/3 it reads
//! each request and resets its stream without answering; over TCP its event
//! stream is cut after the first event, and a reconnection with
//! `Last-Event-ID` gets the second event and a clean end. A send signed with
//! an earlier send's values would get the 401 and no event. Real loopback
//! sockets, no mocks.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus, TransportState, WarningCode};
use anvil_domain::request::{Protocol, RequestSpec, SseSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::replay_guard::{self, Received};
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
            username: "sse-client".into(),
            secret: SensitiveValue::template("audit-only-hmac-secret-5t8e"),
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
            access_token: SensitiveValue::template("audit-only-dpop-token-3v6n"),
            private_key_pem: SensitiveValue::template(anvil_auth::dpop::generate_key_pem().unwrap()),
            dpop_scheme: true,
            handle_nonce_challenge: false,
        },
    }
}

/// An event stream from `url` with `auth`, reconnection on, over `version`,
/// trusting the lab CA.
fn ctx(url: &str, auth: AuthConfig, version: HttpVersionPolicy) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events: 0, idle_timeout_ms: 5_000, last_event_id: None, reconnect: true });
    // The context takes its auth layer from the spec when it is built.
    s.auth = auth;
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
            http_version: Some(version),
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(2_000)),
                tls_handshake_ms: Some(Some(2_000)),
                response_headers_ms: Some(Some(4_000)),
                total_ms: Some(Some(15_000)),
                ..Default::default()
            }),
            ..Default::default()
        },
    ));
    c
}

async fn run(c: &ExecutionContext) -> ExecutionOutput {
    Engine::new().execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn sse_status(o: &ExecutionOutput) -> (u16, u64, ClosedBy) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Sse { http_status, events, closed_by } => (*http_status, *events, *closed_by),
        other => panic!("{other:?}"),
    }
}

/// The per-send value of a request that the destination checks for replays.
#[derive(Clone, Copy)]
enum PerSend {
    /// The `nonce` of an HMAC `Authorization` header.
    HmacNonce,
    /// The `jti` of a `DPoP` proof.
    DpopJti,
}

impl PerSend {
    /// The auth fact the record keeps for the value.
    fn fact(self) -> &'static str {
        match self {
            PerSend::HmacNonce => "hmac.nonce",
            PerSend::DpopJti => "dpop.jti",
        }
    }
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

/// Every send the destination received: none a replay, each with a per-send
/// value of its own. The record's prepared request is the last send's.
fn assert_signed_per_send(o: &ExecutionOutput, seen: &[Received], kind: PerSend) {
    assert!(seen.iter().all(|r| r.method == "GET" && !r.replayed), "{seen:?}");
    let values: Vec<String> = seen.iter().map(|r| per_send(r, kind)).collect();
    assert!(values.iter().all(|v| !v.is_empty()), "{values:?}");
    let distinct: HashSet<&String> = values.iter().collect();
    assert_eq!(distinct.len(), values.len(), "a per-send value was sent twice: {values:?}");
    let last = format!("auth {}: {}", kind.fact(), values.last().unwrap());
    assert!(o.record.prepared.inferred.contains(&last), "{last} not in {:?}", o.record.prepared.inferred);
}

/// A stream cut after its first event is reconnected, signed again: the
/// destination accepts the reconnection only with a per-send value it has
/// not seen, and it still carries `Last-Event-ID`.
async fn reconnection_signed_again(auth: AuthConfig, kind: PerSend) {
    init();
    let o = replay_guard::serve(server_tls(), false).await.unwrap();
    let out = run(&ctx(&o.url("/sse"), auth, HttpVersionPolicy::Auto)).await;
    let seen = o.received();
    assert_eq!(sse_status(&out), (200, 2, ClosedBy::Peer), "the destination saw a per-send value again: {seen:?}");
    assert_eq!(out.record.outcome.transport, TransportState::Completed);

    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 2, "{:?}", atts.iter().map(|a| (&a.reason, &a.failure)).collect::<Vec<_>>());
    assert_eq!(atts[0].reason, AttemptReason::Initial);
    assert!(atts[0].failure.is_some(), "the cut stream failed the first attempt");
    assert!(matches!(atts[1].reason, AttemptReason::Retry { .. }), "{:?}", atts[1].reason);
    assert!(atts[1].failure.is_none(), "{:?}", atts[1].failure);

    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].last_event_id, "");
    assert_eq!(seen[1].last_event_id, "1", "the reconnection sends the last event id");
    assert_signed_per_send(&out, &seen, kind);
}

#[tokio::test]
async fn an_hmac_signed_event_stream_reconnects_with_a_new_nonce() {
    reconnection_signed_again(hmac(), PerSend::HmacNonce).await;
}

#[tokio::test]
async fn a_dpop_event_stream_reconnects_with_a_new_proof() {
    reconnection_signed_again(dpop(), PerSend::DpopJti).await;
}

/// An event stream whose HTTP/3 request reached the destination and got no
/// response falls back to TCP signed again, and its reconnection is signed
/// again too: three sends, three per-send values.
async fn fallback_signed_again(auth: AuthConfig, kind: PerSend) {
    init();
    let o = replay_guard::serve(server_tls(), true).await.unwrap();
    let out = run(&ctx(&o.url("/sse"), auth, HttpVersionPolicy::Http3WithFallback)).await;
    let seen = o.received();
    assert_eq!(sse_status(&out), (200, 2, ClosedBy::Peer), "the destination saw a per-send value again: {seen:?}");

    let atts = &out.record.attempts;
    assert_eq!(atts.len(), 3, "{:?}", atts.iter().map(|a| (&a.reason, &a.failure)).collect::<Vec<_>>());
    let h3 = &atts[0];
    assert_eq!(h3.connection.as_ref().and_then(|c| c.protocol.as_deref()), Some("h3"));
    assert!(h3.response_status.is_none());
    assert_eq!(h3.dispatch, DispatchState::MayHaveBeenSent);
    let tcp = &atts[1];
    assert_eq!(tcp.reason, AttemptReason::ProtocolFallback { from: "h3".into() });
    assert_ne!(tcp.connection.as_ref().and_then(|c| c.protocol.as_deref()), Some("h3"));
    assert_eq!(tcp.response_status, Some(200), "the fallback repeated the HTTP/3 attempt's per-send value: {seen:?}");
    assert!(matches!(atts[2].reason, AttemptReason::Retry { .. }), "{:?}", atts[2].reason);
    assert!(out.record.outcome.warnings.iter().any(|w| w.code == WarningCode::ProtocolFallback));

    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0].protocol, "h3");
    assert!(seen[1..].iter().all(|r| r.protocol != "h3"), "{seen:?}");
    assert_eq!(seen[1].last_event_id, "");
    assert_eq!(seen[2].last_event_id, "1");
    assert_signed_per_send(&out, &seen, kind);
}

#[tokio::test]
async fn an_hmac_signed_event_stream_falls_back_to_tcp_with_a_new_nonce() {
    fallback_signed_again(hmac(), PerSend::HmacNonce).await;
}

#[tokio::test]
async fn a_dpop_event_stream_falls_back_to_tcp_with_a_new_proof() {
    fallback_signed_again(dpop(), PerSend::DpopJti).await;
}
