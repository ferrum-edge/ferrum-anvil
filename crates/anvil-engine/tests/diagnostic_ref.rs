//! G01 diagnostic references (Ferrum Edge v0.9.9 and later) through the
//! shared engine: a trusted gateway profile with a lookup configured, a
//! fixture standing in for the gateway's proxy listener and a fake admin
//! listener answering `GET /diagnostics/v1/refs/<ref>`. Only a record that
//! binds to the response is gateway evidence; the header alone never is, and
//! the lookup credential never leaves the lookup.

use anvil_diagnostics::gateway_detail::{GatewayDetail, LookupOutcome};
use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, EvidenceSource};
use anvil_domain::integration::{DiagnosticDetailAccess, IntegrationKind, IntegrationProfile};
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::tls::{HostBinding, TlsProfile};
use anvil_engine::context::MemorySecrets;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_transport::recorder::EventCtx;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const REF: &str = "fd1_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f";
/// Planted canary: it must reach only the admin listener's `Authorization` header.
const TOKEN: &str = "tok-SENSITIVE-g01-lookup-credential";

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

/// A fake admin listener answering every request with one response, and
/// keeping each request head it received.
struct Admin {
    url: String,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Admin {
    async fn start(status: u16, headers: Vec<(String, String)>, body: String) -> Admin {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let heads = Arc::new(Mutex::new(Vec::new()));
        let seen = heads.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut head = Vec::new();
                let mut chunk = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                seen.lock().unwrap().push(String::from_utf8_lossy(&head).into_owned());
                let mut answer = format!("HTTP/1.1 {status} Lookup\r\ncontent-length: {}\r\n", body.len());
                answer.push_str("content-type: application/json\r\n");
                for (n, v) in &headers {
                    answer.push_str(&format!("{n}: {v}\r\n"));
                }
                answer.push_str("connection: close\r\n\r\n");
                answer.push_str(&body);
                let _ = s.write_all(answer.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        Admin { url, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

/// A `ferrum.diagnostic_ref.v1` record of a `502 connection_failure` response
/// over HTTP/1.1, created now.
fn record(reference: &str, status: u16, namespace: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    serde_json::json!({
        "schema_version": "ferrum.diagnostic_ref.v1",
        "ref": reference,
        "namespace": namespace,
        "created_at": now,
        "expires_at": "2099-01-01T00:00:00Z",
        "protocol": "http1",
        "status": status,
        "gateway_error": "connection_failure",
        "detail_available": true,
        "detail": {
            "error_class": "connection_refused",
            "body_error_class": null,
            "rejection_phase": null,
            "route_timeout_phase": null,
            "backend_dispatch": "pre_wire_failure",
            "proxy_id": "orders",
            "backend_target": "http://127.0.0.1:19002",
            "duration_bucket": "lt_10ms",
            "attempts": [{"attempt": 1, "backend_dispatch": "pre_wire_failure", "error_class": "connection_refused"}]
        }
    })
    .to_string()
}

fn access(admin: &Admin, namespace: Option<&str>, secret: &SecretRef) -> DiagnosticDetailAccess {
    DiagnosticDetailAccess {
        base_url: admin.url.clone(),
        credential: SensitiveValue::Secret { secret: secret.clone() },
        namespace: namespace.map(String::from),
    }
}

/// A request to `url`, declaring `127.0.0.1` a trusted Ferrum v0.9.9 gateway
/// (plain HTTP, lab style) with `lookup`, and the lookup token in the vault.
fn ctx(url: &str, lookup: Option<DiagnosticDetailAccess>, secret: &SecretRef) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(RequestSpec::http("POST", url));
    c.integrations.push(IntegrationProfile {
        id: anvil_domain::Id::new(),
        workspace_id: anvil_domain::Id::new(),
        name: "lab gateway".into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: vec![HostBinding { host: "127.0.0.1".into(), port: None }],
            compatibility_id: "ferrum-edge-0.9.9".into(),
            require_verified_tls: false,
            detail: lookup,
            console_url: None,
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    let mut vault = std::collections::HashMap::new();
    vault.insert(secret.id, zeroize::Zeroizing::new(TOKEN.to_string()));
    c.secrets = Arc::new(MemorySecrets(vault));
    c
}

fn vault_ref() -> SecretRef {
    SecretRef { id: anvil_domain::Id::new(), label: "lab diagnostics token".into() }
}

/// The gateway fixture's `502 connection_failure`, carrying `reference`.
fn gateway_url(f: &fx::Fixture, reference: &str) -> String {
    f.url(&format!("/status/502?header=X-Gateway-Error:connection_failure&header=X-Ferrum-Diagnostic-Ref:{reference}"))
}

async fn run(engine: &Engine, ctx: &ExecutionContext) -> ExecutionOutput {
    engine.execute(ctx, EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<&str> {
    o.record.findings.iter().map(|f| f.code.as_str()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("missing {code}; have {:?}", codes(o)))
}

/// The public evidence keeps its own capped confidence, nothing else claims
/// more than likely, and no gateway-detail evidence exists without a bound record.
fn stays_public(o: &ExecutionOutput) {
    assert_eq!(finding(o, "ferrum.token.connection_failure").confidence, Confidence::Likely, "the public marker is kept");
    let raised: Vec<&str> = o
        .record
        .findings
        .iter()
        .filter(|f| f.code.starts_with("ferrum.") && f.code != "ferrum.detail.refused" && f.confidence > Confidence::Likely)
        .map(|f| f.code.as_str())
        .collect();
    assert!(raised.is_empty(), "raised above likely without a bound record: {raised:?}");
    assert!(!o.record.findings.iter().flat_map(|f| &f.evidence).any(|e| e.source == EvidenceSource::GatewayDetail), "{:?}", codes(o));
}

/// The lookup token appears nowhere in the record, and the gateway's proxy
/// listener never received it.
fn token_stays_in_the_lookup(o: &ExecutionOutput, gateway: &fx::Fixture) {
    let record = serde_json::to_string(&o.record).unwrap();
    assert!(!record.contains(TOKEN) && !record.contains("tok-SENSITIVE"), "the lookup token leaked into the record");
    let seen = serde_json::to_string(&gateway.log.entries()).unwrap();
    assert!(!seen.contains("tok-SENSITIVE"), "the lookup token was sent to the proxy listener");
}

#[tokio::test]
async fn g01_a_bound_record_is_confirmed_gateway_evidence() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let admin = Admin::start(200, vec![], record(REF, 502, "ferrum")).await;
    let secret = vault_ref();
    let e = Engine::new();
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&admin, Some("ferrum"), &secret)), &secret)).await;
    let d = finding(&o, "ferrum.detail.failure");
    assert_eq!(d.confidence, Confidence::Confirmed, "both legs are direct loopback connections");
    assert!(d.explanation.contains("connection_refused") && d.explanation.contains(REF), "{}", d.explanation);
    assert!(d.evidence.iter().any(|x| x.source == EvidenceSource::GatewayDetail && x.key == "detail.error_class"));
    // The public marker keeps its own ceiling for comparison.
    assert_eq!(finding(&o, "ferrum.token.connection_failure").confidence, Confidence::Likely);
    let heads = admin.heads();
    assert_eq!(heads.len(), 1, "one lookup");
    assert!(heads[0].starts_with(&format!("GET /diagnostics/v1/refs/{REF} HTTP/1.1\r\n")), "{}", heads[0].lines().next().unwrap_or(""));
    assert!(heads[0].to_ascii_lowercase().contains(&format!("authorization: bearer {}", TOKEN.to_ascii_lowercase())));
    token_stays_in_the_lookup(&o, &f);
}

/// TRUST-009: a valid credential for another namespace learns nothing (the
/// gateway's indistinguishable 404), a credential without the scope is
/// refused, and a record of another namespace is never used.
#[tokio::test]
async fn trust_009_cross_tenant_lookup_is_refused_and_stays_public() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();

    let other_tenant = Admin::start(404, vec![], r#"{"error":"Diagnostic reference not found"}"#.into()).await;
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&other_tenant, None, &secret)), &secret)).await;
    assert_eq!(finding(&o, "ferrum.detail.unavailable").confidence, Confidence::Unknown);
    stays_public(&o);
    token_stays_in_the_lookup(&o, &f);

    let no_scope = Admin::start(403, vec![], r#"{"error":"Diagnostic reference lookups require a scope"}"#.into()).await;
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&no_scope, None, &secret)), &secret)).await;
    let refused = finding(&o, "ferrum.detail.refused");
    assert!(refused.explanation.contains("diagnostics:read") && refused.explanation.contains("403"), "{}", refused.explanation);
    stays_public(&o);

    // The profile names tenant-a; a record of the ferrum namespace does not describe its gateway.
    let ferrum = Admin::start(200, vec![], record(REF, 502, "ferrum")).await;
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&ferrum, Some("tenant-a"), &secret)), &secret)).await;
    let m = finding(&o, "ferrum.detail.mismatch");
    assert_eq!(m.confidence, Confidence::ConflictingEvidence);
    assert!(m.explanation.contains("namespace"), "{}", m.explanation);
    stays_public(&o);
}

/// TRUST-010: an expired or evicted reference (the same 404) leaves the
/// detail unavailable, keeps the public evidence and fabricates no cause, also
/// when the recorded response is looked up again later.
#[tokio::test]
async fn trust_010_expired_reference_keeps_the_public_evidence() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();
    let expired = Admin::start(404, vec![], r#"{"error":"Diagnostic reference not found"}"#.into()).await;
    let lookup = access(&expired, Some("ferrum"), &secret);
    let c = ctx(&gateway_url(&f, REF), Some(lookup.clone()), &secret);
    let o = run(&e, &c).await;
    let u = finding(&o, "ferrum.detail.unavailable");
    assert!(u.alternatives.iter().any(|a| a.contains("expired or was evicted")), "{:?}", u.alternatives);
    assert!(u.does_not_prove.iter().any(|d| d.contains("forged")), "{:?}", u.does_not_prove);
    stays_public(&o);

    let response = o.record.response.as_ref().expect("the gateway answered");
    let attempt = o.record.attempts.last().expect("one attempt");
    let again = anvil_engine::gateway_detail::lookup_recorded(&e, &c, &lookup, response, attempt, &CancellationToken::new()).await;
    match again {
        GatewayDetail::Looked { reference, outcome: LookupOutcome::NotFound { owner_replica: None }, .. } => assert_eq!(reference, REF),
        other => panic!("{other:?}"),
    }
    assert_eq!(expired.heads().len(), 2);
}

/// TRUST-011: a reference a backend (or anything but the gateway) sets is
/// never trusted: never looked up for an untrusted destination, not looked up
/// when malformed, and never used when the record describes another response.
#[tokio::test]
async fn trust_011_spoofed_reference_is_never_trusted() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();
    let admin = Admin::start(200, vec![], record(REF, 502, "ferrum")).await;

    // An untrusted destination: no lookup, no detail finding.
    let untrusted = ExecutionContext::standalone(RequestSpec::http("POST", &gateway_url(&f, REF)));
    let o = run(&e, &untrusted).await;
    assert!(!codes(&o).iter().any(|c| c.starts_with("ferrum.detail.") || c.starts_with("ferrum.token.")), "{:?}", codes(&o));
    assert!(admin.heads().is_empty(), "an untrusted destination's reference is never looked up");

    // A malformed reference is reported, not looked up.
    let o = run(&e, &ctx(&gateway_url(&f, "fd1_FORGED"), Some(access(&admin, None, &secret)), &secret)).await;
    assert_eq!(finding(&o, "ferrum.detail.invalid_reference").confidence, Confidence::Unknown);
    assert!(admin.heads().is_empty(), "a malformed reference is never looked up");
    stays_public(&o);

    // A backend replays a real reference of another response: the record does not bind.
    let other_response = Admin::start(200, vec![], record(REF, 503, "ferrum")).await;
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&other_response, None, &secret)), &secret)).await;
    let m = finding(&o, "ferrum.detail.mismatch");
    assert!(m.explanation.contains("status"), "{}", m.explanation);
    stays_public(&o);

    // A record of another reference is never accepted for this one.
    let forged = "fd1_00000000000000000000000000000000";
    let other_ref = Admin::start(200, vec![], record(REF, 502, "ferrum")).await;
    let o = run(&e, &ctx(&gateway_url(&f, forged), Some(access(&other_ref, None, &secret)), &secret)).await;
    assert!(finding(&o, "ferrum.detail.mismatch").explanation.contains(forged));
    stays_public(&o);
    token_stays_in_the_lookup(&o, &f);
}

/// TRUST-011, continued: no lookup for a destination the lookup's profile does
/// not cover, none after a redirect to an untrusted origin, an admin listener
/// that redirects is asked exactly once and never followed, and a plain-HTTP
/// admin URL off loopback is refused before anything is sent.
#[tokio::test]
async fn trust_011_lookups_stay_on_the_configured_path() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();
    let admin = Admin::start(200, vec![], record(REF, 502, "ferrum")).await;

    // The profile with the lookup covers another host: this destination is untrusted.
    let mut other_host = ctx(&gateway_url(&f, REF), Some(access(&admin, None, &secret)), &secret);
    let IntegrationKind::FerrumGateway { hosts, .. } = &mut other_host.integrations[0].kind;
    *hosts = vec![HostBinding { host: "gateway.example".into(), port: None }];
    let o = run(&e, &other_host).await;
    assert!(!codes(&o).iter().any(|c| c.starts_with("ferrum.detail.")), "{:?}", codes(&o));
    assert!(admin.heads().is_empty(), "no lookup for a destination the profile does not cover");

    // The trusted gateway redirects to an untrusted origin whose 502 carries a reference.
    let untrusted = fx::serve("127.0.0.1:0", None).await.unwrap();
    let to: String = url::form_urlencoded::byte_serialize(gateway_url(&untrusted, REF).as_bytes()).collect();
    let mut redirected = ExecutionContext::standalone(RequestSpec::http("GET", &f.url(&format!("/redirect?to={to}"))));
    redirected.integrations = ctx(&f.url("/"), Some(access(&admin, None, &secret)), &secret).integrations;
    let IntegrationKind::FerrumGateway { hosts, .. } = &mut redirected.integrations[0].kind;
    *hosts = vec![HostBinding { host: "127.0.0.1".into(), port: Some(f.addr.port()) }];
    redirected.secrets = ctx(&f.url("/"), None, &secret).secrets;
    let o = run(&e, &redirected).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(502), "the redirect was followed");
    assert!(!codes(&o).iter().any(|c| c.starts_with("ferrum.detail.")), "{:?}", codes(&o));
    assert!(admin.heads().is_empty(), "no lookup for the untrusted origin that answered");

    // An admin listener answering 3xx: one request, never followed.
    let elsewhere = format!("{}/diagnostics/v1/refs/{REF}", admin.url);
    let redirecting = Admin::start(302, vec![("Location".into(), elsewhere)], String::new()).await;
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&redirecting, None, &secret)), &secret)).await;
    assert!(finding(&o, "ferrum.detail.lookup_failed").explanation.contains("302"));
    assert_eq!(redirecting.heads().len(), 1, "asked exactly once");
    assert!(admin.heads().is_empty(), "the redirect was not followed");
    stays_public(&o);

    // Plain HTTP to a host name (even localhost) is refused before sending.
    let named = Admin { url: admin.url.replace("127.0.0.1", "localhost"), heads: admin.heads.clone() };
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&named, None, &secret)), &secret)).await;
    let refused = finding(&o, "ferrum.detail.lookup_failed");
    assert!(refused.explanation.contains("refused before sending"), "{}", refused.explanation);
    assert!(admin.heads().is_empty(), "nothing was sent");
    stays_public(&o);
    token_stays_in_the_lookup(&o, &f);
}

/// An https lookup is always verified: the request's TLS profile bypasses
/// verification and trusts nothing extra, and the admin listener's
/// certificate chains to a root nobody trusts. The handshake fails, nothing of
/// the lookup reaches the listener, and the public evidence stays capped.
#[tokio::test]
async fn g01_an_https_lookup_never_inherits_a_verification_bypass() {
    init();
    let pki = anvil_fixtures::pki::LabPki::generate();
    let tls = anvil_fixtures::tlsserver::TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone());
    let admin = fx::serve("127.0.0.1:0", Some(tls)).await.unwrap();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();
    let lookup = DiagnosticDetailAccess {
        base_url: admin.url(""),
        credential: SensitiveValue::Secret { secret: secret.clone() },
        namespace: None,
    };
    assert!(lookup.base_url.starts_with("https://127.0.0.1:"), "{}", lookup.base_url);
    let mut c = ctx(&gateway_url(&f, REF), Some(lookup), &secret);
    let bypass = TlsProfile {
        id: anvil_domain::Id::new(),
        workspace_id: anvil_domain::Id::new(),
        name: "bypass".into(),
        verify: false,
        use_system_roots: true,
        extra_roots_pem: vec![],
        client_identity: None,
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let id = bypass.id;
    c.tls_profiles.push(bypass);
    c.settings_layers.push(("run".into(), SettingsOverrides { tls_profile_id: Some(id), ..Default::default() }));
    let o = run(&e, &c).await;
    let failed = finding(&o, "ferrum.detail.lookup_failed");
    assert!(failed.explanation.to_ascii_lowercase().contains("tls"), "{}", failed.explanation);
    assert_eq!(admin.log.count_requests(), 0, "no request headers reached the admin listener");
    stays_public(&o);
    token_stays_in_the_lookup(&o, &f);
}

/// A record whose detail is not recorded yet is asked for once more, then
/// reported as the gateway's authorship alone.
#[tokio::test]
async fn g01_a_record_without_detail_is_asked_for_once_more() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();
    let mut pending: serde_json::Value = serde_json::from_str(&record(REF, 502, "ferrum")).unwrap();
    pending["detail_available"] = false.into();
    pending["detail"] = serde_json::Value::Null;
    let admin = Admin::start(200, vec![], pending.to_string()).await;
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&admin, None, &secret)), &secret)).await;
    assert_eq!(admin.heads().len(), 2, "one retry");
    assert_eq!(finding(&o, "ferrum.detail.authored").confidence, Confidence::Confirmed);
}

/// Two profiles for one destination: the record names the one used and the one ignored.
#[tokio::test]
async fn g01_a_shadowed_gateway_profile_is_named() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();
    let mut c = ctx(&gateway_url(&f, REF), None, &secret);
    let mut imported = c.integrations[0].clone();
    imported.id = anvil_domain::Id::new();
    imported.name = "imported gateway".into();
    c.integrations.push(imported);
    let o = run(&e, &c).await;
    let note = o.record.prepared.inferred.iter().find(|n| n.contains("several Ferrum gateway profiles")).expect("a note");
    assert!(note.contains("'lab gateway' is used") && note.contains("'imported gateway' ignored"), "{note}");
}

/// References are off by default: a gateway-marked error without one is
/// noted, nothing is looked up, and the public evidence stays capped.
#[tokio::test]
async fn g01_references_off_keeps_the_public_evidence() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();
    let admin = Admin::start(200, vec![], record(REF, 502, "ferrum")).await;
    let url = f.url("/status/502?header=X-Gateway-Error:connection_failure");
    let o = run(&e, &ctx(&url, Some(access(&admin, None, &secret)), &secret)).await;
    assert_eq!(finding(&o, "ferrum.detail.no_reference").confidence, Confidence::Unknown);
    assert!(admin.heads().is_empty());
    stays_public(&o);
}

/// A rate-limited lookup and an owner-replica hint are reported, never used.
#[tokio::test]
async fn g01_rate_limits_and_other_replicas_stay_public() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = vault_ref();
    let limited = Admin::start(429, vec![("Retry-After".into(), "1".into())], r#"{"error":"rate limited"}"#.into()).await;
    let o = run(&e, &ctx(&gateway_url(&f, REF), Some(access(&limited, None, &secret)), &secret)).await;
    assert!(finding(&o, "ferrum.detail.lookup_failed").explanation.contains("429"));
    stays_public(&o);

    let tagged = "fd2_1a2b3c4d_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f";
    let hint = vec![("X-Ferrum-Diagnostic-Owner-Replica".to_string(), "1a2b3c4d".to_string())];
    let other_replica = Admin::start(404, hint, r#"{"error":"Diagnostic reference not found"}"#.into()).await;
    let o = run(&e, &ctx(&gateway_url(&f, tagged), Some(access(&other_replica, None, &secret)), &secret)).await;
    assert!(finding(&o, "ferrum.detail.unavailable").alternatives.iter().any(|a| a.contains("replica 1a2b3c4d")));
    stays_public(&o);
}
