//! G01 diagnostic references on the `core` profile (Ferrum Edge v0.9.9 and
//! later): the gateway runs with `FERRUM_DIAGNOSTIC_REFS=all` and a short
//! reference retention, and the harness signs lookup tokens with the
//! instance's primary admin key (role `viewer`, the `diagnostics:read` scope
//! and an `ns` claim; the variants leave one out or name another namespace).
//! The trusted profile's lookup holds the token as a vault secret, like any
//! profile credential.
//!
//! Only a lookup record that binds to the response may raise a Ferrum finding
//! above `likely` (both legs here are direct loopback connections); refused,
//! unknown, expired and spoofed references keep the public evidence's
//! confidence. Earlier releases have no references: these scenarios are
//! skipped there.

use crate::core::{self, Env};
use crate::harness::{Def, Outcome};
use crate::scenario::{CheckKind, Checks};
use anvil_diagnostics::gateway_detail::{GatewayDetail, LookupOutcome, parse_ref};
use anvil_diagnostics::{DiagnosticInput, FerrumTrust};
use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, EvidenceSource, SourceScope};
use anvil_domain::integration::{DiagnosticDetailAccess, IntegrationKind};
use anvil_domain::request::Protocol;
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_engine::context::MemorySecrets;
use anvil_engine::{ExecutionContext, ExecutionOutput};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// The core instance's admin listener.
pub const ADMIN: &str = "http://127.0.0.1:18090";
/// Reference retention on the core instance (`FERRUM_DIAGNOSTIC_REF_TTL_SECONDS`):
/// long enough for the lookup Anvil makes as the response arrives, short
/// enough for TRUST-010 to outlive it.
pub const REF_TTL_SECS: u64 = 5;
/// The release that introduced diagnostic references.
pub const FIRST_RELEASE: &str = "v0.9.9";

/// Gateway environment for the core instance: references on, a short
/// retention, and the admin key the harness signs lookup tokens with.
pub fn gateway_env(admin_secret: &str) -> Vec<(&'static str, String)> {
    vec![
        ("FERRUM_ADMIN_JWT_SECRET", admin_secret.to_string()),
        ("FERRUM_DIAGNOSTIC_REFS", "all".into()),
        ("FERRUM_DIAGNOSTIC_REF_TTL_SECONDS", REF_TTL_SECS.to_string()),
    ]
}

/// A lookup token signed with the instance's primary admin key: role
/// `viewer` (the lookup needs no more), with the given `scope` and `ns`
/// claims (`None` leaves the claim out).
fn token(env: &Env, sub: &str, scope: Option<&str>, ns: Option<&str>) -> String {
    let secret = env.admin_secret.as_deref().expect("references run on v0.9.9 and later only");
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "iss": "ferrum-edge",
        "sub": sub,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": crate::gateway::random_secret(),
        "role": "viewer",
    });
    if let Some(s) = scope {
        claims["scope"] = s.into();
    }
    if let Some(n) = ns {
        claims["ns"] = n.into();
    }
    let key = jsonwebtoken::EncodingKey::from_secret(secret.as_bytes());
    jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256), &claims, &key).expect("HS256 lab token")
}

/// The least-privilege token the lookup is meant to use.
fn good_token(env: &Env, sub: &str) -> String {
    token(env, sub, Some("diagnostics:read"), Some("ferrum"))
}

/// [`core::ctx`] with the trusted profile's diagnostic reference lookup, the
/// token held in the vault. Untrusted: the plain context (no profile, no lookup).
fn lookup_ctx(env: &Env, method: &str, path: &str, token: String) -> ExecutionContext {
    let mut c = core::ctx(env, method, path);
    let Some(profile) = c.integrations.first_mut() else { return c };
    let secret = SecretRef { id: anvil_domain::Id::new(), label: "lab diagnostics token".into() };
    let IntegrationKind::FerrumGateway { detail, .. } = &mut profile.kind;
    *detail = Some(DiagnosticDetailAccess {
        base_url: ADMIN.into(),
        credential: SensitiveValue::Secret { secret: secret.clone() },
        namespace: Some("ferrum".into()),
    });
    let mut vault = std::collections::HashMap::new();
    vault.insert(secret.id, Zeroizing::new(token));
    c.secrets = Arc::new(MemorySecrets(vault));
    c
}

/// A fresh one-second window of the gateway's lookup rate limit.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(1100)).await;
}

fn response_ref(o: &ExecutionOutput) -> Option<String> {
    o.record.response.as_ref().and_then(|r| r.header_values("x-ferrum-diagnostic-ref").first().map(|v| v.to_string()))
}

fn find<'a>(o: &'a ExecutionOutput, code: &str) -> Option<&'a DiagnosticFinding> {
    o.record.findings.iter().find(|f| f.code == code)
}

fn evidence(f: Option<&DiagnosticFinding>, key: &str) -> Option<String> {
    f.and_then(|f| f.evidence.iter().find(|e| e.key == key)).map(|e| e.value.clone())
}

fn gateway_detail_evidence(findings: &[DiagnosticFinding]) -> bool {
    findings.iter().flat_map(|f| &f.evidence).any(|e| e.source == EvidenceSource::GatewayDetail)
}

/// Whether a finding cites a field of a gateway record.
fn cites_record(f: &DiagnosticFinding) -> bool {
    f.evidence.iter().any(|e| e.key.starts_with("detail.") && e.key != "detail.lookup.status")
}

fn minted(c: &mut Checks, o: &ExecutionOutput) {
    let r = response_ref(o);
    let ok = r.as_deref().is_some_and(|r| parse_ref(r).is_some());
    c.add(CheckKind::GroundTruth, "the gateway minted a diagnostic reference", ok, format!("{r:?}"));
}

fn confirmed(c: &mut Checks, o: &ExecutionOutput, code: &str) {
    c.has(o, code);
    let got = find(o, code).map(|f| f.confidence);
    c.add(CheckKind::Diagnosis, format!("{code} is confirmed"), got == Some(Confidence::Confirmed), format!("{got:?}"));
}

/// Nothing raised above likely, and no gateway-detail evidence, without a bound record.
fn stays_public(c: &mut Checks, findings: &[DiagnosticFinding]) {
    let raised: Vec<String> = findings
        .iter()
        .filter(|f| f.code.starts_with("ferrum.") && f.code != "ferrum.detail.refused" && f.confidence > Confidence::Likely)
        .map(|f| f.code.clone())
        .collect();
    c.add(CheckKind::Diagnosis, "no Ferrum finding above likely without a bound record", raised.is_empty(), format!("{raised:?}"));
    c.add(CheckKind::Diagnosis, "no gateway-detail evidence without a bound record", !gateway_detail_evidence(findings), "");
}

fn no_token_in_record(c: &mut Checks, o: &ExecutionOutput, token: &str) {
    let record = serde_json::to_string(&o.record).unwrap_or_default();
    c.add(CheckKind::Diagnosis, "the lookup token appears nowhere in the record", !record.contains(token), "");
}

type Scenario<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

/// G01-001: a backend connect refusal resolves to the gateway's own record,
/// whose error class matches the operator log; the public token stays capped.
fn g01_001(env: &Env) -> Scenario<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        settle().await;
        let from = env.gateway.log_lines().len();
        let t = good_token(env, "anvil-lab-g01");
        let o = core::send(env, &lookup_ctx(env, "GET", "/up/refused/", t.clone())).await;
        c.status_in(&o, &[502, 503]);
        minted(&mut c, &o);
        let log = core::op_log_class(env, from, "up002-refused", &["connection_refused"]).await;
        c.operator_class(&log, "up002-refused", &["connection_refused"]);
        if env.trusted {
            confirmed(&mut c, &o, "ferrum.detail.failure");
            c.scope(&o, "ferrum.detail.failure", SourceScope::GatewayToUpstream);
            let class = evidence(find(&o, "ferrum.detail.failure"), "detail.error_class");
            let truth = log.iter().any(|l| class.as_deref().is_some_and(|k| l.contains(&format!("\"error_class\":\"{k}\""))));
            c.add(CheckKind::GroundTruth, "the record's error class is the operator log's", truth, format!("{class:?}"));
            c.max_confidence(&o, "ferrum.token.connection_failure", Confidence::Likely);
        } else {
            c.absent_prefix(&o, "ferrum.detail");
        }
        no_token_in_record(&mut c, &o, &t);
        let r = core::send(env, &core::ctx(env, "GET", "/ok/")).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: log }
    })
}

/// G01-002: in `all` mode a route miss resolves to a routing rejection, while
/// the application's own 404 through a route carries no reference at all.
fn g01_002(env: &Env) -> Scenario<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        settle().await;
        let o = core::send(env, &lookup_ctx(env, "GET", "/gw/no-such-route", good_token(env, "anvil-lab-g01-routing"))).await;
        c.status_in(&o, &[404]);
        minted(&mut c, &o);
        let look = core::send(env, &lookup_ctx(env, "GET", "/ok/status/404", good_token(env, "anvil-lab-g01-routing"))).await;
        c.add(CheckKind::GroundTruth, "the application's own 404 carries no reference", response_ref(&look).is_none(), "");
        c.absent_prefix(&look, "ferrum.detail");
        if env.trusted {
            confirmed(&mut c, &o, "ferrum.detail.rejected");
            c.scope(&o, "ferrum.detail.rejected", SourceScope::GatewayAdmission);
            let rejection = evidence(find(&o, "ferrum.detail.rejected"), "detail.rejection");
            let routing = rejection.as_deref() == Some("routing route_not_found");
            c.add(CheckKind::Diagnosis, "the record names the routing rejection", routing, format!("{rejection:?}"));
        } else {
            c.absent_prefix(&o, "ferrum.detail");
        }
        Outcome { main: Some(o), recovery: Some(look), checks: c, operator_log: vec![] }
    })
}

/// TRUST-009: a valid token for another namespace gets the indistinguishable
/// 404, and tokens without the scope or without an `ns` claim are refused;
/// none of them yields gateway detail. The scoped token for this namespace
/// is the positive control.
fn trust_009(env: &Env) -> Scenario<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        settle().await;
        let other_tenant = token(env, "anvil-lab-tenant-b", Some("diagnostics:read"), Some("tenant-b"));
        let o = core::send(env, &lookup_ctx(env, "GET", "/up/refused/", other_tenant)).await;
        minted(&mut c, &o);
        let no_scope = token(env, "anvil-lab-no-scope", None, Some("ferrum"));
        let no_scope = core::send(env, &lookup_ctx(env, "GET", "/up/refused/", no_scope)).await;
        let no_ns = token(env, "anvil-lab-no-ns", Some("diagnostics:read"), None);
        let no_ns = core::send(env, &lookup_ctx(env, "GET", "/up/refused/", no_ns)).await;
        let r = core::send(env, &lookup_ctx(env, "GET", "/up/refused/", good_token(env, "anvil-lab-tenant-a"))).await;
        if env.trusted {
            c.has(&o, "ferrum.detail.unavailable");
            let leaked = find(&o, "ferrum.detail.unavailable").is_some_and(cites_record);
            c.add(CheckKind::Diagnosis, "another namespace's token learns nothing about the reference", !leaked, "");
            c.has(&no_scope, "ferrum.detail.refused");
            c.has(&no_ns, "ferrum.detail.refused");
            for x in [&o, &no_scope, &no_ns] {
                stays_public(&mut c, &x.record.findings);
            }
            confirmed(&mut c, &r, "ferrum.detail.failure");
        } else {
            for x in [&o, &no_scope, &no_ns, &r] {
                c.absent_prefix(x, "ferrum.detail");
            }
        }
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

/// Diagnose a recorded execution again with another lookup outcome.
fn rediagnose(o: &ExecutionOutput, detail: &GatewayDetail) -> Vec<DiagnosticFinding> {
    let trust = FerrumTrust::Trusted {
        profile_name: "lab core gateway".into(),
        compatibility_id: crate::gateway::compatibility_id(),
        channel_authenticated: false,
    };
    anvil_diagnostics::diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: &o.record.prepared.method,
        preparation_failure: None,
        attempts: &o.record.attempts,
        response: o.record.response.as_ref(),
        body: o.decoded_body.as_deref().unwrap_or(&o.body),
        stream: None,
        protocol_status: &o.record.outcome.protocol_status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
        workload: None,
        gateway_detail: Some(detail),
        redact: None,
    })
    .findings
}

/// TRUST-010: the reference resolves while it is retained; once its
/// retention has passed, the same lookup is the gateway's 404, the detail is
/// unavailable, and the public evidence is all that remains.
fn trust_010(env: &Env) -> Scenario<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        settle().await;
        let x = lookup_ctx(env, "GET", "/up/refused/", good_token(env, "anvil-lab-retention"));
        let o = core::send(env, &x).await;
        minted(&mut c, &o);
        if !env.trusted {
            c.absent_prefix(&o, "ferrum.detail");
            return Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] };
        }
        confirmed(&mut c, &o, "ferrum.detail.failure");
        tokio::time::sleep(Duration::from_secs(REF_TTL_SECS + 2)).await;
        let IntegrationKind::FerrumGateway { detail: Some(access), .. } = &x.integrations[0].kind else {
            unreachable!("lookup_ctx configures the lookup")
        };
        let (Some(response), Some(sent)) = (o.record.response.as_ref(), o.record.attempts.last()) else {
            c.add(CheckKind::GroundTruth, "the gateway answered", false, "");
            return Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] };
        };
        let cancel = CancellationToken::new();
        let later = anvil_engine::gateway_detail::lookup_recorded(&env.engine, &x, access, response, sent, &cancel).await;
        let expired = matches!(&later, GatewayDetail::Looked { outcome: LookupOutcome::NotFound { .. }, .. });
        c.add(CheckKind::GroundTruth, "after its retention the gateway no longer resolves the reference", expired, format!("{later:?}"));
        let findings = rediagnose(&o, &later);
        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        let unavailable = codes.contains(&"ferrum.detail.unavailable");
        c.add(CheckKind::Diagnosis, "the detail is reported unavailable", unavailable, format!("{codes:?}"));
        let token = findings.iter().find(|f| f.code == "ferrum.token.connection_failure").map(|f| f.confidence);
        c.add(CheckKind::Diagnosis, "the public token finding is kept, capped", token == Some(Confidence::Likely), format!("{token:?}"));
        stays_public(&mut c, &findings);
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

/// TRUST-011: the backend sets its own `X-Ferrum-Diagnostic-Ref` on a 500.
/// The gateway strips it: the client never sees the forged value, and no
/// finding cites it.
fn trust_011(env: &Env) -> Scenario<'_> {
    Box::pin(async move {
        const FORGED: &str = "fd1_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";
        let mut c = Checks::new();
        settle().await;
        let before = env.fixtures.ok.log.count_requests();
        let path = format!("/ok/status/500?header=X-Ferrum-Diagnostic-Ref:{FORGED}");
        let o = core::send(env, &lookup_ctx(env, "GET", &path, good_token(env, "anvil-lab-spoof"))).await;
        c.status_in(&o, &[500]);
        c.add(CheckKind::GroundTruth, "the backend produced the 500", env.fixtures.ok.log.count_requests() > before, "");
        let seen = response_ref(&o);
        let stripped = seen.as_deref() != Some(FORGED);
        c.add(CheckKind::GroundTruth, "the client never sees the backend's reference", stripped, format!("{seen:?}"));
        let cited = serde_json::to_string(&o.record.findings).unwrap_or_default().contains(FORGED);
        c.add(CheckKind::Diagnosis, "no finding cites the backend's reference", !cited, "");
        if env.trusted {
            // A reference the gateway minted itself may resolve; nothing else may raise confidence.
            if seen.is_none() {
                stays_public(&mut c, &o.record.findings);
            }
        } else {
            c.absent_prefix(&o, "ferrum.detail");
        }
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

/// The G01 scenarios (Ferrum Edge v0.9.9 and later).
pub fn all() -> Vec<Def<Env>> {
    vec![
        Def { id: "G01-001", title: "Diagnostic reference resolves to the gateway's own record", run: g01_001 },
        Def { id: "G01-002", title: "Route miss confirmed by its record; application 404 has none", run: g01_002 },
        Def { id: "TRUST-009", title: "Cross-tenant and under-scoped diagnostic lookups", run: trust_009 },
        Def { id: "TRUST-010", title: "Diagnostic reference after its retention", run: trust_010 },
        Def { id: "TRUST-011", title: "Backend-forged diagnostic reference", run: trust_011 },
    ]
}

/// Why the G01 scenarios do not run on the release under test.
pub fn skip_reason() -> Option<String> {
    (!crate::gateway::release_at_least(FIRST_RELEASE))
        .then(|| crate::gateway::release_text("{release} has no diagnostic references (added in Ferrum Edge v0.9.9)"))
}
