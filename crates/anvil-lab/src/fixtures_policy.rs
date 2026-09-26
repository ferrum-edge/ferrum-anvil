//! Fixture sets and request helpers for the `policy`, `admission` and `drain`
//! profiles (ports: docs/audit/gateway-lab-config.md §3 — policy 192xx,
//! admission 195xx, drain 196xx). Every fixture keeps its own ground-truth
//! log; none of it is ever given to the diagnostic engine.

use crate::gateway::Gateway;
use crate::harness::RunCtx;
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::tls::HostBinding;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http::{self, Fixture};
use anvil_fixtures::policy::{self, AiProviderMock, OpaMock};
use anvil_fixtures::raw::{self, RawFixture, RawMode};
use anvil_transport::recorder::EventCtx;
use anyhow::Result;
use tokio_util::sync::CancellationToken;

/// Policy profile fixtures. 19207 (backend) and 19209 (OPA) stay unbound on
/// purpose: they are refused-connection stimuli.
pub struct PolicyFixtures {
    /// 19201: echo / `/status/{code}` backend behind most policy routes.
    pub echo: Fixture,
    /// 19202: OPA decision API mock.
    pub opa: OpaMock,
    /// 19203: accepts, reads the OPA query, never answers.
    pub opa_stall: RawFixture,
    /// 19204: OpenAI-style provider mock.
    pub ai: AiProviderMock,
    /// 19205: slow backend (`/delay-headers/{ms}`).
    pub slow: Fixture,
    /// 19206: returns `{}` via `/status/200?body={}` (transformer ceiling origin).
    pub json_empty: Fixture,
    /// 19208: backend that forges gateway-owned headers via `/status/200?header=…`.
    pub forged: Fixture,
    /// 19210: circuit-breaker target (`/status/{code}`).
    pub breaker: Fixture,
}

impl PolicyFixtures {
    pub async fn start() -> Result<Self> {
        Ok(PolicyFixtures {
            echo: http::serve("127.0.0.1:19201", None).await?,
            opa: policy::serve_opa("127.0.0.1:19202").await?,
            opa_stall: raw::serve("127.0.0.1:19203", RawMode::ReadThenStall, None).await?,
            ai: policy::serve_ai_provider("127.0.0.1:19204").await?,
            slow: http::serve("127.0.0.1:19205", None).await?,
            json_empty: http::serve("127.0.0.1:19206", None).await?,
            forged: http::serve("127.0.0.1:19208", None).await?,
            breaker: http::serve("127.0.0.1:19210", None).await?,
        })
    }
}

/// Admission profile fixtures.
pub struct AdmissionFixtures {
    /// 19501: sized responder (`/bytes/{n}` with Content-Length, `/status/{code}`).
    pub sized: Fixture,
    /// 19502: staller (`/delay-headers/{ms}`) that holds the only request slot.
    pub staller: Fixture,
}

impl AdmissionFixtures {
    pub async fn start() -> Result<Self> {
        Ok(AdmissionFixtures { sized: http::serve("127.0.0.1:19501", None).await?, staller: http::serve("127.0.0.1:19502", None).await? })
    }
}

/// Drain profile fixtures.
pub struct DrainFixtures {
    /// 19601: fast echo.
    pub fast: Fixture,
    /// 19602: slow backend (`/delay-headers/{ms}`), finishes inside the drain window.
    pub slow: Fixture,
}

impl DrainFixtures {
    pub async fn start() -> Result<Self> {
        Ok(DrainFixtures { fast: http::serve("127.0.0.1:19601", None).await?, slow: http::serve("127.0.0.1:19602", None).await? })
    }
}

/// A gateway listener the scenarios address.
#[derive(Clone, Copy)]
pub struct Target {
    pub base: &'static str,
    pub port: u16,
    pub profile_name: &'static str,
    pub isolation: &'static str,
}

/// Build a request to `target`. With `trusted`, the destination is declared as
/// a trusted Ferrum profile over plain HTTP (marker claims cap at `likely`).
pub fn request(t: &Target, trusted: bool, method: &str, path: &str) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(RequestSpec::http(method, &format!("{}{path}", t.base)));
    c.isolation = t.isolation.into();
    if trusted {
        c.integrations.push(IntegrationProfile {
            id: anvil_domain::Id::new(),
            workspace_id: anvil_domain::Id::new(),
            name: t.profile_name.into(),
            kind: IntegrationKind::FerrumGateway {
                hosts: vec![HostBinding { host: "127.0.0.1".into(), port: Some(t.port) }],
                compatibility_id: crate::gateway::compatibility_id(),
                require_verified_tls: false,
                detail: None,
                console_url: None,
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
    }
    c
}

pub fn with_header(mut c: ExecutionContext, name: &str, value: &str) -> ExecutionContext {
    c.spec.headers.push(KeyValue::new(name, value));
    c
}

pub async fn send(engine: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    engine.execute(c, EventCtx::none(), CancellationToken::new()).await
}

/// New gateway operator-log lines since line `from` for `proxy_id`
/// (operator ground truth; never given to the engine).
fn op_lines(gw: &Gateway, from: usize, proxy_id: &str) -> Vec<String> {
    gw.log_lines().into_iter().skip(from).filter(|l| l.contains(&format!("\"proxy_id\":\"{proxy_id}\""))).take(10).collect()
}

pub async fn op_log(gw: &Gateway, from: usize, proxy_id: &str) -> Vec<String> {
    wait_for_op_log(|| op_lines(gw, from, proxy_id)).await
}

pub(crate) async fn wait_for_op_log(mut read_lines: impl FnMut() -> Vec<String>) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let lines = read_lines();
        if !lines.is_empty() || tokio::time::Instant::now() >= deadline {
            return lines;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod op_log_tests {
    use super::wait_for_op_log;

    #[tokio::test]
    async fn waits_until_a_transaction_line_appears() {
        let mut reads = 0;
        let lines = wait_for_op_log(|| {
            reads += 1;
            if reads == 2 {
                vec!["transaction".to_owned()]
            } else {
                vec![]
            }
        })
        .await;

        assert_eq!(reads, 2);
        assert_eq!(lines, vec!["transaction".to_owned()]);
    }
}

/// Explicit skip records for scenarios a profile cannot drive live (filtered
/// by `--scenario`). A skip is reported separately and never counts as a pass.
pub fn skips(ctx: &RunCtx, only: &[String], list: &[(&str, &str, &str)]) -> Vec<ScenarioResult> {
    list.iter()
        .filter(|(id, _, _)| only.is_empty() || only.iter().any(|s| s.eq_ignore_ascii_case(id)))
        .map(|(id, title, why)| {
            let why = crate::gateway::release_text(why);
            eprintln!("{id:22} skipped {title} — {why}");
            ctx.skipped(id, title, &why)
        })
        .collect()
}

/// URL-encode a query value.
pub fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ---- evidence helpers (public evidence = what the engine concluded; ground
// truth = fixture logs and the gateway operator log) -------------------------

pub fn header(o: &ExecutionOutput, name: &str) -> Vec<String> {
    o.record.response.as_ref().map(|r| r.header_values(name).iter().map(|s| s.to_string()).collect()).unwrap_or_default()
}

pub fn body_text(o: &ExecutionOutput) -> String {
    String::from_utf8_lossy(o.decoded_body.as_ref().unwrap_or(&o.body)).into_owned()
}

pub fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

/// The catalog outcome id a `ferrum.outcome` finding matched, if any.
pub fn catalog_outcome(o: &ExecutionOutput) -> Option<String> {
    o.record
        .findings
        .iter()
        .filter(|f| f.code == "ferrum.outcome")
        .flat_map(|f| f.evidence.iter())
        .find(|e| e.key == "catalog.outcome")
        .map(|e| e.value.clone())
}

/// Every catalog outcome id Anvil considered consistent with the response:
/// the single `ferrum.outcome` match or the `ferrum.outcome_ambiguous`
/// candidate list.
pub fn catalog_ids(o: &ExecutionOutput) -> Vec<String> {
    o.record
        .findings
        .iter()
        .filter(|f| f.code == "ferrum.outcome" || f.code == "ferrum.outcome_ambiguous")
        .flat_map(|f| f.evidence.iter())
        .filter(|e| e.key == "catalog.outcome" || e.key == "catalog.candidates")
        .flat_map(|e| e.value.split(", ").map(String::from).collect::<Vec<_>>())
        .collect()
}

/// No finding at or above `min` whose code or title mentions `term`
/// (forbidden claims such as "waf", "cpu", "rate limit").
pub fn no_claim(c: &mut Checks, o: &ExecutionOutput, term: &str, min: Confidence) {
    let t = term.to_lowercase();
    let bad: Vec<String> = o
        .record
        .findings
        .iter()
        .filter(|f| f.confidence >= min && (f.code.to_lowercase().contains(&t) || f.title.to_lowercase().contains(&t)))
        .map(|f| format!("{} ({:?})", f.code, f.confidence))
        .collect();
    c.add(CheckKind::Diagnosis, format!("no '{term}' claim at ≥ {min:?}"), bad.is_empty(), format!("{bad:?}"));
}

/// No finding at or above `min` is scoped to `scope` (for example: nothing
/// blames the client leg for a response the gateway delivered).
pub fn no_scope(c: &mut Checks, o: &ExecutionOutput, scope: SourceScope, min: Confidence) {
    let bad: Vec<String> = o.record.findings.iter().filter(|f| f.scope == scope && f.confidence >= min).map(|f| f.code.clone()).collect();
    c.add(CheckKind::Diagnosis, format!("no {scope:?} finding at ≥ {min:?}"), bad.is_empty(), format!("{bad:?}"));
}

/// Different root causes with an identical public signal must receive the
/// same (cautious) findings: same codes, confidences and scopes.
pub fn indistinguishable(c: &mut Checks, a: &ExecutionOutput, b: &ExecutionOutput, what: &str) {
    let sig = |o: &ExecutionOutput| {
        let mut v: Vec<String> = o.record.findings.iter().map(|f| format!("{}/{:?}/{:?}", f.code, f.confidence, f.scope)).collect();
        v.sort();
        v
    };
    let (x, y) = (sig(a), sig(b));
    c.add(CheckKind::Diagnosis, format!("{what}: identical public signal gets identical findings"), x == y, format!("{x:?} vs {y:?}"));
}

/// The finding `code` states `needle` among its explanation, alternatives or
/// does-not-prove statements (the honest caveat is shown to the user).
pub fn caveat(c: &mut Checks, o: &ExecutionOutput, code: &str, needle: &str) {
    let n = needle.to_lowercase();
    let found = o.record.findings.iter().filter(|f| f.code == code).any(|f| {
        f.alternatives.iter().chain(f.does_not_prove.iter()).chain(std::iter::once(&f.explanation)).any(|s| s.to_lowercase().contains(&n))
    });
    c.add(CheckKind::Diagnosis, format!("{code} states the caveat '{needle}'"), found, format!("{:?}", codes(o)));
}

/// Operator-log field (JSON pointer) on this proxy's transaction lines.
pub fn operator_field(c: &mut Checks, lines: &[String], pointer: &str, allowed: &[&str]) {
    let vals: Vec<String> = lines
        .iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.pointer(pointer).map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())))
        .collect();
    let ok = vals.iter().any(|v| allowed.contains(&v.as_str()));
    c.add(CheckKind::GroundTruth, format!("gateway operator log {pointer} in {allowed:?}"), ok, format!("{vals:?}"));
}

/// Gateway runtime log lines (not transaction lines) containing `needle`
/// since line `from`, kept as supporting operator evidence. Not asserted:
/// the gateway samples most plugin WARNs (one per 10 s per reason), so a
/// repeat within the window is legitimately suppressed.
pub fn operator_lines(gw: &Gateway, from: usize, needle: &str) -> Vec<String> {
    gw.log_lines().into_iter().skip(from).filter(|l| l.contains(needle)).take(3).collect()
}

#[cfg(test)]
mod tests {
    use crate::gateway::repo_root;

    /// Port plan (docs/audit/gateway-lab-config.md §3): each profile keeps its
    /// gateway listeners in 18N00–18N99 and every fixture it points the gateway
    /// at in 19N00–19N99, all on loopback, so profiles can run side by side.
    #[test]
    fn profiles_stay_inside_their_port_blocks() {
        for (name, target, n) in
            [("policy", crate::policy::TARGET, 2u16), ("admission", crate::admission::TARGET, 5), ("drain", crate::drain::TARGET, 6)]
        {
            let (gw_lo, fx_lo) = (18000 + n * 100, 19000 + n * 100);
            assert!((gw_lo..gw_lo + 100).contains(&target.port), "{name} listener {}", target.port);
            assert_eq!(target.base, format!("http://127.0.0.1:{}", target.port));
            let conf = std::fs::read_to_string(repo_root().join(format!("lab/gateway/{name}.conf"))).unwrap();
            for line in conf.lines().filter(|l| l.contains("_PORT =")) {
                let port: u16 = line.rsplit('=').next().unwrap().trim().parse().unwrap();
                assert!(port == 0 || (gw_lo..gw_lo + 100).contains(&port), "{name}.conf: {line}");
            }
            for line in conf.lines().filter(|l| l.contains("BIND_ADDRESS")) {
                assert!(line.trim_end().ends_with("127.0.0.1"), "{name}.conf binds beyond loopback: {line}");
            }
            let yaml = std::fs::read_to_string(repo_root().join(format!("lab/gateway/{name}.yaml"))).unwrap();
            for line in yaml.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
                let port = if let Some(p) = line.strip_prefix("backend_port:") {
                    p.trim().parse::<u16>().ok()
                } else if let Some(h) = line.strip_prefix("opa_host:") {
                    h.trim().trim_matches('"').rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
                } else {
                    None
                };
                if let Some(p) = port {
                    assert!((fx_lo..fx_lo + 100).contains(&p), "{name}.yaml points outside its fixture block: {line}");
                }
                if line.starts_with("backend_host:") {
                    assert_eq!(line, "backend_host: 127.0.0.1", "{name}.yaml");
                }
            }
        }
    }

    /// The admission profile's mesh instance (UP-018) stays on loopback in
    /// the admission block too, and its ServiceEntries point into 195xx.
    #[test]
    fn admission_mesh_instance_stays_inside_the_admission_block() {
        let conf = std::fs::read_to_string(repo_root().join("lab/gateway/admission-mesh.conf")).unwrap();
        for line in conf.lines().filter(|l| !l.starts_with('#')) {
            if line.contains("_PORT =") {
                let port: u16 = line.rsplit('=').next().unwrap().trim().parse().unwrap();
                assert!(port == 0 || (18500..18600).contains(&port), "admission-mesh.conf: {line}");
            }
            if line.contains("LISTEN_ADDR =") {
                let addr = line.rsplit('=').next().unwrap().trim();
                let port: u16 = addr.strip_prefix("127.0.0.1:").expect("loopback listener").parse().unwrap();
                assert!((18500..18600).contains(&port), "admission-mesh.conf: {line}");
            }
            if line.contains("BIND_ADDRESS") {
                assert!(line.trim_end().ends_with("127.0.0.1"), "admission-mesh.conf binds beyond loopback: {line}");
            }
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(repo_root().join("lab/gateway/admission-mesh.json")).unwrap()).unwrap();
        for se in doc["mesh"]["service_entries"].as_array().unwrap() {
            for p in se["ports"].as_array().unwrap() {
                let port = p["port"].as_u64().unwrap();
                assert!((19500..19600).contains(&port), "ServiceEntry port {port} outside 195xx");
            }
            for h in se["hosts"].as_array().unwrap() {
                assert!(matches!(h.as_str(), Some("localhost" | "127.0.0.1")), "non-loopback ServiceEntry host {h}");
            }
        }
        assert_eq!(crate::fixtures_admission_mesh::EGRESS_PORT, 18589);
    }

    #[test]
    fn profile_registry_names_are_unique() {
        let names: Vec<&str> = crate::profiles::all().iter().map(|p| p.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "{names:?}");
        for n in ["policy", "admission", "drain"] {
            assert!(names.contains(&n), "{n} is registered");
        }
    }
}
