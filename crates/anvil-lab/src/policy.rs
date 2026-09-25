//! Scenarios for the `policy` gateway profile (HTTP 127.0.0.1:18280): WAF and
//! bot detection, OPA (deny / timeout / refused / error), IP restriction,
//! OpenAPI validation, the response-transformer ceiling, adaptive
//! concurrency, rate limiting, AI guard/budget/content/provider outcomes,
//! circuit-breaker half-open recovery and gateway-header ownership.
//!
//! Every stimulus drives the real gateway (config: `lab/gateway/policy.yaml`).
//! Anvil sees public evidence only; the destination is a trusted Ferrum
//! profile over plain HTTP, so marker/body-derived claims cap at `likely`.
//! Ground truth (fixture logs, the gateway operator log) is only compared
//! with Anvil's conclusions afterwards. Each scenario also runs a lookalike
//! that must not receive the gateway diagnosis, and a positive recovery.

use crate::fixtures_policy::{
    PolicyFixtures, Target, body_text, catalog_outcome, caveat, codes, enc, header, indistinguishable, no_claim, no_scope, op_log,
    operator_field, operator_lines, request, send, skips, with_header,
};
use crate::gateway::Gateway;
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::outcome::WarningCode;
use anvil_domain::request::Body;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub const TARGET: Target =
    Target { base: "http://127.0.0.1:18280", port: 18280, profile_name: "lab policy gateway", isolation: "lab-policy" };

const FORBIDDEN: &str = r#"{"error":"Forbidden"}"#;

pub struct Env {
    pub engine: Engine,
    pub fixtures: PolicyFixtures,
    pub gateway: Gateway,
    pub trusted: bool,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<std::path::PathBuf> {
        vec![self.gateway.log_path.clone()]
    }
}

impl Env {
    fn req(&self, method: &str, path: &str) -> ExecutionContext {
        request(&TARGET, self.trusted, method, path)
    }
    async fn send(&self, c: &ExecutionContext) -> ExecutionOutput {
        send(&self.engine, c).await
    }
    async fn get(&self, path: &str) -> ExecutionOutput {
        self.send(&self.req("GET", path)).await
    }
    async fn post_json(&self, path: &str, json: &str) -> ExecutionOutput {
        let mut c = self.req("POST", path);
        c.spec.body = Body::Raw { text: json.into(), content_type: Some("application/json".into()) };
        c.send_anyway = true;
        self.send(&c).await
    }
    fn mark(&self) -> usize {
        self.gateway.log_lines().len()
    }
    fn op(&self, from: usize, proxy_id: &str) -> Vec<String> {
        op_log(&self.gateway, from, proxy_id)
    }
    /// A backend-authored response through the plain `/ok` route.
    async fn backend(&self, code: u16, body: &str, headers: &[&str]) -> ExecutionOutput {
        let mut path = format!("/ok/status/{code}?body={}", enc(body));
        for h in headers {
            path.push_str(&format!("&header={}", enc(h)));
        }
        self.get(&path).await
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

fn has_code(o: &ExecutionOutput, code: &str) -> bool {
    o.record.findings.iter().any(|f| f.code == code)
}

/// Shared public-evidence assertions for a plugin rejection that carries no
/// `X-Gateway-Error` value.
fn plugin_reject(c: &mut Checks, o: &ExecutionOutput, status_code: u16, generic: &str) {
    c.status_in(o, &[status_code]);
    c.add(CheckKind::GroundTruth, "no X-Gateway-Error on the plugin rejection", header(o, "x-gateway-error").is_empty(), "");
    c.has(o, generic);
    c.absent_prefix(o, "ferrum.token");
    c.absent_prefix(o, "ferrum.backend_passthrough");
    no_scope(c, o, SourceScope::ClientToPeer, Confidence::Likely);
    no_scope(c, o, SourceScope::UpstreamApplication, Confidence::Likely);
}

/// The catalog match for a trusted profile is at most `likely`, scoped to
/// gateway admission, and states that a backend could send identical bytes.
fn catalog_match(c: &mut Checks, o: &ExecutionOutput, trusted: bool, outcome: &str) {
    if !trusted {
        return;
    }
    let got = catalog_outcome(o);
    c.add(CheckKind::Diagnosis, format!("catalog outcome {outcome}"), got.as_deref() == Some(outcome), format!("{got:?}; {:?}", codes(o)));
    c.max_confidence(o, "ferrum.outcome", Confidence::Likely);
    c.scope(o, "ferrum.outcome", SourceScope::GatewayAdmission);
    caveat(c, o, "ferrum.outcome", "identical");
}

fn backend_hits(before: usize, after: usize, expected: usize, what: &str, c: &mut Checks) {
    c.add(
        CheckKind::GroundTruth,
        format!("{what}: backend received {expected} request(s)"),
        after.saturating_sub(before) == expected,
        format!("{}", after.saturating_sub(before)),
    );
}

// ---------------------------------------------------------------------------

fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fixtures.echo.log.count_requests();
        let o = env.get("/ok/echo").await;
        c.success(CheckKind::Diagnosis, &o);
        backend_hits(before, env.fixtures.echo.log.count_requests(), 1, "control", &mut c);
        c.absent_prefix(&o, "ferrum.token");
        c.absent_prefix(&o, "ferrum.marker");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

/// GW-010 (header rule): a real WAF block vs a byte-identical application 403.
fn gw010(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let before = env.fixtures.echo.log.count_requests();
        let o = env.send(&with_header(env.req("GET", "/gw/waf/echo"), "x-lab-waf-test", "1")).await;
        backend_hits(before, env.fixtures.echo.log.count_requests(), 0, "WAF block", &mut c);
        let ops = env.op(from, "gw010-waf");
        operator_field(&mut c, &ops, "/metadata/waf.action", &["blocked"]);
        operator_field(&mut c, &ops, "/metadata/waf.first_blocking_rule", &["ANVIL-LAB-HEADER"]);
        plugin_reject(&mut c, &o, 403, "http.forbidden");
        no_claim(&mut c, &o, "waf", Confidence::Likely);
        no_claim(&mut c, &o, "bot", Confidence::Likely);
        c.add(CheckKind::Diagnosis, "no single-cause catalog attribution", !has_code(&o, "ferrum.outcome"), format!("{:?}", codes(&o)));
        if env.trusted {
            c.has(&o, "ferrum.outcome_ambiguous");
            c.max_confidence(&o, "ferrum.outcome_ambiguous", Confidence::Unknown);
            caveat(&mut c, &o, "ferrum.outcome_ambiguous", "backend returned a response with identical");
        }
        // Lookalike: the application itself answers 403 with the same bytes.
        let b2 = env.fixtures.echo.log.count_requests();
        let look = env.backend(403, FORBIDDEN, &[]).await;
        backend_hits(b2, env.fixtures.echo.log.count_requests(), 1, "application 403 lookalike", &mut c);
        c.add(CheckKind::GroundTruth, "lookalike body is byte-identical", body_text(&look) == body_text(&o), body_text(&look));
        indistinguishable(&mut c, &o, &look, "WAF 403 vs application 403");
        no_claim(&mut c, &look, "waf", Confidence::Likely);
        // Recovery: same route without the marker.
        let r = env.get("/gw/waf/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-010 (body rule): a POST body marker blocked by request-body inspection.
fn gw010_body(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let before = env.fixtures.echo.log.count_requests();
        let o = env.post_json("/gw/waf/echo", r#"{"comment":"ANVIL-LAB-WAF-MARKER"}"#).await;
        backend_hits(before, env.fixtures.echo.log.count_requests(), 0, "WAF body block", &mut c);
        let ops = env.op(from, "gw010-waf");
        operator_field(&mut c, &ops, "/metadata/waf.first_blocking_rule", &["ANVIL-LAB-BODY"]);
        plugin_reject(&mut c, &o, 403, "http.forbidden");
        no_claim(&mut c, &o, "waf", Confidence::Likely);
        c.add(CheckKind::Diagnosis, "no single-cause catalog attribution", !has_code(&o, "ferrum.outcome"), format!("{:?}", codes(&o)));
        let r = env.post_json("/gw/waf/echo", r#"{"comment":"ordinary text"}"#).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-010 / TRUST-006: bot detection's default 403 is byte-identical to the
/// WAF reject; Anvil must give both the same cautious answer.
fn gw010_bot(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let before = env.fixtures.echo.log.count_requests();
        let o = env.send(&with_header(env.req("GET", "/gw/bot/"), "User-Agent", "anvil-lab-bot/1.0")).await;
        backend_hits(before, env.fixtures.echo.log.count_requests(), 0, "bot block", &mut c);
        let ops = env.op(from, "gw010-bot");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["on_request_received"]);
        operator_field(&mut c, &ops, "/request_user_agent", &["anvil-lab-bot/1.0"]);
        plugin_reject(&mut c, &o, 403, "http.forbidden");
        no_claim(&mut c, &o, "waf", Confidence::Likely);
        no_claim(&mut c, &o, "bot", Confidence::Likely);
        let waf = env.send(&with_header(env.req("GET", "/gw/waf/echo"), "x-lab-waf-test", "1")).await;
        c.add(CheckKind::GroundTruth, "bot and WAF bodies are byte-identical", body_text(&waf) == body_text(&o), body_text(&o));
        indistinguishable(&mut c, &o, &waf, "bot-detection 403 vs WAF 403");
        let r = env.send(&with_header(env.req("GET", "/gw/bot/"), "User-Agent", "anvil-lab-client/1.0")).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-012: OPA explicit denial.
fn gw012(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let (q0, before) = (env.fixtures.opa.query_count(), env.fixtures.echo.log.count_requests());
        let o = env.get("/gw/opa-deny/echo").await;
        let q = env.fixtures.opa.queries();
        let asked = q.get(q0..).unwrap_or_default().iter().any(|x| x.policy_path == "anvil/lab/deny");
        c.add(
            CheckKind::GroundTruth,
            "OPA was asked for anvil/lab/deny and answered false",
            asked,
            format!("{} new queries", q.len() - q0),
        );
        backend_hits(before, env.fixtures.echo.log.count_requests(), 0, "OPA deny", &mut c);
        let ops = env.op(from, "gw012-opa-deny");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["authorize"]);
        plugin_reject(&mut c, &o, 403, "http.forbidden");
        c.absent_prefix(&o, "http.unauthorized");
        no_claim(&mut c, &o, "credential", Confidence::Likely);
        no_claim(&mut c, &o, "waf", Confidence::Likely);
        catalog_match(&mut c, &o, env.trusted, "plugin.opa.policy_denied");
        // Lookalike A: the application's own 403 with its own body.
        let look = env.backend(403, r#"{"error":"forbidden","reason":"account suspended"}"#, &[]).await;
        c.add(
            CheckKind::Diagnosis,
            "application 403 is not attributed to OPA",
            catalog_outcome(&look).is_none(),
            format!("{:?}", codes(&look)),
        );
        // Lookalike B: byte-identical application body — the best Anvil can
        // honestly say is "likely", with the identical-bytes caveat.
        let same = env.backend(403, r#"{"error":"forbidden by policy"}"#, &[]).await;
        c.max_confidence(&same, "ferrum.outcome", Confidence::Likely);
        if has_code(&same, "ferrum.outcome") {
            caveat(&mut c, &same, "ferrum.outcome", "identical");
        }
        let r = env.get("/gw/opa-allow/echo").await;
        c.success(CheckKind::Recovery, &r);
        let allow_asked = env.fixtures.opa.queries().iter().skip(q0).any(|x| x.policy_path == "anvil/lab/allow");
        c.add(CheckKind::Recovery, "OPA allowed the recovery request", allow_asked, "");
        let mut ground = ops;
        ground.extend(q.iter().skip(q0).map(|x| format!("opa-mock query {} input={}", x.policy_path, x.input)));
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ground }
    })
}

/// Shared checks for a fail-closed OPA refusal (GW-013 variants).
fn opa_fail_closed(c: &mut Checks, env: &Env, o: &ExecutionOutput) {
    plugin_reject(c, o, 503, "http.service_unavailable");
    c.absent_prefix(o, "http.unauthorized");
    no_claim(c, o, "credential", Confidence::Likely);
    no_claim(c, o, "cpu", Confidence::Likely);
    catalog_match(c, o, env.trusted, "plugin.opa.fail_closed");
    if env.trusted {
        // A trusted 5xx without a marker: absence is reported as unknown and
        // must name the plugin-rejection possibility (0.9.5 plugin rejects
        // carry no X-Gateway-Error).
        c.has(o, "ferrum.marker.absent");
        c.max_confidence(o, "ferrum.marker.absent", Confidence::Unknown);
        caveat(c, o, "ferrum.marker.absent", "plugin");
    }
}

/// GW-013: OPA accepts the query but never answers (500 ms plugin timeout).
fn gw013_timeout(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let (s0, before) = (env.fixtures.opa_stall.log.count_requests(), env.fixtures.echo.log.count_requests());
        let o = env.get("/gw/opa-timeout/echo").await;
        c.add(CheckKind::GroundTruth, "stalled OPA received the decision query", env.fixtures.opa_stall.log.count_requests() > s0, "");
        backend_hits(before, env.fixtures.echo.log.count_requests(), 0, "OPA timeout", &mut c);
        let mut ops = env.op(from, "gw013-opa-timeout");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["authorize"]);
        ops.extend(operator_lines(&env.gateway, from, "OPA authorization decision failed"));
        opa_fail_closed(&mut c, env, &o);
        // Lookalike: the application's own 503, even with byte-identical text,
        // is stamped backend_error by the gateway and is not an OPA outcome.
        let look = env.backend(503, r#"{"error":"authorization service unavailable"}"#, &[]).await;
        c.token(&look, "ferrum.token.backend_error", env.trusted);
        c.add(
            CheckKind::Diagnosis,
            "application 503 lookalike is not attributed to OPA",
            catalog_outcome(&look).as_deref() != Some("plugin.opa.fail_closed"),
            format!("{:?}", codes(&look)),
        );
        let r = env.get("/gw/opa-allow/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-013: nothing listens on the OPA port; recovery binds an OPA mock there.
fn gw013_refused(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let before = env.fixtures.echo.log.count_requests();
        let o = env.get("/gw/opa-refused/echo").await;
        backend_hits(before, env.fixtures.echo.log.count_requests(), 0, "OPA refused", &mut c);
        let mut ops = env.op(from, "gw013-opa-refused");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["authorize"]);
        ops.extend(operator_lines(&env.gateway, from, "OPA authorization decision failed"));
        opa_fail_closed(&mut c, env, &o);
        // Remove the fault: bring the policy service up on the refused port.
        let r = match anvil_fixtures::policy::serve_opa("127.0.0.1:19209").await {
            Ok(opa) => {
                let r = env.get("/gw/opa-refused/echo").await;
                c.add(CheckKind::Recovery, "restored OPA answered the decision", opa.query_count() >= 1, "");
                drop(opa);
                r
            }
            Err(e) => {
                c.add(CheckKind::Recovery, "bind OPA mock on 19209 for recovery", false, e.to_string());
                env.get("/gw/opa-allow/echo").await
            }
        };
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-013: OPA answers HTTP 500; recovery clears the fault on the same route.
fn gw013_error(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let q0 = env.fixtures.opa.query_count();
        env.fixtures.opa.set_failing(true);
        let o = env.get("/gw/opa-allow/echo").await;
        env.fixtures.opa.set_failing(false);
        let failed = env.fixtures.opa.queries().iter().skip(q0).any(|q| q.status == 500);
        c.add(CheckKind::GroundTruth, "OPA answered HTTP 500 to the decision query", failed, "");
        let mut ops = env.op(from, "gw012-opa-allow");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["authorize"]);
        ops.extend(operator_lines(&env.gateway, from, "OPA authorization decision failed"));
        opa_fail_closed(&mut c, env, &o);
        let r = env.get("/gw/opa-allow/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-014: IP restriction denies the loopback client.
fn gw014(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let before = env.fixtures.echo.log.count_requests();
        let o = env.get("/gw/ip-deny/echo").await;
        backend_hits(before, env.fixtures.echo.log.count_requests(), 0, "IP deny", &mut c);
        let mut ops = env.op(from, "gw014-ip-deny");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["on_request_received"]);
        ops.extend(operator_lines(&env.gateway, from, "IP address denied"));
        plugin_reject(&mut c, &o, 403, "http.forbidden");
        c.add(
            CheckKind::Diagnosis,
            "the gateway was reachable: transport completed",
            codes(&o).iter().all(|x| !x.starts_with("client.")),
            "",
        );
        no_claim(&mut c, &o, "unreachable", Confidence::Unknown);
        catalog_match(&mut c, &o, env.trusted, "plugin.ip_restriction.ip_denied");
        let look = env.backend(403, r#"{"error":"forbidden","reason":"not your resource"}"#, &[]).await;
        c.add(
            CheckKind::Diagnosis,
            "application 403 is not attributed to IP policy",
            catalog_outcome(&look).is_none(),
            format!("{:?}", codes(&look)),
        );
        let r = env.get("/ok/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-015: OpenAPI request validation (syntax vs schema vs unknown operation).
fn gw015(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let before = env.fixtures.echo.log.count_requests();
        let malformed = env.post_json("/gw/openapi/items", r#"{"name": "x", "qty": "#).await;
        let o = env.post_json("/gw/openapi/items", r#"{"name":"x","qty":0}"#).await;
        let unknown = env.get("/gw/openapi/other").await;
        backend_hits(before, env.fixtures.echo.log.count_requests(), 0, "validator rejections", &mut c);
        let ops = env.op(from, "gw015-openapi");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["validate_client_request_contract"]);
        for (what, x) in [("malformed JSON", &malformed), ("schema violation", &o), ("unknown operation", &unknown)] {
            plugin_reject(&mut c, x, 400, "http.client_error");
            no_claim(&mut c, x, "tls", Confidence::Unknown);
            c.add(
                CheckKind::GroundTruth,
                format!("{what}: problem+json body preserved for the user"),
                header(x, "content-type").iter().any(|v| v.contains("problem+json")),
                body_text(x),
            );
        }
        let (bm, bs) = (body_text(&malformed), body_text(&o));
        c.add(
            CheckKind::GroundTruth,
            "syntax and schema rejections are distinguishable in the body",
            bm.contains("Invalid JSON") && bs.contains("minimum"),
            "",
        );
        // Lookalike: an application-authored problem+json 400.
        let look = env
            .backend(
                400,
                r#"{"type":"about:blank","title":"Request body validation failed","status":400,"detail":"qty must be >= 1"}"#,
                &["content-type:application/problem+json"],
            )
            .await;
        indistinguishable(&mut c, &o, &look, "gateway validator 400 vs application 400");
        let r = env.post_json("/gw/openapi/items", r#"{"name":"x","qty":2}"#).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-009: response-transformer output ceiling (`overload` that is not load).
fn gw009(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let before = env.fixtures.json_empty.log.count_requests();
        let o = env.get("/gw/transform-ceiling/status/200?body=%7B%7D").await;
        backend_hits(before, env.fixtures.json_empty.log.count_requests(), 1, "origin served a 2-byte body", &mut c);
        let mut ops = env.op(from, "gw009-transform-ceiling");
        c.operator_class(&ops, "gw009-transform-ceiling", &["dispatch_policy_rejected"]);
        ops.extend(operator_lines(&env.gateway, from, "output exceeds response size policy"));
        c.status_in(&o, &[502]);
        c.token(&o, "ferrum.token.overload", env.trusted);
        c.scope(&o, "ferrum.token.overload", SourceScope::GatewayAdmission);
        c.max_confidence(&o, "ferrum.token.overload", Confidence::Likely);
        no_claim(&mut c, &o, "cpu", Confidence::Unknown);
        no_claim(&mut c, &o, "overloaded", Confidence::Likely);
        c.absent_prefix(&o, "ferrum.backend_passthrough");
        if env.trusted {
            caveat(&mut c, &o, "ferrum.token.overload", "transform");
            caveat(&mut c, &o, "ferrum.token.overload", "cpu");
            let got = catalog_outcome(&o);
            c.add(
                CheckKind::Diagnosis,
                "catalog outcome gateway.response.transformer_output_ceiling",
                got.as_deref() == Some("gateway.response.transformer_output_ceiling"),
                format!("{got:?}"),
            );
        }
        // Lookalike 1: the application returns the same bytes as a 502.
        let look = env.backend(502, r#"{"error":"Response body too large","limit":128}"#, &[]).await;
        c.token(&look, "ferrum.token.backend_error", env.trusted);
        c.add(
            CheckKind::Diagnosis,
            "application 502 lookalike gets no overload claim",
            !has_code(&look, "ferrum.token.overload"),
            format!("{:?}", codes(&look)),
        );
        // Lookalike 2: a plain response-size ceiling is a gateway limit with a
        // different (backend_error) token.
        let from2 = env.mark();
        let size = env.get("/gw/response-size/bytes/1024").await;
        c.operator_class(&env.op(from2, "gw009-response-size"), "gw009-response-size", &["response_body_too_large"]);
        c.add(
            CheckKind::Diagnosis,
            "declared-size ceiling gets no overload claim",
            !has_code(&size, "ferrum.token.overload"),
            format!("{:?}", codes(&size)),
        );
        no_claim(&mut c, &size, "cpu", Confidence::Unknown);
        // Control / recovery: 114-char transform stays within 128 bytes.
        let r = env.get("/gw/transform-boundary/status/200?body=%7B%7D").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-004: adaptive concurrency (limit 1) while one request holds the permit.
fn gw004(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let before = env.fixtures.slow.log.count_requests();
        let occupant = env.req("GET", "/gw/concurrency/delay-headers/3000");
        let second = env.req("GET", "/gw/concurrency/delay-headers/10");
        let (first, o) = tokio::join!(env.send(&occupant), async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            env.send(&second).await
        });
        c.success(CheckKind::GroundTruth, &first);
        backend_hits(before, env.fixtures.slow.log.count_requests(), 1, "only the occupant reached the backend", &mut c);
        let ops = env.op(from, "gw004-concurrency");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["adaptive_concurrency"]);
        c.status_in(&o, &[503]);
        c.add(CheckKind::GroundTruth, "x-adaptive-concurrency-limit exposed", header(&o, "x-adaptive-concurrency-limit") == ["1"], "");
        c.token(&o, "ferrum.token.concurrency_limit", env.trusted);
        c.scope(&o, "ferrum.token.concurrency_limit", SourceScope::GatewayAdmission);
        c.max_confidence(&o, "ferrum.token.concurrency_limit", Confidence::Likely);
        c.absent_prefix(&o, "http.too_many_requests");
        no_claim(&mut c, &o, "rate limit", Confidence::Likely);
        no_claim(&mut c, &o, "crash", Confidence::Unknown);
        catalog_match(&mut c, &o, env.trusted, "gateway.admission.adaptive_concurrency");
        let look = env.backend(503, r#"{"error":"Upstream concurrency limit reached"}"#, &[]).await;
        c.token(&look, "ferrum.token.backend_error", env.trusted);
        c.add(
            CheckKind::Diagnosis,
            "application 503 lookalike gets no concurrency_limit claim",
            !has_code(&look, "ferrum.token.concurrency_limit"),
            format!("{:?}", codes(&look)),
        );
        let r = env.get("/gw/concurrency/delay-headers/10").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// Plan §15.4 extension: gateway rate limit vs an application's identical 429.
fn ext_rate_limit(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        tokio::time::sleep(Duration::from_millis(2100)).await; // fresh 2 s window
        let from = env.mark();
        let before = env.fixtures.echo.log.count_requests();
        let a = env.get("/gw/rate-limit/echo").await;
        let b = env.get("/gw/rate-limit/echo").await;
        let o = env.get("/gw/rate-limit/echo").await;
        c.success(CheckKind::GroundTruth, &a);
        c.success(CheckKind::GroundTruth, &b);
        backend_hits(before, env.fixtures.echo.log.count_requests(), 2, "admitted within the window", &mut c);
        let ops = env.op(from, "rl-rate-limit");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["on_request_received"]);
        plugin_reject(&mut c, &o, 429, "http.too_many_requests");
        c.add(CheckKind::GroundTruth, "x-ratelimit-remaining: 0 exposed", header(&o, "x-ratelimit-remaining") == ["0"], "");
        no_claim(&mut c, &o, "concurrency", Confidence::Likely);
        c.add(CheckKind::Diagnosis, "no single-cause catalog attribution", !has_code(&o, "ferrum.outcome"), format!("{:?}", codes(&o)));
        // Lookalike: the application answers the same 429 with the same headers.
        let look = env
            .backend(429, r#"{"error":"Rate limit exceeded"}"#, &["x-ratelimit-limit:2", "x-ratelimit-remaining:0", "x-ratelimit-window:2"])
            .await;
        c.add(CheckKind::GroundTruth, "lookalike body is byte-identical", body_text(&look) == body_text(&o), "");
        indistinguishable(&mut c, &o, &look, "gateway 429 vs application 429");
        tokio::time::sleep(Duration::from_millis(2100)).await;
        let r = env.get("/gw/rate-limit/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

const CHAT: &str = r#"{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}"#;

/// GW-020 (request guard): model outside the allow list.
fn gw020_guard(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let calls = env.fixtures.ai.call_count();
        let o = env
            .post_json(
                "/gw/ai/guard/v1/chat/completions",
                r#"{"model":"gpt-3.5-turbo","max_tokens":50,"messages":[{"role":"user","content":"hello"}]}"#,
            )
            .await;
        c.add(CheckKind::GroundTruth, "provider was never called", env.fixtures.ai.call_count() == calls, "");
        let ops = env.op(from, "gw020-ai-guard");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["before_proxy"]);
        plugin_reject(&mut c, &o, 400, "http.client_error");
        c.add(CheckKind::GroundTruth, "public body names the model policy", body_text(&o).contains("Model not allowed"), body_text(&o));
        // Lookalike: the provider itself rejects a request with a 400.
        let look = env.post_json("/gw/ai/provider/v1/error/400", CHAT).await;
        c.add(
            CheckKind::GroundTruth,
            "provider authored the lookalike 400",
            env.fixtures.ai.calls().last().map(|x| x.status) == Some(400),
            "",
        );
        indistinguishable(&mut c, &o, &look, "gateway AI guard 400 vs provider 400");
        let r = env.post_json("/gw/ai/guard/v1/chat/completions", CHAT).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-020 (token budget): reservation-based AI token limit (50 per 3 s).
fn gw020_budget(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        env.fixtures.ai.set_usage(20, 10);
        tokio::time::sleep(Duration::from_millis(3100)).await; // fresh window
        let from = env.mark();
        let calls = env.fixtures.ai.call_count();
        let a = env.post_json("/gw/ai/budget/v1/chat/completions", CHAT).await;
        let b = env.post_json("/gw/ai/budget/v1/chat/completions", CHAT).await;
        let o = env.post_json("/gw/ai/budget/v1/chat/completions", CHAT).await;
        c.success(CheckKind::GroundTruth, &a);
        c.success(CheckKind::GroundTruth, &b);
        let used: u64 = env.fixtures.ai.calls().iter().skip(calls).map(|x| x.total_tokens).sum();
        c.add(CheckKind::GroundTruth, "provider reported 60 tokens across two calls (limit 50)", used == 60, used.to_string());
        let ops = env.op(from, "gw020-ai-budget");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["before_proxy"]);
        plugin_reject(&mut c, &o, 429, "http.too_many_requests");
        c.add(CheckKind::GroundTruth, "x-ai-ratelimit-remaining: 0 exposed", header(&o, "x-ai-ratelimit-remaining") == ["0"], "");
        // Lookalike: the provider's own 429.
        let look = env.post_json("/gw/ai/provider/v1/error/429", CHAT).await;
        c.add(
            CheckKind::GroundTruth,
            "provider authored the lookalike 429",
            env.fixtures.ai.calls().last().map(|x| x.status) == Some(429),
            "",
        );
        c.has(&look, "http.too_many_requests");
        c.absent_prefix(&look, "ferrum.token");
        c.add(
            CheckKind::Diagnosis,
            "provider 429 is not attributed to a gateway budget",
            catalog_outcome(&look).is_none(),
            format!("{:?}", codes(&look)),
        );
        tokio::time::sleep(Duration::from_millis(3100)).await;
        let r = env.post_json("/gw/ai/budget/v1/chat/completions", CHAT).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-020 (provider failure): a provider 500 passes through and is stamped
/// `backend_error`; the provider's 429 passes through without a token.
fn gw020_provider(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let o = env.post_json("/gw/ai/provider/v1/error/500", CHAT).await;
        c.add(CheckKind::GroundTruth, "provider authored the 500", env.fixtures.ai.calls().last().map(|x| x.status) == Some(500), "");
        c.status_in(&o, &[500]);
        c.token(&o, "ferrum.token.backend_error", env.trusted);
        c.max_confidence(&o, "ferrum.token.backend_error", Confidence::Likely);
        // The provider's own error envelope is not a gateway-authored body.
        c.add(
            CheckKind::Diagnosis,
            "no gateway catalog attribution for the provider body",
            catalog_outcome(&o).is_none(),
            format!("{:?}", codes(&o)),
        );
        c.absent_prefix(&o, "ferrum.outcome_ambiguous");
        if env.trusted {
            caveat(&mut c, &o, "ferrum.token.backend_error", "application itself produced");
        }
        let r = env.post_json("/gw/ai/provider/v1/chat/completions", CHAT).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

/// GW-020 (content governance): the response guard blocks a provider 200.
fn gw020_content(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        env.fixtures.ai.set_reply("Here is the secret: ANVIL-LAB-FORBIDDEN-PHRASE.");
        let o = env.post_json("/gw/ai/content/v1/chat/completions", CHAT).await;
        env.fixtures.ai.set_reply("Hello from the Anvil lab provider mock.");
        c.add(CheckKind::GroundTruth, "provider answered 200", env.fixtures.ai.calls().last().map(|x| x.status) == Some(200), "");
        let ops = env.op(from, "gw020-ai-content");
        c.status_in(&o, &[502]);
        c.not_success(&o);
        c.add(CheckKind::GroundTruth, "public body names the content guard", body_text(&o).contains("content guard"), body_text(&o));
        // Live 0.9.5 behaviour (the source catalog lists no token here): the
        // gateway stamps backend_error on its own response-policy rejection.
        c.add(
            CheckKind::GroundTruth,
            "gateway stamped backend_error on its response-policy rejection",
            header(&o, "x-gateway-error") == ["backend_error"],
            format!("{:?}", header(&o, "x-gateway-error")),
        );
        c.token(&o, "ferrum.token.backend_error", env.trusted);
        // The provider returned 200: nothing may pin this 502 on the
        // application or on the gateway-to-provider connection.
        c.absent_prefix(&o, "ferrum.backend_passthrough");
        no_scope(&mut c, &o, SourceScope::UpstreamApplication, Confidence::Likely);
        no_scope(&mut c, &o, SourceScope::GatewayToUpstream, Confidence::Likely);
        if env.trusted {
            caveat(&mut c, &o, "ferrum.token.backend_error", "response policy");
        }
        let r = env.post_json("/gw/ai/content/v1/chat/completions", CHAT).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-001 beyond core: open → half-open probe fails → re-open → half-open
/// probe succeeds → closed.
fn gw001_halfopen(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let log = &env.fixtures.breaker.log;
        let from = env.mark();
        let n0 = log.count_requests();
        let f1 = env.get("/gw/breaker/status/500").await;
        let f2 = env.get("/gw/breaker/status/500").await;
        c.token(&f1, "ferrum.token.backend_error", env.trusted);
        c.token(&f2, "ferrum.token.backend_error", env.trusted);
        let n1 = log.count_requests();
        let o = env.get("/gw/breaker/status/200").await; // would succeed, but the breaker is open
        backend_hits(n1, log.count_requests(), 0, "open breaker", &mut c);
        c.add(CheckKind::GroundTruth, "two failures reached the backend", n1 - n0 == 2, "");
        c.status_in(&o, &[503]);
        c.token(&o, "ferrum.token.circuit_breaker_open", env.trusted);
        c.scope(&o, "ferrum.token.circuit_breaker_open", SourceScope::GatewayAdmission);
        c.max_confidence(&o, "ferrum.token.circuit_breaker_open", Confidence::Likely);
        // Half-open probe that fails re-opens the breaker immediately.
        tokio::time::sleep(Duration::from_millis(2300)).await;
        let n2 = log.count_requests();
        let probe_fail = env.get("/gw/breaker/status/500").await;
        let reopened = env.get("/gw/breaker/status/200").await;
        backend_hits(n2, log.count_requests(), 1, "half-open admitted exactly one probe", &mut c);
        c.status_in(&probe_fail, &[500]);
        c.token(&reopened, "ferrum.token.circuit_breaker_open", env.trusted);
        // Half-open probe that succeeds closes it.
        tokio::time::sleep(Duration::from_millis(2300)).await;
        let n3 = log.count_requests();
        let probe_ok = env.get("/gw/breaker/status/200").await;
        let r = env.get("/gw/breaker/status/200").await;
        backend_hits(n3, log.count_requests(), 2, "closed breaker forwards again", &mut c);
        c.success(CheckKind::Recovery, &probe_ok);
        c.success(CheckKind::Recovery, &r);
        let mut ops = env.op(from, "gw001-breaker-halfopen");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["circuit_breaker_open"]);
        ops.extend(operator_lines(&env.gateway, from, "Circuit breaker opening"));
        // Lookalike: the application's own 503 with the breaker's exact body.
        let look = env.backend(503, r#"{"error":"Service temporarily unavailable (circuit breaker open)"}"#, &[]).await;
        c.token(&look, "ferrum.token.backend_error", env.trusted);
        c.add(
            CheckKind::Diagnosis,
            "application 503 lookalike gets no circuit-breaker claim",
            !has_code(&look, "ferrum.token.circuit_breaker_open"),
            format!("{:?}", codes(&look)),
        );
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-019 (a): a response hook overwrites X-Gateway-Error on a gateway error.
fn gw019_error(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let o = env.get("/gw/header-mutation-error/").await;
        let ops = env.op(from, "gw019-error-spoof");
        c.operator_class(&ops, "gw019-error-spoof", &["connection_refused"]);
        c.status_in(&o, &[502]);
        c.add(
            CheckKind::GroundTruth,
            "gateway restored the authoritative X-Gateway-Error",
            header(&o, "x-gateway-error") == ["connection_failure"],
            format!("{:?}", header(&o, "x-gateway-error")),
        );
        c.token(&o, "ferrum.token.connection_failure", env.trusted);
        c.max_confidence(&o, "ferrum.token.connection_failure", Confidence::Likely);
        c.absent_prefix(&o, "ferrum.marker.unknown_token");
        // The hook's X-Gateway-Upstream-Status survives: never above likely,
        // and the caveat that a non-gateway writer can set it is shown.
        let spoofed_degraded = !header(&o, "x-gateway-upstream-status").is_empty();
        c.add(CheckKind::GroundTruth, "hook-injected X-Gateway-Upstream-Status reached the client", spoofed_degraded, "");
        if env.trusted {
            c.max_confidence(&o, "ferrum.degraded_routing", Confidence::Likely);
            caveat(&mut c, &o, "ferrum.degraded_routing", "plugin");
        }
        let r = env.get("/ok/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-019 (b): a response hook injects gateway headers on a successful response.
fn gw019_ok(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let o = env.get("/gw/header-mutation-ok/").await;
        forged_checks(&mut c, env, &o, "response hook");
        let r = env.get("/ok/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

/// GW-019 (c) / TRUST-011: the backend itself forges gateway headers on a 200.
fn gw019_forged(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fixtures.forged.log.count_requests();
        let o = env
            .get(&format!(
                "/gw/backend-forged-headers/status/200?header={}&header={}",
                enc("X-Gateway-Error:backend_error"),
                enc("X-Gateway-Upstream-Status:degraded")
            ))
            .await;
        backend_hits(before, env.fixtures.forged.log.count_requests(), 1, "forging backend answered", &mut c);
        forged_checks(&mut c, env, &o, "backend");
        let r = env.get("/ok/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

/// Injected gateway headers on a 200: `X-Gateway-Error` is stripped, the
/// degraded marker passes and may only surface as a capped warning.
fn forged_checks(c: &mut Checks, env: &Env, o: &ExecutionOutput, who: &str) {
    c.success(CheckKind::Diagnosis, o);
    c.add(CheckKind::GroundTruth, format!("{who}-injected X-Gateway-Error was stripped"), header(o, "x-gateway-error").is_empty(), "");
    c.add(
        CheckKind::GroundTruth,
        format!("{who}-injected X-Gateway-Upstream-Status passed"),
        !header(o, "x-gateway-upstream-status").is_empty(),
        "",
    );
    c.absent_prefix(o, "ferrum.token");
    let want = if env.trusted { WarningCode::DegradedRouting } else { WarningCode::UnverifiedFerrumMarker };
    c.add(
        CheckKind::Diagnosis,
        format!("marker surfaced only as a {want:?} warning"),
        o.record.outcome.warnings.iter().any(|w| w.code == want),
        "",
    );
    if env.trusted {
        c.max_confidence(o, "ferrum.degraded_routing", Confidence::Likely);
        caveat(c, o, "ferrum.degraded_routing", "backend");
    }
}

/// GW-019 (d) / TRUST-003: a reject-path hook adds a value outside the
/// 7-token vocabulary to a gateway 403.
fn gw019_reject_unknown(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let o = env.get("/gw/reject-decorated/").await;
        let ops = env.op(from, "gw019-reject-decorated");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["on_request_received"]);
        c.status_in(&o, &[403]);
        c.add(
            CheckKind::GroundTruth,
            "decorated reject carries lab-future-token",
            header(&o, "x-gateway-error") == ["lab-future-token"],
            "",
        );
        c.has(&o, "http.forbidden");
        c.absent_prefix(&o, "ferrum.token");
        if env.trusted {
            c.has_any(&o, &["ferrum.marker.unknown_token", "ferrum.marker.inconsistent"]);
            c.max_confidence(&o, "ferrum.marker.unknown_token", Confidence::Unknown);
            c.max_confidence(&o, "ferrum.marker.inconsistent", Confidence::ConflictingEvidence);
        } else {
            c.has(&o, "ferrum.marker.unverified");
        }
        let r = env.get("/ok/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-019 (e) / TRUST-011: a reject-path hook writes a KNOWN token
/// (`overload`) onto a gateway 403. Ferrum's core never writes a token on a
/// 4xx, so the value cannot be a gateway overload verdict.
fn gw019_reject_known(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.mark();
        let o = env.get("/gw/reject-known-token/").await;
        let ops = env.op(from, "gw019-reject-known-token");
        operator_field(&mut c, &ops, "/metadata/rejection_phase", &["on_request_received"]);
        c.status_in(&o, &[403]);
        c.add(
            CheckKind::GroundTruth,
            "decorated reject carries X-Gateway-Error: overload",
            header(&o, "x-gateway-error") == ["overload"],
            "",
        );
        c.has(&o, "http.forbidden");
        c.absent_prefix(&o, "ferrum.token");
        no_claim(&mut c, &o, "overload", Confidence::Likely);
        no_claim(&mut c, &o, "cpu", Confidence::Unknown);
        if env.trusted {
            c.has(&o, "ferrum.marker.inconsistent");
            c.max_confidence(&o, "ferrum.marker.inconsistent", Confidence::ConflictingEvidence);
        } else {
            c.has(&o, "ferrum.marker.unverified");
        }
        let r = env.get("/ok/echo").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-POL-001", title: "Positive control through the policy gateway", run: ctrl },
        Def { id: "GW-010", title: "WAF header-rule block vs byte-identical application 403", run: gw010 },
        Def { id: "GW-010-BODY", title: "WAF request-body rule block", run: gw010_body },
        Def { id: "GW-010-BOT", title: "Bot-detection 403 indistinguishable from WAF 403", run: gw010_bot },
        Def { id: "GW-012", title: "OPA explicit denial (+ application 403 lookalikes)", run: gw012 },
        Def { id: "GW-013-TIMEOUT", title: "OPA stalls; gateway fails closed (+ application 503 lookalike)", run: gw013_timeout },
        Def { id: "GW-013-REFUSED", title: "OPA unreachable; recovery restores the policy service", run: gw013_refused },
        Def { id: "GW-013-ERROR", title: "OPA answers 500; gateway fails closed", run: gw013_error },
        Def { id: "GW-014", title: "IP restriction denial", run: gw014 },
        Def { id: "GW-015", title: "OpenAPI request validation (syntax, schema, unknown operation)", run: gw015 },
        Def { id: "GW-009", title: "Response-transformer ceiling ('overload' that is not load)", run: gw009 },
        Def { id: "GW-004", title: "Adaptive concurrency limit (+ application 503 lookalike)", run: gw004 },
        Def { id: "EXT-RL-001", title: "Gateway rate limit vs byte-identical application 429", run: ext_rate_limit },
        Def { id: "GW-020-GUARD", title: "AI request guard rejects a disallowed model", run: gw020_guard },
        Def { id: "GW-020-BUDGET", title: "AI token budget exhausted (+ provider 429 lookalike)", run: gw020_budget },
        Def { id: "GW-020-PROVIDER", title: "AI provider 500 passes through with backend_error", run: gw020_provider },
        Def { id: "GW-020-CONTENT", title: "AI response content guard blocks a provider 200", run: gw020_content },
        Def { id: "GW-001-HALFOPEN", title: "Circuit breaker half-open probe: fail re-opens, success closes", run: gw001_halfopen },
        Def { id: "GW-019-ERROR", title: "Response hook overwrites gateway headers on an error", run: gw019_error },
        Def { id: "GW-019-OK", title: "Response hook injects gateway headers on a 200", run: gw019_ok },
        Def { id: "GW-019-FORGED", title: "Backend forges gateway headers on a 200", run: gw019_forged },
        Def { id: "GW-019-REJECT-UNKNOWN", title: "Reject-path hook adds an unknown X-Gateway-Error value", run: gw019_reject_unknown },
        Def { id: "GW-019-REJECT-KNOWN", title: "Reject-path hook adds a known token to a 403", run: gw019_reject_known },
    ]
}

/// Family members this profile cannot drive live (reported as skips, never passes).
const SKIPPED: &[(&str, &str, &str)] = &[(
    "GW-014-GEO",
    "Geo restriction (country block / GeoIP database unavailable)",
    "geo_restriction needs a readable MaxMind country .mmdb: `ferrum-edge validate` rejects a missing db_path \
     ('not accessible before open'), no database is vendored in the repo and the lab may not download one, so neither \
     the country-deny nor the database-unavailable path is reachable with v0.9.5 file mode here.",
)];

pub fn profile() -> Profile {
    Profile {
        name: "policy",
        about: "WAF/bot, OPA, IP, validators, rate/AI limits, concurrency, breaker, header ownership (HTTP 18280)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let fixtures = PolicyFixtures::start().await?;
    let gateway = Gateway::start("policy", "policy.conf", "policy.yaml", &[], 18290, &[]).await?;
    // Let the startup capability probes settle before scenarios count fixture hits.
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(Env { engine: Engine::new(), fixtures, gateway, trusted: true })
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("policy")?;
    let mut env = start().await?;
    let results = harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await;
    let mut results = match results {
        Ok(r) => r,
        Err(e) => {
            env.gateway.stop().await;
            return Err(e);
        }
    };
    results.extend(skips(&ctx, &args.only, SKIPPED));
    harness::finish(&ctx, &env, &results)?;
    env.gateway.stop().await;
    Ok(results)
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!("policy lab running: gateway {} (admin 127.0.0.1:18290); operator log {}", TARGET.base, env.gateway.log_path.display());
    println!(
        "routes: /ok /gw/waf /gw/bot /gw/opa-{{allow,deny,timeout,refused}} /gw/ip-deny /gw/openapi/items /gw/transform-{{ceiling,boundary}} /gw/response-size /gw/concurrency /gw/rate-limit /gw/ai/{{guard,budget,provider,content}} /gw/breaker /gw/header-mutation-{{error,ok}} /gw/backend-forged-headers /gw/reject-{{decorated,known-token}}"
    );
    harness::wait_for_shutdown().await?;
    env.gateway.stop().await;
    Ok(())
}
