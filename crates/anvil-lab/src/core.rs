//! Scenarios for the `core` gateway profile (upstream failures, admission,
//! response ownership). Public-evidence mode: Anvil sees only what any
//! client sees; the destination is configured as a trusted Ferrum profile
//! over plain HTTP (so every marker-derived claim is capped at "likely").

use crate::fixtures::CoreFixtures;
use crate::gateway::Gateway;
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::request::{Body, RequestSpec};
use anvil_domain::tls::HostBinding;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_transport::recorder::EventCtx;
use std::future::Future;
use std::pin::Pin;
use tokio_util::sync::CancellationToken;

pub const GATEWAY: &str = "http://127.0.0.1:18080";

pub struct Env {
    pub engine: Engine,
    pub fixtures: CoreFixtures,
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

type Def = harness::Def<Env>;

pub fn ctx(env: &Env, method: &str, path: &str) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(RequestSpec::http(method, &format!("{GATEWAY}{path}")));
    c.isolation = "lab-core".into();
    if env.trusted {
        c.integrations.push(IntegrationProfile {
            id: anvil_domain::Id::new(),
            workspace_id: anvil_domain::Id::new(),
            name: "lab core gateway".into(),
            kind: IntegrationKind::FerrumGateway {
                hosts: vec![HostBinding { host: "127.0.0.1".into(), port: Some(18080) }],
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

pub async fn send(env: &Env, c: &ExecutionContext) -> ExecutionOutput {
    env.engine.execute(c, EventCtx::none(), CancellationToken::new()).await
}

/// New gateway operator-log lines since `from`, mentioning `needle`.
fn op_lines(env: &Env, from: usize, proxy_id: &str) -> Vec<String> {
    env.gateway.log_lines().into_iter().skip(from).filter(|l| l.contains(&format!("\"proxy_id\":\"{proxy_id}\""))).take(10).collect()
}

async fn op_log(env: &Env, from: usize, proxy_id: &str) -> Vec<String> {
    crate::fixtures_policy::wait_for_op_log(|| op_lines(env, from, proxy_id)).await
}

async fn recovery(env: &Env, checks: &mut Checks) -> ExecutionOutput {
    let r = send(env, &ctx(env, "GET", "/ok/")).await;
    checks.success(CheckKind::Recovery, &r);
    r
}

fn ctrl_ok(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fixtures.ok.log.count_requests();
        let o = send(env, &ctx(env, "GET", "/ok/echo")).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(CheckKind::GroundTruth, "backend received the request", env.fixtures.ok.log.count_requests() > before, "");
        c.absent_prefix(&o, "ferrum.token");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn up001(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let o = send(env, &ctx(env, "GET", "/up/dns/")).await;
        c.status_in(&o, &[502, 503]);
        c.operator_class(&op_log(env, from, "up001-dns").await, "up001-dns", &["dns_lookup_error"]);
        c.token(&o, "ferrum.token.connection_failure", env.trusted);
        c.scope(&o, "ferrum.token.connection_failure", SourceScope::GatewayToUpstream);
        c.max_confidence(&o, "ferrum.token.connection_failure", Confidence::Likely);
        c.absent_prefix(&o, "client.dns");
        c.no_confirmed_claim(&o, "tls");
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up001-dns").await }
    })
}

fn up002(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let o = send(env, &ctx(env, "GET", "/up/refused/")).await;
        c.status_in(&o, &[502, 503]);
        c.operator_class(&op_log(env, from, "up002-refused").await, "up002-refused", &["connection_refused"]);
        c.token(&o, "ferrum.token.connection_failure", env.trusted);
        c.max_confidence(&o, "ferrum.token.connection_failure", Confidence::Likely);
        c.absent_prefix(&o, "client.connect");
        c.no_confirmed_claim(&o, "tls");
        c.no_confirmed_claim(&o, "dns");
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up002-refused").await }
    })
}

fn up003(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let o = send(env, &ctx(env, "GET", "/up/connect-stall/")).await;
        c.status_in(&o, &[502, 503, 504]);
        c.operator_class(
            &op_log(env, from, "up003-connect-stall").await,
            "up003-connect-stall",
            &["connection_timeout", "connection_refused", "request_error", "connection_pool_error"],
        );
        c.token_any(&o, &["ferrum.token.connection_failure", "ferrum.token.backend_timeout"], env.trusted);
        c.no_confirmed_claim(&o, "read");
        c.absent_prefix(&o, "client.");
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up003-connect-stall").await }
    })
}

fn up009(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let mut x = ctx(env, "POST", "/up/upload-stall/");
        x.spec.body = Body::Raw { text: "u".repeat(4 * 1024 * 1024), content_type: Some("application/octet-stream".into()) };
        let o = send(env, &x).await;
        c.add(
            CheckKind::GroundTruth,
            "backend accepted the connection and read the head",
            env.fixtures.upload_stall.log.count_requests() >= 1,
            "",
        );
        c.not_success(&o);
        c.operator_class(
            &op_log(env, from, "up009-upload-stall").await,
            "up009-upload-stall",
            &["read_write_timeout", "connection_reset", "connection_closed", "request_error"],
        );
        c.no_confirmed_claim(&o, "read timeout");
        // The gateway answers 504 while the client is still uploading and then
        // resets the socket; depending on timing the client either reads the
        // 504 or only sees the reset (the RST discards the buffered response).
        match o.record.response.as_ref().map(|r| r.status) {
            Some(s) => {
                c.add(CheckKind::GroundTruth, "gateway status is a timeout/error", s == 504 || s == 502, s.to_string());
                c.token_any(&o, &["ferrum.token.backend_timeout", "ferrum.token.backend_error"], env.trusted);
            }
            None => {
                c.has_any(&o, &["exchange.reset_before_response", "exchange.write_failed", "exchange.closed_before_response"]);
                c.has(&o, "request.processing_uncertain");
                c.absent_prefix(&o, "ferrum.");
            }
        }
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up009-upload-stall").await }
    })
}

fn up010(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let o = send(env, &ctx(env, "GET", "/up/header-stall/")).await;
        c.status_in(&o, &[504]);
        c.operator_class(&op_log(env, from, "up010-header-stall").await, "up010-header-stall", &["read_write_timeout"]);
        c.token(&o, "ferrum.token.backend_timeout", env.trusted);
        c.scope(&o, "ferrum.token.backend_timeout", SourceScope::GatewayToUpstream);
        c.add(
            CheckKind::GroundTruth,
            "backend received the request (fixture log)",
            env.fixtures.header_stall.log.count_requests() >= 1,
            "",
        );
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up010-header-stall").await }
    })
}

fn up011(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let o = send(env, &ctx(env, "GET", "/up/body-stall/")).await;
        c.not_success(&o);
        c.has_any(
            &o,
            &["response.body_incomplete", "response.body_idle_timeout", "ferrum.token.backend_timeout", "ferrum.token.backend_error"],
        );
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up011-body-stall").await }
    })
}

fn up012(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let mut x = ctx(env, "POST", "/up/reset/");
        x.spec.body = Body::Json { text: r#"{"order":42}"#.into() };
        let o = send(env, &x).await;
        c.not_success(&o);
        c.add(CheckKind::GroundTruth, "backend received the request before resetting", env.fixtures.reset.log.count_requests() >= 1, "");
        c.no_confirmed_claim(&o, "not dispatched");
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up012-reset").await }
    })
}

fn up013(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let o = send(env, &ctx(env, "GET", "/up/short-body/")).await;
        c.not_success(&o);
        if env.trusted {
            c.has_any(&o, &["response.body_incomplete", "ferrum.token.backend_error", "ferrum.token.connection_failure"]);
        } else {
            c.has_any(&o, &["response.body_incomplete", "http.bad_gateway"]);
        }
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up013-short-body").await }
    })
}

fn up014(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let o = send(env, &ctx(env, "GET", "/up/oversize-buffered/bytes/200000")).await;
        c.not_success(&o);
        c.no_confirmed_claim(&o, "crash");
        c.absent_prefix(&o, "ferrum.backend_passthrough");
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up014-oversize-buffered").await }
    })
}

fn up020(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let o = send(env, &ctx(env, "GET", "/up/post-dispatch/")).await;
        c.status_in(&o, &[502, 503]);
        c.add(CheckKind::GroundTruth, "backend read the request (post-dispatch)", env.fixtures.post_dispatch.log.count_requests() >= 1, "");
        c.token_any(&o, &["ferrum.token.backend_error", "ferrum.token.connection_failure"], env.trusted);
        c.no_confirmed_claim(&o, "not dispatched");
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "up020-post-dispatch").await }
    })
}

fn gw001(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.gateway.log_lines().len();
        let mut last = None;
        for _ in 0..6 {
            let o = send(env, &ctx(env, "GET", "/gw/breaker/status/500")).await;
            let open =
                o.record.response.as_ref().map(|r| r.header_values("x-gateway-error").contains(&"circuit_breaker_open")).unwrap_or(false);
            last = Some(o);
            if open {
                break;
            }
        }
        let o = last.expect("at least one request");
        c.status_in(&o, &[503]);
        c.token(&o, "ferrum.token.circuit_breaker_open", env.trusted);
        c.scope(&o, "ferrum.token.circuit_breaker_open", SourceScope::GatewayAdmission);
        let r = recovery(env, &mut c).await;
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: op_log(env, from, "gw001-breaker").await }
    })
}

fn gw006(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let o = send(env, &ctx(env, "GET", "/gw/no-such-route")).await;
        c.status_in(&o, &[404]);
        c.has(&o, "http.not_found");
        c.max_confidence(&o, "ferrum.outcome", Confidence::Likely);
        // Lookalike: the application's own 404 through a valid route.
        let look = send(env, &ctx(env, "GET", "/ok/status/404")).await;
        let lookalike_attributed = look.record.findings.iter().any(|f| f.code == "ferrum.outcome");
        c.add(
            CheckKind::Diagnosis,
            "application 404 lookalike is not attributed to a gateway route miss",
            !lookalike_attributed,
            format!("{:?}", look.record.findings.iter().map(|f| &f.code).collect::<Vec<_>>()),
        );
        Outcome { main: Some(o), recovery: Some(look), checks: c, operator_log: vec![] }
    })
}

fn gw007(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let o = send(env, &ctx(env, "DELETE", "/gw/methods/")).await;
        c.status_in(&o, &[405]);
        c.has(&o, "http.method_not_allowed");
        c.absent_prefix(&o, "http.unauthorized");
        let r = send(env, &ctx(env, "GET", "/gw/methods/")).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn gw008(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fixtures.ok.log.count_requests();
        let mut x = ctx(env, "POST", "/gw/request-size/echo");
        x.spec.body = Body::Raw { text: "b".repeat(4096), content_type: Some("text/plain".into()) };
        let o = send(env, &x).await;
        c.status_in(&o, &[413]);
        c.has(&o, "http.payload_too_large");
        c.add(CheckKind::GroundTruth, "backend never received the oversized body", env.fixtures.ok.log.count_requests() == before, "");
        let mut small = ctx(env, "POST", "/gw/request-size/echo");
        small.spec.body = Body::Raw { text: "b".repeat(100), content_type: Some("text/plain".into()) };
        let r = send(env, &small).await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn gw016(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let body: String = url::form_urlencoded::byte_serialize(br#"{"error":"Forbidden"}"#).collect();
        let o = send(env, &ctx(env, "GET", &format!("/gw/app-403/status/403?body={body}"))).await;
        c.status_in(&o, &[403]);
        c.has(&o, "http.forbidden");
        c.no_confirmed_claim(&o, "waf");
        let waf_likely = o.record.findings.iter().any(|f| f.confidence >= Confidence::Likely && f.title.to_lowercase().contains("waf"));
        c.add(CheckKind::Diagnosis, "application 403 with WAF-identical body is not called a WAF block", !waf_likely, "");
        c.add(CheckKind::GroundTruth, "the backend itself produced the 403", env.fixtures.app403.log.count_requests() >= 1, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn gw017(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        let o = send(env, &ctx(env, "GET", "/gw/app-500/status/500")).await;
        c.status_in(&o, &[500]);
        c.token(&o, "ferrum.token.backend_error", env.trusted);
        c.no_confirmed_claim(&o, "application");
        c.add(CheckKind::GroundTruth, "backend produced a complete 500", env.fixtures.app500.log.count_requests() >= 1, "");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn gw018(env: &Env) -> Pin<Box<dyn Future<Output = Outcome> + '_>> {
    Box::pin(async move {
        let mut c = Checks::new();
        // Let the active health check mark the only target unhealthy.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let o = send(env, &ctx(env, "GET", "/gw/degraded/")).await;
        c.success(CheckKind::Diagnosis, &o);
        let degraded = o.record.response.as_ref().map(|r| !r.header_values("x-gateway-upstream-status").is_empty()).unwrap_or(false);
        c.add(CheckKind::GroundTruth, "gateway emitted X-Gateway-Upstream-Status", degraded, "");
        if degraded {
            let want = if env.trusted {
                anvil_domain::outcome::WarningCode::DegradedRouting
            } else {
                anvil_domain::outcome::WarningCode::UnverifiedFerrumMarker
            };
            c.add(
                CheckKind::Diagnosis,
                format!("degraded marker surfaced as {want:?}"),
                o.record.outcome.warnings.iter().any(|w| w.code == want),
                "",
            );
        }
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-001", title: "Positive control through the gateway", run: ctrl_ok },
        Def { id: "UP-001", title: "Backend DNS failure", run: up001 },
        Def { id: "UP-002", title: "Backend connect refused", run: up002 },
        Def { id: "UP-003", title: "Backend connect deadline", run: up003 },
        Def { id: "UP-009", title: "Backend upload stall", run: up009 },
        Def { id: "UP-010", title: "Backend first-header stall", run: up010 },
        Def { id: "UP-011", title: "Backend body idle stall", run: up011 },
        Def { id: "UP-012", title: "Backend mid-body reset", run: up012 },
        Def { id: "UP-013", title: "Backend short Content-Length body", run: up013 },
        Def { id: "UP-014", title: "Backend oversized response", run: up014 },
        Def { id: "UP-020", title: "Generic post-dispatch failure", run: up020 },
        Def { id: "GW-001", title: "Open circuit breaker", run: gw001 },
        Def { id: "GW-006", title: "No matched route (+ application 404 lookalike)", run: gw006 },
        Def { id: "GW-007", title: "Method not allowed", run: gw007 },
        Def { id: "GW-008", title: "Request size ceiling", run: gw008 },
        Def { id: "GW-016", title: "Application 403 lookalike", run: gw016 },
        Def { id: "GW-017", title: "Application 5xx", run: gw017 },
        Def { id: "GW-018", title: "Degraded but successful routing", run: gw018 },
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "core",
        about: "Upstream failures, gateway admission and response ownership (HTTP 18080)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let fixtures = CoreFixtures::start().await?;
    let gateway = Gateway::start("core", "core.conf", "core.yaml", &[], 18090, &[]).await?;
    Ok(Env { engine: Engine::new(), fixtures, gateway, trusted: true })
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("core")?;
    let mut env = start().await?;
    let results = harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await?;
    harness::finish(&ctx, &env, &results)?;
    env.gateway.stop().await;
    Ok(results)
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!("core lab running: gateway {GATEWAY} (admin 127.0.0.1:18090); operator log {}", env.gateway.log_path.display());
    println!(
        "routes: /ok/… (healthy), /up/dns /up/refused /up/connect-stall /up/header-stall /up/body-stall /up/reset /up/short-body /up/oversize… /gw/breaker /gw/methods /gw/request-size /gw/app-403 /gw/app-500 /gw/degraded"
    );
    harness::wait_for_shutdown().await?;
    env.gateway.stop().await;
    Ok(())
}
