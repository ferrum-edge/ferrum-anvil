//! Scenarios for the `admission` gateway profile (HTTP 127.0.0.1:18580):
//! process-wide admission knobs that need their own gateway instance —
//! `FERRUM_MAX_REQUESTS=1` (overload refusal before routing) and a 64 KiB
//! retained-response budget (gateway buffer capacity stamped `backend_error`).
//! Config: `lab/gateway/admission.{conf,yaml}`.

use crate::fixtures_policy::{
    AdmissionFixtures, Target, body_text, catalog_ids, catalog_outcome, caveat, codes, enc, header, no_claim, no_scope, op_log, request,
    send, skips,
};
use crate::gateway::Gateway;
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_engine::{Engine, ExecutionOutput};
use anvil_fixtures::GroundTruth;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub const TARGET: Target =
    Target { base: "http://127.0.0.1:18580", port: 18580, profile_name: "lab admission gateway", isolation: "lab-admission" };
const ADMIN: &str = "127.0.0.1:18590";

pub struct Env {
    pub engine: Engine,
    pub fixtures: AdmissionFixtures,
    pub gateway: Gateway,
    pub trusted: bool,
    /// Operator credential for the authenticated admin `/overload` snapshot
    /// (operator ground truth only; never given to the engine).
    pub metrics_token: String,
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
    async fn get(&self, path: &str) -> ExecutionOutput {
        send(&self.engine, &request(&TARGET, self.trusted, "GET", path)).await
    }
    fn mark(&self) -> usize {
        self.gateway.log_lines().len()
    }

    /// Operator view of the overload manager (`GET /overload` with the
    /// metrics bearer token).
    async fn overload_snapshot(&self) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let fetch = async {
            let mut s = tokio::net::TcpStream::connect(ADMIN).await?;
            let req = format!(
                "GET /overload HTTP/1.1\r\nHost: {ADMIN}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
                self.metrics_token
            );
            s.write_all(req.as_bytes()).await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).into_owned())
        };
        match tokio::time::timeout(Duration::from_secs(3), fetch).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => format!("error: {e}"),
            Err(_) => "error: timeout".into(),
        }
    }

    /// The overload manager's `level` (`normal` / `pressure` / `critical`).
    async fn overload_level(&self) -> Option<String> {
        let raw = self.overload_snapshot().await;
        let body = raw.split_once("\r\n\r\n").map(|(_, b)| b)?;
        let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
        v.get("level").and_then(|l| l.as_str()).map(String::from)
    }

    /// Poll until the overload manager reports `normal` (it re-evaluates every
    /// FERRUM_OVERLOAD_CHECK_INTERVAL_MS = 100 ms, so the fence outlives the
    /// occupant by up to one tick). Returns the wait, or `None` on timeout.
    async fn wait_normal(&self, max: Duration) -> Option<Duration> {
        let t0 = std::time::Instant::now();
        while t0.elapsed() < max {
            if self.overload_level().await.as_deref() == Some("normal") {
                return Some(t0.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

fn has_code(o: &ExecutionOutput, code: &str) -> bool {
    o.record.findings.iter().any(|f| f.code == code)
}

fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        env.wait_normal(Duration::from_secs(3)).await;
        let before = env.fixtures.sized.log.count_requests();
        let o = env.get("/gw/probe/bytes/100").await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(CheckKind::GroundTruth, "backend received the request", env.fixtures.sized.log.count_requests() == before + 1, "");
        c.absent_prefix(&o, "ferrum.token");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

/// UP-015: the backend delivers a valid 256 KiB response; the gateway cannot
/// reserve retained-buffer capacity and answers 503 with `backend_error`.
fn up015(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        env.wait_normal(Duration::from_secs(3)).await;
        let from = env.mark();
        let log = &env.fixtures.sized.log;
        let before = log.count_requests();
        let o = env.get("/up/buffer-capacity/bytes/262144").await;
        c.add(CheckKind::GroundTruth, "backend received the request", log.count_requests() == before + 1, "");
        let backend_status = log.entries().iter().rev().find_map(|e| match e.event {
            GroundTruth::ResponseStarted { status } => Some(status),
            _ => None,
        });
        c.add(
            CheckKind::GroundTruth,
            "backend answered 200 (a valid response)",
            backend_status == Some(200),
            format!("{backend_status:?}"),
        );
        let ops = op_log(&env.gateway, from, "up015-buffer-capacity");
        c.operator_class(&ops, "up015-buffer-capacity", &["gateway_buffer_capacity"]);
        c.status_in(&o, &[503]);
        c.add(
            CheckKind::GroundTruth,
            "gateway-authored capacity body",
            body_text(&o).contains("Response buffering capacity exceeded"),
            body_text(&o),
        );
        c.token(&o, "ferrum.token.backend_error", env.trusted);
        c.max_confidence(&o, "ferrum.token.backend_error", Confidence::Likely);
        // The matrix's forbidden claim: blaming the application because the
        // marker says backend_error.
        c.absent_prefix(&o, "ferrum.backend_passthrough");
        no_scope(&mut c, &o, SourceScope::UpstreamApplication, Confidence::Likely);
        no_scope(&mut c, &o, SourceScope::GatewayToUpstream, Confidence::Likely);
        no_claim(&mut c, &o, "unhealthy", Confidence::Unknown);
        if env.trusted {
            c.scope(&o, "ferrum.token.backend_error", SourceScope::Unknown);
            caveat(&mut c, &o, "ferrum.token.backend_error", "gateway-local limit");
            // 0.9.5 has two sources of this exact signal (the core budget and a
            // custom plugin without a declared body producer): the honest
            // result is the ambiguous finding naming the buffer-capacity cause.
            let ids = catalog_ids(&o);
            c.add(
                CheckKind::Diagnosis,
                "catalog candidates include gateway.capacity.response_buffer",
                ids.iter().any(|i| i == "gateway.capacity.response_buffer"),
                format!("{ids:?}"),
            );
            c.max_confidence(&o, "ferrum.outcome", Confidence::Likely);
            c.max_confidence(&o, "ferrum.outcome_ambiguous", Confidence::Unknown);
        }
        // The refusal can briefly raise the overload monitor; let it settle so
        // the lookalike and recovery see the route, not an admission refusal.
        env.wait_normal(Duration::from_secs(3)).await;
        // Lookalike: the application's own 503 on the same buffered route.
        let look = env.get("/up/buffer-capacity/status/503").await;
        c.token(&look, "ferrum.token.backend_error", env.trusted);
        c.add(
            CheckKind::Diagnosis,
            "application 503 is not called a gateway buffer-capacity refusal",
            !catalog_ids(&look).iter().any(|i| i == "gateway.capacity.response_buffer"),
            format!("{:?}", codes(&look)),
        );
        // Recovery: a 32 KiB response fits the budget.
        env.wait_normal(Duration::from_secs(3)).await;
        let r = env.get("/up/buffer-capacity/bytes/32768").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

/// GW-002: one in-flight request saturates `FERRUM_MAX_REQUESTS=1`; new
/// requests are refused with `overload` before routing.
fn gw002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let settled = env.wait_normal(Duration::from_secs(3)).await;
        c.add(CheckKind::GroundTruth, "overload manager normal before the stimulus", settled.is_some(), "");
        let from = env.mark();
        let sized = &env.fixtures.sized.log;
        let (s0, h0) = (sized.count_requests(), env.fixtures.staller.log.count_requests());
        let occupant = request(&TARGET, env.trusted, "GET", "/gw/occupant/delay-headers/3000");
        // Hold the slot, let the 100 ms overload monitor observe it, then probe.
        let (first, (level, o, unrouted)) = tokio::join!(send(&env.engine, &occupant), async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let level = env.overload_level().await;
            let o = env.get("/gw/probe/bytes/100").await;
            let unrouted = env.get("/no-such-route").await;
            (level, o, unrouted)
        });
        c.success(CheckKind::GroundTruth, &first);
        c.add(CheckKind::GroundTruth, "the occupant held the only request slot", env.fixtures.staller.log.count_requests() == h0 + 1, "");
        c.add(CheckKind::GroundTruth, "refused requests never reached a backend", sized.count_requests() == s0, "");
        c.add(
            CheckKind::GroundTruth,
            "operator /overload level was critical during the hold",
            level.as_deref() == Some("critical"),
            format!("{level:?}"),
        );
        // The fence lifts at the next monitor tick after the slot frees.
        let lifted = env.wait_normal(Duration::from_secs(3)).await;
        c.add(CheckKind::GroundTruth, "overload fence lifted after the occupant finished", lifted.is_some(), format!("{lifted:?}"));
        let mut ops: Vec<String> = env
            .gateway
            .log_lines()
            .into_iter()
            .skip(from)
            .filter(|l| l.contains("Overload CRITICAL") || l.contains("Overload recovered"))
            .take(4)
            .collect();
        c.add(
            CheckKind::GroundTruth,
            "gateway logged 'Overload CRITICAL: rejecting new requests'",
            ops.iter().any(|l| l.contains("Overload CRITICAL")),
            "",
        );
        ops.push(format!("admin /overload level during hold: {level:?}; normal again after {lifted:?}"));
        c.status_in(&o, &[503]);
        c.token(&o, "ferrum.token.overload", env.trusted);
        c.scope(&o, "ferrum.token.overload", SourceScope::GatewayAdmission);
        c.max_confidence(&o, "ferrum.token.overload", Confidence::Likely);
        c.absent_prefix(&o, "ferrum.backend_passthrough");
        no_scope(&mut c, &o, SourceScope::UpstreamApplication, Confidence::Likely);
        no_claim(&mut c, &o, "cpu", Confidence::Unknown);
        if env.trusted {
            caveat(&mut c, &o, "ferrum.token.overload", "cpu");
            let got = catalog_outcome(&o);
            c.add(
                CheckKind::Diagnosis,
                "catalog outcome gateway.admission.overload_or_drain",
                got.as_deref() == Some("gateway.admission.overload_or_drain"),
                format!("{got:?}"),
            );
        }
        // The refusal happens before routing: an unrouted path gets the same
        // overload answer instead of a 404.
        c.add(
            CheckKind::GroundTruth,
            "admission refusal precedes routing (unrouted path also 503 overload)",
            header(&unrouted, "x-gateway-error") == ["overload"],
            format!("{:?}", unrouted.record.response.as_ref().map(|r| r.status)),
        );
        c.absent_prefix(&unrouted, "http.not_found");
        // Lookalike: the application's own 503 with byte-identical text.
        let look = env.get(&format!("/gw/probe/status/503?body={}", enc(r#"{"error":"Service overloaded"}"#))).await;
        c.add(CheckKind::GroundTruth, "lookalike body is byte-identical", body_text(&look) == body_text(&o), "");
        c.token(&look, "ferrum.token.backend_error", env.trusted);
        c.add(
            CheckKind::Diagnosis,
            "application 503 gets no overload claim",
            !has_code(&look, "ferrum.token.overload"),
            format!("{:?}", codes(&look)),
        );
        c.add(
            CheckKind::Diagnosis,
            "application 503 is not matched to the overload outcome",
            catalog_outcome(&look).as_deref() != Some("gateway.admission.overload_or_drain"),
            "",
        );
        // Recovery: the slot is free again.
        let r = env.get("/gw/probe/bytes/32768").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: ops }
    })
}

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-ADM-001", title: "Positive control through the admission gateway", run: ctrl },
        Def { id: "UP-015", title: "Gateway retained-buffer exhaustion stamped backend_error", run: up015 },
        Def { id: "GW-002", title: "Overload refusal before routing (+ application 503 lookalike)", run: gw002 },
    ]
}

/// Family members this profile cannot drive live (reported as skips, never passes).
const SKIPPED: &[(&str, &str, &str)] = &[(
    "GW-005",
    "Stale DP fence (config_stale)",
    "Needs a real CP + DP pair (a file-mode gateway never installs the DP freshness fence, src/modes/data_plane.rs:44); \
     it is owned by the cpdp profile (ports 187xx/197xx), not this file-mode admission instance.",
)];

pub fn profile() -> Profile {
    Profile {
        name: "admission",
        about: "Process-wide admission: overload refusal, retained-buffer capacity (HTTP 18580)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let fixtures = AdmissionFixtures::start().await?;
    let mut b = [0u8; 24];
    rand::fill(&mut b);
    let metrics_token = hex::encode(b);
    let gateway = Gateway::start(
        "admission",
        "admission.conf",
        "admission.yaml",
        &[],
        18590,
        &[("FERRUM_METRICS_BEARER_TOKEN", metrics_token.clone())],
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(Env { engine: Engine::new(), fixtures, gateway, trusted: true, metrics_token })
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("admission")?;
    let mut env = start().await?;
    let mut results = match harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await {
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
    println!("admission lab running: gateway {} (admin {ADMIN}); operator log {}", TARGET.base, env.gateway.log_path.display());
    println!("routes: /up/buffer-capacity/bytes/{{n}} /gw/occupant/delay-headers/{{ms}} /gw/probe/bytes/{{n}}");
    harness::wait_for_shutdown().await?;
    env.gateway.stop().await;
    Ok(())
}
