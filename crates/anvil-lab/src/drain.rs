//! Scenarios for the `drain` gateway profile (HTTP 127.0.0.1:18680): graceful
//! shutdown with a 3 s pre-drain and a 10 s drain window
//! (`lab/gateway/drain.{conf,yaml}`). The drain scenario SIGTERMs its own
//! gateway, observes connections during the drain, then starts a fresh
//! instance for the recovery request (and for the next pass).

use crate::fixtures_policy::{DrainFixtures, Target, caveat, codes, header, no_claim, request, send};
use crate::gateway::{self, Gateway};
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub const TARGET: Target =
    Target { base: "http://127.0.0.1:18680", port: 18680, profile_name: "lab drain gateway", isolation: "lab-drain" };
const ADMIN: &str = "127.0.0.1:18690";
/// FERRUM_SHUTDOWN_PREDRAIN_SECONDS in drain.conf.
const PREDRAIN: Duration = Duration::from_secs(3);

pub struct Env {
    pub engine: Engine,
    pub fixtures: DrainFixtures,
    /// The current gateway instance (the drain scenario replaces it).
    pub gateway: Mutex<Option<Gateway>>,
    pub log_path: PathBuf,
    /// Operator logs of drained instances, archived before each restart.
    pub archived: std::sync::Mutex<Vec<PathBuf>>,
    pub trusted: bool,
    fresh: AtomicU64,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<PathBuf> {
        let mut v = vec![self.log_path.clone()];
        v.extend(self.archived.lock().map(|a| a.clone()).unwrap_or_default());
        v
    }
}

impl Env {
    /// A request on its own connection pool, so it must open a new TCP
    /// connection to the gateway (tests the listener, not a pooled socket).
    fn fresh(&self, path: &str) -> ExecutionContext {
        let mut c = request(&TARGET, self.trusted, "GET", path);
        c.isolation = format!("lab-drain-fresh-{}", self.fresh.fetch_add(1, Ordering::Relaxed));
        c
    }
    async fn send(&self, c: &ExecutionContext) -> ExecutionOutput {
        send(&self.engine, c).await
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

async fn start_gateway() -> anyhow::Result<Gateway> {
    let gw = Gateway::start("drain", "drain.conf", "drain.yaml", &[], 18690, &[]).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(gw)
}

/// Make sure a gateway is running; records a failed check when it cannot start.
async fn ensure_gateway(env: &Env, c: &mut Checks) -> bool {
    let mut g = env.gateway.lock().await;
    if g.is_some() {
        return true;
    }
    match start_gateway().await {
        Ok(gw) => {
            *g = Some(gw);
            true
        }
        Err(e) => {
            c.add(CheckKind::GroundTruth, "drain gateway running", false, e.to_string());
            false
        }
    }
}

fn sigterm(pid: u32) -> bool {
    std::process::Command::new("kill").arg("-TERM").arg(pid.to_string()).status().map(|s| s.success()).unwrap_or(false)
}

fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        if !ensure_gateway(env, &mut c).await {
            return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
        }
        let before = env.fixtures.fast.log.count_requests();
        let o = env.send(&env.fresh("/gw/fast/")).await;
        c.success(CheckKind::Diagnosis, &o);
        c.add(CheckKind::GroundTruth, "backend received the request", env.fixtures.fast.log.count_requests() == before + 1, "");
        c.absent_prefix(&o, "ferrum.token");
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

/// GW-003: graceful drain. After SIGTERM: health reports draining while the
/// pre-drain still serves; after the pre-drain new connections are refused;
/// the in-flight request completes with `Connection: close`.
fn gw003(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        if !ensure_gateway(env, &mut c).await {
            return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
        }
        let mut guard = env.gateway.lock().await;
        let Some(gw) = guard.as_mut() else {
            return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
        };
        let pid = gw.child.id().unwrap_or(0);
        let from = gw.log_lines().len();
        let slow0 = env.fixtures.slow.log.count_requests();

        // A keep-alive connection opened before the drain starts.
        let mut keepalive = request(&TARGET, env.trusted, "GET", "/gw/fast/");
        keepalive.isolation = format!("lab-drain-keepalive-{}", env.fresh.fetch_add(1, Ordering::Relaxed));
        let ka0 = env.send(&keepalive).await;
        c.success(CheckKind::GroundTruth, &ka0);

        let slow_ctx = env.fresh("/gw/slow/delay-headers/6000");
        let (slow, (term_sent, health, predrain, refused, reused, raw_connect)) = tokio::join!(env.send(&slow_ctx), async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let t0 = Instant::now();
            let term_sent = sigterm(pid);
            tokio::time::sleep(Duration::from_millis(300)).await;
            let health = gateway::http_get(ADMIN, "/health").await.unwrap_or_else(|e| format!("error: {e}"));
            let predrain = env.send(&env.fresh("/gw/fast/")).await;
            tokio::time::sleep((PREDRAIN + Duration::from_millis(600)).saturating_sub(t0.elapsed())).await;
            let refused = env.send(&env.fresh("/gw/fast/")).await;
            let reused = env.send(&keepalive).await;
            let raw_connect = tokio::net::TcpStream::connect(TARGET.base.trim_start_matches("http://")).await.err().map(|e| e.kind());
            (term_sent, health, predrain, refused, reused, raw_connect)
        });
        c.add(CheckKind::GroundTruth, "SIGTERM delivered to the gateway", term_sent, pid.to_string());

        // (a) Operator view: draining; the proxy still serves in pre-drain.
        c.add(
            CheckKind::GroundTruth,
            "admin /health reports 503 draining",
            health.starts_with("HTTP/1.1 503") && health.contains("draining"),
            health.lines().last().unwrap_or("").to_string(),
        );
        c.success(CheckKind::Diagnosis, &predrain);
        c.absent_prefix(&predrain, "ferrum.");

        // (b) After the pre-drain the listener is closed: Anvil must report a
        // client-leg refusal, not a crashed destination or a gateway verdict.
        c.add(
            CheckKind::GroundTruth,
            "listener closed after the pre-drain (raw connect refused)",
            raw_connect == Some(std::io::ErrorKind::ConnectionRefused),
            format!("{raw_connect:?}"),
        );
        c.not_success(&refused);
        c.has(&refused, "client.connect.refused");
        c.scope(&refused, "client.connect.refused", SourceScope::ClientToPeer);
        c.absent_prefix(&refused, "ferrum.");
        no_claim(&mut c, &refused, "crash", Confidence::Unknown);
        caveat(&mut c, &refused, "client.connect.refused", "restarting");

        // (c) The in-flight request finishes inside the drain window.
        c.success(CheckKind::Diagnosis, &slow);
        c.add(
            CheckKind::GroundTruth,
            "in-flight response carries Connection: close",
            header(&slow, "connection").iter().any(|v| v.eq_ignore_ascii_case("close")),
            format!("{:?}", header(&slow, "connection")),
        );
        c.add(CheckKind::GroundTruth, "slow backend served the in-flight request", env.fixtures.slow.log.count_requests() == slow0 + 1, "");

        // (d) Racy by design: a request on the pre-drain keep-alive socket may
        // meet a 503 overload refusal, a closed socket, or a refused re-dial.
        // Whatever happened, Anvil's explanation must match it.
        let reused_status = reused.record.response.as_ref().map(|r| r.status);
        let branch = match reused_status {
            Some(503) => {
                c.token(&reused, "ferrum.token.overload", env.trusted);
                c.absent_prefix(&reused, "ferrum.backend_passthrough");
                "503 overload on the existing connection"
            }
            Some(200) => {
                c.success(CheckKind::Diagnosis, &reused);
                "served on the existing connection"
            }
            Some(_) => {
                c.add(CheckKind::Diagnosis, "unexpected status on the reused connection", false, format!("{reused_status:?}"));
                "unexpected status"
            }
            None => {
                c.has_any(
                    &reused,
                    &[
                        "client.connect.refused",
                        "exchange.closed_before_response",
                        "exchange.reset_before_response",
                        "exchange.write_failed",
                    ],
                );
                c.absent_prefix(&reused, "ferrum.");
                "no response (closed socket or refused re-dial)"
            }
        };
        c.add(CheckKind::GroundTruth, format!("keep-alive request during drain: {branch}"), true, format!("{:?}", codes(&reused)));

        // The drained instance exits on its own.
        let exited = tokio::time::timeout(Duration::from_secs(15), gw.child.wait()).await;
        c.add(
            CheckKind::GroundTruth,
            "gateway exited after draining",
            matches!(exited, Ok(Ok(ref s)) if s.success()),
            format!("{exited:?}"),
        );
        let lines = gw.log_lines();
        let drain_lines: Vec<String> = lines
            .iter()
            .skip(from)
            .filter(|l| l.contains("Draining active connections") || l.contains("drained successfully") || l.contains("shut down cleanly"))
            .cloned()
            .collect();
        c.add(
            CheckKind::GroundTruth,
            "operator log: all connections and requests drained",
            drain_lines.iter().any(|l| l.contains("drained successfully")),
            "",
        );
        let slow_line: Vec<String> = lines.iter().skip(from).filter(|l| l.contains("\"proxy_id\":\"gw003-slow\"")).cloned().collect();
        let mut operator_log = drain_lines;
        operator_log.extend(slow_line);

        // Archive the drained instance's log, then recover with a fresh one.
        let n = env.archived.lock().map(|a| a.len()).unwrap_or(0);
        let archived = gw.run_dir.join(format!("gateway-drained-{n}.log"));
        if std::fs::copy(&gw.log_path, &archived).is_ok()
            && let Ok(mut a) = env.archived.lock()
        {
            a.push(archived);
        }
        *guard = None;
        let r = match start_gateway().await {
            Ok(new_gw) => {
                *guard = Some(new_gw);
                drop(guard);
                let r = env.send(&env.fresh("/gw/fast/")).await;
                c.success(CheckKind::Recovery, &r);
                Some(r)
            }
            Err(e) => {
                c.add(CheckKind::Recovery, "restart the gateway", false, e.to_string());
                None
            }
        };
        Outcome { main: Some(refused), recovery: r, checks: c, operator_log }
    })
}

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-DRN-001", title: "Positive control through the drain gateway", run: ctrl },
        Def { id: "GW-003", title: "Graceful drain: pre-drain served, new connects refused, in-flight completes", run: gw003 },
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "drain",
        about: "Graceful shutdown: drain refusal and in-flight completion (HTTP 18680; destroyed and restarted by GW-003)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let fixtures = DrainFixtures::start().await?;
    let gw = start_gateway().await?;
    let log_path = gw.log_path.clone();
    Ok(Env {
        engine: Engine::new(),
        fixtures,
        gateway: Mutex::new(Some(gw)),
        log_path,
        archived: std::sync::Mutex::new(vec![]),
        trusted: true,
        fresh: AtomicU64::new(0),
    })
}

async fn stop(env: &Env) {
    if let Some(gw) = env.gateway.lock().await.take() {
        gw.stop().await;
    }
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("drain")?;
    let mut env = start().await?;
    let results = match harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await {
        Ok(r) => r,
        Err(e) => {
            stop(&env).await;
            return Err(e);
        }
    };
    harness::finish(&ctx, &env, &results)?;
    stop(&env).await;
    Ok(results)
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!("drain lab running: gateway {} (admin {ADMIN}); operator log {}", TARGET.base, env.log_path.display());
    println!("routes: /gw/fast/ /gw/slow/delay-headers/{{ms}}; SIGTERM the gateway to observe the drain");
    harness::wait_for_shutdown().await?;
    stop(&env).await;
    Ok(())
}
