//! Profile-independent scenario harness: runs scenario definitions against a
//! profile environment (trusted and optionally untrusted destination passes),
//! writes one result file per scenario plus a summary.

use crate::gateway::{self, Lock};
use crate::scenario::{Checks, ScenarioResult, summarize};
use anvil_engine::ExecutionOutput;
use anyhow::Result;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Instant;

/// What one scenario observed. `main` is the stimulus; `recovery` is the
/// positive request run after the fault is removed (or on a healthy route).
pub struct Outcome {
    pub main: Option<ExecutionOutput>,
    pub recovery: Option<ExecutionOutput>,
    pub checks: Checks,
    /// Operator-log lines used as ground truth. Never fed to the engine.
    pub operator_log: Vec<String>,
}

pub type ScenarioFn<E> = for<'a> fn(&'a E) -> Pin<Box<dyn Future<Output = Outcome> + 'a>>;

pub struct Def<E> {
    pub id: &'static str,
    pub title: &'static str,
    pub run: ScenarioFn<E>,
}

/// A running profile environment (fixtures + gateway).
pub trait LabEnv {
    /// Whether requests declare the destination as a trusted Ferrum gateway.
    fn set_trusted(&mut self, trusted: bool);
    /// Operator logs to archive beside the results.
    fn operator_logs(&self) -> Vec<PathBuf>;
}

pub struct RunCtx {
    pub profile: String,
    pub out_dir: PathBuf,
    pub stamp: String,
    pub lock: Lock,
}

impl RunCtx {
    pub fn new(profile: &str) -> Result<Self> {
        let (_bin, lock) = gateway::binary()?;
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let out_dir = gateway::repo_root().join("results/lab").join(format!("{stamp}-{profile}"));
        std::fs::create_dir_all(&out_dir)?;
        Ok(RunCtx { profile: profile.into(), out_dir, stamp, lock })
    }

    fn platform() -> String {
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
    }

    /// A result for a scenario that could not run in this environment. A skip
    /// is never counted as a pass.
    #[allow(dead_code)] // for profiles whose prerequisites can be missing
    pub fn skipped(&self, id: &str, title: &str, reason: &str) -> ScenarioResult {
        ScenarioResult {
            id: id.into(),
            title: title.into(),
            profile: self.profile.clone(),
            evidence_mode: "public".into(),
            trusted_destination: true,
            gateway_release: self.lock.release.clone(),
            gateway_source_sha: self.lock.source_sha.clone(),
            gateway_binary_sha256: self.lock.sha256.clone(),
            platform: Self::platform(),
            observed: None,
            recovery: None,
            operator_log_evidence: vec![],
            checks: vec![],
            status: "skipped".into(),
            skip_reason: Some(reason.into()),
            duration_ms: 0,
        }
    }
}

/// Run `defs` (filtered by `only`) once with a trusted destination and, when
/// requested, again untrusted — where no gateway attribution may occur.
pub async fn run_defs<E: LabEnv>(
    ctx: &RunCtx,
    env: &mut E,
    defs: Vec<Def<E>>,
    only: &[String],
    untrusted_pass: bool,
) -> Result<Vec<ScenarioResult>> {
    let mut results = Vec::new();
    let passes: Vec<bool> = if untrusted_pass { vec![true, false] } else { vec![true] };
    for trusted in passes {
        env.set_trusted(trusted);
        for def in &defs {
            if !only.is_empty() && !only.iter().any(|s| s.eq_ignore_ascii_case(def.id)) {
                continue;
            }
            let started = Instant::now();
            let o = (def.run)(env).await;
            let mut checks = o.checks;
            if !trusted && let Some(m) = &o.main {
                checks.absent_prefix(m, "ferrum.token");
                checks.absent_prefix(m, "ferrum.outcome");
            }
            let status = if checks.all_passed() { "passed" } else { "failed" };
            let id = if trusted { def.id.to_string() } else { format!("{}-untrusted", def.id) };
            eprintln!("{:22} {:7} {}", id, status, def.title);
            for c in checks.items.iter().filter(|c| !c.passed) {
                eprintln!("    ✗ [{:?}] {} — {}", c.kind, c.name, c.detail);
            }
            let r = ScenarioResult {
                id: id.clone(),
                title: def.title.into(),
                profile: ctx.profile.clone(),
                evidence_mode: "public".into(),
                trusted_destination: trusted,
                gateway_release: ctx.lock.release.clone(),
                gateway_source_sha: ctx.lock.source_sha.clone(),
                gateway_binary_sha256: ctx.lock.sha256.clone(),
                platform: RunCtx::platform(),
                observed: o.main.as_ref().map(summarize),
                recovery: o.recovery.as_ref().map(summarize),
                operator_log_evidence: o.operator_log,
                checks: checks.items,
                status: status.into(),
                skip_reason: None,
                duration_ms: started.elapsed().as_millis(),
            };
            std::fs::write(ctx.out_dir.join(format!("{id}.json")), serde_json::to_vec_pretty(&r)?)?;
            if let Some(m) = &o.main {
                std::fs::write(ctx.out_dir.join(format!("{id}.record.json")), serde_json::to_vec_pretty(&m.record)?)?;
            }
            results.push(r);
        }
    }
    Ok(results)
}

/// Write `summary.json`, archive operator logs and return (passed, failed).
/// Skipped scenarios are reported separately and never counted as passed.
pub fn finish<E: LabEnv>(ctx: &RunCtx, env: &E, results: &[ScenarioResult]) -> Result<(usize, usize)> {
    for r in results.iter().filter(|r| r.status == "skipped") {
        std::fs::write(ctx.out_dir.join(format!("{}.json", r.id)), serde_json::to_vec_pretty(r)?)?;
    }
    let passed = results.iter().filter(|r| r.status == "passed").count();
    let failed = results.iter().filter(|r| r.status == "failed").count();
    let skipped = results.iter().filter(|r| r.status == "skipped").count();
    let summary = serde_json::json!({
        "profile": ctx.profile,
        "gateway_release": ctx.lock.release,
        "gateway_source_sha": ctx.lock.source_sha,
        "gateway_binary_sha256": ctx.lock.sha256,
        "platform": RunCtx::platform(),
        "started": ctx.stamp,
        "total": results.len(),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "scenarios": results.iter().map(|r| serde_json::json!({
            "id": r.id, "status": r.status, "title": r.title, "skip_reason": r.skip_reason,
        })).collect::<Vec<_>>(),
    });
    std::fs::write(ctx.out_dir.join("summary.json"), serde_json::to_vec_pretty(&summary)?)?;
    for (i, p) in env.operator_logs().iter().enumerate() {
        let name = if i == 0 { "gateway-operator.log".to_string() } else { format!("gateway-operator-{i}.log") };
        std::fs::copy(p, ctx.out_dir.join(name)).ok();
    }
    eprintln!("{}: {passed} passed, {failed} failed, {skipped} skipped; results in {}", ctx.profile, ctx.out_dir.display());
    Ok((passed, failed))
}

/// Wait for Ctrl-C or SIGTERM, so `up` always stops its gateway child (a
/// signal that kills the process skips destructors and would orphan it).
pub async fn wait_for_shutdown() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r?,
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
