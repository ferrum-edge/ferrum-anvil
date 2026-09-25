//! `anvil-lab` — run failure-matrix scenarios against the real, pinned
//! Ferrum Edge release binary and controllable fixtures.
//!
//! ```text
//! lab/scripts/fetch-gateway.sh            # download + verify the pinned binary
//! cargo run -p anvil-lab -- run core      # start fixtures + gateway, run scenarios, stop
//! cargo run -p anvil-lab -- run core --scenario UP-002
//! ```
//! Results: `results/lab/<timestamp>-<profile>/{summary.json, <ID>.json}`.

mod core;
mod fixtures;
mod gateway;
mod scenario;

use anyhow::Result;
use clap::{Parser, Subcommand};
use scenario::{ScenarioResult, summarize};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "anvil-lab", about = "Ferrum Anvil local failure laboratory")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List scenarios for a profile.
    List { profile: String },
    /// Start fixtures and the gateway, run scenarios, write results, stop.
    Run {
        profile: String,
        #[arg(long)]
        scenario: Vec<String>,
        /// Also run every scenario with the destination NOT configured as a
        /// trusted Ferrum profile (checks that no gateway attribution occurs).
        #[arg(long)]
        untrusted_pass: bool,
    },
    /// Verify the pinned gateway binary and print its identity.
    Verify,
}

#[tokio::main]
async fn main() -> Result<()> {
    anvil_transport::init();
    anvil_fixtures::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Verify => {
            let (bin, lock) = gateway::binary()?;
            println!("ferrum-edge {} ({}) at {} sha256 {}", lock.release, gateway::asset_name(), bin.display(), lock.sha256);
        }
        Cmd::List { profile } => {
            if profile != "core" {
                anyhow::bail!("unknown profile {profile} (available: core)");
            }
            for d in core::all() {
                println!("{:10} {}", d.id, d.title);
            }
        }
        Cmd::Run { profile, scenario, untrusted_pass } => {
            if profile != "core" {
                anyhow::bail!("unknown profile {profile} (available: core)");
            }
            run_core(scenario, untrusted_pass).await?;
        }
    }
    Ok(())
}

async fn run_core(only: Vec<String>, untrusted_pass: bool) -> Result<()> {
    let (bin, lock) = gateway::binary()?;
    let root = gateway::repo_root();
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let out_dir = root.join("results/lab").join(format!("{stamp}-core"));
    std::fs::create_dir_all(&out_dir)?;
    eprintln!("starting core fixtures…");
    let fixtures = fixtures::CoreFixtures::start().await?;
    eprintln!("starting ferrum-edge {} ({})…", lock.release, bin.display());
    let gw = gateway::Gateway::start("core", "core.conf", "core.yaml", &[], 18090, &[]).await?;
    let mut env = core::Env { engine: anvil_engine::Engine::new(), fixtures, gateway: gw, trusted: true };
    let binary_sha = lock.sha256.clone();
    let mut results = Vec::new();
    let passes: Vec<bool> = if untrusted_pass { vec![true, false] } else { vec![true] };
    for trusted in passes {
        env.trusted = trusted;
        for def in core::all() {
            if !only.is_empty() && !only.iter().any(|s| s.eq_ignore_ascii_case(def.id)) {
                continue;
            }
            let started = Instant::now();
            let o = (def.run)(&env).await;
            let mut checks = o.checks;
            if !trusted && let Some(m) = &o.main {
                // Untrusted pass: nothing may be attributed to the gateway.
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
                profile: "core".into(),
                evidence_mode: "public".into(),
                trusted_destination: trusted,
                gateway_release: lock.release.clone(),
                gateway_source_sha: lock.source_sha.clone(),
                gateway_binary_sha256: binary_sha.clone(),
                platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                observed: o.main.as_ref().map(summarize),
                recovery: o.recovery.as_ref().map(summarize),
                operator_log_evidence: o.operator_log,
                checks: checks.items,
                status: status.into(),
                skip_reason: None,
                duration_ms: started.elapsed().as_millis(),
            };
            std::fs::write(out_dir.join(format!("{id}.json")), serde_json::to_vec_pretty(&r)?)?;
            if let Some(m) = &o.main {
                std::fs::write(out_dir.join(format!("{id}.record.json")), serde_json::to_vec_pretty(&m.record)?)?;
            }
            results.push(r);
        }
    }
    let passed = results.iter().filter(|r| r.status == "passed").count();
    let summary = serde_json::json!({
        "profile": "core",
        "gateway_release": lock.release,
        "gateway_source_sha": lock.source_sha,
        "gateway_binary_sha256": binary_sha,
        "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "started": stamp,
        "total": results.len(),
        "passed": passed,
        "failed": results.len() - passed,
        "scenarios": results.iter().map(|r| serde_json::json!({"id": r.id, "status": r.status, "title": r.title})).collect::<Vec<_>>(),
    });
    std::fs::write(out_dir.join("summary.json"), serde_json::to_vec_pretty(&summary)?)?;
    std::fs::copy(&env.gateway.log_path, out_dir.join("gateway-operator.log")).ok();
    env.gateway.stop().await;
    eprintln!("{passed}/{} scenarios passed; results in {}", results.len(), out_dir.display());
    if passed != results.len() {
        std::process::exit(1);
    }
    Ok(())
}
