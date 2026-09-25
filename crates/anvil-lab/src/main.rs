//! `anvil-lab` — run failure-matrix scenarios against the real, pinned
//! Ferrum Edge release binary and controllable fixtures.
//!
//! ```text
//! lab/scripts/fetch-gateway.sh            # download + verify the pinned binary
//! cargo run -p anvil-lab -- run core      # start fixtures + gateway, run scenarios, stop
//! cargo run -p anvil-lab -- run core --scenario UP-002
//! ```
//! Results: `results/lab/<timestamp>-<profile>/{summary.json, <ID>.json}`.

mod admission;
mod auth;
mod core;
mod drain;
mod fixtures;
mod fixtures_auth;
mod fixtures_policy;
mod fixtures_tls;
mod gateway;
mod harness;
mod policy;
mod profiles;
mod scenario;
mod tls;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "anvil-lab", about = "Ferrum Anvil local failure laboratory")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List profiles, or the scenarios of one profile.
    List { profile: Option<String> },
    /// Start fixtures and the gateway, run scenarios, write results, stop.
    /// `all` runs every profile in turn.
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
    /// Start fixtures + gateway for a profile and keep them running until Ctrl-C
    /// (for manual desktop/CLI sessions and screenshots).
    Up { profile: String },
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
        Cmd::Up { profile } => (profiles::find(&profile)?.up)().await?,
        Cmd::List { profile: None } => {
            for p in profiles::all() {
                println!("{:10} {:3} scenarios  {}", p.name, (p.scenarios)().len(), p.about);
            }
        }
        Cmd::List { profile: Some(profile) } => {
            for (id, title) in (profiles::find(&profile)?.scenarios)() {
                println!("{id:10} {title}");
            }
        }
        Cmd::Run { profile, scenario, untrusted_pass } => {
            let selected = if profile == "all" { profiles::all() } else { vec![profiles::find(&profile)?] };
            let (mut passed, mut failed, mut skipped) = (0, 0, 0);
            for p in selected {
                let results = (p.run)(profiles::RunArgs { only: scenario.clone(), untrusted_pass }).await?;
                passed += results.iter().filter(|r| r.status == "passed").count();
                failed += results.iter().filter(|r| r.status == "failed").count();
                skipped += results.iter().filter(|r| r.status == "skipped").count();
            }
            eprintln!("total: {passed} passed, {failed} failed, {skipped} skipped");
            if failed > 0 {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
