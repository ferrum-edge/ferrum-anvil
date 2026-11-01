//! `anvil gateway`: list and remove a workspace's Ferrum gateway profiles,
//! the profiles that make Anvil read a destination's Ferrum markers as
//! gateway-authored. Names and hosts from storage (an import may have
//! written them) are printed through `terminal_safe`.

use crate::env::find_workspace;
use anvil_app::App;
use anvil_contract::terminal_safe as t;
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::workspace::Workspace;
use anyhow::{Result, bail};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum GatewayCmd {
    /// List the workspace's Ferrum gateway profiles (by name, case ignored,
    /// then id): id, name, catalog, hosts, and whether trust needs verified
    /// TLS.
    List {
        /// Workspace (id, or a name no other workspace has).
        workspace: String,
    },
    /// Remove a Ferrum gateway profile. Sends to its hosts are no longer
    /// trusted as a Ferrum gateway unless another profile matches them.
    Remove {
        /// Workspace (id, or a name no other workspace has).
        workspace: String,
        /// Profile (id, or a name no other profile in the workspace has).
        profile: String,
    },
}

pub fn gateway_cmd(app: &App, cmd: &GatewayCmd) -> Result<i32> {
    match cmd {
        GatewayCmd::List { workspace } => {
            let ws = find_workspace(app, workspace)?;
            let mut all = app.integrations(&ws.meta.id)?;
            if all.is_empty() {
                println!("workspace '{}' has no Ferrum gateway profiles", t(&ws.name));
                return Ok(0);
            }
            all.sort_by_cached_key(|p| (p.name.to_lowercase(), p.id.to_string()));
            for p in &all {
                println!("{}", line(p));
            }
        }
        GatewayCmd::Remove { workspace, profile } => {
            let ws = find_workspace(app, workspace)?;
            let p = find_profile(app, &ws, profile)?;
            app.delete_integration(&p.id)?;
            println!("removed Ferrum gateway profile '{}' from '{}'", t(&p.name), t(&ws.name));
        }
    }
    Ok(0)
}

fn line(p: &IntegrationProfile) -> String {
    let IntegrationKind::FerrumGateway { hosts, compatibility_id, require_verified_tls, .. } = &p.kind;
    let hosts: Vec<String> = hosts.iter().map(|h| t(&h.port.map_or_else(|| h.host.clone(), |port| format!("{}:{port}", h.host)))).collect();
    let tls = if *require_verified_tls { "verified TLS required" } else { "plain-HTTP trust (lab)" };
    format!("{}  {}  {}  {}  {tls}", p.id, t(&p.name), t(compatibility_id), hosts.join(", "))
}

fn find_profile(app: &App, ws: &Workspace, key: &str) -> Result<IntegrationProfile> {
    let mut all = app.integrations(&ws.meta.id)?;
    if let Some(i) = all.iter().position(|p| p.id.to_string() == key) {
        return Ok(all.swap_remove(i));
    }
    let mut named: Vec<IntegrationProfile> = all.into_iter().filter(|p| p.name.eq_ignore_ascii_case(key)).collect();
    match named.len() {
        1 => Ok(named.remove(0)),
        0 => bail!("workspace '{}' has no Ferrum gateway profile '{}' (`anvil gateway list` shows them)", t(&ws.name), t(key)),
        n => bail!(
            "{n} Ferrum gateway profiles are named '{}'; name the one you mean by its id: {}",
            t(key),
            named.iter().map(|p| p.id.to_string()).collect::<Vec<_>>().join(", ")
        ),
    }
}
