//! Lab profile registry. Each profile owns its fixtures, gateway config
//! (`lab/gateway/<profile>.*`), port block (see docs/audit/gateway-lab-config.md
//! §3) and scenario list; the harness is shared. To add a profile, create a
//! module exposing `pub fn profile() -> Profile` and register it in `all()`.

use crate::scenario::ScenarioResult;
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T>>>;

pub struct RunArgs {
    /// Scenario ids to run (empty = all).
    pub only: Vec<String>,
    /// Repeat every scenario with the destination not declared as Ferrum.
    pub untrusted_pass: bool,
}

pub struct Profile {
    pub name: &'static str,
    pub about: &'static str,
    /// (id, title) of every scenario, in run order.
    pub scenarios: fn() -> Vec<(&'static str, &'static str)>,
    /// Start fixtures and gateway, run scenarios, write results, stop.
    /// Returns every result, including explicit skips.
    pub run: fn(RunArgs) -> BoxFut<Result<Vec<ScenarioResult>>>,
    /// Start fixtures and gateway and keep them up until Ctrl-C.
    pub up: fn() -> BoxFut<Result<()>>,
}

pub fn all() -> Vec<Profile> {
    vec![
        crate::core::profile(),
        crate::policy::profile(),
        crate::admission::profile(),
        crate::drain::profile(),
        crate::tls::profile(),
        crate::auth::profile(),
        crate::streams::profile(),
        crate::cpdp::profile(),
        crate::h3x::profile(),
        crate::mesh::profile(),
        crate::proxyproto::profile(),
        crate::workload::profile(),
        crate::early::profile(),
        crate::mcp::profile(),
    ]
}

/// `--scenario` selectors that name no scenario (run or explicitly skipped)
/// of `profiles`, matched case-insensitively. A run refuses them before any
/// fixture starts, so a typo never passes as an empty, successful run.
pub fn unknown_selectors(profiles: &[Profile], selectors: &[String]) -> Vec<String> {
    let known: Vec<&'static str> = profiles.iter().flat_map(|p| (p.scenarios)()).map(|(id, _)| id).collect();
    selectors.iter().filter(|s| !known.iter().any(|id| id.eq_ignore_ascii_case(s))).cloned().collect()
}

pub fn find(name: &str) -> Result<Profile> {
    all().into_iter().find(|p| p.name == name).ok_or_else(|| {
        anyhow::anyhow!("unknown profile {name} (available: {})", all().iter().map(|p| p.name).collect::<Vec<_>>().join(", "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unknown_selectors_are_reported_alone_or_mixed() {
        let mcp = vec![find("mcp").unwrap()];
        assert_eq!(unknown_selectors(&mcp, &sel(&["MCP-DOES-NOT-EXIST"])), sel(&["MCP-DOES-NOT-EXIST"]));
        assert_eq!(unknown_selectors(&mcp, &sel(&["mcp-003", "MCP-NOPE"])), sel(&["MCP-NOPE"]));
        assert!(unknown_selectors(&mcp, &sel(&["mcp-003", "MCP-004"])).is_empty());
        assert!(unknown_selectors(&mcp, &[]).is_empty());
    }

    #[test]
    fn explicit_skips_and_the_all_profile_are_known() {
        assert!(unknown_selectors(&[find("policy").unwrap()], &sel(&["gw-014-geo"])).is_empty());
        assert!(unknown_selectors(&[find("admission").unwrap()], &sel(&["UP-018-H2"])).is_empty());
        assert!(unknown_selectors(&[find("tls").unwrap()], &sel(&["TLS-003"])).is_empty());
        // `all` validates against the union of every profile.
        assert!(unknown_selectors(&all(), &sel(&["MCP-003", "GW-014-GEO", "TLS-003"])).is_empty());
        assert_eq!(unknown_selectors(&[find("mcp").unwrap()], &sel(&["TLS-003"])), sel(&["TLS-003"]));
    }
}
