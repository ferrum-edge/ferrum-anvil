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
    ]
}

pub fn find(name: &str) -> Result<Profile> {
    all().into_iter().find(|p| p.name == name).ok_or_else(|| {
        anyhow::anyhow!("unknown profile {name} (available: {})", all().iter().map(|p| p.name).collect::<Vec<_>>().join(", "))
    })
}
