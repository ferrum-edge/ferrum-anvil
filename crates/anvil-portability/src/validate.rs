//! Import validation and safety normalization.
//!
//! * Referential integrity: folders/requests/environments must belong to a
//!   workspace in the bundle; folder parents must exist and form no cycle.
//! * Safety: imports never activate a TLS verification bypass, never mark
//!   scenarios or load plans as trusted, and never enable legacy HMAC.

use crate::bundle::BundleError;
use crate::graph::PortableGraph;
use anvil_domain::Id;
use std::collections::{HashMap, HashSet};

pub fn validate_and_normalize(g: &mut PortableGraph) -> Result<Vec<String>, BundleError> {
    let mut warnings = Vec::new();
    let ws: HashSet<Id> = g.workspaces.iter().map(|w| w.meta.id).collect();
    let folder_ids: HashSet<Id> = g.folders.iter().map(|f| f.meta.id).collect();
    for f in &g.folders {
        if !ws.contains(&f.workspace_id) {
            return Err(BundleError::Invalid(format!("folder '{}' belongs to a workspace that is not in the bundle", f.name)));
        }
        if let Some(p) = f.parent_id
            && !folder_ids.contains(&p)
        {
            return Err(BundleError::Invalid(format!("folder '{}' has a parent that is not in the bundle", f.name)));
        }
    }
    // Cycle detection over parent links.
    let parent: HashMap<Id, Option<Id>> = g.folders.iter().map(|f| (f.meta.id, f.parent_id)).collect();
    for f in &g.folders {
        let mut seen = HashSet::new();
        let mut cur = Some(f.meta.id);
        while let Some(c) = cur {
            if !seen.insert(c) {
                return Err(BundleError::Invalid(format!("folder '{}' is part of a parent cycle", f.name)));
            }
            cur = parent.get(&c).copied().flatten();
        }
    }
    for r in &g.requests {
        if !ws.contains(&r.workspace_id) {
            return Err(BundleError::Invalid(format!("request '{}' belongs to a workspace that is not in the bundle", r.name)));
        }
        if let Some(fid) = r.folder_id
            && !folder_ids.contains(&fid)
        {
            return Err(BundleError::Invalid(format!("request '{}' is in a folder that is not in the bundle", r.name)));
        }
    }
    for e in &g.environments {
        if !ws.contains(&e.workspace_id) {
            return Err(BundleError::Invalid(format!("environment '{}' belongs to a workspace that is not in the bundle", e.name)));
        }
    }
    // ---- safety normalization (DATA-008) ----
    for t in &mut g.tls_profiles {
        if !t.verify {
            t.verify = true;
            warnings.push(format!("TLS profile '{}' had certificate verification disabled; the import re-enabled it. Disable it again deliberately if you need a scoped bypass.", t.name));
        }
    }
    for s in &mut g.scenarios {
        if s.trusted {
            s.trusted = false;
        }
    }
    if !g.scenarios.is_empty() {
        warnings.push(format!("{} scenario(s) imported as untrusted; review them before running.", g.scenarios.len()));
    }
    for p in &mut g.load_plans {
        p.trusted = false;
    }
    if !g.load_plans.is_empty() {
        warnings.push(format!("{} load plan(s) imported as untrusted; they never start automatically.", g.load_plans.len()));
    }
    for i in &mut g.integrations {
        let anvil_domain::integration::IntegrationKind::FerrumGateway { require_verified_tls, .. } = &mut i.kind;
        if !*require_verified_tls {
            *require_verified_tls = true;
            warnings.push(format!(
                "Gateway profile '{}' trusted markers over unverified connections; the import turned that off. Re-enable it deliberately for a local lab.",
                i.name
            ));
        }
    }
    let mut forwarding = 0;
    for s in g
        .workspaces
        .iter_mut()
        .map(|w| &mut w.settings)
        .chain(g.folders.iter_mut().map(|f| &mut f.settings))
        .chain(g.requests.iter_mut().map(|r| &mut r.spec.settings))
    {
        if let Some(r) = s.redirects.as_mut()
            && r.forward_credentials_cross_origin
        {
            r.forward_credentials_cross_origin = false;
            forwarding += 1;
        }
    }
    if forwarding > 0 {
        warnings.push(format!("{forwarding} item(s) forwarded credentials to other origins on redirect; the import turned that off."));
    }
    let mut legacy = 0;
    for r in &mut g.requests {
        disable_legacy(&mut r.spec.auth, &mut legacy);
    }
    for f in &mut g.folders {
        disable_legacy(&mut f.auth, &mut legacy);
    }
    for w in &mut g.workspaces {
        disable_legacy(&mut w.auth, &mut legacy);
    }
    if legacy > 0 {
        warnings
            .push(format!("{legacy} auth profile(s) requested the replayable legacy HMAC v1 opt-in; the opt-in was turned off on import."));
    }
    Ok(warnings)
}

fn disable_legacy(a: &mut anvil_domain::auth::AuthConfig, n: &mut usize) {
    match a {
        anvil_domain::auth::AuthConfig::Hmac { config } if config.allow_unsafe_legacy => {
            config.allow_unsafe_legacy = false;
            *n += 1;
        }
        anvil_domain::auth::AuthConfig::Multi { profiles } => profiles.iter_mut().for_each(|p| disable_legacy(p, n)),
        _ => {}
    }
}
