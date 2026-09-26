//! Import validation and safety normalization.
//!
//! * Referential integrity: every workspace-scoped object (folders,
//!   requests, environments, TLS/proxy/integration profiles, datasets,
//!   scenarios, load plans) must belong to a workspace in the bundle; folder
//!   parents, request folders and the requests, datasets and environments a
//!   scenario or load plan names must be in the bundle and in the same
//!   workspace; folder parents form no cycle; every secret must be owned by a
//!   workspace in the bundle; no two objects share an id. Revisions of
//!   requests outside the bundle are left out, and a request keeps its
//!   `revision_id` only when that revision of it is in the bundle.
//!   Execution records of a workspace outside the bundle are left out, and
//!   each keeps only the links to objects of its own workspace in the bundle.
//! * Stored attachments a request or dataset names without their bytes are
//!   listed by [`uncarried_attachments`]; the importer checks them against
//!   what its device stores.
//! * Safety: imports never activate a TLS verification bypass, never mark
//!   scenarios or load plans as trusted, never enable legacy HMAC, never
//!   turn on cross-origin credential forwarding or 0-RTT early data in
//!   workspace, folder, request or app settings, and never open an imported
//!   collection's root folder to its workspace. Linked local files are
//!   listed: they need choosing on this device.

use crate::bundle::BundleError;
use crate::graph::PortableGraph;
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::execution::ExecutionRecord;
use anvil_domain::request::AttachmentRef;
use anvil_domain::workspace::RequestRevision;
use std::collections::{HashMap, HashSet};

pub fn validate_and_normalize(g: &mut PortableGraph) -> Result<Vec<String>, BundleError> {
    let mut warnings = Vec::new();
    let ws: HashSet<Id> = g.workspaces.iter().map(|w| w.meta.id).collect();
    // Import writes each object under the workspace it names, and a Duplicate
    // import remaps only workspaces in the bundle: any other workspace id
    // would place the object in an unrelated local workspace.
    let members = [
        g.folders.iter().map(|x| ("folder", x.name.as_str(), x.workspace_id)).collect::<Vec<_>>(),
        g.requests.iter().map(|x| ("request", x.name.as_str(), x.workspace_id)).collect(),
        g.environments.iter().map(|x| ("environment", x.name.as_str(), x.workspace_id)).collect(),
        g.tls_profiles.iter().map(|x| ("TLS profile", x.name.as_str(), x.workspace_id)).collect(),
        g.proxy_profiles.iter().map(|x| ("proxy profile", x.name.as_str(), x.workspace_id)).collect(),
        g.integrations.iter().map(|x| ("integration profile", x.name.as_str(), x.workspace_id)).collect(),
        g.datasets.iter().map(|x| ("dataset", x.name.as_str(), x.workspace_id)).collect(),
        g.scenarios.iter().map(|x| ("scenario", x.name.as_str(), x.workspace_id)).collect(),
        g.load_plans.iter().map(|x| ("load plan", x.name.as_str(), x.workspace_id)).collect(),
    ];
    for (kind, name, w) in members.into_iter().flatten() {
        if !ws.contains(&w) {
            return Err(BundleError::Invalid(format!("{kind} '{name}' belongs to a workspace that is not in the bundle")));
        }
    }
    // Each object a reference may name, with its workspace.
    let folder_ws: HashMap<Id, Id> = g.folders.iter().map(|f| (f.meta.id, f.workspace_id)).collect();
    let request_ws: HashMap<Id, Id> = g.requests.iter().map(|r| (r.meta.id, r.workspace_id)).collect();
    let dataset_ws: HashMap<Id, Id> = g.datasets.iter().map(|d| (d.meta.id, d.workspace_id)).collect();
    let environment_ws: HashMap<Id, Id> = g.environments.iter().map(|e| (e.meta.id, e.workspace_id)).collect();
    for f in &g.folders {
        if let Some(p) = f.parent_id
            && folder_ws.get(&p) != Some(&f.workspace_id)
        {
            return Err(BundleError::Invalid(format!("folder '{}' has a parent that is not in the bundle or its workspace", f.name)));
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
        if let Some(fid) = r.folder_id
            && folder_ws.get(&fid) != Some(&r.workspace_id)
        {
            return Err(BundleError::Invalid(format!("request '{}' is in a folder that is not in the bundle or its workspace", r.name)));
        }
    }
    // A scenario or load plan runs requests, a dataset and an environment of
    // its own workspace; one outside the bundle would be a local object that
    // a Duplicate import never remaps.
    let outside = |map: &HashMap<Id, Id>, id: &Id, w: &Id| map.get(id) != Some(w);
    for sc in &g.scenarios {
        if sc.steps.iter().any(|st| outside(&request_ws, &st.request_id, &sc.workspace_id)) {
            return Err(BundleError::Invalid(format!("scenario '{}' runs a request that is not in the bundle or its workspace", sc.name)));
        }
        if sc.dataset_id.is_some_and(|d| outside(&dataset_ws, &d, &sc.workspace_id)) {
            return Err(BundleError::Invalid(format!("scenario '{}' uses a dataset that is not in the bundle or its workspace", sc.name)));
        }
    }
    for p in &g.load_plans {
        if p.chain.iter().chain(p.mix.iter().map(|m| &m.request_id)).any(|r| outside(&request_ws, r, &p.workspace_id)) {
            return Err(BundleError::Invalid(format!("load plan '{}' runs a request that is not in the bundle or its workspace", p.name)));
        }
        if p.dataset_id.is_some_and(|d| outside(&dataset_ws, &d, &p.workspace_id)) {
            return Err(BundleError::Invalid(format!("load plan '{}' uses a dataset that is not in the bundle or its workspace", p.name)));
        }
        if p.environment_id.is_some_and(|e| outside(&environment_ws, &e, &p.workspace_id)) {
            return Err(BundleError::Invalid(format!(
                "load plan '{}' uses an environment that is not in the bundle or its workspace",
                p.name
            )));
        }
    }
    // Two requests can name the same revision, so a backup may carry it
    // twice; identical copies collapse to one.
    let mut revisions: Vec<RequestRevision> = Vec::with_capacity(g.revisions.len());
    let mut position: HashMap<Id, usize> = HashMap::new();
    for r in std::mem::take(&mut g.revisions) {
        match position.get(&r.id) {
            Some(&i) if revisions.get(i) == Some(&r) => {}
            Some(_) => return Err(BundleError::Invalid(format!("revision {} appears twice with different contents", r.id))),
            None => {
                position.insert(r.id, revisions.len());
                revisions.push(r);
            }
        }
    }
    // A revision is written under its request; one whose request is not in
    // the bundle has nothing to belong to and is left out.
    let request_ids: HashSet<Id> = g.requests.iter().map(|r| r.meta.id).collect();
    let before = revisions.len();
    revisions.retain(|r| request_ids.contains(&r.request_id));
    if revisions.len() < before {
        warnings.push(format!(
            "{} request revision(s) belonged to requests that are not in the bundle and were left out.",
            before - revisions.len()
        ));
    }
    // A request's current revision must be one of its own in the bundle;
    // any other id would name an object this import does not write (and a
    // Duplicate import does not remap). Saving the request records a new one.
    let own_revisions: HashSet<(Id, Id)> = revisions.iter().map(|r| (r.id, r.request_id)).collect();
    for r in &mut g.requests {
        if r.revision_id.is_some_and(|rev| !own_revisions.contains(&(rev, r.meta.id))) {
            r.revision_id = None;
        }
    }
    g.revisions = revisions;
    // An execution record is written under the workspace it names; one of a
    // workspace outside the bundle, or of none, would land in an unrelated
    // local workspace and is left out. Its links to a request, revision or
    // environment are kept only when that object is in the bundle and in the
    // record's workspace (a revision only as one of the linked request), so a
    // record never appears in the history of an unrelated local object.
    let revision_request: HashMap<Id, Id> = g.revisions.iter().map(|r| (r.id, r.request_id)).collect();
    let mut history_ids = HashSet::new();
    let mut outside_history = 0;
    let mut history = Vec::with_capacity(g.history.len());
    for h in std::mem::take(&mut g.history) {
        let mut rec: ExecutionRecord =
            serde_json::from_value(h).map_err(|e| BundleError::Invalid(format!("a history record is not a valid execution record: {e}")))?;
        if !history_ids.insert(rec.id) {
            return Err(BundleError::Invalid(format!("history record {} appears twice", rec.id)));
        }
        let Some(w) = rec.workspace_id.filter(|w| ws.contains(w)) else {
            outside_history += 1;
            continue;
        };
        rec.request_id = rec.request_id.filter(|r| request_ws.get(r) == Some(&w));
        rec.revision_id = rec.revision_id.filter(|v| rec.request_id.is_some_and(|r| revision_request.get(v) == Some(&r)));
        rec.environment_id = rec.environment_id.filter(|e| environment_ws.get(e) == Some(&w));
        history.push(serde_json::to_value(&rec)?);
    }
    g.history = history;
    if outside_history > 0 {
        warnings.push(format!("{outside_history} history record(s) of workspaces that are not in the bundle were left out."));
    }
    // Import writes objects by id, so a repeated id would make one object
    // silently overwrite another.
    let mut unique = HashSet::new();
    let revision_ids = g.revisions.iter().map(|r| ("revision".to_string(), r.id, String::new()));
    for (kind, id, name) in crate::plan::all_ids(g).into_iter().chain(revision_ids) {
        if !unique.insert(id) {
            return Err(BundleError::Invalid(format!("{kind} '{name}' reuses the id {id} of another object in the bundle")));
        }
    }
    // A secret is written with the owner the bundle names; an owner outside
    // the bundle would attach it to an unrelated local workspace.
    for (id, v) in &g.secrets {
        if id.parse::<Id>().is_err() {
            return Err(BundleError::Invalid(format!("secret '{}' has an invalid id", v.label)));
        }
        let owner = v.workspace_id.as_deref().and_then(|w| w.parse::<Id>().ok());
        if !owner.is_some_and(|w| ws.contains(&w)) {
            return Err(BundleError::Invalid(format!("secret '{}' belongs to a workspace that is not in the bundle", v.label)));
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
    // App settings (carried only by a full backup) are the lowest settings
    // layer of every workspace's requests, so they are normalised the same way.
    let mut forwarding = 0;
    let mut early_data = 0;
    for s in g
        .workspaces
        .iter_mut()
        .map(|w| &mut w.settings)
        .chain(g.folders.iter_mut().map(|f| &mut f.settings))
        .chain(g.requests.iter_mut().map(|r| &mut r.spec.settings))
        .chain(g.app_settings.iter_mut().map(|a| &mut a.defaults))
    {
        if let Some(r) = s.redirects.as_mut()
            && r.forward_credentials_cross_origin
        {
            r.forward_credentials_cross_origin = false;
            forwarding += 1;
        }
        if let Some(e) = s.early_data.as_mut()
            && e.enabled
        {
            e.enabled = false;
            early_data += 1;
        }
    }
    if forwarding > 0 {
        warnings.push(format!("{forwarding} item(s) forwarded credentials to other origins on redirect; the import turned that off."));
    }
    if early_data > 0 {
        warnings.push(format!(
            "{early_data} item(s) sent requests as replayable 0-RTT early data; the import turned that off. Re-enable it deliberately where replay is harmless."
        ));
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
    // SPIFFE Workload API sources carry no secret: an imported profile draws
    // on THIS machine's workload identity. Never import "send a JWT-SVID
    // that failed its checks", and say which profiles use the identity.
    let (mut send_anyway, mut jwt_from_api) = (0, 0);
    for a in g
        .requests
        .iter_mut()
        .map(|r| &mut r.spec.auth)
        .chain(g.folders.iter_mut().map(|f| &mut f.auth))
        .chain(g.workspaces.iter_mut().map(|w| &mut w.auth))
    {
        jwt_svid_safety(a, &mut send_anyway, &mut jwt_from_api);
    }
    if send_anyway > 0 {
        warnings.push(format!(
            "{send_anyway} JWT-SVID auth profile(s) sent tokens that failed Anvil's local checks; the import turned that off."
        ));
    }
    if jwt_from_api > 0 {
        warnings.push(format!(
            "{jwt_from_api} JWT-SVID auth profile(s) fetch tokens from this machine's SPIFFE Workload API and send them to the imported URLs; review their audiences and destinations before sending."
        ));
    }
    let svid_profiles: Vec<&str> = g
        .tls_profiles
        .iter()
        .filter(|t| matches!(t.client_identity, Some(anvil_domain::tls::ClientIdentity::WorkloadApi { .. })))
        .map(|t| t.name.as_str())
        .collect();
    if !svid_profiles.is_empty() {
        warnings.push(format!(
            "TLS profile(s) {} present this machine's X.509-SVID from the SPIFFE Workload API; check their host bindings before sending.",
            svid_profiles.join(", ")
        ));
    }
    // Opening an import root to its workspace is a choice made on one
    // device; it never arrives in a bundle. An import root names only
    // environments of its own workspace.
    let environments: HashMap<Id, Id> = g.environments.iter().map(|e| (e.meta.id, e.workspace_id)).collect();
    let mut opened = 0;
    for f in &mut g.folders {
        if f.use_workspace_scope {
            f.use_workspace_scope = false;
            opened += 1;
        }
        let ws = f.workspace_id;
        f.import_environment_ids.retain(|e| environments.get(e) == Some(&ws));
    }
    if opened > 0 {
        warnings.push(format!(
            "{opened} imported collection(s) used their workspace's variables, environment and auth; the import turned that off. Turn it on again deliberately."
        ));
    }
    let linked = g.linked_files();
    if !linked.is_empty() {
        warnings.push(format!(
            "{} linked local file(s) name files on the machine that made the bundle and stay unused until chosen on this device (or attach the files instead): {}",
            linked.len(),
            linked.join("; ")
        ));
    }
    Ok(warnings)
}

/// Clear the token-cache id of every OAuth 2 profile in the graph's
/// workspaces, folders and requests, and return how many were cleared. An
/// imported profile that kept one could share a cached token with a profile
/// stored here that names the same id (and the same issuer, client and
/// scope); without one, each caches under the id of the object that defines
/// it, as spec imports do.
pub fn clear_token_cache_ids(g: &mut PortableGraph) -> usize {
    let mut cleared = 0;
    for a in g
        .requests
        .iter_mut()
        .map(|r| &mut r.spec.auth)
        .chain(g.folders.iter_mut().map(|f| &mut f.auth))
        .chain(g.workspaces.iter_mut().map(|w| &mut w.auth))
    {
        clear_token_cache_id(a, &mut cleared);
    }
    cleared
}

fn clear_token_cache_id(a: &mut AuthConfig, n: &mut usize) {
    match a {
        AuthConfig::OAuth2 { config } => {
            if config.token_cache_id.take().is_some() {
                *n += 1;
            }
        }
        AuthConfig::Multi { profiles } => profiles.iter_mut().for_each(|p| clear_token_cache_id(p, n)),
        _ => {}
    }
}

/// A stored attachment that a request or dataset names by content hash and
/// whose bytes the file does not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncarriedAttachment {
    /// The item that names it: `request 'name'` or `dataset 'name'`.
    pub item: String,
    pub sha256: String,
}

/// Every stored attachment the graph's requests and datasets name without
/// carrying its bytes, in graph order.
///
/// Stored attachments are found by content hash alone, and an import stores
/// only the bytes the file carries. A reference without its bytes therefore
/// resolves to whatever content with that hash is already stored on the
/// importing device, which may belong to another workspace: the importer
/// refuses the file when that content is stored, and otherwise accepts the
/// reference with a warning (it fails until the file is attached again).
/// Exports carry the bytes of every stored attachment their requests and
/// datasets use that is readable on the exporting device. Revisions are
/// never sent or run, and exports do not carry their attachments.
pub fn uncarried_attachments(g: &PortableGraph) -> Result<Vec<UncarriedAttachment>, serde_json::Error> {
    let mut out = Vec::new();
    for r in &g.requests {
        let mut hashes = Vec::new();
        stored_hashes(&serde_json::to_value(&r.spec)?, &mut hashes);
        for sha256 in hashes.into_iter().filter(|h| !g.attachments.contains_key(h)) {
            out.push(UncarriedAttachment { item: format!("request '{}'", r.name), sha256 });
        }
    }
    for d in &g.datasets {
        if let AttachmentRef::Stored { sha256, .. } = &d.attachment
            && !g.attachments.contains_key(sha256)
        {
            out.push(UncarriedAttachment { item: format!("dataset '{}'", d.name), sha256: sha256.clone() });
        }
    }
    Ok(out)
}

/// The content hash of every stored attachment `v` names, wherever it sits
/// (binary bodies, multipart parts, gRPC schema files).
fn stored_hashes(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(o) => {
            if o.get("kind").and_then(|k| k.as_str()) == Some("stored")
                && let Some(h) = o.get("sha256").and_then(|h| h.as_str())
            {
                out.push(h.to_string());
            }
            o.values().for_each(|x| stored_hashes(x, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| stored_hashes(x, out)),
        _ => {}
    }
}

fn jwt_svid_safety(a: &mut anvil_domain::auth::AuthConfig, send_anyway: &mut usize, from_api: &mut usize) {
    match a {
        anvil_domain::auth::AuthConfig::JwtSvid { config } => {
            if config.send_despite_failed_checks {
                config.send_despite_failed_checks = false;
                *send_anyway += 1;
            }
            if config.source == anvil_domain::workload::JwtSvidSource::WorkloadApi {
                *from_api += 1;
            }
        }
        anvil_domain::auth::AuthConfig::Multi { profiles } => profiles.iter_mut().for_each(|p| jwt_svid_safety(p, send_anyway, from_api)),
        _ => {}
    }
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
