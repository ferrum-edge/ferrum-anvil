//! Export/import between the encrypted store and portable bundles.

use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_portability::bundle::{self, BundleKind, ExportMode, ExportOptions, ExportPreview};
use anvil_portability::plan::{self, ConflictPolicy, ImportPlan};
use anvil_portability::{PortableGraph, SecretValue};
use anvil_storage::{KdfParams, kind};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub plan: ImportPlan,
    pub warnings: Vec<String>,
    pub secrets_restored: bool,
    pub missing_secrets: Vec<String>,
    pub checkpoint: Option<String>,
    /// Workspace names as they will appear (or appear) after import.
    pub workspaces: Vec<String>,
    /// Ids of the imported workspaces (after any duplicate remap); empty for a preview.
    pub workspace_ids: Vec<String>,
}

impl App {
    /// Build the portable graph for one workspace (or all when `None`).
    pub fn graph(&self, ws: Option<&Id>, include_secrets: bool, include_history: bool) -> Result<PortableGraph> {
        let wss = match ws {
            Some(w) => vec![self.workspace(w)?],
            None => self.workspaces()?,
        };
        let mut g = PortableGraph::default();
        for w in &wss {
            let id = w.meta.id;
            g.folders.extend(self.folders(&id)?);
            let reqs = self.requests(&id)?;
            for r in &reqs {
                if let Some(rid) = r.revision_id
                    && let Ok(rev) = self.revision(&rid)
                {
                    g.revisions.push(rev);
                }
            }
            g.requests.extend(reqs);
            g.environments.extend(self.environments(&id)?);
            g.tls_profiles.extend(self.tls_profiles(&id)?);
            g.proxy_profiles.extend(self.proxy_profiles(&id)?);
            g.integrations.extend(self.integrations(&id)?);
            g.datasets.extend(self.datasets(&id)?);
            g.scenarios.extend(self.scenarios(&id)?);
            if include_secrets {
                for sid in self.store.list_secret_ids(Some(&id))? {
                    if let Ok(parsed) = sid.parse::<Id>()
                        && let Some((label, value)) = self.store.get_secret(&parsed)?
                    {
                        g.secrets.insert(sid, SecretValue { label, value: value.to_string(), workspace_id: Some(id.to_string()) });
                    }
                }
            }
            if include_history {
                for h in self.store.list_history(Some(&id), None, 1000)? {
                    if let Some((rec, _)) = self.store.get_history::<serde_json::Value>(&h.id)? {
                        g.history.push(rec);
                    }
                }
            }
        }
        g.workspaces = wss;
        // Attachments referenced anywhere in the graph.
        let text = serde_json::to_string(&g.requests)? + &serde_json::to_string(&g.datasets)?;
        for cap in text.split("\"sha256\":\"").skip(1) {
            let sha: String = cap.chars().take(64).collect();
            if sha.len() == 64
                && let Some(b) = self.get_attachment(&sha)?
            {
                g.attachments.insert(sha, b);
            }
        }
        if ws.is_none() {
            g.app_settings = Some(self.settings()?);
        }
        Ok(g)
    }

    pub fn export_preview(&self, ws: Option<&Id>, mode: ExportMode, include_history: bool) -> Result<ExportPreview> {
        let g = self.graph(ws, !matches!(mode, ExportMode::ShareSafely), include_history)?;
        let opts = ExportOptions {
            kind: if ws.is_some() { BundleKind::Workspace } else { BundleKind::Backup },
            mode,
            passphrase: Some("preview-only-passphrase"),
            include_history,
            kdf: KdfParams::testing(),
            app_version: env!("CARGO_PKG_VERSION"),
        };
        Ok(bundle::preview(&g, &opts)?)
    }

    pub fn export(
        &self,
        ws: Option<&Id>,
        mode: ExportMode,
        passphrase: Option<&str>,
        include_history: bool,
    ) -> Result<(Vec<u8>, ExportPreview)> {
        let g = self.graph(ws, !matches!(mode, ExportMode::ShareSafely), include_history)?;
        let opts = ExportOptions {
            kind: if ws.is_some() { BundleKind::Workspace } else { BundleKind::Backup },
            mode,
            passphrase,
            include_history,
            kdf: KdfParams::interactive(),
            app_version: env!("CARGO_PKG_VERSION"),
        };
        Ok(bundle::write(&g, &opts)?)
    }

    fn existing_ids(&self) -> Result<HashSet<Id>> {
        let mut s = HashSet::new();
        for k in kind::ALL {
            for m in self.store.object_meta(k)? {
                if let Ok(id) = m.id.parse() {
                    s.insert(id);
                }
            }
        }
        Ok(s)
    }

    /// Dry run: validate and plan without mutating anything.
    pub fn import_preview(&self, bytes: &[u8], passphrase: Option<&str>, policy: ConflictPolicy) -> Result<ImportReport> {
        let opened = bundle::open(bytes, passphrase)?;
        let plan = plan::plan(&opened.graph, &self.existing_ids()?, policy);
        Ok(ImportReport {
            plan,
            warnings: opened.warnings,
            secrets_restored: opened.secrets_restored,
            missing_secrets: missing_secrets(&opened.graph),
            checkpoint: None,
            workspaces: opened.graph.workspaces.iter().map(|w| w.name.clone()).collect(),
            workspace_ids: vec![],
        })
    }

    /// Apply atomically after taking a restore checkpoint. Any failure rolls back.
    pub fn import(&self, bytes: &[u8], passphrase: Option<&str>, policy: ConflictPolicy) -> Result<ImportReport> {
        let opened = bundle::open(bytes, passphrase)?;
        let mut g = opened.graph;
        let existing = self.existing_ids()?;
        let plan = plan::plan(&g, &existing, policy);
        if policy == ConflictPolicy::Duplicate {
            plan::remap_all(&mut g);
        }
        // A different workspace with the same name would be indistinguishable
        // in the UI; label the incoming copy.
        let local = self.workspaces()?;
        for w in &mut g.workspaces {
            if local.iter().any(|l| l.name == w.name && l.meta.id != w.meta.id) {
                w.name = format!("{} (imported)", w.name);
            }
        }
        let checkpoint = self.store.checkpoint("before-import")?;
        let skip = |id: &Id| policy == ConflictPolicy::Merge && existing.contains(id);
        let res = self.store.atomically(|s| {
            for w in &g.workspaces {
                if !skip(&w.meta.id) {
                    s.put(kind::WORKSPACE, &w.meta.id, None, None, 0.0, w)?;
                }
            }
            for f in &g.folders {
                if !skip(&f.meta.id) {
                    s.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, f)?;
                }
            }
            for r in &g.requests {
                if !skip(&r.meta.id) {
                    s.put(kind::REQUEST, &r.meta.id, Some(&r.workspace_id), r.folder_id.as_ref(), r.sort_key, r)?;
                }
            }
            for r in &g.revisions {
                s.put(kind::REVISION, &r.id, None, Some(&r.request_id), 0.0, r)?;
            }
            for e in &g.environments {
                if !skip(&e.meta.id) {
                    s.put(kind::ENVIRONMENT, &e.meta.id, Some(&e.workspace_id), None, 0.0, e)?;
                }
            }
            for p in &g.tls_profiles {
                if !skip(&p.id) {
                    s.put(kind::TLS_PROFILE, &p.id, Some(&p.workspace_id), None, 0.0, p)?;
                }
            }
            for p in &g.proxy_profiles {
                if !skip(&p.id) {
                    s.put(kind::PROXY_PROFILE, &p.id, Some(&p.workspace_id), None, 0.0, p)?;
                }
            }
            for p in &g.integrations {
                if !skip(&p.id) {
                    s.put(kind::INTEGRATION, &p.id, Some(&p.workspace_id), None, 0.0, p)?;
                }
            }
            for d in &g.datasets {
                if !skip(&d.meta.id) {
                    s.put(kind::DATASET, &d.meta.id, Some(&d.workspace_id), None, 0.0, d)?;
                }
            }
            for sc in &g.scenarios {
                if !skip(&sc.meta.id) {
                    s.put(kind::SCENARIO, &sc.meta.id, Some(&sc.workspace_id), None, 0.0, sc)?;
                }
            }
            for (id, v) in &g.secrets {
                if let Ok(sid) = id.parse::<Id>() {
                    let ws = v.workspace_id.as_deref().and_then(|w| w.parse::<Id>().ok());
                    s.put_secret(&sid, ws.as_ref(), &v.label, &v.value)?;
                }
            }
            Ok(())
        });
        if let Err(e) = res {
            // Belt and braces: the transaction rolled back; also restore the checkpoint.
            let _ = self.store.restore_checkpoint(&checkpoint);
            return Err(e.into());
        }
        for (sha, bytes) in &g.attachments {
            let r = self.put_attachment(sha, bytes, None)?;
            if let anvil_domain::request::AttachmentRef::Stored { sha256, .. } = r
                && sha256 != *sha
            {
                return Err(AppError::Invalid(format!("attachment {sha} failed its integrity check")));
            }
        }
        Ok(ImportReport {
            plan,
            warnings: opened.warnings,
            secrets_restored: opened.secrets_restored,
            missing_secrets: missing_secrets(&g),
            checkpoint: Some(checkpoint.display().to_string()),
            workspaces: g.workspaces.iter().map(|w| w.name.clone()).collect(),
            workspace_ids: g.workspaces.iter().map(|w| w.meta.id.to_string()).collect(),
        })
    }
}

/// Secret references in the graph whose values were not included.
fn missing_secrets(g: &PortableGraph) -> Vec<String> {
    let text = serde_json::to_string(&(&g.requests, &g.environments, &g.tls_profiles, &g.workspaces, &g.folders)).unwrap_or_default();
    let mut out = Vec::new();
    for part in text.split("\"kind\":\"secret\",\"secret\":{\"id\":\"").skip(1) {
        let id: String = part.chars().take(36).collect();
        if !g.secrets.contains_key(&id) {
            let label = part.split("\"label\":\"").nth(1).map(|l| l.split('"').next().unwrap_or("").to_string()).unwrap_or_default();
            out.push(format!("{label} ({id})"));
        }
    }
    out.sort();
    out.dedup();
    out
}
