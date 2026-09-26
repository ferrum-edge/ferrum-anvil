//! Accumulates the imported object graph with deterministic ids.

use crate::detect::Detected;
use crate::report::ImportReport;
use crate::util::spec_hash;
use crate::{ImportOptions, ImportResult, ImportedSource};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{ImportSource, RequestSpec};
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::workspace::{Environment, Folder, Meta, RequestDefinition, Variable, Workspace};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Root namespace for every id this crate derives (UUIDv5).
pub const ANVIL_IMPORT_NAMESPACE: Uuid = Uuid::from_u128(0x7a1c_6f0e_3b2d_5e48_9c1a_0d4f_6b8e_2a37);

pub(crate) struct Builder<'o> {
    pub opts: &'o ImportOptions,
    ns: Uuid,
    pub now: DateTime<Utc>,
    pub import_id: Id,
    pub workspace: Workspace,
    pub folders: Vec<Folder>,
    folder_index: HashMap<String, Id>,
    pub requests: Vec<RequestDefinition>,
    op_keys: HashSet<String>,
    pub environments: Vec<Environment>,
    pub report: ImportReport,
    next_sort: HashMap<Option<Id>, f64>,
    pub title: Option<String>,
    limit_warned: bool,
}

impl<'o> Builder<'o> {
    pub fn new(opts: &'o ImportOptions, sha: &str) -> Self {
        let fp = opts.fingerprint();
        let ns = match opts.id_namespace {
            Some(id) => id.0,
            None => Uuid::new_v5(&ANVIL_IMPORT_NAMESPACE, format!("ns|{sha}|{fp}").as_bytes()),
        };
        let import_id = Id(Uuid::new_v5(&ANVIL_IMPORT_NAMESPACE, format!("import|{sha}|{fp}|{ns}").as_bytes()));
        let now = opts.imported_at.unwrap_or_else(Utc::now);
        let ws_id = Id(Uuid::new_v5(&ns, b"workspace"));
        let workspace = Workspace {
            meta: Meta { id: ws_id, schema_version: anvil_domain::SCHEMA_VERSION, created_at: now, updated_at: now },
            name: String::new(),
            description: String::new(),
            settings: SettingsOverrides::default(),
            variables: vec![],
            auth: AuthConfig::Inherit,
            active_environment_id: None,
        };
        Builder {
            opts,
            ns,
            now,
            import_id,
            workspace,
            folders: vec![],
            folder_index: HashMap::new(),
            requests: vec![],
            op_keys: HashSet::new(),
            environments: vec![],
            report: ImportReport::default(),
            next_sort: HashMap::new(),
            title: None,
            limit_warned: false,
        }
    }

    pub fn id(&self, kind: &str, key: &str) -> Id {
        Id(Uuid::new_v5(&self.ns, format!("{kind}|{key}").as_bytes()))
    }

    pub fn meta(&self, kind: &str, key: &str) -> Meta {
        Meta { id: self.id(kind, key), schema_version: anvil_domain::SCHEMA_VERSION, created_at: self.now, updated_at: self.now }
    }

    fn sort_key(&mut self, parent: Option<Id>) -> f64 {
        let e = self.next_sort.entry(parent).or_insert(0.0);
        *e += 1.0;
        *e
    }

    /// Get or create the folder identified by `key` (stable across reimports
    /// when the same id namespace is used).
    pub fn folder(&mut self, parent: Option<Id>, key: &str, name: &str) -> Id {
        if let Some(id) = self.folder_index.get(key) {
            return *id;
        }
        let meta = self.meta("folder", key);
        let id = meta.id;
        let sort_key = self.sort_key(parent);
        self.folders.push(Folder {
            meta,
            workspace_id: self.workspace.meta.id,
            parent_id: parent,
            name: name.to_string(),
            description: String::new(),
            sort_key,
            settings: SettingsOverrides::default(),
            variables: vec![],
            auth: AuthConfig::Inherit,
            tags: vec![],
            import_root: false,
            import_environment_ids: vec![],
            use_workspace_scope: false,
        });
        self.folder_index.insert(key.to_string(), id);
        id
    }

    pub fn folder_mut(&mut self, id: Id) -> Option<&mut Folder> {
        self.folders.iter_mut().find(|f| f.meta.id == id)
    }

    /// Count one operation found in the source and decide whether it fits
    /// within `max_operations`.
    pub fn admit(&mut self, pointer: &str) -> bool {
        self.report.counts.operations_found += 1;
        if self.requests.len() >= self.opts.max_operations {
            self.report.counts.skipped_operations += 1;
            if !self.limit_warned {
                self.limit_warned = true;
                self.report.warn(
                    "operation_limit",
                    pointer,
                    format!(
                        "only the first {} operations were imported (max_operations); later ones are skipped",
                        self.opts.max_operations
                    ),
                );
            }
            return false;
        }
        true
    }

    /// Mark an operation as found but not importable (already reported).
    pub fn skipped(&mut self) {
        self.report.counts.skipped_operations += 1;
    }

    /// Add a request. `operation_key` is made unique (duplicates get a
    /// `#n` suffix and a warning); `source` and `generated_hash` are set
    /// from the final spec.
    pub fn add_request(
        &mut self,
        folder: Option<Id>,
        name: &str,
        operation_key: &str,
        mut spec: RequestSpec,
        pointer: &str,
    ) -> &mut RequestDefinition {
        let mut key = operation_key.to_string();
        if self.op_keys.contains(&key) {
            let mut n = 2;
            while self.op_keys.contains(&format!("{operation_key}#{n}")) {
                n += 1;
            }
            key = format!("{operation_key}#{n}");
            self.report.warn(
                "duplicate_operation_key",
                pointer,
                format!("operation key '{operation_key}' is not unique; this one is linked as '{key}' for reimport"),
            );
        }
        self.op_keys.insert(key.clone());
        spec.source = None;
        let hash = spec_hash(&spec);
        spec.source = Some(ImportSource { import_id: self.import_id, operation_key: key.clone(), generated_hash: hash });
        let meta = self.meta("request", &key);
        let sort_key = self.sort_key(folder);
        self.requests.push(RequestDefinition {
            meta,
            workspace_id: self.workspace.meta.id,
            folder_id: folder,
            name: if name.trim().is_empty() { key.clone() } else { name.to_string() },
            description: String::new(),
            tags: vec![],
            favorite: false,
            sort_key,
            spec,
            revision_id: None,
        });
        self.requests.last_mut().expect("just pushed")
    }

    pub fn add_environment(&mut self, key: &str, name: &str, variables: Vec<Variable>) -> Id {
        let meta = self.meta("environment", key);
        let id = meta.id;
        self.environments.push(Environment { meta, workspace_id: self.workspace.meta.id, name: name.to_string(), variables });
        id
    }

    pub fn finish(mut self, detected: &Detected, sha: String, size: usize) -> ImportResult {
        if self.workspace.name.trim().is_empty() {
            self.workspace.name = self.title.clone().unwrap_or_else(|| format!("Imported {}", detected.dialect.label()));
        }
        self.report.counts.requests = self.requests.len();
        self.report.counts.folders = self.folders.len();
        self.report.counts.environments = self.environments.len();
        self.report.finalize_counts();
        let source = ImportedSource {
            import_id: self.import_id,
            id_namespace: Id(self.ns),
            kind: detected.kind,
            dialect: detected.dialect,
            syntax: detected.syntax,
            declared_version: detected.declared_version.clone(),
            title: self.title.clone(),
            sha256: sha,
            size_bytes: size as u64,
            imported_at: self.now,
            options: self.opts.clone(),
        };
        ImportResult {
            workspace: self.workspace,
            folders: self.folders,
            requests: self.requests,
            environments: self.environments,
            source,
            report: self.report,
        }
    }
}
