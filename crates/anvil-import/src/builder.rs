//! Accumulates the imported object graph with deterministic ids.

use crate::detect::Detected;
use crate::report::ImportReport;
use crate::util::{spec_hash, text_size_within};
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

/// Text (names, keys, descriptions, actions) the imported objects may copy
/// from the source, per input byte limit. One source string can be copied
/// into many objects (an operation shared by many ports or paths), so the
/// copies are charged.
const TEXT_BYTES_PER_INPUT_BYTE: usize = 4;

pub(crate) struct Builder<'o> {
    pub opts: &'o ImportOptions,
    ns: Uuid,
    pub now: DateTime<Utc>,
    pub import_id: Id,
    pub workspace: Workspace,
    pub folders: Vec<Folder>,
    folder_index: HashMap<String, Id>,
    /// Folder id → its position in `folders`.
    folder_pos: HashMap<Id, usize>,
    pub requests: Vec<RequestDefinition>,
    op_keys: HashSet<String>,
    /// Next `#n` suffix to try for a repeated operation key.
    key_suffix: HashMap<String, usize>,
    /// Text bytes the rest of the import may copy.
    text_left: usize,
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
            folder_pos: HashMap::new(),
            requests: vec![],
            op_keys: HashSet::new(),
            key_suffix: HashMap::new(),
            text_left: opts.max_bytes.saturating_mul(TEXT_BYTES_PER_INPUT_BYTE),
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

    /// Charge `n` bytes of text copied from the source into the imported
    /// objects; `false` (reported once) when they do not fit. Once the budget
    /// is spent no further operation is admitted.
    pub fn charge_text(&mut self, pointer: &str, n: usize) -> bool {
        if n < self.text_left {
            self.text_left -= n;
            return true;
        }
        if self.text_left > 0 {
            self.text_left = 0;
            self.report.warn(
                "text_size_limit",
                pointer,
                "the imported names, keys and descriptions reached the import's text budget; later operations are skipped",
            );
        }
        false
    }

    /// Charge reading `v` (a source object an operation walks and copies
    /// parts of) at about its JSON size; `false` when it does not fit.
    pub fn charge_value(&mut self, pointer: &str, v: &serde_json::Value) -> bool {
        let n = text_size_within(v, self.text_left).unwrap_or(usize::MAX);
        self.charge_text(pointer, n)
    }

    /// A charged copy of `s`, or an empty string once the text budget is spent.
    pub fn text(&mut self, pointer: &str, s: &str) -> String {
        if self.charge_text(pointer, s.len()) { s.to_string() } else { String::new() }
    }

    /// Get or create the folder identified by `key` (stable across reimports
    /// when the same id namespace is used). The key (looked up every time)
    /// and a new folder's name are charged as text. The folder is made even
    /// when they do not fit: every caller makes folders either for an
    /// operation it has just admitted (and the next one is not admitted once
    /// the budget is spent) or once per element of the source (a Postman or
    /// Insomnia folder, a tag, a WSDL service), so what is copied stays
    /// proportional to the input.
    pub fn folder(&mut self, parent: Option<Id>, key: &str, name: &str) -> Id {
        self.charge_text("/", key.len());
        if let Some(id) = self.folder_index.get(key) {
            return *id;
        }
        self.charge_text("/", name.len());
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
        self.folder_pos.insert(id, self.folders.len() - 1);
        id
    }

    pub fn folder_mut(&mut self, id: Id) -> Option<&mut Folder> {
        let i = *self.folder_pos.get(&id)?;
        self.folders.get_mut(i)
    }

    /// Count one operation found in the source and decide whether it fits
    /// within `max_operations` (and the text budget).
    pub fn admit(&mut self, pointer: &str) -> bool {
        self.report.counts.operations_found += 1;
        if self.text_left == 0 {
            self.report.counts.skipped_operations += 1;
            return false;
        }
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

    /// Whether `max_operations` requests exist already, or the text budget
    /// is spent: no further operation can be admitted.
    pub fn operations_full(&self) -> bool {
        self.requests.len() >= self.opts.max_operations || self.text_left == 0
    }

    /// Count `n` more operations once the limit is reached, as `admit` would
    /// one by one (the first of them is at `pointer`).
    pub fn skip_operations(&mut self, pointer: &str, n: usize) {
        if n > 0 {
            self.report.counts.operations_found += n - 1;
            self.report.counts.skipped_operations += n - 1;
            self.admit(pointer);
        }
    }

    /// Mark an operation as found but not importable (already reported).
    pub fn skipped(&mut self) {
        self.report.counts.skipped_operations += 1;
    }

    /// Add a request. `operation_key` is made unique (duplicates get a
    /// `#n` suffix and a warning, found from a counter per key); `source` and
    /// `generated_hash` are set from the final spec. The key, name, URL and
    /// source pointer are charged as text (the request is added either way:
    /// its operation was admitted, and the next one will not be once the
    /// budget is spent, so the overshoot is one request).
    pub fn add_request(
        &mut self,
        folder: Option<Id>,
        name: &str,
        operation_key: &str,
        mut spec: RequestSpec,
        pointer: &str,
    ) -> &mut RequestDefinition {
        let text = operation_key.len().saturating_add(name.len()).saturating_add(spec.url.len()).saturating_add(pointer.len());
        self.charge_text(pointer, text);
        let mut key = operation_key.to_string();
        if self.op_keys.contains(&key) {
            let n = self.key_suffix.entry(key.clone()).or_insert(2);
            key = loop {
                let candidate = format!("{operation_key}#{n}");
                *n += 1;
                if !self.op_keys.contains(&candidate) {
                    break candidate;
                }
            };
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
