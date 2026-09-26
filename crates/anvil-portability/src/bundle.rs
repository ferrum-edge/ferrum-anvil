//! Bundle (zip) writing and hardened reading.

use crate::graph::{PortableGraph, SecretValue};
use crate::sanitize::{self, ContentWarning, Extracted};
use anvil_storage::crypto::{self, KdfParams};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use zip::write::SimpleFileOptions;

pub const FORMAT_VERSION: u32 = 1;
pub const MAX_ENTRIES: usize = 20_000;
pub const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RATIO: u64 = 200;
const VAULT_AAD: &[u8] = b"anvil-portable-vault-v1";

/// Oldest object schema this build reads. Raising [`anvil_domain::SCHEMA_VERSION`]
/// needs an explicit migration step in [`migrate_objects`] for every schema
/// between this and the new version.
pub const MIN_SCHEMA_VERSION: u32 = 1;

/// Largest Argon2id memory cost (KiB) a bundle may ask for.
pub const MAX_KDF_MEMORY_KIB: u32 = 256 * 1024;
/// Largest Argon2id pass count a bundle may ask for.
pub const MAX_KDF_ITERATIONS: u32 = 10;
/// Largest Argon2id lane count a bundle may ask for.
pub const MAX_KDF_PARALLELISM: u32 = 4;
/// Largest memory x passes product (KiB-passes) a bundle may ask for: 1 GiB
/// in total, e.g. 256 MiB for 4 passes. Exports use 64 MiB for 3 passes.
pub const MAX_KDF_WORK: u64 = 1024 * 1024;
const MIN_SALT_LEN: usize = 8;
const MAX_SALT_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("not an Anvil bundle: {0}")]
    NotABundle(String),
    #[error("unsafe archive entry '{0}': {1}")]
    Unsafe(String, String),
    #[error("archive exceeds safety limits: {0}")]
    Limits(String),
    #[error("integrity check failed for '{0}' (the bundle is corrupt or was modified)")]
    Checksum(String),
    #[error("this bundle was created by a newer Anvil (format {found}); this version supports format {supported}")]
    FutureFormat { found: u32, supported: u32 },
    #[error("this bundle was written by a newer Anvil (schema {found}); this version supports schema {supported}; nothing was imported")]
    FutureSchema { found: u32, supported: u32 },
    #[error("this bundle uses schema {found}, which this version cannot read (oldest supported: {oldest}); nothing was imported")]
    UnsupportedSchema { found: u32, oldest: u32 },
    #[error("the bundle's key-derivation settings are not supported ({0}); nothing was imported")]
    UnsupportedKdf(String),
    #[error("the bundle is encrypted; a passphrase is required")]
    PassphraseRequired,
    #[error("the passphrase is not correct, or the encrypted vault was modified; nothing was imported")]
    WrongPassphrase,
    #[error("legacy full backups are not supported; restore from an ANVILBAK backup")]
    LegacyFullBackup,
    #[error("a full backup is written as an ANVILBAK backup file, not as a bundle")]
    FullBackupNotABundle,
    #[error("{0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BundleKind {
    Workspace,
    /// A full backup. Only ANVILBAK backup files carry this kind; a bundle
    /// naming it is refused.
    Backup,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExportMode {
    /// Secrets excluded; sensitive literals replaced with placeholders.
    ShareSafely,
    /// Selected secrets and sensitive literals re-encrypted for the recipient.
    EncryptedTransfer,
    /// Every stored item of a profile, encrypted and authenticated as one
    /// ANVILBAK backup file (`anvil_app::backup`). Never written or read as a
    /// bundle.
    FullBackup,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultInfo {
    pub kdf: KdfParams,
    pub salt_b64: String,
    pub envelope_version: u8,
    pub cipher: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Placeholder {
    pub pointer: String,
    pub placeholder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub format: String,
    pub format_version: u32,
    pub kind: BundleKind,
    pub mode: ExportMode,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub app_version: String,
    pub schema_version: u32,
    pub counts: BTreeMap<String, usize>,
    /// Items intentionally not included (labels only).
    pub excluded: Vec<String>,
    /// Fields replaced by placeholders (share-safely), or restored from the vault.
    pub placeholders: Vec<Placeholder>,
    /// Device-specific items that need rebinding on the target machine.
    pub device_bindings: Vec<String>,
    pub content_warnings: Vec<ContentWarning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultInfo>,
    pub includes_history: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultPayload {
    pub secrets: BTreeMap<String, SecretValue>,
    pub literals: Vec<Extracted>,
}

pub struct ExportOptions<'a> {
    pub kind: BundleKind,
    pub mode: ExportMode,
    pub passphrase: Option<&'a str>,
    pub include_history: bool,
    pub kdf: KdfParams,
    pub app_version: &'a str,
}

/// Summary shown before writing (and returned after).
#[derive(Debug, Clone, Serialize)]
pub struct ExportPreview {
    pub manifest: Manifest,
    pub secrets_included: usize,
    pub literals_moved: usize,
}

fn sha256(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn device_bindings(graph: &PortableGraph) -> Vec<String> {
    let mut out = Vec::new();
    if !graph.linked_files().is_empty() {
        out.push("Requests or datasets name linked local files; attach them, or choose them again on the target machine.".into());
    }
    out.push("OS keychain entries, local master keys and signed-in provider sessions are device-bound and are never exported.".into());
    out
}

/// Whether a manifest describes a full backup. Full backups are ANVILBAK
/// files, whose every byte is authenticated, never bundles.
fn is_full_backup(kind: BundleKind, mode: ExportMode) -> bool {
    kind == BundleKind::Backup || mode == ExportMode::FullBackup
}

/// Build the manifest and sanitized objects without writing.
pub fn prepare(graph: &PortableGraph, opts: &ExportOptions<'_>) -> Result<(Manifest, serde_json::Value, VaultPayload), BundleError> {
    if is_full_backup(opts.kind, opts.mode) {
        return Err(BundleError::FullBackupNotABundle);
    }
    let mut objects = serde_json::to_value(graph)?;
    let san = sanitize::sanitize(&mut objects);
    let mut excluded = Vec::new();
    // Stored files whose content could not be read here travel without it.
    for u in crate::validate::uncarried_attachments(graph)? {
        let entry = format!("a stored file of {} (its content could not be read; it fails until the file is attached again)", u.item);
        if !excluded.contains(&entry) {
            excluded.push(entry);
        }
    }
    let encrypted = !matches!(opts.mode, ExportMode::ShareSafely);
    if encrypted && opts.passphrase.map(|p| p.len() < 8).unwrap_or(true) {
        return Err(BundleError::Invalid("encrypted exports need an export passphrase of at least 8 characters".into()));
    }
    let mut vault = VaultPayload::default();
    if encrypted {
        vault.secrets = graph.secrets.clone();
        vault.literals = san.extracted.clone();
    } else {
        for (id, s) in &graph.secrets {
            excluded.push(format!("secret '{}' ({id})", s.label));
        }
        for e in &san.extracted {
            excluded.push(format!(
                "sensitive value at {} (replaced by {{{{{}}}}})",
                e.pointer,
                if e.placeholder.is_empty() { "empty value" } else { &e.placeholder }
            ));
        }
    }
    let mut counts = BTreeMap::new();
    counts.insert("workspaces".into(), graph.workspaces.len());
    counts.insert("folders".into(), graph.folders.len());
    counts.insert("requests".into(), graph.requests.len());
    counts.insert("environments".into(), graph.environments.len());
    counts.insert("tls_profiles".into(), graph.tls_profiles.len());
    counts.insert("proxy_profiles".into(), graph.proxy_profiles.len());
    counts.insert("gateway_profiles".into(), graph.integrations.len());
    counts.insert("scenarios".into(), graph.scenarios.len());
    counts.insert("datasets".into(), graph.datasets.len());
    counts.insert("load_plans".into(), graph.load_plans.len());
    counts.insert("attachments".into(), graph.attachments.len());
    counts.insert("secrets".into(), if encrypted { graph.secrets.len() } else { 0 });
    counts.insert("history".into(), if opts.include_history { graph.history.len() } else { 0 });
    let manifest = Manifest {
        format: "anvil-bundle".into(),
        format_version: FORMAT_VERSION,
        kind: opts.kind,
        mode: opts.mode,
        created_at: chrono::Utc::now(),
        app_version: opts.app_version.into(),
        schema_version: anvil_domain::SCHEMA_VERSION,
        counts,
        excluded,
        placeholders: san
            .extracted
            .iter()
            .map(|e| Placeholder { pointer: e.pointer.clone(), placeholder: e.placeholder.clone() })
            .collect(),
        device_bindings: device_bindings(graph),
        content_warnings: san.warnings,
        vault: None,
        includes_history: opts.include_history,
    };
    Ok((manifest, objects, vault))
}

pub fn preview(graph: &PortableGraph, opts: &ExportOptions<'_>) -> Result<ExportPreview, BundleError> {
    let (manifest, _, vault) = prepare(graph, opts)?;
    Ok(ExportPreview { manifest, secrets_included: vault.secrets.len(), literals_moved: vault.literals.len() })
}

/// Write a bundle to bytes.
pub fn write(graph: &PortableGraph, opts: &ExportOptions<'_>) -> Result<(Vec<u8>, ExportPreview), BundleError> {
    let (mut manifest, objects, vault) = prepare(graph, opts)?;
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    files.push(("workspace/objects.json".into(), serde_json::to_vec_pretty(&objects)?));
    for (hash, data) in &graph.attachments {
        if sha256(data) != *hash {
            return Err(BundleError::Invalid(format!("attachment {hash} does not match its content hash")));
        }
        files.push((format!("attachments/{hash}"), data.clone()));
    }
    if opts.include_history && !graph.history.is_empty() {
        let mut jsonl = Vec::new();
        for h in &graph.history {
            jsonl.extend_from_slice(&serde_json::to_vec(h)?);
            jsonl.push(b'\n');
        }
        files.push(("history/records.jsonl".into(), jsonl));
    }
    if !matches!(opts.mode, ExportMode::ShareSafely) {
        check_kdf(&opts.kdf)?;
        let pass = opts.passphrase.unwrap_or_default();
        let salt = crypto::random_bytes(16);
        let key = crypto::derive(pass.as_bytes(), &salt, &opts.kdf).map_err(|e| BundleError::Invalid(e.to_string()))?;
        let payload = serde_json::to_vec(&vault)?;
        files.push(("secrets/portable-vault.enc".into(), crypto::seal(&key, VAULT_AAD, &payload)));
        manifest.vault = Some(VaultInfo {
            kdf: opts.kdf,
            salt_b64: base64::engine::general_purpose::STANDARD.encode(&salt),
            envelope_version: crypto::ENVELOPE_V1,
            cipher: "xchacha20poly1305".into(),
        });
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let mut checksums: BTreeMap<String, String> = BTreeMap::new();
    checksums.insert("manifest.json".into(), sha256(&manifest_bytes));
    for (n, b) in &files {
        checksums.insert(n.clone(), sha256(b));
    }
    let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opt = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).unix_permissions(0o600);
    zw.start_file("manifest.json", opt)?;
    zw.write_all(&manifest_bytes)?;
    for (n, b) in &files {
        zw.start_file(n.as_str(), opt)?;
        zw.write_all(b)?;
    }
    zw.start_file("checksums.json", opt)?;
    zw.write_all(&serde_json::to_vec_pretty(&checksums)?)?;
    let bytes = zw.finish()?.into_inner();
    let preview = ExportPreview { manifest, secrets_included: vault.secrets.len(), literals_moved: vault.literals.len() };
    Ok((bytes, preview))
}

/// Result of safely opening a bundle (no store mutation happens here).
#[derive(Debug, Clone)]
pub struct Opened {
    pub manifest: Manifest,
    pub graph: PortableGraph,
    /// Warnings produced by validation/normalization.
    pub warnings: Vec<String>,
    /// True when sensitive values were restored from the encrypted vault.
    pub secrets_restored: bool,
}

fn safe_name(name: &str) -> Result<(), BundleError> {
    let bad = |why: &str| Err(BundleError::Unsafe(name.to_string(), why.to_string()));
    if name.is_empty() || name.len() > 255 {
        return bad("invalid length");
    }
    if name.starts_with('/') || name.starts_with('\\') || name.contains('\\') || name.contains(':') || name.contains('\0') {
        return bad("absolute or non-portable path");
    }
    if name.split('/').any(|seg| seg == ".." || seg == ".") {
        return bad("path traversal");
    }
    let allowed = [
        "manifest.json",
        "checksums.json",
        "workspace/objects.json",
        "settings/portable.json",
        "history/records.jsonl",
        "secrets/portable-vault.enc",
    ];
    if allowed.contains(&name) {
        return Ok(());
    }
    if let Some(h) = name.strip_prefix("attachments/")
        && h.len() == 64
        && h.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Ok(());
    }
    bad("unexpected entry")
}

/// Refuse Argon2id costs outside the documented bounds. The vault key is
/// derived before the vault can authenticate, so a bundle's costs are
/// unauthenticated input; they are checked before any derivation.
pub fn check_kdf(p: &KdfParams) -> Result<(), BundleError> {
    let refuse = |why: String| Err(BundleError::UnsupportedKdf(why));
    if !(1..=MAX_KDF_ITERATIONS).contains(&p.t_cost) {
        return refuse(format!("{} passes; allowed 1 to {MAX_KDF_ITERATIONS}", p.t_cost));
    }
    if !(1..=MAX_KDF_PARALLELISM).contains(&p.p_cost) {
        return refuse(format!("{} lanes; allowed 1 to {MAX_KDF_PARALLELISM}", p.p_cost));
    }
    // Argon2 needs at least 8 KiB per lane.
    let min_memory = 8 * p.p_cost;
    if !(min_memory..=MAX_KDF_MEMORY_KIB).contains(&p.m_cost) {
        return refuse(format!("{} KiB of memory; allowed {min_memory} to {MAX_KDF_MEMORY_KIB} KiB", p.m_cost));
    }
    let work = u64::from(p.m_cost) * u64::from(p.t_cost);
    if work > MAX_KDF_WORK {
        return refuse(format!("{} KiB for {} passes exceeds the budget of {MAX_KDF_WORK} KiB-passes", p.m_cost, p.t_cost));
    }
    Ok(())
}

/// Refuse schema versions this build cannot read.
fn check_schema(found: u32) -> Result<(), BundleError> {
    if found > anvil_domain::SCHEMA_VERSION {
        return Err(BundleError::FutureSchema { found, supported: anvil_domain::SCHEMA_VERSION });
    }
    if found < MIN_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedSchema { found, oldest: MIN_SCHEMA_VERSION });
    }
    Ok(())
}

/// Check the `schema_version` a record carries, if it carries one.
fn check_record_schema(record: &serde_json::Value, what: &str) -> Result<(), BundleError> {
    match record.get("schema_version") {
        None => Ok(()),
        Some(v) => {
            let found = v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| BundleError::Invalid(format!("{what} has an invalid schema_version")))?;
            check_schema(found)
        }
    }
}

/// Bring objects written at an older supported schema up to
/// [`anvil_domain::SCHEMA_VERSION`]. Schema 1 is the only one so far, so
/// there is nothing to migrate yet; a schema bump adds its step here.
fn migrate_objects(schema_version: u32, _objects: &mut serde_json::Value) -> Result<(), BundleError> {
    match schema_version {
        anvil_domain::SCHEMA_VERSION => Ok(()),
        // No migration step for this schema: refuse rather than guess.
        found => Err(BundleError::UnsupportedSchema { found, oldest: MIN_SCHEMA_VERSION }),
    }
}

/// Open and fully validate a bundle. Nothing is written anywhere.
pub fn open(bytes: &[u8], passphrase: Option<&str>) -> Result<Opened, BundleError> {
    let mut zr = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| BundleError::NotABundle(e.to_string()))?;
    if zr.len() > MAX_ENTRIES {
        return Err(BundleError::Limits(format!("{} entries (max {MAX_ENTRIES})", zr.len())));
    }
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total: u64 = 0;
    for i in 0..zr.len() {
        let mut f = zr.by_index(i)?;
        let name = f.name().to_string();
        safe_name(&name)?;
        if f.is_symlink() || f.is_dir() {
            return Err(BundleError::Unsafe(name, "symlinks and directories are not allowed".into()));
        }
        if f.enclosed_name().is_none() {
            return Err(BundleError::Unsafe(name, "path escapes the archive".into()));
        }
        let declared = f.size();
        let compressed = f.compressed_size().max(1);
        if declared > MAX_ENTRY_BYTES || declared / compressed > MAX_RATIO {
            return Err(BundleError::Limits(format!(
                "entry '{name}' declares {declared} bytes (compression ratio {})",
                declared / compressed
            )));
        }
        let mut buf = Vec::new();
        f.by_ref().take(MAX_ENTRY_BYTES + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_ENTRY_BYTES || (buf.len() as u64) / compressed > MAX_RATIO {
            return Err(BundleError::Limits(format!("entry '{name}' expands beyond the safety limit")));
        }
        total += buf.len() as u64;
        if total > MAX_TOTAL_BYTES {
            return Err(BundleError::Limits("total uncompressed size exceeds 1 GiB".into()));
        }
        if entries.insert(name.clone(), buf).is_some() {
            return Err(BundleError::Unsafe(name, "duplicate entry".into()));
        }
    }
    let manifest_bytes = entries.get("manifest.json").ok_or_else(|| BundleError::NotABundle("missing manifest.json".into()))?;
    let checksums: BTreeMap<String, String> =
        serde_json::from_slice(entries.get("checksums.json").ok_or_else(|| BundleError::NotABundle("missing checksums.json".into()))?)?;
    for (name, data) in &entries {
        if name == "checksums.json" {
            continue;
        }
        match checksums.get(name) {
            Some(h) if *h == sha256(data) => {}
            _ => return Err(BundleError::Checksum(name.clone())),
        }
    }
    for name in checksums.keys() {
        if !entries.contains_key(name) {
            return Err(BundleError::Checksum(format!("{name} (missing)")));
        }
    }
    let manifest: Manifest = serde_json::from_slice(manifest_bytes).map_err(|e| BundleError::NotABundle(format!("manifest: {e}")))?;
    if manifest.format != "anvil-bundle" {
        return Err(BundleError::NotABundle(format!("unknown format '{}'", manifest.format)));
    }
    if manifest.format_version > FORMAT_VERSION {
        return Err(BundleError::FutureFormat { found: manifest.format_version, supported: FORMAT_VERSION });
    }
    // Full backups were once written as bundles, with a vault that bound
    // nothing else in the archive. They are refused before any object is
    // interpreted or the vault is opened, so nothing of one is ever restored.
    if is_full_backup(manifest.kind, manifest.mode) || entries.contains_key("settings/portable.json") {
        return Err(BundleError::LegacyFullBackup);
    }
    // Schema compatibility is settled before any object is interpreted:
    // serde would silently drop fields a newer schema added.
    check_schema(manifest.schema_version)?;
    let mut objects: serde_json::Value = serde_json::from_slice(
        entries.get("workspace/objects.json").ok_or_else(|| BundleError::NotABundle("missing workspace/objects.json".into()))?,
    )?;
    // Only full backups carried app settings.
    if objects.get("app_settings").is_some() {
        return Err(BundleError::LegacyFullBackup);
    }
    if let Some(o) = objects.as_object() {
        for (name, list) in o {
            if let Some(items) = list.as_array() {
                for item in items {
                    check_record_schema(item, name)?;
                }
            } else {
                check_record_schema(list, name)?;
            }
        }
    }
    migrate_objects(manifest.schema_version, &mut objects)?;
    let mut secrets_restored = false;
    let mut secrets = BTreeMap::new();
    if let Some(v) = &manifest.vault {
        // Checked before asking for the passphrase and before deriving.
        check_kdf(&v.kdf)?;
        let salt = base64::engine::general_purpose::STANDARD.decode(&v.salt_b64).map_err(|_| BundleError::Invalid("vault salt".into()))?;
        if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
            return Err(BundleError::UnsupportedKdf(format!("{}-byte salt; allowed {MIN_SALT_LEN} to {MAX_SALT_LEN}", salt.len())));
        }
        let pass = passphrase.ok_or(BundleError::PassphraseRequired)?;
        let enc = entries
            .get("secrets/portable-vault.enc")
            .ok_or_else(|| BundleError::Checksum("secrets/portable-vault.enc (missing)".into()))?;
        let key = crypto::derive(pass.as_bytes(), &salt, &v.kdf).map_err(|e| BundleError::Invalid(e.to_string()))?;
        let pt = crypto::open(&key, VAULT_AAD, enc).map_err(|_| BundleError::WrongPassphrase)?;
        let payload: VaultPayload = serde_json::from_slice(&pt)?;
        sanitize::restore(&mut objects, &payload.literals).map_err(BundleError::Invalid)?;
        secrets = payload.secrets;
        secrets_restored = true;
    }
    let mut graph: PortableGraph = serde_json::from_value(objects)
        .map_err(|e| BundleError::Invalid(format!("objects.json does not match schema {}: {e}", manifest.schema_version)))?;
    graph.secrets = secrets;
    for (name, data) in &entries {
        if let Some(h) = name.strip_prefix("attachments/") {
            if sha256(data) != h {
                return Err(BundleError::Checksum(name.clone()));
            }
            graph.attachments.insert(h.to_string(), data.clone());
        }
    }
    if let Some(h) = entries.get("history/records.jsonl") {
        for line in h.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let record: serde_json::Value = serde_json::from_slice(line)?;
            check_record_schema(&record, "history record")?;
            graph.history.push(record);
        }
    }
    let warnings = crate::validate::validate_and_normalize(&mut graph)?;
    Ok(Opened { manifest, graph, warnings, secrets_restored })
}
