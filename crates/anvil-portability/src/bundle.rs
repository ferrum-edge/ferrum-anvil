//! Bundle (zip) writing and hardened reading.

use crate::graph::{PortableGraph, SecretValue};
use crate::sanitize::{self, ContentWarning, Extracted};
use anvil_storage::crypto::{self, KdfParams};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek, Write};
use zip::write::SimpleFileOptions;

/// Format 2 binds the encrypted vault to every other entry of its bundle
/// (see [`vault_aad`]). Format 1 vaults bound nothing else and are refused.
pub const FORMAT_VERSION: u32 = 2;
/// Oldest format whose encrypted vault this build opens. Bundles without a
/// vault (share safely) of older formats still open.
pub const MIN_VAULT_FORMAT_VERSION: u32 = 2;
pub const MAX_ENTRIES: usize = 20_000;
/// Shared import/export budget for all inflated entry bytes, including metadata.
/// This bounds cumulative bytes read, not parser, KDF or process memory.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Metadata, attachments, history and the sealed vault have the same entry budget.
pub const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_RATIO: u64 = 200;
const FORMAT: &str = "anvil-bundle";
const MANIFEST_ENTRY: &str = "manifest.json";
const CHECKSUMS_ENTRY: &str = "checksums.json";
const VAULT_ENTRY: &str = "secrets/portable-vault.enc";
const VAULT_BINDING: &str = "anvil-portable-vault-v2";
// Envelope v1: version byte, 24-byte nonce, ciphertext and 16-byte AEAD tag.
const VAULT_ENVELOPE_OVERHEAD: u64 = 1 + 24 + 16;

/// Oldest object schema this build reads. Raising [`anvil_domain::SCHEMA_VERSION`]
/// needs an explicit migration step in [`migrate_objects`] for every schema
/// between this and the new version.
pub const MIN_SCHEMA_VERSION: u32 = 1;

/// Bounds on the Argon2id costs a bundle may ask for: the same as for a
/// profile's own passphrase-wrapped key.
pub use anvil_storage::crypto::{MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB, MAX_KDF_PARALLELISM, MAX_KDF_WORK};

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
    #[error("the passphrase is not correct, or the bundle was modified after it was exported; nothing was imported")]
    WrongPassphrase,
    #[error("this encrypted bundle is from an earlier Anvil build and cannot be opened safely; export it again; nothing was imported")]
    UnboundVault,
    #[error("this bundle is not encrypted; a passphrase proves nothing about it; open it without one; nothing was imported")]
    NotEncrypted,
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
    /// Every linked local file the exported requests and datasets name, as
    /// `request 'Upload': /path/to/file` ([`PortableGraph::linked_files`]).
    /// The bundle carries these paths of this machine (user names, folder
    /// layout), so the preview lists them rather than only warning that
    /// there are some. Not written into the bundle's manifest.
    pub linked_files: Vec<String>,
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

/// Associated data that binds a vault to the rest of its bundle: the format,
/// its version and the SHA-256 of every other entry by name (the manifest,
/// vault parameters included, the objects, each attachment and the history).
/// Changing, adding or removing any entry makes the vault fail to open, so
/// its secrets and literals are only ever restored into the exact bundle
/// they were exported with.
///
/// `checksums` maps entry names to lowercase hex SHA-256 digests; the vault
/// and the checksum list themselves are left out. Entry names never contain
/// a newline (see [`safe_name`]), so the listing is unambiguous.
fn vault_aad(format_version: u32, checksums: &BTreeMap<String, String>) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(format!("{FORMAT}\n{format_version}\n"));
    for (name, digest) in checksums {
        if name != VAULT_ENTRY && name != CHECKSUMS_ENTRY {
            h.update(format!("{name}\n{digest}\n"));
        }
    }
    format!("{VAULT_BINDING}\n{}", hex::encode(h.finalize())).into_bytes()
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
    // Reject known attachment sizes/counts before preparing object/secret copies.
    // The complete preflight below also charges serialized metadata and payloads.
    let mut remaining = MAX_TOTAL_BYTES;
    let extra = 3
        + usize::from(opts.include_history && !graph.history.is_empty())
        + usize::from(opts.mode == ExportMode::EncryptedTransfer);
    if graph.attachments.len().saturating_add(extra) > MAX_ENTRIES {
        return Err(BundleError::Limits("too many export entries".into()));
    }
    for (hash, data) in &graph.attachments {
        let name = format!("attachments/{hash}");
        safe_name(&name)?;
        charge_entry_bytes(&name, data.len() as u64, &mut remaining, READ_LIMITS)?;
    }
    let mut objects = serde_json::to_value(graph)?;
    let san = sanitize::sanitize(&mut objects);
    let mut excluded = graph.omitted.clone();
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
    counts.insert("api_standards".into(), graph.rulesets.len());
    counts.insert("attachments".into(), graph.attachments.len());
    counts.insert("secrets".into(), if encrypted { graph.secrets.len() } else { 0 });
    counts.insert("history".into(), if opts.include_history { graph.history.len() } else { 0 });
    let manifest = Manifest {
        format: FORMAT.into(),
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

// Count serialization without retaining another payload buffer. The writer stops
// at the same remaining/entry budget used by the reader. Errors contain entry
// names and limits only, never serialized objects or vault plaintext.
struct LengthWriter {
    bytes: u64,
    bound: u64,
}

impl Write for LengthWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self.bytes.checked_add(bytes.len() as u64);
        match next {
            Some(next) if next <= self.bound => {
                self.bytes = next;
                Ok(bytes.len())
            }
            _ => Err(std::io::Error::other("export byte budget exceeded")),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn export_size_error(name: &str, limits: ReadLimits) -> BundleError {
    BundleError::Limits(format!(
        "export entry '{name}' exceeds the {}-byte entry or {}-byte total budget",
        limits.entry,
        limits.total
    ))
}

fn charge_json<T: Serialize>(
    name: &str,
    value: &T,
    pretty: bool,
    overhead: u64,
    remaining: &mut u64,
    limits: ReadLimits,
) -> Result<(), BundleError> {
    let mut writer = LengthWriter {
        bytes: overhead,
        bound: (*remaining).min(limits.entry),
    };
    if overhead > writer.bound {
        return Err(export_size_error(name, limits));
    }
    let result = if pretty {
        serde_json::to_writer_pretty(&mut writer, value)
    } else {
        serde_json::to_writer(&mut writer, value)
    };
    result.map_err(|e| {
        if e.is_io() {
            export_size_error(name, limits)
        } else {
            BundleError::Json(e)
        }
    })?;
    charge_entry_bytes(name, writer.bytes, remaining, limits)
}

fn export_preflight(
    graph: &PortableGraph,
    opts: &ExportOptions<'_>,
    manifest: &Manifest,
    objects: &serde_json::Value,
    vault: &VaultPayload,
    limits: ReadLimits,
) -> Result<(), BundleError> {
    let mut remaining = limits.total;
    // SHA-256 hex digests all serialize to exactly the same 64-byte length.
    // Salt randomness and ciphertext contents do not change serialized lengths.
    let mut checksums = BTreeMap::new();
    let mut exported_manifest = manifest.clone();
    let mut names = vec![MANIFEST_ENTRY.to_string(), "workspace/objects.json".to_string()];
    charge_json(
        "workspace/objects.json",
        objects,
        true,
        0,
        &mut remaining,
        limits,
    )?;
    for (hash, data) in &graph.attachments {
        let name = format!("attachments/{hash}");
        safe_name(&name)?;
        charge_entry_bytes(&name, data.len() as u64, &mut remaining, limits)?;
        names.push(name);
    }
    if opts.include_history && !graph.history.is_empty() {
        let name = "history/records.jsonl";
        let mut writer = LengthWriter {
            bytes: 0,
            bound: remaining.min(limits.entry),
        };
        for record in &graph.history {
            serde_json::to_writer(&mut writer, record).map_err(|e| {
                if e.is_io() {
                    export_size_error(name, limits)
                } else {
                    BundleError::Json(e)
                }
            })?;
            writer.write_all(b"\n").map_err(|_| export_size_error(name, limits))?;
        }
        charge_entry_bytes(name, writer.bytes, &mut remaining, limits)?;
        names.push(name.into());
    }
    if opts.mode == ExportMode::EncryptedTransfer {
        check_kdf(&opts.kdf)?;
        charge_json(
            VAULT_ENTRY,
            vault,
            false,
            VAULT_ENVELOPE_OVERHEAD,
            &mut remaining,
            limits,
        )?;
        exported_manifest.vault = Some(VaultInfo {
            kdf: opts.kdf,
            salt_b64: base64::engine::general_purpose::STANDARD.encode([0u8; 16]),
            envelope_version: crypto::ENVELOPE_V1,
            cipher: "xchacha20poly1305".into(),
        });
        names.push(VAULT_ENTRY.into());
    }
    if names.len().saturating_add(1) > limits.entries {
        return Err(BundleError::Limits("too many export entries".into()));
    }
    for name in names {
        checksums.insert(name, "0".repeat(64));
    }
    charge_json(
        MANIFEST_ENTRY,
        &exported_manifest,
        true,
        0,
        &mut remaining,
        limits,
    )?;
    charge_json(
        CHECKSUMS_ENTRY,
        &checksums,
        true,
        0,
        &mut remaining,
        limits,
    )
}

fn zip_export_files(
    files: &[(String, Cow<'_, [u8]>)],
    stored: &BTreeSet<String>,
) -> Result<Vec<u8>, BundleError> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        let method = if stored.contains(name) {
            zip::CompressionMethod::Stored
        } else {
            zip::CompressionMethod::Deflated
        };
        let options = SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(0o600);
        writer.start_file(name.as_str(), options)?;
        writer.write_all(data)?;
    }
    Ok(writer.finish()?.into_inner())
}

pub fn preview(graph: &PortableGraph, opts: &ExportOptions<'_>) -> Result<ExportPreview, BundleError> {
    let (manifest, objects, vault) = prepare(graph, opts)?;
    export_preflight(
        graph,
        opts,
        &manifest,
        &objects,
        &vault,
        READ_LIMITS,
    )?;
    Ok(ExportPreview {
        manifest,
        secrets_included: vault.secrets.len(),
        literals_moved: vault.literals.len(),
        linked_files: graph.linked_files(),
    })
}

/// Write a bundle to bytes.
pub fn write(graph: &PortableGraph, opts: &ExportOptions<'_>) -> Result<(Vec<u8>, ExportPreview), BundleError> {
    let (mut manifest, objects, vault) = prepare(graph, opts)?;
    // Check exact serialized lengths before payload buffers, ZIP output or KDF work.
    export_preflight(
        graph,
        opts,
        &manifest,
        &objects,
        &vault,
        READ_LIMITS,
    )?;
    let mut files: Vec<(String, Cow<'_, [u8]>)> = Vec::new();
    files.push((
        "workspace/objects.json".into(),
        Cow::Owned(serde_json::to_vec_pretty(&objects)?),
    ));
    for (hash, data) in &graph.attachments {
        if sha256(data) != *hash {
            return Err(BundleError::Invalid(format!("attachment {hash} does not match its content hash")));
        }
        files.push((format!("attachments/{hash}"), Cow::Borrowed(data.as_slice())));
    }
    if opts.include_history && !graph.history.is_empty() {
        let mut jsonl = Vec::new();
        for h in &graph.history {
            jsonl.extend_from_slice(&serde_json::to_vec(h)?);
            jsonl.push(b'\n');
        }
        files.push(("history/records.jsonl".into(), Cow::Owned(jsonl)));
    }
    let mut key = None;
    if !matches!(opts.mode, ExportMode::ShareSafely) {
        check_kdf(&opts.kdf)?;
        let pass = opts.passphrase.unwrap_or_default();
        let salt = crypto::random_bytes(16);
        key = Some(crypto::derive(pass.as_bytes(), &salt, &opts.kdf).map_err(|e| BundleError::Invalid(e.to_string()))?);
        manifest.vault = Some(VaultInfo {
            kdf: opts.kdf,
            salt_b64: base64::engine::general_purpose::STANDARD.encode(&salt),
            envelope_version: crypto::ENVELOPE_V1,
            cipher: "xchacha20poly1305".into(),
        });
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let mut checksums: BTreeMap<String, String> = BTreeMap::new();
    checksums.insert(MANIFEST_ENTRY.into(), sha256(&manifest_bytes));
    for (n, b) in &files {
        checksums.insert(n.clone(), sha256(b));
    }
    // The vault is sealed last, bound to every other entry as written.
    if let Some(key) = key {
        let payload = zeroize::Zeroizing::new(serde_json::to_vec(&vault)?);
        let sealed = crypto::seal(&key, &vault_aad(manifest.format_version, &checksums), &payload);
        checksums.insert(VAULT_ENTRY.into(), sha256(&sealed));
        files.push((VAULT_ENTRY.into(), Cow::Owned(sealed)));
    }
    files.insert(0, (MANIFEST_ENTRY.into(), Cow::Owned(manifest_bytes)));
    files.push((
        CHECKSUMS_ENTRY.into(),
        Cow::Owned(serde_json::to_vec_pretty(&checksums)?),
    ));
    let mut stored = BTreeSet::new();
    let mut bytes = zip_export_files(&files, &stored)?;
    {
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes))?;
        for index in 0..archive.len() {
            let f = archive.by_index_raw(index)?;
            if f.size() / f.compressed_size().max(1) > MAX_RATIO {
                stored.insert(f.name().to_string());
            }
        }
    }
    // Highly compressible legitimate exports must still pass the reader's ratio
    // rule. Rebuild only when needed, storing those entries without compression.
    // Digests and vault AAD bind inflated bytes, so this changes neither.
    if !stored.is_empty() {
        drop(bytes);
        bytes = zip_export_files(&files, &stored)?;
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(&bytes))?;
    preflight(&mut archive, &bytes, READ_LIMITS)?;
    drop(archive);
    let preview = ExportPreview {
        manifest,
        secrets_included: vault.secrets.len(),
        literals_moved: vault.literals.len(),
        linked_files: graph.linked_files(),
    };
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
    let allowed =
        [MANIFEST_ENTRY, CHECKSUMS_ENTRY, "workspace/objects.json", "settings/portable.json", "history/records.jsonl", VAULT_ENTRY];
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
    p.check_bounds().map_err(BundleError::UnsupportedKdf)
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

#[derive(Clone, Copy)]
struct ReadLimits {
    entries: usize,
    total: u64,
    entry: u64,
    ratio: u64,
}

const READ_LIMITS: ReadLimits = ReadLimits { entries: MAX_ENTRIES, total: MAX_TOTAL_BYTES, entry: MAX_ENTRY_BYTES, ratio: MAX_RATIO };

struct EntryInfo {
    index: usize,
    declared: u64,
    compressed: u64,
}

// zip's name index keeps only the last record for a repeated raw filename.
// Walk the central headers too, without decoding or expanding their payloads,
// so duplicates cannot hide entry counts, types or sizes from preflight.
fn check_directory(bytes: &[u8], start: u64, indexed_count: usize, limits: ReadLimits) -> Result<(), BundleError> {
    let invalid = || BundleError::NotABundle("invalid central directory".into());
    let mut offset = usize::try_from(start).map_err(|_| invalid())?;
    let mut names = BTreeSet::new();
    let mut count = 0usize;
    while bytes.get(offset..offset.saturating_add(4)) == Some(b"PK\x01\x02") {
        let header_end = offset.checked_add(46).ok_or_else(invalid)?;
        let header = bytes.get(offset..header_end).ok_or_else(invalid)?;
        let length = |at| u16::from_le_bytes([header[at], header[at + 1]]) as usize;
        let name_end = header_end.checked_add(length(28)).ok_or_else(invalid)?;
        let end = name_end.checked_add(length(30)).and_then(|n| n.checked_add(length(32))).ok_or_else(invalid)?;
        let name = bytes.get(header_end..name_end).ok_or_else(invalid)?;
        bytes.get(name_end..end).ok_or_else(invalid)?;
        count = count.checked_add(1).ok_or_else(invalid)?;
        if count > limits.entries {
            return Err(BundleError::Limits(format!("{count} entries (max {})", limits.entries)));
        }
        if !names.insert(name) {
            return Err(BundleError::Unsafe(String::from_utf8_lossy(name).into_owned(), "duplicate entry".into()));
        }
        offset = end;
    }
    if count != indexed_count {
        return Err(invalid());
    }
    Ok(())
}

fn check_entry_size(name: &str, info: &EntryInfo, limits: ReadLimits) -> Result<(), BundleError> {
    // Preserve the existing integer-quotient ratio rule. Division avoids
    // overflow even when a hostile compressed size is near u64::MAX.
    let ratio = info.declared / info.compressed.max(1);
    if info.declared > limits.entry || ratio > limits.ratio {
        return Err(BundleError::Limits(format!("entry '{name}' declares {} bytes (compression ratio {ratio})", info.declared)));
    }
    Ok(())
}

fn charge_total_bytes(size: u64, remaining: &mut u64) -> Result<(), BundleError> {
    *remaining = remaining
        .checked_sub(size)
        .ok_or_else(|| BundleError::Limits("total uncompressed size exceeds the byte budget".into()))?;
    Ok(())
}

fn charge_entry_bytes(
    name: &str,
    size: u64,
    remaining: &mut u64,
    limits: ReadLimits,
) -> Result<(), BundleError> {
    if size > limits.entry {
        return Err(BundleError::Limits(format!(
            "entry '{name}' exceeds the {}-byte entry budget",
            limits.entry
        )));
    }
    charge_total_bytes(size, remaining)
}

fn preflight<R: Read + Seek>(
    zr: &mut zip::ZipArchive<R>,
    bytes: &[u8],
    limits: ReadLimits,
) -> Result<BTreeMap<String, EntryInfo>, BundleError> {
    check_directory(bytes, zr.central_directory_start(), zr.len(), limits)?;
    let mut entries = BTreeMap::new();
    let mut remaining = limits.total;
    for index in 0..zr.len() {
        // Raw readers inspect local headers but never initialize an inflater.
        let f = zr.by_index_raw(index)?;
        let name = f.name().to_string();
        safe_name(&name)?;
        let file_type = f.unix_mode().unwrap_or(0) & 0o170000;
        if !f.is_file() || (file_type != 0 && file_type != 0o100000) {
            return Err(BundleError::Unsafe(name, "only regular files are allowed".into()));
        }
        if f.enclosed_name().is_none() {
            return Err(BundleError::Unsafe(name, "path escapes the archive".into()));
        }
        let info = EntryInfo { index, declared: f.size(), compressed: f.compressed_size() };
        check_entry_size(&name, &info, limits)?;
        charge_entry_bytes(&name, info.declared, &mut remaining, limits)?;
        if entries.insert(name.clone(), info).is_some() {
            return Err(BundleError::Unsafe(name, "duplicate entry".into()));
        }
    }
    for name in [MANIFEST_ENTRY, CHECKSUMS_ENTRY, "workspace/objects.json"] {
        if !entries.contains_key(name) {
            return Err(BundleError::NotABundle(format!("missing {name}")));
        }
    }
    Ok(entries)
}

// Check the complete reservation before allocating; charge each actual read
// against one cumulative budget, including metadata whose buffers are dropped.
// Retain at most the declared size; a one-byte probe detects a lying size,
// including data-descriptor ZIPs.
// Every inflated read is bounded by both the per-entry and remaining budgets.
fn read_entry<R: Read + Seek>(
    zr: &mut zip::ZipArchive<R>,
    name: &str,
    info: &EntryInfo,
    remaining: &mut u64,
    limits: ReadLimits,
) -> Result<(Vec<u8>, String), BundleError> {
    check_entry_size(name, info, limits)?;
    let available = (*remaining).min(limits.entry);
    let mut reservation = *remaining;
    charge_entry_bytes(name, info.declared, &mut reservation, limits)?;
    let bound = available.checked_add(1).ok_or_else(|| BundleError::Limits("read budget overflow".into()))?;
    let capacity = usize::try_from(info.declared).map_err(|_| BundleError::Limits("entry does not fit in memory".into()))?;
    let mut reader = zr.by_index(info.index)?.take(bound);
    let mut data = Vec::new();
    data.try_reserve_exact(capacity).map_err(|_| BundleError::Limits("cannot allocate entry within the budget".into()))?;
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 8192];
    loop {
        // Request no more than the declared remainder plus a sentinel, even
        // when there is ample aggregate budget left for later entries.
        let probe = info
            .declared
            .checked_sub(data.len() as u64)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| BundleError::Limits("read size overflow".into()))?;
        let request = probe.min(chunk.len() as u64) as usize;
        let n = match reader.read(&mut chunk[..request]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        let actual = (data.len() as u64).checked_add(n as u64).ok_or_else(|| BundleError::Limits("inflated size overflow".into()))?;
        if actual > available {
            return Err(BundleError::Limits(format!("entry '{name}' expands beyond the remaining budget")));
        }
        charge_total_bytes(n as u64, remaining)?;
        if actual > info.declared || (n == 0 && actual != info.declared) {
            return Err(BundleError::Invalid(format!("entry '{name}' inflated size does not match its declared size")));
        }
        if n == 0 {
            break;
        }
        hash.update(&chunk[..n]);
        data.extend_from_slice(&chunk[..n]);
    }
    Ok((data, hex::encode(hash.finalize())))
}

fn verify_digest(name: &str, digest: &str, checksums: &BTreeMap<String, String>) -> Result<(), BundleError> {
    if checksums.get(name).is_some_and(|expected| expected == digest) { Ok(()) } else { Err(BundleError::Checksum(name.to_string())) }
}

/// Open and fully validate a bundle. Nothing is written anywhere.
/// Directory and mandatory metadata checks precede payload expansion. The
/// Shared 64 MiB/32 MiB byte budgets are not bounds on parser or process memory.
pub fn open(bytes: &[u8], passphrase: Option<&str>) -> Result<Opened, BundleError> {
    let zr = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| BundleError::NotABundle(e.to_string()))?;
    open_archive(bytes, zr, passphrase, READ_LIMITS)
}

// The reader must address `bytes`. Keeping it generic lets unit tests count
// actual archive payload reads through this same path, without a public hook.
fn open_archive<R: Read + Seek>(
    bytes: &[u8],
    mut zr: zip::ZipArchive<R>,
    passphrase: Option<&str>,
    limits: ReadLimits,
) -> Result<Opened, BundleError> {
    let entries = preflight(&mut zr, bytes, limits)?;
    let mut remaining = limits.total;
    let (manifest_bytes, manifest_digest) = read_entry(&mut zr, MANIFEST_ENTRY, &entries[MANIFEST_ENTRY], &mut remaining, limits)?;
    let checksums: BTreeMap<String, String> = {
        let (data, _) = read_entry(&mut zr, CHECKSUMS_ENTRY, &entries[CHECKSUMS_ENTRY], &mut remaining, limits)?;
        serde_json::from_slice(&data)?
    };
    for name in entries.keys().filter(|name| name.as_str() != CHECKSUMS_ENTRY) {
        match checksums.get(name) {
            Some(digest) if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {}
            _ => return Err(BundleError::Checksum(name.clone())),
        }
    }
    for name in checksums.keys() {
        if !entries.contains_key(name) {
            return Err(BundleError::Checksum(format!("{name} (missing)")));
        }
    }
    verify_digest(MANIFEST_ENTRY, &manifest_digest, &checksums)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|e| BundleError::NotABundle(format!("manifest: {e}")))?;
    drop(manifest_bytes);
    if manifest.format != FORMAT {
        return Err(BundleError::NotABundle(format!("unknown format '{}'", manifest.format)));
    }
    if manifest.format_version > FORMAT_VERSION {
        return Err(BundleError::FutureFormat { found: manifest.format_version, supported: FORMAT_VERSION });
    }
    // Full backups were once written as bundles, with a vault that bound
    // nothing else in the archive. One that still describes itself as such
    // is refused before any object is interpreted or the vault is opened;
    // one relabelled as a workspace bundle has a format 1 vault (below).
    if is_full_backup(manifest.kind, manifest.mode) || entries.contains_key("settings/portable.json") {
        return Err(BundleError::LegacyFullBackup);
    }
    // A vault is only ever opened as part of the exact bundle it was sealed
    // with. Earlier formats sealed it without binding anything else in the
    // archive, so their vaults are refused before a passphrase is asked for.
    match (&manifest.vault, manifest.mode) {
        (Some(_), ExportMode::EncryptedTransfer) if !entries.contains_key(VAULT_ENTRY) => {
            return Err(BundleError::Checksum(format!("{VAULT_ENTRY} (missing)")));
        }
        (Some(_), ExportMode::EncryptedTransfer) if manifest.format_version < MIN_VAULT_FORMAT_VERSION => {
            return Err(BundleError::UnboundVault);
        }
        (Some(_), ExportMode::EncryptedTransfer) => {}
        (None, ExportMode::ShareSafely) if !entries.contains_key(VAULT_ENTRY) => {}
        _ => {
            return Err(BundleError::Invalid("the manifest's export mode does not match the bundle's encrypted vault".into()));
        }
    }
    // A passphrase is only ever checked against a vault. One given for a
    // bundle without a vault would verify nothing, yet read as though the
    // bundle had been checked against it.
    if manifest.vault.is_none() && passphrase.is_some() {
        return Err(BundleError::NotEncrypted);
    }
    // Schema compatibility is settled before any object is interpreted:
    // serde would silently drop fields a newer schema added.
    check_schema(manifest.schema_version)?;
    // Vault metadata needs no payload expansion or key derivation. Keep its
    // existing per-entry budget rather than adding a smaller metadata cap.
    let vault_salt = if let Some(v) = &manifest.vault {
        check_kdf(&v.kdf)?;
        if v.cipher != "xchacha20poly1305" || v.envelope_version != crypto::ENVELOPE_V1 {
            return Err(BundleError::Invalid("unsupported vault cipher or envelope version".into()));
        }
        let salt = base64::engine::general_purpose::STANDARD.decode(&v.salt_b64).map_err(|_| BundleError::Invalid("vault salt".into()))?;
        crypto::check_salt(&salt).map_err(BundleError::UnsupportedKdf)?;
        if passphrase.is_none() {
            return Err(BundleError::PassphraseRequired);
        }
        Some(salt)
    } else {
        None
    };
    let mut objects: serde_json::Value = {
        let name = "workspace/objects.json";
        let (data, digest) = read_entry(&mut zr, name, &entries[name], &mut remaining, limits)?;
        verify_digest(name, &digest, &checksums)?;
        serde_json::from_slice(&data)?
    };
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
        let salt = vault_salt.as_ref().ok_or_else(|| BundleError::Invalid("vault salt".into()))?;
        let pass = passphrase.ok_or(BundleError::PassphraseRequired)?;
        let (enc, digest) = read_entry(&mut zr, VAULT_ENTRY, &entries[VAULT_ENTRY], &mut remaining, limits)?;
        verify_digest(VAULT_ENTRY, &digest, &checksums)?;
        let key = crypto::derive(pass.as_bytes(), salt, &v.kdf).map_err(|e| BundleError::Invalid(e.to_string()))?;
        // The listing still binds every other entry's exact bytes. Remaining
        // payload digests are checked below before Opened can be returned.
        let aad = vault_aad(manifest.format_version, &checksums);
        let pt = crypto::open(&key, &aad, &enc).map_err(|_| BundleError::WrongPassphrase)?;
        drop(enc);
        let payload: VaultPayload = serde_json::from_slice(&pt)?;
        // Literals go back only to the fields the manifest lists as replaced,
        // each of which must still hold its placeholder.
        let listed = manifest.placeholders.iter().map(|p| (&p.pointer, &p.placeholder));
        if !payload.literals.iter().map(|l| (&l.pointer, &l.placeholder)).eq(listed) {
            return Err(BundleError::Invalid("the encrypted vault does not match the manifest's placeholders".into()));
        }
        sanitize::restore(&mut objects, &payload.literals).map_err(BundleError::Invalid)?;
        secrets = payload.secrets;
        secrets_restored = true;
    }
    let mut graph: PortableGraph = serde_json::from_value(objects)
        .map_err(|e| BundleError::Invalid(format!("objects.json does not match schema {}: {e}", manifest.schema_version)))?;
    graph.secrets = secrets;
    for (name, info) in &entries {
        if let Some(h) = name.strip_prefix("attachments/") {
            let (data, digest) = read_entry(&mut zr, name, info, &mut remaining, limits)?;
            verify_digest(name, &digest, &checksums)?;
            if digest != h {
                return Err(BundleError::Checksum(name.clone()));
            }
            // Opened owns the attachment bytes; no second retained copy.
            graph.attachments.insert(h.to_string(), data);
        }
    }
    let history_name = "history/records.jsonl";
    if let Some(info) = entries.get(history_name) {
        let (h, digest) = read_entry(&mut zr, history_name, info, &mut remaining, limits)?;
        verify_digest(history_name, &digest, &checksums)?;
        for line in h.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let record: serde_json::Value = serde_json::from_slice(line)?;
            check_record_schema(&record, "history record")?;
            graph.history.push(record);
        }
    }
    let mut warnings = crate::validate::validate_and_normalize(&mut graph)?;
    // Each imported OAuth 2 profile caches its token under the object that
    // defines it, never under a cache id the bundle names.
    crate::validate::clear_token_cache_ids(&mut graph);
    // A gateway profile's diagnostic reference lookup never arrives in a bundle.
    warnings.extend(crate::validate::clear_gateway_lookups(&mut graph));
    Ok(Opened { manifest, graph, warnings, secrets_restored })
}

#[cfg(test)]
mod read_tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::SeekFrom;
    use std::ops::Range;
    use std::rc::Rc;

    type Files = Vec<(String, Vec<u8>)>;
    type ReadCounts = Rc<RefCell<BTreeMap<String, usize>>>;

    struct TrackedReader<'a> {
        cursor: Cursor<&'a [u8]>,
        payloads: Vec<(String, Range<u64>)>,
        counts: ReadCounts,
    }

    impl Read for TrackedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let start = self.cursor.position();
            let n = self.cursor.read(buf)?;
            let end = start + n as u64;
            for (name, range) in &self.payloads {
                let overlap = end.min(range.end).saturating_sub(start.max(range.start));
                *self.counts.borrow_mut().entry(name.clone()).or_default() += overlap as usize;
            }
            Ok(n)
        }
    }

    impl Seek for TrackedReader<'_> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.cursor.seek(pos)
        }
    }

    fn tracked(bytes: &[u8]) -> (zip::ZipArchive<TrackedReader<'_>>, ReadCounts) {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut payloads = Vec::new();
        for index in 0..archive.len() {
            let f = archive.by_index_raw(index).unwrap();
            let start = f.data_start().unwrap();
            payloads.push((f.name().to_string(), start..start + f.compressed_size()));
        }
        let counts = Rc::new(RefCell::new(BTreeMap::new()));
        let reader = TrackedReader { cursor: Cursor::new(bytes), payloads, counts: counts.clone() };
        let archive = zip::ZipArchive::new(reader).unwrap();
        // Directory discovery may scan the end of a small archive. Count
        // reads after discovery, through preflight and actual entry readers.
        counts.borrow_mut().clear();
        (archive, counts)
    }

    fn fixture(mode: ExportMode) -> Files {
        let mut graph = PortableGraph::default();
        for data in [vec![17; 2048], vec![23; 2048]] {
            graph.attachments.insert(sha256(&data), data);
        }
        let options = ExportOptions {
            kind: BundleKind::Workspace,
            mode,
            passphrase: Some("correct horse battery"),
            include_history: false,
            kdf: KdfParams::testing(),
            app_version: "test",
        };
        let (bytes, _) = write(&graph, &options).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut files = Vec::new();
        for index in 0..archive.len() {
            let mut f = archive.by_index(index).unwrap();
            let mut data = Vec::new();
            f.read_to_end(&mut data).unwrap();
            files.push((f.name().to_string(), data));
        }
        // Attachments precede metadata on disk: ordering must not depend on
        // the order the exporter happens to use.
        files.sort_by_key(|(name, _)| !name.starts_with("attachments/"));
        files
    }

    fn update_checksums(files: &mut Files) {
        let checksums: BTreeMap<_, _> =
            files.iter().filter(|(name, _)| name != CHECKSUMS_ENTRY).map(|(name, data)| (name.clone(), sha256(data))).collect();
        let data = serde_json::to_vec(&checksums).unwrap();
        files.iter_mut().find(|(name, _)| name == CHECKSUMS_ENTRY).unwrap().1 = data;
    }

    fn edit_json(files: &mut Files, name: &str, edit: impl FnOnce(&mut serde_json::Value)) {
        let (_, data) = files.iter_mut().find(|(n, _)| n == name).unwrap();
        let mut json = serde_json::from_slice(data).unwrap();
        edit(&mut json);
        *data = serde_json::to_vec(&json).unwrap();
    }

    fn pack(files: &Files, compression: zip::CompressionMethod, descriptor: bool) -> Vec<u8> {
        let options = SimpleFileOptions::default().compression_method(compression);
        if descriptor {
            let mut writer = zip::ZipWriter::new_stream(Vec::new());
            for (name, data) in files {
                writer.start_file(name.as_str(), options).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap().into_inner()
        } else {
            let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
            for (name, data) in files {
                writer.start_file(name.as_str(), options).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap().into_inner()
        }
    }

    fn boundary_limits(files: &Files) -> ReadLimits {
        ReadLimits {
            entries: files.len(),
            total: files.iter().map(|(_, data)| data.len() as u64).sum(),
            entry: files.iter().map(|(_, data)| data.len() as u64).max().unwrap(),
            ratio: MAX_RATIO,
        }
    }

    fn assert_no_payload_reads(counts: &ReadCounts, metadata_allowed: bool) {
        for (name, count) in counts.borrow().iter() {
            if !metadata_allowed || (name != MANIFEST_ENTRY && name != CHECKSUMS_ENTRY) {
                assert_eq!(*count, 0, "unexpected payload read from {name}");
            }
        }
    }

    fn refused_before_payloads(files: &Files) -> BundleError {
        let bytes = pack(files, zip::CompressionMethod::Deflated, false);
        let (archive, counts) = tracked(&bytes);
        let error = open_archive(&bytes, archive, None, READ_LIMITS).unwrap_err();
        assert_no_payload_reads(&counts, true);
        error
    }

    #[test]
    fn mandatory_metadata_is_required_before_any_entry_is_read() {
        for missing in [MANIFEST_ENTRY, CHECKSUMS_ENTRY, "workspace/objects.json"] {
            let mut files = fixture(ExportMode::ShareSafely);
            files.retain(|(name, _)| name != missing);
            let bytes = pack(&files, zip::CompressionMethod::Stored, false);
            let (archive, counts) = tracked(&bytes);
            let error = open_archive(&bytes, archive, None, READ_LIMITS).unwrap_err();
            assert!(matches!(error, BundleError::NotABundle(_)), "{missing}: {error}");
            assert_no_payload_reads(&counts, false);
        }
    }

    #[test]
    fn malformed_unknown_and_future_manifest_precede_attachment_expansion() {
        let original = fixture(ExportMode::ShareSafely);
        for invalid in [b"{".as_slice(), b"{}".as_slice()] {
            let mut files = original.clone();
            files.iter_mut().find(|(n, _)| n == MANIFEST_ENTRY).unwrap().1 = invalid.to_vec();
            update_checksums(&mut files);
            assert!(matches!(refused_before_payloads(&files), BundleError::NotABundle(_)));
        }
        for (field, value, expected) in [
            ("format", serde_json::json!("unknown"), "not_bundle"),
            ("format_version", serde_json::json!(FORMAT_VERSION + 1), "future_format"),
            ("schema_version", serde_json::json!(anvil_domain::SCHEMA_VERSION + 1), "future_schema"),
            ("schema_version", serde_json::json!(0), "old_schema"),
            ("kind", serde_json::json!("backup"), "backup"),
        ] {
            let mut files = original.clone();
            edit_json(&mut files, MANIFEST_ENTRY, |m| m[field] = value);
            update_checksums(&mut files);
            let error = refused_before_payloads(&files);
            let category = match error {
                BundleError::NotABundle(_) => "not_bundle",
                BundleError::FutureFormat { .. } => "future_format",
                BundleError::FutureSchema { .. } => "future_schema",
                BundleError::UnsupportedSchema { .. } => "old_schema",
                BundleError::LegacyFullBackup => "backup",
                other => panic!("unexpected metadata failure: {other}"),
            };
            assert_eq!(category, expected, "{field}");
        }
    }

    #[test]
    fn checksum_metadata_is_validated_before_attachment_expansion() {
        let original = fixture(ExportMode::ShareSafely);
        let attachment = original.iter().find(|(n, _)| n.starts_with("attachments/")).unwrap().0.clone();
        let mut malformed = original.clone();
        malformed.iter_mut().find(|(n, _)| n == CHECKSUMS_ENTRY).unwrap().1 = b"{".to_vec();
        assert!(matches!(refused_before_payloads(&malformed), BundleError::Json(_)));
        for bad in [None, Some("0".repeat(64)), Some("z".repeat(64)), Some("ab".into())] {
            let mut files = original.clone();
            edit_json(&mut files, CHECKSUMS_ENTRY, |c| {
                if let Some(digest) = bad {
                    // The well-formed wrong digest tests the manifest hash;
                    // malformed attachment hashes can be rejected cheaply.
                    let name = if digest == "0".repeat(64) { MANIFEST_ENTRY } else { &attachment };
                    c[name] = digest.into();
                } else {
                    c.as_object_mut().unwrap().remove(&attachment);
                }
            });
            assert!(matches!(refused_before_payloads(&files), BundleError::Checksum(_)));
        }
        let mut extra = original;
        edit_json(&mut extra, CHECKSUMS_ENTRY, |c| {
            c["attachments/absent"] = "0".repeat(64).into();
        });
        assert!(matches!(refused_before_payloads(&extra), BundleError::Checksum(_)));
    }

    #[test]
    fn vault_metadata_is_validated_without_reading_objects_or_attachments() {
        let original = fixture(ExportMode::EncryptedTransfer);
        for (field, value) in [
            ("cipher", serde_json::json!("unsupported")),
            ("envelope_version", serde_json::json!(255)),
            ("salt_b64", serde_json::json!("invalid base64")),
            ("salt_b64", serde_json::json!("AA==")),
            ("kdf", serde_json::json!({"algorithm": "argon2id", "m_cost": 0, "t_cost": 1, "p_cost": 1})),
        ] {
            let mut files = original.clone();
            edit_json(&mut files, MANIFEST_ENTRY, |m| m["vault"][field] = value);
            update_checksums(&mut files);
            let error = refused_before_payloads(&files);
            assert!(matches!(error, BundleError::Invalid(_) | BundleError::UnsupportedKdf(_)));
        }
        assert!(matches!(refused_before_payloads(&original), BundleError::PassphraseRequired));
        let mut old = original.clone();
        edit_json(&mut old, MANIFEST_ENTRY, |m| m["format_version"] = 1.into());
        update_checksums(&mut old);
        assert!(matches!(refused_before_payloads(&old), BundleError::UnboundVault));
        let mut missing = original;
        missing.retain(|(name, _)| name != VAULT_ENTRY);
        update_checksums(&mut missing);
        assert!(matches!(refused_before_payloads(&missing), BundleError::Checksum(_)));
    }

    fn central_offset(bytes: &[u8], name: &str) -> usize {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let offset = archive.by_name(name).unwrap().central_header_start();
        offset as usize
    }

    fn assert_preflight_refusal(bytes: &[u8], limits: ReadLimits) -> BundleError {
        let (archive, counts) = tracked(bytes);
        let error = open_archive(bytes, archive, None, limits).unwrap_err();
        assert_no_payload_reads(&counts, false);
        error
    }

    #[test]
    fn directory_counts_sizes_and_aggregate_are_checked_before_allocation() {
        let files = fixture(ExportMode::ShareSafely);
        let bytes = pack(&files, zip::CompressionMethod::Stored, false);
        let limits = boundary_limits(&files);
        for smaller in [
            ReadLimits { entries: limits.entries - 1, ..limits },
            ReadLimits { total: limits.total - 1, ..limits },
            ReadLimits { entry: limits.entry - 1, ..limits },
        ] {
            assert!(matches!(assert_preflight_refusal(&bytes, smaller), BundleError::Limits(_)));
        }
        let attachment = &files[0].0;
        let offset = central_offset(&bytes, attachment);
        let mut oversized = bytes.clone();
        oversized[offset + 24..offset + 28].copy_from_slice(&((MAX_ENTRY_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(assert_preflight_refusal(&oversized, READ_LIMITS), BundleError::Limits(_)));
        let mut ratio = bytes;
        ratio[offset + 20..offset + 24].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(assert_preflight_refusal(&ratio, READ_LIMITS), BundleError::Limits(_)));
    }

    #[test]
    fn duplicate_raw_names_and_unsupported_names_and_types_precede_allocation() {
        let files = fixture(ExportMode::ShareSafely);
        let bytes = pack(&files, zip::CompressionMethod::Stored, false);
        let offset = central_offset(&bytes, &files[1].0);
        let mut duplicate = bytes.clone();
        duplicate[offset + 46..offset + 46 + files[0].0.len()].copy_from_slice(files[0].0.as_bytes());
        // zip's indexed length is now one smaller; our raw directory walk
        // must still see and refuse the duplicate before opening any entry.
        let indexed_count = zip::ZipArchive::new(Cursor::new(&duplicate)).unwrap().len();
        assert_eq!(indexed_count, files.len() - 1);
        assert!(matches!(
            assert_preflight_refusal(&duplicate, READ_LIMITS),
            BundleError::Unsafe(_, why) if why == "duplicate entry"
        ));
        for mode in [0o120600u32, 0o040600, 0o010600, 0o020600] {
            let mut wrong_type = bytes.clone();
            wrong_type[offset + 38..offset + 42].copy_from_slice(&(mode << 16).to_le_bytes());
            assert!(matches!(assert_preflight_refusal(&wrong_type, READ_LIMITS), BundleError::Unsafe(..)));
        }
        for name in ["unexpected.json", "../escape", "attachments/not-a-hash"] {
            let mut unsupported = files.clone();
            unsupported.push((name.into(), vec![1; 32]));
            let archive = pack(&unsupported, zip::CompressionMethod::Stored, false);
            assert!(matches!(assert_preflight_refusal(&archive, READ_LIMITS), BundleError::Unsafe(..)));
        }
    }

    #[test]
    fn valid_archives_open_at_exact_scaled_budgets_and_keep_vault_binding() {
        assert_eq!((READ_LIMITS.total, READ_LIMITS.entry), (64 << 20, 32 << 20));
        assert_eq!((READ_LIMITS.ratio, READ_LIMITS.entries), (200, 20_000));
        for mode in [ExportMode::ShareSafely, ExportMode::EncryptedTransfer] {
            let files = fixture(mode);
            let limits = boundary_limits(&files);
            let bytes = pack(&files, zip::CompressionMethod::Stored, true);
            let (archive, counts) = tracked(&bytes);
            let pass = (mode == ExportMode::EncryptedTransfer).then_some("correct horse battery");
            let opened = open_archive(&bytes, archive, pass, limits).unwrap();
            assert_eq!(opened.graph.attachments.len(), 2);
            assert_eq!(opened.secrets_restored, pass.is_some());
            for (name, data) in &files {
                assert_eq!(counts.borrow()[name], data.len(), "each entry is read once");
                if let Some(hash) = name.strip_prefix("attachments/") {
                    assert_eq!(&opened.graph.attachments[hash], data);
                }
            }
            if pass.is_some() {
                let mut edited = files.clone();
                edit_json(&mut edited, MANIFEST_ENTRY, |m| m["counts"]["requests"] = 1.into());
                update_checksums(&mut edited);
                let changed = pack(&edited, zip::CompressionMethod::Stored, false);
                let (archive, _) = tracked(&changed);
                let error = open_archive(&changed, archive, pass, boundary_limits(&edited)).unwrap_err();
                assert!(matches!(error, BundleError::WrongPassphrase));
            }
        }
    }

    #[test]
    fn format_one_share_safe_and_metadata_use_the_same_entry_budget() {
        let mut files = fixture(ExportMode::ShareSafely);
        edit_json(&mut files, MANIFEST_ENTRY, |m| {
            m["format_version"] = 1.into();
            m["app_version"] = "x".repeat(8192).into();
        });
        update_checksums(&mut files);
        let bytes = pack(&files, zip::CompressionMethod::Stored, false);
        let (archive, _) = tracked(&bytes);
        let opened = open_archive(&bytes, archive, None, boundary_limits(&files)).unwrap();
        assert_eq!(opened.manifest.format_version, 1);
        assert_eq!(opened.manifest.app_version.len(), 8192);
        assert_eq!(opened.graph.attachments.len(), 2);
    }

    #[test]
    fn lying_sizes_and_descriptors_cannot_overrun_remaining_aggregate() {
        let files = fixture(ExportMode::ShareSafely);
        let name = files.iter().filter(|(n, _)| n.starts_with("attachments/")).map(|(n, _)| n).max().unwrap();
        let actual = files.iter().find(|(n, _)| n == name).unwrap().1.len() as u64;
        for descriptor in [false, true] {
            let bytes = pack(&files, zip::CompressionMethod::Stored, descriptor);
            let offset = central_offset(&bytes, name);
            let flags = u16::from_le_bytes(bytes[offset + 8..offset + 10].try_into().unwrap());
            assert_eq!(flags & 8 != 0, descriptor);
            for declared in [7u64, actual - 1, actual + 1] {
                let mut lying = bytes.clone();
                lying[offset + 24..offset + 28].copy_from_slice(&(declared as u32).to_le_bytes());
                let limits = ReadLimits { total: boundary_limits(&files).total - actual + declared, entry: actual + 1, ..READ_LIMITS };
                let (archive, counts) = tracked(&lying);
                let error = open_archive(&lying, archive, None, limits).unwrap_err();
                if declared < actual {
                    assert!(matches!(error, BundleError::Limits(_)), "{error}");
                    assert_eq!(counts.borrow()[name], (declared + 1) as usize);
                    assert_eq!(counts.borrow().values().sum::<usize>() as u64, limits.total + 1);
                } else {
                    assert!(matches!(error, BundleError::Invalid(_)), "{error}");
                    assert_eq!(counts.borrow()[name], actual as usize);
                }
            }
        }
    }

    #[test]
    fn deflated_payloads_with_lying_sizes_are_refused_with_and_without_descriptors() {
        let files = fixture(ExportMode::ShareSafely);
        let name = &files[0].0;
        for descriptor in [false, true] {
            let bytes = pack(&files, zip::CompressionMethod::Deflated, descriptor);
            // First prove that the untouched deflated archive is accepted.
            let (archive, _) = tracked(&bytes);
            open_archive(&bytes, archive, None, boundary_limits(&files)).unwrap();
            let offset = central_offset(&bytes, name);
            let mut lying = bytes;
            lying[offset + 24..offset + 28].copy_from_slice(&7u32.to_le_bytes());
            let (archive, _) = tracked(&lying);
            let error = open_archive(&lying, archive, None, READ_LIMITS).unwrap_err();
            assert!(matches!(error, BundleError::Invalid(_)), "{error}");
        }
    }

    #[test]
    fn reservation_precedes_reading_and_inflation_has_a_one_byte_probe() {
        let name = format!("attachments/{}", "a".repeat(64));
        let files = vec![(name.clone(), vec![1; 64])];
        let bytes = pack(&files, zip::CompressionMethod::Stored, false);
        let info = EntryInfo { index: 0, declared: 7, compressed: 64 };
        let limits = ReadLimits { entry: 7, ..READ_LIMITS };
        for budget in [6, 7, 100] {
            let (mut archive, counts) = tracked(&bytes);
            let mut remaining = budget;
            let error = read_entry(&mut archive, &name, &info, &mut remaining, limits).unwrap_err();
            assert!(matches!(error, BundleError::Limits(_)), "{error}");
            if budget < info.declared {
                assert_no_payload_reads(&counts, false);
                assert_eq!(remaining, budget);
            } else {
                assert_eq!(counts.borrow()[&name], 8);
                // The sentinel is never retained; failure stops this opening.
                assert_eq!(remaining, budget);
            }
        }
    }

    #[test]
    fn actual_reads_charge_metadata_and_payloads_without_refunds() {
        let files = fixture(ExportMode::ShareSafely);
        let bytes = pack(&files, zip::CompressionMethod::Stored, false);
        let (mut archive, counts) = tracked(&bytes);
        let entries = preflight(&mut archive, &bytes, READ_LIMITS).unwrap();
        let mut remaining = MAX_TOTAL_BYTES;
        let mut total = 0;
        for (name, info) in entries {
            let (data, _) = read_entry(
                &mut archive,
                &name,
                &info,
                &mut remaining,
                READ_LIMITS,
            )
            .unwrap();
            total += data.len() as u64;
            drop(data);
            assert_eq!(remaining, MAX_TOTAL_BYTES - total);
        }
        assert_eq!(counts.borrow().values().sum::<usize>() as u64, total);
    }

    #[test]
    fn policy_boundaries_are_inclusive_and_all_entries_share_the_budget() {
        for name in [MANIFEST_ENTRY, CHECKSUMS_ENTRY, VAULT_ENTRY, "workspace/objects.json"] {
            let info = EntryInfo {
                index: 0,
                declared: MAX_ENTRY_BYTES,
                compressed: MAX_ENTRY_BYTES,
            };
            check_entry_size(name, &info, READ_LIMITS).unwrap();
            let larger = EntryInfo { declared: MAX_ENTRY_BYTES + 1, ..info };
            assert!(matches!(
                check_entry_size(name, &larger, READ_LIMITS),
                Err(BundleError::Limits(_))
            ));
        }
        let mut remaining = MAX_TOTAL_BYTES;
        charge_entry_bytes(
            MANIFEST_ENTRY,
            MAX_ENTRY_BYTES,
            &mut remaining,
            READ_LIMITS,
        )
        .unwrap();
        charge_entry_bytes("attachment", MAX_ENTRY_BYTES, &mut remaining, READ_LIMITS).unwrap();
        assert_eq!(remaining, 0);
        assert!(matches!(charge_total_bytes(1, &mut remaining), Err(BundleError::Limits(_))));
    }

    #[test]
    fn export_preflight_counts_exact_metadata_payload_history_and_vault_lengths() {
        for mode in [ExportMode::ShareSafely, ExportMode::EncryptedTransfer] {
            let mut graph = PortableGraph::default();
            for data in [vec![17; 2048], vec![23; 2048]] {
                graph.attachments.insert(sha256(&data), data);
            }
            graph.history.push(serde_json::json!({"status": "redacted"}));
            graph.secrets.insert(
                "test".into(),
                SecretValue {
                    label: "test".into(),
                    value: "private-test-value".into(),
                    workspace_id: None,
                },
            );
            let opts = ExportOptions {
                kind: BundleKind::Workspace,
                mode,
                passphrase: Some("correct horse battery"),
                include_history: true,
                kdf: KdfParams::testing(),
                app_version: "test",
            };
            let (bytes, preview) = write(&graph, &opts).unwrap();
            let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
            let mut files = Vec::new();
            for index in 0..archive.len() {
                let mut f = archive.by_index(index).unwrap();
                let mut data = Vec::new();
                f.read_to_end(&mut data).unwrap();
                files.push((f.name().to_string(), data));
            }
            let limits = boundary_limits(&files);
            let (_, objects, vault) = prepare(&graph, &opts).unwrap();
            export_preflight(
                &graph,
                &opts,
                &preview.manifest,
                &objects,
                &vault,
                limits,
            )
            .unwrap();
            for smaller in [
                ReadLimits { total: limits.total - 1, ..limits },
                ReadLimits { entry: limits.entry - 1, ..limits },
                ReadLimits { entries: limits.entries - 1, ..limits },
            ] {
                let error = export_preflight(
                    &graph,
                    &opts,
                    &preview.manifest,
                    &objects,
                    &vault,
                    smaller,
                )
                .unwrap_err();
                assert!(matches!(error, BundleError::Limits(_)));
                assert!(!error.to_string().contains("private-test-value"));
            }
            let pass = (mode == ExportMode::EncryptedTransfer).then_some("correct horse battery");
            open(&bytes, pass).unwrap();
        }
    }

    #[test]
    fn export_stores_over_ratio_entries_so_its_output_can_be_opened() {
        let mut graph = PortableGraph::default();
        let data = vec![0; 1024 * 1024];
        let hash = sha256(&data);
        graph.attachments.insert(hash.clone(), data);
        let opts = ExportOptions {
            kind: BundleKind::Workspace,
            mode: ExportMode::ShareSafely,
            passphrase: None,
            include_history: false,
            kdf: KdfParams::testing(),
            app_version: "test",
        };
        preview(&graph, &opts).unwrap();
        let (bytes, _) = write(&graph, &opts).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
        let entry = archive.by_name(&format!("attachments/{hash}")).unwrap();
        assert_eq!(entry.compression(), zip::CompressionMethod::Stored);
        assert_eq!(open(&bytes, None).unwrap().graph.attachments, graph.attachments);
    }

    #[test]
    fn export_metadata_history_and_vault_share_the_attachment_entry_cap() {
        for name in [
            MANIFEST_ENTRY,
            CHECKSUMS_ENTRY,
            "workspace/objects.json",
            "history/records.jsonl",
            VAULT_ENTRY,
        ] {
            let mut graph = PortableGraph::default();
            let mode = if name == VAULT_ENTRY {
                graph.secrets.insert(
                    "test".into(),
                    SecretValue {
                        label: "test".into(),
                        value: "private-test-value".repeat(256),
                        workspace_id: None,
                    },
                );
                ExportMode::EncryptedTransfer
            } else {
                ExportMode::ShareSafely
            };
            if name == CHECKSUMS_ENTRY {
                for index in 0..20 {
                    let data = vec![index; 32];
                    graph.attachments.insert(sha256(&data), data);
                }
            }
            if name == "history/records.jsonl" {
                graph.history.push(serde_json::json!({"sample": "x".repeat(4096)}));
            }
            let app_version = if name == MANIFEST_ENTRY { "x".repeat(4096) } else { "test".into() };
            let opts = ExportOptions {
                kind: BundleKind::Workspace,
                mode,
                passphrase: Some("correct horse battery"),
                include_history: true,
                kdf: KdfParams::testing(),
                app_version: &app_version,
            };
            let (manifest, mut objects, vault) = prepare(&graph, &opts).unwrap();
            if name == "workspace/objects.json" {
                objects = serde_json::json!({"sample": "x".repeat(4096)});
            }
            let limits = ReadLimits { entry: 2048, ..READ_LIMITS };
            let error = export_preflight(
                &graph,
                &opts,
                &manifest,
                &objects,
                &vault,
                limits,
            )
            .unwrap_err();
            assert!(matches!(error, BundleError::Limits(_)));
            assert!(error.to_string().contains(name), "{name}: {error}");
            assert!(!error.to_string().contains("private-test-value"));
        }
    }

    #[test]
    fn oversized_exports_fail_preview_and_write_before_returning_any_output() {
        let graph = PortableGraph::default();
        // No large buffer: excessive entry count is independently rejected early.
        let mut too_many = graph.clone();
        for index in 0..MAX_ENTRIES {
            too_many.attachments.insert(format!("{index:064x}"), Vec::new());
        }
        let opts = ExportOptions {
            kind: BundleKind::Workspace,
            mode: ExportMode::ShareSafely,
            passphrase: None,
            include_history: false,
            kdf: KdfParams::testing(),
            app_version: "test",
        };
        assert!(matches!(preview(&too_many, &opts), Err(BundleError::Limits(_))));
        assert!(matches!(write(&too_many, &opts), Err(BundleError::Limits(_))));
        let mut writer = LengthWriter { bytes: 7, bound: 8 };
        assert!(writer.write_all(b"secret").is_err());
        assert_eq!(writer.bytes, 7);
    }

    #[test]
    fn ratio_arithmetic_preserves_boundaries_without_overflow() {
        for compressed in [0, 1, 10, u64::MAX] {
            let info = EntryInfo { index: 0, declared: 200, compressed };
            check_entry_size("attachment", &info, READ_LIMITS).unwrap();
        }
        let info = EntryInfo { index: 0, declared: 2009, compressed: 10 };
        check_entry_size("attachment", &info, READ_LIMITS).unwrap();
        let too_large = EntryInfo { declared: 2010, ..info };
        assert!(matches!(check_entry_size("attachment", &too_large, READ_LIMITS), Err(BundleError::Limits(_))));
        let info = EntryInfo { index: 0, declared: u64::MAX, compressed: u64::MAX };
        let limits = ReadLimits { entry: u64::MAX, total: u64::MAX, ..READ_LIMITS };
        check_entry_size("attachment", &info, limits).unwrap();
    }
}
