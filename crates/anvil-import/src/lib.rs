//! Offline importers that turn API descriptions and other clients' exports
//! into Anvil workspace objects (build plan §11).
//!
//! Supported sources: OpenAPI 3.0/3.1/3.2 and Swagger 2.0 (JSON or YAML),
//! WSDL 1.1 (SOAP 1.1/1.2 bindings), Postman collections v2.0/v2.1 and
//! environments, Insomnia v4 JSON and v5 YAML exports, cURL command lines and
//! HAR 1.2 archives. See `docs/import.md` for the per-format construct list.
//!
//! Guarantees:
//! * **No I/O.** Nothing is fetched or read: external `$ref`s, WSDL/XSD
//!   imports and file references are listed in the [`ImportReport`] as
//!   requiring explicit approval (DATA-009).
//! * **Bounded.** Input size, parsed node count, nesting depth, `$ref`
//!   depth/expansions, generated sample size and operation count are all
//!   capped by [`ImportOptions`]; malformed input returns an error, never a
//!   panic. XML is parsed with DTDs refused (DATA-013).
//! * **Nothing becomes active by import.** Scripts are retained in the
//!   report as disabled/untrusted; TLS-verification bypasses, callbacks and
//!   similar settings are reported, never applied (DATA-008). Imported
//!   requests are never sent.
//! * **No invented credentials.** Auth is imported as placeholders that
//!   reference `{{variables}}` the user must supply; literal credentials in
//!   migrated collections/HAR files are replaced by placeholders unless
//!   [`ImportOptions::include_credentials`] is set.
//! * **Honest reporting.** Every construct that is not imported or only
//!   approximated is reported with its location.
//! * **Deterministic.** The same bytes and options produce the same objects
//!   and ids (UUIDv5 from the input hash, or from a caller-supplied
//!   namespace for reimports); timestamps come from
//!   [`ImportOptions::imported_at`] when set.

mod builder;
mod common;
mod detect;
mod insomnia;
mod openapi;
mod postman;
mod reimport;
mod report;
mod structured;
mod util;
mod wsdl;

pub use builder::ANVIL_IMPORT_NAMESPACE;
pub use detect::{Detected, Dialect, SourceKind, Syntax, detect};
pub use reimport::{ReimportApproval, ReimportChange, ReimportPlan, ReimportRemoval, reimport_diff};
pub use report::{
    ExternalRef, ExternalRefKind, Finding, ImportCounts, ImportReport, InactiveSetting, Redaction, RequiredVariable, RetainedScript,
};
pub use util::spec_hash;

use anvil_domain::Id;
use anvil_domain::workspace::{Environment, Folder, RequestDefinition, Workspace};
use chrono::{DateTime, Utc};
use detect::Parsed;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Blank or sample payloads for spec-driven imports (OpenAPI, WSDL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum SampleMode {
    /// Structurally correct, editable skeletons: empty strings, zeros,
    /// `false`, empty arrays, required object members (all members with
    /// `include_optional`). Examples, defaults and enums are *not* used.
    Blank,
    /// Explicit example → default/const/enum → seeded schema generator.
    #[default]
    Sample,
}

/// Folder layout for OpenAPI operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    /// One folder per (first) tag; OpenAPI 3.2 `parent` tags nest.
    #[default]
    Tags,
    /// One folder per first path segment.
    Paths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ImportOptions {
    pub mode: SampleMode,
    /// Seed for generated sample values. Each operation derives its own
    /// stream from this seed and its operation key, so adding or removing an
    /// operation does not change the samples of the others.
    pub seed: u64,
    pub group_by: GroupBy,
    /// Include optional parameters (enabled rather than disabled), optional
    /// body members and optional XML elements/attributes.
    pub include_optional: bool,
    /// Which OpenAPI server / Swagger scheme becomes the active environment.
    pub server_index: usize,
    /// Keep literal credentials found in migrated artifacts (HAR, cURL,
    /// Postman, Insomnia). Default `false`: they become `{{placeholders}}`
    /// and are listed in [`ImportReport::redactions`].
    pub include_credentials: bool,
    /// Maximum requests created; later operations are skipped and reported.
    pub max_operations: usize,
    /// Maximum input size in bytes.
    pub max_bytes: usize,
    /// Maximum chained/nested `$ref` depth followed while generating one value.
    pub max_ref_depth: usize,
    /// Maximum parsed JSON/YAML nodes (alias expansion included) or XML nodes.
    pub max_nodes: usize,
    /// Maximum `$ref` resolutions across the whole import.
    pub max_ref_expansions: usize,
    /// Maximum generated nodes per sample payload/envelope.
    pub max_sample_nodes: usize,
    /// Namespace for deterministic ids. `None` derives one from the input hash
    /// and options. Pass [`ImportedSource::id_namespace`] of a previous import
    /// to reimport a newer version so unchanged folders/requests keep ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_namespace: Option<Id>,
    /// Timestamp for created objects; `None` uses the current time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_at: Option<DateTime<Utc>>,
}

impl Default for ImportOptions {
    fn default() -> Self {
        ImportOptions {
            mode: SampleMode::Sample,
            seed: 0,
            group_by: GroupBy::Tags,
            include_optional: false,
            server_index: 0,
            include_credentials: false,
            max_operations: 5_000,
            max_bytes: 32 * 1024 * 1024,
            max_ref_depth: 32,
            max_nodes: 2_000_000,
            max_ref_expansions: 250_000,
            max_sample_nodes: 20_000,
            id_namespace: None,
            imported_at: None,
        }
    }
}

impl ImportOptions {
    /// The options that influence generated content (part of the id
    /// namespace so different choices never collide).
    pub(crate) fn fingerprint(&self) -> String {
        format!(
            "{:?}|{}|{:?}|{}|{}|{}",
            self.mode, self.seed, self.group_by, self.include_optional, self.server_index, self.include_credentials
        )
    }
}

/// Provenance of an import. Callers should store the original bytes as a
/// content-addressed attachment keyed by `sha256` (build plan §11: retain
/// the imported source and its hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ImportedSource {
    pub import_id: Id,
    /// Namespace every id in this result was derived from.
    pub id_namespace: Id,
    pub kind: SourceKind,
    pub dialect: Dialect,
    pub syntax: Syntax,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// SHA-256 (hex) of the exact input bytes.
    pub sha256: String,
    pub size_bytes: u64,
    pub imported_at: DateTime<Utc>,
    pub options: ImportOptions,
}

/// Imported objects plus the report. Nothing here has been persisted or
/// sent; the caller previews, lets the user choose, then saves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ImportResult {
    pub workspace: Workspace,
    /// Parents always precede children.
    pub folders: Vec<Folder>,
    pub requests: Vec<RequestDefinition>,
    pub environments: Vec<Environment>,
    pub source: ImportedSource,
    pub report: ImportReport,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportError {
    #[error("input is {size} bytes; the import limit is {max} bytes")]
    TooLarge { size: usize, max: usize },
    #[error("unrecognized input: {message}")]
    Unrecognized { message: String },
    #[error("{syntax} syntax error: {message}")]
    Syntax { syntax: String, message: String, line: Option<usize>, column: Option<usize> },
    #[error("{dialect} is not supported: {message}")]
    UnsupportedDialect { dialect: Dialect, message: String },
    #[error("import limit exceeded: {what} (limit {limit})")]
    LimitExceeded { what: String, limit: usize },
    #[error("invalid {dialect} document at {pointer}: {message}")]
    Invalid { dialect: Dialect, pointer: String, message: String },
    #[error("unsafe XML refused: {message}")]
    UnsafeXml { message: String },
}

/// Import `bytes` (format auto-detected). Performs no I/O.
pub fn import(bytes: &[u8], opts: &ImportOptions) -> Result<ImportResult, ImportError> {
    if bytes.len() > opts.max_bytes {
        return Err(ImportError::TooLarge { size: bytes.len(), max: opts.max_bytes });
    }
    let (detected, parsed) = detect::detect_parsed(bytes, opts)?;
    if !detected.dialect.is_supported() {
        let message = detected.note.clone().unwrap_or_else(|| "unrecognized format".into());
        return Err(if detected.dialect == Dialect::Unknown {
            ImportError::Unrecognized { message }
        } else {
            ImportError::UnsupportedDialect { dialect: detected.dialect, message }
        });
    }
    let sha = util::sha256_hex(bytes);
    let mut b = builder::Builder::new(opts, &sha);
    match (&parsed, detected.dialect) {
        (Parsed::Structured(v), Dialect::Swagger20 | Dialect::OpenApi30 | Dialect::OpenApi31 | Dialect::OpenApi32) => {
            openapi::import(v, detected.dialect, &mut b)?
        }
        (Parsed::Structured(v), Dialect::PostmanV20 | Dialect::PostmanV21) => postman::import_collection(v, detected.dialect, &mut b)?,
        (Parsed::Structured(v), Dialect::PostmanEnvironment | Dialect::PostmanGlobals) => postman::import_environment(v, &mut b)?,
        (Parsed::Structured(v), Dialect::InsomniaV4) => insomnia::import_v4(v, &mut b)?,
        (Parsed::Structured(v), Dialect::InsomniaV5) => insomnia::import_v5(v, &mut b)?,
        (Parsed::Xml(text), Dialect::Wsdl11) => wsdl::import(text, &mut b)?,
        _ => {
            return Err(ImportError::Unrecognized { message: format!("{} input could not be dispatched", detected.dialect) });
        }
    }
    Ok(b.finish(&detected, sha, bytes.len()))
}
