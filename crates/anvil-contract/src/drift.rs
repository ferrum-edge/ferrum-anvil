//! Contract drift: what an API was seen doing, compared with what its
//! OpenAPI description says, and the revisions that would make the
//! description match.
//!
//! Each observed exchange is routed to an operation ([`crate::route`]) and
//! checked: an undeclared path, method, status, content type or query
//! parameter; a JSON body that does not match its schema; a required
//! parameter or response header that was missing; and a call slower or
//! larger than the operation's declared budget (`x-anvil-expectations`,
//! see `docs/contract.md`). Findings are grouped across exchanges with a
//! count. Suggestions are patches to the description, written for its
//! dialect: an *addition* documents what was seen (a response, a property,
//! a path); a *relaxation* loosens the contract (a required property made
//! optional, a type widened, a budget raised) and may hide a bug in the
//! API instead, so it is not recommended by default.
//!
//! Messages and suggestions carry no observed values except property and
//! parameter names that look like names ([`safe_name`]), status codes,
//! media types, sizes and times: inferred schemas keep only the shape
//! ([`crate::infer`]), undeclared paths keep only short lower-case words
//! (every other segment becomes a parameter), and keys of map-like objects
//! become `*`. An observed value becomes part of a suggestion only as a
//! short enum token.

use crate::infer::{Shape, mark_nullable, safe_name};
use crate::lint::MAX_EXAMPLE_SCAN_STEPS;
use crate::lint::SpecSummary;
use crate::locate::ptr;
use crate::model::{Direction, METHODS, Media, OperationRef, parameters, request_body, responses, schema_types, swagger_media};
use crate::observe::{Observation, ObservedBody, count_values, essence, is_json, split_url};
use crate::patch::{self, PatchOp};
use crate::route::{Route, Router};
use crate::ruleset::Severity;
use crate::schema;
use crate::spec::Spec;
use anvil_import::Dialect;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// The extension an operation, path item or document declares its budget in.
pub const EXPECTATIONS: &str = "x-anvil-expectations";

/// Undeclared properties suggested per object schema.
const MAX_PROPERTIES_PER_SCHEMA: usize = 50;
/// Schema changes (properties, nulls, types, enums) suggested in all.
const MAX_SCHEMA_FIXES: usize = 500;
/// Observed enum values suggested per location.
const MAX_ENUM_TOKENS: usize = 20;
/// Body values walked for schema suggestions, across the analysis.
const MAX_WALK_STEPS: usize = 2_000_000;
/// Query parameter names kept per undeclared endpoint or per operation.
const MAX_QUERY_NAMES: usize = 50;
/// Undeclared endpoints and undeclared servers reported.
const MAX_ENDPOINTS: usize = 500;
const MAX_SERVERS: usize = 50;
/// Distinct findings collected before the most severe are kept.
const MAX_FINDING_KEYS: usize = 20_000;
/// Suggestions in a report.
const MAX_SUGGESTIONS: usize = 2_000;
/// Validation errors a body may produce before only its first is asked for:
/// the validator collects every error before any is read, and a body can
/// miss each name of a long `required` list in each of its objects.
const MAX_ERROR_WORK: usize = 1_000_000;
/// How an observed method that is not an HTTP token is shown.
const INVALID_METHOD: &str = "(invalid method)";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DriftOptions {
    /// Distinct findings kept (the most severe first).
    pub max_findings: usize,
    /// Observation ids kept per finding.
    pub max_examples: usize,
    /// Array items of a body walked for schema suggestions.
    pub max_items_walked: usize,
}

impl Default for DriftOptions {
    fn default() -> Self {
        DriftOptions { max_findings: 1_000, max_examples: 5, max_items_walked: 20 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    UndeclaredPath,
    UndeclaredMethod,
    UndeclaredStatus,
    UndeclaredContentType,
    ResponseSchemaMismatch,
    UndeclaredRequestContentType,
    UndeclaredQueryParameter,
    MissingRequiredParameter,
    MissingResponseHeader,
    SlowerThanDeclared,
    ResponseLargerThanDeclared,
    RequestLargerThanDeclared,
    UndeclaredServer,
    DeprecatedOperationCalled,
}

impl DriftKind {
    fn severity(self) -> Severity {
        match self {
            DriftKind::ResponseSchemaMismatch | DriftKind::SlowerThanDeclared | DriftKind::ResponseLargerThanDeclared => Severity::Error,
            DriftKind::UndeclaredQueryParameter
            | DriftKind::MissingRequiredParameter
            | DriftKind::UndeclaredServer
            | DriftKind::DeprecatedOperationCalled => Severity::Info,
            _ => Severity::Warn,
        }
    }
}

/// One kind of difference, seen in one or more exchanges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DriftFinding {
    pub kind: DriftKind,
    pub severity: Severity,
    pub message: String,
    /// `GET /pets/{id}`, when an operation (or observed endpoint) is concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Where in the description, when it names an existing object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Exchanges that showed it.
    pub count: usize,
    /// Some of those exchanges' ids.
    pub observations: Vec<String>,
    /// Suggestions that would resolve it.
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionKind {
    /// Documents something the API does that the description leaves out.
    Addition,
    /// Loosens the contract; the API may be what needs fixing.
    Relaxation,
}

/// A revision of the description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Suggestion {
    /// Derived from the description, what the suggestion is about and its
    /// operations: the same for the same description and observations, and
    /// different as soon as the change it makes is different.
    pub id: String,
    pub title: String,
    pub detail: String,
    pub kind: SuggestionKind,
    /// Selected by default (additions are, relaxations are not).
    pub recommended: bool,
    /// The main location it changes.
    pub pointer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub ops: Vec<PatchOp>,
    /// The change as a fragment of the description, in its syntax.
    pub snippet: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LatencyStats {
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
}

/// An operation's declared budget (`x-anvil-expectations`, the most
/// specific of operation, path item and document).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Budget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_latency_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_request_bytes: Option<u64>,
}

/// How an operation was exercised.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationCoverage {
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub method: String,
    pub path: String,
    pub pointer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub calls: usize,
    /// Observed status → count.
    pub statuses: BTreeMap<String, usize>,
    pub declared_statuses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<LatencyStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    pub budget: Budget,
    pub findings: usize,
}

/// Calls to a path or method the description does not declare.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UndeclaredEndpoint {
    pub method: String,
    /// The observed paths generalized: every segment that is not a short
    /// lower-case word is a parameter (`/users/{userId}`). Observed paths
    /// themselves are not kept.
    pub path: String,
    pub calls: usize,
    pub statuses: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DriftReport {
    pub spec: SpecSummary,
    pub observations: usize,
    /// Routed to a declared operation.
    pub matched: usize,
    /// Exchanges that got no response (checked for routing only).
    pub without_response: usize,
    /// CORS preflights (`OPTIONS` without a declared operation), not checked.
    pub ignored: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    /// Most severe first, then most frequent.
    pub findings: Vec<DriftFinding>,
    /// Every declared operation, exercised or not.
    pub operations: Vec<OperationCoverage>,
    pub undeclared: Vec<UndeclaredEndpoint>,
    pub suggestions: Vec<Suggestion>,
    /// Limits of the analysis (bodies not available, and why).
    pub notes: Vec<String>,
}

/// A description revised with chosen suggestions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Revision {
    /// The whole revised description, in the original syntax. YAML is
    /// written anew: comments and formatting of the original are not kept.
    pub text: String,
    /// RFC 6902 operations from the original to the revision.
    pub json_patch: Vec<Value>,
    pub applied: Vec<String>,
    /// Suggestion ids that were not found, and ops that could not apply.
    pub skipped: Vec<String>,
    /// SHA-256 (hex) of the description and the revised text: the same
    /// digest means the same revision, so a preview can be applied exactly
    /// as shown.
    pub digest: String,
}

/// Apply the suggestions with `ids` (in report order) to `spec`.
pub fn revise(spec: &Spec, report: &DriftReport, ids: &[String]) -> Revision {
    let chosen: HashSet<&str> = ids.iter().map(String::as_str).collect();
    let known: HashSet<&str> = report.suggestions.iter().map(|s| s.id.as_str()).collect();
    let mut doc = spec.root.clone();
    let mut applied: Vec<&Suggestion> = vec![];
    let mut skipped: Vec<String> = ids.iter().filter(|id| !known.contains(id.as_str())).cloned().collect();
    for s in report.suggestions.iter().filter(|s| chosen.contains(s.id.as_str())) {
        // All of a suggestion or none of it.
        if patch::apply_atomic(&mut doc, &s.ops) {
            applied.push(s);
        } else {
            skipped.push(s.id.clone());
        }
    }
    let text = patch::render(&doc, spec.syntax);
    // The digest is of what the revision is: the description it starts
    // from and the text it produces.
    let mut digest = Sha256::new();
    digest.update(spec.sha256.as_bytes());
    digest.update(format!("\0{:?}\0", spec.syntax).as_bytes());
    digest.update(text.as_bytes());
    Revision {
        text,
        json_patch: patch::diff(&spec.root, &doc),
        applied: applied.iter().map(|s| s.id.clone()).collect(),
        skipped,
        digest: hex::encode(digest.finalize()),
    }
}

// ---------------------------------------------------------------- analysis

#[derive(Default)]
struct FindingAcc {
    kind: Option<DriftKind>,
    message: String,
    operation: Option<String>,
    pointer: Option<String>,
    count: usize,
    observations: Vec<String>,
    suggestions: BTreeSet<String>,
}

#[derive(Default)]
struct OpAcc {
    calls: usize,
    statuses: BTreeMap<String, usize>,
    latencies: Vec<f64>,
    max_bytes: Option<u64>,
    max_request: Option<u64>,
    /// Undeclared (code, media type) → body shape.
    new_responses: BTreeMap<(String, Option<String>), Shape>,
    /// Declared code with an undeclared media type → (response pointer, shape).
    new_media: BTreeMap<(String, String), (String, Shape)>,
    new_query: BTreeSet<String>,
    new_request_types: BTreeSet<String>,
    slow: usize,
    large: usize,
    large_request: usize,
}

#[derive(Default)]
struct EndpointAcc {
    /// The prefix before the path, generalized, when it is not a declared
    /// server base path.
    unknown_prefix: Option<String>,
    /// The declared path, when only the method is new.
    template: Option<String>,
    calls: usize,
    statuses: BTreeMap<String, usize>,
    responses: BTreeMap<(String, Option<String>), Shape>,
    query: BTreeSet<String>,
    request_type: Option<String>,
    /// Observed values of each path parameter are only typed, never kept.
    param_numeric: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum FixKey {
    AddProperty { at: String, name: String },
    Nullable { at: String },
    Widen { at: String },
    Enum { at: String },
}

struct State<'a> {
    spec: &'a Spec,
    router: Router<'a>,
    opts: DriftOptions,
    findings: BTreeMap<String, FindingAcc>,
    ops: Vec<OpAcc>,
    endpoints: BTreeMap<(String, String), EndpointAcc>,
    fixes: BTreeMap<FixKey, (String, Shape, BTreeSet<String>)>,
    /// (schema holding `required`, name) → (seen, missing, owner).
    required: BTreeMap<(String, String), (usize, usize, String)>,
    servers: BTreeMap<String, (usize, String)>,
    validators: HashMap<(String, bool), Option<jsonschema::Validator>>,
    /// Members and items scanned by schema compiles.
    scan_steps: usize,
    /// The longest `required` list of the description.
    max_required: usize,
    /// Body values walked.
    walk_steps: usize,
    /// Undeclared properties suggested per object schema.
    per_schema: HashMap<String, usize>,
    notes: BTreeMap<String, usize>,
    matched: usize,
    without_response: usize,
    ignored: usize,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    /// Schema findings by (operation, status, place in the body, error
    /// category; see [`describe`]).
    schema_places: HashMap<(String, String, String, String), BTreeSet<String>>,
    /// Fixes to link to the schema findings about the same place and
    /// category, resolved once at the end: (operation, status, place,
    /// category, suggestion key).
    pending_links: BTreeSet<(String, String, String, String, String)>,
}

/// Compare observations with the description.
pub fn analyze(spec: &Spec, observations: &[Observation], opts: &DriftOptions) -> DriftReport {
    let router = Router::new(spec);
    let n_ops = router.ops.len();
    let mut st = State {
        spec,
        router,
        opts: opts.clone(),
        findings: BTreeMap::new(),
        ops: (0..n_ops).map(|_| OpAcc::default()).collect(),
        endpoints: BTreeMap::new(),
        fixes: BTreeMap::new(),
        required: BTreeMap::new(),
        servers: BTreeMap::new(),
        validators: HashMap::new(),
        scan_steps: 0,
        max_required: longest_required(&spec.root),
        walk_steps: 0,
        per_schema: HashMap::new(),
        notes: BTreeMap::new(),
        matched: 0,
        without_response: 0,
        ignored: 0,
        from: None,
        to: None,
        schema_places: HashMap::new(),
        pending_links: BTreeSet::new(),
    };
    for o in observations {
        st.observe(o);
    }
    st.finish(observations.len())
}

fn reason(code: &str) -> &'static str {
    match code {
        "200" => "OK",
        "201" => "Created",
        "202" => "Accepted",
        "204" => "No Content",
        "301" => "Moved Permanently",
        "302" => "Found",
        "304" => "Not Modified",
        "400" => "Bad Request",
        "401" => "Unauthorized",
        "403" => "Forbidden",
        "404" => "Not Found",
        "405" => "Method Not Allowed",
        "409" => "Conflict",
        "410" => "Gone",
        "412" => "Precondition Failed",
        "415" => "Unsupported Media Type",
        "422" => "Unprocessable Content",
        "429" => "Too Many Requests",
        "500" => "Internal Server Error",
        "502" => "Bad Gateway",
        "503" => "Service Unavailable",
        "504" => "Gateway Timeout",
        _ => "Response",
    }
}

/// The declared response for `code`: exact, then `4XX`, then `default`.
fn declared_response<'a, 'b>(resps: &'b [crate::model::Response<'a>], code: &str) -> Option<&'b crate::model::Response<'a>> {
    let range = |declared: &str| {
        // Bytes, not characters: a declared key may be any string.
        let d = declared.as_bytes();
        d.len() == 3 && d[1..].eq_ignore_ascii_case(b"xx") && code.as_bytes().first() == Some(&d[0])
    };
    resps
        .iter()
        .find(|r| r.code == code)
        .or_else(|| resps.iter().find(|r| range(&r.code)))
        .or_else(|| resps.iter().find(|r| r.code == "default"))
}

/// The declared media type `ct` falls under.
fn media_for<'a, 'b>(media: &'b [Media<'a>], ct: &str) -> Option<&'b Media<'a>> {
    let e = essence(ct);
    let main = e.split('/').next().unwrap_or("");
    media
        .iter()
        .find(|m| essence(&m.media_type) == e)
        .or_else(|| media.iter().find(|m| essence(&m.media_type) == format!("{main}/*")))
        .or_else(|| media.iter().find(|m| essence(&m.media_type) == "*/*"))
}

fn budget(spec: &Spec, op: &OperationRef<'_>) -> Budget {
    let mut b = Budget::default();
    for scope in [Some(op.op), Some(op.item), Some(&spec.root)].into_iter().flatten() {
        let Some(x) = scope.get(EXPECTATIONS) else { continue };
        b.max_latency_ms = b.max_latency_ms.or_else(|| x.get("max_latency_ms").and_then(Value::as_f64));
        b.max_response_bytes = b.max_response_bytes.or_else(|| x.get("max_response_bytes").and_then(Value::as_u64));
        b.max_request_bytes = b.max_request_bytes.or_else(|| x.get("max_request_bytes").and_then(Value::as_u64));
    }
    b
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

/// Round up to 1, 2, 2.5 or 5 × 10ⁿ.
fn nice_ceil(x: f64) -> f64 {
    if x <= 1.0 {
        return 1.0;
    }
    let mag = 10f64.powf(x.log10().floor());
    for m in [1.0, 2.0, 2.5, 5.0, 10.0] {
        if m * mag >= x {
            return m * mag;
        }
    }
    10.0 * mag
}

fn short_id(key: &str) -> String {
    hex::encode(&Sha256::digest(key.as_bytes())[..6])
}

/// A path segment kept as observed: lower-case ASCII letters, digits, `-`
/// and `_`, at most 32 characters with at most one digit (`v1`, `orders`,
/// `line-items`). Anything else (an id, an email, a token, a mixed-case or
/// encoded value) could be data.
fn literal_segment(seg: &str) -> bool {
    let b = seg.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_'))
        && b.iter().filter(|c| c.is_ascii_digit()).count() < 2
}

/// A generalized path: every segment that is not a [`literal_segment`]
/// becomes a `{nameId}` parameter.
fn generalize(path: &str) -> String {
    let mut out = String::new();
    // The last literal segment names the next parameter.
    let mut prev = "";
    let mut used = BTreeSet::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        if !literal_segment(seg) {
            let base = prev.trim_end_matches('s');
            let mut name = if base.is_empty() || !base.chars().all(|c| c.is_ascii_alphanumeric()) {
                "id".to_string()
            } else {
                format!("{}Id", base.to_ascii_lowercase())
            };
            let stem = name.clone();
            let mut n = 1;
            while !used.insert(name.clone()) {
                n += 1;
                name = format!("{stem}{n}");
            }
            out.push_str(&format!("{{{name}}}"));
            prev = "";
        } else {
            out.push_str(seg);
            prev = seg;
        }
    }
    if out.is_empty() { "/".into() } else { out }
}

/// Where in a body, as a message shows it.
fn place(ipath: &str) -> String {
    if ipath.is_empty() { "the body".to_string() } else { format!("`{ipath}`") }
}

/// A value-free description of a validation error: where in the body,
/// what is wrong there, and the error's category (`type`, `enum`,
/// `additional`, `required:<name>`, `other`) that fixes are linked by.
///
/// Only keys the schema names under `properties` are shown; array indexes
/// and the keys of map-like objects (`additionalProperties`,
/// `patternProperties`) become `*`.
fn describe(e: &jsonschema::ValidationError<'_>) -> (String, String, String) {
    use jsonschema::error::ValidationErrorKind as K;
    let schema_path = e.schema_path().as_str();
    let tokens: Vec<&str> = schema_path.split('/').collect();
    let named: HashSet<&str> = tokens.windows(2).filter(|w| w[0] == "properties").map(|w| w[1]).collect();
    let at: String = e
        .instance_path()
        .as_str()
        .split('/')
        .map(|t| if t.is_empty() || named.contains(t) { t } else { "*" })
        .collect::<Vec<_>>()
        .join("/");
    let category = match e.kind() {
        K::Type { .. } => "type".to_string(),
        K::Required { property } => format!("required:{}", property.as_str().unwrap_or("?")),
        K::AdditionalProperties { .. } => "additional".into(),
        K::Enum { .. } | K::Constant { .. } => "enum".into(),
        _ => "other".into(),
    };
    let what = match e.kind() {
        K::Type { kind } => {
            let expected = match kind {
                jsonschema::error::TypeKind::Single(t) => t.to_string(),
                jsonschema::error::TypeKind::Multiple(set) => set.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(" or "),
            };
            format!("is {}, expected {expected}", crate::infer::json_type_name(e.instance()))
        }
        K::Required { property } => format!("is missing required property `{}`", property.as_str().unwrap_or("?")),
        K::AdditionalProperties { unexpected } => {
            // Keys that look like data are not named.
            let names: Vec<String> = unexpected.iter().filter(|u| safe_name(u)).take(5).map(|u| format!("`{u}`")).collect();
            match (names.is_empty(), names.len() < unexpected.len()) {
                (true, _) => "has undeclared properties".to_string(),
                (false, false) => format!("has undeclared properties {}", names.join(", ")),
                (false, true) => format!("has undeclared properties {} and others", names.join(", ")),
            }
        }
        K::Enum { .. } => "is not one of the declared values".into(),
        K::Constant { .. } => "is not the declared constant".into(),
        K::Format { format } => format!("is not a valid `{format}`"),
        K::MinLength { limit } => format!("is shorter than {limit} characters"),
        K::MaxLength { limit } => format!("is longer than {limit} characters"),
        K::Minimum { limit } => format!("is below the minimum {limit}"),
        K::Maximum { limit } => format!("is above the maximum {limit}"),
        K::ExclusiveMinimum { limit } => format!("is not above {limit}"),
        K::ExclusiveMaximum { limit } => format!("is not below {limit}"),
        K::MinItems { limit } => format!("has fewer than {limit} items"),
        K::MaxItems { limit } => format!("has more than {limit} items"),
        K::MinProperties { limit } => format!("has fewer than {limit} properties"),
        K::MaxProperties { limit } => format!("has more than {limit} properties"),
        K::Pattern { pattern } => format!("does not match the pattern `{pattern}`"),
        K::UniqueItems => "has duplicate items".into(),
        K::OneOfNotValid { .. } => "matches none of the `oneOf` schemas".into(),
        K::OneOfMultipleValid { .. } => "matches more than one `oneOf` schema".into(),
        K::AnyOf { .. } => "matches none of the `anyOf` schemas".into(),
        K::Not { .. } => "matches a schema it must not".into(),
        K::FalseSchema => "is not allowed".into(),
        _ => format!("violates `{}`", schema_path.rsplit('/').next().unwrap_or("?")),
    };
    (place(&at), what, category)
}

/// An observed method as it is shown and keyed: an RFC 9110 token of at
/// most 20 characters, upper case.
fn method_token(m: &str) -> String {
    let tchar = |c: &u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(c);
    if !m.is_empty() && m.len() <= 20 && m.as_bytes().iter().all(tchar) { m.to_ascii_uppercase() } else { INVALID_METHOD.into() }
}

fn allows_null(s: &Value) -> bool {
    // A constant or a list of values admits null only by naming it.
    if let Some(c) = s.get("const") {
        return c.is_null();
    }
    if let Some(Value::Array(values)) = s.get("enum") {
        return values.contains(&Value::Null);
    }
    let (_, types, nullable) = schema_types(s);
    nullable || (types.is_empty() && s.get("type").is_none())
}

impl<'a> State<'a> {
    fn dialect(&self) -> Dialect {
        self.spec.dialect
    }

    /// Record a difference; false when it was not recorded (too many
    /// distinct ones), and then nothing about it is gathered either.
    fn finding(
        &mut self,
        key: String,
        kind: DriftKind,
        obs: &Observation,
        message: String,
        operation: Option<String>,
        pointer: Option<String>,
    ) -> bool {
        if !self.findings.contains_key(&key) && self.findings.len() >= MAX_FINDING_KEYS {
            self.note(format!("only the first {MAX_FINDING_KEYS} distinct differences were collected"));
            return false;
        }
        let f = self.findings.entry(key.clone()).or_default();
        if f.kind.is_none() {
            *f = FindingAcc { kind: Some(kind), message, operation, pointer, ..FindingAcc::default() };
        }
        f.count += 1;
        if f.observations.len() < self.opts.max_examples && !f.observations.contains(&obs.id) {
            f.observations.push(obs.id.clone());
        }
        true
    }

    /// No more distinct differences are recorded: body walks, which only
    /// feed suggestions for them, stop.
    fn findings_full(&self) -> bool {
        self.findings.len() >= MAX_FINDING_KEYS
    }

    fn link(&mut self, finding: &str, suggestion_key: &str) {
        if let Some(f) = self.findings.get_mut(finding) {
            f.suggestions.insert(suggestion_key.to_string());
        }
    }

    fn note(&mut self, n: impl Into<String>) {
        *self.notes.entry(n.into()).or_default() += 1;
    }

    fn observe(&mut self, o: &Observation) {
        if let Some(at) = o.at {
            self.from = Some(self.from.map_or(at, |f| f.min(at)));
            self.to = Some(self.to.map_or(at, |t| t.max(at)));
        }
        let route = self.router.route(&o.method, &o.url, o.operation_hint.as_deref());
        let (origin, path) = split_url(&o.url);
        if let Some(origin) = &origin
            && self.router.origin_declared(origin) == Some(false)
            && (self.servers.contains_key(origin) || self.servers.len() < MAX_SERVERS || {
                self.note(format!("only the first {MAX_SERVERS} undeclared servers are reported"));
                false
            })
        {
            let base = match &route {
                Route::Operation { base, .. } | Route::Method { base, .. } | Route::Path { base } => base.clone(),
            };
            // An undeclared prefix is kept only when nothing in it could be data.
            let base = if self.router.base_declared(&base) {
                base
            } else {
                Some(generalize(&base)).filter(|g| !g.contains('{') && g != "/").unwrap_or_default()
            };
            let key = format!("server|{origin}");
            if self.finding(
                key.clone(),
                DriftKind::UndeclaredServer,
                o,
                format!("Requests went to {origin}, which is not one of the declared servers"),
                None,
                Some(if self.spec.is_swagger2() { "/host".into() } else { "/servers".into() }),
            ) {
                self.link(&key, &key);
                self.servers.entry(origin.clone()).or_insert((0, base)).0 += 1;
            }
        }
        match route {
            Route::Operation { op, .. } => {
                self.matched += 1;
                self.check_operation(op, o);
            }
            Route::Method { .. } | Route::Path { .. } if o.method.eq_ignore_ascii_case("OPTIONS") => self.ignored += 1,
            Route::Method { template, base } => self.undeclared(o, &path, base, Some(template)),
            Route::Path { base } => self.undeclared(o, &path, base, None),
        }
        if o.response.is_none() {
            self.without_response += 1;
        }
    }

    fn undeclared(&mut self, o: &Observation, path: &str, base: String, template: Option<String>) {
        let rest = path.strip_prefix(&base).unwrap_or(path);
        let pattern = template.clone().unwrap_or_else(|| generalize(rest));
        let method = method_token(&o.method);
        if self.endpoints.len() >= MAX_ENDPOINTS && !self.endpoints.contains_key(&(method.clone(), pattern.clone())) {
            self.note(format!("only the first {MAX_ENDPOINTS} undeclared endpoints are reported"));
            return;
        }
        let label = format!("{method} {pattern}");
        let (kind, message, pointer) = match &template {
            Some(t) => {
                let declared: Vec<String> =
                    self.router.ops.iter().filter(|x| &x.path == t).map(|x| x.method.to_ascii_uppercase()).collect();
                let list = if declared.is_empty() { "no operations".into() } else { declared.join(", ") };
                (
                    DriftKind::UndeclaredMethod,
                    format!("{method} is called on {t}, which declares only {list}"),
                    Some(Router::path_pointer(t)),
                )
            }
            None => (DriftKind::UndeclaredPath, format!("{label} is called, but the description has no such path"), None),
        };
        let key = format!("endpoint|{method}|{pattern}");
        if !self.finding(key.clone(), kind, o, message, Some(label), pointer) {
            return;
        }
        self.link(&key, &key);
        let unknown_prefix = (!base.is_empty() && !self.router.base_declared(&base)).then(|| generalize(&base));
        let acc = self.endpoints.entry((method, pattern.clone())).or_default();
        acc.unknown_prefix = acc.unknown_prefix.take().or(unknown_prefix);
        acc.template = template;
        acc.calls += 1;
        for q in o.query.iter().filter(|q| safe_name(q)) {
            if acc.query.len() < MAX_QUERY_NAMES {
                acc.query.insert(q.clone());
            }
        }
        if o.request_bytes > 0 {
            acc.request_type = acc.request_type.clone().or_else(|| o.request_content_type.as_deref().map(essence));
        }
        // Type each generalized path parameter from its observed segment.
        let pat_segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let obs_segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        if pat_segs.len() == obs_segs.len() {
            for (p, v) in pat_segs.iter().zip(&obs_segs) {
                if let Some(name) = p.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
                    let numeric = v.chars().all(|c| c.is_ascii_digit());
                    let e = acc.param_numeric.entry(name.to_string()).or_insert(numeric);
                    *e &= numeric;
                }
            }
        }
        if let Some(r) = &o.response {
            *acc.statuses.entry(r.status.to_string()).or_default() += 1;
            let ct = r.content_type.as_deref().map(essence).filter(|_| !matches!(r.body, ObservedBody::Empty));
            let shape = acc.responses.entry((r.status.to_string(), ct)).or_default();
            if let ObservedBody::Json(v) = &r.body {
                shape.add(v);
            }
        }
    }

    fn check_operation(&mut self, i: usize, o: &Observation) {
        let spec = self.spec;
        let op = self.router.ops[i].clone();
        let label = op.label();
        let op_ptr = op.pointer.clone();
        let b = budget(spec, &op);
        {
            let acc = &mut self.ops[i];
            acc.calls += 1;
            if let Some(l) = o.latency_ms {
                acc.latencies.push(l);
            }
            acc.max_request = acc.max_request.max(Some(o.request_bytes));
        }
        if op.op.get("deprecated").and_then(Value::as_bool) == Some(true) {
            self.finding(
                format!("deprecated|{op_ptr}"),
                DriftKind::DeprecatedOperationCalled,
                o,
                format!("{label} is deprecated but was called"),
                Some(label.clone()),
                Some(op_ptr.clone()),
            );
        }

        // Parameters.
        let params = parameters(spec, &op);
        let has_querystring = params.iter().any(|p| p.location == "querystring");
        if !has_querystring {
            for q in &o.query {
                if !params.iter().any(|p| p.location == "query" && &p.name == q) {
                    if !safe_name(q) {
                        self.note("undeclared query parameters whose names look like values were not reported");
                        continue;
                    }
                    if self.ops[i].new_query.len() >= MAX_QUERY_NAMES && !self.ops[i].new_query.contains(q) {
                        self.note(format!("at most {MAX_QUERY_NAMES} undeclared query parameters are reported per operation"));
                        continue;
                    }
                    let key = format!("query|{op_ptr}|{q}");
                    if self.finding(
                        key.clone(),
                        DriftKind::UndeclaredQueryParameter,
                        o,
                        format!("{label} was called with query parameter `{q}`, which is not declared"),
                        Some(label.clone()),
                        Some(op_ptr.clone()),
                    ) {
                        self.link(&key, &key);
                        self.ops[i].new_query.insert(q.clone());
                    }
                }
            }
        }
        for p in params.iter().filter(|p| p.value.get("required").and_then(Value::as_bool) == Some(true)) {
            let present = match p.location.as_str() {
                "query" => o.query.iter().any(|q| q == &p.name),
                "header" => o.request_headers.iter().any(|h| h.eq_ignore_ascii_case(&p.name)),
                _ => true,
            };
            if !present {
                self.finding(
                    format!("required|{}|{}", p.pointer, p.name),
                    DriftKind::MissingRequiredParameter,
                    o,
                    format!("{label} was called without the required {} parameter `{}`", p.location, p.name),
                    Some(label.clone()),
                    Some(p.pointer.clone()),
                );
            }
        }

        // Request body.
        if o.request_bytes > 0
            && let Some(ct) = o.request_content_type.as_deref()
        {
            let body = request_body(spec, &op);
            let declared = body.as_ref().map(|b| b.media.clone()).unwrap_or_default();
            if media_for(&declared, ct).is_none() {
                let e = essence(ct);
                let list = if declared.is_empty() {
                    "no request body".to_string()
                } else {
                    declared.iter().map(|m| m.media_type.clone()).collect::<Vec<_>>().join(", ")
                };
                let key = format!("reqtype|{op_ptr}|{e}");
                if self.finding(
                    key.clone(),
                    DriftKind::UndeclaredRequestContentType,
                    o,
                    format!("{label} was sent a {e} body; the description declares {list}"),
                    Some(label.clone()),
                    body.as_ref().map(|b| b.pointer.clone()).or(Some(op_ptr.clone())),
                ) {
                    self.link(&key, &key);
                    self.ops[i].new_request_types.insert(e);
                }
            }
        }
        if let Some(max) = b.max_request_bytes
            && o.request_bytes > max
        {
            self.ops[i].large_request += 1;
            let key = format!("reqsize|{op_ptr}");
            self.finding(key.clone(), DriftKind::RequestLargerThanDeclared, o, String::new(), Some(label.clone()), Some(op_ptr.clone()));
            self.link(&key, &key);
        }

        // Response.
        let Some(r) = &o.response else { return };
        let code = r.status.to_string();
        *self.ops[i].statuses.entry(code.clone()).or_default() += 1;
        self.ops[i].max_bytes = self.ops[i].max_bytes.max(r.bytes);
        if let (Some(max), Some(l)) = (b.max_latency_ms, o.latency_ms)
            && l > max
        {
            self.ops[i].slow += 1;
            let key = format!("slow|{op_ptr}");
            self.finding(key.clone(), DriftKind::SlowerThanDeclared, o, String::new(), Some(label.clone()), Some(op_ptr.clone()));
            self.link(&key, &key);
        }
        if let (Some(max), Some(n)) = (b.max_response_bytes, r.bytes)
            && n > max
        {
            self.ops[i].large += 1;
            let key = format!("size|{op_ptr}");
            self.finding(key.clone(), DriftKind::ResponseLargerThanDeclared, o, String::new(), Some(label.clone()), Some(op_ptr.clone()));
            self.link(&key, &key);
        }
        let has_body = !matches!(r.body, ObservedBody::Empty) && r.bytes != Some(0);
        let ct = r.content_type.as_deref().map(essence).filter(|_| has_body);
        let resps = responses(spec, &op);
        let Some(resp) = declared_response(&resps, &code) else {
            let key = format!("status|{op_ptr}|{code}");
            if !self.finding(
                key.clone(),
                DriftKind::UndeclaredStatus,
                o,
                format!("{label} returned {code}, which is not a documented response"),
                Some(label.clone()),
                Some(ptr(&op_ptr, "responses")),
            ) {
                return;
            }
            self.link(&key, &key);
            let shape = self.ops[i].new_responses.entry((code, ct)).or_default();
            if let ObservedBody::Json(v) = &r.body {
                shape.add(v);
            }
            return;
        };
        // Required response headers.
        if let Some(hs) = resp.value.get("headers").and_then(Value::as_object) {
            for (name, h) in hs {
                let (h, hptr) = spec.deref(h, &ptr(&ptr(&resp.pointer, "headers"), name));
                if h.get("required").and_then(Value::as_bool) == Some(true) && !r.headers.iter().any(|x| x.eq_ignore_ascii_case(name)) {
                    self.finding(
                        format!("header|{hptr}"),
                        DriftKind::MissingResponseHeader,
                        o,
                        format!("The {code} response of {label} did not include the required header `{name}`"),
                        Some(label.clone()),
                        Some(hptr),
                    );
                }
            }
        }
        let Some(ct) = ct else {
            if let ObservedBody::Unavailable(why) = &r.body {
                self.note(format!("response bodies not checked: {why}"));
            }
            return;
        };
        let Some(media) = media_for(&resp.media, &ct).cloned() else {
            let list = if resp.media.is_empty() {
                "no content".to_string()
            } else {
                resp.media.iter().map(|m| m.media_type.clone()).collect::<Vec<_>>().join(", ")
            };
            let key = format!("ctype|{}|{ct}", resp.pointer);
            if !self.finding(
                key.clone(),
                DriftKind::UndeclaredContentType,
                o,
                format!("The {code} response of {label} was {ct}; the description declares {list}"),
                Some(label.clone()),
                Some(resp.pointer.clone()),
            ) {
                return;
            }
            self.link(&key, &key);
            let entry =
                self.ops[i].new_media.entry((resp.code.clone(), ct.clone())).or_insert_with(|| (resp.pointer.clone(), Shape::default()));
            if let ObservedBody::Json(v) = &r.body {
                entry.1.add(v);
            }
            return;
        };
        let body = match &r.body {
            ObservedBody::Json(v) => v,
            ObservedBody::Unavailable(why) => {
                self.note(format!("response bodies not checked: {why}"));
                return;
            }
            _ => return,
        };
        let Some(schema) = media.schema else { return };
        if !is_json(&ct) && !is_json(&media.media_type) && media.media_type != "*/*" {
            return;
        }
        // Media types whose schema is only a `$ref` to the same target share
        // its validator (keyed by the first hop, as in the linter).
        let target = match schema.as_object() {
            Some(s) if s.len() == 1 => s.get("$ref").and_then(Value::as_str).and_then(crate::spec::internal_pointer),
            _ => None,
        };
        let vkey = (target.unwrap_or_else(|| media.schema_pointer.clone()), false);
        if !self.validators.contains_key(&vkey) {
            let v = schema::compile_within(spec, schema, Direction::Response, &mut self.scan_steps, MAX_EXAMPLE_SCAN_STEPS).ok();
            if v.is_none() {
                self.note(if self.scan_steps > MAX_EXAMPLE_SCAN_STEPS {
                    "the analysis' budget for scanning schemas is spent; bodies of the remaining schemas were not checked"
                } else {
                    "some response schemas could not be compiled (an external or broken reference); their bodies were not checked"
                });
            }
            self.validators.insert(vkey.clone(), v);
        }
        let Some(validator) = self.validators.get(&vkey).and_then(Option::as_ref) else { return };
        let mut first_only = false;
        let messages: Vec<(String, String, String)> = if validator.is_valid(body) {
            vec![]
        } else if count_values(body, MAX_ERROR_WORK).saturating_mul(1 + self.max_required) <= MAX_ERROR_WORK {
            validator.iter_errors(body).take(10).map(|e| describe(&e)).collect()
        } else {
            first_only = true;
            validator.validate(body).err().map(|e| describe(&e)).into_iter().collect()
        };
        if first_only {
            self.note("for large bodies against long `required` lists only the first schema difference is reported");
        }
        if self.findings_full() {
            return;
        }
        if messages.is_empty() {
            // Still record required-property presence for relaxations.
            self.walk(schema, &media.schema_pointer, body, "", 0, &label, &code, o, false);
            return;
        }
        for (place, what, category) in &messages {
            let m = format!("{place} {what}");
            let key = format!("schema|{}|{m}", media.schema_pointer);
            if !self.finding(
                key.clone(),
                DriftKind::ResponseSchemaMismatch,
                o,
                format!("The {code} response of {label} does not match its schema: {m}"),
                Some(label.clone()),
                Some(media.schema_pointer.clone()),
            ) {
                return;
            }
            self.schema_places.entry((label.clone(), code.clone(), place.clone(), category.clone())).or_default().insert(key);
        }
        self.walk(schema, &media.schema_pointer, body, "", 0, &label, &code, o, true);
    }

    /// Count `n` steps of walking bodies and their schemas; false once the
    /// analysis' budget is spent.
    fn spend(&mut self, n: usize) -> bool {
        if self.walk_steps > MAX_WALK_STEPS {
            return false;
        }
        self.walk_steps += n;
        if self.walk_steps > MAX_WALK_STEPS {
            self.note("the analysis' budget for walking bodies is spent; later bodies got no schema suggestions");
            return false;
        }
        true
    }

    /// The fix at `key`, created with `owner` unless a cap is reached.
    fn fix(&mut self, key: &FixKey, owner: impl FnOnce() -> String) -> Option<&mut (String, Shape, BTreeSet<String>)> {
        if !self.fixes.contains_key(key) {
            if self.fixes.len() >= MAX_SCHEMA_FIXES {
                self.note(format!("only {MAX_SCHEMA_FIXES} schema changes are suggested; check again after applying them"));
                return None;
            }
            if let FixKey::AddProperty { at, .. } = key {
                let n = self.per_schema.entry(at.clone()).or_default();
                if *n >= MAX_PROPERTIES_PER_SCHEMA {
                    self.note(format!("at most {MAX_PROPERTIES_PER_SCHEMA} undeclared properties are suggested per schema"));
                    return None;
                }
                *n += 1;
            }
            self.fixes.insert(key.clone(), (owner(), Shape::default(), BTreeSet::new()));
        }
        self.fixes.get_mut(key)
    }

    /// Walk a body along its schema, collecting fixes that would make the
    /// schema accept it. `failed`: the body did not validate (fixes are
    /// linked to that response's schema findings of the same place and
    /// category).
    #[allow(clippy::too_many_arguments)]
    fn walk(
        &mut self,
        schema: &'a Value,
        at: &str,
        v: &Value,
        ipath: &str,
        depth: usize,
        label: &str,
        code: &str,
        o: &Observation,
        failed: bool,
    ) {
        if depth > 32 || !self.spend(1) {
            return;
        }
        let spec: &'a Spec = self.spec;
        let (s, at) = spec.deref(schema, at);
        if s.get("oneOf").is_some() || s.get("anyOf").is_some() {
            return;
        }
        let owner = || schema_owner(&at, code, label);
        // Link a fix to the schema findings about the same place and
        // category (resolved once, in `finish`).
        let fix_link = |st: &mut Self, key: String, at_path: &str, category: &str| {
            if failed {
                st.pending_links.insert((label.to_string(), code.to_string(), place(at_path), category.to_string(), key));
            }
        };
        match v {
            Value::Null => {
                if !allows_null(s) {
                    let key = FixKey::Nullable { at: at.clone() };
                    if let Some(e) = self.fix(&key, owner) {
                        e.2.insert(o.id.clone());
                        fix_link(self, fix_suggestion_key(&key), ipath, "type");
                    }
                }
            }
            Value::Object(obj) => {
                // Declared properties, across `allOf` branches (the first
                // declaration of a name wins).
                // Values: (schema, index of the part declaring it).
                let mut declared: HashMap<&'a str, (&'a Value, usize)> = HashMap::new();
                let mut required: Vec<(&'a str, usize)> = vec![];
                let mut holder = at.clone();
                let mut additional: Option<(&'a Value, String)> = None;
                let mut patterned = false;
                let all = s.get("allOf").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
                if !self.spend(1 + all.len()) {
                    return;
                }
                let mut parts: Vec<(&'a Value, String)> = vec![(s, at.clone())];
                for (k, b) in all.iter().enumerate() {
                    parts.push(spec.deref(b, &ptr(&ptr(&at, "allOf"), &k.to_string())));
                }
                // Reading the schema costs as much as its members.
                let members: usize = parts
                    .iter()
                    .map(|(p, _)| {
                        p.get("properties").and_then(Value::as_object).map_or(0, |o| o.len())
                            + p.get("required").and_then(Value::as_array).map_or(0, Vec::len)
                    })
                    .sum();
                if !self.spend(members) {
                    return;
                }
                let mut found_holder = false;
                for (pi, (part, pp)) in parts.iter().enumerate() {
                    if let Some(props) = part.get("properties").and_then(Value::as_object) {
                        if !found_holder {
                            holder = pp.clone();
                            found_holder = true;
                        }
                        for (n, ps) in props {
                            declared.entry(n.as_str()).or_insert((ps, pi));
                        }
                    }
                    for r in part.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                        required.push((r, pi));
                    }
                    if let Some(ap) = part.get("additionalProperties").filter(|a| a.is_object()) {
                        additional = Some((ap, ptr(pp, "additionalProperties")));
                    }
                    patterned |= part.get("patternProperties").is_some();
                }
                let object_like = s.get("type").and_then(Value::as_str) == Some("object") || !declared.is_empty() || parts.len() > 1;
                if !object_like {
                    return;
                }
                // A schema that names no properties (a free-form object or
                // a map) or matches names by pattern gets no property
                // suggestions: its keys are likely data.
                let names_properties = !declared.is_empty() && !patterned;
                if !self.spend(obj.len()) {
                    return;
                }
                for (k, x) in obj {
                    if let Some(&(ps, pi)) = declared.get(k.as_str()) {
                        let pp = ptr(&ptr(&parts[pi].1, "properties"), k);
                        self.walk(ps, &pp, x, &ptr(ipath, k), depth + 1, label, code, o, failed);
                    } else if let Some((ap, app)) = &additional {
                        let (ap, app) = (*ap, app.clone());
                        self.walk(ap, &app, x, &ptr(ipath, "*"), depth + 1, label, code, o, failed);
                    } else if names_properties && safe_name(k) {
                        let key = FixKey::AddProperty { at: holder.clone(), name: k.clone() };
                        if let Some(e) = self.fix(&key, owner) {
                            e.1.add(x);
                            e.2.insert(o.id.clone());
                            fix_link(self, fix_suggestion_key(&key), ipath, "additional");
                        }
                    }
                }
                for (name, pi) in required {
                    let rp = parts[pi].1.clone();
                    let write_only = declared
                        .get(name)
                        .is_some_and(|(ps, _)| spec.deref(ps, "").0.get("writeOnly").and_then(Value::as_bool) == Some(true));
                    if write_only {
                        continue;
                    }
                    let missing = !obj.contains_key(name);
                    if missing {
                        fix_link(self, format!("optional|{rp}"), ipath, &format!("required:{name}"));
                    }
                    let owner = schema_owner(&rp, code, label);
                    let e = self.required.entry((rp, name.to_string())).or_insert((0, 0, owner));
                    e.0 += 1;
                    if missing {
                        e.1 += 1;
                    }
                }
            }
            Value::Array(items) => {
                if let Some(is) = s.get("items").filter(|i| i.is_object()) {
                    let ip = ptr(&at, "items");
                    let child = ptr(ipath, "*");
                    for x in items.iter().take(self.opts.max_items_walked) {
                        self.walk(is, &ip, x, &child, depth + 1, label, code, o, failed);
                    }
                }
            }
            Value::Number(n) if !(n.is_i64() || n.is_u64()) => {
                let (_, types, _) = schema_types(s);
                if types.iter().any(|t| t == "integer") && !types.iter().any(|t| t == "number") {
                    let key = FixKey::Widen { at: at.clone() };
                    if let Some(e) = self.fix(&key, owner) {
                        e.2.insert(o.id.clone());
                        fix_link(self, fix_suggestion_key(&key), ipath, "type");
                    }
                }
            }
            Value::String(text) => {
                if let Some(values) = s.get("enum").and_then(Value::as_array)
                    && !values.contains(v)
                    && text.len() <= 64
                    && text.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                {
                    let key = FixKey::Enum { at: at.clone() };
                    let token = format!("value:{text}");
                    let Some(e) = self.fix(&key, owner) else { return };
                    // The token itself is kept (see the module docs), a few
                    // per location.
                    if e.2.len() < MAX_ENUM_TOKENS {
                        e.2.insert(token);
                    } else if !e.2.contains(&token) {
                        self.note(format!("at most {MAX_ENUM_TOKENS} new values are suggested per enum"));
                    }
                    fix_link(self, fix_suggestion_key(&key), ipath, "enum");
                }
            }
            _ => {}
        }
    }

    fn finish(mut self, total: usize) -> DriftReport {
        for (label, code, place, category, skey) in std::mem::take(&mut self.pending_links) {
            let keys: Vec<String> = self.schema_places.get(&(label, code, place, category)).into_iter().flatten().cloned().collect();
            for k in keys {
                self.link(&k, &skey);
            }
        }
        let spec = self.spec;
        let d = self.dialect();
        let syntax = spec.syntax;
        let mut suggestions: BTreeMap<String, Suggestion> = BTreeMap::new();
        let mut add =
            |key: &str, title: String, detail: String, kind: SuggestionKind, recommended: bool, pointer: String, ops: Vec<PatchOp>| {
                let snippet = patch::fragment(&ops, syntax);
                let line = spec.position(&pointer).filter(|_| spec.root.pointer(&pointer).is_some()).map(|p| p.line);
                let id = short_id(&format!("{}\0{key}\0{}", spec.sha256, serde_json::to_string(&ops).unwrap_or_default()));
                suggestions.insert(key.to_string(), Suggestion { id, title, detail, kind, recommended, pointer, line, ops, snippet });
            };

        // Undeclared responses, media types, query parameters, request types.
        for (i, acc) in self.ops.iter().enumerate() {
            let op = &self.router.ops[i];
            let label = op.label();
            let op_ptr = op.pointer.clone();
            let mut by_code: BTreeMap<&String, Vec<(&Option<String>, &Shape)>> = BTreeMap::new();
            for ((code, ct), shape) in &acc.new_responses {
                by_code.entry(code).or_default().push((ct, shape));
            }
            for (code, variants) in by_code {
                let key = format!("status|{op_ptr}|{code}");
                let mut ops = vec![];
                let value = response_object(d, code, &variants);
                ops.push(PatchOp::add(ptr(&ptr(&op_ptr, "responses"), code), value));
                if d == Dialect::Swagger20 {
                    ops.extend(produces_ops(spec, op, variants.iter().filter_map(|(ct, _)| (*ct).clone())));
                }
                add(
                    &key,
                    format!("Document the {code} response of {label}"),
                    format!(
                        "{label} returned {code} {}; the description does not list it. \
                         The schema is inferred from the observed bodies (shape only).",
                        reason(code)
                    ),
                    SuggestionKind::Addition,
                    true,
                    ptr(&op_ptr, "responses"),
                    ops,
                );
            }
            for ((code, ct), (resp_ptr, shape)) in &acc.new_media {
                let key = format!("ctype|{resp_ptr}|{ct}");
                let mut ops = vec![];
                if d == Dialect::Swagger20 {
                    ops.extend(produces_ops(spec, op, [ct.clone()]));
                    if shape_has_samples(shape) && spec.root.pointer(resp_ptr).and_then(|r| r.get("schema")).is_none() {
                        ops.push(PatchOp::add(ptr(resp_ptr, "schema"), shape.schema(d)));
                    }
                } else {
                    ops.push(PatchOp::add(ptr(&ptr(resp_ptr, "content"), ct), media_object(d, ct, Some(shape))));
                }
                add(
                    &key,
                    format!("Document {ct} for the {code} response of {label}"),
                    format!("The {code} response of {label} came back as {ct}."),
                    SuggestionKind::Addition,
                    true,
                    resp_ptr.clone(),
                    ops,
                );
            }
            for q in &acc.new_query {
                let key = format!("query|{op_ptr}|{q}");
                let param = if d == Dialect::Swagger20 {
                    json!({"name": q, "in": "query", "required": false, "type": "string"})
                } else {
                    json!({"name": q, "in": "query", "required": false, "schema": {"type": "string"}})
                };
                add(
                    &key,
                    format!("Document query parameter `{q}` of {label}"),
                    format!("{label} was called with `{q}`. Its type is not inferred from values; adjust `string` if needed."),
                    SuggestionKind::Addition,
                    true,
                    op_ptr.clone(),
                    vec![PatchOp::add(ptr(&ptr(&op_ptr, "parameters"), "-"), param)],
                );
            }
            for ct in &acc.new_request_types {
                let key = format!("reqtype|{op_ptr}|{ct}");
                let ops = if d == Dialect::Swagger20 {
                    let mut consumes = swagger_media(spec, op.op, "consumes").unwrap_or_default();
                    consumes.push(ct.clone());
                    let mut ops = vec![PatchOp::union(ptr(&op_ptr, "consumes"), consumes.into_iter().map(Value::String).collect())];
                    if request_body(spec, op).is_none() {
                        ops.push(PatchOp::add(ptr(&ptr(&op_ptr, "parameters"), "-"), json!({"name": "body", "in": "body", "schema": {}})));
                    }
                    ops
                } else {
                    match request_body(spec, op) {
                        Some(b) => vec![PatchOp::add(ptr(&ptr(&b.pointer, "content"), ct), json!({"schema": {}}))],
                        None => vec![PatchOp::add(ptr(&op_ptr, "requestBody"), json!({"content": {ct.clone(): {"schema": {}}}}))],
                    }
                };
                add(
                    &key,
                    format!("Document the {ct} request body of {label}"),
                    "Request bodies are not kept, so describe its schema (left empty here).".into(),
                    SuggestionKind::Addition,
                    true,
                    op_ptr.clone(),
                    ops,
                );
            }
        }

        // Undeclared endpoints.
        let mut not_describable = 0;
        for ((method, pattern), acc) in &self.endpoints {
            let key = format!("endpoint|{method}|{pattern}");
            // Where the dialect describes this method: a Path Item field, or
            // (3.2) `additionalOperations`; other methods get no suggestion.
            let m = method.to_ascii_lowercase();
            let member: Option<Vec<String>> = if METHODS.contains(&m.as_str()) || (d == Dialect::OpenApi32 && m == "query") {
                Some(vec![m])
            } else if d == Dialect::OpenApi32 && method != INVALID_METHOD {
                Some(vec!["additionalOperations".into(), method.clone()])
            } else {
                None
            };
            let Some(member) = member else {
                not_describable += 1;
                continue;
            };
            let mut resp = serde_json::Map::new();
            let codes: BTreeSet<&String> = acc.responses.keys().map(|(c, _)| c).collect();
            for code in codes {
                let v: Vec<(&Option<String>, &Shape)> =
                    acc.responses.iter().filter(|((c, _), _)| c == code).map(|((_, ct), s)| (ct, s)).collect();
                resp.insert(code.clone(), response_object(d, code, &v));
            }
            if resp.is_empty() {
                resp.insert("default".into(), json!({"description": "Not observed yet"}));
            }
            let declared_path_params: BTreeSet<String> = acc
                .template
                .as_ref()
                .and_then(|t| spec.root.pointer(&Router::path_pointer(t)))
                .and_then(|item| item.get("parameters").and_then(Value::as_array))
                .map(|ps| ps.iter().filter_map(|p| spec.deref(p, "").0.get("name").and_then(Value::as_str).map(str::to_string)).collect())
                .unwrap_or_default();
            let mut params = vec![];
            for name in crate::model::template_params(pattern) {
                if declared_path_params.contains(&name) {
                    continue;
                }
                let t = if acc.param_numeric.get(&name).copied().unwrap_or(false) { "integer" } else { "string" };
                params.push(if d == Dialect::Swagger20 {
                    json!({"name": name, "in": "path", "required": true, "type": t})
                } else {
                    json!({"name": name, "in": "path", "required": true, "schema": {"type": t}})
                });
            }
            for q in &acc.query {
                params.push(if d == Dialect::Swagger20 {
                    json!({"name": q, "in": "query", "required": false, "type": "string"})
                } else {
                    json!({"name": q, "in": "query", "required": false, "schema": {"type": "string"}})
                });
            }
            let mut operation = serde_json::Map::new();
            operation.insert("summary".into(), json!(format!("{method} {pattern}")));
            operation.insert("description".into(), json!("Observed by Anvil; describe what it does."));
            if !params.is_empty() {
                operation.insert("parameters".into(), Value::Array(params));
            }
            if let Some(ct) = &acc.request_type {
                if d == Dialect::Swagger20 {
                    operation.insert("consumes".into(), json!([ct]));
                } else {
                    operation.insert("requestBody".into(), json!({"content": {ct.clone(): {"schema": {}}}}));
                }
            }
            if d == Dialect::Swagger20 {
                let cts: BTreeSet<String> = acc.responses.keys().filter_map(|(_, ct)| ct.clone()).collect();
                if !cts.is_empty() {
                    operation.insert("produces".into(), json!(cts));
                }
            }
            operation.insert("responses".into(), Value::Object(resp));
            let (path_ptr, path_key) = match &acc.template {
                Some(t) => (
                    spec.root
                        .pointer(&Router::path_pointer(t))
                        .map(|v| spec.deref(v, &Router::path_pointer(t)).1)
                        .unwrap_or_else(|| Router::path_pointer(t)),
                    t.clone(),
                ),
                None => (Router::path_pointer(pattern), pattern.clone()),
            };
            let mut detail = format!("Seen {} time(s).", acc.calls);
            if let Some(prefix) = &acc.unknown_prefix {
                detail.push_str(&format!(" The prefix {prefix} is not a declared server path; it was left out."));
            }
            let target = member.iter().fold(path_ptr.clone(), |p, t| ptr(&p, t));
            add(
                &key,
                format!("Document {method} {path_key}"),
                detail,
                SuggestionKind::Addition,
                true,
                path_ptr.clone(),
                vec![PatchOp::add(target, Value::Object(operation))],
            );
        }
        if not_describable > 0 {
            self.notes.insert(format!("{} description has no place for some observed methods; they got no suggestion", d), not_describable);
        }

        // Schema fixes.
        let mut enum_groups: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
        for (key, (owner, shape, seen)) in &self.fixes {
            let skey = fix_suggestion_key(key);
            match key {
                FixKey::AddProperty { at, name } => add(
                    &skey,
                    format!("Document property `{name}` of {owner}"),
                    format!(
                        "Seen in {} response(s) but not declared. Its schema is inferred from the observed values (shape only).",
                        seen.len()
                    ),
                    SuggestionKind::Addition,
                    true,
                    at.clone(),
                    vec![PatchOp::add(ptr(&ptr(at, "properties"), name), shape.schema(d))],
                ),
                FixKey::Nullable { at } => {
                    let current = spec.root.pointer(at).cloned().unwrap_or_else(|| json!({}));
                    let ops = nullable_ops(d, at, &current);
                    add(
                        &skey,
                        format!("Allow null at {}", display_pointer(at, owner)),
                        format!("The API returned null here {} time(s). If null is not intended, fix the API instead.", seen.len()),
                        SuggestionKind::Relaxation,
                        false,
                        at.clone(),
                        ops,
                    );
                }
                FixKey::Widen { at } => {
                    // 3.1 and 3.2 add `number` to the type (a union, so
                    // allowing null too keeps both); older dialects have one
                    // type, and their null is a separate flag.
                    let op = if matches!(d, Dialect::OpenApi31 | Dialect::OpenApi32) {
                        PatchOp::union(ptr(at, "type"), vec![json!("number")])
                    } else {
                        PatchOp::replace(ptr(at, "type"), json!("number"))
                    };
                    add(
                        &skey,
                        format!("Allow fractional numbers at {}", display_pointer(at, owner)),
                        "Declared an integer; fractional numbers were returned.".into(),
                        SuggestionKind::Relaxation,
                        false,
                        at.clone(),
                        vec![op],
                    );
                }
                FixKey::Enum { at } => {
                    let values: Vec<String> = seen.iter().filter_map(|s| s.strip_prefix("value:")).map(str::to_string).collect();
                    enum_groups.entry(at.clone()).or_insert_with(|| (owner.clone(), vec![])).1.extend(values);
                }
            }
        }
        for (at, (owner, values)) in enum_groups {
            let key = fix_suggestion_key(&FixKey::Enum { at: at.clone() });
            add(
                &key,
                format!(
                    "Add {} to the values of {}",
                    values.iter().map(|v| format!("`{v}`")).collect::<Vec<_>>().join(", "),
                    display_pointer(&at, &owner)
                ),
                "The API returned values the enum does not list.".into(),
                SuggestionKind::Relaxation,
                false,
                at.clone(),
                // A union: allowing null may add to the same list.
                vec![PatchOp::union(ptr(&at, "enum"), values.iter().map(|v| json!(v)).collect())],
            );
        }
        // Required properties that were sometimes missing.
        // Schema → (owner, [(name, missing, seen)]).
        type Missing = (String, Vec<(String, usize, usize)>);
        let mut optional: BTreeMap<String, Missing> = BTreeMap::new();
        for ((at, name), (seen, missing, owner)) in &self.required {
            if *missing > 0 {
                optional.entry(at.clone()).or_insert_with(|| (owner.clone(), vec![])).1.push((name.clone(), *missing, *seen));
            }
        }
        for (at, (owner, names)) in optional {
            let current: Vec<Value> = spec.root.pointer(&ptr(&at, "required")).and_then(Value::as_array).cloned().unwrap_or_default();
            let keep: Vec<Value> = current.into_iter().filter(|r| !names.iter().any(|(n, _, _)| r.as_str() == Some(n))).collect();
            let key = format!("optional|{at}");
            let listed = names.iter().map(|(n, m, s)| format!("`{n}` (missing in {m} of {s})")).collect::<Vec<_>>().join(", ");
            add(
                &key,
                format!(
                    "Make {} optional in {}",
                    names.iter().map(|(n, _, _)| format!("`{n}`")).collect::<Vec<_>>().join(", "),
                    display_pointer(&at, &owner)
                ),
                format!("Required but not always returned: {listed}. If they must always be there, fix the API instead."),
                SuggestionKind::Relaxation,
                false,
                at.clone(),
                // An empty `required` is invalid before 3.1: drop it.
                vec![if keep.is_empty() {
                    PatchOp::remove(ptr(&at, "required"))
                } else {
                    PatchOp::replace(ptr(&at, "required"), Value::Array(keep))
                }],
            );
        }

        // Budgets and servers.
        let mut per_operation: HashMap<String, usize> = HashMap::new();
        for f in self.findings.values() {
            if let Some(op) = &f.operation {
                *per_operation.entry(op.clone()).or_default() += f.count;
            }
        }
        let mut coverage = vec![];
        for (i, acc) in self.ops.iter().enumerate() {
            let op = &self.router.ops[i];
            let label = op.label();
            let b = budget(spec, op);
            let mut lat = acc.latencies.clone();
            lat.sort_by(|a, b| a.total_cmp(b));
            let stats = (!lat.is_empty()).then(|| LatencyStats {
                p50: percentile(&lat, 50.0),
                p95: percentile(&lat, 95.0),
                max: *lat.last().unwrap_or(&0.0),
            });
            let x_ptr = ptr(&op.pointer, EXPECTATIONS);
            if let (Some(max), Some(s)) = (b.max_latency_ms, stats) {
                let key = format!("slow|{}", op.pointer);
                if let Some(f) = self.findings.get_mut(&key) {
                    f.message = format!(
                        "{label} took longer than its {max} ms budget in {} of {} calls (p95 {:.0} ms, slowest {:.0} ms)",
                        acc.slow,
                        lat.len(),
                        s.p95,
                        s.max
                    );
                    add(
                        &key,
                        format!("Raise the latency budget of {label} to {} ms", nice_ceil(s.max)),
                        format!(
                            "Observed p95 {:.0} ms and slowest {:.0} ms against {max} ms. \
                             Raise it only if the budget, not the API, is wrong.",
                            s.p95, s.max
                        ),
                        SuggestionKind::Relaxation,
                        false,
                        op.pointer.clone(),
                        vec![PatchOp::replace(ptr(&x_ptr, "max_latency_ms"), json!(nice_ceil(s.max)))],
                    );
                }
            } else if b.max_latency_ms.is_none()
                && let Some(s) = stats
            {
                let key = format!("budget|{}", op.pointer);
                let v = nice_ceil(s.p95 * 1.5);
                add(
                    &key,
                    format!("Declare a {v} ms latency budget for {label}"),
                    format!(
                        "No budget is declared. Observed p95 {:.0} ms over {} call(s); later checks then flag slower calls.",
                        s.p95,
                        lat.len()
                    ),
                    SuggestionKind::Addition,
                    false,
                    op.pointer.clone(),
                    vec![PatchOp::add(x_ptr.clone(), json!({"max_latency_ms": v}))],
                );
            }
            let size_budgets = [
                ("size", "max_response_bytes", b.max_response_bytes, acc.large, acc.max_bytes, "returned more than its", "response"),
                (
                    "reqsize",
                    "max_request_bytes",
                    b.max_request_bytes,
                    acc.large_request,
                    acc.max_request,
                    "was sent more than its",
                    "request",
                ),
            ];
            for (prefix, field, max, over, largest, verb, what) in size_budgets {
                let key = format!("{prefix}|{}", op.pointer);
                let (Some(max), Some(f)) = (max, self.findings.get_mut(&key)) else { continue };
                let largest = largest.unwrap_or(0);
                let of = if what == "request" { "request " } else { "" };
                f.message = format!("{label} {verb} {max}-byte {of}budget in {over} call(s) (largest {largest} bytes)");
                let raised = nice_ceil(largest as f64) as u64;
                add(
                    &key,
                    format!("Raise the {what} size budget of {label} to {raised} bytes"),
                    format!("The largest {what} was {largest} bytes against {max}. Raise it only if the budget, not the API, is wrong."),
                    SuggestionKind::Relaxation,
                    false,
                    op.pointer.clone(),
                    vec![PatchOp::replace(ptr(&x_ptr, field), json!(raised))],
                );
            }
            let declared_statuses: Vec<String> = responses(spec, op).into_iter().map(|r| r.code).collect();
            let finding_count = per_operation.get(&label).copied().unwrap_or(0);
            coverage.push(OperationCoverage {
                operation: label,
                operation_id: op.operation_id().map(str::to_string),
                method: op.method.to_ascii_uppercase(),
                path: op.path.clone(),
                pointer: op.pointer.clone(),
                line: spec.position(&op.pointer).map(|p| p.line),
                calls: acc.calls,
                statuses: acc.statuses.clone(),
                declared_statuses,
                latency_ms: stats,
                max_response_bytes: acc.max_bytes,
                budget: b,
                findings: finding_count,
            });
        }
        if !spec.is_swagger2() {
            for (origin, (n, base)) in &self.servers {
                let key = format!("server|{origin}");
                add(
                    &key,
                    format!("Declare the server {origin}{base}"),
                    format!("{n} request(s) went there."),
                    SuggestionKind::Addition,
                    false,
                    "/servers".into(),
                    vec![PatchOp::add("/servers/-", json!({"url": format!("{origin}{base}"), "description": "Observed by Anvil"}))],
                );
            }
        }

        // Findings, most severe then most frequent.
        let mut findings: Vec<DriftFinding> = self
            .findings
            .into_values()
            .filter_map(|f| {
                let kind = f.kind?;
                let line = f.pointer.as_deref().filter(|p| spec.root.pointer(p).is_some()).and_then(|p| spec.position(p)).map(|p| p.line);
                Some(DriftFinding {
                    kind,
                    severity: kind.severity(),
                    message: f.message,
                    operation: f.operation,
                    pointer: f.pointer,
                    line,
                    count: f.count,
                    observations: f.observations,
                    suggestions: f.suggestions.iter().filter_map(|k| suggestions.get(k)).map(|s| s.id.clone()).collect(),
                })
            })
            .collect();
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.count.cmp(&a.count)).then(a.message.cmp(&b.message)));
        findings.truncate(self.opts.max_findings);
        let mut suggestions: Vec<Suggestion> = suggestions.into_values().collect();
        suggestions.sort_by(|a, b| b.recommended.cmp(&a.recommended).then(a.pointer.cmp(&b.pointer)).then(a.title.cmp(&b.title)));
        if suggestions.len() > MAX_SUGGESTIONS {
            self.notes.insert(
                format!("only {MAX_SUGGESTIONS} suggestions are listed; check again after applying them"),
                suggestions.len() - MAX_SUGGESTIONS,
            );
            suggestions.truncate(MAX_SUGGESTIONS);
            let kept: HashSet<String> = suggestions.iter().map(|s| s.id.clone()).collect();
            for f in &mut findings {
                f.suggestions.retain(|id| kept.contains(id));
            }
        }
        if self.router.dropped_servers > 0 {
            self.notes.insert(
                "the description declares more server base paths than are matched; some were not used".into(),
                self.router.dropped_servers,
            );
        }
        let undeclared = self
            .endpoints
            .into_iter()
            .map(|((method, path), a)| UndeclaredEndpoint { method, path, calls: a.calls, statuses: a.statuses })
            .collect();
        DriftReport {
            spec: SpecSummary {
                title: spec.title().map(str::to_string),
                version: spec.version(),
                dialect: spec.dialect,
                declared_version: spec.declared_version.clone(),
                sha256: spec.sha256.clone(),
                size_bytes: spec.size_bytes,
                operations: self.router.ops.len(),
            },
            observations: total,
            matched: self.matched,
            without_response: self.without_response,
            ignored: self.ignored,
            from: self.from,
            to: self.to,
            findings,
            operations: coverage,
            undeclared,
            suggestions,
            notes: self.notes.into_iter().map(|(n, c)| format!("{n} ({c}×)")).collect(),
        }
    }
}

fn fix_suggestion_key(k: &FixKey) -> String {
    match k {
        FixKey::AddProperty { at, name } => format!("prop|{at}|{name}"),
        FixKey::Nullable { at } => format!("null|{at}"),
        FixKey::Widen { at } => format!("widen|{at}"),
        FixKey::Enum { at } => format!("enum|{at}"),
    }
}

/// Ops allowing `null` on the schema `s` at `at`, written to compose with
/// the other suggestions on the same schema (unions into `type` and
/// `enum`, flags): whichever order they apply in, both hold.
fn nullable_ops(d: Dialect, at: &str, s: &Value) -> Vec<PatchOp> {
    let modern = matches!(d, Dialect::OpenApi31 | Dialect::OpenApi32);
    let mut ops = vec![];
    if let Some(c) = s.get("const").filter(|_| modern) {
        ops.push(PatchOp::remove(ptr(at, "const")));
        match s.get("enum").and_then(Value::as_array) {
            // Both constrain: what they allow together, and null.
            Some(values) => {
                let kept = if values.contains(c) { vec![c.clone(), Value::Null] } else { vec![Value::Null] };
                ops.push(PatchOp::replace(ptr(at, "enum"), Value::Array(kept)));
            }
            None => ops.push(PatchOp::union(ptr(at, "enum"), vec![c.clone(), Value::Null])),
        }
    } else if s.get("enum").is_some() {
        ops.push(PatchOp::union(ptr(at, "enum"), vec![Value::Null]));
    }
    match d {
        Dialect::Swagger20 => ops.push(PatchOp::replace(ptr(at, "x-nullable"), json!(true))),
        Dialect::OpenApi30 => ops.push(PatchOp::replace(ptr(at, "nullable"), json!(true))),
        _ if s.get("type").is_some() => ops.push(PatchOp::union(ptr(at, "type"), vec![json!("null")])),
        _ => {}
    }
    if ops.is_empty() {
        // Nothing to extend (null is refused some other way): offer `null`
        // beside the schema.
        let mut wrapped = s.clone();
        mark_nullable(&mut wrapped, d);
        ops.push(PatchOp::replace(at.to_string(), wrapped));
    }
    ops
}

/// The length of the longest `required` list anywhere in `root`.
fn longest_required(root: &Value) -> usize {
    let mut max = 0;
    let mut stack = vec![root];
    while let Some(v) = stack.pop() {
        match v {
            Value::Object(o) => {
                if let Some(Value::Array(r)) = o.get("required") {
                    max = max.max(r.len());
                }
                stack.extend(o.values());
            }
            Value::Array(a) => stack.extend(a),
            _ => {}
        }
    }
    max
}

/// The component a schema location is in, else the response.
fn schema_owner(at: &str, code: &str, label: &str) -> String {
    match at.strip_prefix("/components/schemas/").or_else(|| at.strip_prefix("/definitions/")) {
        Some(rest) => rest.split('/').next().unwrap_or(rest).replace("~1", "/").replace("~0", "~"),
        None => format!("the {code} response of {label}"),
    }
}

/// A schema location as `Owner.a.*.b[]`: property names, `*` for a map's
/// values, `[]` for array items, from the owner's root schema on.
fn display_pointer(at: &str, owner: &str) -> String {
    let toks: Vec<&str> = at.split('/').collect();
    let root = if at.starts_with("/components/schemas/") {
        4
    } else if at.starts_with("/definitions/") {
        3
    } else {
        toks.iter().position(|t| *t == "schema").map_or(toks.len(), |i| i + 1)
    };
    let mut out = owner.to_string();
    let mut i = root;
    while i < toks.len() {
        match toks[i] {
            "properties" if i + 1 < toks.len() => {
                out.push('.');
                out.push_str(&toks[i + 1].replace("~1", "/").replace("~0", "~"));
                i += 1;
            }
            "additionalProperties" => out.push_str(".*"),
            "items" => out.push_str("[]"),
            _ => {}
        }
        i += 1;
    }
    out
}

fn shape_has_samples(s: &Shape) -> bool {
    *s != Shape::default()
}

/// A Media Type Object for an observed body.
fn media_object(d: Dialect, ct: &str, shape: Option<&Shape>) -> Value {
    match shape.filter(|s| shape_has_samples(s)) {
        Some(s) => json!({"schema": s.schema(d)}),
        None if ct.starts_with("text/") => json!({"schema": {"type": "string"}}),
        None => json!({}),
    }
}

/// A Response Object for observed (media type, body shape) variants.
fn response_object(d: Dialect, code: &str, variants: &[(&Option<String>, &Shape)]) -> Value {
    let description = format!("{} (observed by Anvil)", reason(code));
    if d == Dialect::Swagger20 {
        let schema = variants.iter().find(|(_, s)| shape_has_samples(s)).map(|(_, s)| s.schema(d));
        return match schema {
            Some(s) => json!({"description": description, "schema": s}),
            None => json!({"description": description}),
        };
    }
    let mut content = serde_json::Map::new();
    for (ct, shape) in variants {
        if let Some(ct) = ct {
            content.insert(ct.clone(), media_object(d, ct, Some(shape)));
        }
    }
    if content.is_empty() { json!({"description": description}) } else { json!({"description": description, "content": content}) }
}

/// Swagger 2.0: add media types to the operation's `produces`.
fn produces_ops(spec: &Spec, op: &OperationRef<'_>, cts: impl IntoIterator<Item = String>) -> Vec<PatchOp> {
    let mut list = swagger_media(spec, op.op, "produces").unwrap_or_default();
    let before = list.len();
    for ct in cts {
        if !list.iter().any(|x| essence(x) == ct) {
            list.push(ct);
        }
    }
    // A union: another suggestion may add to the same list.
    if list.len() == before {
        vec![]
    } else {
        vec![PatchOp::union(ptr(&op.pointer, "produces"), list.into_iter().map(Value::String).collect())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(generalize("/users/123/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301"), "/users/{userId}/orders/{orderId}");
        assert_eq!(generalize("/v1/health"), "/v1/health");
        assert_eq!(generalize("/42/42"), "/{id}/{id2}");
        // Anything that could be a value is a parameter.
        assert_eq!(generalize("/users/jane.doe@example.com/Tokens/eyJhbGci.eyJzdWIi.sig/a%20b"), "/users/{userId}/{id}/{id2}/{id3}");
        assert_eq!(generalize("/line-items/v2/oauth2/abc12"), "/line-items/v2/oauth2/{oauth2Id}");
        assert_eq!(method_token("get"), "GET");
        assert_eq!(method_token("GET /x"), INVALID_METHOD);
        let null = Value::Null;
        let resps: Vec<crate::model::Response> = ["é1", "4xx", "ñXX", "default"]
            .iter()
            .map(|c| crate::model::Response { code: c.to_string(), pointer: String::new(), value: &null, media: vec![] })
            .collect();
        assert_eq!(declared_response(&resps, "404").map(|r| r.code.as_str()), Some("4xx"));
        assert_eq!(declared_response(&resps, "500").map(|r| r.code.as_str()), Some("default"));
        assert_eq!(nice_ceil(412.0), 500.0);
        assert_eq!(nice_ceil(180.0), 200.0);
        assert_eq!(nice_ceil(2100.0), 2500.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50.0), 2.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 95.0), 4.0);
    }
}
