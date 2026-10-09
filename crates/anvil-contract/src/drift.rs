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
use crate::lint::MAX_EXAMPLE_SCAN;
use crate::lint::SpecSummary;
use crate::locate::ptr;
use crate::model::{
    Direction, METHODS, Media, OperationRef, Param, RequestBody, Response, body_of, parameters, responses, schema_types, swagger_media,
};
use crate::observe::{Observation, ObservedBody, count_values, essence, is_json, split_url};
use crate::patch::{self, PatchOp};
use crate::route::{Route, Router};
use crate::ruleset::Severity;
use crate::schema::{self, Scanned};
use crate::spec::{Meter, Spec};
use anvil_import::Dialect;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

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
/// What walking bodies along their schemas may cost, in bytes: the
/// references followed and the schema pointers copied on the way (see
/// [`Spec::resolve_within`]). Apart from [`MAX_RESOLVE_BYTES`], so that
/// walks never leave operations unresolved. Larger than the budgets of what
/// an analysis keeps: most of these copies are dropped as the walk returns
/// (only suggested fixes, capped by count, and required-property tallies
/// keep theirs), and every body walked copies its schema pointers again, so
/// on a large ordinary description a smaller budget would stop suggestions
/// early. It bounds the copying work as well as what is kept.
const MAX_WALK_BYTES: usize = 1024 * 1024 * 1024;
/// Noted once either walking budget is spent.
const WALK_SPENT: &str = "the analysis' budget for walking bodies is spent; later bodies got no schema suggestions";
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
/// What resolving the operations' parameters, bodies, responses and required
/// response headers may cost, in bytes: the references followed and what is
/// copied out of them (see [`Spec::resolve_within`]). Each operation is
/// resolved once, however many paths and calls reach it; past this, calls to
/// the rest are not checked.
const MAX_RESOLVE_BYTES: usize = crate::model::MAX_MODEL_VIEW_BYTES;
/// Charged per required response header kept, besides its pointer.
const HEADER_BYTES: usize = 64;

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

/// A new finding's message, operation and pointer.
type Details = (String, Option<String>, Option<String>);

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

/// One operation object's finding keys, by kind and what the call adds to its pointer.
type OpKeys = HashMap<(DriftKind, String), Rc<str>>;

struct State<'a> {
    spec: &'a Spec,
    router: Router<'a>,
    /// Each listed operation, built the first time a call reaches it.
    operations: Vec<Option<Rc<OperationRef<'a>>>>,
    /// What each operation object declares, resolved once (`None`: it did
    /// not fit [`MAX_RESOLVE_BYTES`]; see [`State::lists`]).
    declared: HashMap<(usize, usize), Option<Rc<Declared<'a>>>>,
    /// What resolving them may still cost.
    resolve_meter: Meter,
    /// What walking bodies may still cost (see [`MAX_WALK_BYTES`]).
    walk_bytes: Meter,
    opts: DriftOptions,
    findings: BTreeMap<Rc<str>, FindingAcc>,
    /// The keys of each operation object's findings, by kind and what the
    /// call adds to the operation's pointer (see [`State::op_finding`]).
    op_keys: HashMap<(usize, usize), OpKeys>,
    ops: Vec<OpAcc>,
    endpoints: BTreeMap<(String, String), EndpointAcc>,
    fixes: BTreeMap<FixKey, (String, Shape, BTreeSet<String>)>,
    /// (schema holding `required`, name) → (seen, missing, owner).
    required: BTreeMap<(String, String), (usize, usize, String)>,
    servers: BTreeMap<String, (usize, String)>,
    validators: HashMap<(String, bool), Option<jsonschema::Validator>>,
    /// What schema compiles scanned (members and items, and bytes).
    scanned: Scanned,
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
    schema_places: HashMap<(String, String, String, String), BTreeSet<Rc<str>>>,
    /// Fixes to link to the schema findings about the same place and
    /// category, resolved once at the end: (operation, status, place,
    /// category, suggestion key).
    pending_links: BTreeSet<(String, String, String, String, String)>,
}

/// What an operation declares, resolved once for every call to it.
struct Declared<'a> {
    params: Vec<Param<'a>>,
    body: Option<RequestBody<'a>>,
    resps: Vec<Response<'a>>,
    /// The required headers of each of `resps`: name and pointer.
    required_headers: Vec<Vec<(&'a str, String)>>,
}

/// Compare observations with the description.
pub fn analyze(spec: &Spec, observations: &[Observation], opts: &DriftOptions) -> DriftReport {
    let mut st = State::new(spec, opts);
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

/// The declared response for `code` (an index into `resps`): exact, then
/// `4XX`, then `default`.
fn declared_response(resps: &[Response<'_>], code: &str) -> Option<usize> {
    let range = |declared: &str| {
        // Bytes, not characters: a declared key may be any string.
        let d = declared.as_bytes();
        d.len() == 3 && d[1..].eq_ignore_ascii_case(b"xx") && code.as_bytes().first() == Some(&d[0])
    };
    resps
        .iter()
        .position(|r| r.code == code)
        .or_else(|| resps.iter().position(|r| range(&r.code)))
        .or_else(|| resps.iter().position(|r| r.code == "default"))
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
    // The next suffix to try for each stem. Resuming here instead of from
    // one keeps naming bounded by the input size, not quadratic in the
    // number of colliding segments in one path.
    let mut next = BTreeMap::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        if !literal_segment(seg) {
            let base = prev.trim_end_matches('s');
            let stem = if base.is_empty() || !base.chars().all(|c| c.is_ascii_alphanumeric()) {
                "id".to_string()
            } else {
                format!("{}Id", base.to_ascii_lowercase())
            };
            let n = next.entry(stem.clone()).or_insert(1u64);
            let mut name = if *n == 1 { stem.clone() } else { format!("{stem}{n}") };
            while !used.insert(name.clone()) {
                *n += 1;
                name = format!("{stem}{n}");
            }
            *n += 1;
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
    fn new(spec: &'a Spec, opts: &DriftOptions) -> State<'a> {
        let router = Router::new(spec);
        let n_ops = router.operation_count();
        State {
            spec,
            router,
            operations: vec![None; n_ops],
            declared: HashMap::new(),
            resolve_meter: Meter::new(MAX_RESOLVE_BYTES),
            walk_bytes: Meter::new(MAX_WALK_BYTES),
            opts: opts.clone(),
            findings: BTreeMap::new(),
            op_keys: HashMap::new(),
            ops: (0..n_ops).map(|_| OpAcc::default()).collect(),
            endpoints: BTreeMap::new(),
            fixes: BTreeMap::new(),
            required: BTreeMap::new(),
            servers: BTreeMap::new(),
            validators: HashMap::new(),
            scanned: Scanned::default(),
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
        }
    }

    fn dialect(&self) -> Dialect {
        self.spec.dialect
    }

    /// Record a difference; false when it was not recorded (too many
    /// distinct ones), and then nothing about it is gathered either. Its
    /// message, operation and pointer are made only when it is new.
    fn finding(&mut self, key: &Rc<str>, kind: DriftKind, obs: &Observation, details: impl FnOnce() -> Details) -> bool {
        if !self.findings.contains_key(key) {
            if self.findings_full() {
                self.note(format!("only the first {MAX_FINDING_KEYS} distinct differences were collected"));
                return false;
            }
            let (message, operation, pointer) = details();
            self.findings.insert(Rc::clone(key), FindingAcc { kind: Some(kind), message, operation, pointer, ..FindingAcc::default() });
        }
        let Some(f) = self.findings.get_mut(key) else { return false };
        f.count += 1;
        if f.observations.len() < self.opts.max_examples && !f.observations.contains(&obs.id) {
            f.observations.push(obs.id.clone());
        }
        true
    }

    /// Record a difference about operation object `object` (see
    /// [`State::finding`]) under the key `key` builds, and return that key
    /// when it is recorded. Such a key copies the operation's pointer, which
    /// may be long: it is built the first time a call to the operation needs
    /// it and then kept by its kind and `end` (what the call adds: a query
    /// name, content type or status, or nothing), shared with
    /// [`State::findings`], instead of being built again for each call. Only
    /// the keys of recorded findings are kept.
    fn op_finding(
        &mut self,
        object: (usize, usize),
        kind: DriftKind,
        end: &str,
        key: impl FnOnce() -> String,
        obs: &Observation,
        details: impl FnOnce() -> Details,
    ) -> Option<Rc<str>> {
        let key = match self.op_keys.get(&object).and_then(|keys| keys.get(&(kind, end.to_string()))) {
            Some(k) => Rc::clone(k),
            None => {
                // Not kept, so not recorded: nothing else records it.
                if self.findings_full() {
                    self.note(format!("only the first {MAX_FINDING_KEYS} distinct differences were collected"));
                    return None;
                }
                let k: Rc<str> = key().into();
                self.op_keys.entry(object).or_default().insert((kind, end.to_string()), Rc::clone(&k));
                k
            }
        };
        self.finding(&key, kind, obs, details).then_some(key)
    }

    /// No more distinct differences are recorded: body walks, which only
    /// feed suggestions for them, stop.
    fn findings_full(&self) -> bool {
        self.findings.len() >= MAX_FINDING_KEYS
    }

    fn link(&mut self, finding: &str, suggestion_key: &str) {
        if let Some(f) = self.findings.get_mut(finding)
            && !f.suggestions.contains(suggestion_key)
        {
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
            let key: Rc<str> = format!("server|{origin}").into();
            let at = if self.spec.is_swagger2() { "/host" } else { "/servers" };
            let details = || (format!("Requests went to {origin}, which is not one of the declared servers"), None, Some(at.into()));
            if self.finding(&key, DriftKind::UndeclaredServer, o, details) {
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
                let declared = self.router.methods_of(t);
                let list = if declared.is_empty() { "no operations".into() } else { declared.join(", ") };
                (
                    DriftKind::UndeclaredMethod,
                    format!("{method} is called on {t}, which declares only {list}"),
                    Some(Router::path_pointer(t)),
                )
            }
            None => (DriftKind::UndeclaredPath, format!("{label} is called, but the description has no such path"), None),
        };
        let key: Rc<str> = format!("endpoint|{method}|{pattern}").into();
        if !self.finding(&key, kind, o, || (message, Some(label), pointer)) {
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

    /// Listed operation `i`, built once however many calls reach it.
    fn operation(&mut self, i: usize) -> Rc<OperationRef<'a>> {
        let router = &self.router;
        Rc::clone(self.operations[i].get_or_insert_with(|| Rc::new(router.operation(i))))
    }

    /// What listed operation `i` declares, resolved the first time a call
    /// reaches its operation object (one Path Item that several paths `$ref`
    /// is resolved once) and charged to [`MAX_RESOLVE_BYTES`]. `None` once
    /// that is spent: no partial lists are kept.
    fn lists(&mut self, i: usize) -> Option<Rc<Declared<'a>>> {
        let object = self.router.operation_object(i);
        if let Some(found) = self.declared.get(&object) {
            return found.clone();
        }
        let op = self.operation(i);
        let spec = self.spec;
        let meter = &mut self.resolve_meter;
        let params = parameters(spec, &op, meter);
        let body = body_of(spec, &op, &params, meter);
        let resps = responses(spec, &op, meter);
        let headers = resps.iter().map(|r| required_headers(spec, r, meter)).collect();
        let found = (!meter.exhausted()).then(|| Rc::new(Declared { params, body, resps, required_headers: headers }));
        self.declared.insert(object, found.clone());
        found
    }

    fn check_operation(&mut self, i: usize, o: &Observation) {
        let spec = self.spec;
        let op = self.operation(i);
        let object = self.router.operation_object(i);
        let label = op.label();
        let op_ptr = &op.pointer;
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
            let key = || format!("deprecated|{op_ptr}");
            let details = || (format!("{label} is deprecated but was called"), Some(label.clone()), Some(op_ptr.clone()));
            self.op_finding(object, DriftKind::DeprecatedOperationCalled, "", key, o, details);
        }
        let Some(lists) = self.lists(i) else {
            self.note("the description is too large to compare completely; some calls to declared operations were not checked");
            return;
        };

        // Parameters.
        let params = &lists.params;
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
                    let key = || format!("query|{op_ptr}|{q}");
                    let message = || format!("{label} was called with query parameter `{q}`, which is not declared");
                    let details = || (message(), Some(label.clone()), Some(op_ptr.clone()));
                    if let Some(key) = self.op_finding(object, DriftKind::UndeclaredQueryParameter, q, key, o, details) {
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
                let key: Rc<str> = format!("required|{}|{}", p.pointer, p.name).into();
                let message = || format!("{label} was called without the required {} parameter `{}`", p.location, p.name);
                self.finding(&key, DriftKind::MissingRequiredParameter, o, || (message(), Some(label.clone()), Some(p.pointer.clone())));
            }
        }

        // Request body.
        if o.request_bytes > 0
            && let Some(ct) = o.request_content_type.as_deref()
        {
            let body = lists.body.as_ref();
            let declared = body.map(|b| b.media.as_slice()).unwrap_or_default();
            if media_for(declared, ct).is_none() {
                let e = essence(ct);
                let list = if declared.is_empty() {
                    "no request body".to_string()
                } else {
                    declared.iter().map(|m| m.media_type.clone()).collect::<Vec<_>>().join(", ")
                };
                let key = || format!("reqtype|{op_ptr}|{e}");
                let message = || format!("{label} was sent a {e} body; the description declares {list}");
                let details = || (message(), Some(label.clone()), Some(body.map_or_else(|| op_ptr.clone(), |b| b.pointer.clone())));
                if let Some(key) = self.op_finding(object, DriftKind::UndeclaredRequestContentType, &e, key, o, details) {
                    self.link(&key, &key);
                    self.ops[i].new_request_types.insert(e);
                }
            }
        }
        if let Some(max) = b.max_request_bytes
            && o.request_bytes > max
        {
            self.ops[i].large_request += 1;
            let key = || format!("reqsize|{op_ptr}");
            let details = || (String::new(), Some(label.clone()), Some(op_ptr.clone()));
            if let Some(key) = self.op_finding(object, DriftKind::RequestLargerThanDeclared, "", key, o, details) {
                self.link(&key, &key);
            }
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
            let key = || format!("slow|{op_ptr}");
            let details = || (String::new(), Some(label.clone()), Some(op_ptr.clone()));
            if let Some(key) = self.op_finding(object, DriftKind::SlowerThanDeclared, "", key, o, details) {
                self.link(&key, &key);
            }
        }
        if let (Some(max), Some(n)) = (b.max_response_bytes, r.bytes)
            && n > max
        {
            self.ops[i].large += 1;
            let key = || format!("size|{op_ptr}");
            let details = || (String::new(), Some(label.clone()), Some(op_ptr.clone()));
            if let Some(key) = self.op_finding(object, DriftKind::ResponseLargerThanDeclared, "", key, o, details) {
                self.link(&key, &key);
            }
        }
        let has_body = !matches!(r.body, ObservedBody::Empty) && r.bytes != Some(0);
        let ct = r.content_type.as_deref().map(essence).filter(|_| has_body);
        let Some(k) = declared_response(&lists.resps, &code) else {
            let key = || format!("status|{op_ptr}|{code}");
            let message = || format!("{label} returned {code}, which is not a documented response");
            let details = || (message(), Some(label.clone()), Some(ptr(op_ptr, "responses")));
            let Some(key) = self.op_finding(object, DriftKind::UndeclaredStatus, &code, key, o, details) else { return };
            self.link(&key, &key);
            let shape = self.ops[i].new_responses.entry((code, ct)).or_default();
            if let ObservedBody::Json(v) = &r.body {
                shape.add(v);
            }
            return;
        };
        let resp = &lists.resps[k];
        // Required response headers.
        for (name, hptr) in &lists.required_headers[k] {
            if !r.headers.iter().any(|x| x.eq_ignore_ascii_case(name)) {
                let key: Rc<str> = format!("header|{hptr}").into();
                let message = || format!("The {code} response of {label} did not include the required header `{name}`");
                self.finding(&key, DriftKind::MissingResponseHeader, o, || (message(), Some(label.clone()), Some(hptr.clone())));
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
            let key: Rc<str> = format!("ctype|{}|{ct}", resp.pointer).into();
            let message = || format!("The {code} response of {label} was {ct}; the description declares {list}");
            if !self.finding(&key, DriftKind::UndeclaredContentType, o, || (message(), Some(label.clone()), Some(resp.pointer.clone()))) {
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
            let v = schema::compile_within(spec, schema, Direction::Response, &mut self.scanned, MAX_EXAMPLE_SCAN).ok();
            if v.is_none() {
                self.note(if self.scanned.exceeds(MAX_EXAMPLE_SCAN) {
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
            let key: Rc<str> = format!("schema|{}|{m}", media.schema_pointer).into();
            let message = || format!("The {code} response of {label} does not match its schema: {m}");
            let details = || (message(), Some(label.clone()), Some(media.schema_pointer.clone()));
            if !self.finding(&key, DriftKind::ResponseSchemaMismatch, o, details) {
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
            self.note(WALK_SPENT);
            return false;
        }
        true
    }

    /// Charge `bytes` copied while walking bodies to [`State::walk_bytes`];
    /// false once that budget is spent.
    fn walk_charge(&mut self, bytes: usize) -> bool {
        let fresh = !self.walk_bytes.exhausted();
        if self.walk_bytes.charge(bytes) {
            return true;
        }
        if fresh {
            self.note(WALK_SPENT);
        }
        false
    }

    /// [`Spec::deref`] charged to [`State::walk_bytes`]: `None` once that
    /// budget is spent.
    fn walk_deref(&mut self, v: &'a Value, at: &str) -> Option<(&'a Value, String)> {
        let fresh = !self.walk_bytes.exhausted();
        let spec: &'a Spec = self.spec;
        match spec.resolve_within(v, at, &mut self.walk_bytes) {
            Some(found) => Some(found),
            None if self.walk_bytes.exhausted() => {
                if fresh {
                    self.note(WALK_SPENT);
                }
                None
            }
            None => Some((v, at.to_string())),
        }
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
        if depth > 32 || self.walk_bytes.exhausted() || !self.spend(1) {
            return;
        }
        let Some((s, at)) = self.walk_deref(schema, at) else { return };
        if s.get("oneOf").is_some() || s.get("anyOf").is_some() {
            return;
        }
        // The copies of `at` below: the holder and the first part, or a
        // fix's key and its suggestion's.
        if !self.walk_charge(2 * at.len()) {
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
                    let Some(part) = self.walk_deref(b, &ptr(&ptr(&at, "allOf"), &k.to_string())) else { return };
                    parts.push(part);
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
                        if !self.walk_charge(parts[pi].1.len() + k.len()) {
                            return;
                        }
                        let pp = ptr(&ptr(&parts[pi].1, "properties"), k);
                        self.walk(ps, &pp, x, &ptr(ipath, k), depth + 1, label, code, o, failed);
                    } else if let Some((ap, app)) = &additional {
                        self.walk(ap, app, x, &ptr(ipath, "*"), depth + 1, label, code, o, failed);
                    } else if names_properties && safe_name(k) {
                        // The fix's key, then its suggestion's.
                        if !self.walk_charge(2 * (holder.len() + k.len())) {
                            return;
                        }
                        let key = FixKey::AddProperty { at: holder.clone(), name: k.clone() };
                        if let Some(e) = self.fix(&key, owner) {
                            e.1.add(x);
                            e.2.insert(o.id.clone());
                            fix_link(self, fix_suggestion_key(&key), ipath, "additional");
                        }
                    }
                }
                for (name, pi) in required {
                    let write_only = match declared.get(name) {
                        Some(&(ps, _)) => match self.walk_deref(ps, "") {
                            Some((p, _)) => p.get("writeOnly").and_then(Value::as_bool) == Some(true),
                            None => return,
                        },
                        None => false,
                    };
                    if write_only {
                        continue;
                    }
                    // The copies of the pointer below: the entry's key, its
                    // owner and the link.
                    if !self.walk_charge(3 * parts[pi].1.len()) {
                        return;
                    }
                    let rp = parts[pi].1.clone();
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
                    if !self.walk_charge(at.len()) {
                        return;
                    }
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
            let keys: Vec<Rc<str>> = self.schema_places.get(&(label, code, place, category)).into_iter().flatten().cloned().collect();
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
            let op = &self.router.operation(i);
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
            // Only checked operations have new request types: their body is
            // already resolved.
            let body = self.declared.get(&self.router.operation_object(i)).and_then(Option::as_ref).and_then(|d| d.body.as_ref());
            for ct in &acc.new_request_types {
                let key = format!("reqtype|{op_ptr}|{ct}");
                let ops = if d == Dialect::Swagger20 {
                    let mut consumes = swagger_media(spec, op.op, "consumes").unwrap_or_default();
                    consumes.push(ct.clone());
                    let mut ops = vec![PatchOp::union(ptr(&op_ptr, "consumes"), consumes.into_iter().map(Value::String).collect())];
                    if body.is_none() {
                        ops.push(PatchOp::add(ptr(&ptr(&op_ptr, "parameters"), "-"), json!({"name": "body", "in": "body", "schema": {}})));
                    }
                    ops
                } else {
                    match body {
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

        // Undeclared endpoints. What each template's Path Item declares is
        // resolved once, however many methods were called on it.
        let mut items: HashMap<&str, Option<PathItemView>> = HashMap::new();
        let no_params = BTreeSet::new();
        let mut not_describable = 0;
        let mut unresolved_items = 0;
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
            let (declared_path_params, path_ptr, path_key) = match &acc.template {
                Some(t) => {
                    let item = items.entry(t.as_str()).or_insert_with(|| path_item_view(spec, t, &mut self.resolve_meter));
                    let Some(item) = item.as_ref() else {
                        unresolved_items += 1;
                        continue;
                    };
                    (&item.params, item.pointer.clone(), t.clone())
                }
                None => (&no_params, Router::path_pointer(pattern), pattern.clone()),
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
        if unresolved_items > 0 {
            self.notes.insert(
                "the description is too large to compare completely; some undeclared endpoints got no suggestion".into(),
                unresolved_items,
            );
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
        // Declared statuses once per operation, however many paths reach it
        // (`None`: past the resolution budget).
        let mut statuses: HashMap<(usize, usize), Option<Vec<String>>> = HashMap::new();
        let mut unlisted = 0;
        for (i, acc) in self.ops.iter().enumerate() {
            let op = &self.router.operation(i);
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
                if let Some(f) = self.findings.get_mut(key.as_str()) {
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
                let (Some(max), Some(f)) = (max, self.findings.get_mut(key.as_str())) else { continue };
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
            let object = self.router.operation_object(i);
            let declared_statuses = match self.declared.get(&object) {
                Some(Some(lists)) => Some(lists.resps.iter().map(|r| r.code.clone()).collect()),
                _ => statuses.entry(object).or_insert_with(|| declared_codes(spec, op, &mut self.resolve_meter)).clone(),
            };
            let declared_statuses = declared_statuses.unwrap_or_else(|| {
                unlisted += 1;
                vec![]
            });
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
        if unlisted > 0 {
            self.notes.insert(
                "the description is too large to compare completely; some operations' declared statuses are not listed".into(),
                unlisted,
            );
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
        if self.router.skipped_operations > 0 {
            self.notes.insert(
                "the description is too large to compare completely; calls to the operations left out are reported as undeclared".into(),
                self.router.skipped_operations,
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
                // Those left out of matching too.
                operations: self.router.operation_count() + self.router.skipped_operations,
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

/// The declared statuses of `op`, charged to `meter`; `None` once it is
/// spent.
fn declared_codes<'a>(spec: &'a Spec, op: &OperationRef<'a>, meter: &mut Meter) -> Option<Vec<String>> {
    let resps = responses(spec, op, meter);
    (!meter.exhausted()).then(|| resps.into_iter().map(|r| r.code).collect())
}

/// The required headers of `resp`: name and pointer, each charged to `meter`
/// (see [`responses`]).
fn required_headers<'a>(spec: &'a Spec, resp: &Response<'a>, meter: &mut Meter) -> Vec<(&'a str, String)> {
    let mut out = vec![];
    let Some(headers) = resp.value.get("headers").and_then(Value::as_object) else { return out };
    if !meter.charge(resp.pointer.len() + 8) {
        return out;
    }
    let base = ptr(&resp.pointer, "headers");
    for (name, h) in headers {
        if meter.exhausted() {
            break;
        }
        let Some((h, hptr)) = spec.resolve_within(h, &ptr(&base, name), meter) else { continue };
        if h.get("required").and_then(Value::as_bool) == Some(true) {
            if !meter.charge(HEADER_BYTES + name.len()) {
                break;
            }
            out.push((name.as_str(), hptr));
        }
    }
    out
}

/// What a Path Item declares for the suggestions of undeclared methods on it.
struct PathItemView {
    /// Where it is (its `$ref` followed).
    pointer: String,
    /// The names of its path-level parameters.
    params: BTreeSet<String>,
}

/// The Path Item of `template`, each reference followed within `meter`:
/// `None` once a charge is refused.
fn path_item_view(spec: &Spec, template: &str, meter: &mut Meter) -> Option<PathItemView> {
    let at = Router::path_pointer(template);
    let Some(item) = spec.root.pointer(&at) else { return Some(PathItemView { pointer: at, params: BTreeSet::new() }) };
    let pointer = match spec.resolve_within(item, &at, meter) {
        Some((_, p)) => p,
        None if meter.exhausted() => return None,
        None => at.clone(),
    };
    let base = ptr(&at, "parameters");
    let mut params = BTreeSet::new();
    for (i, p) in item.get("parameters").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let p = match spec.resolve_within(p, &ptr(&base, &i.to_string()), meter) {
            Some((p, _)) => p,
            None if meter.exhausted() => return None,
            None => p,
        };
        params.extend(p.get("name").and_then(Value::as_str).map(str::to_string));
    }
    Some(PathItemView { pointer, params })
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
        let resps: Vec<Response> = ["é1", "4xx", "ñXX", "default"]
            .iter()
            .map(|c| Response { code: c.to_string(), pointer: String::new(), value: &null, media: vec![] })
            .collect();
        assert_eq!(declared_response(&resps, "404").map(|i| resps[i].code.as_str()), Some("4xx"));
        assert_eq!(declared_response(&resps, "500").map(|i| resps[i].code.as_str()), Some("default"));
        assert_eq!(nice_ceil(412.0), 500.0);
        assert_eq!(nice_ceil(180.0), 200.0);
        assert_eq!(nice_ceil(2100.0), 2500.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50.0), 2.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 95.0), 4.0);
    }

    #[test]
    fn pathological_path_parameters_are_named_within_input_size() {
        // Every non-literal segment here names the same `{id}` stem. Restarting
        // the suffix search from one for each segment made this quadratic; the
        // work is now bounded by the number of segments.
        const SEGMENTS: usize = 50_000;
        let path = "/123".repeat(SEGMENTS);
        let generalized = generalize(&path);
        assert_eq!(generalized.matches('{').count(), SEGMENTS);
        assert!(generalized.ends_with(&format!("{{id{SEGMENTS}}}")), "{}", &generalized[generalized.len() - 32..]);
    }

    #[test]
    fn each_operation_is_resolved_once_however_many_calls_reach_it() {
        // A parameter, a response and its header at pointers of about
        // 200 KB, each behind one alias.
        let key = "k".repeat(4_000);
        let nest = |mut v: Value| {
            for _ in 0..50 {
                let mut level = serde_json::Map::new();
                level.insert(key.clone(), v);
                v = Value::Object(level);
            }
            v
        };
        let deep = |name: &str| format!("#/{name}{}", format!("/{key}").repeat(50));
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"},
            "paths": {"/a": {"get": {"parameters": [{"$ref": "#/p"}], "responses": {"200": {"$ref": "#/r"}}}}},
            "xp": nest(json!({"name": "q", "in": "query", "required": true})),
            "xr": nest(json!({"description": "ok", "headers": {"X-Id": {"$ref": "#/h"}}})),
            "xh": nest(json!({"required": true, "schema": {"type": "string"}})),
            "p": {"$ref": deep("xp")}, "r": {"$ref": deep("xr")}, "h": {"$ref": deep("xh")}});
        let text = doc.to_string();
        let call = |i: usize| Observation {
            id: format!("har:{i}"),
            at: None,
            method: "GET".into(),
            url: "/a".into(),
            operation_hint: None,
            request_content_type: None,
            request_bytes: 0,
            query: vec![],
            request_headers: vec![],
            response: Some(crate::observe::ObservedResponse {
                status: 200,
                content_type: None,
                headers: vec![],
                bytes: Some(0),
                body: ObservedBody::Empty,
            }),
            latency_ms: None,
        };
        // Pointers walked to follow references in an analysis of `calls`
        // calls, each missing the required parameter and header.
        let walks = |calls: usize| {
            let spec = Spec::parse(text.as_bytes()).unwrap();
            let observations: Vec<Observation> = (0..calls).map(&call).collect();
            let report = analyze(&spec, &observations, &DriftOptions::default());
            for kind in [DriftKind::MissingRequiredParameter, DriftKind::MissingResponseHeader] {
                assert_eq!(report.findings.iter().find(|f| f.kind == kind).map(|f| f.count), Some(calls), "{kind:?}");
            }
            spec.walks.load(std::sync::atomic::Ordering::Relaxed)
        };
        assert_eq!(walks(1), walks(2_000));
    }

    /// `v` under 50 members named `key`, and a reference to it from `name`.
    fn buried(key: &str, name: &str, mut v: Value) -> (Value, String) {
        for _ in 0..50 {
            let mut level = serde_json::Map::new();
            level.insert(key.to_string(), v);
            v = Value::Object(level);
        }
        (v, format!("#/{name}{}", format!("/{key}").repeat(50)))
    }

    #[test]
    fn an_operations_finding_keys_are_built_once_however_many_calls_reach_it() {
        // A deprecated operation in a Path Item behind one alias of a pointer
        // of about 200 KB: each key about it copies that pointer.
        let key = "k".repeat(4_000);
        let (xi, deep) = buried(&key, "xi", json!({"get": {"deprecated": true, "responses": {"200": {"description": "ok"}}}}));
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"},
            "paths": {"/a": {"$ref": "#/i"}}, "xi": xi, "i": {"$ref": deep}});
        let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
        // Each call is deprecated, sends an undeclared query parameter and
        // gets an undeclared status.
        let call = |i: usize| Observation {
            id: format!("har:{i}"),
            at: None,
            method: "GET".into(),
            url: "/a".into(),
            operation_hint: None,
            request_content_type: None,
            request_bytes: 0,
            query: vec!["limit".into()],
            request_headers: vec![],
            response: Some(crate::observe::ObservedResponse {
                status: 404,
                content_type: None,
                headers: vec![],
                bytes: Some(0),
                body: ObservedBody::Empty,
            }),
            latency_ms: None,
        };
        let mut st = State::new(&spec, &DriftOptions::default());
        for i in 0..1_000 {
            st.observe(&call(i));
        }
        // One key per finding, kept once and shared with the finding.
        let kept: Vec<(&(DriftKind, String), &Rc<str>)> = st.op_keys.values().flat_map(|keys| keys.iter()).collect();
        let mut kinds: Vec<DriftKind> = kept.iter().map(|((kind, _), _)| *kind).collect();
        kinds.sort();
        let mut expected = [DriftKind::DeprecatedOperationCalled, DriftKind::UndeclaredQueryParameter, DriftKind::UndeclaredStatus];
        expected.sort();
        assert_eq!(kinds, expected);
        for (_, k) in kept {
            assert!(k.len() > 200_000, "{}", k.len());
            let (recorded, f) = st.findings.get_key_value(&**k).unwrap();
            assert!(Rc::ptr_eq(recorded, k));
            assert_eq!(f.count, 1_000);
        }
        assert_eq!(st.findings.len(), 3);
        let report = st.finish(1_000);
        assert_eq!(report.findings.len(), 3, "{:#?}", report.findings);
        assert!(report.findings.iter().all(|f| f.count == 1_000 && f.operation.as_deref() == Some("GET /a")), "{:#?}", report.findings);
    }

    #[test]
    fn walking_bodies_is_charged_for_the_pointers_it_copies() {
        // A response schema behind one alias of a pointer of about 200 KB:
        // each body walked along it copies that pointer for each key.
        let key = "k".repeat(4_000);
        let (xs, deep) = buried(&key, "xs", json!({"type": "object", "properties": {"id": {"type": "string"}}}));
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"},
            "paths": {"/a": {"get": {"responses": {"200": {"description": "ok",
                "content": {"application/json": {"schema": {"$ref": "#/s"}}}}}}}},
            "xs": xs, "s": {"$ref": deep}});
        let text = doc.to_string();
        let call = |i: usize| Observation {
            id: format!("har:{i}"),
            at: None,
            method: "GET".into(),
            url: "/a".into(),
            operation_hint: None,
            request_content_type: None,
            request_bytes: 0,
            query: vec![],
            request_headers: vec![],
            response: Some(crate::observe::ObservedResponse {
                status: 200,
                content_type: Some("application/json".into()),
                headers: vec![],
                bytes: None,
                body: ObservedBody::Json(json!({"id": "x", "extra": i})),
            }),
            latency_ms: None,
        };
        // Pointers walked to follow references in an analysis of `calls`
        // calls.
        let walks = |calls: usize| {
            let spec = Spec::parse(text.as_bytes()).unwrap();
            let observations: Vec<Observation> = (0..calls).map(&call).collect();
            let report = analyze(&spec, &observations, &DriftOptions::default());
            assert!(report.suggestions.iter().any(|s| s.title.contains("extra")), "{:?}", report.suggestions);
            (spec.walks.load(std::sync::atomic::Ordering::Relaxed), report.notes)
        };
        let (few, notes) = walks(10);
        assert!(!notes.iter().any(|n| n.starts_with(WALK_SPENT)), "{notes:?}");
        // Past the budget, bodies are no longer walked: no more references
        // are followed, however many calls there are.
        let (many, notes) = walks(2_000);
        assert!(notes.iter().any(|n| n.starts_with(WALK_SPENT)), "{notes:?}");
        assert!(many < 2_000, "{many}");
        assert!(few < many, "{few} {many}");
        assert_eq!(walks(4_000).0, many);
    }

    #[test]
    fn path_parameters_are_resolved_once_however_many_methods_are_undeclared() {
        // 100 path-level parameters, each behind one alias of a pointer of
        // about 200 KB.
        let key = "k".repeat(4_000);
        let (xp, deep) = buried(&key, "xp", json!({"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}));
        let params: Vec<Value> = (0..100).map(|_| json!({"$ref": "#/p"})).collect();
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"},
            "paths": {"/a/{id}": {"parameters": params, "get": {"responses": {"200": {"description": "ok"}}}}},
            "xp": xp, "p": {"$ref": deep}});
        let text = doc.to_string();
        let call = |method: &str| Observation {
            id: format!("har:{method}"),
            at: None,
            method: method.into(),
            url: "/a/7".into(),
            operation_hint: None,
            request_content_type: None,
            request_bytes: 0,
            query: vec![],
            request_headers: vec![],
            response: None,
            latency_ms: None,
        };
        // Pointers walked to follow references in an analysis of a call
        // with each of `methods`, none declared.
        let walks = |methods: &[&str]| {
            let spec = Spec::parse(text.as_bytes()).unwrap();
            let observations: Vec<Observation> = methods.iter().map(|m| call(m)).collect();
            let report = analyze(&spec, &observations, &DriftOptions::default());
            for m in methods {
                let s = report.suggestions.iter().find(|s| s.title == format!("Document {m} /a/{{id}}")).expect(m);
                // `id` is declared on the Path Item: the operation does not
                // repeat it.
                let ops = serde_json::to_string(&s.ops).unwrap();
                assert!(!ops.contains(r#""in":"path""#), "{ops}");
            }
            spec.walks.load(std::sync::atomic::Ordering::Relaxed)
        };
        assert_eq!(walks(&["POST"]), walks(&["POST", "PUT", "DELETE", "PATCH", "TRACE"]));
    }
}
