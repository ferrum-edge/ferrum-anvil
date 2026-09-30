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
//! Messages and suggestions carry no observed values except property,
//! parameter and header names, status codes, media types, sizes and times:
//! inferred schemas keep only the shape ([`crate::infer`]). An observed
//! value becomes part of a suggestion only as a short enum token.

use crate::infer::{Shape, mark_nullable};
use crate::lint::SpecSummary;
use crate::locate::ptr;
use crate::model::{Direction, Media, OperationRef, parameters, request_body, responses, schema_types, swagger_media};
use crate::observe::{Observation, ObservedBody, essence, is_json, split_url};
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
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The extension an operation, path item or document declares its budget in.
pub const EXPECTATIONS: &str = "x-anvil-expectations";

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
    /// Stable for the same description and observations.
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
    /// Observed paths with id-like segments generalized (`/users/{userId}`).
    pub path: String,
    pub calls: usize,
    pub statuses: BTreeMap<String, usize>,
    /// Some observed paths.
    pub examples: Vec<String>,
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
}

/// Apply the suggestions with `ids` (in report order) to `spec`.
pub fn revise(spec: &Spec, report: &DriftReport, ids: &[String]) -> Revision {
    let mut doc = spec.root.clone();
    let mut applied = vec![];
    let mut skipped: Vec<String> = ids.iter().filter(|id| !report.suggestions.iter().any(|s| &&s.id == id)).cloned().collect();
    for s in report.suggestions.iter().filter(|s| ids.contains(&s.id)) {
        if patch::apply(&mut doc, &s.ops) > 0 {
            skipped.push(s.id.clone());
        } else {
            applied.push(s.id.clone());
        }
    }
    Revision { text: patch::render(&doc, spec.syntax), json_patch: patch::diff(&spec.root, &doc), applied, skipped }
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
    method: String,
    base: String,
    /// The declared path, when only the method is new.
    template: Option<String>,
    calls: usize,
    statuses: BTreeMap<String, usize>,
    examples: Vec<String>,
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
    required: BTreeMap<(String, String), (usize, usize)>,
    servers: BTreeMap<String, (usize, String)>,
    validators: HashMap<(String, bool), Option<jsonschema::Validator>>,
    notes: BTreeMap<String, usize>,
    matched: usize,
    without_response: usize,
    ignored: usize,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    /// Schema findings by (operation, status, place in the body).
    schema_places: HashMap<(String, String, String), BTreeSet<String>>,
    /// Fixes to link to the schema findings about the same place, resolved
    /// once at the end: (operation, status, place, suggestion key).
    pending_links: BTreeSet<(String, String, String, String)>,
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
    resps
        .iter()
        .find(|r| r.code == code)
        .or_else(|| resps.iter().find(|r| r.code.len() == 3 && r.code[1..].eq_ignore_ascii_case("xx") && r.code[..1] == code[..1]))
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

/// A generalized path: id-like segments become `{nameId}` parameters.
fn generalize(path: &str) -> String {
    let mut out = String::new();
    // The last literal segment names the next parameter.
    let mut prev = "";
    let mut used = BTreeSet::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        let digits = seg.chars().filter(char::is_ascii_digit).count();
        let id_like = seg.chars().all(|c| c.is_ascii_digit())
            || (seg.len() == 36 && seg.matches('-').count() == 4)
            || (seg.len() >= 8 && digits >= 2 && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        out.push('/');
        if id_like {
            let base = prev.trim_end_matches('s');
            let mut name = if base.is_empty() || !base.chars().all(|c| c.is_ascii_alphanumeric()) {
                "id".to_string()
            } else {
                format!("{}Id", base.to_ascii_lowercase())
            };
            while !used.insert(name.clone()) {
                name.push('2');
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

/// A value-free description of a validation error: where in the body, and
/// what is wrong there.
fn describe(e: &jsonschema::ValidationError<'_>) -> (String, String) {
    use jsonschema::error::ValidationErrorKind as K;
    let at: String = e
        .instance_path()
        .as_str()
        .split('/')
        .map(|t| if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) { "*" } else { t })
        .collect::<Vec<_>>()
        .join("/");
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
            format!("has undeclared properties {}", unexpected.iter().map(|u| format!("`{u}`")).collect::<Vec<_>>().join(", "))
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
        _ => format!("violates `{}`", e.schema_path().as_str().rsplit('/').next().unwrap_or("?")),
    };
    (if at.is_empty() { "the body".to_string() } else { format!("`{at}`") }, what)
}

fn allows_null(s: &Value) -> bool {
    let (_, types, nullable) = schema_types(s);
    nullable || (types.is_empty() && s.get("type").is_none())
}

impl<'a> State<'a> {
    fn dialect(&self) -> Dialect {
        self.spec.dialect
    }

    fn finding(
        &mut self,
        key: String,
        kind: DriftKind,
        obs: &Observation,
        message: String,
        operation: Option<String>,
        pointer: Option<String>,
    ) -> String {
        let f = self.findings.entry(key.clone()).or_default();
        if f.kind.is_none() {
            *f = FindingAcc { kind: Some(kind), message, operation, pointer, ..FindingAcc::default() };
        }
        f.count += 1;
        if f.observations.len() < self.opts.max_examples && !f.observations.contains(&obs.id) {
            f.observations.push(obs.id.clone());
        }
        key
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
        {
            let base = match &route {
                Route::Operation { base, .. } | Route::Method { base, .. } | Route::Path { base } => base.clone(),
            };
            let e = self.servers.entry(origin.clone()).or_insert((0, base));
            e.0 += 1;
            let key = format!("server|{origin}");
            self.finding(
                key.clone(),
                DriftKind::UndeclaredServer,
                o,
                format!("Requests went to {origin}, which is not one of the declared servers"),
                None,
                Some(if self.spec.is_swagger2() { "/host".into() } else { "/servers".into() }),
            );
            self.link(&key, &format!("server|{origin}"));
        }
        match route {
            Route::Operation { op, .. } => {
                self.matched += 1;
                self.check_operation(op, o);
            }
            Route::Method { .. } | Route::Path { .. } if o.method == "OPTIONS" => self.ignored += 1,
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
        let label = format!("{} {pattern}", o.method);
        let (kind, message, pointer) = match &template {
            Some(t) => {
                let declared: Vec<String> =
                    self.router.ops.iter().filter(|x| &x.path == t).map(|x| x.method.to_ascii_uppercase()).collect();
                let list = if declared.is_empty() { "no operations".into() } else { declared.join(", ") };
                (
                    DriftKind::UndeclaredMethod,
                    format!("{} is called on {t}, which declares only {list}", o.method),
                    Some(Router::path_pointer(t)),
                )
            }
            None => (DriftKind::UndeclaredPath, format!("{label} is called, but the description has no such path"), None),
        };
        let key = format!("endpoint|{}|{pattern}", o.method);
        self.finding(key.clone(), kind, o, message, Some(label), pointer);
        self.link(&key, &key);
        let acc = self.endpoints.entry((o.method.clone(), pattern.clone())).or_default();
        acc.method = o.method.clone();
        acc.base = base;
        acc.template = template;
        acc.calls += 1;
        if acc.examples.len() < 3 && !acc.examples.iter().any(|e| e == path) {
            acc.examples.push(path.to_string());
        }
        acc.query.extend(o.query.iter().cloned());
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
                    let key = format!("query|{op_ptr}|{q}");
                    self.finding(
                        key.clone(),
                        DriftKind::UndeclaredQueryParameter,
                        o,
                        format!("{label} was called with query parameter `{q}`, which is not declared"),
                        Some(label.clone()),
                        Some(op_ptr.clone()),
                    );
                    self.link(&key, &key);
                    self.ops[i].new_query.insert(q.clone());
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
                self.finding(
                    key.clone(),
                    DriftKind::UndeclaredRequestContentType,
                    o,
                    format!("{label} was sent a {e} body; the description declares {list}"),
                    Some(label.clone()),
                    body.as_ref().map(|b| b.pointer.clone()).or(Some(op_ptr.clone())),
                );
                self.link(&key, &key);
                self.ops[i].new_request_types.insert(e);
            }
        }
        if let Some(max) = b.max_request_bytes
            && o.request_bytes > max
        {
            self.ops[i].large_request += 1;
            let key = format!("reqsize|{op_ptr}");
            self.finding(key, DriftKind::RequestLargerThanDeclared, o, String::new(), Some(label.clone()), Some(op_ptr.clone()));
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
            self.finding(key, DriftKind::ResponseLargerThanDeclared, o, String::new(), Some(label.clone()), Some(op_ptr.clone()));
        }
        let has_body = !matches!(r.body, ObservedBody::Empty) && r.bytes != Some(0);
        let ct = r.content_type.as_deref().map(essence).filter(|_| has_body);
        let resps = responses(spec, &op);
        let Some(resp) = declared_response(&resps, &code) else {
            let key = format!("status|{op_ptr}|{code}");
            self.finding(
                key.clone(),
                DriftKind::UndeclaredStatus,
                o,
                format!("{label} returned {code}, which is not a documented response"),
                Some(label.clone()),
                Some(ptr(&op_ptr, "responses")),
            );
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
            self.finding(
                key.clone(),
                DriftKind::UndeclaredContentType,
                o,
                format!("The {code} response of {label} was {ct}; the description declares {list}"),
                Some(label.clone()),
                Some(resp.pointer.clone()),
            );
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
        let vkey = (media.schema_pointer.clone(), false);
        if !self.validators.contains_key(&vkey) {
            let v = schema::compile(spec, schema, Direction::Response).ok();
            if v.is_none() {
                self.note("some response schemas could not be compiled (an external or broken reference); their bodies were not checked");
            }
            self.validators.insert(vkey.clone(), v);
        }
        let messages: Vec<(String, String)> = match self.validators.get(&vkey).and_then(Option::as_ref) {
            Some(v) => v.iter_errors(body).take(10).map(|e| describe(&e)).collect(),
            None => vec![],
        };
        if messages.is_empty() {
            // Still record required-property presence for relaxations.
            self.walk(schema, &media.schema_pointer, body, "", 0, &label, &code, o, false);
            return;
        }
        for (place, what) in &messages {
            let m = format!("{place} {what}");
            let key = format!("schema|{}|{m}", media.schema_pointer);
            self.finding(
                key.clone(),
                DriftKind::ResponseSchemaMismatch,
                o,
                format!("The {code} response of {label} does not match its schema: {m}"),
                Some(label.clone()),
                Some(media.schema_pointer.clone()),
            );
            self.schema_places.entry((label.clone(), code.clone(), place.clone())).or_default().insert(key);
        }
        self.walk(schema, &media.schema_pointer, body, "", 0, &label, &code, o, true);
    }

    /// Walk a body along its schema, collecting fixes that would make the
    /// schema accept it. `failed`: the body did not validate (fixes are
    /// linked to that response's schema findings).
    #[allow(clippy::too_many_arguments)]
    fn walk(
        &mut self,
        schema: &Value,
        at: &str,
        v: &Value,
        ipath: &str,
        depth: usize,
        label: &str,
        code: &str,
        o: &Observation,
        failed: bool,
    ) {
        if depth > 32 {
            return;
        }
        let spec = self.spec;
        let (s, at) = spec.deref(schema, at);
        if s.get("oneOf").is_some() || s.get("anyOf").is_some() {
            return;
        }
        let owner = || -> String {
            // The component the location is in, else the response.
            match at.strip_prefix("/components/schemas/").or_else(|| at.strip_prefix("/definitions/")) {
                Some(rest) => rest.split('/').next().unwrap_or(rest).replace("~1", "/").replace("~0", "~"),
                None => format!("the {code} response of {label}"),
            }
        };
        // Link a fix to the schema findings about the same place in the
        // body (resolved once, in `finish`).
        let fix_link = |st: &mut Self, key: &FixKey, at_path: &str| {
            if failed {
                let place = if at_path.is_empty() { "the body".to_string() } else { format!("`{at_path}`") };
                st.pending_links.insert((label.to_string(), code.to_string(), place, fix_suggestion_key(key)));
            }
        };
        match v {
            Value::Null => {
                if !allows_null(s) {
                    let key = FixKey::Nullable { at: at.clone() };
                    self.fixes.entry(key.clone()).or_insert_with(|| (owner(), Shape::default(), BTreeSet::new())).2.insert(o.id.clone());
                    fix_link(self, &key, ipath);
                }
            }
            Value::Object(obj) => {
                // Declared properties, across `allOf` branches.
                let mut declared: Vec<(String, Value, String)> = vec![];
                let mut required: Vec<(String, String)> = vec![];
                let mut holder = at.clone();
                let mut additional: Option<(Value, String)> = None;
                let mut parts: Vec<(Value, String)> = vec![(s.clone(), at.clone())];
                if let Some(all) = s.get("allOf").and_then(Value::as_array) {
                    for (k, b) in all.iter().enumerate() {
                        let (b, bp) = spec.deref(b, &ptr(&ptr(&at, "allOf"), &k.to_string()));
                        parts.push((b.clone(), bp));
                    }
                }
                let mut found_holder = false;
                for (part, pp) in &parts {
                    if let Some(props) = part.get("properties").and_then(Value::as_object) {
                        if !found_holder {
                            holder = pp.clone();
                            found_holder = true;
                        }
                        for (n, ps) in props {
                            declared.push((n.clone(), ps.clone(), ptr(&ptr(pp, "properties"), n)));
                        }
                    }
                    for r in part.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                        required.push((r.to_string(), pp.clone()));
                    }
                    if let Some(ap) = part.get("additionalProperties").filter(|a| a.is_object()) {
                        additional = Some((ap.clone(), ptr(pp, "additionalProperties")));
                    }
                }
                let object_like = s.get("type").and_then(Value::as_str) == Some("object") || !declared.is_empty() || parts.len() > 1;
                if !object_like {
                    return;
                }
                for (k, x) in obj {
                    let child = ptr(ipath, k);
                    if let Some((_, ps, pp)) = declared.iter().find(|(n, _, _)| n == k) {
                        let (ps, pp) = (ps.clone(), pp.clone());
                        self.walk(&ps, &pp, x, &child, depth + 1, label, code, o, failed);
                    } else if let Some((ap, app)) = &additional {
                        let (ap, app) = (ap.clone(), app.clone());
                        self.walk(&ap, &app, x, &child, depth + 1, label, code, o, failed);
                    } else {
                        let key = FixKey::AddProperty { at: holder.clone(), name: k.clone() };
                        let e = self.fixes.entry(key.clone()).or_insert_with(|| (owner(), Shape::default(), BTreeSet::new()));
                        e.1.add(x);
                        e.2.insert(o.id.clone());
                        fix_link(self, &key, ipath);
                    }
                }
                for (name, rp) in required {
                    let write_only = declared
                        .iter()
                        .find(|(n, _, _)| *n == name)
                        .is_some_and(|(_, ps, _)| spec.deref(ps, "").0.get("writeOnly").and_then(Value::as_bool) == Some(true));
                    if write_only {
                        continue;
                    }
                    let e = self.required.entry((rp, name.clone())).or_default();
                    e.0 += 1;
                    if !obj.contains_key(&name) {
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
                    self.fixes.entry(key.clone()).or_insert_with(|| (owner(), Shape::default(), BTreeSet::new())).2.insert(o.id.clone());
                    fix_link(self, &key, ipath);
                }
            }
            Value::String(text) => {
                if let Some(values) = s.get("enum").and_then(Value::as_array)
                    && !values.contains(v)
                    && text.len() <= 64
                    && text.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                {
                    let key = FixKey::Enum { at: at.clone() };
                    let e = self.fixes.entry(key.clone()).or_insert_with(|| (owner(), Shape::default(), BTreeSet::new()));
                    e.1.add(v);
                    // The token itself is kept (see the module docs).
                    e.2.insert(format!("value:{text}"));
                    fix_link(self, &key, ipath);
                }
            }
            _ => {}
        }
    }

    fn finish(mut self, total: usize) -> DriftReport {
        for (label, code, place, skey) in std::mem::take(&mut self.pending_links) {
            let keys: Vec<String> = self.schema_places.get(&(label, code, place)).into_iter().flatten().cloned().collect();
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
                suggestions.insert(
                    key.to_string(),
                    Suggestion { id: short_id(key), title, detail, kind, recommended, pointer, line, ops, snippet },
                );
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
                        "{label} returned {code} {}; the description does not list it. The schema is inferred from the observed bodies (shape only).",
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
        for ((method, pattern), acc) in &self.endpoints {
            let key = format!("endpoint|{method}|{pattern}");
            let m = method.to_ascii_lowercase();
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
            let guessed_base =
                !acc.base.is_empty() && !self.router.servers.iter().any(|s| s.url.trim_end_matches('/').ends_with(&acc.base));
            let mut detail = format!("Seen {} time(s), e.g. {}.", acc.calls, acc.examples.join(", "));
            if guessed_base {
                detail.push_str(&format!(" The prefix {} is not a declared server path; it was left out.", acc.base));
            }
            add(
                &key,
                format!("Document {method} {path_key}"),
                detail,
                SuggestionKind::Addition,
                true,
                path_ptr.clone(),
                vec![PatchOp::add(ptr(&path_ptr, &m), Value::Object(operation))],
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
                    let mut widened = current.clone();
                    mark_nullable(&mut widened, d);
                    let ops = patch::diff(&current, &widened)
                        .into_iter()
                        .filter_map(|o| serde_json::from_value::<PatchOp>(json!({"op": o["op"], "path": format!("{at}{}", o["path"].as_str().unwrap_or("")), "value": o.get("value")})).ok())
                        .collect();
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
                    let t = match spec.root.pointer(at).and_then(|s| s.get("type")) {
                        Some(Value::Array(a)) => {
                            json!(a.iter().map(|x| if x == "integer" { json!("number") } else { x.clone() }).collect::<Vec<_>>())
                        }
                        _ => json!("number"),
                    };
                    add(
                        &skey,
                        format!("Allow fractional numbers at {}", display_pointer(at, owner)),
                        "Declared an integer; fractional numbers were returned.".into(),
                        SuggestionKind::Relaxation,
                        false,
                        at.clone(),
                        vec![PatchOp::replace(ptr(at, "type"), t)],
                    );
                }
                FixKey::Enum { at } => {
                    let values: Vec<String> = seen.iter().filter_map(|s| s.strip_prefix("value:")).map(str::to_string).collect();
                    enum_groups.entry(at.clone()).or_insert_with(|| (owner.clone(), vec![])).1.extend(values);
                }
            }
        }
        for (at, (owner, values)) in enum_groups {
            let mut list = spec.root.pointer(&ptr(&at, "enum")).and_then(Value::as_array).cloned().unwrap_or_default();
            for v in &values {
                if !list.contains(&json!(v)) {
                    list.push(json!(v));
                }
            }
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
                vec![PatchOp::replace(ptr(&at, "enum"), Value::Array(list))],
            );
        }
        // Required properties that were sometimes missing.
        let mut optional: BTreeMap<String, Vec<(String, usize, usize)>> = BTreeMap::new();
        for ((at, name), (seen, missing)) in &self.required {
            if *missing > 0 {
                optional.entry(at.clone()).or_default().push((name.clone(), *missing, *seen));
            }
        }
        for (at, names) in optional {
            let current: Vec<Value> = spec.root.pointer(&ptr(&at, "required")).and_then(Value::as_array).cloned().unwrap_or_default();
            let keep: Vec<Value> = current.into_iter().filter(|r| !names.iter().any(|(n, _, _)| r.as_str() == Some(n))).collect();
            let key = format!("optional|{at}");
            let owner = at.rsplit('/').next().unwrap_or("").to_string();
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
                vec![PatchOp::replace(ptr(&at, "required"), Value::Array(keep))],
            );
            // Link to the response schema findings naming these properties.
            let keys: Vec<String> = self
                .findings
                .iter()
                .filter(|(_, f)| {
                    f.kind == Some(DriftKind::ResponseSchemaMismatch)
                        && names.iter().any(|(n, _, _)| f.message.contains(&format!("required property `{n}`")))
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in keys {
                self.link(&k, &key);
            }
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
                            "Observed p95 {:.0} ms and slowest {:.0} ms against {max} ms. Raise it only if the budget, not the API, is wrong.",
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
            if let Some(max) = b.max_response_bytes
                && let Some(f) = self.findings.get_mut(&format!("size|{}", op.pointer))
            {
                f.message = format!(
                    "{label} returned more than its {max}-byte budget in {} call(s) (largest {} bytes)",
                    acc.large,
                    acc.max_bytes.unwrap_or(0)
                );
            }
            if let Some(max) = b.max_request_bytes
                && let Some(f) = self.findings.get_mut(&format!("reqsize|{}", op.pointer))
            {
                f.message = format!(
                    "{label} was sent more than its {max}-byte request budget in {} call(s) (largest {} bytes)",
                    acc.large_request,
                    acc.max_request.unwrap_or(0)
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
        let undeclared = self
            .endpoints
            .into_iter()
            .map(|((method, path), a)| UndeclaredEndpoint { method, path, calls: a.calls, statuses: a.statuses, examples: a.examples })
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

fn display_pointer(at: &str, owner: &str) -> String {
    let props: Vec<String> =
        at.split("/properties/").skip(1).map(|p| p.split('/').next().unwrap_or("").replace("~1", "/").replace("~0", "~")).collect();
    if props.is_empty() { owner.to_string() } else { format!("{owner}.{}", props.join(".")) }
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
        assert_eq!(nice_ceil(412.0), 500.0);
        assert_eq!(nice_ceil(180.0), 200.0);
        assert_eq!(nice_ceil(2100.0), 2500.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50.0), 2.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 95.0), 4.0);
    }
}
