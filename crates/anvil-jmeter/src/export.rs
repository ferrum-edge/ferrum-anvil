//! Export an Anvil HTTP load plan as an Apache JMeter test plan (`.jmx`).
//!
//! The export prepares every step exactly as a load run prepares it: the
//! request's own [`anvil_engine::prepare::prepare_http`] with the step's
//! variable layers, so the method, URL, query encoding, headers (the
//! inferred `Content-Type`, `User-Agent`, `Accept` and `Accept-Encoding`
//! included) and body bytes are Anvil's own. Values that change per
//! iteration (dataset cells, values extracted by an earlier chain step,
//! `anvil.iteration` / `anvil.vu`, dynamic helpers) and secrets are replaced
//! by unique alphanumeric markers before preparation (no encoder alters
//! them), then the markers in the prepared request become JMeter
//! expressions: `${anvil_ds_0}`, `${anvil_x_0}`, `${__UUID()}`,
//! `${__P(anvil.secret.…,)}`. A marker inside a query parameter or a
//! form-urlencoded body becomes `${__urlencode(…)}`, as Anvil encodes there.
//!
//! What JMeter cannot do as Anvil does is either **refused**
//! ([`ExportRefused`], every reason at once) or **listed** in
//! [`ExportReport::differences`]; nothing is dropped silently. In particular
//! JMeter's HTTP samplers accept any server certificate, so a request that
//! Anvil sends with certificate and host-name verification is refused
//! (LOAD-012): only a TLS profile that already turns verification off (the
//! same behaviour) is exported.
//!
//! Secrets never reach the `.jmx`: they are JMeter properties
//! (`${__P(anvil.secret.<name>,)}`), and a setUp thread group stops the test
//! before any traffic when one is not set. Their values are written only on
//! the explicit secret-export path ([`ExportOptions::include_secrets`]), to a
//! separate properties file for `jmeter -q`.

use crate::jmx::{self, Node, Prop, Text};
use anvil_domain::Id;
use anvil_domain::assertions::{AssertionKind, Comparison, ExtractionSource};
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::load::{ConnectionMode, LoadPlan, LoadUnitKind, Workload};
use anvil_domain::request::{Body, LintSendPolicy, Protocol};
use anvil_domain::secret::{SecretRef, SensitiveValue, TemplateKind, TemplateSyntax, classify_template_value};
use anvil_domain::settings::{HttpVersionPolicy, IpPreference, ResolverMode};
use anvil_domain::tls::TlsMinVersion;
use anvil_engine::ExecutionContext;
use anvil_engine::vars::{DEFERRED_SECRET_VALUE, Resolver, VarEntry, VarLayer};
use anvil_load::LoadJob;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use zeroize::Zeroizing;

/// The Apache JMeter release the exported plans target and the hosted
/// round trip runs (`.github/workflows/jmeter.yml`).
pub const JMETER_VERSION: &str = "5.6.3";

/// Prefix of the markers that stand in for per-iteration values and
/// secrets while a step is prepared. A plan whose text already contains it
/// is refused, so every marker found afterwards is one of ours.
const MARK: &str = "ANVILJMX";

/// Methods JMeter's HttpClient 4 sampler sends.
const METHODS: &[&str] = &[
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "OPTIONS",
    "TRACE",
    "DELETE",
    "PATCH",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "REPORT",
    "MKCALENDAR",
    "SEARCH",
];
/// Methods that may carry a request body in the exported sampler.
const BODY_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

/// JMeter variable holding the previous chain step's 3-digit status (or
/// `none` after a transport failure or timeout).
const RC_VAR: &str = "anvil_rc";
const PICK_VAR: &str = "anvil_pick";
const ITERATION_VAR: &str = "anvil_iteration";

#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Write the secrets the plan uses to a separate properties file
    /// ([`Export::secrets_properties`]). Off by default: the `.jmx` then
    /// names the properties and nothing holds their values.
    pub include_secrets: bool,
    /// File name the plan's CSV Data Set reads, relative to the `.jmx`.
    pub dataset_file: String,
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions { include_secrets: false, dataset_file: "dataset.csv".into() }
    }
}

/// What to export: the plan, its frozen execution contexts (exactly what a
/// load run prepares, [`anvil_load::LoadJob`]) and the requests' names.
pub struct ExportInput<'a> {
    pub plan: &'a LoadPlan,
    pub job: &'a LoadJob,
    pub request_names: &'a HashMap<Id, String>,
}

/// The exported plan.
pub struct Export {
    pub jmx: String,
    /// The dataset as the CSV the plan's CSV Data Set reads (header row,
    /// every cell quoted). Holds secret values only when the dataset has
    /// sensitive columns, which needs [`ExportOptions::include_secrets`].
    pub dataset_csv: Option<Vec<u8>>,
    /// `anvil.secret.*=value` lines for `jmeter -q`, only with
    /// [`ExportOptions::include_secrets`] and when the plan uses a secret.
    pub secrets_properties: Option<Zeroizing<String>>,
    pub report: ExportReport,
}

/// How the plan was translated, what differs and what JMeter needs.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExportReport {
    pub plan_id: Id,
    pub plan_name: String,
    pub jmeter_version: String,
    pub adapter_version: String,
    /// Anvil concept → JMeter element, for what this plan uses.
    pub mapping: Vec<Mapping>,
    /// Behaviour JMeter does not reproduce exactly (listed, never silent).
    pub differences: Vec<String>,
    /// JMeter properties the plan reads with `${__P(…)}`; each must be set
    /// (for example with `jmeter -q <secrets file>`) or the plan stops before
    /// any traffic.
    pub secret_properties: Vec<SecretProperty>,
    /// Non-secret JMeter properties to pass with `-J` so JMeter follows the
    /// plan's settings (e.g. XML JTL save settings that omit URLs and response
    /// bodies).
    pub jmeter_properties: Vec<(String, String)>,
    pub dataset: Option<DatasetReport>,
    pub thread_groups: usize,
    /// Samples a complete run records when that is fixed by the plan (an
    /// iteration workload of a chain whose steps all complete).
    pub expected_samples: Option<u64>,
    pub secrets_written: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Mapping {
    pub anvil: String,
    pub jmeter: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecretProperty {
    pub name: String,
    /// What it holds (never its value).
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DatasetReport {
    pub file: String,
    pub rows: usize,
    pub columns: Vec<String>,
    /// SHA-256 of the Anvil dataset's exact bytes (as in Anvil reports).
    pub source_sha256: String,
    /// SHA-256 of the CSV written for JMeter.
    pub csv_sha256: String,
    /// Columns whose values are secrets (the file is then secret material).
    pub sensitive_columns: Vec<String>,
}

/// One reason the plan cannot be exported faithfully.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Reason {
    /// The request (by name), when the reason is about one step.
    pub request: Option<String>,
    /// Stable code, e.g. `strict_tls`, `unsupported_protocol`, `auth`.
    pub code: &'static str,
    pub message: String,
}

/// The plan was not exported. Every reason found is listed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExportRefused {
    pub reasons: Vec<Reason>,
}

impl std::fmt::Display for ExportRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the load plan cannot be exported to JMeter: ")?;
        for (i, r) in self.reasons.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            match &r.request {
                Some(q) => write!(f, "request '{q}': {} ({})", r.message, r.code)?,
                None => write!(f, "{} ({})", r.message, r.code)?,
            }
        }
        Ok(())
    }
}

impl std::error::Error for ExportRefused {}

fn reason(request: Option<&str>, code: &'static str, message: impl Into<String>) -> Reason {
    Reason { request: request.map(str::to_string), code, message: message.into() }
}

// ---------------------------------------------------------------- markers

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Mark {
    /// A JMeter variable (dataset column, extracted value, iteration counter).
    Var(String),
    /// A JMeter variable carrying sensitive data (a sensitive dataset column
    /// or a sensitive extraction): renders like [`Mark::Var`], but triggers
    /// credential-forwarding protections such as the redirect check.
    SensitiveVar(String),
    /// A secret property (index into [`Secrets::props`]).
    Secret(usize),
    /// A JMeter function for a dynamic helper.
    Helper(String),
    /// `anvil.vu`: depends on the thread group.
    Vu,
    /// A dynamic helper JMeter cannot reproduce; refused where it is used.
    Unsupported(String),
}

#[derive(Default)]
struct Markers {
    list: Vec<Mark>,
    index: HashMap<Mark, usize>,
}

enum Part<'s> {
    Lit(&'s str),
    Mark(usize),
}

impl Markers {
    fn add(&mut self, m: Mark) -> String {
        let i = match self.index.get(&m) {
            Some(i) => *i,
            None => {
                self.list.push(m.clone());
                self.index.insert(m, self.list.len() - 1);
                self.list.len() - 1
            }
        };
        format!("{MARK}{i:06}X")
    }

    fn split<'s>(&self, s: &'s str) -> Vec<Part<'s>> {
        let mut out = Vec::new();
        let mut rest = s;
        let mut lit_start = 0usize;
        let base = s;
        while let Some(at) = rest.find(MARK) {
            let abs = base.len() - rest.len() + at;
            let tail = &base[abs + MARK.len()..];
            let digits = tail.get(..6).filter(|d| d.bytes().all(|b| b.is_ascii_digit()));
            match (digits, tail.as_bytes().get(6)) {
                (Some(d), Some(b'X')) if d.parse::<usize>().is_ok_and(|i| i < self.list.len()) => {
                    if abs > lit_start {
                        out.push(Part::Lit(&base[lit_start..abs]));
                    }
                    out.push(Part::Mark(d.parse().unwrap_or(0)));
                    lit_start = abs + MARK.len() + 7;
                    rest = &base[lit_start..];
                }
                _ => rest = &base[abs + MARK.len()..],
            }
        }
        if lit_start < base.len() {
            out.push(Part::Lit(&base[lit_start..]));
        }
        out
    }

    fn has_marks(&self, s: &str) -> bool {
        self.split(s).iter().any(|p| matches!(p, Part::Mark(_)))
    }
}

/// A value of the prepared request with the context its markers are in.
#[derive(Debug, Clone, Default)]
struct Tmpl(Vec<(String, bool)>);

impl Tmpl {
    fn raw(s: impl Into<String>) -> Self {
        Tmpl(vec![(s.into(), false)])
    }

    fn push(&mut self, s: impl Into<String>, encoded: bool) {
        self.0.push((s.into(), encoded));
    }
}

/// Where secret values come from (resolved only for used properties, and
/// only on the secret-export path).
enum SecretSource {
    /// A specific non-literal variable entry in a step's layers, resolved via
    /// that step's own layers and vault without re-looking up by variable name
    /// (so another step's or higher layer's override can never shadow it).
    VariableEntry { step: usize, layer: usize, var: usize },
    /// A whole field's template through the step's own resolver.
    Template { step: usize, template: String },
    /// A vault reference.
    Vault { step: usize, secret: SecretRef },
    /// A literal credential value or fragment that must never be copied into
    /// the JMX.
    Literal(String),
}

struct SecretProp {
    name: String,
    purpose: String,
    source: SecretSource,
}

#[derive(Default)]
struct Secrets {
    props: Vec<SecretProp>,
    by_key: HashMap<String, usize>,
}

fn slug(s: &str) -> String {
    let mut out: String =
        s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c.to_ascii_lowercase() } else { '_' }).take(48).collect();
    if out.is_empty() {
        out.push('x');
    }
    out
}

impl Secrets {
    /// The property for `key` (identity of the value), named after `base`.
    fn add(&mut self, key: String, base: String, purpose: String, source: SecretSource) -> usize {
        if let Some(i) = self.by_key.get(&key) {
            return *i;
        }
        let mut name = format!("anvil.secret.{base}");
        let mut n = 2;
        while self.props.iter().any(|p| p.name == name) {
            name = format!("anvil.secret.{base}.{n}");
            n += 1;
        }
        self.props.push(SecretProp { name, purpose, source });
        self.by_key.insert(key, self.props.len() - 1);
        self.props.len() - 1
    }
}

/// Replace every dynamic helper (`{{$…}}`) in `input` with a marker, tokenized
/// exactly as the resolver tokenizes it (`{{`, the first `}}`, the trimmed
/// expression starting with `$`). A helper JMeter cannot reproduce becomes
/// an [`Mark::Unsupported`] marker, refused only where it is actually used.
fn mask_helpers(input: &str, markers: &mut Markers) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            out.push_str(&rest[open..]);
            return out;
        };
        let expr = after[..close].trim();
        match expr.strip_prefix('$') {
            Some(helper) => {
                let mark = match helper_expr(helper) {
                    Ok(e) => Mark::Helper(e),
                    Err(why) => Mark::Unsupported(why),
                };
                out.push_str(&markers.add(mark));
            }
            None => out.push_str(&rest[open..open + 2 + close + 2]),
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    out
}

/// The JMeter function for an Anvil dynamic helper, or why there is none.
fn helper_expr(helper: &str) -> Result<String, String> {
    let mut parts = helper.split_whitespace();
    let name = parts.next().unwrap_or("");
    let args: Vec<&str> = parts.collect();
    Ok(match name {
        "uuid" | "randomUUID" | "guid" => "${__UUID()}".into(),
        "timestamp" => "${__time(/1000,)}".into(),
        "timestampMs" => "${__time(,)}".into(),
        "randomInt" => {
            let (lo, hi) = match args.as_slice() {
                [a, b] => (a.parse::<i64>().unwrap_or(0), b.parse::<i64>().unwrap_or(1000)),
                _ => (0, 1000),
            };
            if hi < lo {
                return Err(format!("the dynamic helper {{{{${helper}}}}} has an empty range, so Anvil refuses every send"));
            }
            format!("${{__Random({lo},{hi},)}}")
        }
        "isoTimestamp" => {
            return Err("{{$isoTimestamp}} is UTC in Anvil; JMeter's __time formats in the JVM's local time zone".into());
        }
        "counter" => return Err("{{$counter}} restarts for every Anvil send; JMeter has no per-send counter".into()),
        "randomFrom" => return Err("{{$randomFrom}} has no JMeter core function that picks from literal choices".into()),
        other => return Err(format!("the dynamic helper {{{{${other}}}}} is unknown to Anvil, which refuses every send")),
    })
}

/// Per-iteration values a step sees (see `anvil_load::executor::run_iteration`).
struct PerRun<'a> {
    dataset_columns: &'a [String],
    dataset_sensitive: &'a [String],
    with_dataset: bool,
    /// `(variable_name, sensitive)` for values extracted by earlier chain steps.
    extracted: Vec<(String, bool)>,
}

/// JMeter variable names for extracted values, by Anvil variable name.
#[derive(Default)]
struct Extracted {
    names: Vec<String>,
}

impl Extracted {
    fn var(&mut self, name: &str) -> String {
        let i = match self.names.iter().position(|n| n == name) {
            Some(i) => i,
            None => {
                self.names.push(name.to_string());
                self.names.len() - 1
            }
        };
        format!("anvil_x_{i}")
    }
}

struct Translator<'a> {
    input: &'a ExportInput<'a>,
    opts: &'a ExportOptions,
    markers: Markers,
    secrets: Secrets,
    extracted: Extracted,
    reasons: Vec<Reason>,
    differences: Vec<String>,
    mapping: Vec<Mapping>,
    jmeter_properties: Vec<(String, String)>,
    contexts: Vec<&'a ExecutionContext>,
}

impl Translator<'_> {
    fn note(&mut self, s: impl Into<String>) {
        let s = s.into();
        if !self.differences.contains(&s) {
            self.differences.push(s);
        }
    }

    fn map(&mut self, anvil: &str, jmeter: &str) {
        if !self.mapping.iter().any(|m| m.anvil == anvil) {
            self.mapping.push(Mapping { anvil: anvil.into(), jmeter: jmeter.into() });
        }
    }
}

/// A step ready to become a sampler.
struct StepSpec {
    label: String,
    method: String,
    protocol: String,
    host: String,
    port: u16,
    path: Tmpl,
    body: Option<Tmpl>,
    headers: Vec<(String, Tmpl)>,
    basic: Option<(String, Tmpl, Tmpl)>,
    follow_redirects: bool,
    keepalive: bool,
    connect_timeout: Option<u64>,
    response_timeout: Option<u64>,
    children: Vec<Node>,
}

/// Export the plan, or refuse it with every reason found.
pub fn export(input: &ExportInput<'_>, opts: &ExportOptions) -> Result<Export, ExportRefused> {
    let plan = input.plan;
    let refuse_now = |r: Reason| ExportRefused { reasons: vec![r] };
    anvil_load::validate_plan(plan).map_err(|e| refuse_now(reason(None, "invalid_plan", e.to_string())))?;
    let mix: Vec<(Id, u32)> = plan.mix.iter().filter(|m| m.weight > 0).map(|m| (m.request_id, m.weight)).collect();
    let steps: Vec<Id> = if plan.mix.is_empty() { plan.chain.clone() } else { mix.iter().map(|(id, _)| *id).collect() };
    let mut contexts: Vec<&ExecutionContext> = Vec::new();
    for id in &steps {
        let ctx = input
            .job
            .requests
            .get(id)
            .ok_or_else(|| refuse_now(reason(None, "invalid_plan", format!("request {id} of the plan is missing"))))?;
        contexts.push(ctx);
    }
    // The same unit check as a load run: a plan a run refuses is not exported.
    let mut unique: Vec<(Id, &ExecutionContext)> = Vec::new();
    for (id, ctx) in steps.iter().zip(&contexts) {
        if !unique.iter().any(|(seen, _)| seen == id) {
            unique.push((*id, *ctx));
        }
    }
    match anvil_load::protocol::classify_plan(unique.iter().map(|(id, ctx)| (*id, *ctx)), plan.connection_mode) {
        Err(r) => return Err(refuse_now(reason(name_of(input, r.request_id.as_ref()).as_deref(), "load_refusal", r.message))),
        Ok((LoadUnitKind::HttpRequest, _)) => {}
        Ok((unit, _)) => {
            let label = anvil_load::protocol::label(unit);
            return Err(refuse_now(reason(
                None,
                "unsupported_protocol",
                format!(
                    "the plan's load unit is {label}; the JMeter adapter exports HTTP requests only, and JMeter's core samplers have no equivalent of this unit"
                ),
            )));
        }
    }
    // Default JMeter save settings write XML JTL without the request URL,
    // response message, or assertion results/failure messages, so resolved URL
    // credentials (path secrets or query API keys), missing-Location redirect
    // request lines, and echoed response bodies are never written to the result
    // file while `<httpSample>` still identifies every sample as an HTTP request.
    let mut t = Translator {
        input,
        opts,
        markers: Markers::default(),
        secrets: Secrets::default(),
        extracted: Extracted::default(),
        reasons: Vec::new(),
        differences: Vec::new(),
        mapping: Vec::new(),
        jmeter_properties: vec![
            ("jmeter.save.saveservice.output_format".into(), "xml".into()),
            ("jmeter.save.saveservice.url".into(), "false".into()),
            ("jmeter.save.saveservice.response_message".into(), "false".into()),
            ("jmeter.save.saveservice.assertions".into(), "false".into()),
            ("jmeter.save.saveservice.assertion_results".into(), "none".into()),
            ("jmeter.save.saveservice.assertion_results_failure_message".into(), "false".into()),
            ("jmeter.save.saveservice.response_data".into(), "false".into()),
            ("jmeter.save.saveservice.response_data.on_error".into(), "false".into()),
            ("jmeter.save.saveservice.samplerData".into(), "false".into()),
            ("jmeter.save.saveservice.requestHeaders".into(), "false".into()),
            ("jmeter.save.saveservice.responseHeaders".into(), "false".into()),
        ],
        contexts: contexts.clone(),
    };
    // Markers must be ours alone.
    for (id, ctx) in steps.iter().zip(&contexts) {
        let mut texts = serde_json::to_string(&ctx.spec).unwrap_or_default();
        for (_, a) in &ctx.auth_layers {
            texts.push_str(&serde_json::to_string(a).unwrap_or_default());
        }
        for l in &ctx.var_layers {
            for v in &l.vars {
                texts.push_str(&v.name);
                texts.push_str(&v.value);
            }
        }
        if texts.to_ascii_uppercase().contains(MARK) {
            let n = name_of(input, Some(id));
            t.reasons.push(reason(
                n.as_deref(),
                "reserved_text",
                format!("the request contains the text '{MARK}', which the export reserves"),
            ));
        }
    }
    plan_checks(&mut t, &contexts);

    let dataset = input.job.dataset.as_ref();
    let chain = plan.mix.is_empty();
    let mut specs = Vec::new();
    for (pos, (id, ctx)) in steps.iter().zip(&contexts).enumerate() {
        let name = name_of(input, Some(id)).unwrap_or_else(|| id.to_string());
        // Values extracted at earlier chain positions of the same scope,
        // preserving sensitivity metadata for redirect checks.
        let mut extracted: Vec<(String, bool)> = Vec::new();
        if chain {
            for earlier in &contexts[..pos] {
                if earlier.scope == ctx.scope {
                    for e in &earlier.spec.extractions {
                        if let Some(existing) = extracted.iter_mut().find(|(n, _)| n == &e.variable) {
                            existing.1 = e.sensitive;
                        } else {
                            extracted.push((e.variable.clone(), e.sensitive));
                        }
                    }
                }
            }
        }
        let per_run = PerRun {
            dataset_columns: dataset.map(|d| d.columns.as_slice()).unwrap_or(&[]),
            dataset_sensitive: dataset.map(|d| d.sensitive_columns.as_slice()).unwrap_or(&[]),
            with_dataset: dataset.is_some() && ctx.scope.is_none(),
            extracted,
        };
        let label = if chain { format!("{}. {}", pos + 1, safe_name(&name)) } else { safe_name(&name) };
        match translate_step(&mut t, pos, ctx, &name, label, &per_run) {
            Ok(spec) => specs.push(spec),
            Err(mut rs) => t.reasons.append(&mut rs),
        }
    }
    let cookies: Vec<bool> = contexts.iter().map(|c| anvil_engine::settings::resolve(&c.settings_layers).cookies).collect();
    let use_cookies = cookies.first().copied().unwrap_or(true);
    if cookies.iter().any(|c| *c != use_cookies) {
        t.reasons.push(reason(
            None,
            "cookies",
            "the plan's requests differ in cookie handling; JMeter's cookie manager applies to every request of a thread",
        ));
    }
    let total_weight: u64 = mix.iter().map(|(_, w)| *w as u64).sum();
    if !chain && total_weight > i32::MAX as u64 {
        t.reasons.push(reason(
            None,
            "mix_weight_range",
            format!(
                "the weighted mix's total weight ({total_weight}) exceeds JMeter's Random Variable maximum ({}); scale the weights down to export it",
                i32::MAX
            ),
        ));
    }
    let groups = thread_groups(&mut t);
    if !t.reasons.is_empty() {
        return Err(ExportRefused { reasons: t.reasons });
    }
    if use_cookies {
        t.map("cookie jar per virtual user", "HTTP Cookie Manager per thread (kept across iterations)");
    }

    // ---- dataset ----
    // Build the CSV Data Set Config up front and attach it inside each load
    // thread group (with `shareMode.all` and the shared filename) rather than
    // at TestPlan scope so the `SetupThreadGroup` secrets check never advances
    // the CSV cursor past row 0 before load traffic starts.
    let mut dataset_report = None;
    let mut dataset_csv = None;
    let mut dataset_node = None;
    if let Some(d) = dataset {
        let csv = dataset_to_csv(d);
        let vars: Vec<String> = (0..d.columns.len()).map(|i| format!("anvil_ds_{i}")).collect();
        // JMeter's CSVDataSet calls `.trim()` on `filename`; prefix relative
        // paths with `./` so a filename with leading whitespace still resolves
        // to the exact sidecar Anvil wrote beside the JMX.
        let jmx_dataset_file = if opts.dataset_file.starts_with("./")
            || opts.dataset_file.starts_with("../")
            || std::path::Path::new(&opts.dataset_file).is_absolute()
        {
            opts.dataset_file.clone()
        } else {
            format!("./{}", opts.dataset_file)
        };
        dataset_node = Some(Node::new(
            "CSVDataSet",
            "TestBeanGUI",
            "Anvil dataset",
            vec![
                Prop::s("delimiter", ","),
                Prop::s("fileEncoding", "UTF-8"),
                Prop::t("filename", &Text::lit(jmx_dataset_file)),
                Prop::Bool("ignoreFirstLine", true),
                Prop::Bool("quotedData", true),
                Prop::Bool("recycle", true),
                Prop::s("shareMode", "shareMode.all"),
                Prop::Bool("stopThread", false),
                Prop::s("variableNames", vars.join(",")),
            ],
        ));
        dataset_report = Some(DatasetReport {
            file: opts.dataset_file.clone(),
            rows: d.rows.len(),
            columns: d.columns.clone(),
            source_sha256: d.sha256.clone(),
            csv_sha256: hex::encode(Sha256::digest(&csv)),
            sensitive_columns: d.sensitive_columns.clone(),
        });
        dataset_csv = Some(csv);
        t.map(
            "dataset (row = iteration mod rows)",
            "CSV Data Set Config shared by all load thread groups, recycled at the end of the file",
        );
        t.note("Dataset rows: Anvil gives iteration k the row k mod rows; JMeter's CSV Data Set hands the next row to whichever thread asks, so the same rows are used in the same proportions but not by the same iteration numbers.");
        if !d.sensitive_columns.is_empty() {
            t.note("The dataset has sensitive columns. Their values are in the dataset file (secret export only), and JMeter does not redact them in its log or result files.");
        }
    }

    // Render every thread group, recording which markers are used.
    let used: RefCell<BTreeSet<usize>> = RefCell::new(BTreeSet::new());
    let mut group_nodes = Vec::new();
    for (gi, g) in groups.iter().enumerate() {
        let r = Render { markers: &t.markers, secrets: &t.secrets, vu_offset: g.vu_offset, used: &used };
        let body = iteration_body(chain, &specs, &mix, total_weight, &r);
        group_nodes.push(thread_group_node(gi, g, body, use_cookies, dataset_node.clone()));
    }
    let used = used.into_inner();
    let used_marks: Vec<&Mark> = used.iter().map(|i| &t.markers.list[*i]).collect();
    let mut used_secrets: Vec<usize> = used_marks.iter().filter_map(|m| if let Mark::Secret(s) = m { Some(*s) } else { None }).collect();
    used_secrets.sort_unstable();
    used_secrets.dedup();
    let uses_iteration = used_marks.iter().any(|m| matches!(m, Mark::Var(v) if v == ITERATION_VAR));
    let needs_iteration_gate = groups.iter().any(|g| matches!(g.kind, GroupKind::Iterations { gate: Some(_), .. }));
    let uses_vu = used_marks.iter().any(|m| matches!(m, Mark::Vu));

    // Recursively validate every used secret property (both variable entries
    // and whole-field templates, expanding through nested non-literal secret
    // variables too) so no static JMeter property can silently freeze a
    // per-iteration value or dynamic helper.
    let mut secret_reasons = Vec::new();
    for i in &used_secrets {
        let p = &t.secrets.props[*i];
        match &p.source {
            SecretSource::VariableEntry { step, layer, var } => {
                let ctx = t.contexts[*step];
                let entry = &ctx.var_layers[*layer].vars[*var];
                if ctx.secrets.variable_secret(*layer, *var).is_none() && !entry.literal && entry.value.contains("{{") {
                    if let Err(r) =
                        validate_static_secret_template(&t, *step, &entry.value, &p.purpose, entry.secret, dataset, chain, false)
                    {
                        secret_reasons.push(r);
                    }
                }
            }
            SecretSource::Template { step, template } if template.contains("{{") => {
                if let Err(r) = validate_static_secret_template(&t, *step, template, &p.purpose, true, dataset, chain, false) {
                    secret_reasons.push(r);
                }
            }
            _ => {}
        }
    }
    if !secret_reasons.is_empty() {
        return Err(ExportRefused { reasons: secret_reasons });
    }

    let mut plan_children = Vec::new();
    let secret_properties: Vec<SecretProperty> = used_secrets
        .iter()
        .map(|i| SecretProperty { name: t.secrets.props[*i].name.clone(), purpose: t.secrets.props[*i].purpose.clone() })
        .collect();
    let has_secrets_guard = !secret_properties.is_empty();
    let single_group = group_nodes.len() == 1;
    if uses_iteration || needs_iteration_gate {
        // Scope CounterConfig inside the sole load thread group when there is
        // only one so the SetupThreadGroup secrets check never advances
        // `anvil.iteration` before iteration 0. For multi-stage closed
        // workloads that share one TestPlan-scoped counter across groups,
        // start at -1 when SetupThreadGroup is present so the setup iteration
        // consumes -1 and load traffic starts at 0. Fixed-count workloads with
        // an uneven thread/loop gate also use this single CounterConfig so the
        // gate and `{{anvil.iteration}}` can never diverge across threads.
        let start = if !single_group && has_secrets_guard { "-1" } else { "0" };
        let counter = Node::new(
            "CounterConfig",
            "CounterConfigGui",
            "anvil.iteration",
            vec![
                Prop::s("CounterConfig.start", start),
                Prop::s("CounterConfig.end", ""),
                Prop::s("CounterConfig.incr", "1"),
                Prop::s("CounterConfig.name", ITERATION_VAR),
                Prop::s("CounterConfig.format", ""),
                Prop::Bool("CounterConfig.per_user", false),
                Prop::Bool("CounterConfig.reset_on_tg_iteration", false),
            ],
        );
        if single_group {
            group_nodes[0].children.insert(0, counter);
        } else {
            plan_children.push(counter);
        }
        if uses_iteration {
            t.map("{{anvil.iteration}}", "Counter shared by all threads (from 0, one per iteration)");
        }
    }
    if uses_vu {
        t.map("{{anvil.vu}}", "${__intSum(${__threadNum},offset)}: the thread number from 0 across the thread groups");
        if matches!(plan.workload, Workload::OpenArrivalRate { .. }) {
            t.note("{{anvil.vu}} in an open workload is Anvil's in-flight slot (reused); in JMeter's open model every arrival is a new thread, so the value grows with every arrival.");
        }
    }
    if !chain {
        // Scope RandomVariableConfig inside each load thread group so the
        // SetupThreadGroup secrets check never draws from the mix RNG.
        for (gi, group_node) in group_nodes.iter_mut().enumerate() {
            group_node.children.insert(
                0,
                Node::new(
                    "RandomVariableConfig",
                    "TestBeanGUI",
                    "Anvil weighted mix",
                    vec![
                        Prop::s("variableName", PICK_VAR),
                        Prop::s("outputFormat", ""),
                        Prop::s("minimumValue", "1"),
                        Prop::s("maximumValue", total_weight.to_string()),
                        Prop::s("randomSeed", (plan.seed.wrapping_add(gi as u64) as i64).to_string()),
                        Prop::Bool("perThread", false),
                    ],
                ),
            );
        }
        t.map("weighted mix", "Random Variable (1 to the total weight, per iteration) and one If Controller per request");
        t.note("Weighted mix: Anvil picks each iteration's request with a seeded function of the iteration number; JMeter draws a random number per iteration. The proportions match the weights in expectation, not iteration by iteration.");
    } else if specs.len() > 1 {
        t.map(
            "sequential chain (stops at a transport failure or timeout)",
            "samplers in order; each later one inside an If Controller that runs only after the previous sample got an HTTP status",
        );
    }
    if has_secrets_guard {
        plan_children.push(secrets_guard(&secret_properties));
        t.map(
            "secrets (vault values, secret variables, credential fields)",
            "JMeter properties ${__P(anvil.secret.…,)}; a setUp thread group stops the test before any traffic when one is not set",
        );
    }
    plan_children.extend(group_nodes);

    // Secret values: only on the explicit path, only for used properties.
    let mut secrets_properties = None;
    if opts.include_secrets && !used_secrets.is_empty() {
        let mut out = Zeroizing::new(String::from(
            "# Secrets of an Anvil load plan exported to JMeter. Pass with `jmeter -q <this file>`; keep it private and delete it after the run.\n",
        ));
        let mut errors = Vec::new();
        for i in &used_secrets {
            let p = &t.secrets.props[*i];
            match resolve_secret(&t, &p.source, &p.purpose, dataset, chain) {
                Ok(v) => {
                    out.push_str(&p.name);
                    out.push('=');
                    out.push_str(&jmx::properties_value(&v));
                    out.push('\n');
                }
                Err(r) => errors.push(r),
            }
        }
        if !errors.is_empty() {
            return Err(ExportRefused { reasons: errors });
        }
        secrets_properties = Some(out);
    }

    let test_plan = Node::new(
        "TestPlan",
        "TestPlanGui",
        format!("Anvil: {}", safe_name(&plan.name)),
        vec![
            Prop::t("TestPlan.comments", &Text::lit(format!("Exported by Ferrum Anvil from load plan {} ({}).", plan.id, plan.name))),
            Prop::Bool("TestPlan.functional_mode", false),
            Prop::Bool("TestPlan.tearDown_on_shutdown", true),
            Prop::Bool("TestPlan.serialize_threadgroups", false),
            Prop::Element {
                name: "TestPlan.user_defined_variables".into(),
                element_type: "Arguments",
                attrs: vec![
                    ("guiclass", "ArgumentsPanel".into()),
                    ("testclass", "Arguments".into()),
                    ("testname", "User Defined Variables".into()),
                ],
                props: vec![Prop::Collection("Arguments.arguments", vec![])],
            },
        ],
    )
    .with_children(plan_children);
    if let Err(c) = jmx::check_tree(&test_plan) {
        return Err(refuse_now(reason(
            None,
            "xml_character",
            format!("the plan contains the character U+{:04X}, which an XML 1.0 test plan cannot carry", c as u32),
        )));
    }
    let comment = format!(
        "Exported by Ferrum Anvil {} (JMeter adapter, Apache JMeter {JMETER_VERSION}) from load plan {}. Secrets are JMeter properties (anvil.secret.*), never values in this file.",
        env!("CARGO_PKG_VERSION"),
        plan.id
    );
    let jmx = jmx::document(&test_plan, JMETER_VERSION, &comment);
    let expected_samples = match &plan.workload {
        Workload::Iterations { iterations, .. } if chain => iterations.checked_mul(plan.chain.len() as u64),
        Workload::Iterations { iterations, .. } => Some(*iterations),
        _ => None,
    };
    let secrets_written = secrets_properties.is_some();
    Ok(Export {
        jmx,
        dataset_csv,
        secrets_properties,
        report: ExportReport {
            plan_id: plan.id,
            plan_name: plan.name.clone(),
            jmeter_version: JMETER_VERSION.into(),
            adapter_version: crate::adapter_version(),
            mapping: t.mapping,
            differences: t.differences,
            secret_properties,
            jmeter_properties: t.jmeter_properties,
            dataset: dataset_report,
            thread_groups: groups.len(),
            expected_samples,
            secrets_written,
        },
    })
}

fn name_of(input: &ExportInput<'_>, id: Option<&Id>) -> Option<String> {
    id.and_then(|i| input.request_names.get(i).cloned())
}

/// A name as an element name: JMeter evaluates `${…}` in element names.
fn safe_name(s: &str) -> String {
    s.replace("${", "$ {")
}

/// Plan-level checks: abort rule, scopes, dataset, warmup.
fn plan_checks(t: &mut Translator<'_>, contexts: &[&ExecutionContext]) {
    let plan = t.input.plan;
    if plan.abort.is_some() {
        t.reasons.push(reason(
            None,
            "abort_rule",
            "the plan has an abort rule (stop when the failure ratio over a window exceeds a limit); JMeter's core elements cannot express it, and dropping it would remove the protection it gives the target. Remove the abort rule from the plan (or a copy of it) to export",
        ));
    }
    let scope = contexts.first().and_then(|c| c.scope);
    if contexts.iter().any(|c| c.scope != scope) {
        t.reasons.push(reason(
            None,
            "scope",
            "the plan mixes requests of an unopened import root with others; their variable scopes cannot be expressed in JMeter, where every variable is visible to every sampler",
        ));
    }
    if let Some(d) = &t.input.job.dataset {
        if scope.is_some() {
            t.reasons.push(reason(
                None,
                "scope",
                "requests of an unopened import root get no dataset row in Anvil; JMeter would give them one",
            ));
        }
        if let Some((r, c)) = d.rows.iter().enumerate().find_map(|(r, row)| row.iter().position(Option::is_none).map(|c| (r, c))) {
            t.reasons.push(reason(
                None,
                "dataset",
                format!(
                    "dataset row {} has no value for column '{}': Anvil then falls back to the variable's other definitions, JMeter's CSV Data Set would send an empty value",
                    r + 1,
                    d.columns[c]
                ),
            ));
        }
        if d.rows.iter().flatten().flatten().any(|v| v.contains(['\r', '\n'])) {
            t.reasons.push(reason(
                None,
                "dataset",
                "a dataset cell contains a line break, which JMeter's CSV Data Set does not read back as one value",
            ));
        }
        if !d.sensitive_columns.is_empty() && !t.opts.include_secrets {
            t.reasons.push(reason(
                None,
                "dataset_secret",
                format!(
                    "the dataset's columns {} are sensitive; their values would have to be written to the dataset file. Export with secrets (the explicit secret-export path) to write them",
                    d.sensitive_columns.join(", ")
                ),
            ));
        }
    }
    if plan.warmup_secs > 0 {
        t.note(format!(
            "Warmup: JMeter records the first {} s like the rest; importing the result file with this plan excludes them again.",
            plan.warmup_secs
        ));
    }
}

/// The resolver a step's fields are prepared with: the step's own layers
/// (secrets and credential variables replaced by markers, dynamic helpers
/// masked), then the per-iteration layers as a load worker adds them.
fn step_layers(t: &mut Translator<'_>, pos: usize, ctx: &ExecutionContext, per_run: &PerRun<'_>) -> Vec<VarLayer> {
    let mut layers = Vec::new();
    for (li, layer) in ctx.var_layers.iter().enumerate() {
        let mut vars = Vec::new();
        for (vi, e) in layer.vars.iter().enumerate() {
            let vault = ctx.secrets.variable_secret(li, vi);
            let credential = anvil_domain::credential_names::is_export_secret_name(&e.name, &ctx.redaction_names)
                && classify_template_value(&e.value, TemplateSyntax::Nunjucks) == TemplateKind::Literal;
            if e.secret || vault.is_some() || e.value == DEFERRED_SECRET_VALUE || credential {
                let key = match &vault {
                    Some(r) if e.literal => format!("vault:{}", r.id),
                    None if e.value != DEFERRED_SECRET_VALUE && (e.literal || !e.value.contains("{{")) => {
                        format!("var:{}:{}:{}", layer.label, e.name, hex::encode(Sha256::digest(e.value.as_bytes())))
                    }
                    _ => format!("var-entry:{pos}:{li}:{vi}"),
                };
                let idx = t.secrets.add(
                    key,
                    format!("var.{}", slug(&e.name)),
                    format!("variable '{}' ({})", e.name, layer.label),
                    SecretSource::VariableEntry { step: pos, layer: li, var: vi },
                );
                vars.push(VarEntry { name: e.name.clone(), value: t.markers.add(Mark::Secret(idx)), secret: false, literal: true });
            } else if e.literal {
                vars.push(e.clone());
            } else {
                vars.push(VarEntry { name: e.name.clone(), value: mask_helpers(&e.value, &mut t.markers), secret: false, literal: false });
            }
        }
        layers.push(VarLayer { label: layer.label.clone(), vars });
    }
    let stand_in = |name: &str, value: String| VarEntry { name: name.into(), value, secret: false, literal: true };
    let iteration = t.markers.add(Mark::Var(ITERATION_VAR.into()));
    let vu = t.markers.add(Mark::Vu);
    layers.push(VarLayer { label: "load".into(), vars: vec![stand_in("anvil.iteration", iteration), stand_in("anvil.vu", vu)] });
    if per_run.with_dataset {
        let vars = per_run
            .dataset_columns
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let var_name = format!("anvil_ds_{i}");
                let mark =
                    if per_run.dataset_sensitive.iter().any(|s| s == c) { Mark::SensitiveVar(var_name) } else { Mark::Var(var_name) };
                stand_in(c, t.markers.add(mark))
            })
            .collect();
        layers.push(VarLayer { label: "dataset".into(), vars });
    }
    if !per_run.extracted.is_empty() {
        let mut vars = Vec::new();
        for (name, sensitive) in &per_run.extracted {
            let var = t.extracted.var(name);
            let mark = if *sensitive { Mark::SensitiveVar(var) } else { Mark::Var(var) };
            vars.push(stand_in(name, t.markers.add(mark)));
        }
        layers.push(VarLayer { label: "iteration (extracted)".into(), vars });
    }
    layers
}

/// Recognized HTTP authentication schemes permitted as a delimited prefix in
/// an `Authorization` header (e.g. `Bearer {{token}}`).
fn is_recognized_auth_scheme(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "bearer"
            | "basic"
            | "digest"
            | "token"
            | "apikey"
            | "api-key"
            | "oauth"
            | "dpop"
            | "hoba"
            | "mutual"
            | "negotiate"
            | "scram-sha-256"
    )
}

/// Whether a resolved credential value needs a whole-value property: it holds
/// any non-whitespace literal material (except a recognized, space-delimited
/// HTTP auth scheme prefix when `allow_auth_scheme` is true, i.e. an
/// `Authorization` header). `Err` when that literal material is mixed with a
/// per-iteration value, which no constant property can hold.
fn needs_property(markers: &Markers, resolved: &str, allow_auth_scheme: bool) -> Result<bool, ()> {
    let parts = markers.split(resolved);
    let mut has_mark = false;
    let mut per_run = false;
    let mut non_ws_lit_count = 0usize;
    for p in &parts {
        match p {
            Part::Lit(l) => {
                if !l.trim().is_empty() {
                    non_ws_lit_count += 1;
                }
            }
            Part::Mark(i) => {
                has_mark = true;
                per_run |= !matches!(markers.list[*i], Mark::Secret(_));
            }
        }
    }
    if non_ws_lit_count == 0 {
        return Ok(false);
    }
    if allow_auth_scheme
        && has_mark
        && non_ws_lit_count == 1
        && let [Part::Lit(prefix), Part::Mark(_), rest @ ..] = parts.as_slice()
        && rest.iter().all(|p| match p {
            Part::Lit(l) => l.trim().is_empty(),
            Part::Mark(_) => true,
        })
    {
        let trimmed_start = prefix.trim_start();
        if let Some(scheme) = trimmed_start.strip_suffix(|c: char| c == ' ' || c == '\t') {
            let scheme = scheme.trim_end();
            if !scheme.is_empty() && !scheme.chars().any(char::is_whitespace) && is_recognized_auth_scheme(scheme) {
                return Ok(false);
            }
        }
    }
    if per_run { Err(()) } else { Ok(true) }
}

/// The marker text for a credential (a sensitive auth field).
#[allow(clippy::too_many_arguments)]
fn sensitive_value(
    t: &mut Translator<'_>,
    pos: usize,
    ctx: &ExecutionContext,
    resolver: &Resolver,
    request: &str,
    value: &SensitiveValue,
    field: &str,
    base: String,
) -> Result<String, Reason> {
    match value {
        SensitiveValue::Secret { secret } => {
            let idx = t.secrets.add(
                format!("vault:{}", secret.id),
                base,
                format!("{field} of request '{request}' (vault secret '{}')", secret.label),
                SecretSource::Vault { step: pos, secret: secret.clone() },
            );
            Ok(t.markers.add(Mark::Secret(idx)))
        }
        SensitiveValue::Template { value } => {
            let masked = mask_helpers(value, &mut t.markers);
            let out = resolver.resolve(&masked, field).map_err(|f| reason(Some(request), "does_not_prepare", f.message))?;
            match needs_property(&t.markers, &out, false) {
                Ok(false) => Ok(out),
                Ok(true) => {
                    let key = format!("field:{}:{field}", ctx.request_id.map(|i| i.to_string()).unwrap_or_else(|| pos.to_string()));
                    let idx = t.secrets.add(
                        key,
                        base,
                        format!("{field} of request '{request}'"),
                        SecretSource::Template { step: pos, template: value.clone() },
                    );
                    Ok(t.markers.add(Mark::Secret(idx)))
                }
                Err(()) => Err(reason(
                    Some(request),
                    "secret_mixed",
                    format!("{field} mixes literal credential text with a per-iteration value; JMeter cannot keep the literal part secret"),
                )),
            }
        }
    }
}

/// A credential-named or sensitive header, query or form field whose value
/// holds literal material becomes a whole-value property: the replacement
/// value (a marker), or `None` to keep the field as it is.
#[allow(clippy::too_many_arguments)]
fn credential_field(
    t: &mut Translator<'_>,
    pos: usize,
    ctx: &ExecutionContext,
    resolver: &Resolver,
    request: &str,
    kind: &str,
    index: usize,
    name: &str,
    masked_value: &str,
    original_value: &str,
    sensitive: bool,
) -> Result<Option<String>, Reason> {
    let Ok(resolved_name) = resolver.resolve(name.trim(), kind) else { return Ok(None) };
    if !(sensitive || anvil_domain::credential_names::is_export_secret_name(&resolved_name, &ctx.redaction_names)) {
        return Ok(None);
    }
    let Ok(out) = resolver.resolve(masked_value, kind) else { return Ok(None) };
    let allow_auth_scheme = kind == "header" && resolved_name.eq_ignore_ascii_case("authorization");
    match needs_property(&t.markers, &out, allow_auth_scheme) {
        Ok(false) => Ok(None),
        Ok(true) => {
            // The field's position too: two fields of one name hold two values.
            let key = format!(
                "field:{}:{kind}:{index}:{resolved_name}",
                ctx.request_id.map(|i| i.to_string()).unwrap_or_else(|| pos.to_string())
            );
            let idx = t.secrets.add(
                key,
                format!("{kind}.{}.{}", slug(request), slug(&resolved_name)),
                format!("{kind} '{resolved_name}' of request '{request}'"),
                SecretSource::Template { step: pos, template: original_value.to_string() },
            );
            Ok(Some(t.markers.add(Mark::Secret(idx))))
        }
        Err(()) => Err(reason(
            Some(request),
            "secret_mixed",
            format!(
                "the {kind} '{resolved_name}' mixes literal credential text with a per-iteration value; JMeter cannot keep the literal part secret"
            ),
        )),
    }
}

/// Translate one step, or every reason it cannot be.
fn translate_step(
    t: &mut Translator<'_>,
    pos: usize,
    ctx: &ExecutionContext,
    name: &str,
    label: String,
    per_run: &PerRun<'_>,
) -> Result<StepSpec, Vec<Reason>> {
    let rq = Some(name);
    let mut rs: Vec<Reason> = Vec::new();
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    match settings.http_version {
        HttpVersionPolicy::Auto | HttpVersionPolicy::Http1Only => {}
        other => rs.push(reason(
            rq,
            "http_version",
            format!("the request's HTTP version policy is {other:?}; JMeter's HttpClient 4 sampler speaks HTTP/1.1 only"),
        )),
    }
    if settings.proxy_profile_id.is_some() {
        rs.push(reason(rq, "proxy", "the request goes through a proxy profile; its routing (NO_PROXY, HTTPS, SOCKS5, HBONE proxies, proxy TLS) has no faithful per-sampler JMeter equivalent"));
    }
    if !settings.dns_overrides.is_empty()
        || !matches!(settings.resolver, ResolverMode::System)
        || settings.ip_preference != IpPreference::System
    {
        rs.push(reason(rq, "dns", "the request uses DNS overrides, a custom resolver or an IP-family preference, which JMeter's HTTP sampler does not apply per request"));
    }
    if settings.retries.max_retries > 0 {
        rs.push(reason(rq, "retries", "the request retries automatically; JMeter's retry setting is a global HttpClient property without Anvil's never-replay-a-possibly-processed-request rule"));
    }
    if ctx.spec.proxy_protocol.is_some() {
        rs.push(reason(rq, "proxy_protocol", "the request writes a PROXY protocol header, which JMeter cannot send"));
    }
    match &ctx.spec.body {
        Body::None | Body::Raw { .. } | Body::Json { .. } | Body::Xml { .. } | Body::FormUrlEncoded { .. } => {}
        Body::GraphQl { .. } | Body::Soap { .. } => rs.push(reason(
            rq,
            "body",
            "Anvil judges a GraphQL or SOAP request's outcome from the response body (GraphQL errors, SOAP faults); JMeter's HTTP sampler judges by the status code, so the two would count different successes",
        )),
        Body::Multipart { .. } | Body::Binary { .. } => rs.push(reason(
            rq,
            "body",
            "the body uses stored or linked files; the export writes no attachment out of Anvil's encrypted storage",
        )),
    }
    let (_, auth) = ctx.effective_auth();
    match &auth {
        AuthConfig::None | AuthConfig::Inherit | AuthConfig::Basic { .. } | AuthConfig::Bearer { .. } | AuthConfig::ApiKey { .. } => {}
        other => rs.push(reason(
            rq,
            "auth",
            format!(
                "the request's auth ({}) is generated or acquired per send by Anvil (signatures, tokens, proofs); JMeter's core elements cannot do that without scripts",
                auth_kind(other)
            ),
        )),
    }
    if !rs.is_empty() {
        return Err(rs);
    }

    let resolver = Resolver::new(step_layers(t, pos, ctx, per_run), None);
    // The step's own fields, with dynamic helpers masked and credential
    // fields with literal material replaced by property markers.
    let mut spec = ctx.spec.clone();
    spec.method = mask_helpers(&spec.method, &mut t.markers);
    spec.url = mask_helpers(&spec.url, &mut t.markers);
    for (i, p) in spec.params.iter_mut().enumerate().filter(|(_, p)| p.enabled) {
        let original = p.value.clone();
        p.name = mask_helpers(&p.name, &mut t.markers);
        p.value = mask_helpers(&p.value, &mut t.markers);
        match credential_field(t, pos, ctx, &resolver, name, "query", i, &p.name, &p.value, &original, p.sensitive) {
            Ok(Some(m)) => p.value = m,
            Ok(None) => {}
            Err(r) => rs.push(r),
        }
    }
    let auth_overrides_authorization = matches!(auth, AuthConfig::Basic { .. } | AuthConfig::Bearer { .. });
    for (i, h) in spec.headers.iter_mut().enumerate().filter(|(_, h)| h.enabled) {
        let original = h.value.clone();
        h.name = mask_helpers(&h.name, &mut t.markers);
        h.value = mask_helpers(&h.value, &mut t.markers);
        let overridden_auth = auth_overrides_authorization
            && resolver.resolve(h.name.trim(), "header").is_ok_and(|n| n.eq_ignore_ascii_case("authorization"));
        if !overridden_auth {
            match credential_field(t, pos, ctx, &resolver, name, "header", i, &h.name, &h.value, &original, h.sensitive) {
                Ok(Some(m)) => h.value = m,
                Ok(None) => {}
                Err(r) => rs.push(r),
            }
        }
    }
    match &mut spec.body {
        Body::Raw { text, .. } | Body::Json { text } | Body::Xml { text } => *text = mask_helpers(text, &mut t.markers),
        Body::FormUrlEncoded { fields } => {
            for (i, f) in fields.iter_mut().enumerate().filter(|(_, f)| f.enabled) {
                let original = f.value.clone();
                f.name = mask_helpers(&f.name, &mut t.markers);
                f.value = mask_helpers(&f.value, &mut t.markers);
                match credential_field(t, pos, ctx, &resolver, name, "form", i, &f.name, &f.value, &original, f.sensitive) {
                    Ok(Some(m)) => f.value = m,
                    Ok(None) => {}
                    Err(r) => rs.push(r),
                }
            }
        }
        _ => {}
    }
    let schemes = anvil_load::protocol::send_schemes(Protocol::Http);
    let prepared = match anvil_engine::prepare::prepare_http(&spec, &resolver, &*ctx.attachments, &settings, true, schemes) {
        Ok(p) => p,
        Err(f) => {
            rs.push(reason(
                rq,
                "does_not_prepare",
                format!("Anvil cannot prepare this request ({}), so every send would fail locally", f.message),
            ));
            return Err(rs);
        }
    };
    let target = &prepared.target;
    if target.host.to_ascii_uppercase().contains(MARK) || target.authority.to_ascii_uppercase().contains(MARK) {
        rs.push(reason(
            rq,
            "url",
            "a per-iteration value or a secret is part of the URL's host; Anvil's load preflight refuses such a plan too",
        ));
        return Err(rs);
    }
    if !anvil_transport::destination::permitted_literal(&target.host) {
        rs.push(reason(
            rq,
            "destination_policy",
            format!(
                "the target host '{}' is an unspecified, multicast, or reserved IP literal that Anvil's destination policy refuses; JMeter does not enforce Anvil's destination network-zone checks",
                target.host
            ),
        ));
    }
    t.note("Destination policy: Anvil checks resolved IP addresses against its destination network-zone policy before connecting; JMeter uses the JVM's own DNS resolution without Anvil's destination-zone checks.");

    // ---- TLS (LOAD-012) ----
    let profile = settings.tls_profile_id.and_then(|id| ctx.tls_profiles.iter().find(|p| p.id == id));
    // Whether an https connection would behave as in Anvil: verification
    // off (JMeter never verifies), nothing JMeter cannot set, HTTP/1.1.
    let https_like_jmeter = profile.is_some_and(|p| {
        !p.verify
            && p.client_identity.is_none()
            && p.min_version != TlsMinVersion::Tls13
            && p.server_name_override.is_none()
            && p.server_spiffe.is_none()
    }) && settings.http_version == HttpVersionPolicy::Http1Only;
    if target.scheme == "https" {
        match profile {
            Some(p) if !p.verify => {
                if p.client_identity.is_some() {
                    rs.push(reason(rq, "tls_setting", format!("the TLS profile '{}' presents a client certificate; JMeter takes a client keystore only as a JVM-wide setting, not per request", p.name)));
                }
                if p.min_version == TlsMinVersion::Tls13 {
                    rs.push(reason(rq, "tls_setting", format!("the TLS profile '{}' requires TLS 1.3; JMeter negotiates with the JVM's default protocol versions", p.name)));
                }
                if p.server_name_override.is_some() || p.server_spiffe.is_some() {
                    rs.push(reason(rq, "tls_setting", format!("the TLS profile '{}' overrides the server name or expects a SPIFFE identity, which JMeter cannot set", p.name)));
                }
                t.note(format!(
                    "TLS: the TLS profile '{}' turns certificate verification off, and JMeter's HTTP sampler never verifies certificates, so both accept any server certificate; the connection stays encrypted. JMeter negotiates with the JVM's default TLS versions (1.2 and 1.3).",
                    p.name
                ));
                t.map("TLS profile with verification off", "JMeter's default HTTPS handling (no certificate verification)");
            }
            _ => rs.push(reason(
                rq,
                "strict_tls",
                "Anvil verifies this https request's server certificate and host name; JMeter's HTTP samplers accept any certificate, trusted or not, so a JMeter run would silently accept an untrusted certificate. Load test it with Anvil's native engine, or (only for a test system whose certificate you deliberately do not verify) select a TLS profile with verification turned off",
            )),
        }
        if settings.http_version == HttpVersionPolicy::Auto {
            rs.push(reason(
                rq,
                "http_version",
                "over https Anvil negotiates HTTP/2 or HTTP/1.1 by ALPN; JMeter's HttpClient 4 sampler sends HTTP/1.1 only. Set the request's HTTP version to HTTP/1.1 only to export it",
            ));
        }
    }

    // ---- method and body ----
    let method = prepared.method.clone();
    if t.markers.has_marks(&method) {
        rs.push(reason(rq, "method", "the method comes from a per-iteration value"));
    } else if !METHODS.contains(&method.as_str()) {
        rs.push(reason(rq, "method", format!("JMeter's HTTP sampler does not send the method {method}")));
    }
    let body = if prepared.body.is_empty() {
        None
    } else {
        match String::from_utf8(prepared.body.to_vec()) {
            Ok(text) => {
                if !BODY_METHODS.contains(&method.as_str()) {
                    rs.push(reason(
                        rq,
                        "body",
                        format!(
                            "the request sends a body with {method}; the exported sampler sends a body only with POST, PUT, PATCH or DELETE"
                        ),
                    ));
                }
                let encoded = matches!(spec.body, Body::FormUrlEncoded { .. });
                Some(Tmpl(vec![(text, encoded)]))
            }
            Err(_) => {
                rs.push(reason(rq, "body", "the body is not UTF-8 text"));
                None
            }
        }
    };
    let marked_body = body.as_ref().is_some_and(|b| b.0.iter().any(|(s, _)| t.markers.has_marks(s)));
    let linted = matches!(ctx.spec.body, Body::Json { .. } | Body::Xml { .. }) && ctx.spec.lint_policy != LintSendPolicy::Off;
    if linted && ctx.spec.lint_policy == LintSendPolicy::Block && marked_body {
        // Anvil lints the body after each iteration's values are filled in
        // and does not send it when that fails; JMeter cannot lint.
        rs.push(reason(
            rq,
            "lint",
            "the JSON or XML body takes per-iteration values or secrets, and the request's lint policy blocks a body that fails lint: Anvil checks every iteration's body and does not send an invalid one, JMeter would send it. Set the request's lint policy to warn or off to export it",
        ));
    } else if let Some(msg) = &prepared.lint_bypassed
        && ctx.spec.lint_policy == LintSendPolicy::Block
    {
        rs.push(reason(
            rq,
            "lint",
            format!("the body fails Anvil's lint ({msg}) and the request's lint policy blocks it, so Anvil never sends it"),
        ));
    }

    // ---- URL ----
    let resolved_url = resolver.resolve(&spec.url, "url").unwrap_or_default();
    let base_query = anvil_engine::prepare::parse_target(&resolved_url, schemes, &mut Vec::new()).map(|b| b.query.len()).unwrap_or(0);
    let mut path = Tmpl::raw(target.path.clone());
    let mut has_query = false;
    if !target.query.is_empty() {
        has_query = true;
        let split = base_query.min(target.query.len());
        path.push(format!("?{}", &target.query[..split]), false);
        path.push(&target.query[split..], true);
    }
    // Credentials written into the URL's own query (not as query
    // parameters) follow the same rule as fields: literal material is never
    // copied into the test plan.
    for pair in target.query[..base_query.min(target.query.len())].split('&') {
        let (raw_name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let qname = percent_decode(raw_name);
        if anvil_domain::credential_names::is_export_secret_name(&qname, &ctx.redaction_names)
            && needs_property(&t.markers, value, false) != Ok(false)
        {
            rs.push(reason(
                rq,
                "url_credential",
                format!(
                    "the URL's query holds a value for the credential '{}'; the export would copy it into the test plan. Move it to the request's query parameters or an API key auth, where it becomes a JMeter property",
                    qname
                ),
            ));
        }
    }
    if t.markers.has_marks(&target.path) || t.markers.has_marks(&target.query[..base_query.min(target.query.len())]) {
        t.note("A per-iteration value in the URL path or in the URL's own query is inserted as it is by JMeter; Anvil percent-encodes the characters a request target cannot carry (space, quotes, braces, non-ASCII).");
    }

    // ---- headers and auth ----
    let mut headers: Vec<(String, Tmpl)> = Vec::new();
    for (n, v) in &prepared.headers {
        if t.markers.has_marks(n) {
            rs.push(reason(rq, "header", "a header name comes from a per-iteration value or a secret"));
            continue;
        }
        headers.push((n.clone(), Tmpl::raw(v.clone())));
    }
    // Accept-Encoding: JMeter 5.6.3 (HttpClient 4) decodes gzip, deflate and
    // Brotli. Anvil's inferred header also offers zstd, which JMeter would
    // receive and could not decode; the inferred header is sent without it.
    // An explicit header JMeter cannot honour the same way is refused.
    let explicit_ae = spec
        .headers
        .iter()
        .filter(|h| h.enabled)
        .any(|h| resolver.resolve(h.name.trim(), "header").is_ok_and(|n| n.trim().eq_ignore_ascii_case("accept-encoding")));
    if !settings.decompress {
        rs.push(reason(
            rq,
            "accept_encoding",
            "automatic decompression is off: Anvil keeps compressed responses encoded, whereas JMeter's HttpClient 4 sampler automatically decompresses gzip, deflate and br responses even without an explicit Accept-Encoding header. Turn automatic decompression on to export it",
        ));
    }
    let mut noted_inferred_ae = false;
    for (_, v) in headers.iter_mut().filter(|(n, _)| n.eq_ignore_ascii_case("accept-encoding")) {
        let text = v.0.iter().map(|(s, _)| s.as_str()).collect::<String>();
        if !explicit_ae {
            *v = Tmpl::raw("gzip, deflate, br");
            if !noted_inferred_ae {
                t.note("Accept-Encoding: Anvil's inferred header offers gzip, deflate, br and zstd; JMeter 5.6.3 cannot decode zstd, so the test plan offers gzip, deflate and br.");
                noted_inferred_ae = true;
            }
        } else if t.markers.has_marks(&text) {
            rs.push(reason(rq, "accept_encoding", "the Accept-Encoding header comes from a per-iteration value or a secret"));
        } else {
            let codings: Vec<String> =
                text.split(',').map(|c| c.split(';').next().unwrap_or("").trim().to_ascii_lowercase()).filter(|c| !c.is_empty()).collect();
            if let Some(c) = codings.iter().find(|c| !matches!(c.as_str(), "gzip" | "x-gzip" | "deflate" | "br" | "identity")) {
                rs.push(reason(
                    rq,
                    "accept_encoding",
                    format!("the Accept-Encoding header offers '{c}', which JMeter 5.6.3 cannot decode (it decodes gzip, deflate and br)"),
                ));
            }
        }
    }
    fn set_header(headers: &mut Vec<(String, Tmpl)>, name: &str, value: Tmpl) {
        headers.retain(|(h, _)| !h.eq_ignore_ascii_case(name));
        headers.push((name.to_string(), value));
    }
    let request_slug = slug(name);
    let mut basic = None;
    let mut credential_headers = false;
    let mut encoded_query_value = false;
    match &auth {
        AuthConfig::Basic { username, password } => {
            let user = match resolver.resolve(&mask_helpers(username, &mut t.markers), "auth.username") {
                Ok(u) => u,
                Err(f) => {
                    rs.push(reason(rq, "does_not_prepare", f.message));
                    String::new()
                }
            };
            if !t.markers.has_marks(&user) && user.contains(':') {
                rs.push(reason(rq, "auth", "the Basic auth user name contains ':', which Anvil refuses on every send"));
            }
            if !user.is_ascii() {
                rs.push(reason(
                    rq,
                    "auth",
                    "the Basic auth user name is not ASCII; JMeter's HttpClient encodes Basic credentials as ASCII",
                ));
            }
            match sensitive_value(t, pos, ctx, &resolver, name, password, "auth.password", format!("auth.{request_slug}.password")) {
                Ok(pass) => {
                    let host = if target.host.contains(':') { format!("[{}]", target.host) } else { target.host.clone() };
                    let default = (target.scheme == "https" && target.port == 443) || (target.scheme == "http" && target.port == 80);
                    let url = if default {
                        format!("{}://{host}/", target.scheme)
                    } else {
                        format!("{}://{host}:{}/", target.scheme, target.port)
                    };
                    headers.retain(|(n, _)| !n.eq_ignore_ascii_case("authorization"));
                    basic = Some((url, Tmpl::raw(user), Tmpl::raw(pass)));
                    t.map("Basic auth", "HTTP Authorization Manager (Basic, preemptive), scoped to the sampler and its origin");
                    t.note("Basic auth: JMeter's HttpClient encodes the user name and password as ASCII; Anvil encodes them as UTF-8 (identical for ASCII values).");
                }
                Err(r) => rs.push(r),
            }
        }
        AuthConfig::Bearer { token, prefix } => {
            match sensitive_value(t, pos, ctx, &resolver, name, token, "auth.token", format!("auth.{request_slug}.token")) {
                Ok(tok) => {
                    let v = if prefix.is_empty() {
                        tok
                    } else if !prefix.chars().any(char::is_whitespace) && is_recognized_auth_scheme(prefix) {
                        format!("{prefix} {tok}")
                    } else {
                        let key = format!("field:{}:auth.prefix", ctx.request_id.map(|i| i.to_string()).unwrap_or_else(|| pos.to_string()));
                        let idx = t.secrets.add(
                            key,
                            format!("auth.{request_slug}.prefix"),
                            format!("auth.prefix of request '{name}'"),
                            SecretSource::Literal(prefix.clone()),
                        );
                        format!("{} {tok}", t.markers.add(Mark::Secret(idx)))
                    };
                    set_header(&mut headers, "Authorization", Tmpl::raw(v));
                    credential_headers = true;
                    t.map("Bearer auth", "Authorization header in the sampler's HTTP Header Manager");
                }
                Err(r) => rs.push(r),
            }
        }
        AuthConfig::ApiKey { name: key, value, location } => {
            let key = resolver.resolve(&mask_helpers(key, &mut t.markers), "auth.name").unwrap_or_default();
            if key.trim().is_empty() || t.markers.has_marks(&key) {
                rs.push(reason(rq, "auth", "the API key name is empty or comes from a per-iteration value or a secret"));
            } else if matches!(location, KeyLocation::Header) && key.trim().eq_ignore_ascii_case("accept-encoding") {
                rs.push(reason(rq, "accept_encoding", "the Accept-Encoding header comes from a per-iteration value or a secret"));
            }
            match sensitive_value(t, pos, ctx, &resolver, name, value, "auth.api_key", format!("auth.{request_slug}.api_key")) {
                Ok(v) => match location {
                    KeyLocation::Header => {
                        set_header(&mut headers, &key, Tmpl::raw(v));
                        credential_headers = true;
                        t.map("API key in a header", "header in the sampler's HTTP Header Manager");
                    }
                    KeyLocation::Query => {
                        path.push(
                            format!("{}{}=", if has_query { "&" } else { "?" }, anvil_engine::prepare::encode_component(&key)),
                            false,
                        );
                        path.push(v, true);
                        encoded_query_value = true;
                        t.map("API key in the query", "query parameter in the sampler's path (value through ${__urlencode()})");
                    }
                    KeyLocation::Cookie => {
                        if headers.iter().any(|(h, _)| h.eq_ignore_ascii_case("cookie")) {
                            rs.push(reason(rq, "auth", "a cookie API key would be merged into the request's own Cookie header, which the export does not reproduce"));
                        }
                        set_header(&mut headers, "Cookie", Tmpl::raw(format!("{key}={v}")));
                        credential_headers = true;
                    }
                },
                Err(r) => rs.push(r),
            }
        }
        _ => {}
    }
    let query_tail_marked = path.0.iter().any(|(s, enc)| *enc && t.markers.has_marks(s));
    if query_tail_marked || encoded_query_value {
        t.note("Query parameter values that come from a per-iteration value or a secret are encoded by JMeter's __urlencode (form encoding: a space becomes '+'); Anvil percent-encodes them (a space becomes %20). Other characters are encoded alike.");
    }
    if settings.cookies && headers.iter().any(|(h, _)| h.eq_ignore_ascii_case("cookie")) {
        rs.push(reason(rq, "cookies", "the request sets a Cookie header while cookies are on; Anvil merges the jar's cookies into it, JMeter's cookie manager handles them separately"));
    }

    // ---- redirects ----
    let tr: &Translator<'_> = &*t;
    let secret_in = |s: &str| {
        tr.markers
            .split(s)
            .iter()
            .any(|p| matches!(p, Part::Mark(i) if matches!(tr.markers.list[*i], Mark::Secret(_) | Mark::SensitiveVar(_))))
    };
    let carries_credentials = credential_headers
        || prepared.body_uses_secret
        || headers.iter().any(|(n, v)| {
            anvil_domain::credential_names::is_export_secret_name(n, &ctx.redaction_names)
                || prepared.sensitive_headers.contains(&n.to_ascii_lowercase())
                || v.0.iter().any(|(s, _)| secret_in(s))
        })
        || body.as_ref().is_some_and(|b| b.0.iter().any(|(s, _)| secret_in(s)));
    if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-length")) {
        rs.push(reason(
            rq,
            "content_length_header",
            "the request sets an explicit Content-Length header; JMeter's HttpClient 4 sampler discards Content-Length from the HTTP Header Manager and computes it from the request body. Remove the explicit Content-Length header to export it",
        ));
    }
    if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding")) {
        rs.push(reason(
            rq,
            "transfer_encoding_header",
            "the request sets an explicit Transfer-Encoding header; JMeter's HttpClient 4 sampler manages transfer framing itself and rejects or rewrites an explicit Transfer-Encoding header. Remove the explicit Transfer-Encoding header to export it",
        ));
    }
    if headers.iter().any(|(n, v)| {
        n.eq_ignore_ascii_case("host")
            && (v.0.iter().any(|(s, _)| t.markers.has_marks(s))
                || host_header_rewritten_by_hc4(&v.0.iter().map(|(s, _)| s.as_str()).collect::<String>(), &target.scheme, target.port))
    }) {
        rs.push(reason(
            rq,
            "host_header",
            "the request sets an explicit Host header whose wire form JMeter's HttpClient 4 sampler would rewrite (appending a non-default sampler port to a portless Host, stripping an explicit default port, or resolving a dynamic template). Remove the Host header or match the sampler's port rule to export it",
        ));
    }
    let follow = settings.redirects.follow;
    if follow && !settings.redirects.forward_credentials_cross_origin && carries_credentials {
        rs.push(reason(
            rq,
            "redirect_credentials",
            "the request follows redirects and carries credentials; Anvil never forwards them to another origin, but JMeter's header manager sends its headers to every redirect target. Turn off following redirects for this request to export it",
        ));
    }
    if follow {
        rs.push(reason(
            rq,
            "redirect_destination_policy",
            "the request follows redirects; Anvil enforces its per-hop destination network-zone policy on every redirect (preventing redirects into private, loopback, or other unapproved network zones), whereas JMeter follows redirects to any host without network-zone enforcement. Turn off following redirects for this request to export it",
        ));
        if matches!(auth, AuthConfig::Basic { .. }) {
            rs.push(reason(
                rq,
                "redirect_basic_auth",
                "the request follows redirects and uses Basic auth; JMeter scopes its HTTP Authorization Manager to the initial origin (withholding Basic auth cross-origin and resuming it on return), whereas Anvil either forwards it cross-origin when enabled or strips it for the rest of the chain after leaving the origin. Turn off following redirects for this request to export it",
            ));
        }
        if matches!(auth, AuthConfig::ApiKey { location: KeyLocation::Query, .. }) {
            rs.push(reason(
                rq,
                "redirect_query_auth",
                "the request follows redirects and sends its API key in the query string; Anvil reapplies query authentication on same-origin redirect hops, whereas JMeter follows the Location URL without re-appending the key. Turn off following redirects for this request to export it",
            ));
        }
        if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
            rs.push(reason(
                rq,
                "redirect_host_header",
                "the request follows redirects and sets an explicit Host header; Anvil clears Host on every redirect hop, whereas JMeter's header manager sends it to every redirect target. Remove the Host header or turn off following redirects for this request to export it",
            ));
        }
        if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("mcp-session-id")) {
            rs.push(reason(
                rq,
                "redirect_mcp_session",
                "the request follows redirects and sets an Mcp-Session-Id header; Anvil withholds Mcp-Session-Id on cross-origin redirects even when credential forwarding is enabled, whereas JMeter's header manager sends it to every redirect target. Turn off following redirects for this request to export it",
            ));
        }
        if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-type")) {
            rs.push(reason(
                rq,
                "redirect_content_type",
                "the request follows redirects and sets an explicit Content-Type header; Anvil strips Content-Type on bodyless redirect hops, whereas JMeter's header manager sends it to every redirect target. Remove the Content-Type header or turn off following redirects for this request to export it",
            ));
        }
        // JMeter 5.6.3 turns every redirected method except HEAD into GET
        // and drops the body (HTTPSamplerBase), where Anvil keeps a 307/308's
        // method and body.
        if !matches!(method.as_str(), "GET" | "HEAD") {
            rs.push(reason(
                rq,
                "redirect_method",
                format!("the request follows redirects with {method}; JMeter re-sends a redirected {method} as GET without its body, Anvil keeps the method and body of a 307 or 308. Turn off following redirects for this request to export it"),
            ));
        }
        // A redirect can lead to an https URL, which Anvil verifies (and
        // may reach over HTTP/2); JMeter would accept any certificate.
        if target.scheme != "https" && !https_like_jmeter {
            rs.push(reason(
                rq,
                "redirect_tls",
                "the request follows redirects, and a redirect can lead to an https URL: Anvil verifies that certificate (and may negotiate HTTP/2), JMeter would accept any certificate over HTTP/1.1. Turn off following redirects for this request to export it",
            ));
        }
        let max = settings.redirects.max.to_string();
        match t.jmeter_properties.iter().find(|(k, _)| k == "httpsampler.max_redirects") {
            Some((_, v)) if *v != max => rs.push(reason(
                rq,
                "redirects",
                "the plan's requests follow different numbers of redirects; JMeter's limit is one global property",
            )),
            Some(_) => {}
            None => t.jmeter_properties.push(("httpsampler.max_redirects".into(), max)),
        }
    }

    // ---- timeouts and limits ----
    let to = settings.timeouts;
    let response_timeout = match (to.response_headers_ms, to.body_idle_ms) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    if to.dns_ms.is_some() || to.tls_handshake_ms.is_some() || to.request_write_ms.is_some() || to.total_ms.is_some() {
        t.note("Timeouts: JMeter applies a connect timeout and a socket read timeout (the larger of Anvil's response-headers and body-idle timeouts); Anvil's DNS, TLS handshake, request-write and total deadlines have no per-sample JMeter equivalent.");
    }
    t.note("Limits: Anvil's response size, decoded size and header size limits are not enforced by JMeter.");
    t.note(
        "Redirect responses without Location (301, 302, 303, 308, and 307 on GET/HEAD): Anvil keeps the completed response, whereas JMeter's HttpClient 4 sampler records a transport failure (and skips later steps in an exported chain) even when Follow Redirects is off.",
    );
    if !ctx.integrations.is_empty() {
        t.note("Ferrum gateway profiles: Anvil's gateway diagnostics are not performed by JMeter (they never change what is sent).");
    }
    let keepalive = t.input.plan.connection_mode == ConnectionMode::Persistent;
    if !keepalive {
        t.note("Fresh connection mode: JMeter closes the connection after each sample by sending `Connection: close`; Anvil opens a new connection without that header.");
    }

    // ---- assertions and extractions ----
    let mut children = Vec::new();
    let mut reads_body = false;
    for a in ctx.spec.assertions.iter().filter(|a| a.enabled) {
        match assertion_node(t, a) {
            Ok((n, body_read)) => {
                reads_body |= body_read;
                children.push(n);
            }
            Err(m) => rs.push(reason(rq, "assertion", m)),
        }
    }
    for e in &ctx.spec.extractions {
        match extraction_node(t, e) {
            Ok((n, body_read)) => {
                reads_body |= body_read;
                children.push(n);
            }
            Err(m) => rs.push(reason(rq, "extraction", m)),
        }
    }
    if reads_body {
        t.note("Anvil evaluates body assertions and extractions in a load run only when the body fits its 1 MiB capture (larger bodies are not evaluated); JMeter evaluates the whole body.");
    }

    // ---- dynamic helpers JMeter cannot reproduce, where used ----
    let mut texts: Vec<&str> = vec![method.as_str()];
    texts.extend(path.0.iter().map(|(s, _)| s.as_str()));
    texts.extend(headers.iter().flat_map(|(_, v)| v.0.iter().map(|(s, _)| s.as_str())));
    if let Some(b) = &body {
        texts.extend(b.0.iter().map(|(s, _)| s.as_str()));
    }
    if let Some((_, u, p)) = &basic {
        texts.extend(u.0.iter().chain(&p.0).map(|(s, _)| s.as_str()));
    }
    for s in texts {
        for p in t.markers.split(s) {
            if let Part::Mark(i) = p
                && let Mark::Unsupported(why) = &t.markers.list[i]
            {
                rs.push(reason(rq, "dynamic_helper", why.clone()));
            }
        }
    }
    if !rs.is_empty() {
        return Err(rs);
    }
    if t.markers.list.iter().any(|m| matches!(m, Mark::Helper(_))) {
        t.note("Dynamic helpers ({{$uuid}}, {{$timestamp}}, {{$timestampMs}}, {{$randomInt}}) become JMeter functions; Anvil seeds its random values per iteration, JMeter does not.");
    }
    t.map("HTTP request (HTTP/1.1)", "HTTP Request sampler (HttpClient4), method, URL, body and headers as Anvil prepares them");
    Ok(StepSpec {
        label,
        method,
        protocol: target.scheme.clone(),
        host: if target.host.contains(':') { format!("[{}]", target.host) } else { target.host.clone() },
        port: target.port,
        path,
        body,
        headers,
        basic,
        follow_redirects: follow,
        keepalive,
        connect_timeout: to.connect_ms,
        response_timeout,
        children,
    })
}

/// Percent-decode a query component (`+` is a space), for comparing names.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn auth_kind(a: &AuthConfig) -> &'static str {
    match a {
        AuthConfig::Inherit => "inherit",
        AuthConfig::None => "none",
        AuthConfig::ApiKey { .. } => "API key",
        AuthConfig::Basic { .. } => "Basic",
        AuthConfig::Bearer { .. } => "Bearer",
        AuthConfig::Jwt { .. } => "JWT",
        AuthConfig::OAuth2 { .. } => "OAuth 2",
        AuthConfig::Hmac { .. } => "HMAC",
        AuthConfig::Dpop { .. } => "DPoP",
        AuthConfig::Wsse { .. } => "WS-Security",
        AuthConfig::JwtSvid { .. } => "JWT-SVID",
        AuthConfig::Multi { .. } => "multiple profiles",
    }
}

/// A JSONPath JMeter (Jayway) and Anvil (RFC 9535) both read as one node:
/// `$` followed by `.name`, `['name']` or `[index]` steps.
fn simple_json_path(p: &str) -> bool {
    let Some(mut rest) = p.strip_prefix('$') else { return false };
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('.') {
            let end = r.find(['.', '[']).unwrap_or(r.len());
            let ident = &r[..end];
            let mut chars = ident.chars();
            if !chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return false;
            }
            rest = &r[end..];
        } else if let Some(r) = rest.strip_prefix("['") {
            let Some(end) = r.find("']") else { return false };
            let key = &r[..end];
            if key.is_empty() || key.contains(['\'', '\\', '"']) || !key.is_ascii() {
                return false;
            }
            rest = &r[end + 2..];
        } else if let Some(r) = rest.strip_prefix('[') {
            let Some(end) = r.find(']') else { return false };
            if end == 0 || !r[..end].bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            rest = &r[end + 1..];
        } else {
            return false;
        }
    }
    true
}

fn response_assertion(name: &str, field: &str, test_type: i64, strings: &[String]) -> Node {
    Node::new(
        "ResponseAssertion",
        "AssertionGui",
        safe_name(name),
        vec![
            Prop::Collection(
                "Asserion.test_strings",
                strings.iter().enumerate().map(|(i, s)| Prop::NamedStr(i.to_string(), Text::lit(s.clone()).to_jmeter())).collect(),
            ),
            Prop::s("Assertion.custom_message", ""),
            Prop::s("Assertion.test_field", field),
            Prop::Bool("Assertion.assume_success", false),
            Prop::Int("Assertion.test_type", test_type),
        ],
    )
}

const RA_MATCH_CONTAINS: i64 = 2;
const RA_NOT: i64 = 4;
const RA_EQUALS: i64 = 8;
const RA_SUBSTRING: i64 = 16;
const RA_OR: i64 = 32;

/// The JMeter assertion for an Anvil assertion, and whether it reads the
/// body; `Err` says why it cannot be reproduced.
fn assertion_node(t: &mut Translator<'_>, a: &anvil_domain::assertions::Assertion) -> Result<(Node, bool), String> {
    let label = if a.label.is_empty() { None } else { Some(a.label.clone()) };
    let name = |default: String| label.clone().unwrap_or(default);
    let refuse = |what: &str| format!("the assertion '{what}' has no JMeter core equivalent that judges the same way");
    Ok(match &a.kind {
        AssertionKind::Status { comparison, value } => {
            let tt = match comparison {
                Comparison::Equals => RA_EQUALS,
                Comparison::NotEquals => RA_NOT | RA_EQUALS,
                _ => return Err(refuse(&format!("status {comparison:?} {value}"))),
            };
            t.map("status assertion", "Response Assertion on the response code");
            (
                response_assertion(
                    &name(format!("status {comparison:?} {value}")),
                    "Assertion.response_code",
                    tt,
                    std::slice::from_ref(value),
                ),
                false,
            )
        }
        AssertionKind::StatusIn { values } => {
            if values.is_empty() {
                return Err("the status-in assertion lists no status, so it never passes in Anvil".into());
            }
            let strings: Vec<String> = values.iter().map(|v| v.to_string()).collect();
            t.map("status assertion", "Response Assertion on the response code");
            (
                response_assertion(
                    &name(format!("status in {}", strings.join(","))),
                    "Assertion.response_code",
                    RA_EQUALS | RA_OR,
                    &strings,
                ),
                false,
            )
        }
        AssertionKind::Header { name: header, comparison, value } => {
            if !header.is_ascii() || !value.is_ascii() || header.trim().is_empty() {
                return Err(refuse(&format!("header {header}")));
            }
            let n = jmx::regex_header_name(header.trim());
            let v = jmx::regex_literal(value);
            let (tt, pattern) = match comparison {
                Comparison::Exists => (RA_MATCH_CONTAINS, format!("\\n{n}:")),
                Comparison::NotExists => (RA_NOT | RA_MATCH_CONTAINS, format!("\\n{n}:")),
                Comparison::Equals => (RA_MATCH_CONTAINS, format!("\\n{n}:[ \\t]*{v}[ \\t]*\\r?\\n")),
                Comparison::Contains => (RA_MATCH_CONTAINS, format!("\\n{n}:[^\\n]*{v}")),
                _ => return Err(refuse(&format!("header {header} {comparison:?}"))),
            };
            if matches!(comparison, Comparison::Equals | Comparison::Contains) {
                t.note("Header assertions: Anvil compares the first value of the header; JMeter's assertion passes when any header line of that name matches.");
            }
            t.map("header assertion", "Response Assertion on the response headers (pattern)");
            (response_assertion(&name(format!("header {header} {comparison:?}")), "Assertion.response_headers", tt, &[pattern]), false)
        }
        AssertionKind::Body { comparison, value } => {
            if !value.is_ascii() {
                return Err("a body assertion with non-ASCII text depends on how JMeter decodes the response (its default charset), so it is not exported".into());
            }
            let tt = match comparison {
                Comparison::Contains => RA_SUBSTRING,
                Comparison::NotContains => RA_NOT | RA_SUBSTRING,
                Comparison::Equals => RA_EQUALS,
                Comparison::NotEquals => RA_NOT | RA_EQUALS,
                _ => return Err(refuse(&format!("body {comparison:?}"))),
            };
            t.map("body assertion", "Response Assertion on the response text (substring or equality, not a pattern)");
            (response_assertion(&name(format!("body {comparison:?}")), "Assertion.response_data", tt, std::slice::from_ref(value)), true)
        }
        AssertionKind::JsonPath { path, comparison, value } => {
            if !simple_json_path(path) {
                return Err(format!(
                    "the JSONPath '{path}' is not a simple path ($ with .name, ['name'] or [index] steps) that JMeter and Anvil read alike"
                ));
            }
            let (validate, invert, expected, regex) = match comparison {
                Comparison::Exists => (false, false, String::new(), false),
                Comparison::NotExists => (false, true, String::new(), false),
                Comparison::Equals if value.is_ascii() => (true, false, jmx::regex_literal(value), true),
                _ => return Err(refuse(&format!("JSONPath {path} {comparison:?}"))),
            };
            if matches!(comparison, Comparison::Equals) {
                t.note("JSONPath equality: both compare the value's text (a string as itself, other values as JSON); JMeter also passes when the value is an array with an equal element, and formats decimals its own way.");
            }
            t.map("JSONPath assertion", "JSON Assertion");
            let node = Node::new(
                "JSONPathAssertion",
                "JSONPathAssertionGui",
                safe_name(&name(format!("JSONPath {path} {comparison:?}"))),
                vec![
                    Prop::t("JSON_PATH", &Text::lit(path.clone())),
                    Prop::t("EXPECTED_VALUE", &Text::lit(expected)),
                    Prop::Bool("JSONVALIDATION", validate),
                    Prop::Bool("EXPECT_NULL", false),
                    Prop::Bool("INVERT", invert),
                    Prop::Bool("ISREGEX", regex),
                ],
            );
            (node, true)
        }
        AssertionKind::LatencyMs { max } => {
            t.map("latency assertion", "Duration Assertion");
            t.note("Latency assertions: JMeter compares its elapsed time (in whole milliseconds) with the limit; Anvil compares the sum of its attempt durations.");
            (
                Node::new(
                    "DurationAssertion",
                    "DurationAssertionGui",
                    safe_name(&name(format!("latency ≤ {max} ms"))),
                    vec![Prop::s("DurationAssertion.duration", max.to_string())],
                ),
                false,
            )
        }
        other => {
            let kind = serde_json::to_value(other)
                .ok()
                .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
                .unwrap_or_default();
            return Err(refuse(&kind));
        }
    })
}

fn regex_extractor(name: &str, var: &str, field: &str, regex: String, default: &str) -> Node {
    Node::new(
        "RegexExtractor",
        "RegexExtractorGui",
        safe_name(name),
        vec![
            Prop::s("RegexExtractor.useHeaders", field),
            Prop::s("RegexExtractor.refname", var),
            Prop::t("RegexExtractor.regex", &Text::lit(regex)),
            Prop::s("RegexExtractor.template", "$1$"),
            Prop::s("RegexExtractor.default", default),
            Prop::Bool("RegexExtractor.default_empty_value", default.is_empty()),
            Prop::s("RegexExtractor.match_number", "1"),
        ],
    )
}

/// The JMeter post-processor for an extraction, and whether it reads the body.
fn extraction_node(t: &mut Translator<'_>, e: &anvil_domain::assertions::Extraction) -> Result<(Node, bool), String> {
    let var = t.extracted.var(&e.variable);
    if e.sensitive {
        t.note(format!("The extracted value '{}' is sensitive in Anvil (redacted); JMeter keeps it as an ordinary variable.", e.variable));
    }
    t.note("When an extraction matches nothing, Anvil leaves the variable unset (a later step that uses it fails to prepare and is not sent); JMeter sets it to an empty value.");
    let name = format!("extract {}", e.variable);
    Ok(match &e.source {
        ExtractionSource::JsonPath { path } if simple_json_path(path) && !path.contains(';') => {
            t.map("JSONPath extraction", "JSON Extractor");
            let node = Node::new(
                "JSONPostProcessor",
                "JSONPostProcessorGui",
                safe_name(&name),
                vec![
                    Prop::s("JSONPostProcessor.referenceNames", var),
                    Prop::t("JSONPostProcessor.jsonPathExprs", &Text::lit(path.clone())),
                    Prop::s("JSONPostProcessor.match_numbers", "1"),
                    Prop::s("JSONPostProcessor.defaultValues", ""),
                    Prop::Bool("JSONPostProcessor.compute_concat", false),
                ],
            );
            (node, true)
        }
        ExtractionSource::Header { name: header } if header.is_ascii() && !header.trim().is_empty() => {
            t.map("header extraction", "Regular Expression Extractor on the response headers (first header of that name)");
            let regex = format!("\\n{}:[ \\t]*([^\\r\\n]*?)[ \\t]*\\r?\\n", jmx::regex_header_name(header.trim()));
            (regex_extractor(&name, &var, "true", regex, ""), false)
        }
        ExtractionSource::Status => {
            t.map("status extraction", "Regular Expression Extractor on the response code");
            (regex_extractor(&name, &var, "code", "^(\\d{3})$".into(), ""), false)
        }
        ExtractionSource::JsonPath { path } => {
            return Err(format!(
                "the JSONPath '{path}' is not a simple path ($ with .name, ['name'] or [index] steps) that JMeter and Anvil read alike"
            ));
        }
        ExtractionSource::Header { name } => return Err(format!("the header name '{name}' is empty or not ASCII")),
        ExtractionSource::Regex { .. } => {
            return Err(
                "Anvil's regular expressions (Rust syntax) and JMeter's (Perl 5 / Java) differ, so a regex extraction is not exported"
                    .into(),
            );
        }
        ExtractionSource::XPath { .. } => {
            return Err(
                "Anvil's XPath subset and JMeter's XPath extractors select differently, so an XPath extraction is not exported".into()
            );
        }
    })
}

// ---------------------------------------------------------------- thread groups

enum GroupKind {
    Closed { threads: u64, ramp: u64, delay: u64, duration: u64, think_ms: u64 },
    Iterations { threads: u64, loops: u64, gate: Option<u64> },
    Open { schedule: String },
}

struct Group {
    kind: GroupKind,
    vu_offset: i64,
}

fn thread_groups(t: &mut Translator<'_>) -> Vec<Group> {
    let plan = t.input.plan;
    match &plan.workload {
        Workload::ClosedVirtualUsers { stages, think_time_ms } => {
            let total: u64 = stages.iter().map(|s| s.duration_secs).sum();
            let (mut cur, mut time) = (0u64, 0u64);
            let mut groups = Vec::new();
            for s in stages {
                if s.target < cur {
                    t.reasons.push(reason(
                        None,
                        "workload",
                        format!(
                            "the closed workload lowers its virtual users from {cur} to {} at {time} s; JMeter's core thread groups stop all their threads together at the end of their duration, so a ramp-down or step-down cannot be expressed. Export a plan whose targets never decrease, or use Anvil's native engine",
                            s.target
                        ),
                    ));
                } else if s.target > cur && total > time {
                    groups.push(Group {
                        kind: GroupKind::Closed {
                            threads: s.target - cur,
                            ramp: s.duration_secs,
                            delay: time,
                            duration: total - time,
                            think_ms: *think_time_ms,
                        },
                        vu_offset: cur as i64,
                    });
                }
                cur = cur.max(s.target);
                time += s.duration_secs;
            }
            if groups.is_empty() {
                t.reasons.push(reason(
                    None,
                    "workload",
                    "the closed workload has no active virtual users before the end of its schedule, so JMeter would send 0 requests",
                ));
            }
            t.map(
                "closed workload (virtual users, stages)",
                "one Thread Group per increase: its threads, ramp-up, start delay and duration to the end of the schedule",
            );
            if groups.iter().any(|g| matches!(g.kind, GroupKind::Closed { ramp, .. } if ramp > 0)) {
                t.note("Ramps: JMeter starts a ramp's first thread at the ramp's start and the others evenly over it; Anvil activates virtual user k of n after k/n of the ramp, so JMeter leads each ramp by one step (the ramp duration divided by the users it adds).");
            }
            if *think_time_ms > 0 {
                t.map("think time", "Flow Control Action (pause) at the end of each iteration");
            }
            t.note("End of schedule: Anvil lets in-flight iterations finish for up to 5 s and then cancels them; JMeter's scheduler stops each thread at its end time.");
            groups
        }
        Workload::Iterations { iterations, concurrency } => {
            let threads = (*concurrency).min(*iterations).max(1);
            let loops = iterations.div_ceil(threads);
            let gate = (iterations % threads != 0).then_some(*iterations);
            t.map(
                "iteration workload (count, concurrency)",
                "Thread Group with min(concurrency, iterations) threads and loops; a shared counter stops the iterations beyond the count",
            );
            vec![Group { kind: GroupKind::Iterations { threads, loops, gate }, vu_offset: 0 }]
        }
        Workload::OpenArrivalRate { stages, max_in_flight } => {
            // JMeter's open model has no in-flight cap and its socket read
            // timeout is an idle timeout (not a total request deadline), so a
            // slow-streaming response can outlive Anvil's `total_ms`. Export
            // only when `max_in_flight` covers the schedule's total possible
            // arrivals, so Anvil's cap can never bind regardless of response
            // duration.
            let mut prev_rate = 0u128;
            let mut total_arrivals = 0u128;
            let mut jmeter_arrivals = 0u128;
            for s in stages {
                let target = u128::from(s.target);
                let dur = u128::from(s.duration_secs);
                if dur > 0 {
                    let area_twice = prev_rate.saturating_add(target).saturating_mul(dur);
                    total_arrivals = total_arrivals.saturating_add(area_twice.div_ceil(2));
                    jmeter_arrivals = jmeter_arrivals.saturating_add(area_twice / 2);
                }
                prev_rate = target;
            }
            if jmeter_arrivals == 0 {
                t.reasons.push(reason(
                    None,
                    "workload",
                    "JMeter's Open Model Thread Group rounds each stage's arrivals down to a whole number, so this schedule would start 0 arrivals in JMeter (empty JTL). Raise a stage's rate or duration so at least one whole arrival is scheduled",
                ));
            }
            if u128::from(*max_in_flight) < total_arrivals {
                t.reasons.push(reason(
                    None,
                    "open_cap",
                    format!(
                        "the open workload caps in-flight iterations at {max_in_flight}, and Anvil drops arrivals beyond it; JMeter's open model has no cap and its socket timeout does not bound a slow-streaming response. Raise max_in_flight to at least the schedule's total possible arrivals ({total_arrivals}) for the export to behave the same"
                    ),
                ));
            }
            if plan.connection_mode == ConnectionMode::Persistent {
                t.reasons.push(reason(
                    None,
                    "open_connections",
                    "an open workload in the persistent connection mode reuses connections and cookies across arrivals in Anvil; JMeter's open model starts every arrival as a new thread with its own connections. Choose the fresh connection mode to export it",
                ));
            }
            let mut schedule = String::from("rate(0/s)");
            for s in stages {
                if s.duration_secs > 0 {
                    schedule.push_str(&format!(" even_arrivals({} s)", s.duration_secs));
                }
                schedule.push_str(&format!(" rate({}/s)", s.target));
            }
            // Anvil's graceful stop: in-flight iterations get 5 s.
            schedule.push_str(" pause(5 s)");
            t.map(
                "open workload (arrival rate, stages)",
                "Open Model Thread Group: even_arrivals between the stages' rates, one new thread per arrival",
            );
            t.note(format!(
                "Open workload: the in-flight cap ({max_in_flight}) covers all {total_arrivals} scheduled arrivals, so Anvil never drops an arrival and JMeter's uncapped open model starts the same arrivals; each JMeter arrival is a new thread with its own cookie jar."
            ));
            t.note("Arrival counts: Anvil schedules arrivals on the integral of the rate across stages; JMeter rounds each stage's arrivals down separately, so a multi-stage schedule may differ by one arrival per stage.");
            vec![Group { kind: GroupKind::Open { schedule }, vu_offset: 0 }]
        }
    }
}

struct Render<'a> {
    markers: &'a Markers,
    secrets: &'a Secrets,
    vu_offset: i64,
    used: &'a RefCell<BTreeSet<usize>>,
}

impl Render<'_> {
    fn text(&self, tmpl: &Tmpl) -> Text {
        let mut out = Text::default();
        for (s, encoded) in &tmpl.0 {
            for p in self.markers.split(s) {
                match p {
                    Part::Lit(l) => out.push_lit(l),
                    Part::Mark(i) => {
                        self.used.borrow_mut().insert(i);
                        let e = self.expr(i);
                        out.push_expr(if *encoded { format!("${{__urlencode({e})}}") } else { e });
                    }
                }
            }
        }
        out
    }

    fn expr(&self, i: usize) -> String {
        match &self.markers.list[i] {
            Mark::Var(v) | Mark::SensitiveVar(v) => format!("${{{v}}}"),
            Mark::Secret(s) => format!("${{__P({},)}}", self.secrets.props[*s].name),
            Mark::Helper(e) => e.clone(),
            Mark::Vu => format!("${{__intSum(${{__threadNum}},{})}}", self.vu_offset - 1),
            // Refused before rendering.
            Mark::Unsupported(_) => String::new(),
        }
    }
}

fn if_node(name: String, condition: String, children: Vec<Node>) -> Node {
    Node::new(
        "IfController",
        "IfControllerPanel",
        name,
        vec![
            Prop::s("IfController.condition", condition),
            Prop::Bool("IfController.evaluateAll", false),
            Prop::Bool("IfController.useExpression", true),
        ],
    )
    .with_children(children)
}

fn test_action(name: &str, action: i64, target: i64, duration_ms: u64) -> Node {
    Node::new(
        "TestAction",
        "TestActionGui",
        name,
        vec![
            Prop::Int("ActionProcessor.action", action),
            Prop::Int("ActionProcessor.target", target),
            Prop::s("ActionProcessor.duration", duration_ms.to_string()),
        ],
    )
}

fn iteration_body(chain: bool, specs: &[StepSpec], mix: &[(Id, u32)], total_weight: u64, r: &Render<'_>) -> Vec<Node> {
    let mut out = Vec::new();
    if chain {
        let gated = specs.len() > 1;
        for (i, s) in specs.iter().enumerate() {
            let node = sampler_node(s, r, gated);
            if i == 0 {
                out.push(node);
            } else {
                out.push(if_node(
                    format!("Step {}: only after a complete response", i + 1),
                    format!("${{__jexl3(\"${{{RC_VAR}}}\" != \"none\")}}"),
                    vec![node],
                ));
            }
        }
    } else {
        let mut lo = 0u64;
        for ((_, w), s) in mix.iter().zip(specs) {
            let hi = lo + *w as u64;
            out.push(if_node(
                format!("Weight {w} of {total_weight}"),
                format!("${{__jexl3(${{{PICK_VAR}}} > {lo} && ${{{PICK_VAR}}} <= {hi})}}"),
                vec![sampler_node(s, r, false)],
            ));
            lo = hi;
        }
    }
    out
}

fn sampler_node(s: &StepSpec, r: &Render<'_>, chain_gate: bool) -> Node {
    let mut args = Vec::new();
    if let Some(b) = &s.body {
        args.push(Prop::Element {
            name: String::new(),
            element_type: "HTTPArgument",
            attrs: vec![],
            props: vec![
                Prop::Bool("HTTPArgument.always_encode", false),
                Prop::t("Argument.value", &r.text(b)),
                Prop::s("Argument.metadata", "="),
            ],
        });
    }
    let mut props = vec![
        Prop::Element {
            name: "HTTPsampler.Arguments".into(),
            element_type: "Arguments",
            attrs: vec![
                ("guiclass", "HTTPArgumentsPanel".into()),
                ("testclass", "Arguments".into()),
                ("testname", "User Defined Variables".into()),
            ],
            props: vec![Prop::Collection("Arguments.arguments", args)],
        },
        Prop::s("HTTPSampler.domain", s.host.clone()),
        Prop::s("HTTPSampler.port", s.port.to_string()),
        Prop::s("HTTPSampler.protocol", s.protocol.clone()),
        Prop::s("HTTPSampler.contentEncoding", "UTF-8"),
        Prop::t("HTTPSampler.path", &r.text(&s.path)),
        Prop::s("HTTPSampler.method", s.method.clone()),
        Prop::Bool("HTTPSampler.follow_redirects", s.follow_redirects),
        Prop::Bool("HTTPSampler.auto_redirects", false),
        Prop::Bool("HTTPSampler.use_keepalive", s.keepalive),
        Prop::Bool("HTTPSampler.DO_MULTIPART_POST", false),
        Prop::s("HTTPSampler.embedded_url_re", ""),
        Prop::s("HTTPSampler.connect_timeout", s.connect_timeout.map(|v| v.to_string()).unwrap_or_default()),
        Prop::s("HTTPSampler.response_timeout", s.response_timeout.map(|v| v.to_string()).unwrap_or_default()),
        Prop::s("HTTPSampler.implementation", "HttpClient4"),
    ];
    if s.body.is_some() {
        props.push(Prop::Bool("HTTPSampler.postBodyRaw", true));
    }
    let mut children = Vec::new();
    if !s.headers.is_empty() {
        let headers = s
            .headers
            .iter()
            .map(|(n, v)| Prop::Element {
                name: String::new(),
                element_type: "Header",
                attrs: vec![],
                props: vec![Prop::t("Header.name", &Text::lit(n.clone())), Prop::t("Header.value", &r.text(v))],
            })
            .collect();
        children.push(Node::new(
            "HeaderManager",
            "HeaderPanel",
            "HTTP Header Manager",
            vec![Prop::Collection("HeaderManager.headers", headers)],
        ));
    }
    if let Some((url, user, pass)) = &s.basic {
        children.push(Node::new(
            "AuthManager",
            "AuthPanel",
            "HTTP Authorization Manager",
            vec![
                Prop::Collection(
                    "AuthManager.auth_list",
                    vec![Prop::Element {
                        name: String::new(),
                        element_type: "Authorization",
                        attrs: vec![],
                        props: vec![
                            Prop::t("Authorization.url", &Text::lit(url.clone())),
                            Prop::t("Authorization.username", &r.text(user)),
                            Prop::t("Authorization.password", &r.text(pass)),
                            Prop::s("Authorization.domain", ""),
                            Prop::s("Authorization.realm", ""),
                        ],
                    }],
                ),
                Prop::Bool("AuthManager.controlledByThreadGroup", false),
            ],
        ));
    }
    children.extend(s.children.iter().cloned());
    if chain_gate {
        // A transport failure or timeout leaves no 3-digit code: `none`.
        children.push(regex_extractor("Anvil chain: response status", RC_VAR, "code", "^(\\d{3})$".into(), "none"));
    }
    Node::new("HTTPSamplerProxy", "HttpTestSampleGui", s.label.clone(), props).with_children(children)
}

fn cookie_manager() -> Node {
    Node::new(
        "CookieManager",
        "CookiePanel",
        "HTTP Cookie Manager",
        vec![
            Prop::Collection("CookieManager.cookies", vec![]),
            Prop::Bool("CookieManager.clearEachIteration", false),
            Prop::Bool("CookieManager.controlledByThreadGroup", false),
        ],
    )
}

fn thread_group_props(threads: u64, ramp: u64, loops: i64, scheduler: bool, duration: Option<u64>, delay: Option<u64>) -> Vec<Prop> {
    vec![
        Prop::s("ThreadGroup.on_sample_error", "continue"),
        Prop::Element {
            name: "ThreadGroup.main_controller".into(),
            element_type: "LoopController",
            attrs: vec![
                ("guiclass", "LoopControlPanel".into()),
                ("testclass", "LoopController".into()),
                ("testname", "Loop Controller".into()),
            ],
            props: vec![Prop::Bool("LoopController.continue_forever", false), Prop::s("LoopController.loops", loops.to_string())],
        },
        Prop::s("ThreadGroup.num_threads", threads.to_string()),
        Prop::s("ThreadGroup.ramp_time", ramp.to_string()),
        Prop::Bool("ThreadGroup.scheduler", scheduler),
        Prop::s("ThreadGroup.duration", duration.map(|d| d.to_string()).unwrap_or_default()),
        Prop::s("ThreadGroup.delay", delay.map(|d| d.to_string()).unwrap_or_default()),
        Prop::Bool("ThreadGroup.same_user_on_next_iteration", true),
    ]
}

fn thread_group_node(index: usize, g: &Group, body: Vec<Node>, cookies: bool, dataset: Option<Node>) -> Node {
    let mut children = Vec::new();
    if cookies {
        children.push(cookie_manager());
    }
    let mut body = body;
    match &g.kind {
        GroupKind::Closed { think_ms, .. } => {
            if let Some(ds) = dataset {
                children.push(ds);
            }
            if *think_ms > 0 {
                body.push(test_action("Anvil think time", 1, 0, *think_ms));
            }
        }
        GroupKind::Iterations { gate: Some(n), .. } => {
            // Place CSVDataSet inside a 1-loop LoopController underneath the
            // iteration gate so discarded excess iterations never advance the
            // CSV cursor (JMeter attaches CSVDataSet to its enclosing
            // LoopController).
            let gated_children = if let Some(ds) = dataset {
                let mut inner = Vec::with_capacity(body.len() + 1);
                inner.push(ds);
                inner.extend(body);
                vec![
                    Node::new(
                        "LoopController",
                        "LoopControlPanel",
                        "Anvil gated dataset iteration",
                        vec![Prop::Bool("LoopController.continue_forever", false), Prop::s("LoopController.loops", "1")],
                    )
                    .with_children(inner),
                ]
            } else {
                body
            };
            body = vec![if_node(
                format!("Anvil: stop after {n} iterations"),
                format!("${{__jexl3(${{{ITERATION_VAR}}} < {n})}}"),
                gated_children,
            )];
        }
        _ => {
            if let Some(ds) = dataset {
                children.push(ds);
            }
        }
    }
    children.extend(body);
    let name = format!("Anvil group {}", index + 1);
    let node = match &g.kind {
        GroupKind::Closed { threads, ramp, delay, duration, .. } => {
            Node::new("ThreadGroup", "ThreadGroupGui", name, thread_group_props(*threads, *ramp, -1, true, Some(*duration), Some(*delay)))
        }
        GroupKind::Iterations { threads, loops, .. } => {
            Node::new("ThreadGroup", "ThreadGroupGui", name, thread_group_props(*threads, 0, *loops as i64, false, None, None))
        }
        GroupKind::Open { schedule } => Node::new(
            "OpenModelThreadGroup",
            "OpenModelThreadGroupGui",
            name,
            vec![
                Prop::Element {
                    name: "ThreadGroup.main_controller".into(),
                    element_type: "OpenModelThreadGroupController",
                    attrs: vec![],
                    props: vec![],
                },
                Prop::s("ThreadGroup.on_sample_error", "continue"),
                Prop::s("OpenModelThreadGroup.schedule", schedule.clone()),
                Prop::s("OpenModelThreadGroup.random_seed", ""),
            ],
        ),
    };
    node.with_children(children)
}

/// A setUp thread group that stops the test before any traffic when a
/// secret property is not set (it never reads a value: `__isPropDefined`).
fn secrets_guard(props: &[SecretProperty]) -> Node {
    let cond = props.iter().map(|p| format!("!${{__isPropDefined({})}}", p.name)).collect::<Vec<_>>().join(" || ");
    let stop = test_action(
        "Anvil: a required anvil.secret.* property is not set (pass the secrets file with -q); stopping before any traffic",
        2,
        2,
        0,
    );
    let check = if_node("Anvil: any secret property missing?".into(), format!("${{__jexl3({cond})}}"), vec![stop]);
    Node::new("SetupThreadGroup", "SetupThreadGroupGui", "Anvil secrets check", thread_group_props(1, 0, 1, false, None, None))
        .with_children(vec![check])
}

/// Probe `template` recursively through `step`'s variable layers (including
/// nested non-literal secret variables, and optionally decrypted non-literal
/// vault values during explicit secret export) to verify it depends on no
/// per-iteration value or dynamic helper before evaluating or exporting it as
/// a static JMeter property.
#[allow(clippy::too_many_arguments)]
fn validate_static_secret_template(
    t: &Translator<'_>,
    step: usize,
    template: &str,
    purpose: &str,
    redact_errors: bool,
    dataset: Option<&anvil_load::Dataset>,
    chain: bool,
    expand_vault: bool,
) -> Result<(), Reason> {
    let ctx = t.contexts[step];
    let mut probe_markers = Markers::default();
    let mut probe_layers = Vec::new();
    let real_for_vault = expand_vault.then(|| Resolver::new(ctx.var_layers.clone(), None).with_secrets(ctx.secrets.clone()));
    for (li, l) in ctx.var_layers.iter().enumerate() {
        let mut vars = Vec::new();
        for (vi, e) in l.vars.iter().enumerate() {
            let vault_ref = ctx.secrets.variable_secret(li, vi);
            if let Some(ref r) = real_for_vault
                && vault_ref.is_some()
            {
                let raw = r.variable_value(li, vi).map_err(|f| reason(None, "secret_unavailable", format!("{purpose}: {}", f.message)))?;
                if e.literal || !raw.contains("{{") {
                    vars.push(VarEntry { name: e.name.clone(), value: probe_markers.add(Mark::Secret(0)), secret: false, literal: true });
                } else {
                    vars.push(VarEntry {
                        name: e.name.clone(),
                        value: mask_helpers(&raw, &mut probe_markers),
                        secret: false,
                        literal: false,
                    });
                }
            } else if vault_ref.is_some() || e.value == DEFERRED_SECRET_VALUE || e.literal || !e.value.contains("{{") {
                vars.push(VarEntry {
                    name: e.name.clone(),
                    value: if e.secret || vault_ref.is_some() || e.value == DEFERRED_SECRET_VALUE {
                        probe_markers.add(Mark::Secret(0))
                    } else {
                        e.value.clone()
                    },
                    secret: false,
                    literal: true,
                });
            } else {
                // Non-literal plain or secret variable containing `{{`: expand
                // recursively with dynamic helpers masked so nested dynamic or
                // per-iteration dependencies are always caught.
                vars.push(VarEntry {
                    name: e.name.clone(),
                    value: mask_helpers(&e.value, &mut probe_markers),
                    secret: false,
                    literal: false,
                });
            }
        }
        probe_layers.push(VarLayer { label: l.label.clone(), vars });
    }
    let stand_in = |name: &str, value: String| VarEntry { name: name.into(), value, secret: false, literal: true };
    let iter_mark = probe_markers.add(Mark::Var(ITERATION_VAR.into()));
    let vu_mark = probe_markers.add(Mark::Vu);
    probe_layers.push(VarLayer { label: "load".into(), vars: vec![stand_in("anvil.iteration", iter_mark), stand_in("anvil.vu", vu_mark)] });
    if let Some(d) = dataset
        && ctx.scope.is_none()
    {
        let vars =
            d.columns.iter().enumerate().map(|(ci, c)| stand_in(c, probe_markers.add(Mark::Var(format!("anvil_ds_{ci}"))))).collect();
        probe_layers.push(VarLayer { label: "dataset".into(), vars });
    }
    if chain {
        let mut ext_vars = Vec::new();
        for earlier in &t.contexts[..step] {
            if earlier.scope == ctx.scope {
                for ex in &earlier.spec.extractions {
                    ext_vars.push(stand_in(&ex.variable, probe_markers.add(Mark::Var(ex.variable.clone()))));
                }
            }
        }
        if !ext_vars.is_empty() {
            probe_layers.push(VarLayer { label: "iteration (extracted)".into(), vars: ext_vars });
        }
    }
    let probe = Resolver::new(probe_layers, None);
    let masked = mask_helpers(template, &mut probe_markers);
    match probe.resolve(&masked, "variables") {
        Ok(expanded) => {
            let has_per_run = probe_markers
                .split(&expanded)
                .iter()
                .any(|part| matches!(part, Part::Mark(mi) if !matches!(probe_markers.list[*mi], Mark::Secret(_))));
            if has_per_run {
                return Err(reason(
                    None,
                    "secret_mixed",
                    format!(
                        "{purpose} depends on a per-iteration value or dynamic helper; JMeter cannot represent it as a static property"
                    ),
                ));
            }
            Ok(())
        }
        Err(f) => {
            let msg = if redact_errors {
                "could not resolve a secret variable; check the vault and active variables".to_string()
            } else {
                f.message
            };
            Err(reason(None, "does_not_prepare", format!("{purpose}: {msg}")))
        }
    }
}

fn resolve_secret(
    t: &Translator<'_>,
    source: &SecretSource,
    purpose: &str,
    dataset: Option<&anvil_load::Dataset>,
    chain: bool,
) -> Result<Zeroizing<String>, Reason> {
    let real = |ctx: &ExecutionContext| Resolver::new(ctx.var_layers.clone(), None).with_secrets(ctx.secrets.clone());
    match source {
        SecretSource::VariableEntry { step, layer, var } => {
            let ctx = t.contexts[*step];
            let entry = &ctx.var_layers[*layer].vars[*var];
            let r = real(ctx);
            if !entry.literal {
                let raw =
                    r.variable_value(*layer, *var).map_err(|f| reason(None, "secret_unavailable", format!("{purpose}: {}", f.message)))?;
                if raw.contains("{{") {
                    validate_static_secret_template(t, *step, &raw, purpose, entry.secret, dataset, chain, true)?;
                }
            }
            r.resolve_entry(*layer, *var, "variables")
                .map(Zeroizing::new)
                .map_err(|f| reason(None, "secret_unavailable", format!("{purpose}: {}", f.message)))
        }
        SecretSource::Template { step, template } => {
            let ctx = t.contexts[*step];
            if template.contains("{{") {
                validate_static_secret_template(t, *step, template, purpose, true, dataset, chain, true)?;
            }
            real(ctx)
                .resolve(template, "credential")
                .map(Zeroizing::new)
                .map_err(|f| reason(None, "secret_unavailable", format!("{purpose}: {}", f.message)))
        }
        SecretSource::Vault { step, secret } => {
            t.contexts[*step].secrets.resolve(secret).map_err(|e| reason(None, "secret_unavailable", format!("{purpose}: {e}")))
        }
        SecretSource::Literal(value) => Ok(Zeroizing::new(value.clone())),
    }
}

/// Whether JMeter's HttpClient 4 sampler would rewrite an explicit static
/// `Host` header value (appending a non-default sampler port when the header
/// has no port, stripping an explicit default port `:80`/`:443`, or
/// normalizing non-canonical port text such as `:08080` or `:+8080`).
fn host_header_rewritten_by_hc4(raw: &str, scheme: &str, target_port: u16) -> bool {
    let s = raw.trim();
    if s.is_empty() {
        return true;
    }
    let parse_canonical_port = |p: &str| -> Option<u16> {
        let port = p.parse::<u16>().ok()?;
        (port.to_string() == p).then_some(port)
    };
    let explicit_port: Option<u16> = if let Some(rest) = s.strip_prefix('[') {
        let Some((_, after)) = rest.split_once(']') else { return true };
        if after.is_empty() {
            None
        } else if let Some(p) = after.strip_prefix(':') {
            let Some(port) = parse_canonical_port(p) else { return true };
            Some(port)
        } else {
            return true;
        }
    } else if let Some((_, p)) = s.split_once(':') {
        let Some(port) = parse_canonical_port(p) else { return true };
        Some(port)
    } else {
        None
    };
    let default_port = if scheme == "https" { 443 } else { 80 };
    match explicit_port {
        None => target_port != default_port,
        Some(p) => p == default_port,
    }
}

/// The dataset as CSV: a header row of the column names, every cell quoted.
fn dataset_to_csv(d: &anvil_load::Dataset) -> Vec<u8> {
    fn cell(s: &str) -> String {
        format!("\"{}\"", s.replace('"', "\"\""))
    }
    let mut out = String::new();
    out.push_str(&d.columns.iter().map(|c| cell(c)).collect::<Vec<_>>().join(","));
    out.push('\n');
    for row in &d.rows {
        out.push_str(&row.iter().map(|v| cell(v.as_deref().unwrap_or(""))).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out.into_bytes()
}
