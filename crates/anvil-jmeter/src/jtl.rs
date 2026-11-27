//! Import JMeter result files (JTL) into Anvil's load report model.
//!
//! Both JTL formats JMeter writes are read: CSV (with its header row, the
//! default) and XML. A result file is untrusted input:
//!
//! * **Bounded memory.** The file is streamed twice (a validating scan for
//!   the time span, then the aggregation), never loaded whole. Samples go
//!   into Anvil's mergeable HDR histograms and bounded maps; the timeline has
//!   at most 3,600 buckets, each with a small millisecond histogram for its
//!   percentiles (at most about 30 MiB in all).
//! * **Limits with clear errors.** Total size ([`JtlLimits::max_bytes`]),
//!   samples ([`JtlLimits::max_samples`]), one CSV record or one XML event
//!   ([`JtlLimits::max_record_bytes`], enforced while reading so a huge line
//!   or tag is refused before it is buffered) and XML nesting depth.
//! * **No entity expansion.** XML is read with a pull parser that processes
//!   no DTD; a `DOCTYPE` is refused outright, only the five predefined
//!   entities and character references are decoded, and any other entity
//!   reference is an error. External entities can therefore never be read.
//! * **Strict fields.** Timestamps must be millisecond epochs, elapsed times
//!   bounded, `success` a boolean; anything else is refused with the line or
//!   byte position, never guessed.
//!
//! Each top-level sample is one HTTP request unit. Its classification
//! follows Anvil's unit ledger: a 3-digit response code is a complete
//! response (a status of 400 or above is an application failure, a failed
//! assertion an assertion failure); no code (`Non HTTP response code: …`) is
//! a transport failure, or a timeout (censored) for a socket or connect
//! timeout. Failure examples hold only the sample label, the status or
//! exception class and the assertion name, never failure messages, which can
//! quote response bodies.

use anvil_domain::load::{
    CensoredTimeouts, ConnectionMode, GeneratorHealth, LoadCounts, LoadPlan, LoadReport, LoadUnitKind, RequestCounts, RunCompletion,
    TimeBucket, UnitSemantics, Workload,
};
use anvil_domain::{Id, Timestamp};
use anvil_load::metrics::{MAX_EXAMPLE_CHARS, Metrics, ProtoAccum, SendObservation, Terminal};
use hdrhistogram::Histogram;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

/// Earliest and latest accepted sample start (2000-01-01 and 2100-01-01, ms).
const MIN_TS_MS: i64 = 946_684_800_000;
const MAX_TS_MS: i64 = 4_102_444_800_000;
/// Longest accepted elapsed time of one sample (24 h, the longest Anvil run).
const MAX_ELAPSED_MS: u64 = 86_400_000;
const MAX_TIMELINE_BUCKETS: u64 = 3_600;
const MAX_FIELD_CHARS: usize = 1_024;
const MAX_SAMPLE_ATTRIBUTES: usize = 64;
/// Text kept from one captured element (assertion name, URL).
const MAX_CAPTURE_BYTES: usize = 8 * 1024;

/// Bounds on what one import reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JtlLimits {
    /// Size of the result file.
    pub max_bytes: u64,
    /// Top-level samples (requests).
    pub max_samples: u64,
    /// One CSV record, or one XML event (a tag with its attributes, or a text).
    pub max_record_bytes: u64,
    /// XML element nesting.
    pub max_depth: usize,
}

impl Default for JtlLimits {
    fn default() -> Self {
        JtlLimits { max_bytes: 4 * 1024 * 1024 * 1024, max_samples: 50_000_000, max_record_bytes: 1024 * 1024, max_depth: 32 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JtlFormat {
    Csv,
    Xml,
}

/// What an import needs besides the file.
#[derive(Debug, Clone)]
pub struct JtlOptions {
    pub workspace_id: Id,
    /// The Anvil plan the JMeter test plan was exported from, if known: the
    /// report carries it (and its warmup), so it compares with that plan's
    /// Anvil runs. Without one, the report describes only the result file.
    pub plan: Option<LoadPlan>,
    /// The file's name, for the report's notes.
    pub source_name: String,
    /// The JMeter version that produced the file (a JTL file does not record it).
    pub jmeter_version: Option<String>,
    /// Seconds from the first sample excluded from every summary metric
    /// (default: the plan's warmup, else 0).
    pub warmup_secs: Option<u64>,
    pub limits: JtlLimits,
}

#[derive(Debug, thiserror::Error)]
pub enum JtlError {
    #[error("the result file is larger than the {limit}-byte limit")]
    TooLarge { limit: u64 },
    #[error("the result file has more than {limit} samples (the import limit)")]
    TooManySamples { limit: u64 },
    #[error("{what} longer than the {limit}-byte limit (near byte {position})")]
    RecordTooLong { what: &'static str, limit: u64, position: u64 },
    #[error("not a valid JMeter result file: {0}")]
    Invalid(String),
    #[error("reading the result file: {0}")]
    Io(#[from] std::io::Error),
}

/// Which limit a [`Guard`] hit.
#[derive(Debug, Clone, Copy)]
enum Hit {
    Total,
    Record,
}

/// A reader that stops at the total size limit and at the per-record limit
/// (bytes read since the parser last called [`Guard::reset`]).
struct Guard<R> {
    inner: R,
    total: u64,
    since_reset: u64,
    max_total: u64,
    max_record: u64,
    hit: Option<Hit>,
}

impl<R> Guard<R> {
    fn new(inner: R, limits: &JtlLimits) -> Self {
        // A buffered parser reads ahead by one buffer; allow for it.
        Guard { inner, total: 0, since_reset: 0, max_total: limits.max_bytes, max_record: limits.max_record_bytes + 64 * 1024, hit: None }
    }

    fn reset(&mut self) {
        self.since_reset = 0;
    }
}

impl<R: Read> Read for Guard<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.total += n as u64;
        self.since_reset += n as u64;
        if self.total > self.max_total {
            self.hit = Some(Hit::Total);
            return Err(std::io::Error::other("result file size limit"));
        }
        if self.since_reset > self.max_record {
            self.hit = Some(Hit::Record);
            return Err(std::io::Error::other("record size limit"));
        }
        Ok(n)
    }
}

fn limit_error<R>(g: &Guard<R>, limits: &JtlLimits, what: &'static str) -> Option<JtlError> {
    match g.hit? {
        Hit::Total => Some(JtlError::TooLarge { limit: limits.max_bytes }),
        Hit::Record => Some(JtlError::RecordTooLong { what, limit: limits.max_record_bytes, position: g.total }),
    }
}

/// One top-level sample, validated.
#[derive(Debug, Clone, Default)]
struct Sample {
    ts: i64,
    elapsed: u64,
    label: String,
    code: String,
    success: bool,
    /// CSV `failureMessage` is non-empty.
    failure_message: bool,
    /// XML: the name of the first failed assertion.
    failed_assertion: Option<String>,
    bytes: u64,
    sent_bytes: u64,
    all_threads: u64,
    url: String,
}

fn bounded(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(MAX_FIELD_CHARS).collect()
}

fn parse_ts(v: &str, at: &str) -> Result<i64, JtlError> {
    let ts: i64 = v.trim().parse().map_err(|_| {
        JtlError::Invalid(format!(
            "{at}: the timestamp '{}' is not a millisecond epoch (JMeter writes one unless jmeter.save.saveservice.timestamp_format is changed; set it to ms)",
            bounded(v)
        ))
    })?;
    if !(MIN_TS_MS..=MAX_TS_MS).contains(&ts) {
        return Err(JtlError::Invalid(format!("{at}: the timestamp {ts} is not a millisecond epoch between 2000 and 2100")));
    }
    Ok(ts)
}

fn parse_elapsed(v: &str, at: &str) -> Result<u64, JtlError> {
    let e: u64 = v
        .trim()
        .parse()
        .map_err(|_| JtlError::Invalid(format!("{at}: the elapsed time '{}' is not a number of milliseconds", bounded(v))))?;
    if e > MAX_ELAPSED_MS {
        return Err(JtlError::Invalid(format!("{at}: the elapsed time {e} ms is longer than 24 hours")));
    }
    Ok(e)
}

fn parse_bool(v: &str, at: &str) -> Result<bool, JtlError> {
    match v.trim() {
        t if t.eq_ignore_ascii_case("true") => Ok(true),
        t if t.eq_ignore_ascii_case("false") => Ok(false),
        other => Err(JtlError::Invalid(format!("{at}: success is '{}', not true or false", bounded(other)))),
    }
}

fn parse_count(v: &str) -> u64 {
    v.trim().parse().unwrap_or(0)
}

fn check_http(url: &str, at: &str) -> Result<(), JtlError> {
    let u = url.trim();
    if u.is_empty() || u.starts_with("http://") || u.starts_with("https://") {
        Ok(())
    } else {
        Err(JtlError::Invalid(format!(
            "{at}: the sample's URL is '{}', not an HTTP URL; only HTTP sampler results can be imported (the report's unit is an HTTP request)",
            bounded(u)
        )))
    }
}

/// Stream the samples of a result file.
fn for_each_sample<R: Read>(
    r: R,
    format: JtlFormat,
    limits: &JtlLimits,
    f: &mut dyn FnMut(Sample) -> Result<(), JtlError>,
) -> Result<Stats, JtlError> {
    match format {
        JtlFormat::Csv => csv_samples(r, limits, f),
        JtlFormat::Xml => xml_samples(r, limits, f),
    }
}

/// What a pass counted besides the samples it handed over.
#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    /// XML sub-results (redirects, embedded resources) not counted as requests.
    sub_results: u64,
}

fn csv_samples<R: Read>(r: R, limits: &JtlLimits, f: &mut dyn FnMut(Sample) -> Result<(), JtlError>) -> Result<Stats, JtlError> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(false).from_reader(Guard::new(r, limits));
    let headers = match rdr.headers().cloned() {
        Ok(h) => h,
        Err(e) => {
            return Err(limit_error(rdr.get_ref(), limits, "the CSV header row")
                .unwrap_or_else(|| JtlError::Invalid(format!("the CSV header row: {e}"))));
        }
    };
    let col = |name: &str| headers.iter().position(|h| h.trim() == name);
    let required = |name: &str| {
        col(name).ok_or_else(|| {
            JtlError::Invalid(format!(
                "the CSV header has no '{name}' column; import a JTL written with JMeter's default CSV fields (with field names, jmeter.save.saveservice.print_field_names=true)"
            ))
        })
    };
    let (c_ts, c_elapsed, c_label, c_code, c_success) =
        (required("timeStamp")?, required("elapsed")?, required("label")?, required("responseCode")?, required("success")?);
    let (c_failure, c_bytes, c_sent, c_threads, c_url) =
        (col("failureMessage"), col("bytes"), col("sentBytes"), col("allThreads"), col("URL"));
    let mut record = csv::StringRecord::new();
    let mut line = 1u64;
    loop {
        rdr.get_mut().reset();
        match rdr.read_record(&mut record) {
            Ok(false) => break,
            Ok(true) => {}
            Err(e) => {
                return Err(limit_error(rdr.get_ref(), limits, "a CSV record").unwrap_or_else(|| match e.kind() {
                    csv::ErrorKind::Utf8 { .. } => JtlError::Invalid(format!("the CSV record after line {line} is not UTF-8")),
                    csv::ErrorKind::UnequalLengths { .. } => {
                        JtlError::Invalid(format!("the CSV record after line {line} does not have the header's {} fields", headers.len()))
                    }
                    _ => JtlError::Invalid(format!("the CSV record after line {line}: {e}")),
                }));
            }
        }
        line = record.position().map(|p| p.line()).unwrap_or(line + 1);
        let at = format!("CSV line {line}");
        let get = |c: Option<usize>| c.and_then(|c| record.get(c)).unwrap_or("");
        let url = get(c_url);
        check_http(url, &at)?;
        f(Sample {
            ts: parse_ts(get(Some(c_ts)), &at)?,
            elapsed: parse_elapsed(get(Some(c_elapsed)), &at)?,
            label: bounded(get(Some(c_label))),
            code: bounded(get(Some(c_code))),
            success: parse_bool(get(Some(c_success)), &at)?,
            failure_message: !get(c_failure).trim().is_empty(),
            failed_assertion: None,
            bytes: parse_count(get(c_bytes)),
            sent_bytes: parse_count(get(c_sent)),
            all_threads: parse_count(get(c_threads)),
            url: bounded(url),
        })?;
    }
    Ok(Stats::default())
}

/// The text of the assertion child element being read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Name,
    Failure,
    Error,
    Url,
}

fn xml_samples<R: Read>(r: R, limits: &JtlLimits, f: &mut dyn FnMut(Sample) -> Result<(), JtlError>) -> Result<Stats, JtlError> {
    use quick_xml::events::{BytesStart, Event};
    let mut reader = quick_xml::Reader::from_reader(BufReader::new(Guard::new(r, limits)));
    {
        let c = reader.config_mut();
        // Captured text (an assertion name) keeps its spaces around entity
        // references, which arrive as separate events.
        c.trim_text_start = false;
        c.trim_text_end = false;
        c.check_end_names = true;
        c.expand_empty_elements = false;
    }
    let mut stats = Stats::default();
    let mut buf = Vec::new();
    let mut depth = 0usize;
    let mut root = false;
    let mut current: Option<Sample> = None;
    // Inside the current sample: an assertion result (name, failed), a
    // field being read, and the depth of a skipped sub-result subtree.
    let mut assertion: Option<(String, bool)> = None;
    let mut field: Option<(Field, String)> = None;
    let mut sub_depth: Option<usize> = None;

    fn attrs(e: &BytesStart<'_>, at: &str) -> Result<Sample, JtlError> {
        let mut s = Sample::default();
        let (mut ts, mut t, mut ok, mut lb, mut rc) = (None, None, None, None, None);
        // Bounded before each duplicate check (which compares an attribute
        // with every earlier one): JMeter writes about fifteen.
        for (i, a) in e.attributes().enumerate() {
            if i >= MAX_SAMPLE_ATTRIBUTES {
                return Err(JtlError::Invalid(format!("{at}: the sample has more than {MAX_SAMPLE_ATTRIBUTES} attributes")));
            }
            let a = a.map_err(|x| JtlError::Invalid(format!("{at}: attribute: {x}")))?;
            let v = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|x| JtlError::Invalid(format!("{at}: attribute value: {x}")))?;
            let key: &str = a.key.as_ref();
            match key {
                "ts" => ts = Some(parse_ts(&v, at)?),
                "t" => t = Some(parse_elapsed(&v, at)?),
                "s" => ok = Some(parse_bool(&v, at)?),
                "lb" => lb = Some(bounded(&v)),
                "rc" => rc = Some(bounded(&v)),
                "by" => s.bytes = parse_count(&v),
                "sby" => s.sent_bytes = parse_count(&v),
                "na" => s.all_threads = parse_count(&v),
                _ => {}
            }
        }
        let missing = |n: &str| JtlError::Invalid(format!("{at}: the sample has no '{n}' attribute"));
        s.ts = ts.ok_or_else(|| missing("ts"))?;
        s.elapsed = t.ok_or_else(|| missing("t"))?;
        s.success = ok.ok_or_else(|| missing("s"))?;
        s.label = lb.ok_or_else(|| missing("lb"))?;
        s.code = rc.ok_or_else(|| missing("rc"))?;
        Ok(s)
    }

    loop {
        reader.get_mut().get_mut().reset();
        let pos = reader.buffer_position();
        let at = format!("XML byte {pos}");
        let event = match reader.read_event_into(&mut buf) {
            Ok(e) => e,
            Err(e) => {
                let g = reader.get_ref().get_ref();
                return Err(limit_error(g, limits, "an XML element or text").unwrap_or_else(|| JtlError::Invalid(format!("{at}: {e}"))));
            }
        };
        match event {
            Event::Eof => break,
            Event::DocType(_) => {
                return Err(JtlError::Invalid(
                    "the file has a DOCTYPE: JMeter result files never have one, and document type definitions (and their entities) are refused".into(),
                ));
            }
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Start(e) => {
                depth += 1;
                if depth > limits.max_depth {
                    return Err(JtlError::Invalid(format!("{at}: elements nest deeper than {}", limits.max_depth)));
                }
                let qn = e.name();
                let name: &str = qn.as_ref();
                open(
                    name,
                    &e,
                    false,
                    depth,
                    &at,
                    &mut root,
                    &mut current,
                    &mut assertion,
                    &mut field,
                    &mut sub_depth,
                    &mut stats,
                    f,
                    attrs,
                )?;
            }
            Event::Empty(e) => {
                let qn = e.name();
                let name: &str = qn.as_ref();
                open(
                    name,
                    &e,
                    true,
                    depth + 1,
                    &at,
                    &mut root,
                    &mut current,
                    &mut assertion,
                    &mut field,
                    &mut sub_depth,
                    &mut stats,
                    f,
                    attrs,
                )?;
            }
            Event::End(_) => {
                if let Some(d) = sub_depth {
                    if depth == d {
                        sub_depth = None;
                    }
                } else if let Some((which, text)) = field.take() {
                    match (which, assertion.as_mut(), current.as_mut()) {
                        (Field::Name, Some(a), _) => a.0 = bounded(&text),
                        (Field::Failure | Field::Error, Some(a), _) => a.1 |= text.trim().eq_ignore_ascii_case("true"),
                        (Field::Url, _, Some(s)) => s.url = bounded(&text),
                        _ => {}
                    }
                } else if depth == 3 && assertion.is_some() {
                    let (name, failed) = assertion.take().unwrap_or_default();
                    if failed && let Some(s) = current.as_mut() {
                        s.failed_assertion.get_or_insert(if name.is_empty() { "assertion".into() } else { name });
                    }
                } else if depth == 2
                    && let Some(s) = current.take()
                {
                    check_http(&s.url, &at)?;
                    f(s)?;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Text(t) => {
                if let Some((_, text)) = field.as_mut() {
                    let raw: &str = &t;
                    capture(text, raw);
                } else if depth <= 1 && !t.trim().is_empty() {
                    return Err(JtlError::Invalid(format!("{at}: text outside the samples")));
                }
            }
            Event::CData(t) => {
                if let Some((_, text)) = field.as_mut() {
                    let raw: &str = &t;
                    capture(text, raw);
                }
            }
            Event::GeneralRef(r) => {
                let resolved: String = if r.is_char_ref() {
                    match r.resolve_char_ref() {
                        Ok(Some(c)) => c.to_string(),
                        _ => return Err(JtlError::Invalid(format!("{at}: an invalid character reference"))),
                    }
                } else {
                    let name: &str = &r;
                    match quick_xml::escape::resolve_predefined_entity(name) {
                        Some(v) => v.to_string(),
                        None => {
                            return Err(JtlError::Invalid(format!(
                                "{at}: the entity &{};, which is not predefined; entities are never expanded",
                                bounded(name)
                            )));
                        }
                    }
                };
                if let Some((_, text)) = field.as_mut() {
                    capture(text, &resolved);
                }
            }
        }
        buf.clear();
    }
    if !root {
        return Err(JtlError::Invalid("the file has no <testResults> element".into()));
    }
    Ok(stats)
}

/// Append captured text, keeping at most [`MAX_CAPTURE_BYTES`].
fn capture(text: &mut String, more: &str) {
    for c in more.chars() {
        if text.len() + c.len_utf8() > MAX_CAPTURE_BYTES {
            return;
        }
        text.push(c);
    }
}

/// A start (or empty) tag at `depth` (1 = the root).
#[allow(clippy::too_many_arguments)]
fn open(
    name: &str,
    e: &quick_xml::events::BytesStart<'_>,
    empty: bool,
    depth: usize,
    at: &str,
    root: &mut bool,
    current: &mut Option<Sample>,
    assertion: &mut Option<(String, bool)>,
    field: &mut Option<(Field, String)>,
    sub_depth: &mut Option<usize>,
    stats: &mut Stats,
    f: &mut dyn FnMut(Sample) -> Result<(), JtlError>,
    attrs: fn(&quick_xml::events::BytesStart<'_>, &str) -> Result<Sample, JtlError>,
) -> Result<(), JtlError> {
    if sub_depth.is_some() {
        return Ok(());
    }
    match depth {
        1 => {
            if name != "testResults" {
                return Err(JtlError::Invalid(format!("{at}: the root element is <{}>, not <testResults>", bounded(name))));
            }
            *root = true;
        }
        2 => match name {
            "httpSample" => {
                let s = attrs(e, at)?;
                if empty {
                    check_http(&s.url, at)?;
                    f(s)?;
                } else {
                    *current = Some(s);
                }
            }
            "sample" => {
                return Err(JtlError::Invalid(format!(
                    "{at}: a non-HTTP sample (<sample>); only HTTP sampler results can be imported (the report's unit is an HTTP request)"
                )));
            }
            other => return Err(JtlError::Invalid(format!("{at}: unexpected element <{}> among the samples", bounded(other)))),
        },
        _ if current.is_none() => {}
        3 => match name {
            "httpSample" | "sample" => {
                stats.sub_results += 1;
                if !empty {
                    *sub_depth = Some(depth);
                }
            }
            "assertionResult" if !empty => *assertion = Some((String::new(), false)),
            "java.net.URL" if !empty => *field = Some((Field::Url, String::new())),
            _ => {}
        },
        4 if assertion.is_some() && !empty => {
            *field = match name {
                "name" => Some((Field::Name, String::new())),
                "failure" => Some((Field::Failure, String::new())),
                "error" => Some((Field::Error, String::new())),
                _ => None,
            };
        }
        _ => {}
    }
    Ok(())
}

/// The origin (`scheme://host[:port]`) of a sample URL, without path, query
/// or user information.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    (!host.is_empty()).then(|| format!("{}://{host}", scheme.to_ascii_lowercase()))
}

/// The exception class JMeter names in a non-HTTP response code.
fn exception(code: &str) -> String {
    let c = code.trim();
    let c = c.strip_prefix("Non HTTP response code:").unwrap_or(c).trim();
    let name: String = c.chars().take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '$')).take(120).collect();
    if name.is_empty() { "unknown".into() } else { name }
}

fn http_status(code: &str) -> Option<u16> {
    let c = code.trim();
    if c.len() == 3 && c.bytes().all(|b| b.is_ascii_digit()) { c.parse::<u16>().ok().filter(|s| (100..=599).contains(s)) } else { None }
}

fn example(s: &Sample, what: &str) -> String {
    let e = format!("{} → {what}", s.label);
    e.chars().take(MAX_EXAMPLE_CHARS).collect()
}

/// The unit observation for one sample (Anvil's unit ledger rules).
fn observe(s: &Sample) -> SendObservation {
    let mut o = SendObservation {
        latency_us: s.elapsed.saturating_mul(1000),
        bytes_sent: s.sent_bytes,
        bytes_received: s.bytes,
        protocol: Some("http/1.1".into()),
        destination: origin(&s.url),
        ..Default::default()
    };
    match http_status(&s.code) {
        Some(status) => {
            o.terminal = Terminal::Completed;
            o.status = Some(status);
            o.application_failure = status >= 400;
            o.assertion_failure = !s.success && (s.failed_assertion.is_some() || s.failure_message);
            if !s.success && !o.application_failure && !o.assertion_failure {
                // JMeter judged it failed without saying why.
                o.application_failure = true;
                o.category = Some("application_failure: JMeter marked the sample failed".into());
                o.example = Some(example(s, &format!("{status}, marked failed by JMeter")));
            } else if o.assertion_failure {
                let name = s.failed_assertion.clone().unwrap_or_else(|| "JMeter assertion".into());
                o.category = Some(format!("assertion_failure: {}", bounded(&name)));
                o.example = Some(example(s, &format!("{status}, assertion '{}' failed", bounded(&name))));
            } else if o.application_failure {
                o.category = Some(format!("application_failure: http {status}"));
                o.example = Some(example(s, &status.to_string()));
            }
        }
        None => {
            let ex = exception(&s.code);
            let timeout =
                ex.contains("SocketTimeoutException") || ex.contains("ConnectTimeoutException") || ex.contains("TimeoutException");
            o.terminal = if timeout { Terminal::Timeout } else { Terminal::TransportFailure };
            o.category = Some(format!("{}: {ex}", if timeout { "timeout" } else { "transport_failure" }));
            o.example = Some(example(s, &ex));
        }
    }
    o
}

struct Bucket {
    started: u64,
    completed: u64,
    failures: u64,
    in_flight: u64,
    /// Success latency in milliseconds + 1 (so 0 ms is recordable).
    hist: Option<Histogram<u32>>,
}

/// What the first pass learned.
#[derive(Debug, Default, Clone, Copy)]
struct Span {
    samples: u64,
    first_ts: i64,
    last_end: i64,
    max_threads: u64,
}

/// Import a JMeter result file (CSV or XML JTL) as an Anvil load report.
/// The reader is read twice (it must seek), never more than the limits.
pub fn import_jtl<R: Read + Seek>(mut r: R, opts: &JtlOptions) -> Result<LoadReport, JtlError> {
    let limits = &opts.limits;
    let len = r.seek(SeekFrom::End(0))?;
    if len > limits.max_bytes {
        return Err(JtlError::TooLarge { limit: limits.max_bytes });
    }
    if len == 0 {
        return Err(JtlError::Invalid("the file is empty".into()));
    }
    r.seek(SeekFrom::Start(0))?;
    let format = detect(&mut r)?;
    r.seek(SeekFrom::Start(0))?;

    // ---- pass 1: validate and find the time span ----
    let mut span = Span { first_ts: i64::MAX, last_end: i64::MIN, ..Default::default() };
    for_each_sample(&mut r, format, limits, &mut |s: Sample| {
        span.samples += 1;
        if span.samples > limits.max_samples {
            return Err(JtlError::TooManySamples { limit: limits.max_samples });
        }
        span.first_ts = span.first_ts.min(s.ts);
        span.last_end = span.last_end.max(s.ts + s.elapsed as i64);
        span.max_threads = span.max_threads.max(s.all_threads);
        Ok(())
    })?;
    if span.samples == 0 {
        return Err(JtlError::Invalid("the file holds no samples".into()));
    }

    // ---- pass 2: aggregate ----
    r.seek(SeekFrom::Start(0))?;
    let warmup_secs = opts.warmup_secs.or(opts.plan.as_ref().map(|p| p.warmup_secs)).unwrap_or(0);
    let t0 = span.first_ts;
    let warmup_end = t0.saturating_add((warmup_secs as i64).saturating_mul(1000));
    let span_secs = ((span.last_end - t0).max(1) as u64).div_ceil(1000);
    let width = span_secs.div_ceil(MAX_TIMELINE_BUCKETS).max(1);
    let n_buckets = span_secs.div_ceil(width).max(1) as usize;
    let mut buckets: Vec<Bucket> =
        (0..n_buckets).map(|_| Bucket { started: 0, completed: 0, failures: 0, in_flight: 0, hist: None }).collect();
    let bucket_of = |ts: i64| (((ts - t0).max(0) as u64 / 1000 / width) as usize).min(n_buckets - 1);
    let mut metrics = Metrics::new();
    let mut req = RequestCounts::default();
    let mut warmup_sends = 0u64;
    let mut seen = 0u64;
    let stats = for_each_sample(&mut r, format, limits, &mut |s: Sample| {
        seen += 1;
        if seen > span.samples {
            return Err(JtlError::Invalid("the file changed while it was imported".into()));
        }
        let o = observe(&s);
        let end = s.ts + s.elapsed as i64;
        buckets[bucket_of(s.ts)].started += 1;
        let b = &mut buckets[bucket_of(end)];
        b.completed += u64::from(o.terminal == Terminal::Completed);
        b.failures += u64::from(o.is_failure());
        b.in_flight = b.in_flight.max(s.all_threads);
        if o.is_success() {
            let h = b.hist.get_or_insert_with(|| Histogram::new_with_bounds(1, 86_400_001, 2).expect("static histogram bounds are valid"));
            h.saturating_record(s.elapsed + 1);
        }
        if s.ts < warmup_end {
            warmup_sends += 1;
            return Ok(());
        }
        metrics.record(&o);
        req.started += 1;
        match o.terminal {
            Terminal::Completed => {
                req.completed += 1;
                req.application_failures += u64::from(o.application_failure);
                req.assertion_failures += u64::from(o.assertion_failure);
            }
            Terminal::TransportFailure => req.transport_failures += 1,
            Terminal::Timeout => req.timeouts += 1,
            Terminal::Canceled => req.canceled += 1,
        }
        Ok(())
    })?;
    if seen != span.samples {
        return Err(JtlError::Invalid("the file changed while it was imported".into()));
    }
    Ok(assemble(opts, format, span, stats, warmup_secs, warmup_end, width, buckets, metrics, req, warmup_sends))
}

fn detect<R: Read>(r: &mut R) -> Result<JtlFormat, JtlError> {
    let mut head = [0u8; 4096];
    let mut n = 0;
    while n < head.len() {
        let k = r.read(&mut head[n..])?;
        if k == 0 {
            break;
        }
        n += k;
    }
    let mut s = &head[..n];
    if s.starts_with(&[0xEF, 0xBB, 0xBF]) {
        s = &s[3..];
    }
    let first = s.iter().find(|b| !b.is_ascii_whitespace());
    Ok(if first == Some(&b'<') { JtlFormat::Xml } else { JtlFormat::Csv })
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    opts: &JtlOptions,
    format: JtlFormat,
    span: Span,
    stats: Stats,
    warmup_secs: u64,
    warmup_end: i64,
    width: u64,
    buckets: Vec<Bucket>,
    metrics: Metrics,
    req: RequestCounts,
    warmup_sends: u64,
) -> LoadReport {
    let now = Timestamp::now();
    let plan = opts.plan.clone().unwrap_or_else(|| LoadPlan {
        id: Id::new(),
        workspace_id: opts.workspace_id,
        name: format!("JMeter results: {}", bounded(&opts.source_name)),
        workload: Workload::Iterations { iterations: span.samples.max(1), concurrency: span.max_threads.max(1) },
        chain: vec![],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: ConnectionMode::Persistent,
        warmup_secs,
        abort: None,
        seed: 0,
        trusted: false,
        created_at: now,
        updated_at: now,
    });
    let version = opts.jmeter_version.as_deref().map(bounded).filter(|v| !v.is_empty()).unwrap_or_else(|| "unrecorded".into());
    let format_name = match format {
        JtlFormat::Csv => "csv",
        JtlFormat::Xml => "xml",
    };
    let timeline: Vec<TimeBucket> = buckets
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            let q = |p: f64| b.hist.as_ref().map(|h| h.value_at_quantile(p).saturating_sub(1).saturating_mul(1000)).unwrap_or(0);
            let second = i as u64 * width;
            TimeBucket {
                second,
                started: b.started,
                completed: b.completed,
                failures: b.failures,
                dropped: 0,
                p50_us: q(0.5),
                p99_us: q(0.99),
                in_flight: b.in_flight,
                warmup: second < warmup_secs,
                p99_schedule_lag_us: 0,
            }
        })
        .collect();
    let measured_from = warmup_end.max(span.first_ts);
    let measured_duration_secs = ((span.last_end - measured_from).max(0)) as f64 / 1000.0;
    let rate = if measured_duration_secs > 0.0 { req.started as f64 / measured_duration_secs } else { 0.0 };
    let counts = LoadCounts {
        scheduled: req.started,
        started: req.started,
        dropped: 0,
        completed: req.completed,
        transport_failures: req.transport_failures,
        application_failures: req.application_failures,
        assertion_failures: req.assertion_failures,
        timeouts: req.timeouts,
        canceled: req.canceled,
        in_flight_at_end: 0,
    };
    let mut protocol = ProtoAccum::new().summary(LoadUnitKind::HttpRequest, plan.connection_mode, &[]);
    protocol.semantics = UnitSemantics {
        unit_singular: "request".into(),
        unit_plural: "requests".into(),
        completed_means: "JMeter recorded an HTTP status code for the sample (any status).".into(),
        success_means: "JMeter marked the sample successful (status below 400, every assertion passed); a status of 400 or above is an application failure."
            .into(),
        latency_means: "JMeter's elapsed time per sample, from connecting to the last byte (redirects included), in whole milliseconds.".into(),
        connection_mode_means: "JMeter's own connection handling (HttpClient 4, connections per thread); not measured by Anvil.".into(),
    };
    let censored = metrics.censored.summary();
    let mut notes = vec![
        format!(
            "Imported from the JMeter result file '{}' ({} JTL, {} samples). Engine: Apache JMeter {version}. Measured by JMeter, not Anvil: latencies are JMeter's elapsed times in whole milliseconds, and there is no setup time, generator health or connection evidence.",
            bounded(&opts.source_name),
            format_name.to_uppercase(),
            span.samples
        ),
        format!(
            "Unit: HTTP request — every count, rate and latency is per JMeter sample. Completed: {} Success: {}",
            protocol.semantics.completed_means, protocol.semantics.success_means
        ),
        "Iterations: a JMeter result file records samples, not iterations, so the iteration counts repeat the request counts (a chain's iterations are not reconstructed).".into(),
        "In flight per timeline bucket is JMeter's active thread count (allThreads), not a count of requests in flight.".into(),
        "JMeter and Anvil measure and classify differently, so their metrics are not automatically comparable as identical: a comparison with an Anvil run lists the engine as a difference and withholds latency deltas.".into(),
    ];
    if stats.sub_results > 0 {
        notes.push(format!(
            "{} sub-result(s) (redirects or embedded resources) were not counted: each top-level sample is one request.",
            stats.sub_results
        ));
    }
    if warmup_secs > 0 {
        notes.push(format!(
            "Warmup: samples that started in the first {warmup_secs} s ({warmup_sends} sample(s)) are excluded from every summary metric; the timeline shows them flagged."
        ));
    }
    if opts.plan.is_none() {
        notes.push(format!(
            "No Anvil plan was named: the plan in this report only describes the result file ({} samples, up to {} concurrent JMeter threads).",
            span.samples,
            span.max_threads.max(1)
        ));
    }
    if req.timeouts > 0 {
        notes.push(format!("{} request(s) timed out. {}", req.timeouts, anvil_load::report::CENSORED_LABEL));
    }
    let workload_label = match &opts.plan {
        Some(p) => format!("Run by Apache JMeter from this plan: {}", anvil_load::report::workload_label(&p.workload)),
        None => "Run by Apache JMeter; the workload is not known from the result file.".into(),
    };
    let mut report = LoadReport {
        run_id: Id::new(),
        schema_version: anvil_load::report::REPORT_SCHEMA_VERSION,
        engine: crate::ENGINE_NAME.into(),
        engine_version: format!("jmeter/{version}+jtl-{format_name}"),
        plan,
        request_revisions: vec![],
        dataset_sha256: None,
        started_at: Timestamp::from_unix_millis(span.first_ts).unwrap_or(now),
        finished_at: Timestamp::from_unix_millis(span.last_end).unwrap_or(now),
        completion: RunCompletion::Completed,
        partial: false,
        warmup_included_in_metrics: false,
        destination_summary: metrics.destinations.iter().cloned().collect(),
        counts,
        achieved_rate_per_sec: rate,
        latency_success: metrics.success.summary(),
        latency_failure: metrics.failure.summary(),
        histogram_success_b64: metrics.success.to_b64(),
        status_distribution: metrics.status.iter().map(|(k, v)| (*k, *v)).collect(),
        failure_categories: metrics.failure_samples(),
        timeline,
        bytes_sent: metrics.bytes_sent,
        bytes_received: metrics.bytes_received,
        generator: GeneratorHealth {
            peak_cpu_percent: None,
            peak_rss_bytes: None,
            peak_open_fds: None,
            max_schedule_lag_us: 0,
            p99_schedule_lag_us: 0,
            target_not_achieved: false,
            notes: vec!["Generator health was not measured: JMeter generated the load.".into()],
        },
        notes,
        requests: req,
        workload_label,
        offered_rate_per_sec: None,
        measured_duration_secs,
        timeouts_censored: CensoredTimeouts {
            count: censored.count,
            deadline_ms_min: None,
            deadline_ms_max: None,
            elapsed_at_timeout: censored,
            label: anvil_load::report::CENSORED_LABEL.into(),
        },
        latency_setup: Default::default(),
        histogram_failure_b64: metrics.failure.to_b64(),
        protocols: metrics.protocols.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        warmup_iterations_excluded: warmup_sends,
        warmup_sends_excluded: warmup_sends,
        protocol_metrics: Some(protocol),
        integrity_sha256: None,
    };
    anvil_load::report::seal(&mut report);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_drop_paths_queries_and_user_information() {
        assert_eq!(origin("http://127.0.0.1:8080/a?b=c").as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(origin("HTTPS://u:p@api.example.test/x").as_deref(), Some("https://api.example.test"));
        assert_eq!(origin("null"), None);
    }

    #[test]
    fn exception_names_come_from_the_non_http_code() {
        assert_eq!(exception("Non HTTP response code: java.net.ConnectException"), "java.net.ConnectException");
        assert_eq!(
            exception("Non HTTP response code: java.net.SocketTimeoutException/Non HTTP response message: Read timed out"),
            "java.net.SocketTimeoutException"
        );
        assert_eq!(http_status("200"), Some(200));
        assert_eq!(http_status("20"), None);
        assert_eq!(http_status("700"), None);
    }
}
