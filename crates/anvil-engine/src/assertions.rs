//! Declarative assertions and response extraction. Assertion results are a
//! separate outcome dimension from transport and application status.

use crate::redact::Redactor;
use anvil_domain::assertions::*;
use anvil_domain::diagnostics::DiagnosticFinding;
use anvil_domain::execution::{ResponseRecord, StreamTranscript};
use anvil_domain::outcome::{ProtocolStatus, TransportState};

pub struct Observed<'a> {
    pub response: Option<&'a ResponseRecord>,
    pub body: &'a [u8],
    /// Why the body is not the complete decoded content (a truncated or
    /// failed content decoding). Assertions that read the body are then not
    /// evaluated rather than judged against a prefix or still-encoded bytes.
    pub body_unavailable: Option<&'a str>,
    pub latency_ms: Option<u64>,
    pub protocol_status: &'a ProtocolStatus,
    pub stream: Option<&'a StreamTranscript>,
    pub findings: &'a [DiagnosticFinding],
    pub transport: TransportState,
}

fn compare(c: Comparison, actual: Option<&str>, expected: &str) -> Result<bool, String> {
    Ok(match c {
        Comparison::Exists => actual.is_some(),
        Comparison::NotExists => actual.is_none(),
        Comparison::Equals => actual == Some(expected),
        Comparison::NotEquals => actual != Some(expected),
        Comparison::Contains => actual.map(|a| a.contains(expected)).unwrap_or(false),
        Comparison::NotContains => !actual.map(|a| a.contains(expected)).unwrap_or(false),
        Comparison::Matches => {
            let re = regex::RegexBuilder::new(expected).size_limit(1 << 20).build().map_err(|e| format!("invalid pattern: {e}"))?;
            actual.map(|a| re.is_match(a)).unwrap_or(false)
        }
        Comparison::LessThan | Comparison::GreaterThan => {
            let (Some(a), Ok(e)) = (actual.and_then(|a| a.trim().parse::<f64>().ok()), expected.trim().parse::<f64>()) else {
                return Ok(false);
            };
            if c == Comparison::LessThan { a < e } else { a > e }
        }
    })
}

pub fn json_path(body: &[u8], path: &str) -> Result<Option<String>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("body is not JSON: {e}"))?;
    let p = serde_json_path::JsonPath::parse(path).map_err(|e| format!("invalid JSONPath: {e}"))?;
    let nodes = p.query(&v).all();
    Ok(match nodes.as_slice() {
        [] => None,
        [one] => Some(match one {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        }),
        many => Some(serde_json::Value::Array(many.iter().map(|x| (*x).clone()).collect()).to_string()),
    })
}

/// One location step of the supported XPath subset. `descendant` is true
/// after `//` (descendant-or-self of the context, then the step).
#[derive(Debug)]
enum XStep<'a> {
    /// Child elements by local name (`*` for any), optionally only the n-th
    /// matching child of each parent (1-based).
    Element { descendant: bool, name: &'a str, position: Option<usize> },
    /// `@name`: the attribute of the selected elements. Last step only.
    Attribute { descendant: bool, name: &'a str },
    /// `text()`: the text-node children of the selected elements. Last step only.
    Text { descendant: bool },
}

/// Parse the whole path up front: anything outside the subset is an error,
/// never a step that silently selects more (or other) nodes.
fn parse_xpath(path: &str) -> Result<Vec<XStep<'_>>, String> {
    let mut rest = path.trim();
    if !rest.starts_with('/') {
        return Err("XPath must start with / or //".into());
    }
    let mut steps = Vec::new();
    while !rest.is_empty() {
        if matches!(steps.last(), Some(XStep::Attribute { .. } | XStep::Text { .. })) {
            return Err("XPath: @attribute and text() must be the last step".into());
        }
        let descendant = rest.starts_with("//");
        rest = &rest[if descendant { 2 } else { 1 }..];
        let (step, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        rest = tail;
        if step.is_empty() {
            return Err(format!("XPath has an empty step in '{path}'"));
        }
        if step == "text()" || step.starts_with('@') {
            if steps.is_empty() && !descendant {
                return Err(format!("XPath step '/{step}' must follow an element step"));
            }
            steps.push(match step.strip_prefix('@') {
                Some(attr) => XStep::Attribute { descendant, name: xpath_name(attr)? },
                None => XStep::Text { descendant },
            });
            continue;
        }
        let (name, position) = match step.split_once('[') {
            None if step.contains(']') => return Err(format!("XPath step '{step}' has an unbalanced ']'")),
            None => (step, None),
            Some((name, predicate)) => {
                let Some(inner) = predicate.strip_suffix(']') else {
                    return Err(format!("XPath step '{step}' has a malformed predicate (expected it to end with ']')"));
                };
                if inner.contains(['[', ']']) {
                    return Err(format!("XPath step '{step}': only one predicate per step is supported"));
                }
                let inner = inner.trim();
                if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("XPath predicate '[{inner}]' is not supported; only a position such as [1] or [2] is"));
                }
                let n: usize = inner.parse().map_err(|_| format!("XPath position [{inner}] is too large"))?;
                if n == 0 {
                    return Err("XPath positions start at 1; [0] never selects anything".into());
                }
                (name, Some(n))
            }
        };
        let name = if name == "*" { name } else { xpath_name(name)? };
        steps.push(XStep::Element { descendant, name, position });
    }
    Ok(steps)
}

/// A (possibly prefixed) XML name reduced to its local name; prefixes are
/// ignored because the subset matches local names only.
fn xpath_name(name: &str) -> Result<&str, String> {
    let is_name = |s: &str| {
        let mut chars = s.chars();
        chars.next().is_some_and(|c| c.is_alphabetic() || c == '_') && chars.all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
    };
    let local = match name.split_once(':') {
        Some((prefix, local)) if is_name(prefix) => local,
        Some(_) => "",
        None => name,
    };
    if is_name(local) { Ok(local) } else { Err(format!("XPath step '{name}' is not supported")) }
}

/// The nodes a step starts from: the context itself, or after `//` every
/// node below it too. `nodes` is in document order without duplicates, and
/// so is the result.
fn xpath_axis<'a, 'i>(nodes: &[roxmltree::Node<'a, 'i>], descendant: bool) -> Vec<roxmltree::Node<'a, 'i>> {
    if !descendant {
        return nodes.to_vec();
    }
    // A context inside an earlier context's subtree adds nothing; skipping it
    // keeps nested contexts linear, and the disjoint subtrees stay in order.
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for n in nodes {
        if !seen.contains(n) {
            for d in n.descendants() {
                seen.insert(d);
                out.push(d);
            }
        }
    }
    out
}

/// XPath subset over a DTD-free parse, validated before the body is read:
/// `/a/b`, `//b`, `/a/b[2]`, `/a/*`, `/a/@attr`, `//@attr`, `/a/text()`.
/// Names match local names (namespace prefixes ignored). The result is the
/// first selected node in document order: an element's full text, an
/// attribute value or a text node. Any other syntax is an error.
pub fn xpath(body: &[u8], path: &str) -> Result<Option<String>, String> {
    let steps = parse_xpath(path)?;
    let text = std::str::from_utf8(body).map_err(|_| "body is not UTF-8".to_string())?;
    let doc = roxmltree::Document::parse_with_options(text, roxmltree::ParsingOptions { allow_dtd: false, ..Default::default() })
        .map_err(|e| format!("body is not XML: {e}"))?;
    let mut nodes: Vec<roxmltree::Node> = vec![doc.root()];
    for step in steps {
        match step {
            XStep::Text { descendant } => {
                let first = xpath_axis(&nodes, descendant).into_iter().flat_map(|n| n.children()).filter(|c| c.is_text()).min();
                return Ok(first.map(|t| t.text().unwrap_or("").to_string()));
            }
            XStep::Attribute { descendant, name } => {
                let mut owners = xpath_axis(&nodes, descendant).into_iter();
                return Ok(owners.find_map(|n| n.attributes().find(|a| a.name() == name).map(|a| a.value().to_string())));
            }
            XStep::Element { descendant, name, position } => {
                let mut next = Vec::new();
                for parent in xpath_axis(&nodes, descendant) {
                    let mut matched = parent.children().filter(|c| c.is_element() && (name == "*" || c.tag_name().name() == name));
                    match position {
                        Some(i) => next.extend(matched.nth(i - 1)),
                        None => next.extend(matched),
                    }
                }
                // Children of nested parents interleave.
                next.sort();
                nodes = next;
                if nodes.is_empty() {
                    return Ok(None);
                }
            }
        }
    }
    Ok(nodes.first().map(|n| n.descendants().filter(|d| d.is_text()).map(|d| d.text().unwrap_or("")).collect::<String>()))
}

/// Exhaustive so a new assertion kind has to decide whether it reads the body.
fn reads_body(k: &AssertionKind) -> bool {
    use AssertionKind as K;
    match k {
        K::JsonPath { .. } | K::XPath { .. } | K::JsonSchema { .. } | K::Body { .. } => true,
        K::Status { .. }
        | K::StatusIn { .. }
        | K::Header { .. }
        | K::Trailer { .. }
        | K::LatencyMs { .. }
        | K::GrpcStatus { .. }
        | K::MessageCount { .. }
        | K::Diagnostic { .. }
        | K::Transport { .. } => false,
    }
}

fn not_fully_decoded(reason: &str) -> String {
    format!("the response body was not fully decoded ({reason})")
}

/// Comparisons and validation use the original values; only the evidence a
/// result carries (label, actual value, messages) is redacted, since results
/// are persisted in the execution record and printed by the CLI.
pub fn evaluate(assertions: &[Assertion], o: &Observed<'_>, redactor: &Redactor) -> Vec<AssertionResult> {
    let mut out = Vec::new();
    for a in assertions.iter().filter(|a| a.enabled) {
        let label = if a.label.is_empty() { default_label(&a.kind) } else { a.label.clone() };
        let label = redactor.text(&label);
        let res: Result<(bool, Option<String>), String> = (|| {
            if let Some(reason) = o.body_unavailable
                && reads_body(&a.kind)
            {
                return Err(not_fully_decoded(reason));
            }
            Ok(match &a.kind {
                AssertionKind::Status { comparison, value } => {
                    let s = o.response.map(|r| r.status.to_string());
                    (compare(*comparison, s.as_deref(), value)?, s)
                }
                AssertionKind::StatusIn { values } => {
                    let s = o.response.map(|r| r.status);
                    (s.map(|s| values.contains(&s)).unwrap_or(false), s.map(|s| s.to_string()))
                }
                AssertionKind::Header { name, comparison, value } => {
                    let v = o.response.and_then(|r| r.header_values(name).first().map(|s| s.to_string()));
                    (compare(*comparison, v.as_deref(), value)?, v.map(|x| redactor.header(name, &x)))
                }
                AssertionKind::Trailer { name, comparison, value } => {
                    let v = o.response.and_then(|r| r.trailer_values(name).first().map(|s| s.to_string()));
                    (compare(*comparison, v.as_deref(), value)?, v.map(|x| redactor.header(name, &x)))
                }
                AssertionKind::JsonPath { path, comparison, value } => {
                    let v = json_path(o.body, path)?;
                    (compare(*comparison, v.as_deref(), value)?, v.map(|x| redactor.text(&x)))
                }
                AssertionKind::XPath { path, comparison, value } => {
                    let v = xpath(o.body, path)?;
                    (compare(*comparison, v.as_deref(), value)?, v.map(|x| redactor.text(&x)))
                }
                AssertionKind::JsonSchema { schema } => {
                    let schema: serde_json::Value = serde_json::from_str(schema).map_err(|e| format!("schema is not JSON: {e}"))?;
                    let instance: serde_json::Value = serde_json::from_slice(o.body).map_err(|e| format!("body is not JSON: {e}"))?;
                    let validator = jsonschema::validator_for(&schema).map_err(|e| format!("invalid schema: {e}"))?;
                    let errors: Vec<String> =
                        validator.iter_errors(&instance).take(5).map(|e| format!("{} at {}", e, e.instance_path())).collect();
                    // Validator messages quote the offending instance values.
                    (errors.is_empty(), if errors.is_empty() { None } else { Some(redactor.text(&errors.join("; "))) })
                }
                AssertionKind::Body { comparison, value } => {
                    let text = String::from_utf8_lossy(o.body);
                    (compare(*comparison, Some(&text), value)?, None)
                }
                AssertionKind::LatencyMs { max } => {
                    (o.latency_ms.map(|l| l <= *max).unwrap_or(false), o.latency_ms.map(|l| format!("{l} ms")))
                }
                AssertionKind::GrpcStatus { code } => match o.protocol_status {
                    ProtocolStatus::Grpc { grpc_status, .. } => (*grpc_status == Some(*code), grpc_status.map(|g| g.to_string())),
                    _ => (false, Some("not a gRPC call".into())),
                },
                AssertionKind::MessageCount { comparison, value } => {
                    let n = o.stream.map(|s| s.received_count);
                    (compare(*comparison, n.map(|n| n.to_string()).as_deref(), &value.to_string())?, n.map(|n| n.to_string()))
                }
                AssertionKind::Diagnostic { code, present } => {
                    let found = o.findings.iter().any(|f| f.code == *code || f.code.starts_with(&format!("{code}.")));
                    (found == *present, Some(if found { "present".into() } else { "absent".into() }))
                }
                AssertionKind::Transport { state } => {
                    let actual = serde_json::to_value(o.transport).ok().and_then(|v| v.as_str().map(|s| s.to_string())).unwrap_or_default();
                    (actual.eq_ignore_ascii_case(state), Some(actual))
                }
            })
        })();
        // Evaluation errors can quote the body or the assertion's own values.
        let res = res.map_err(|e| redactor.text(&e));
        match res {
            Ok((passed, actual)) => out.push(AssertionResult {
                label: label.clone(),
                passed,
                actual: actual.clone(),
                message: if passed { "passed".into() } else { format!("failed (actual: {})", actual.unwrap_or_else(|| "none".into())) },
            }),
            Err(e) => out.push(AssertionResult { label, passed: false, actual: None, message: format!("could not evaluate: {e}") }),
        }
    }
    out
}

fn default_label(k: &AssertionKind) -> String {
    match k {
        AssertionKind::Status { comparison, value } => format!("status {comparison:?} {value}"),
        AssertionKind::StatusIn { values } => format!("status in {values:?}"),
        AssertionKind::Header { name, comparison, value } => format!("header {name} {comparison:?} {value}"),
        AssertionKind::Trailer { name, comparison, value } => format!("trailer {name} {comparison:?} {value}"),
        AssertionKind::JsonPath { path, comparison, value } => format!("{path} {comparison:?} {value}"),
        AssertionKind::XPath { path, comparison, value } => format!("{path} {comparison:?} {value}"),
        AssertionKind::JsonSchema { .. } => "body matches JSON Schema".into(),
        AssertionKind::Body { comparison, value } => format!("body {comparison:?} {value}"),
        AssertionKind::LatencyMs { max } => format!("latency ≤ {max} ms"),
        AssertionKind::GrpcStatus { code } => format!("grpc-status = {code}"),
        AssertionKind::MessageCount { comparison, value } => format!("messages {comparison:?} {value}"),
        AssertionKind::Diagnostic { code, present } => format!("diagnostic {code} {}", if *present { "present" } else { "absent" }),
        AssertionKind::Transport { state } => format!("transport {state}"),
    }
}

/// Run extractions; returns (variable, value, sensitive). With
/// `body_unavailable` set, extractions that read the body fail instead of
/// matching against a prefix or still-encoded bytes.
pub fn extract(
    extractions: &[Extraction],
    response: Option<&ResponseRecord>,
    body: &[u8],
    body_unavailable: Option<&str>,
) -> Vec<Result<(String, String, bool), String>> {
    extractions
        .iter()
        .map(|e| {
            if let Some(reason) = body_unavailable
                && matches!(e.source, ExtractionSource::JsonPath { .. } | ExtractionSource::XPath { .. } | ExtractionSource::Regex { .. })
            {
                return Err(format!("extraction for '{}' was not run: {}", e.variable, not_fully_decoded(reason)));
            }
            let v = match &e.source {
                ExtractionSource::JsonPath { path } => json_path(body, path)?,
                ExtractionSource::XPath { path } => xpath(body, path)?,
                ExtractionSource::Header { name } => response.and_then(|r| r.header_values(name).first().map(|s| s.to_string())),
                ExtractionSource::Regex { pattern, group } => {
                    let re = regex::RegexBuilder::new(pattern).size_limit(1 << 20).build().map_err(|x| format!("invalid pattern: {x}"))?;
                    let text = String::from_utf8_lossy(body);
                    re.captures(&text).and_then(|c| c.get(*group)).map(|m| m.as_str().to_string())
                }
                ExtractionSource::Status => response.map(|r| r.status.to_string()),
            };
            v.map(|v| (e.variable.clone(), v, e.sensitive)).ok_or_else(|| format!("extraction for '{}' matched nothing", e.variable))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonpath_and_xpath_subset() {
        let body = br#"{"items":[{"id":7,"name":"a"},{"id":9}],"token":"t"}"#;
        assert_eq!(json_path(body, "$.items[0].id").unwrap().as_deref(), Some("7"));
        assert_eq!(json_path(body, "$.token").unwrap().as_deref(), Some("t"));
        assert_eq!(json_path(body, "$.missing").unwrap(), None);
        let xml = br#"<s:Envelope xmlns:s="x"><s:Body><r a="1"><v>one</v><v>two</v></r></s:Body></s:Envelope>"#;
        assert_eq!(xpath(xml, "//v[2]").unwrap().as_deref(), Some("two"));
        assert_eq!(xpath(xml, "/Envelope/Body/r/@a").unwrap().as_deref(), Some("1"));
    }
}
