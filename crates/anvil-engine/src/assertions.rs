//! Declarative assertions and response extraction. Assertion results are a
//! separate outcome dimension from transport and application status.

use crate::redact::Redactor;
use anvil_domain::assertions::*;
use anvil_domain::diagnostics::DiagnosticFinding;
use anvil_domain::execution::{ResponseRecord, StreamTranscript};
use anvil_domain::outcome::{ProtocolStatus, TransportState};
use anvil_xml_limits::{XmlLimits, check_xml_limits};

/// XML nodes an XPath assertion or extraction parses. A response body can be
/// up to 256 MiB, and the parsed tree costs more than the text.
const XPATH_MAX_NODES: u32 = 4_000_000;
/// What a response body may contain before it is parsed for XPath. The
/// parser compares each attribute with every earlier one on its element,
/// names and full namespace URIs; for each element that declares a namespace
/// it copies the n in scope, checking each against those already copied
/// (about n²/2 prefix comparisons); and it looks every element and prefixed
/// attribute name up among the namespaces in scope. With these bounds a body
/// of any size stays under about 2^22 attribute comparisons of at most
/// 768 bytes, 2^25 prefix comparisons of at most 64 bytes while copying
/// scopes, 8192 · 128 = 2^20 copied namespace references, and 129 comparisons
/// per name looked up: about 1.6·10^9 for the at most 12 million names that
/// 4 million nodes and 2^22 attribute pairs allow. A service that declares
/// the same prefix again on many sibling elements costs little per element.
const XPATH_XML_LIMITS: XmlLimits = XmlLimits {
    attributes_per_element: 256,
    attribute_pairs: 1 << 22,
    attribute_name_bytes: 256,
    xmlns_declarations: 8_192,
    xmlns_prefix_bytes: 64,
    xmlns_uri_bytes: 512,
    in_scope_namespaces: 128,
    namespace_scope_work: 1 << 26,
};
/// How a body over those bounds is reported.
const TOO_COMPLEX: &str = "XML too complex to evaluate safely";

pub struct Observed<'a> {
    pub response: Option<&'a ResponseRecord>,
    pub body: &'a [u8],
    /// Why the body is not the complete decoded content (a capture cut short,
    /// or a truncated or failed content decoding). Assertions that read the
    /// body are then not evaluated rather than judged against a prefix or
    /// still-encoded bytes.
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

/// The elements an element step selects below `nodes`, in document order
/// without duplicates: each node has one parent, and the axis lists every
/// parent once.
fn xpath_elements<'a, 'i>(
    nodes: &[roxmltree::Node<'a, 'i>],
    descendant: bool,
    name: &str,
    position: Option<usize>,
) -> Vec<roxmltree::Node<'a, 'i>> {
    let mut next = Vec::new();
    for parent in xpath_axis(nodes, descendant) {
        let mut matched = parent.children().filter(|c| c.is_element() && (name == "*" || c.tag_name().name() == name));
        match position {
            Some(i) => next.extend(matched.nth(i - 1)),
            None => next.extend(matched),
        }
    }
    // Children of nested parents interleave.
    next.sort();
    next
}

/// XPath subset over a DTD-free parse, validated before the body is read:
/// `/a/b`, `//b`, `/a/b[2]`, `/a/*`, `/a/@attr`, `//@attr`, `/a/text()`.
/// Names match local names (namespace prefixes ignored). The result is the
/// first selected node in document order: an element's full text, an
/// attribute value or a text node. Any other syntax is an error, and so is a
/// body over `XPATH_XML_LIMITS` or `XPATH_MAX_NODES` ("XML too complex to
/// evaluate safely"), which is not parsed.
pub fn xpath(body: &[u8], path: &str) -> Result<Option<String>, String> {
    let steps = parse_xpath(path)?;
    let text = std::str::from_utf8(body).map_err(|_| "body is not UTF-8".to_string())?;
    // A malicious server controls the body: bound the parser's work before it
    // runs. The scan relies on DTDs being refused (it stops at a DOCTYPE).
    check_xml_limits(text, &XPATH_XML_LIMITS).map_err(|e| format!("{TOO_COMPLEX} ({e})"))?;
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: XPATH_MAX_NODES, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(text, opts).map_err(|e| match e {
        roxmltree::Error::NodesLimitReached => format!("{TOO_COMPLEX} (more than {XPATH_MAX_NODES} nodes)"),
        e => format!("body is not XML: {e}"),
    })?;
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
                nodes = xpath_elements(&nodes, descendant, name, position);
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
        K::JsonPath { .. }
        | K::XPath { .. }
        | K::JsonSchema { .. }
        | K::Body { .. }
        | K::JsonRpcError { .. }
        | K::JsonRpcResult
        | K::McpIsError { .. }
        | K::ToolPresent { .. }
        | K::ToolAbsent { .. }
        | K::ToolInputSchema { .. } => true,
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

/// The JSON-RPC response a body holds: an object with a `result` or an
/// `error` (an MCP execution evaluates the message it read from the POST's
/// event stream, see `crate::mcp`).
fn jsonrpc_response(body: &[u8]) -> Result<serde_json::Value, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("body is not JSON: {e}"))?;
    if v.get("result").is_none() && v.get("error").is_none() {
        return Err("the body is not a JSON-RPC response (it has no result or error)".into());
    }
    Ok(v)
}

/// At most this many characters of a server's JSON-RPC error message in an
/// assertion's actual value.
const MAX_ERROR_MESSAGE_CHARS: usize = 200;

/// `error <code>: <message>` or `result`, as an assertion's actual value.
fn jsonrpc_outcome(v: &serde_json::Value) -> String {
    match v.get("error") {
        Some(e) => {
            let code = e.get("code").map(|c| c.to_string()).unwrap_or_else(|| "without a code".into());
            let message: String = e.get("message").and_then(|m| m.as_str()).unwrap_or("").chars().take(MAX_ERROR_MESSAGE_CHARS).collect();
            if message.is_empty() { format!("error {code}") } else { format!("error {code}: {message}") }
        }
        None => "result".into(),
    }
}

/// The `result` of a JSON-RPC response, or why it has none.
fn jsonrpc_result(v: &serde_json::Value) -> Result<&serde_json::Value, String> {
    match v.get("result") {
        Some(r) if v.get("error").is_none() => Ok(r),
        _ => Err(format!("the response is a JSON-RPC {}, not a result", jsonrpc_outcome(v))),
    }
}

/// The tools of a `tools/list` result.
fn listed_tools(v: &serde_json::Value) -> Result<&Vec<serde_json::Value>, String> {
    let result = jsonrpc_result(v)?;
    result.get("tools").and_then(|t| t.as_array()).ok_or_else(|| "the result has no tools list (it is not a tools/list result)".into())
}

fn listed_tool<'a>(tools: &'a [serde_json::Value], name: &str) -> Option<&'a serde_json::Value> {
    tools.iter().find(|t| t.get("name").and_then(|n| n.as_str()) == Some(name))
}

/// SHA-256 (lowercase hex) of a JSON value with object keys sorted and no
/// whitespace: a tool `inputSchema` digest that does not depend on how the
/// server orders or spaces its JSON.
pub fn schema_sha256(v: &serde_json::Value) -> String {
    let mut text = String::new();
    canonical_json(v, &mut text);
    anvil_transport::certs::sha256_hex(text.as_bytes())
}

fn canonical_json(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String(k.clone()).to_string());
                out.push(':');
                canonical_json(&m[k.as_str()], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Whether the listed tool's `inputSchema` is `schema` (JSON, compared as
/// values) and/or has the digest `sha256`; the actual value is the digest.
fn tool_input_schema(body: &[u8], name: &str, schema: Option<&str>, sha256: Option<&str>) -> Result<(bool, Option<String>), String> {
    if schema.is_none() && sha256.is_none() {
        return Err("give the expected inputSchema or its sha256".into());
    }
    let v = jsonrpc_response(body)?;
    let tools = listed_tools(&v)?;
    let Some(tool) = listed_tool(tools, name) else { return Ok((false, Some("the tool is not listed".into()))) };
    let Some(actual) = tool.get("inputSchema") else { return Ok((false, Some("the tool has no inputSchema".into()))) };
    let digest = schema_sha256(actual);
    let mut passed = true;
    if let Some(expected) = schema {
        let expected: serde_json::Value = serde_json::from_str(expected).map_err(|e| format!("the expected schema is not JSON: {e}"))?;
        passed &= expected == *actual;
    }
    if let Some(expected) = sha256 {
        passed &= expected.trim().eq_ignore_ascii_case(&digest);
    }
    Ok((passed, Some(format!("sha256 {digest}"))))
}

fn body_not_available(reason: &str) -> String {
    format!("the complete response body is not available ({reason})")
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
                return Err(body_not_available(reason));
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
                AssertionKind::JsonRpcError { code } => {
                    let v = jsonrpc_response(o.body)?;
                    let actual = v.get("error").and_then(|e| e.get("code")).and_then(|c| c.as_i64());
                    (actual == Some(*code), Some(redactor.text(&jsonrpc_outcome(&v))))
                }
                AssertionKind::JsonRpcResult => {
                    let v = jsonrpc_response(o.body)?;
                    (v.get("result").is_some() && v.get("error").is_none(), Some(redactor.text(&jsonrpc_outcome(&v))))
                }
                AssertionKind::McpIsError { is_error } => {
                    let v = jsonrpc_response(o.body)?;
                    let flag = jsonrpc_result(&v)?.get("isError").and_then(|f| f.as_bool()).unwrap_or(false);
                    (flag == *is_error, Some(format!("isError {flag}")))
                }
                AssertionKind::ToolPresent { name } | AssertionKind::ToolAbsent { name } => {
                    let v = jsonrpc_response(o.body)?;
                    let tools = listed_tools(&v)?;
                    let listed = listed_tool(tools, name).is_some();
                    let wanted = matches!(a.kind, AssertionKind::ToolPresent { .. });
                    let actual = format!("{} (of {} listed tools)", if listed { "listed" } else { "not listed" }, tools.len());
                    (listed == wanted, Some(actual))
                }
                AssertionKind::ToolInputSchema { name, schema, sha256 } => {
                    tool_input_schema(o.body, name, schema.as_deref(), sha256.as_deref())?
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
        AssertionKind::JsonRpcError { code } => format!("JSON-RPC error {code}"),
        AssertionKind::JsonRpcResult => "JSON-RPC result".into(),
        AssertionKind::McpIsError { is_error } => format!("tool result isError = {is_error}"),
        AssertionKind::ToolPresent { name } => format!("tool {name} listed"),
        AssertionKind::ToolAbsent { name } => format!("tool {name} not listed"),
        AssertionKind::ToolInputSchema { name, .. } => format!("tool {name} inputSchema"),
    }
}

fn extraction_value(source: &ExtractionSource, response: Option<&ResponseRecord>, body: &[u8]) -> Result<Option<String>, String> {
    Ok(match source {
        ExtractionSource::JsonPath { path } => json_path(body, path)?,
        ExtractionSource::XPath { path } => xpath(body, path)?,
        ExtractionSource::Header { name } => response.and_then(|r| r.header_values(name).first().map(|s| s.to_string())),
        ExtractionSource::Regex { pattern, group } => {
            let re = regex::RegexBuilder::new(pattern).size_limit(1 << 20).build().map_err(|x| format!("invalid pattern: {x}"))?;
            let text = String::from_utf8_lossy(body);
            re.captures(&text).and_then(|c| c.get(*group)).map(|m| m.as_str().to_string())
        }
        ExtractionSource::Status => response.map(|r| r.status.to_string()),
    })
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
                return Err(format!("extraction for '{}' was not run: {}", e.variable, body_not_available(reason)));
            }
            // Name the variable: a run reports several extractions' errors together.
            let v = extraction_value(&e.source, response, body).map_err(|x| format!("extraction for '{}': {x}", e.variable))?;
            v.map(|v| (e.variable.clone(), v, e.sensitive)).ok_or_else(|| format!("extraction for '{}' matched nothing", e.variable))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(body: &str) -> Observed<'_> {
        Observed {
            response: None,
            body: body.as_bytes(),
            body_unavailable: None,
            latency_ms: None,
            protocol_status: &ProtocolStatus::None,
            stream: None,
            findings: &[],
            transport: TransportState::Completed,
        }
    }

    fn check(kind: AssertionKind, body: &str) -> AssertionResult {
        let a = Assertion { enabled: true, label: String::new(), kind };
        evaluate(&[a], &observed(body), &Redactor::default()).remove(0)
    }

    #[test]
    fn json_rpc_and_mcp_result_assertions() {
        let denied = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"MCP tool call denied by gateway policy"}}"#;
        let r = check(AssertionKind::JsonRpcError { code: -32001 }, denied);
        assert!(r.passed, "{r:?}");
        assert_eq!(r.actual.as_deref(), Some("error -32001: MCP tool call denied by gateway policy"));
        assert!(!check(AssertionKind::JsonRpcError { code: -32602 }, denied).passed);
        assert!(!check(AssertionKind::JsonRpcResult, denied).passed);
        let not_a_result = check(AssertionKind::McpIsError { is_error: false }, denied);
        assert!(!not_a_result.passed && not_a_result.message.starts_with("could not evaluate"), "{not_a_result:?}");

        let ok = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"hi"}],"structuredContent":{"text":"hi"}}}"#;
        assert!(check(AssertionKind::JsonRpcResult, ok).passed);
        assert!(!check(AssertionKind::JsonRpcError { code: -32001 }, ok).passed);
        assert!(check(AssertionKind::McpIsError { is_error: false }, ok).passed, "an absent isError is false");
        assert!(!check(AssertionKind::McpIsError { is_error: true }, ok).passed);
        let failed = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[],"isError":true}}"#;
        assert!(check(AssertionKind::McpIsError { is_error: true }, failed).passed);
        let structured = "$.result.structuredContent.text".to_string();
        let path = check(AssertionKind::JsonPath { path: structured, comparison: Comparison::Equals, value: "hi".into() }, ok);
        assert!(path.passed, "{path:?}");
        let plain = check(AssertionKind::JsonRpcResult, r#"{"ok":true}"#);
        assert!(!plain.passed && plain.message.contains("not a JSON-RPC response"), "{plain:?}");
    }

    #[test]
    fn tools_list_assertions() {
        let schema = serde_json::json!({"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]});
        let tool = serde_json::json!({"name": "fx.echo", "inputSchema": schema});
        let list = serde_json::json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [tool]}}).to_string();
        assert!(check(AssertionKind::ToolPresent { name: "fx.echo".into() }, &list).passed);
        assert!(!check(AssertionKind::ToolPresent { name: "fx.secret".into() }, &list).passed);
        assert!(check(AssertionKind::ToolAbsent { name: "fx.secret".into() }, &list).passed);
        let absent = check(AssertionKind::ToolAbsent { name: "fx.echo".into() }, &list);
        assert_eq!((absent.passed, absent.actual.as_deref()), (false, Some("listed (of 1 listed tools)")));

        // Key order and spacing do not change the digest; values do.
        let reordered = r#"{ "required": ["text"], "properties": {"text": {"type": "string"}}, "type": "object" }"#;
        let digest = schema_sha256(&serde_json::from_str(reordered).unwrap());
        assert_eq!(digest, schema_sha256(&schema));
        assert_ne!(digest, schema_sha256(&serde_json::json!({"type": "object"})));
        let sha = |s: &str| AssertionKind::ToolInputSchema { name: "fx.echo".into(), schema: None, sha256: Some(s.into()) };
        assert!(check(sha(&digest.to_uppercase()), &list).passed);
        assert!(!check(sha(&"0".repeat(64)), &list).passed);
        let same = AssertionKind::ToolInputSchema { name: "fx.echo".into(), schema: Some(reordered.into()), sha256: None };
        assert!(check(same, &list).passed);
        let other = AssertionKind::ToolInputSchema { name: "fx.echo".into(), schema: Some(r#"{"type":"object"}"#.into()), sha256: None };
        assert!(!check(other, &list).passed);
        let missing = AssertionKind::ToolInputSchema { name: "fx.nope".into(), schema: None, sha256: Some(digest.clone()) };
        assert_eq!(check(missing, &list).actual.as_deref(), Some("the tool is not listed"));
        let neither = check(AssertionKind::ToolInputSchema { name: "fx.echo".into(), schema: None, sha256: None }, &list);
        assert!(neither.message.contains("give the expected inputSchema"), "{neither:?}");
        let not_a_list = check(AssertionKind::ToolPresent { name: "x".into() }, r#"{"jsonrpc":"2.0","id":2,"result":{}}"#);
        assert!(not_a_list.message.contains("not a tools/list result"), "{not_a_list:?}");
    }

    #[test]
    fn a_json_rpc_error_message_is_redacted_in_the_actual_value() {
        let secret = "echoed-token-7Hq2";
        let body = format!(r#"{{"jsonrpc":"2.0","id":2,"error":{{"code":-32602,"message":"bad token {secret}"}}}}"#);
        let a = Assertion { enabled: true, label: String::new(), kind: AssertionKind::JsonRpcError { code: -32602 } };
        let r = evaluate(&[a], &observed(&body), &Redactor::new(vec![secret.into()], vec![])).remove(0);
        assert!(r.passed, "{r:?}");
        let actual = r.actual.unwrap_or_default();
        assert!(!actual.contains(secret) && actual.contains(anvil_domain::secret::REDACTED), "{actual}");
    }

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

    /// The `id` attributes of the elements `path` (element steps only) selects.
    fn selected_ids(xml: &str, path: &str) -> Vec<String> {
        let doc = roxmltree::Document::parse(xml).unwrap();
        let mut nodes = vec![doc.root()];
        for step in parse_xpath(path).unwrap() {
            let XStep::Element { descendant, name, position } = step else { panic!("{path}: element steps only") };
            nodes = xpath_elements(&nodes, descendant, name, position);
        }
        nodes.iter().map(|n| n.attribute("id").unwrap_or("?").to_string()).collect()
    }

    #[test]
    fn descendant_steps_select_each_element_once_in_document_order() {
        let xml = r#"<r id="r"><a id="a1"><a id="a2"><b id="b1"/></a><b id="b2"><b id="b3"/></b></a><b id="b4"/></r>"#;
        assert_eq!(selected_ids(xml, "//a//b"), ["b1", "b2", "b3"], "no element twice although a2 is inside a1");
        assert_eq!(selected_ids(xml, "//a"), ["a1", "a2"]);
        assert_eq!(selected_ids(xml, "//b"), ["b1", "b2", "b3", "b4"]);
        // `//` below an element selects its descendants, never the element itself.
        assert_eq!(selected_ids(r#"<b id="outer"><b id="inner"><b id="deepest"/></b></b>"#, "/b//b"), ["inner", "deepest"]);
    }

    /// GHSA-mvjp-hhjj-mh63: a body with the most namespace work the limits
    /// allow (the deepest chain of the longest prefixes, siblings until the
    /// scope budget is spent, and names the parser finds last in the scope)
    /// is evaluated, promptly.
    #[test]
    fn a_body_at_the_namespace_limits_is_evaluated_promptly() {
        let worst = anvil_xml_limits::test_support::namespace_worst_case(&XPATH_XML_LIMITS, 0, 100_000);
        let body = format!("<r>{worst}</r>");
        let started = std::time::Instant::now();
        assert_eq!(xpath(body.as_bytes(), "//e[100000]").unwrap().as_deref(), Some(""));
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "took {:?}", started.elapsed());
    }
}
