//! MCP tool discovery ("discover tools"): turn a `tools/list` result into
//! one request per tool, each calling its tool with arguments taken from the
//! tool's `inputSchema`.
//!
//! The result comes from a server over the network, so it is untrusted: a
//! tool whose name holds `{{` (which the variable resolver would read as a
//! reference, sending a variable's value back to the server) is skipped, and
//! `{{` in generated arguments is written as a JSON escape, so it reaches
//! the tool as the text it listed and is never resolved. Bounded: at most
//! [`MAX_DISCOVERED_TOOLS`] tools, arguments sampled to
//! [`MAX_SAMPLE_DEPTH`] levels.

use anvil_domain::assertions::{Assertion, AssertionKind};
use anvil_domain::request::{McpOperation, Protocol, RequestSpec};
use serde_json::{Map, Value};

/// Most tools one discovery saves.
pub const MAX_DISCOVERED_TOOLS: usize = 500;
/// Deepest nested object an argument sample fills in.
pub const MAX_SAMPLE_DEPTH: usize = 8;
/// Longest request name taken from a tool's title or name.
const MAX_NAME_CHARS: usize = 120;

/// Where a tool request's arguments came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentSource {
    /// The schema's first `examples` entry for the whole arguments object.
    Example,
    /// Per-property examples, defaults, constants or enum values, with
    /// blank values for required properties that have none.
    Sampled,
    /// No property has an example or a default: only blank required values.
    Blank,
}

/// One tool's request.
#[derive(Debug, Clone)]
pub struct DiscoveredTool {
    /// The tool's name, as `tools/call` sends it.
    pub tool: String,
    /// The request's name: the tool's title, else its name.
    pub name: String,
    pub spec: RequestSpec,
    pub arguments: ArgumentSource,
}

/// What a `tools/list` result yields.
#[derive(Debug, Clone, Default)]
pub struct McpDiscovery {
    pub tools: Vec<DiscoveredTool>,
    /// Tools not saved, and why (no usable name, or over the bound).
    pub skipped: Vec<String>,
    /// The result has a `nextCursor`: the server lists more tools than this
    /// page holds.
    pub more: bool,
}

/// The requests for the tools of a `tools/list` `result`, made from
/// `template` (the MCP request that listed them: its URL, headers, auth,
/// settings and session options). Each calls its tool and checks that the
/// answer is a JSON-RPC result the tool did not mark as an error.
pub fn mcp_tool_requests(template: &RequestSpec, result: &Value) -> Result<McpDiscovery, String> {
    if template.protocol != Protocol::Mcp || template.mcp.is_none() {
        return Err("tools are discovered with an MCP request".into());
    }
    let Some(tools) = result.get("tools").and_then(Value::as_array) else {
        return Err("the tools/list result has no tools list".into());
    };
    let mut d = McpDiscovery { more: result.get("nextCursor").is_some_and(|c| !c.is_null()), ..Default::default() };
    for (i, t) in tools.iter().enumerate() {
        let Some(tool) = t.get("name").and_then(Value::as_str).map(str::trim).filter(|n| !n.is_empty()) else {
            d.skipped.push(format!("tool {i}: it has no name"));
            continue;
        };
        if tool.contains("{{") || tool.contains("}}") || tool.chars().any(char::is_control) {
            d.skipped.push(format!("tool {i}: its name holds '{{{{', '}}}}' or a control character, which Anvil would not send as listed"));
            continue;
        }
        if d.tools.len() >= MAX_DISCOVERED_TOOLS {
            d.skipped.push(format!("{}: more than {MAX_DISCOVERED_TOOLS} tools", display_name(tool)));
            continue;
        }
        let schema = t.get("inputSchema").cloned().unwrap_or(Value::Null);
        let (arguments, source) = sample_arguments(&schema);
        let mut spec = template.clone();
        if let Some(m) = spec.mcp.as_mut() {
            m.operation = McpOperation::ToolsCall { name: tool.to_string(), arguments: arguments_text(&arguments) };
        }
        spec.assertions = vec![check(AssertionKind::JsonRpcResult), check(AssertionKind::McpIsError { is_error: false })];
        spec.extractions = vec![];
        spec.source = None;
        let title = t.get("title").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).unwrap_or(tool);
        d.tools.push(DiscoveredTool { tool: tool.to_string(), name: display_name(title), spec, arguments: source });
    }
    Ok(d)
}

fn check(kind: AssertionKind) -> Assertion {
    Assertion { enabled: true, label: String::new(), kind }
}

/// A server-chosen name as a request name: no control characters, cut.
fn display_name(s: &str) -> String {
    let name: String = s.chars().filter(|c| !c.is_control()).take(MAX_NAME_CHARS).collect();
    name.trim().to_string()
}

/// The arguments as the request's JSON text: `{{` is written `{{`, so
/// the variable resolver leaves it as the text the tool listed.
fn arguments_text(v: &Value) -> String {
    let text = serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into());
    // In JSON, `{{` can only occur inside a string, where the escape reads the same.
    text.replace("{{", "{\\u007b")
}

/// Arguments for a tool: its schema's first example of the whole object,
/// else a sample of its properties.
pub fn sample_arguments(schema: &Value) -> (Value, ArgumentSource) {
    if let Some(ex) = schema.get("examples").and_then(Value::as_array).and_then(|a| a.first()).filter(|e| e.is_object()) {
        return (ex.clone(), ArgumentSource::Example);
    }
    let mut explicit = false;
    let v = sample_object(schema, 0, &mut explicit);
    (v, if explicit { ArgumentSource::Sampled } else { ArgumentSource::Blank })
}

/// A value the schema names itself: an example, a default, a constant or an
/// enum's first value.
fn named_value(schema: &Value) -> Option<Value> {
    let first = |k: &str| schema.get(k).and_then(Value::as_array).and_then(|a| a.first()).cloned();
    first("examples")
        .or_else(|| schema.get("example").cloned())
        .or_else(|| schema.get("default").cloned())
        .or_else(|| schema.get("const").cloned())
        .or_else(|| first("enum"))
}

/// The object's properties that are required or name a value, in schema
/// order. `explicit` is set when any value came from the schema.
fn sample_object(schema: &Value, depth: usize, explicit: &mut bool) -> Value {
    let mut out = Map::new();
    let Some(props) = schema.get("properties").and_then(Value::as_object) else { return Value::Object(out) };
    if depth >= MAX_SAMPLE_DEPTH {
        return Value::Object(out);
    }
    let required = schema.get("required").and_then(Value::as_array);
    let required: Vec<&str> = required.map(|r| r.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    for (name, prop) in props {
        if let Some(v) = named_value(prop) {
            *explicit = true;
            out.insert(name.clone(), v);
        } else if required.contains(&name.as_str()) {
            out.insert(name.clone(), blank(prop, depth + 1, explicit));
        }
    }
    Value::Object(out)
}

/// A blank value of the schema's type (an object's required members filled
/// in the same way).
fn blank(schema: &Value, depth: usize, explicit: &mut bool) -> Value {
    let kind = match schema.get("type") {
        Some(Value::String(t)) => t.as_str(),
        // A union: its first type that is not null.
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).find(|t| *t != "null").unwrap_or("null"),
        _ if schema.get("properties").is_some() => "object",
        _ => "",
    };
    match kind {
        "object" => sample_object(schema, depth, explicit),
        "array" => Value::Array(vec![]),
        "string" => Value::String(String::new()),
        "integer" | "number" => Value::from(0),
        "boolean" => Value::Bool(false),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn template() -> RequestSpec {
        let mut spec = RequestSpec::http("POST", "https://gw.example/mcp");
        spec.protocol = Protocol::Mcp;
        spec.mcp = Some(serde_json::from_value(json!({"operation": {"kind": "tools_list"}})).unwrap());
        spec
    }

    fn arguments(d: &DiscoveredTool) -> Value {
        match &d.spec.mcp.as_ref().unwrap().operation {
            McpOperation::ToolsCall { arguments, .. } => serde_json::from_str(arguments).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn one_request_per_tool_with_arguments_from_the_schema() {
        let result = json!({"tools": [
            {"name": "echo", "title": "Echo", "inputSchema": {"type": "object",
                "properties": {"text": {"type": "string", "examples": ["hello"]}, "loud": {"type": "boolean"}}, "required": ["text"]}},
            {"name": "add", "inputSchema": {"type": "object", "examples": [{"a": 1, "b": 2}], "properties": {"a": {"type": "number"}}}},
            {"name": "search", "inputSchema": {"type": "object", "required": ["q", "filter", "limit"], "properties": {
                "q": {"type": "string"}, "limit": {"type": ["integer", "null"]},
                "filter": {"type": "object", "required": ["tags"], "properties": {
                    "tags": {"type": "array"}, "mode": {"enum": ["any", "all"]}}}}}},
            {"name": "noop"}
        ], "nextCursor": "page-2"});
        let d = mcp_tool_requests(&template(), &result).unwrap();
        assert!(d.more && d.skipped.is_empty(), "{d:?}");
        let names: Vec<(&str, &str)> = d.tools.iter().map(|t| (t.tool.as_str(), t.name.as_str())).collect();
        assert_eq!(names, [("echo", "Echo"), ("add", "add"), ("search", "search"), ("noop", "noop")]);
        assert_eq!((arguments(&d.tools[0]), d.tools[0].arguments), (json!({"text": "hello"}), ArgumentSource::Sampled));
        assert_eq!((arguments(&d.tools[1]), d.tools[1].arguments), (json!({"a": 1, "b": 2}), ArgumentSource::Example));
        let search = json!({"q": "", "limit": 0, "filter": {"tags": [], "mode": "any"}});
        assert_eq!((arguments(&d.tools[2]), d.tools[2].arguments), (search, ArgumentSource::Sampled));
        assert_eq!((arguments(&d.tools[3]), d.tools[3].arguments), (json!({}), ArgumentSource::Blank));
        for t in &d.tools {
            assert_eq!(t.spec.url, "https://gw.example/mcp", "the template's endpoint");
            let kinds: Vec<&AssertionKind> = t.spec.assertions.iter().map(|a| &a.kind).collect();
            assert_eq!(kinds, [&AssertionKind::JsonRpcResult, &AssertionKind::McpIsError { is_error: false }]);
        }
    }

    #[test]
    fn a_listed_variable_reference_is_never_resolved() {
        let result = json!({"tools": [
            {"name": "leak{{api_token}}", "inputSchema": {}},
            {"name": "", "inputSchema": {}},
            {"name": "echo", "inputSchema": {"type": "object", "properties": {"text": {"default": "{{api_token}} and {{{x}}}"}}}}
        ]});
        let d = mcp_tool_requests(&template(), &result).unwrap();
        assert_eq!(d.skipped.len(), 2, "{:?}", d.skipped);
        assert_eq!(d.tools.len(), 1);
        let McpOperation::ToolsCall { arguments: text, .. } = &d.tools[0].spec.mcp.as_ref().unwrap().operation else { panic!() };
        assert!(!text.contains("{{"), "{text}");
        assert_eq!(arguments(&d.tools[0]), json!({"text": "{{api_token}} and {{{x}}}"}), "the tool gets the text it listed");
    }

    #[test]
    fn only_mcp_requests_and_tools_lists_discover_tools() {
        assert!(mcp_tool_requests(&RequestSpec::http("GET", "https://x/"), &json!({"tools": []})).is_err());
        assert!(mcp_tool_requests(&template(), &json!({"resources": []})).is_err());
        let mut deep = json!({"type": "string"});
        for _ in 0..20 {
            deep = json!({"type": "object", "required": ["n"], "properties": {"n": deep}});
        }
        let (v, _) = sample_arguments(&deep);
        let mut depth = 0;
        let mut at = &v;
        while let Some(next) = at.get("n") {
            depth += 1;
            at = next;
        }
        assert!(depth <= MAX_SAMPLE_DEPTH, "{depth}");
    }
}
