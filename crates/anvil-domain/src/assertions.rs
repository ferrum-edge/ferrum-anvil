use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    #[default]
    Equals,
    NotEquals,
    Contains,
    NotContains,
    Matches,
    Exists,
    NotExists,
    LessThan,
    GreaterThan,
}

/// Declarative, no-code assertion. Assertion failures are reported separately
/// from transport and application failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AssertionKind {
    Status {
        comparison: Comparison,
        value: String,
    },
    StatusIn {
        values: Vec<u16>,
    },
    Header {
        name: String,
        comparison: Comparison,
        #[serde(default)]
        value: String,
    },
    Trailer {
        name: String,
        comparison: Comparison,
        #[serde(default)]
        value: String,
    },
    JsonPath {
        path: String,
        comparison: Comparison,
        #[serde(default)]
        value: String,
    },
    XPath {
        path: String,
        comparison: Comparison,
        #[serde(default)]
        value: String,
    },
    JsonSchema {
        schema: String,
    },
    Body {
        comparison: Comparison,
        #[serde(default)]
        value: String,
    },
    LatencyMs {
        max: u64,
    },
    GrpcStatus {
        code: i32,
    },
    MessageCount {
        comparison: Comparison,
        value: u64,
    },
    /// Assert the presence/absence of a diagnostic finding code.
    Diagnostic {
        code: String,
        present: bool,
    },
    /// Assert transport completion state (`completed`, `failed`, ...).
    Transport {
        state: String,
    },
    /// The response is a JSON-RPC error with this `code` (MCP, and any
    /// JSON-RPC API).
    JsonRpcError {
        code: i64,
    },
    /// The response is a JSON-RPC result, not an error.
    JsonRpcResult,
    /// MCP `tools/call`: the tool result's `isError` flag (absent = false).
    McpIsError {
        is_error: bool,
    },
    /// MCP `tools/list`: a tool with this name is listed.
    ToolPresent {
        name: String,
    },
    /// MCP `tools/list`: no tool with this name is listed.
    ToolAbsent {
        name: String,
    },
    /// MCP `tools/list`: the listed tool's `inputSchema` equals `schema`
    /// (JSON, compared as values) and/or its SHA-256 is `sha256` (lowercase
    /// hex of the schema's JSON with object keys sorted and no whitespace).
    ToolInputSchema {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Assertion {
    #[serde(default = "crate::request::default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(flatten)]
    pub kind: AssertionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AssertionResult {
    pub label: String,
    pub passed: bool,
    /// Redacted observed value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum ExtractionSource {
    JsonPath {
        path: String,
    },
    XPath {
        path: String,
    },
    Header {
        name: String,
    },
    Regex {
        pattern: String,
        #[serde(default)]
        group: usize,
    },
    Status,
}

/// Extract a response value into an iteration-local variable for chaining.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Extraction {
    pub variable: String,
    #[serde(flatten)]
    pub source: ExtractionSource,
    /// Treat the extracted value as sensitive (masked, redacted from reports).
    #[serde(default)]
    pub sensitive: bool,
}
