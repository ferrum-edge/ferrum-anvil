//! MCP "discover tools": run `tools/list` with a saved MCP request and save
//! one request per listed tool beside it (its URL, headers, auth, settings and
//! session options; arguments from each tool's `inputSchema`, see
//! `anvil_import::mcp`). The list is sent like any request (history per the
//! send options); nothing else is sent, and the saved requests are not run.

use crate::exec::SendOptions;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::request::{McpOperation, Protocol};
use anvil_domain::workspace::RequestDefinition;
use anvil_transport::recorder::EventCtx;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

/// What a discovery saved.
#[derive(Debug, Clone, Serialize)]
pub struct McpDiscovered {
    /// The saved requests, one per tool, in the order the server listed them.
    pub created: Vec<RequestDefinition>,
    /// Tools not saved, and why.
    pub skipped: Vec<String>,
    /// The server lists more tools than the first page (`nextCursor`); only
    /// the first page was read.
    pub more: bool,
    /// The execution that listed the tools (in history when it was recorded).
    pub execution_id: Id,
}

impl App {
    /// Discover the tools of the MCP endpoint `request_id` addresses (a saved
    /// MCP request of workspace `ws`) and save a request per tool in the same
    /// folder.
    pub async fn mcp_discover_tools(&self, ws: &Id, request_id: &Id, opts: SendOptions, cancel: CancellationToken) -> Result<McpDiscovered> {
        let template = self.request(request_id)?;
        if template.spec.protocol != Protocol::Mcp || template.spec.mcp.is_none() {
            return Err(AppError::Invalid(format!("'{}' is not an MCP request; tools are discovered with one", template.name)));
        }
        let mut list = template.spec.clone();
        if let Some(m) = list.mcp.as_mut() {
            m.operation = McpOperation::ToolsList { cursor: None };
        }
        list.assertions.clear();
        list.extractions.clear();
        let out = self.send(Some(*request_id), ws, Some(list), opts, EventCtx::none(), cancel).await?;
        let Some(message) = anvil_engine::mcp::operation_response(&out) else {
            return Err(AppError::Invalid(format!("tools/list got no JSON-RPC response: {}", out.record.outcome.summary)));
        };
        if let Some(e) = message.get("error") {
            let code = e.get("code").map(|c| c.to_string()).unwrap_or_default();
            return Err(AppError::Invalid(format!("tools/list was refused with JSON-RPC error {code}: {}", out.record.outcome.summary)));
        }
        let result = message.get("result").cloned().unwrap_or_default();
        let found = anvil_import::mcp::mcp_tool_requests(&template.spec, &result).map_err(AppError::Invalid)?;
        let mut created = Vec::with_capacity(found.tools.len());
        for t in found.tools {
            created.push(self.create_request(ws, template.folder_id, &t.name, t.spec)?);
        }
        Ok(McpDiscovered { created, skipped: found.skipped, more: found.more, execution_id: out.record.id })
    }
}
