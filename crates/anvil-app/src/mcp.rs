//! MCP "discover tools": run `tools/list` with a saved MCP request and save
//! one request per listed tool beside it (its URL, headers, auth, settings and
//! session options; arguments from each tool's `inputSchema`, see
//! `anvil_import::mcp`). Every page the server lists is read, following
//! `nextCursor`, each page sent like any request (history per the send
//! options); nothing else is sent, and the saved requests are not run.
//! Bounded: at most [`MAX_DISCOVERY_PAGES`] pages, and no page after
//! [`anvil_import::mcp::MAX_DISCOVERED_TOOLS`] tools were listed. A cursor is
//! sent back only when it is plain text: a server's cursor holding `{{` would
//! otherwise be read as a variable reference, sending a variable's value back
//! to the server.

use crate::exec::SendOptions;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::request::{McpOperation, Protocol};
use anvil_domain::workspace::RequestDefinition;
use anvil_engine::ExecutionOutput;
use anvil_import::mcp::MAX_DISCOVERED_TOOLS;
use anvil_transport::recorder::EventCtx;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use tokio_util::sync::CancellationToken;

/// Most `tools/list` pages one discovery reads.
pub const MAX_DISCOVERY_PAGES: usize = 50;
/// Longest `nextCursor` sent back.
const MAX_CURSOR_BYTES: usize = 4096;

/// What a discovery saved.
#[derive(Debug, Clone, Serialize)]
pub struct McpDiscovered {
    /// The saved requests, one per tool, in the order the server listed them.
    pub created: Vec<RequestDefinition>,
    /// Tools not saved, and why (the first few).
    pub skipped: Vec<String>,
    /// Every tool not saved.
    pub skipped_total: usize,
    /// What was changed from a listed schema (the first few), e.g. examples
    /// too large to use as arguments.
    pub notes: Vec<String>,
    /// Every note.
    pub notes_total: usize,
    /// The `tools/list` pages read.
    pub pages: usize,
    /// Why pages the server listed were left unread (the page bound, enough
    /// tools listed already, a cursor Anvil does not send back, a repeated
    /// cursor, or a later page that failed); `None` when every page was read.
    pub stopped: Option<String>,
    /// The execution that listed the first page (in history when it was
    /// recorded).
    pub execution_id: Id,
}

/// The `result` of a `tools/list` page, or why there is none.
fn page_result(out: &ExecutionOutput) -> std::result::Result<Value, String> {
    let Some(message) = anvil_engine::mcp::operation_response(out) else {
        return Err(format!("tools/list got no JSON-RPC response: {}", out.record.outcome.summary));
    };
    if let Some(e) = message.get("error") {
        let code = e.get("code").and_then(|c| c.as_i64()).map_or_else(|| "(not an integer)".to_string(), |c| c.to_string());
        return Err(format!("tools/list was refused with JSON-RPC error {code}: {}", out.record.outcome.summary));
    }
    Ok(message.get("result").cloned().unwrap_or_default())
}

/// The cursor of the next page, `Ok(None)` after the last page, or why the
/// cursor is not sent back.
fn next_cursor(result: &Value) -> std::result::Result<Option<String>, String> {
    match result.get("nextCursor") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(c)) if c.is_empty() || c.len() > MAX_CURSOR_BYTES || c.chars().any(char::is_control) => Err(format!(
            "the server's nextCursor is not one Anvil sends back (empty, over {MAX_CURSOR_BYTES} bytes or holding control characters)"
        )),
        Some(Value::String(c)) if c.contains("{{") || c.contains("}}") => {
            Err("the server's nextCursor holds '{{' or '}}', which Anvil would read as a variable reference; it was not sent back".into())
        }
        Some(Value::String(c)) => Ok(Some(c.clone())),
        Some(_) => Err("the server's nextCursor is not a string".into()),
    }
}

impl App {
    /// Discover the tools of the MCP endpoint `request_id` addresses (a saved
    /// MCP request of workspace `ws`) and save a request per tool in the same
    /// folder.
    pub async fn mcp_discover_tools(
        &self,
        ws: &Id,
        request_id: &Id,
        opts: SendOptions,
        cancel: CancellationToken,
    ) -> Result<McpDiscovered> {
        let template = self.request(request_id)?;
        if template.spec.protocol != Protocol::Mcp || template.spec.mcp.is_none() {
            return Err(AppError::Invalid(format!("'{}' is not an MCP request; tools are discovered with one", template.name)));
        }
        let mut tools: Vec<Value> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut cursors: HashSet<String> = HashSet::new();
        let mut first: Option<Id> = None;
        let mut pages = 0usize;
        let mut stopped: Option<String> = None;
        loop {
            let mut list = template.spec.clone();
            if let Some(m) = list.mcp.as_mut() {
                m.operation = McpOperation::ToolsList { cursor: cursor.clone() };
            }
            list.assertions.clear();
            list.extractions.clear();
            // Boxed: the send's future is not held inside this one's.
            let out = Box::pin(self.send(Some(*request_id), ws, Some(list), opts.clone(), EventCtx::none(), cancel.clone())).await?;
            pages += 1;
            first.get_or_insert(out.record.id);
            let listed = page_result(&out).and_then(|result| match result.get("tools").and_then(Value::as_array) {
                Some(page) => Ok((page.clone(), result)),
                None => Err("the tools/list result has no tools list".to_string()),
            });
            let (page, result) = match listed {
                Ok(x) => x,
                // The first page is the discovery; a later one only ends it.
                Err(why) if pages == 1 => return Err(AppError::Invalid(why)),
                Err(why) => {
                    stopped = Some(format!("page {pages}: {why}"));
                    break;
                }
            };
            tools.extend(page);
            let next = match next_cursor(&result) {
                Ok(None) => break,
                Ok(Some(next)) => next,
                Err(why) => {
                    stopped = Some(why);
                    break;
                }
            };
            let why = if pages >= MAX_DISCOVERY_PAGES {
                Some(format!("the server lists more than {MAX_DISCOVERY_PAGES} pages; only those were read"))
            } else if tools.len() >= MAX_DISCOVERED_TOOLS {
                Some(format!("{} tools were listed in {pages} page(s), at least the {MAX_DISCOVERED_TOOLS} a discovery saves", tools.len()))
            } else if !cursors.insert(next.clone()) {
                Some("the server sent a nextCursor it had sent before; reading stopped rather than loop".into())
            } else if cancel.is_cancelled() {
                Some("the discovery was canceled".into())
            } else {
                None
            };
            if let Some(why) = why {
                stopped = Some(why);
                break;
            }
            cursor = Some(next);
        }
        let result = serde_json::json!({ "tools": tools });
        let found = anvil_import::mcp::mcp_tool_requests(&template.spec, &result).map_err(AppError::Invalid)?;
        let mut created = Vec::with_capacity(found.tools.len());
        for t in found.tools {
            created.push(self.create_request(ws, template.folder_id, &t.name, t.spec)?);
        }
        Ok(McpDiscovered {
            created,
            skipped: found.skipped,
            skipped_total: found.skipped_total,
            notes: found.notes,
            notes_total: found.notes_total,
            pages,
            stopped,
            execution_id: first.unwrap_or_else(Id::new),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_plain_text_cursor_is_sent_back() {
        assert_eq!(next_cursor(&json!({"tools": []})), Ok(None));
        assert_eq!(next_cursor(&json!({"nextCursor": null})), Ok(None));
        assert_eq!(next_cursor(&json!({"nextCursor": "page-3"})), Ok(Some("page-3".into())));
        let long = "c".repeat(MAX_CURSOR_BYTES + 1);
        for bad in [json!(""), json!("{{api_token}}"), json!("x}}"), json!("line\nbreak"), json!(long), json!(7)] {
            assert!(next_cursor(&json!({ "nextCursor": bad })).is_err(), "{bad}");
        }
    }
}
