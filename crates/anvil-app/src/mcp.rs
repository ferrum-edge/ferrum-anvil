//! MCP "discover tools": run `tools/list` with a saved MCP request and save
//! one request per listed tool beside it (its URL, headers, auth, settings and
//! session options; arguments from each tool's `inputSchema`, see
//! `anvil_import::mcp`). Every page the server lists is read, following
//! `nextCursor` in one MCP session (a cursor belongs to the session that
//! issued it), each page recorded like any send (history per the send
//! options); nothing else is sent, and the saved requests are not run.
//! Bounded: at most [`MAX_DISCOVERY_PAGES`] pages, and no page after
//! [`anvil_import::mcp::MAX_DISCOVERED_TOOLS`] tools were listed. A cursor is
//! sent back only when it is plain text: a server's cursor holding `{{` would
//! otherwise be read as a variable reference, sending a variable's value back
//! to the server.

use crate::exec::SendOptions;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::request::Protocol;
use anvil_domain::workspace::RequestDefinition;
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

/// The `result` of a `tools/list` page's JSON-RPC response, or why there is
/// none.
fn page_message(response: Option<&Value>) -> std::result::Result<Value, String> {
    let Some(message) = response else {
        return Err("tools/list got no JSON-RPC response".into());
    };
    if let Some(e) = message.get("error") {
        let code = e.get("code").and_then(|c| c.as_i64()).map_or_else(|| "(not an integer)".to_string(), |c| c.to_string());
        return Err(format!("tools/list was refused with JSON-RPC error {code}"));
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
        if self.is_locked() {
            return Err(AppError::Locked);
        }
        let mut list = template.spec.clone();
        list.assertions.clear();
        list.extractions.clear();
        let ctx = self.build_context_off_runtime(Some(*request_id), *ws, Some(list), opts.clone(), &cancel).await?;
        let mut tools: Vec<Value> = Vec::new();
        let mut cursors: HashSet<String> = HashSet::new();
        // Pages the cursor logic judged, and why reading stopped.
        let mut judged = 0usize;
        let mut stopped: Option<String> = None;
        let mut failed: Option<String> = None;
        let mut pages_out: Vec<anvil_engine::mcp::ToolPage>;
        {
            let mut next = |page: usize, response: Option<&Value>| -> Option<String> {
                judged = page;
                let listed = page_message(response).and_then(|result| match result.get("tools").and_then(Value::as_array) {
                    Some(listed) => Ok((listed.clone(), result)),
                    None => Err("the tools/list result has no tools list".to_string()),
                });
                let (listed, result) = match listed {
                    Ok(x) => x,
                    Err(why) => {
                        failed = Some(why);
                        return None;
                    }
                };
                tools.extend(listed);
                let next = match next_cursor(&result) {
                    Ok(next) => next?,
                    Err(why) => {
                        stopped = Some(why);
                        return None;
                    }
                };
                let why = if page >= MAX_DISCOVERY_PAGES {
                    Some(format!("the server lists more than {MAX_DISCOVERY_PAGES} pages; only those were read"))
                } else if tools.len() >= MAX_DISCOVERED_TOOLS {
                    Some(format!(
                        "{} tools were listed in {page} page(s), at least the {MAX_DISCOVERED_TOOLS} a discovery saves",
                        tools.len()
                    ))
                } else if !cursors.insert(next.clone()) {
                    Some("the server sent a nextCursor it had sent before; reading stopped rather than loop".into())
                } else {
                    None
                };
                match why {
                    Some(why) => {
                        stopped = Some(why);
                        None
                    }
                    None => Some(next),
                }
            };
            // One session for every page: a cursor belongs to its session.
            let listed =
                Box::pin(anvil_engine::mcp::list_tool_pages(&self.engine, &ctx, EventCtx::none(), cancel.clone(), &mut next)).await;
            pages_out = listed;
        }
        let pages = pages_out.len();
        let first = pages_out.first().map(|p| p.output.record.id).unwrap_or_default();
        let last_summaries: Vec<String> = pages_out.iter().map(|p| p.output.record.outcome.summary.clone()).collect();
        // Every page sent is history like any send; a page that cannot be
        // recorded after the first only ends the discovery.
        if opts.record_history {
            for (i, p) in std::mem::take(&mut pages_out).into_iter().enumerate() {
                let (_, recorded) = self.record_off_runtime(p.output).await;
                match recorded {
                    Ok(()) => {}
                    Err(e) if i == 0 => return Err(e),
                    Err(e) => {
                        stopped.get_or_insert_with(|| format!("page {}: not recorded in history: {e}", i + 1));
                    }
                }
            }
        }
        let summary = |page: usize| -> String { last_summaries.get(page.saturating_sub(1)).cloned().unwrap_or_default() };
        // The page the session ended on without the cursor logic judging it
        // (refused, canceled, out of time) ended the discovery there.
        if judged < pages {
            let why = format!("tools/list got no JSON-RPC response: {}", summary(pages));
            if pages == 1 {
                return Err(AppError::Invalid(why));
            }
            stopped.get_or_insert_with(|| format!("page {pages}: {why}"));
        }
        if let Some(why) = failed {
            let why = format!("{why}: {}", summary(judged));
            if judged <= 1 {
                return Err(AppError::Invalid(why));
            }
            stopped = Some(format!("page {judged}: {why}"));
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
            execution_id: first,
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
