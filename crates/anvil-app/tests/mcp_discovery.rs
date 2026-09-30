//! MCP "discover tools" through the application services: a saved MCP
//! request lists the fixture's tools, one request per tool is saved beside
//! it, and each saved request calls its tool with arguments from the tool's
//! `inputSchema`. The fixture's record of what it received is ground truth.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_domain::outcome::AssertionState;
use anvil_domain::request::{McpOperation, McpSpec, Protocol, RequestSpec};
use anvil_fixtures::mcp::{self, McpOptions};
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

fn new_app(root: &std::path::Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("mcp", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

fn mcp_request(url: &str) -> RequestSpec {
    let mut spec = RequestSpec::http("POST", url);
    spec.protocol = Protocol::Mcp;
    let operation = serde_json::to_value(McpOperation::ToolsList { cursor: None }).unwrap();
    let mcp: McpSpec = serde_json::from_value(serde_json::json!({ "operation": operation })).unwrap();
    spec.mcp = Some(mcp);
    spec
}

#[tokio::test]
async fn discovered_tools_are_saved_beside_the_template_and_call_their_tool() {
    anvil_fixtures::init();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Agents").unwrap().meta.id;
    let folder = app.create_folder(&ws, None, "Fixture MCP").unwrap().meta.id;
    let template = app.create_request(&ws, Some(folder), "tools", mcp_request(&f.url())).unwrap();
    let opts = SendOptions { record_history: true, ..Default::default() };

    let d = app.mcp_discover_tools(&ws, &template.meta.id, opts.clone(), CancellationToken::new()).await.unwrap();
    let names: Vec<&str> = d.created.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["Echo", "add", "fail", "session", "delete_all", "internal_audit", "new_tool"]);
    assert!(!d.more && d.skipped.is_empty(), "{:?}", d.skipped);
    assert!(d.created.iter().all(|r| r.folder_id == Some(folder)), "saved beside the template");
    assert_eq!(f.state.methods(), ["initialize", "notifications/initialized", "tools/list"], "only the list was sent");

    let send = |id: anvil_domain::Id| app.send(Some(id), &ws, None, opts.clone(), EventCtx::none(), CancellationToken::new());
    // echo: the schema's example; its saved checks pass.
    let out = send(d.created[0].meta.id).await.unwrap();
    assert_eq!(out.record.outcome.assertions, AssertionState::Pass, "{:?}", out.record.assertion_results);
    assert_eq!(f.state.tool_calls("echo"), 1);
    let echoed = anvil_engine::mcp::operation_response(&out).expect("a response");
    assert_eq!(echoed["result"]["structuredContent"]["text"], "hello");
    // add: the properties' defaults.
    let out = send(d.created[1].meta.id).await.unwrap();
    let sum = anvil_engine::mcp::operation_response(&out).expect("a response");
    assert_eq!(sum["result"]["structuredContent"]["sum"], 5.0);
    // fail: the saved "not a tool error" check fails.
    let out = send(d.created[2].meta.id).await.unwrap();
    assert_eq!(out.record.outcome.assertions, AssertionState::Fail);

    let plain = app.create_request(&ws, None, "plain", RequestSpec::http("GET", &f.url())).unwrap();
    let refused = app.mcp_discover_tools(&ws, &plain.meta.id, opts, CancellationToken::new()).await;
    assert!(refused.is_err(), "only an MCP request discovers tools");
}
