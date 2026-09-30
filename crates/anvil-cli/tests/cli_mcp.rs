//! MCP from the command line: an ad-hoc `anvil send --url … --mcp-call`, a
//! saved MCP request (`anvil add … --mcp-list-tools`) and `anvil
//! mcp-discover`, with the real binary, a real profile on disk and the MCP
//! fixture server. The fixture's record of what it received is ground truth.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_fixtures::mcp::{self, McpOptions};
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::Output;

const PASS: &str = "cli-mcp-passphrase-1";

fn setup(root: &Path) {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    app.create_workspace("Agents").unwrap();
}

async fn anvil(data: &Path, args: &[&str]) -> Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .output()
        .await
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_are_listed_called_and_discovered_from_the_cli() {
    anvil_fixtures::init();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    setup(&data);
    let url = f.url();

    let o = anvil(&data, &["send", "--workspace", "Agents", "--url", &url, "--mcp-call", "echo", "--mcp-args", r#"{"text":"cli"}"#]).await;
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert!(out.contains("MCP initialize: HTTP 200"), "{out}");
    assert!(out.contains("MCP session closed: DELETE answered HTTP 200"), "{out}");
    assert_eq!(f.state.tool_calls("echo"), 1);

    // A tool error is an application failure: exit 1.
    let o = anvil(&data, &["send", "--workspace", "Agents", "--url", &url, "--mcp-call", "fail", "--no-history"]).await;
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));

    let o = anvil(&data, &["add", "Agents", "fixture tools", "--url", &url, "--mcp-list-tools"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = anvil(&data, &["mcp-discover", "fixture tools", "--workspace", "Agents"]).await;
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    for name in ["Echo", "add", "fail", "session"] {
        assert!(out.lines().any(|l| l.ends_with(&format!("  {name}"))), "{name}: {out}");
    }
    let o = anvil(&data, &["send", "Echo", "--workspace", "Agents", "--no-history"]).await;
    assert_eq!(o.status.code(), Some(0), "the discovered request calls its tool: {}", text(&o));
    assert_eq!(f.state.tool_calls("echo"), 2);
}
