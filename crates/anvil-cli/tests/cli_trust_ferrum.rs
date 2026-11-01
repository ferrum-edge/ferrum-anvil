//! `anvil send --trust-ferrum` end to end: the real binary, a real profile on
//! disk and a real fixture server. The flag trusts the host for that one send
//! and saves nothing, so a later send without it is not trusted.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Output, Stdio};

const PASS: &str = "cli-trust-passphrase-1";

async fn anvil(data: &Path, args: &[&str]) -> Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn open(root: &Path) -> App {
    let s = ProfileManager::new(root).list().into_iter().next().unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    App::open(s.dir, h, key).unwrap()
}

/// The Ferrum compatibility id the send's record names: set only when the
/// destination was a trusted Ferrum gateway.
async fn trusted_as(data: &Path, url: &str, extra: &[&str]) -> Option<String> {
    let mut args = vec!["send", "--workspace", "Lab", "--url", url, "--json", "--no-history"];
    args.extend_from_slice(extra);
    let o = anvil(data, &args).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let record: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o)));
    record["compatibility_id"].as_str().map(str::to_string)
}

fn saved_gateways(data: &Path) -> usize {
    let app = open(data);
    let ws = app.find_workspace("Lab").unwrap();
    app.integrations(&ws.meta.id).unwrap().len()
}

async fn setup() -> (tempfile::TempDir, std::path::PathBuf, anvil_fixtures::http::Fixture) {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    ProfileManager::new(&data).create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let o = anvil(&data, &["workspace", "create", "Lab"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    (dir, data, f)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_ferrum_applies_to_one_send_and_saves_nothing() {
    let (_dir, data, f) = setup().await;
    let url = f.url("/echo");
    let default = anvil_diagnostics::ferrum::DEFAULT_COMPATIBILITY_ID;

    assert_eq!(trusted_as(&data, &url, &["--trust-ferrum", "127.0.0.1"]).await.as_deref(), Some(default));
    assert_eq!(saved_gateways(&data), 0, "--trust-ferrum saved a Ferrum gateway profile");
    assert_eq!(trusted_as(&data, &url, &[]).await, None, "a later send without --trust-ferrum was trusted");
}
