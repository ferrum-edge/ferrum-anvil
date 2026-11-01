//! `anvil gateway` end to end: the real binary, a real profile on disk and a
//! real fixture server. A saved Ferrum gateway profile is listed, and once
//! removed a send to its host is no longer trusted.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::tls::HostBinding;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Output, Stdio};

const PASS: &str = "cli-gateway-passphrase-1";
const CATALOG: &str = anvil_diagnostics::ferrum::DEFAULT_COMPATIBILITY_ID;

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

/// Save a lab gateway profile for `host` in workspace "Lab".
fn save_gateway(data: &Path, name: &str, host: &str) -> IntegrationProfile {
    let app = open(data);
    let ws = app.find_workspace("Lab").unwrap();
    let now = chrono::Utc::now();
    app.save_integration(IntegrationProfile {
        id: anvil_domain::Id::new(),
        workspace_id: ws.meta.id,
        name: name.into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: vec![HostBinding { host: host.into(), port: None }],
            compatibility_id: CATALOG.into(),
            require_verified_tls: false,
            detail: None,
            console_url: None,
        },
        created_at: now,
        updated_at: now,
    })
    .unwrap()
}

fn saved_gateways(data: &Path) -> usize {
    let app = open(data);
    let ws = app.find_workspace("Lab").unwrap();
    app.integrations(&ws.meta.id).unwrap().len()
}

/// The Ferrum compatibility id the send's record names: set only when the
/// destination was a trusted Ferrum gateway.
async fn trusted_as(data: &Path, url: &str) -> Option<String> {
    let o = anvil(data, &["send", "--workspace", "Lab", "--url", url, "--json", "--no-history"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let record: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o)));
    record["compatibility_id"].as_str().map(str::to_string)
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
async fn a_removed_gateway_is_no_longer_trusted() {
    let (_dir, data, f) = setup().await;
    let url = f.url("/echo");

    let o = anvil(&data, &["gateway", "list", "Lab"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("workspace 'Lab' has no Ferrum gateway profiles"), "{}", text(&o));

    let p = save_gateway(&data, "Lab gateway", "127.0.0.1");
    assert_eq!(trusted_as(&data, &url).await.as_deref(), Some(CATALOG));

    let o = anvil(&data, &["gateway", "list", "Lab"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let listed = String::from_utf8_lossy(&o.stdout).to_string();
    assert_eq!(listed.trim(), format!("{}  Lab gateway  {CATALOG}  127.0.0.1  plain-HTTP trust (lab)", p.id), "{listed}");

    // By name, case ignored.
    let o = anvil(&data, &["gateway", "remove", "Lab", "lab GATEWAY"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("removed Ferrum gateway profile 'Lab gateway' from 'Lab'"), "{}", text(&o));
    assert_eq!(saved_gateways(&data), 0);
    assert_eq!(trusted_as(&data, &url).await, None, "a send after the removal was still trusted");

    let o = anvil(&data, &["gateway", "remove", "Lab", "Lab gateway"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("has no Ferrum gateway profile 'Lab gateway'"), "{}", text(&o));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ambiguous_name_is_refused_and_an_id_removes_one() {
    let (_dir, data, _f) = setup().await;
    let a = save_gateway(&data, "Gateway", "gw-a.example");
    let b = save_gateway(&data, "Gateway", "gw-b.example");

    let o = anvil(&data, &["gateway", "remove", "Lab", "Gateway"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    let out = text(&o);
    assert!(out.contains("2 Ferrum gateway profiles are named 'Gateway'"), "{out}");
    assert!(out.contains(&a.id.to_string()) && out.contains(&b.id.to_string()), "{out}");
    assert_eq!(saved_gateways(&data), 2);

    // Equal names list by id, whatever order they were saved in.
    let o = anvil(&data, &["gateway", "list", "Lab"]).await;
    let ids: Vec<String> = String::from_utf8_lossy(&o.stdout).lines().map(|l| l.split("  ").next().unwrap().to_string()).collect();
    let mut sorted = vec![a.id.to_string(), b.id.to_string()];
    sorted.sort();
    assert_eq!(ids, sorted);

    let id = b.id.to_string();
    let o = anvil(&data, &["gateway", "remove", "Lab", &id]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let app = open(&data);
    let ws = app.find_workspace("Lab").unwrap();
    let left: Vec<_> = app.integrations(&ws.meta.id).unwrap().into_iter().map(|p| p.id).collect();
    assert_eq!(left, vec![a.id]);
}
