//! `anvil send --trust-ferrum` end to end: the real binary, a real profile on
//! disk and a real fixture server. The flag trusts the host for that one send
//! and saves nothing, so a later send without it is not trusted. Only
//! `--save-trust` keeps it as a gateway profile in the workspace.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::tls::HostBinding;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Output, Stdio};

const PASS: &str = "cli-trust-passphrase-1";

async fn anvil(data: &Path, args: &[&str]) -> Output {
    anvil_with_env(data, args, &[]).await
}

async fn anvil_with_env(data: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .envs(env.iter().copied())
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

/// A catalog other than the default, so a test can tell a saved profile's
/// trust from the one `--trust-ferrum` declares.
const OTHER_CATALOG: &str = "ferrum-edge-0.9.14";

/// The send's process output and its JSON execution record.
async fn send(data: &Path, url: &str, extra: &[&str]) -> (Output, serde_json::Value) {
    let mut args = vec!["send", "--workspace", "Lab", "--url", url, "--json", "--no-history"];
    args.extend_from_slice(extra);
    let o = anvil(data, &args).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let record = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o)));
    (o, record)
}

/// The Ferrum compatibility id the send's record names: set only when the
/// destination was a trusted Ferrum gateway.
async fn trusted_as(data: &Path, url: &str, extra: &[&str]) -> Option<String> {
    send(data, url, extra).await.1["compatibility_id"].as_str().map(str::to_string)
}

/// Whether the record notes that several gateway profiles matched.
fn shadowed(record: &serde_json::Value) -> bool {
    record["prepared"]["inferred"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("several Ferrum gateway profiles"))
}

/// Save a gateway profile in workspace "Lab" for `host` (on `port` only,
/// if given), with `OTHER_CATALOG`.
fn save_gateway(data: &Path, host: &str, port: Option<u16>) {
    let app = open(data);
    let ws = app.find_workspace("Lab").unwrap();
    let now = chrono::Utc::now();
    app.save_integration(IntegrationProfile {
        id: anvil_domain::Id::new(),
        workspace_id: ws.meta.id,
        name: "Saved gateway".into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: vec![HostBinding { host: host.into(), port }],
            compatibility_id: OTHER_CATALOG.into(),
            require_verified_tls: false,
            detail: None,
            console_url: None,
        },
        created_at: now,
        updated_at: now,
    })
    .unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn save_trust_keeps_the_gateway_for_later_sends() {
    let (_dir, data, f) = setup().await;
    let url = f.url("/echo");
    let default = anvil_diagnostics::ferrum::DEFAULT_COMPATIBILITY_ID;

    // --save-trust only means something with a host to trust.
    let o = anvil(&data, &["send", "--workspace", "Lab", "--url", &url, "--save-trust"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("--trust-ferrum"), "{}", text(&o));
    assert_eq!(saved_gateways(&data), 0);

    assert_eq!(trusted_as(&data, &url, &["--trust-ferrum", "127.0.0.1", "--save-trust"]).await.as_deref(), Some(default));
    assert_eq!(saved_gateways(&data), 1);
    assert_eq!(trusted_as(&data, &url, &[]).await.as_deref(), Some(default), "the saved profile is used without the flag");

    // Trusting a host that already has a saved profile adds no second one.
    assert_eq!(trusted_as(&data, &url, &["--trust-ferrum", "127.0.0.1", "--save-trust"]).await.as_deref(), Some(default));
    assert_eq!(saved_gateways(&data), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_saved_profile_covering_the_host_means_the_flag_adds_nothing() {
    let (_dir, data, f) = setup().await;
    let url = f.url("/echo");
    // A wildcard covers 127.0.0.1 as the engine matches hosts, though the
    // strings differ.
    save_gateway(&data, "*.0.0.1", None);

    for extra in [&["--trust-ferrum", "127.0.0.1"][..], &["--trust-ferrum", "127.0.0.1", "--save-trust"]] {
        let (o, record) = send(&data, &url, extra).await;
        assert_eq!(record["compatibility_id"].as_str(), Some(OTHER_CATALOG), "{extra:?}: the saved profile is used");
        assert!(!shadowed(&record), "{extra:?}: no second profile was declared: {record}");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(!err.contains("saved Ferrum gateway profile"), "{err}");
        // --save-trust says why it saved nothing.
        assert_eq!(
            err.contains("Ferrum gateway profile 'Saved gateway' already covers 127.0.0.1: nothing saved"),
            extra.len() == 3,
            "{err}"
        );
        assert_eq!(saved_gateways(&data), 1, "{extra:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_profile_bound_to_another_port_does_not_cancel_the_flag() {
    let (_dir, data, f) = setup().await;
    let url = f.url("/echo");
    save_gateway(&data, "127.0.0.1", Some(1));
    let default = anvil_diagnostics::ferrum::DEFAULT_COMPATIBILITY_ID;

    assert_eq!(trusted_as(&data, &url, &[]).await, None, "the saved profile is for port 1 only");
    assert_eq!(trusted_as(&data, &url, &["--trust-ferrum", "127.0.0.1"]).await.as_deref(), Some(default));
    assert_eq!(saved_gateways(&data), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn save_trust_saves_nothing_when_the_send_fails_locally() {
    let (_dir, data, f) = setup().await;
    // The request does not resolve.
    let o = anvil(&data, &["send", "No such request", "--workspace", "Lab", "--trust-ferrum", "127.0.0.1", "--save-trust"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(!text(&o).contains("saved Ferrum gateway profile"), "{}", text(&o));
    assert_eq!(saved_gateways(&data), 0);

    // The request resolves but is refused while it is prepared: nothing is sent.
    let args = [
        "send",
        "--workspace",
        "Lab",
        "--url",
        "ftp://127.0.0.1/",
        "--trust-ferrum",
        "127.0.0.1",
        "--save-trust",
        "--json",
        "--no-history",
    ];
    let o = anvil(&data, &args).await;
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    let record: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o)));
    assert_eq!(record["outcome"]["dispatch"], "not_dispatched", "{record}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("did not save Ferrum gateway profile 'Ferrum gateway 127.0.0.1': no request was sent to 127.0.0.1"), "{err}");
    assert_eq!(saved_gateways(&data), 0);
    assert_eq!(trusted_as(&data, &f.url("/echo"), &[]).await, None, "a later send was trusted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn save_trust_saves_nothing_when_the_send_went_to_another_host() {
    let (_dir, data, f) = setup().await;
    let url = f.url("/echo");
    let expected = "did not save Ferrum gateway profile 'Ferrum gateway gw.example.invalid': no request was sent to gw.example.invalid";
    // The URL's host is 127.0.0.1, so the flag's profile never applies.
    let (o, record) = send(&data, &url, &["--trust-ferrum", "gw.example.invalid", "--save-trust"]).await;
    assert_eq!(record["outcome"]["dispatch"], "sent", "{record}");
    assert_eq!(record["compatibility_id"], serde_json::Value::Null, "{record}");
    assert!(String::from_utf8_lossy(&o.stderr).contains(expected), "{}", text(&o));
    assert_eq!(saved_gateways(&data), 0);

    // Also when a saved profile makes the actual destination trusted.
    save_gateway(&data, "127.0.0.1", None);
    let (o, record) = send(&data, &url, &["--trust-ferrum", "gw.example.invalid", "--save-trust"]).await;
    assert_eq!(record["compatibility_id"].as_str(), Some(OTHER_CATALOG), "{record}");
    assert!(String::from_utf8_lossy(&o.stderr).contains(expected), "{}", text(&o));
    assert_eq!(saved_gateways(&data), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_is_compared_as_the_engine_compares_it() {
    let (_dir, data, f) = setup().await;
    let url = f.url("/echo");
    let default = anvil_diagnostics::ferrum::DEFAULT_COMPATIBILITY_ID;

    // A URL, a path or a port is refused before anything is sent or saved.
    for bad in [
        "http://127.0.0.1/",
        "127.0.0.1/echo",
        "127.0.0.1:8080",
        "[::1]:8080",
        " ",
        "*.0.0.1",
        "%2A.0.0.1",
        "127.0.0.1?x=1",
        "127.0.0.1#f",
        "127.0.0.1\\health",
        "user@127.0.0.1",
    ] {
        let o = anvil(&data, &["send", "--workspace", "Lab", "--url", &url, "--trust-ferrum", bad, "--save-trust"]).await;
        assert_eq!(o.status.code(), Some(3), "{bad:?}: {}", text(&o));
        assert!(text(&o).contains("--trust-ferrum takes a host"), "{bad:?}: {}", text(&o));
    }
    assert_eq!(saved_gateways(&data), 0);

    // An IPv6 address is canonical as the engine parses URLs.
    let (o, _) = send(&data, &url, &["--trust-ferrum", "0:0:0:0:0:0:0:1", "--save-trust"]).await;
    assert!(String::from_utf8_lossy(&o.stderr).contains("'Ferrum gateway ::1': no request was sent to ::1"), "{}", text(&o));

    // Brackets and surrounding spaces do not stop a match, and the saved
    // host is the canonical one.
    assert_eq!(trusted_as(&data, &url, &["--trust-ferrum", " [127.0.0.1] ", "--save-trust"]).await.as_deref(), Some(default));
    let app = open(&data);
    let ws = app.find_workspace("Lab").unwrap();
    let saved = app.integrations(&ws.meta.id).unwrap();
    let IntegrationKind::FerrumGateway { hosts, .. } = &saved[0].kind;
    assert_eq!((saved.len(), saved[0].name.as_str(), hosts[0].host.as_str()), (1, "Ferrum gateway 127.0.0.1", "127.0.0.1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redacted_host_never_proves_the_request_reached_host() {
    let (_dir, data, f) = setup().await;
    // The request's host is a secret, so the record redacts it.
    for args in [
        &["env", "create", "Lab", "local", "--use"][..],
        &["env", "set", "Lab", "gwhost", "--secret", "--value-env", "GW_HOST"],
        &["add", "Lab", "Secret host", "--url", &f.url("/echo").replace("127.0.0.1", "{{gwhost}}")],
    ] {
        let o = anvil_with_env(&data, args, &[("GW_HOST", "127.0.0.1")]).await;
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}", text(&o));
    }
    let send = ["send", "Secret host", "--workspace", "Lab", "--json", "--no-history", "--save-trust", "--trust-ferrum"];
    // The real host, and a HOST spelled like the redaction marker.
    for host in ["127.0.0.1", anvil_domain::secret::REDACTED] {
        let mut args = send.to_vec();
        args.push(host);
        let o = anvil(&data, &args).await;
        assert_eq!(o.status.code(), Some(0), "{host}: {}", text(&o));
        let record: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o)));
        assert_eq!(record["outcome"]["dispatch"], "sent", "{record}");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(err.contains("the record redacts the host the request went to"), "{host}: {err}");
        assert_eq!(saved_gateways(&data), 0, "{host}");
    }
}
