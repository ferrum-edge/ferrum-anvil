//! `anvil send --early-data` and `anvil run` with a workspace that enables
//! 0-RTT early data: the real binary, a real profile on disk and the real
//! HTTP/3 early-data fixture, whose ground truth says which request arrived
//! in early data.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_domain::settings::{EarlyDataPolicy, HttpVersionPolicy, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_fixtures::early_data::{self, EarlyMode};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::Output;

const PASS: &str = "cli-early-passphrase-1";

/// A profile whose workspace trusts the fixture's CA; the folder `Twice`
/// holds two GETs of `url` with early data on, HTTP/3 and no connection reuse.
fn setup(root: &Path, pki: &LabPki, url: &str) {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let mut ws = app.create_workspace("Edge").unwrap();
    let tls = app
        .save_tls_profile(TlsProfile {
            id: Id::new(),
            workspace_id: ws.meta.id,
            name: "lab".into(),
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![pki.ca.cert.clone()],
            client_identity: None,
            bindings: vec![],
            min_version: TlsMinVersion::Tls12,
            server_name_override: None,
            server_spiffe: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
    ws.settings.tls_profile_id = Some(tls.id);
    app.save_workspace(ws.clone()).unwrap();
    let mut folder = app.create_folder(&ws.meta.id, None, "Twice").unwrap();
    folder.settings = SettingsOverrides {
        http_version: Some(HttpVersionPolicy::Http3Only),
        keepalive: Some(false),
        early_data: Some(EarlyDataPolicy { enabled: true, extra_methods: vec![] }),
        ..Default::default()
    };
    app.save_folder(folder.clone()).unwrap();
    app.create_request(&ws.meta.id, Some(folder.meta.id), "First", RequestSpec::http("GET", url)).unwrap();
    app.create_request(&ws.meta.id, Some(folder.meta.id), "Second", RequestSpec::http("GET", url)).unwrap();
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
async fn early_data_flags_and_a_run_that_resumes_into_0rtt() {
    anvil_fixtures::init();
    let pki = LabPki::generate();
    let fx = early_data::serve_h3(
        "127.0.0.1:0",
        TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone()),
        EarlyMode::Accept,
    )
    .await
    .unwrap();
    let url = fx.url("/echo");
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path(), &pki, &url);

    // One `send` process: no ticket yet (tickets are never persisted), so a
    // full handshake whose record shows the tickets it received.
    let o = anvil(
        dir.path(),
        &["send", "--workspace", "Edge", "--url", &url, "--http-version", "http3", "--no-keepalive", "--early-data", "--json"],
    )
    .await;
    assert!(o.status.success(), "{}", text(&o));
    let rec: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let ed = &rec["attempts"][0]["early_data"];
    assert_eq!(ed["transport"], "quic", "{ed}");
    assert_eq!(ed["not_used"], "no_ticket", "{ed}");
    assert!(ed["tickets_received"].as_u64().unwrap_or(0) >= 1, "{ed}");
    assert_eq!(rec["prepared"]["settings"]["early_data"]["enabled"], true);

    // The human output names the evidence too.
    let o = anvil(dir.path(), &["send", "--workspace", "Edge", "--url", &url, "--http-version", "http3", "--early-data"]).await;
    assert!(text(&o).contains("early data (attempt 0): QUIC"), "{}", text(&o));

    // A non-idempotent method in the policy is refused before traffic.
    let before = fx.requests().len();
    let o = anvil(
        dir.path(),
        &["send", "--workspace", "Edge", "--url", &url, "--http-version", "http3", "--early-data", "--early-data-method", "POST"],
    )
    .await;
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("cannot be sent as 0-RTT early data"), "{}", text(&o));
    assert_eq!(fx.requests().len(), before, "nothing was sent");

    // `--early-data-method` needs `--early-data`.
    let o = anvil(dir.path(), &["send", "--url", &url, "--early-data-method", "PUT"]).await;
    assert!(!o.status.success());

    // One `run` process shares its tickets across steps: the second GET of
    // the folder goes out as 0-RTT early data.
    let before = fx.requests().len();
    let o = anvil(dir.path(), &["run", "Edge", "--folder", "Twice", "--quiet"]).await;
    assert!(o.status.success(), "{}", text(&o));
    let seen: Vec<bool> = fx.requests()[before..].iter().map(|r| r.0).collect();
    assert_eq!(seen, vec![false, true], "the run's second request arrived in 0-RTT early data");
}
