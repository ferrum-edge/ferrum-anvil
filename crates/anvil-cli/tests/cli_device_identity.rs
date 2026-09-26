//! `anvil workspace allow-device-identity`: the real binary and a real
//! profile on disk. A bundle import seals the workspace it writes from this
//! device's workload identity, and only this command (or the desktop's
//! workspace settings) lifts the seal.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::RequestSpec;
use anvil_domain::workload::{JwtSvidConfig, JwtSvidSource};
use anvil_portability::ExportMode;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Command, Output};

const PASS: &str = "cli-device-identity-passphrase-1";

/// A profile whose workspace `W` holds a request that fetches a JWT-SVID
/// from the Workload API, and a share-safe bundle of `W` written to `bundle`.
fn setup(root: &Path, bundle: &Path) {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let ws = app.create_workspace("W").unwrap();
    let config = JwtSvidConfig {
        source: JwtSvidSource::WorkloadApi,
        audiences: vec!["spiffe://example.org/api".into()],
        endpoint: String::new(),
        spiffe_id: None,
        verify_with_bundles: false,
        send_despite_failed_checks: false,
        header_name: "Authorization".into(),
        prefix: "Bearer".into(),
    };
    let mut spec = RequestSpec::http("GET", "https://api.example.invalid/svid");
    spec.auth = AuthConfig::JwtSvid { config };
    app.create_request(&ws.meta.id, None, "svid", spec).unwrap();
    let (bytes, _) = app.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, false).unwrap();
    std::fs::write(bundle, bytes).unwrap();
}

fn open(root: &Path) -> App {
    let s = ProfileManager::new(root).list().into_iter().next().unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    App::open(s.dir, h, key).unwrap()
}

fn anvil(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_EXPORT_PASSPHRASE")
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[test]
fn an_imported_workspace_is_sealed_until_allowed_from_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let bundle = dir.path().join("w.anvil");
    setup(&data, &bundle);

    let o = anvil(&data, &["import", bundle.to_str().unwrap(), "--policy", "duplicate"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let report: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(report["warnings"].to_string().contains("allow-device-identity"), "{report}");
    let copy: Id = report["workspace_ids"][0].as_str().unwrap().parse().unwrap();
    {
        let app = open(&data);
        assert!(app.device_identity_sealed(&copy).unwrap());
        let r = app.requests(&copy).unwrap().pop().unwrap();
        let Err(e) = app.build_context(Some(r.meta.id), &copy, None, &Default::default()) else {
            panic!("a sealed workspace's request used this device's workload identity")
        };
        assert!(e.to_string().contains(&format!("anvil workspace allow-device-identity {copy}")), "{e}");
    }

    let id = copy.to_string();
    let o = anvil(&data, &["workspace", "allow-device-identity", &id]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("may now use"), "{}", text(&o));
    let app = open(&data);
    assert!(!app.device_identity_sealed(&copy).unwrap());
    let r = app.requests(&copy).unwrap().pop().unwrap();
    app.build_context(Some(r.meta.id), &copy, None, &Default::default()).unwrap_or_else(|e| panic!("{e}"));

    // Lifting it again finds nothing to lift; an unknown workspace is refused.
    let o = anvil(&data, &["workspace", "allow-device-identity", &id]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("was not sealed"), "{}", text(&o));
    let o = anvil(&data, &["workspace", "allow-device-identity", &Id::new().to_string()]);
    assert!(!o.status.success(), "{}", text(&o));
}
