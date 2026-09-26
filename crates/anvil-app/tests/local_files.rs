//! Files on this machine reach a request only in the ways the user chose: a
//! draft spec (what the desktop webview sends) never names a linked local
//! file, and once the desktop confines token files, a JWT-SVID token file is
//! read only if it was bound in the native dialog. Bindings stay on the
//! device.

use anvil_app::App;
use anvil_app::exec::{SendOptions, refuse_linked_files};
use anvil_app::profiles::ProfileManager;
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::load::{LoadPlan, Workload};
use anvil_domain::request::{AttachmentRef, Body, MultipartContent, MultipartPart, RequestSpec};
use anvil_domain::workload::{JwtSvidConfig, JwtSvidSource};
use anvil_domain::workspace::{Dataset, DatasetFormat, Meta};
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

const CANARY: &str = "anvil-local-file-canary";
const URL: &str = "http://127.0.0.1:9/x";

fn new_app(root: &Path, name: &str) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase(name, "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

fn canary_file(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, CANARY).unwrap();
    p
}

fn linked(path: &Path) -> AttachmentRef {
    AttachmentRef::LinkedFile { path: path.display().to_string() }
}

fn with_body(body: Body) -> RequestSpec {
    let mut spec = RequestSpec::http("POST", URL);
    spec.body = body;
    spec
}

fn linked_specs(path: &Path) -> Vec<(&'static str, RequestSpec)> {
    let part = |attachment| MultipartPart {
        name: "file".into(),
        enabled: true,
        content: MultipartContent::File { attachment, file_name: None },
        content_type: None,
    };
    let stored = AttachmentRef::Stored { sha256: "0".repeat(64), size: 1, file_name: "a".into(), media_type: None };
    vec![
        ("binary body", with_body(Body::Binary { attachment: linked(path), content_type: None })),
        ("multipart part", with_body(Body::Multipart { parts: vec![part(stored), part(linked(path))] })),
        ("disabled multipart part", with_body(Body::Multipart { parts: vec![MultipartPart { enabled: false, ..part(linked(path)) }] })),
    ]
}

fn jwt_svid_file(path: &str) -> AuthConfig {
    let config = JwtSvidConfig {
        source: JwtSvidSource::File { path: path.into() },
        audiences: vec!["spiffe://example.org/api".into()],
        endpoint: String::new(),
        spiffe_id: None,
        verify_with_bundles: false,
        send_despite_failed_checks: false,
        header_name: "Authorization".into(),
        prefix: "Bearer".into(),
    };
    AuthConfig::JwtSvid { config }
}

fn with_auth(auth: AuthConfig) -> RequestSpec {
    let mut spec = RequestSpec::http("GET", URL);
    spec.auth = auth;
    spec
}

#[tokio::test]
async fn a_draft_naming_a_linked_file_is_refused_before_anything_is_read_or_sent() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let path = canary_file(files.path(), "secret.txt");
    let app = new_app(root.path(), "linked");
    let ws = app.create_workspace("W").unwrap();
    let saved = app.create_request(&ws.meta.id, None, "saved", RequestSpec::http("GET", URL)).unwrap();
    for (label, spec) in linked_specs(&path) {
        let err = refuse_linked_files(&spec).unwrap_err().to_string();
        assert!(err.contains("linked local file"), "{label}: {err}");
        for rid in [None, Some(saved.meta.id)] {
            let err = app.build_context(rid, &ws.meta.id, Some(spec.clone()), &SendOptions::default()).err().expect(label).to_string();
            assert!(err.contains("linked local file") && !err.contains(CANARY), "{label}: {err}");
            let opts = SendOptions { record_history: true, ..Default::default() };
            let sent = app.send(rid, &ws.meta.id, Some(spec.clone()), opts, EventCtx::none(), CancellationToken::new()).await;
            assert!(sent.is_err(), "{label}: a draft with a linked file is never sent");
        }
    }
    assert!(app.store.list_history(Some(&ws.meta.id), None, 10).unwrap().is_empty(), "nothing was executed");
}

#[test]
fn a_draft_with_stored_attachments_only_is_accepted() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "stored");
    let ws = app.create_workspace("W").unwrap();
    let attachment = app.put_attachment("payload.bin", b"payload", None).unwrap();
    let spec = with_body(Body::Binary { attachment, content_type: None });
    refuse_linked_files(&spec).unwrap();
    app.build_context(None, &ws.meta.id, Some(spec), &SendOptions::default()).unwrap();
    // A text body that merely mentions the tag is not an attachment.
    let text = with_body(Body::Json { text: r#"{"kind":"linked_file","path":"/etc/hosts"}"#.into() });
    refuse_linked_files(&text).unwrap();
}

#[test]
fn a_confined_app_reads_only_token_files_bound_in_the_dialog() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let token = canary_file(files.path(), "jwt_svid.token");
    let other = canary_file(files.path(), "id_ed25519");
    let app = new_app(root.path(), "tokens");
    let ws = app.create_workspace("W").unwrap();
    let build = |auth: AuthConfig| app.build_context(None, &ws.meta.id, Some(with_auth(auth)), &SendOptions::default());
    let canonical = std::fs::canonicalize(&token).unwrap().to_str().unwrap().to_string();

    // The CLI does not confine token files.
    build(jwt_svid_file(&canonical)).unwrap();

    app.confine_token_files();
    let err = build(jwt_svid_file(&canonical)).err().expect("unbound").to_string();
    assert!(err.contains("not chosen") && !err.contains(CANARY), "{err}");

    let binding = app.bind_token_file(&token).unwrap();
    assert_eq!(binding.path, canonical);
    build(jwt_svid_file(&binding.path)).unwrap();
    build(jwt_svid_file(&format!("  {}\n", binding.path))).unwrap();
    // Binding the same file again keeps one binding.
    assert_eq!(app.bind_token_file(&token).unwrap().id, binding.id);
    assert_eq!(app.token_file_bindings().unwrap().len(), 1);

    // Any other path, or one built from variables, is still refused.
    let other_path = std::fs::canonicalize(&other).unwrap().to_str().unwrap().to_string();
    for path in [other_path.clone(), other.display().to_string(), "{{token_file}}".to_string(), "jwt_svid.token".to_string()] {
        assert!(build(jwt_svid_file(&path)).is_err(), "{path}");
    }
    // Inside a multi-auth profile too.
    let multi = AuthConfig::Multi { profiles: vec![AuthConfig::None, jwt_svid_file(&other_path)] };
    assert!(build(multi).is_err());
    let multi = AuthConfig::Multi { profiles: vec![jwt_svid_file(&binding.path)] };
    build(multi).unwrap();
}

#[test]
fn an_inherited_token_file_is_checked_and_an_overridden_one_is_not_needed() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let token = canary_file(files.path(), "jwt_svid.token");
    let app = new_app(root.path(), "inherit");
    app.confine_token_files();
    let mut ws = app.create_workspace("W").unwrap();
    ws.auth = jwt_svid_file(&token.display().to_string());
    let ws = app.save_workspace(ws).unwrap();
    let inherit = app.create_request(&ws.meta.id, None, "inherit", RequestSpec::http("GET", URL)).unwrap();
    assert!(app.build_context(Some(inherit.meta.id), &ws.meta.id, None, &SendOptions::default()).is_err());
    let none = app.create_request(&ws.meta.id, None, "none", with_auth(AuthConfig::None)).unwrap();
    app.build_context(Some(none.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
}

#[test]
fn only_a_regular_file_with_an_absolute_literal_path_is_bound() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "bind");
    assert!(app.bind_token_file(Path::new("jwt_svid.token")).is_err());
    assert!(app.bind_token_file(files.path()).is_err());
    assert!(app.bind_token_file(&files.path().join("missing.token")).is_err());
    let templated = canary_file(files.path(), "{{token}}");
    assert!(app.bind_token_file(&templated).is_err());
    assert!(app.token_file_bindings().unwrap().is_empty());
}

#[test]
fn token_file_bindings_stay_on_this_device() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let token = canary_file(files.path(), "jwt_svid.token");
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("W").unwrap();
    let binding = a.bind_token_file(&token).unwrap();
    a.create_request(&ws.meta.id, None, "r", with_auth(jwt_svid_file(&binding.path))).unwrap();
    let (bytes, _) = a.export(None, ExportMode::FullBackup, Some("export passphrase 1"), false).unwrap();

    let b = new_app(root.path(), "b");
    b.import(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert!(b.token_file_bindings().unwrap().is_empty(), "an import never binds a token file");
    b.confine_token_files();
    let ws_b = b.workspaces().unwrap().into_iter().find(|w| w.name == "W").unwrap();
    let req = b.requests(&ws_b.meta.id).unwrap().into_iter().find(|r| r.name == "r").unwrap();
    assert!(b.build_context(Some(req.meta.id), &ws_b.meta.id, None, &SendOptions::default()).is_err());
}

#[test]
fn a_linked_dataset_is_read_with_the_dataset_bound() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let big = files.path().join("big.csv");
    std::fs::File::create(&big).unwrap().set_len(64 * 1024 * 1024 + 1).unwrap();
    let app = new_app(root.path(), "dataset");
    let ws = app.create_workspace("W").unwrap();
    let req = app.create_request(&ws.meta.id, None, "r", RequestSpec::http("GET", URL)).unwrap();
    let dataset = Dataset {
        meta: Meta::new(),
        workspace_id: ws.meta.id,
        name: "big".into(),
        format: DatasetFormat::Csv,
        attachment: linked(&big),
        sensitive_columns: vec![],
    };
    let d = app.save_dataset(dataset).unwrap();
    let plan = LoadPlan {
        id: Id::new(),
        workspace_id: ws.meta.id,
        name: "p".into(),
        workload: Workload::Iterations { iterations: 1, concurrency: 1 },
        chain: vec![req.meta.id],
        mix: vec![],
        dataset_id: Some(d.meta.id),
        environment_id: None,
        connection_mode: Default::default(),
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let err = app.load_plan_check(&plan).err().expect("too large").to_string();
    assert!(err.contains("larger than 64 MiB"), "{err}");
}
