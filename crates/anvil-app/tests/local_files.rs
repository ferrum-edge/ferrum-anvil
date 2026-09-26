//! Files on this machine reach a request only in the ways the user chose: a
//! draft spec (what the desktop webview sends) never names a linked local
//! file, a saved request, gRPC schema or dataset reads a linked file only
//! once it was chosen for that request or dataset in the native dialog on
//! this device, and once the desktop confines token files, a JWT-SVID token
//! file is read only if it was bound in the native dialog. Bindings stay on
//! the device, and a load worker never opens a linked file itself.

use anvil_app::exec::{SendOptions, refuse_linked_files};
use anvil_app::linked_files::LinkedFileReferrer;
use anvil_app::port::ImportApproval;
use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::load::{LoadPlan, Workload};
use anvil_domain::request::{
    AttachmentRef, Body, GrpcMode, GrpcSchemaSource, GrpcSpec, GrpcWire, MultipartContent, MultipartPart, Protocol, RequestSpec,
};
use anvil_domain::workload::{JwtSvidConfig, JwtSvidSource};
use anvil_domain::workspace::{Dataset, DatasetFormat, Meta, RequestDefinition};
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
mod fifo;
#[cfg(unix)]
use fifo::{mkfifo, within_seconds};

const CANARY: &str = "anvil-local-file-canary";
const URL: &str = "http://127.0.0.1:9/x";

/// The error of a refused call (an `ExecutionContext` is not `Debug`).
fn refused<T>(r: Result<T, AppError>, label: &str) -> String {
    match r {
        Ok(_) => panic!("{label}: expected a refusal"),
        Err(e) => e.to_string(),
    }
}

fn request(r: &RequestDefinition) -> LinkedFileReferrer {
    LinkedFileReferrer::Request { id: r.meta.id }
}

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

fn grpc_with_proto(proto: AttachmentRef) -> RequestSpec {
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9");
    spec.protocol = Protocol::Grpc;
    spec.grpc = Some(GrpcSpec {
        service: "lab.Echo".into(),
        method: "Say".into(),
        mode: GrpcMode::Unary,
        schema: GrpcSchemaSource::ProtoFiles { files: vec![proto] },
        messages: vec!["{}".into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: true,
        wire: GrpcWire::Grpc,
    });
    spec
}

/// Every place a saved request can name a linked file.
fn saved_linked_specs(path: &Path) -> Vec<(&'static str, RequestSpec)> {
    let mut specs = linked_specs(path);
    specs.push(("gRPC proto file", grpc_with_proto(linked(path))));
    specs
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap()
}

fn linked_dataset(ws: Id, path: &Path) -> Dataset {
    Dataset {
        meta: Meta::new(),
        workspace_id: ws,
        name: "rows".into(),
        format: DatasetFormat::Csv,
        attachment: linked(path),
        sensitive_columns: vec![],
    }
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
            let err = refused(app.build_context(rid, &ws.meta.id, Some(spec.clone()), &SendOptions::default()), label);
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
    let err = refused(build(jwt_svid_file(&canonical)), "unbound");
    assert!(err.contains("not chosen") && !err.contains(CANARY), "{err}");

    let binding = app.bind_token_file(&token).unwrap();
    // The path as chosen, not its canonical form (see the projected token below).
    assert_eq!(binding.path, token.to_str().unwrap());
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
    let (bytes, _) = a.export_backup_with("export passphrase 1", KdfParams::testing()).unwrap();

    let b = new_app(root.path(), "b");
    b.restore(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert!(b.token_file_bindings().unwrap().is_empty(), "a restore never binds a token file");
    b.confine_token_files();
    let ws_b = b.workspaces().unwrap().into_iter().find(|w| w.name == "W").unwrap();
    let req = b.requests(&ws_b.meta.id).unwrap().into_iter().find(|r| r.name == "r").unwrap();
    assert!(b.build_context(Some(req.meta.id), &ws_b.meta.id, None, &SendOptions::default()).is_err());
}

#[test]
fn the_user_lists_and_removes_token_file_bindings() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let first = canary_file(files.path(), "first.token");
    let second = canary_file(files.path(), "second.token");
    let app = new_app(root.path(), "remove");
    app.confine_token_files();
    let ws = app.create_workspace("W").unwrap();
    let build = |path: &str| app.build_context(None, &ws.meta.id, Some(with_auth(jwt_svid_file(path))), &SendOptions::default());
    let listed = |app: &App| app.token_file_bindings().unwrap().into_iter().map(|b| (b.id, b.path)).collect::<Vec<_>>();

    let a = app.bind_token_file(&first).unwrap();
    let b = app.bind_token_file(&second).unwrap();
    assert_eq!(listed(&app), vec![(a.id, a.path.clone()), (b.id, b.path.clone())]);
    build(&a.path).unwrap();

    // A file chosen by mistake stops being read from the next send on.
    app.remove_token_file_binding(&a.id).unwrap();
    assert_eq!(listed(&app), vec![(b.id, b.path.clone())]);
    let err = refused(build(&a.path), "removed");
    assert!(err.contains("not chosen") && !err.contains(CANARY), "{err}");
    let multi = AuthConfig::Multi { profiles: vec![jwt_svid_file(&b.path), jwt_svid_file(&a.path)] };
    assert!(app.build_context(None, &ws.meta.id, Some(with_auth(multi)), &SendOptions::default()).is_err());
    // The other binding is untouched.
    build(&b.path).unwrap();

    // Removing it again, or an id that was never bound, finds nothing.
    assert!(matches!(app.remove_token_file_binding(&a.id), Err(AppError::NotFound(_))));
    assert!(matches!(app.remove_token_file_binding(&Id::new()), Err(AppError::NotFound(_))));
    assert_eq!(listed(&app), vec![(b.id, b.path.clone())]);

    // Choosing the file again binds it anew.
    let again = app.bind_token_file(&first).unwrap();
    assert_ne!(again.id, a.id);
    build(&again.path).unwrap();

    // Locked: nothing is listed or removed.
    app.lock();
    assert!(app.token_file_bindings().is_err());
    assert!(app.remove_token_file_binding(&b.id).is_err());
}

fn load_plan(ws: Id, chain: Vec<Id>, dataset_id: Option<Id>) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: ws,
        name: "p".into(),
        workload: Workload::Iterations { iterations: 1, concurrency: 1 },
        chain,
        mix: vec![],
        dataset_id,
        environment_id: None,
        connection_mode: Default::default(),
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
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
    let d = app.save_dataset(linked_dataset(ws.meta.id, &canonical(&big))).unwrap();
    let plan = load_plan(ws.meta.id, vec![req.meta.id], Some(d.meta.id));
    let err = app.load_plan_check(&plan).expect_err("not chosen").to_string();
    assert!(err.contains("not chosen on this device"), "{err}");
    // A binding made for another dataset naming the same file does not count.
    let other = app.save_dataset(linked_dataset(ws.meta.id, &canonical(&big))).unwrap();
    app.bind_linked_file(LinkedFileReferrer::Dataset { id: other.meta.id }, &big).unwrap();
    let err = app.load_plan_check(&plan).expect_err("chosen for another dataset").to_string();
    assert!(err.contains("not chosen on this device"), "{err}");
    app.bind_linked_file(LinkedFileReferrer::Dataset { id: d.meta.id }, &big).unwrap();
    let err = app.load_plan_check(&plan).expect_err("too large").to_string();
    assert!(err.contains("larger than 64 MiB"), "{err}");
}

#[tokio::test]
async fn a_saved_linked_file_is_inert_until_it_is_chosen_for_that_request_on_this_device() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let path = canonical(&canary_file(files.path(), "secret.txt"));
    let app = new_app(root.path(), "saved");
    let ws = app.create_workspace("W").unwrap();
    let mut saved = Vec::new();
    for (label, spec) in saved_linked_specs(&path) {
        let r = app.create_request(&ws.meta.id, None, label, spec).unwrap();
        let err = refused(app.build_context(Some(r.meta.id), &ws.meta.id, None, &SendOptions::default()), label);
        assert!(err.contains("not chosen on this device") && !err.contains(CANARY), "{label}: {err}");
        let opts = SendOptions { record_history: true, ..Default::default() };
        let sent = app.send(Some(r.meta.id), &ws.meta.id, None, opts, EventCtx::none(), CancellationToken::new()).await;
        assert!(sent.is_err(), "{label}: a request naming an unchosen linked file is never sent");
        saved.push((label, r));
    }
    assert!(app.store.list_history(Some(&ws.meta.id), None, 10).unwrap().is_empty(), "nothing was executed");

    // Choosing the file in the native dialog binds it for that request.
    let other = canonical(&canary_file(files.path(), "other.txt"));
    for (label, r) in &saved {
        let binding = app.bind_linked_file(request(r), &path).expect(label);
        assert_eq!(Path::new(&binding.path), path);
        assert_eq!(binding.referrer, request(r));
        assert_eq!(app.bind_linked_file(request(r), &path).unwrap().id, binding.id, "binding the same file again keeps one binding");
        let ctx = app.build_context(Some(r.meta.id), &ws.meta.id, None, &SendOptions::default()).expect(label);
        assert_eq!(ctx.attachments.load(&linked(&path)).unwrap().as_ref(), CANARY.as_bytes(), "{label}");
        // The resolver reads only the bound files this request names.
        assert!(ctx.attachments.load(&linked(&other)).is_err(), "{label}");
    }
    assert_eq!(app.linked_file_bindings().unwrap().len(), saved.len(), "one binding per request");

    // Another request naming the same file (for example one imported later)
    // cannot use a binding the user made for a different request.
    let spec = with_body(Body::Binary { attachment: linked(&path), content_type: None });
    let later = app.create_request(&ws.meta.id, None, "later", spec).unwrap();
    let err = refused(app.build_context(Some(later.meta.id), &ws.meta.id, None, &SendOptions::default()), "later");
    assert!(err.contains("not chosen on this device"), "{err}");
    // A file is bound only for a request that names it.
    let err = refused(app.bind_linked_file(request(&later), &other), "a file the request does not name");
    assert!(err.contains("not the linked file"), "{err}");
    let err = refused(app.bind_linked_file(LinkedFileReferrer::Request { id: Id::new() }, &path), "no such request");
    assert!(!err.contains(CANARY), "{err}");
    // Only the exact bound path counts.
    let spec = with_body(Body::Binary { attachment: linked(&files.path().join("other.txt")), content_type: None });
    let r = app.create_request(&ws.meta.id, None, "other", spec).unwrap();
    assert!(app.build_context(Some(r.meta.id), &ws.meta.id, None, &SendOptions::default()).is_err());
}

#[test]
fn linked_files_in_an_imported_bundle_stay_inert_on_the_receiving_device() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let path = canonical(&canary_file(files.path(), "secret.txt"));
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("W").unwrap();
    for (label, spec) in saved_linked_specs(&path) {
        let r = a.create_request(&ws.meta.id, None, label, spec).unwrap();
        // A binding on the exporting device does not travel with the bundle.
        a.bind_linked_file(request(&r), &path).unwrap();
    }
    let rows = files.path().join("rows.csv");
    std::fs::write(&rows, "id\n1\n").unwrap();
    let rows = canonical(&rows);
    let d = a.save_dataset(linked_dataset(ws.meta.id, &rows)).unwrap();
    a.bind_linked_file(LinkedFileReferrer::Dataset { id: d.meta.id }, &rows).unwrap();
    let (bytes, _) = a.export(None, ExportMode::EncryptedTransfer, Some("export passphrase 1"), false).unwrap();

    let b = new_app(root.path(), "b");
    // The preview lists every linked file the bundle names, datasets included.
    let preview = b.import_preview(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert_eq!(preview.linked_files.len(), saved_linked_specs(&path).len() + 1, "{:?}", preview.linked_files);
    assert!(preview.linked_files.iter().any(|l| l.starts_with("dataset 'rows'")), "{:?}", preview.linked_files);
    assert!(preview.warnings.iter().any(|w| w.contains("linked local file")), "{:?}", preview.warnings);

    b.import(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert!(b.linked_file_bindings().unwrap().is_empty(), "an import never binds a linked file");
    let ws_b = b.workspaces().unwrap().into_iter().find(|w| w.name == "W").unwrap();
    let requests = b.requests(&ws_b.meta.id).unwrap();
    assert_eq!(requests.len(), saved_linked_specs(&path).len());
    for r in &requests {
        let err = refused(b.build_context(Some(r.meta.id), &ws_b.meta.id, None, &SendOptions::default()), &r.name);
        assert!(err.contains("not chosen on this device") && !err.contains(CANARY), "{}: {err}", r.name);
    }
    let dataset = b.datasets(&ws_b.meta.id).unwrap().pop().unwrap();
    let err = refused(b.run_dataset(&dataset), "dataset");
    assert!(err.contains("not chosen on this device"), "{err}");

    // Choosing the same files on the receiving device makes the references usable.
    for r in &requests {
        b.bind_linked_file(request(r), &path).unwrap();
        b.build_context(Some(r.meta.id), &ws_b.meta.id, None, &SendOptions::default()).expect(&r.name);
    }
    assert!(b.run_dataset(&dataset).is_err(), "the dataset's own file is still not chosen");
    b.bind_linked_file(LinkedFileReferrer::Dataset { id: dataset.meta.id }, &rows).unwrap();
    assert_eq!(b.run_dataset(&dataset).unwrap().rows.len(), 1);
}

#[test]
fn an_import_that_overwrites_a_request_drops_its_linked_file_binding() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let path = canonical(&canary_file(files.path(), "secret.txt"));
    let app = new_app(root.path(), "overwrite");
    let ws = app.create_workspace("W").unwrap();
    let spec = with_body(Body::Binary { attachment: linked(&path), content_type: None });
    let r = app.create_request(&ws.meta.id, None, "upload", spec).unwrap();
    let (bytes, _) = app.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some("export passphrase 1"), false).unwrap();
    app.bind_linked_file(request(&r), &path).unwrap();
    app.build_context(Some(r.meta.id), &ws.meta.id, None, &SendOptions::default()).expect("bound");

    // The bundle is this workspace's own backup: writing into it is approved.
    let approval = ImportApproval { existing_workspaces: vec![ws.meta.id] };
    // Merging leaves the stored request, and its binding, alone.
    app.import_approved(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge, &approval).unwrap();
    assert_eq!(app.linked_file_bindings().unwrap().len(), 1);
    // A bundle that replaces the request is not what the user chose the file for.
    app.import_approved(&bytes, Some("export passphrase 1"), ConflictPolicy::Replace, &approval).unwrap();
    assert!(app.linked_file_bindings().unwrap().is_empty());
    let err = refused(app.build_context(Some(r.meta.id), &ws.meta.id, None, &SendOptions::default()), "replaced");
    assert!(err.contains("not chosen on this device") && !err.contains(CANARY), "{err}");
}

#[test]
fn a_load_worker_gets_a_bound_linked_file_as_bytes_and_never_its_path() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let path = canonical(&canary_file(files.path(), "upload.bin"));
    let app = new_app(root.path(), "load");
    let ws = app.create_workspace("W").unwrap();
    let spec = with_body(Body::Binary { attachment: linked(&path), content_type: None });
    let r = app.create_request(&ws.meta.id, None, "upload", spec).unwrap();
    app.bind_linked_file(request(&r), &path).unwrap();
    let job = app.worker_job(&load_plan(ws.meta.id, vec![r.meta.id], None), true).unwrap();
    let json = serde_json::to_string(&job).unwrap();
    assert!(!json.contains("linked_file") && !json.contains(path.to_str().unwrap()), "the worker job names no local file");

    let (_, lj, _) = job.into_load_job().unwrap();
    let ctx = &lj.requests[&r.meta.id];
    let Body::Binary { attachment, .. } = &ctx.spec.body else { panic!("binary body") };
    assert_eq!(ctx.attachments.load(attachment).unwrap().as_ref(), CANARY.as_bytes());
    // The run sends what was read when the job was built, and the worker
    // itself never opens the path.
    std::fs::write(&path, "changed").unwrap();
    assert_eq!(ctx.attachments.load(attachment).unwrap().as_ref(), CANARY.as_bytes());
    assert!(ctx.attachments.load(&linked(&path)).is_err());
}

#[test]
fn only_a_regular_file_is_bound_as_a_linked_file() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "bind-linked");
    let ws = app.create_workspace("W").unwrap();
    let spec = with_body(Body::Binary { attachment: linked(files.path()), content_type: None });
    let r = app.create_request(&ws.meta.id, None, "r", spec).unwrap();
    assert!(app.bind_linked_file(request(&r), Path::new("secret.txt")).is_err());
    assert!(app.bind_linked_file(request(&r), files.path()).is_err());
    assert!(app.bind_linked_file(request(&r), &files.path().join("missing.txt")).is_err());
    assert!(app.linked_file_bindings().unwrap().is_empty());
    // Token-file and linked-file bindings are separate.
    let token = canary_file(files.path(), "jwt_svid.token");
    app.bind_token_file(&token).unwrap();
    assert!(app.linked_file_bindings().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn a_linked_dataset_swapped_for_a_fifo_is_refused_without_blocking() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let rows = files.path().join("rows.csv");
    std::fs::write(&rows, "id\n1\n").unwrap();
    let app = new_app(root.path(), "fifo");
    let ws = app.create_workspace("W").unwrap();
    let d = app.save_dataset(linked_dataset(ws.meta.id, &canonical(&rows))).unwrap();
    app.bind_linked_file(LinkedFileReferrer::Dataset { id: d.meta.id }, &rows).unwrap();
    assert_eq!(app.run_dataset(&d).unwrap().rows.len(), 1);

    // The same path, now a FIFO with no writer: opening it for reading would
    // wait for one.
    std::fs::remove_file(&rows).unwrap();
    mkfifo(&rows);
    let err = within_seconds(move || app.run_dataset(&d).map(|_| ()).map_err(|e| e.to_string())).unwrap_err();
    assert!(err.contains("not a regular file"), "{err}");
}

/// A Kubernetes projected service-account token: `token` links to
/// `..data/token`, `..data` links to a timestamped directory, and a rotation
/// writes a new directory, repoints `..data` and deletes the old directory.
#[cfg(unix)]
#[test]
fn a_bound_token_file_keeps_working_across_a_projected_token_rotation() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let dir = files.path();
    let first = dir.join("..2026_01_01_00_00_00.000000001");
    std::fs::create_dir(&first).unwrap();
    std::fs::write(first.join("token"), "first-token").unwrap();
    symlink(first.file_name().unwrap(), dir.join("..data")).unwrap();
    symlink("..data/token", dir.join("token")).unwrap();
    let chosen = dir.join("token");

    let app = new_app(root.path(), "projected");
    app.confine_token_files();
    let ws = app.create_workspace("W").unwrap();
    let binding = app.bind_token_file(&chosen).unwrap();
    // The link as chosen, not the timestamped file it leads to now.
    assert_eq!(binding.path, chosen.to_str().unwrap());
    let resolved = canonical(&chosen);
    assert!(resolved.starts_with(canonical(&first)), "{}", resolved.display());
    let r = app.create_request(&ws.meta.id, None, "svid", with_auth(jwt_svid_file(&binding.path))).unwrap();
    app.build_context(Some(r.meta.id), &ws.meta.id, None, &SendOptions::default()).expect("bound");

    // Rotate: the file the first bind resolved to is deleted.
    let second = dir.join("..2026_01_01_01_00_00.000000001");
    std::fs::create_dir(&second).unwrap();
    std::fs::write(second.join("token"), "second-token").unwrap();
    symlink(second.file_name().unwrap(), dir.join("..data_tmp")).unwrap();
    std::fs::rename(dir.join("..data_tmp"), dir.join("..data")).unwrap();
    std::fs::remove_dir_all(&first).unwrap();
    assert!(!resolved.exists());

    // The bound path leads to the new token, and the request still builds.
    assert_eq!(std::fs::read_to_string(&binding.path).unwrap(), "second-token");
    app.build_context(Some(r.meta.id), &ws.meta.id, None, &SendOptions::default()).expect("rotated");
    // Only the chosen path is bound: the file it led to was never bound itself.
    let draft = with_auth(jwt_svid_file(resolved.to_str().unwrap()));
    let err = refused(app.build_context(None, &ws.meta.id, Some(draft), &SendOptions::default()), "resolved");
    assert!(err.contains("not chosen"), "{err}");
    assert_eq!(app.token_file_bindings().unwrap().len(), 1);
}
