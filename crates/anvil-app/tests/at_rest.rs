//! Plaintext-leakage audit at rest. Every kind of user data and observed
//! traffic carries a distinct canary; afterwards no file under the profile
//! root (database, `-wal`/`-shm`/journal side files, blobs, attachment
//! index, headers) and no new file in the system temp directory may contain
//! any canary in the clear — neither while the store is open nor after it
//! is dropped.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{DatasetFormat, Variable};
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio_util::sync::CancellationToken;

const CANARIES: &[(&str, &str)] = &[
    ("request name", "CANARY-NAME-3232"),
    ("URL path", "CANARY-URL-PATH-5150"),
    ("header value", "CANARY-HDR-VALUE-6161"),
    ("request body", "CANARY-BODY-7272"),
    ("vault secret", "CANARY-SECRET-8383"),
    ("secret variable", "CANARY-ENVVAR-9494"),
    ("attachment", "CANARY-ATTACH-1010"),
    ("dataset cell", "CANARY-DATASET-2121"),
    ("workspace name", "CANARY-WORKSPACE-4343"),
];

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => files_under(&p, out),
            Ok(t) if t.is_file() => out.push(p),
            _ => {}
        }
    }
}

/// `(file, what)` for every canary found in plaintext (UTF-8 or UTF-16LE).
fn leaks(files: &[PathBuf]) -> Vec<(String, &'static str)> {
    let mut found = Vec::new();
    for f in files {
        let Ok(bytes) = std::fs::read(f) else { continue };
        for (what, c) in CANARIES {
            let utf16: Vec<u8> = c.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            if contains(&bytes, c.as_bytes()) || contains(&bytes, &utf16) {
                found.push((f.display().to_string(), *what));
            }
        }
    }
    found
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn new_temp_files(since: SystemTime) -> Vec<PathBuf> {
    let mut all = Vec::new();
    // Only the top two levels: enough for SQLite/our own temp files, bounded
    // on a shared machine.
    if let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) {
        for e in rd.flatten() {
            let p = e.path();
            let recent = e.metadata().and_then(|m| m.modified()).map(|t| t >= since).unwrap_or(false);
            if !recent {
                continue;
            }
            if p.is_file() {
                all.push(p);
            } else if p.is_dir()
                && let Ok(inner) = std::fs::read_dir(&p)
            {
                all.extend(inner.flatten().map(|x| x.path()).filter(|x| x.is_file()));
            }
        }
    }
    all.retain(|p| std::fs::metadata(p).map(|m| m.len() <= 64 << 20).unwrap_or(false));
    all
}

#[tokio::test]
async fn no_plaintext_user_data_in_profile_files_side_files_or_temp() {
    anvil_fixtures::init();
    let started = SystemTime::now();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _recovery) = pm.create_passphrase("audit", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();

    let ws = app.create_workspace("CANARY-WORKSPACE-4343").unwrap();
    let secret = app.set_secret(&ws.meta.id, "token", "CANARY-SECRET-8383").unwrap();
    let env = app
        .create_environment(
            &ws.meta.id,
            "lab",
            vec![
                Variable::plain("base", &fx.url("")),
                Variable {
                    name: "tok".into(),
                    value: SensitiveValue::template("CANARY-ENVVAR-9494"),
                    secret: true,
                    enabled: true,
                    description: String::new(),
                },
            ],
        )
        .unwrap();
    let attachment = app.put_attachment("notes.txt", b"attachment body CANARY-ATTACH-1010", Some("text/plain".into())).unwrap();
    app.create_dataset(&ws.meta.id, "users", DatasetFormat::Csv, b"user,password\nalice,CANARY-DATASET-2121\n", vec!["password".into()])
        .unwrap();

    let mut spec = RequestSpec::http("POST", "{{base}}/echo/CANARY-URL-PATH-5150");
    spec.headers.push(KeyValue::new("X-Canary", "CANARY-HDR-VALUE-6161"));
    spec.headers.push(KeyValue::new("X-Env-Token", "{{tok}}"));
    spec.body = Body::Json { text: r#"{"note":"CANARY-BODY-7272"}"#.into() };
    let req = app.create_request(&ws.meta.id, None, "CANARY-NAME-3232", spec).unwrap();
    let _ = &secret;

    let opts = SendOptions { environment: Some(env.meta.id), record_history: true, ..Default::default() };
    let out = app.send(Some(req.meta.id), &ws.meta.id, None, opts, EventCtx::none(), CancellationToken::new()).await.unwrap();
    assert!(out.record.response.is_some(), "the exchange completed: {:?}", out.record.findings);
    let hist = app.store.list_history(Some(&ws.meta.id), None, 10).unwrap();
    assert_eq!(hist.len(), 1, "the exchange (echoing every canary back) is in history");
    // The data really is there and readable through the app.
    assert_eq!(app.get_attachment(&attachment_sha(&attachment)).unwrap().unwrap(), b"attachment body CANARY-ATTACH-1010");
    assert!(app.search(&ws.meta.id, "canary-name").unwrap().iter().any(|r| r.meta.id == req.meta.id));

    // While open (WAL and shared-memory files present).
    let mut files = Vec::new();
    files_under(root.path(), &mut files);
    assert!(files.len() >= 2, "the audit saw the profile files: {files:?}");
    assert_eq!(leaks(&files), vec![], "plaintext at rest while the store is open");

    // After the store is closed (checkpointed), and in new temp files.
    drop(app);
    let mut files = Vec::new();
    files_under(root.path(), &mut files);
    assert_eq!(leaks(&files), vec![], "plaintext at rest after close");
    assert_eq!(leaks(&new_temp_files(started)), vec![], "plaintext in temporary files");
}

fn attachment_sha(a: &anvil_domain::request::AttachmentRef) -> String {
    match a {
        anvil_domain::request::AttachmentRef::Stored { sha256, .. } => sha256.clone(),
        other => panic!("unexpected attachment ref {other:?}"),
    }
}
