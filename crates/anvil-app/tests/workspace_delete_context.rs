//! A workspace delete that lands after the app built an execution context for
//! that workspace but before the context is executed: the execution is
//! answered, but keeps nothing for the deleted workspace (no cookie, prepared
//! TLS configuration or pooled connection) that a workspace restored with the
//! same id could pick up. Once the workspace is restored, its requests keep
//! them again. Real sockets, the real application services.
//!
//! The engine is cleared only once the storage delete is committed: a delete
//! that fails leaves the workspace's engine state as it was.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::ExecutionOutput;
use anvil_fixtures::http as fx;
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_storage::store::DB_FILE;
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

const PASS: &str = "delete-context-backup-passphrase";

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

#[tokio::test]
async fn a_context_built_before_its_workspace_delete_keeps_nothing_for_the_restored_workspace() {
    anvil_fixtures::init();
    let pki = LabPki::generate();
    let plain = fx::serve("127.0.0.1:0", None).await.unwrap();
    let server_tls = TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone());
    let tls = fx::serve("127.0.0.1:0", Some(server_tls)).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _) = pm.create_passphrase("delete", "delete-context-passphrase", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    let mut ws = app.create_workspace("Edge").unwrap();
    let trust = app
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
    ws.settings.tls_profile_id = Some(trust.id);
    app.save_workspace(ws.clone()).unwrap();
    let ws = ws.meta.id;
    let isolation = ws.to_string();
    let backup = app.export_backup_with(PASS, KdfParams::testing()).unwrap().0;
    // A cookie and a pooled connection; a prepared TLS configuration and a
    // pooled TLS connection.
    let login = RequestSpec::http("GET", &plain.url("/set-cookie?name=sid&value=before-the-delete"));
    let specs = [login, RequestSpec::http("GET", &tls.url("/echo"))];

    // Built, then the workspace is deleted, then executed.
    let mut built = Vec::new();
    for spec in &specs {
        built.push(app.build_context(None, &ws, Some(spec.clone()), &SendOptions::default()).unwrap());
    }
    app.delete_workspace(&ws).unwrap();
    for ctx in &built {
        let o = app.engine.execute(ctx, EventCtx::none(), CancellationToken::new()).await;
        let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
        assert_eq!(status(&o), None, "{}: {failure:?}", ctx.spec.url);
        assert!(failure.unwrap().message.contains("configuration changed"));
    }
    assert!(!app.engine.has_cookie_jar(&isolation), "a cookie was kept for the deleted workspace");
    assert_eq!(app.engine.prepared_tls_len(), 0, "a TLS configuration was cached for the deleted workspace");
    assert_eq!(app.engine.http.pool.stats().connections, 0, "a connection was pooled for the deleted workspace");

    // Restored with the same id: its requests keep all of them again.
    app.restore(&backup, Some(PASS), ConflictPolicy::Merge).unwrap();
    for spec in &specs {
        let sent = app.send(None, &ws, Some(spec.clone()), SendOptions::default(), EventCtx::none(), CancellationToken::new()).await;
        let o = sent.unwrap();
        assert_eq!(status(&o), Some(200), "{}", spec.url);
    }
    assert!(app.engine.has_cookie_jar(&isolation), "the restored workspace's cookie was refused");
    assert!(app.engine.prepared_tls_len() >= 1, "the restored workspace's TLS configuration was not cached");
    assert!(app.engine.http.pool.stats().connections >= 1, "the restored workspace's connections were not pooled");
}

/// Make every delete of a workspace row fail inside SQLite.
fn fail_workspace_deletes(app: &App) {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let trigger = "CREATE TRIGGER injected_failure BEFORE DELETE ON objects WHEN old.kind = 'workspace'";
    db.execute_batch(&format!("{trigger} BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")).unwrap();
}

fn allow_workspace_deletes(app: &App) {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    db.execute_batch("DROP TRIGGER IF EXISTS injected_failure;").unwrap();
}

/// Make the commit of a transaction that deleted workspace `ws`'s row fail:
/// a deferred foreign key holds the row, and is checked only at COMMIT, so
/// the failure comes after everything `App::delete_workspace` runs inside
/// its transaction, the row delete included.
fn fail_workspace_delete_commits(app: &App, ws: &Id) {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let hold = "CREATE TABLE injected_hold (kind TEXT NOT NULL, id TEXT NOT NULL, \
                FOREIGN KEY (kind, id) REFERENCES objects (kind, id) DEFERRABLE INITIALLY DEFERRED);";
    db.execute_batch(hold).unwrap();
    db.execute("INSERT INTO injected_hold (kind, id) VALUES ('workspace', ?1)", [ws.to_string()]).unwrap();
}

fn allow_workspace_delete_commits(app: &App) {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    db.execute_batch("DROP TABLE IF EXISTS injected_hold;").unwrap();
}

/// `App::delete_workspace` clears the engine after the storage delete is
/// committed, never before: the epoch fence of a context built during the
/// delete depends on it. A delete whose storage write fails keeps the
/// workspace's engine state (here its cookie jar); clearing the engine first
/// would already have dropped it. It fails once before the workspace row is
/// deleted and once at the commit, after everything the transaction does:
/// a clear moved into the transaction, even after the row delete, would
/// also have dropped it.
#[tokio::test]
async fn the_engine_is_cleared_only_after_the_storage_delete_is_committed() {
    anvil_fixtures::init();
    let plain = fx::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _) = pm.create_passphrase("order", "delete-order-passphrase", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    let ws = app.create_workspace("Edge").unwrap().meta.id;
    let isolation = ws.to_string();
    let login = RequestSpec::http("GET", &plain.url("/set-cookie?name=sid&value=kept"));
    let sent = app.send(None, &ws, Some(login), SendOptions::default(), EventCtx::none(), CancellationToken::new()).await;
    assert_eq!(status(&sent.unwrap()), Some(200));
    assert!(app.engine.has_cookie_jar(&isolation), "the workspace has a cookie jar");

    fail_workspace_deletes(&app);
    assert!(app.delete_workspace(&ws).is_err(), "the injected failure fails the storage delete");
    assert!(app.workspace(&ws).is_ok(), "the failed delete removed nothing");
    assert!(app.engine.has_cookie_jar(&isolation), "the engine was cleared before the storage delete was committed");
    allow_workspace_deletes(&app);

    fail_workspace_delete_commits(&app, &ws);
    assert!(app.delete_workspace(&ws).is_err(), "the held row fails the commit");
    assert!(app.workspace(&ws).is_ok(), "the failed commit removed nothing");
    assert!(app.engine.has_cookie_jar(&isolation), "the engine was cleared inside the storage delete's transaction");
    allow_workspace_delete_commits(&app);

    app.delete_workspace(&ws).unwrap();
    assert!(app.workspace(&ws).is_err());
    assert!(!app.engine.has_cookie_jar(&isolation), "the committed delete cleared the engine");
}
