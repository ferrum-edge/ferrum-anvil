//! A workspace delete that lands after the app built an execution context for
//! that workspace but before the context is executed: the execution is
//! answered, but keeps nothing for the deleted workspace (no cookie, prepared
//! TLS configuration or pooled connection) that a workspace restored with the
//! same id could pick up. Once the workspace is restored, its requests keep
//! them again. Real sockets, the real application services.

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
        assert_eq!(status(&o), Some(200), "{}: {failure:?}", ctx.spec.url);
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
