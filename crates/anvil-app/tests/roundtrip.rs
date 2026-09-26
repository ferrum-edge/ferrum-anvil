//! DATA-001/002/003: workspace and whole-app round trips into a clean
//! profile (different data key, no shared keychain), then a successful send.

use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::Variable;
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

fn new_app(root: &std::path::Path, name: &str) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase(name, "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

#[tokio::test]
async fn data_002_full_backup_restores_into_clean_profile_and_sends() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let a_root = tempfile::tempdir().unwrap();
    let a = new_app(a_root.path(), "machine-a");
    let ws = a.create_workspace("Payments").unwrap();
    let orders = a.create_folder(&ws.meta.id, None, "Orders").unwrap();
    let refunds = a.create_folder(&ws.meta.id, Some(orders.meta.id), "Refunds").unwrap();
    let key_ref = a.set_secret(&ws.meta.id, "api key", "k-SECRET-4242").unwrap();
    let mut env_vars = vec![Variable::plain("base", &fx.url(""))];
    env_vars.push(Variable {
        name: "tok".into(),
        value: SensitiveValue::template("ENV-TOKEN-777"),
        secret: true,
        enabled: true,
        description: String::new(),
    });
    let env = a.create_environment(&ws.meta.id, "lab", env_vars).unwrap();
    let mut spec = RequestSpec::http("GET", "{{base}}/auth/apikey?name=x-api-key&value=k-SECRET-4242");
    spec.headers.push(KeyValue::new("X-Env-Token", "{{tok}}"));
    spec.auth = AuthConfig::ApiKey {
        name: "X-API-Key".into(),
        value: SensitiveValue::Secret { secret: key_ref.clone() },
        location: KeyLocation::Header,
    };
    let req = a.create_request(&ws.meta.id, Some(refunds.meta.id), "Check key", spec).unwrap();
    let opts = SendOptions { environment: Some(env.meta.id), record_history: true, ..Default::default() };
    let out = a.send(Some(req.meta.id), &ws.meta.id, None, opts.clone(), EventCtx::none(), CancellationToken::new()).await.unwrap();
    assert_eq!(out.record.response.as_ref().unwrap().status, 200, "{:?}", out.record.findings);
    assert_eq!(a.store.list_history(Some(&ws.meta.id), None, 10).unwrap().len(), 1);

    // Whole-app encrypted backup.
    let (bytes, preview) = a.export_backup_with("export passphrase 1", KdfParams::testing()).unwrap();
    assert!(anvil_app::backup::is_backup(&bytes));
    assert_eq!(preview.secrets_included, 1);
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("k-SECRET-4242") && !text.contains("ENV-TOKEN-777"));

    // Clean install elsewhere: a different profile/key.
    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "machine-b");
    let dry = b.restore_preview(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert!(dry.missing_secrets.is_empty());
    assert!(b.workspaces().unwrap().is_empty(), "preview does not mutate");
    let rep = b.restore(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert!(rep.secrets_restored);
    let ws_b = b.find_workspace("Payments").unwrap();
    let tree = b.tree(&ws_b.meta.id).unwrap();
    assert_eq!(tree[0].name, "Orders");
    assert_eq!(tree[0].children[0].name, "Refunds");
    let req_b = b.find_request(&ws_b.meta.id, "Orders/Refunds/Check key").unwrap();
    let out_b = b
        .send(
            Some(req_b.meta.id),
            &ws_b.meta.id,
            None,
            SendOptions { environment: Some(env.meta.id), record_history: true, ..Default::default() },
            EventCtx::none(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(out_b.record.response.as_ref().unwrap().status, 200, "restored profile sends successfully: {:?}", out_b.record.findings);
    let hdrs = fx.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "x-env-token" && v == "ENV-TOKEN-777"), "secret variable restored");

    // Restoring the same backup again with Merge is idempotent.
    b.restore(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert_eq!(b.workspaces().unwrap().len(), 1);
    // A full backup restores every item under its own id; it is never duplicated.
    let e = b.restore(&bytes, Some("export passphrase 1"), ConflictPolicy::Duplicate).unwrap_err();
    assert!(matches!(e, AppError::Backup(anvil_app::backup::BackupError::DuplicateUnsupported)), "{e}");
    assert_eq!(b.workspaces().unwrap().len(), 1);
}

#[tokio::test]
async fn data_001_share_safely_import_reports_missing_secrets_and_fails_locally() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let a_root = tempfile::tempdir().unwrap();
    let a = new_app(a_root.path(), "a");
    let ws = a.create_workspace("Shared").unwrap();
    let key_ref = a.set_secret(&ws.meta.id, "token", "tok-SHOULD-NOT-TRAVEL").unwrap();
    let mut spec = RequestSpec::http("GET", &fx.url("/echo"));
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: key_ref }, prefix: "Bearer".into() };
    a.create_request(&ws.meta.id, None, "Echo", spec).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, false).unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "b");
    let rep = b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    assert_eq!(rep.missing_secrets.len(), 1);
    let wsb = b.find_workspace("Shared").unwrap();
    let r = b.find_request(&wsb.meta.id, "Echo").unwrap();
    let out =
        b.send(Some(r.meta.id), &wsb.meta.id, None, SendOptions::default(), EventCtx::none(), CancellationToken::new()).await.unwrap();
    assert!(out.record.findings.iter().any(|f| f.code == "local.auth_preparation_failed"), "{:?}", out.record.findings);
    assert_eq!(fx.log.count_requests(), 0, "nothing was sent without the secret");
}

#[tokio::test]
async fn data_015_locked_app_refuses_privileged_operations() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "locky");
    let ws = a.create_workspace("W").unwrap();
    a.lock();
    assert!(matches!(a.workspaces(), Err(AppError::Locked)));
    assert!(matches!(a.set_secret(&ws.meta.id, "x", "y"), Err(AppError::Locked)));
    assert!(matches!(
        a.send(
            None,
            &ws.meta.id,
            Some(RequestSpec::http("GET", "http://127.0.0.1:9/")),
            SendOptions::default(),
            EventCtx::none(),
            CancellationToken::new()
        )
        .await,
        Err(AppError::Locked)
    ));
    let h = anvil_storage::vault::read_header(&a.dir).unwrap();
    let k = anvil_storage::vault::unlock_with_passphrase(&h, "correct horse battery").unwrap();
    a.unlock(k).unwrap();
    assert_eq!(a.workspaces().unwrap().len(), 1);
}

#[test]
fn folder_moves_cannot_create_cycles() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "t");
    let ws = a.create_workspace("W").unwrap();
    let p = a.create_folder(&ws.meta.id, None, "P").unwrap();
    let c = a.create_folder(&ws.meta.id, Some(p.meta.id), "C").unwrap();
    assert!(a.move_folder(&p.meta.id, Some(c.meta.id), 1.0).is_err());
    assert!(a.move_folder(&p.meta.id, Some(p.meta.id), 1.0).is_err());
    a.move_folder(&c.meta.id, None, 5.0).unwrap();
}

#[test]
fn revisions_are_immutable_history() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "t");
    let ws = a.create_workspace("W").unwrap();
    let r = a.create_request(&ws.meta.id, None, "R", RequestSpec::http("GET", "http://a/")).unwrap();
    let rev1 = r.revision_id.unwrap();
    let mut r2 = r.clone();
    r2.spec.url = "http://b/".into();
    let r2 = a.save_request(r2).unwrap();
    assert_ne!(r2.revision_id.unwrap(), rev1);
    assert_eq!(a.revision(&rev1).unwrap().spec.url, "http://a/", "old revision unchanged");
    let same = a.save_request(r2.clone()).unwrap();
    assert_eq!(same.revision_id, r2.revision_id, "no new revision when unchanged");
}
