//! Bundle import into a profile: a Duplicate copy is independent of its
//! source, a secret stays with the workspace that owns it, and bundles this
//! build cannot read change nothing.

use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::workspace::{Meta, RequestDefinition, Variable, Workspace};
use anvil_portability::bundle::{self, BundleError, BundleKind, ExportOptions};
use anvil_portability::plan::ConflictPolicy;
use anvil_portability::{ExportMode, PortableGraph, SecretValue};
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use sha2::Digest;
use std::io::Write;
use tokio_util::sync::CancellationToken;

const EXPORT_PASS: &str = "export passphrase 1";
const TOKEN: &str = "placeholder-bearer-token";

fn new_app(root: &std::path::Path, name: &str) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase(name, "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

/// Re-pack a bundle after editing its manifest, recomputing the checksums
/// (they detect corruption, not deliberate edits).
fn edit_manifest(bytes: &[u8], edit: impl Fn(&mut serde_json::Value)) -> Vec<u8> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut entries = Vec::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).unwrap();
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut b).unwrap();
        entries.push((f.name().to_string(), b));
    }
    let mut checks = std::collections::BTreeMap::new();
    for (n, b) in &mut entries {
        if n == "manifest.json" {
            let mut m: serde_json::Value = serde_json::from_slice(b).unwrap();
            edit(&mut m);
            *b = serde_json::to_vec(&m).unwrap();
        }
        if n != "checksums.json" {
            checks.insert(n.clone(), hex::encode(sha2::Sha256::digest(&b[..])));
        }
    }
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (n, b) in &entries {
        w.start_file(n.clone(), zip::write::SimpleFileOptions::default()).unwrap();
        if n == "checksums.json" {
            w.write_all(&serde_json::to_vec(&checks).unwrap()).unwrap();
        } else {
            w.write_all(b).unwrap();
        }
    }
    w.finish().unwrap().into_inner()
}

async fn send(app: &App, ws: &Id, request: &Id) -> u16 {
    let out = app.send(Some(*request), ws, None, SendOptions::default(), EventCtx::none(), CancellationToken::new()).await.unwrap();
    out.record.response.as_ref().map(|r| r.status).unwrap_or_else(|| panic!("no response: {:?}", out.record.findings))
}

/// Send `request` and expect its auth to fail before anything is sent.
async fn refused_auth(app: &App, ws: &Id, request: &Id) {
    let out = app.send(Some(*request), ws, None, SendOptions::default(), EventCtx::none(), CancellationToken::new()).await.unwrap();
    assert!(out.record.findings.iter().any(|f| f.code == "local.auth_preparation_failed"), "{:?}", out.record.findings);
}

fn bearer(secret: &SecretRef, url: &str) -> RequestSpec {
    let mut spec = RequestSpec::http("GET", url);
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: secret.clone() }, prefix: "Bearer".into() };
    spec
}

/// An encrypted bundle as anyone could write one: a workspace of its own
/// whose request uses `secret`, with a value for that secret id.
fn bundle_reusing_secret_id(secret: &SecretRef, url: &str) -> Vec<u8> {
    let ws = Workspace {
        meta: Meta::new(),
        name: "Incoming".into(),
        description: String::new(),
        settings: Default::default(),
        variables: vec![],
        auth: AuthConfig::Inherit,
        active_environment_id: None,
    };
    let request = RequestDefinition {
        meta: Meta::new(),
        workspace_id: ws.meta.id,
        folder_id: None,
        name: "Use token".into(),
        description: String::new(),
        tags: vec![],
        favorite: false,
        sort_key: 1.0,
        spec: bearer(secret, url),
        revision_id: None,
    };
    let mut g = PortableGraph { workspaces: vec![ws.clone()], requests: vec![request], ..Default::default() };
    let value = SecretValue {
        label: secret.label.clone(),
        value: "placeholder-incoming".into(),
        workspace_id: Some(ws.meta.id.to_string()),
    };
    g.secrets.insert(secret.id.to_string(), value);
    let opts = ExportOptions {
        kind: BundleKind::Workspace,
        mode: ExportMode::EncryptedTransfer,
        passphrase: Some(EXPORT_PASS),
        include_history: false,
        kdf: KdfParams::testing(),
        app_version: "test",
    };
    bundle::write(&g, &opts).unwrap().0
}

#[tokio::test]
async fn duplicate_import_is_independent_of_its_source() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(Some(&ws.meta.id), "bearer", TOKEN).unwrap();
    let mut spec = RequestSpec::http("GET", &fx.url(&format!("/auth/bearer?token={TOKEN}")));
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: token.clone() }, prefix: "Bearer".into() };
    let original = a.create_request(&ws.meta.id, None, "Check token", spec).unwrap();
    let original_rev = original.revision_id.expect("saving creates a revision");
    assert_eq!(send(&a, &ws.meta.id, &original.meta.id).await, 200);

    // Duplicate the workspace into the same profile.
    let (bytes, preview) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    assert_eq!(preview.secrets_included, 1);
    let rep = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Duplicate).unwrap();
    assert_eq!(rep.workspace_ids.len(), 1);
    let copy_ws: Id = rep.workspace_ids[0].parse().unwrap();
    assert_ne!(copy_ws, ws.meta.id);
    let copies = a.requests(&copy_ws).unwrap();
    assert_eq!(copies.len(), 1);
    let copy = &copies[0];
    assert_ne!(copy.meta.id, original.meta.id);
    let copy_rev = copy.revision_id.expect("the copy has a revision");
    assert_ne!(copy_rev, original_rev, "the copy's revision is a new object");

    // The source is untouched: its request, revision and secret are its own.
    let source = a.request(&original.meta.id).unwrap();
    assert_eq!((source.workspace_id, source.revision_id), (ws.meta.id, Some(original_rev)));
    assert_eq!(a.revision(&original_rev).unwrap().request_id, original.meta.id);
    assert_eq!(a.revision(&copy_rev).unwrap().request_id, copy.meta.id);
    assert_eq!(a.store.list_secret_ids(Some(&ws.meta.id)).unwrap(), vec![token.id.to_string()]);
    let copy_secrets = a.store.list_secret_ids(Some(&copy_ws)).unwrap();
    assert_eq!(copy_secrets.len(), 1, "the copied secret is owned by the copied workspace");
    assert_ne!(copy_secrets[0], token.id.to_string());
    let AuthConfig::Bearer { token: SensitiveValue::Secret { secret }, .. } = &copy.spec.auth else { panic!("{:?}", copy.spec.auth) };
    assert_eq!(secret.id.to_string(), copy_secrets[0], "the copy uses its own secret");

    // Deleting the source leaves a working copy.
    a.delete_workspace(&ws.meta.id).unwrap();
    assert!(a.revision(&original_rev).is_err());
    assert_eq!(a.revision(&copy_rev).unwrap().request_id, copy.meta.id);
    assert_eq!(a.store.list_secret_ids(Some(&copy_ws)).unwrap(), copy_secrets);
    assert_eq!(send(&a, &copy_ws, &copy.meta.id).await, 200, "the copy still has its credentials");

    // And exporting the copy carries its secret and revision.
    let (bytes, preview) = a.export(Some(&copy_ws), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    assert_eq!(preview.secrets_included, 1);
    let opened = bundle::open(&bytes, Some(EXPORT_PASS)).unwrap();
    assert_eq!(opened.graph.revisions.iter().map(|r| r.id).collect::<Vec<_>>(), vec![copy_rev]);
    let expected = SecretValue { label: "bearer".into(), value: TOKEN.into(), workspace_id: Some(copy_ws.to_string()) };
    assert_eq!(opened.graph.secrets.get(&copy_secrets[0]), Some(&expected));
}

#[test]
fn duplicating_twice_gives_two_independent_copies() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(Some(&ws.meta.id), "bearer", TOKEN).unwrap();
    let mut spec = RequestSpec::http("GET", "https://api.example.test/");
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: token }, prefix: "Bearer".into() };
    a.create_request(&ws.meta.id, None, "Check token", spec).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    let first = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Duplicate).unwrap();
    let second = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Duplicate).unwrap();
    let (w1, w2): (Id, Id) = (first.workspace_ids[0].parse().unwrap(), second.workspace_ids[0].parse().unwrap());
    assert_ne!(w1, w2);
    let (r1, r2) = (a.requests(&w1).unwrap().remove(0), a.requests(&w2).unwrap().remove(0));
    assert_ne!(r1.revision_id, r2.revision_id);
    let (s1, s2) = (a.store.list_secret_ids(Some(&w1)).unwrap(), a.store.list_secret_ids(Some(&w2)).unwrap());
    assert_eq!((s1.len(), s2.len()), (1, 1));
    assert_ne!(s1, s2);
    a.delete_workspace(&w1).unwrap();
    assert_eq!(a.revision(&r2.revision_id.unwrap()).unwrap().request_id, r2.meta.id);
    assert_eq!(a.store.list_secret_ids(Some(&w2)).unwrap(), s2);
}

#[test]
fn merge_import_keeps_an_existing_secret() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(Some(&ws.meta.id), "bearer", TOKEN).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    a.store.put_secret(&token.id, Some(&ws.meta.id), "bearer", "placeholder-rotated-token").unwrap();
    a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    let (_, value) = a.store.get_secret(&token.id).unwrap().unwrap();
    assert_eq!(value.as_str(), "placeholder-rotated-token", "Merge keeps what already exists");
}

#[tokio::test]
async fn replace_import_never_takes_a_secret_from_another_workspace() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(Some(&ws.meta.id), "bearer", TOKEN).unwrap();
    let bytes = bundle_reusing_secret_id(&token, &fx.url("/echo"));
    let listed = format!("secret 'bearer' ({})", token.id);
    let untouched = |a: &App| {
        let (_, value) = a.store.get_secret(&token.id).unwrap().unwrap();
        assert_eq!(value.as_str(), TOKEN, "the stored value is kept");
        assert_eq!(a.store.list_secret_ids(Some(&ws.meta.id)).unwrap(), vec![token.id.to_string()], "and so is its owner");
    };

    // The preview lists the secret, as a conflict and as owned outside the bundle.
    let preview = a.import_preview(&bytes, Some(EXPORT_PASS), ConflictPolicy::Replace).unwrap();
    assert_eq!(preview.plan.foreign_secrets, vec![listed.clone()]);
    assert!(preview.plan.conflicts.contains(&listed), "{:?}", preview.plan.conflicts);

    // Replace refuses the whole bundle.
    let e = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Replace).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains(&listed)), "{e}");
    assert_eq!(a.workspaces().unwrap().len(), 1, "nothing was imported");
    untouched(&a);

    // Merge keeps the stored secret, and the imported request cannot use it.
    let rep = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    assert_eq!(rep.plan.foreign_secrets, vec![listed]);
    untouched(&a);
    let incoming: Id = rep.workspace_ids[0].parse().unwrap();
    let request = a.requests(&incoming).unwrap().remove(0);
    refused_auth(&a, &incoming, &request.meta.id).await;
    assert_eq!(fx.log.count_requests(), 0, "the other workspace's secret was never sent");
}

#[test]
fn replace_import_restores_a_secret_its_own_workspace_owns() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(Some(&ws.meta.id), "bearer", TOKEN).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    a.store.put_secret(&token.id, Some(&ws.meta.id), "bearer", "placeholder-rotated-token").unwrap();
    let rep = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Replace).unwrap();
    assert!(rep.plan.foreign_secrets.is_empty(), "{:?}", rep.plan);
    assert!(rep.plan.conflicts.contains(&format!("secret 'bearer' ({})", token.id)), "{:?}", rep.plan.conflicts);
    let (_, value) = a.store.get_secret(&token.id).unwrap().unwrap();
    assert_eq!(value.as_str(), TOKEN, "Replace restores the bundle's value");
    assert_eq!(a.store.list_secret_ids(Some(&ws.meta.id)).unwrap(), vec![token.id.to_string()]);
}

#[tokio::test]
async fn a_request_resolves_only_secrets_its_own_workspace_owns() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(Some(&ws.meta.id), "bearer", TOKEN).unwrap();
    let url = fx.url(&format!("/auth/bearer?token={TOKEN}"));
    let own = a.create_request(&ws.meta.id, None, "Check token", bearer(&token, &url)).unwrap();
    assert_eq!(send(&a, &ws.meta.id, &own.meta.id).await, 200);
    let sent = fx.log.count_requests();

    // Another workspace that names the secret's id cannot use it.
    let other = a.create_workspace("Other").unwrap();
    let borrowed = a.create_request(&other.meta.id, None, "Borrow token", bearer(&token, &url)).unwrap();
    refused_auth(&a, &other.meta.id, &borrowed.meta.id).await;
    let mut w = a.workspace(&other.meta.id).unwrap();
    w.variables.push(Variable {
        name: "token".into(),
        value: SensitiveValue::Secret { secret: token.clone() },
        secret: true,
        enabled: true,
        description: String::new(),
    });
    a.save_workspace(w).unwrap();
    let Err(e) = a.build_context(Some(borrowed.meta.id), &other.meta.id, None, &SendOptions::default()) else {
        panic!("a variable naming another workspace's secret resolved")
    };
    assert!(e.to_string().contains("not in this workspace's vault"), "{e}");

    // Neither can any workspace use a secret no workspace owns.
    let unowned = a.set_secret(None, "unowned", TOKEN).unwrap();
    let orphan = a.create_request(&ws.meta.id, None, "Unowned token", bearer(&unowned, &url)).unwrap();
    refused_auth(&a, &ws.meta.id, &orphan.meta.id).await;
    assert_eq!(fx.log.count_requests(), sent, "nothing more was sent");
    assert_eq!(send(&a, &ws.meta.id, &own.meta.id).await, 200, "the owner still uses its secret");
}

#[tokio::test]
async fn a_duplicate_without_the_secret_never_uses_its_sources() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(Some(&ws.meta.id), "bearer", TOKEN).unwrap();
    let url = fx.url(&format!("/auth/bearer?token={TOKEN}"));
    let original = a.create_request(&ws.meta.id, None, "Check token", bearer(&token, &url)).unwrap();

    // A share-safe bundle carries the reference but not the secret.
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, false).unwrap();
    let rep = a.import(&bytes, None, ConflictPolicy::Duplicate).unwrap();
    assert_eq!(rep.missing_secrets.len(), 1, "{:?}", rep.missing_secrets);
    let copy_ws: Id = rep.workspace_ids[0].parse().unwrap();
    let copy = a.requests(&copy_ws).unwrap().remove(0);
    refused_auth(&a, &copy_ws, &copy.meta.id).await;
    assert_eq!(fx.log.count_requests(), 0, "the copy never sent its source's secret");
    assert_eq!(send(&a, &ws.meta.id, &original.meta.id).await, 200, "the source still works");
}

#[test]
fn bundles_this_build_cannot_read_change_nothing() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    a.set_secret(Some(&ws.meta.id), "bearer", TOKEN).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();

    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "b");
    let future = anvil_domain::SCHEMA_VERSION + 100;
    let newer = edit_manifest(&bytes, |m| m["schema_version"] = future.into());
    let costly = edit_manifest(&bytes, |m| m["vault"]["kdf"]["m_cost"] = u32::MAX.into());
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace, ConflictPolicy::Duplicate] {
        let e = b.import_preview(&newer, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::FutureSchema { found, .. }) if found == future), "{e}");
        let e = b.import(&newer, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::FutureSchema { found, .. }) if found == future), "{e}");
        let e = b.import(&costly, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::UnsupportedKdf(_))), "{e}");
    }
    assert!(b.workspaces().unwrap().is_empty(), "nothing was imported");
    assert!(b.store.list_secret_ids(None).unwrap().is_empty());

    // The same bundle at the current schema imports.
    b.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    assert_eq!(b.workspaces().unwrap().len(), 1);
}
