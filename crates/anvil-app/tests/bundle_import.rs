//! Bundle import into a profile: a Duplicate copy is independent of its
//! source, a secret stays with the workspace that owns it, and bundles this
//! build cannot read change nothing.

use anvil_app::exec::SendOptions;
use anvil_app::port::ImportApproval;
use anvil_app::profiles::ProfileManager;
use anvil_app::runner::RunSettings;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::load::{LoadPlan, Workload};
use anvil_domain::request::{AttachmentRef, Body, MultipartContent, MultipartPart, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::workspace::{
    Dataset, DatasetFormat, Meta, RequestDefinition, RequestRevision, Scenario, ScenarioStep, Variable, Workspace,
};
use anvil_portability::bundle::{self, BundleError, BundleKind, ExportOptions};
use anvil_portability::plan::{ConflictPolicy, ExistingWorkspace};
use anvil_portability::{ExportMode, PortableGraph, SecretValue};
use anvil_storage::{KdfParams, kind};
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

/// Approval to write into the stored workspace `ws`.
fn into(ws: &Id, file: &[u8]) -> ImportApproval {
    ImportApproval::for_file(file, vec![*ws])
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

/// A saved request named `name` in workspace `ws`.
fn request_in(ws: Id, name: &str, spec: RequestSpec) -> RequestDefinition {
    RequestDefinition {
        meta: Meta::new(),
        workspace_id: ws,
        folder_id: None,
        name: name.into(),
        description: String::new(),
        tags: vec![],
        favorite: false,
        sort_key: 1.0,
        spec,
        revision_id: None,
    }
}

/// `g` as an encrypted bundle: anyone with this build can write one, so its
/// encryption says nothing about who did.
fn encrypted(g: &PortableGraph) -> Vec<u8> {
    let opts = ExportOptions {
        kind: BundleKind::Workspace,
        mode: ExportMode::EncryptedTransfer,
        passphrase: Some(EXPORT_PASS),
        include_history: false,
        kdf: KdfParams::testing(),
        app_version: "test",
    };
    bundle::write(g, &opts).unwrap().0
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
    let request = request_in(ws.meta.id, "Use token", bearer(secret, url));
    let mut g = PortableGraph { workspaces: vec![ws.clone()], requests: vec![request], ..Default::default() };
    let value =
        SecretValue { label: secret.label.clone(), value: "placeholder-incoming".into(), workspace_id: Some(ws.meta.id.to_string()) };
    g.secrets.insert(secret.id.to_string(), value);
    encrypted(&g)
}

#[tokio::test]
async fn duplicate_import_is_independent_of_its_source() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
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
    let token = a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
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
    let token = a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    a.store.put_secret(&token.id, Some(&ws.meta.id), "bearer", "placeholder-rotated-token").unwrap();
    a.import_approved(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge, &into(&ws.meta.id, &bytes)).unwrap();
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
    let token = a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
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
    let token = a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    a.store.put_secret(&token.id, Some(&ws.meta.id), "bearer", "placeholder-rotated-token").unwrap();
    let rep = a.import_approved(&bytes, Some(EXPORT_PASS), ConflictPolicy::Replace, &into(&ws.meta.id, &bytes)).unwrap();
    assert!(rep.plan.foreign_secrets.is_empty() && rep.plan.foreign_objects.is_empty(), "{:?}", rep.plan);
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
    let token = a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
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

    // Neither can any workspace use a secret no workspace owns (only older
    // builds stored one).
    let unowned = SecretRef { id: Id::new(), label: "unowned".into() };
    a.store.put_secret(&unowned.id, None, &unowned.label, TOKEN).unwrap();
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
    let token = a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
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
    a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
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

#[tokio::test]
async fn a_bundle_that_claims_a_stored_workspace_is_refused_until_approved() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let token = a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();

    // A bundle that names the stored workspace's id (ids travel in every
    // bundle) and adds a request there that sends its secret to any URL.
    let claimed = Workspace { name: "Look-alike".into(), variables: vec![Variable::plain("base", "placeholder")], ..ws.clone() };
    let request = request_in(ws.meta.id, "Use token", bearer(&token, &fx.url("/echo")));
    let bytes = encrypted(&PortableGraph { workspaces: vec![claimed], requests: vec![request], ..Default::default() });
    let expected = vec![ExistingWorkspace { id: ws.meta.id, name: "Payments".into() }];
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
        // The preview names the stored workspace...
        let preview = a.import_preview(&bytes, Some(EXPORT_PASS), policy).unwrap();
        assert_eq!(preview.plan.existing_workspaces, expected, "{policy:?}");
        // ...and applying without approving it, or approving another one, is refused.
        let e = a.import(&bytes, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(matches!(&e, AppError::Invalid(m) if m.contains("existing workspace 'Payments'")), "{policy:?}: {e}");
        let e = a.import_approved(&bytes, Some(EXPORT_PASS), policy, &into(&Id::new(), &bytes)).unwrap_err();
        assert!(matches!(&e, AppError::Invalid(m) if m.contains("existing workspace 'Payments'")), "{policy:?}: {e}");
    }
    // Nothing was written: the workspace, its requests and its secret are as they were.
    assert_eq!(a.workspaces().unwrap(), vec![ws.clone()]);
    assert!(a.requests(&ws.meta.id).unwrap().is_empty());
    assert_eq!(a.store.list_secret_ids(Some(&ws.meta.id)).unwrap(), vec![token.id.to_string()]);

    // A Duplicate copy claims no stored workspace, and its request cannot use the secret.
    let preview = a.import_preview(&bytes, Some(EXPORT_PASS), ConflictPolicy::Duplicate).unwrap();
    assert!(preview.plan.existing_workspaces.is_empty(), "{:?}", preview.plan);
    let rep = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Duplicate).unwrap();
    let copy_ws: Id = rep.workspace_ids[0].parse().unwrap();
    assert_ne!(copy_ws, ws.meta.id);
    let copy = a.requests(&copy_ws).unwrap().remove(0);
    refused_auth(&a, &copy_ws, &copy.meta.id).await;
    assert_eq!(fx.log.count_requests(), 0, "the stored workspace's secret was never sent");

    // Once the user approves the stored workspace, Merge writes into it.
    let rep = a.import_approved(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge, &into(&ws.meta.id, &bytes)).unwrap();
    assert_eq!(rep.workspace_ids, vec![ws.meta.id.to_string()]);
    assert_eq!(a.requests(&ws.meta.id).unwrap().len(), 1);
    assert_eq!(a.workspace(&ws.meta.id).unwrap(), ws, "Merge keeps the stored workspace itself");
}

#[test]
fn replace_never_overwrites_an_object_of_another_workspace() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let folder = a.create_folder(&ws.meta.id, None, "Orders").unwrap();

    // A bundle with a workspace of its own and a folder that reuses the
    // stored folder's id, with variables of its own.
    let incoming = Workspace { meta: Meta::new(), name: "Incoming".into(), ..ws.clone() };
    let mut look_alike = folder.clone();
    look_alike.workspace_id = incoming.meta.id;
    look_alike.variables.push(Variable::plain("base", "https://elsewhere.example.test"));
    let bytes = encrypted(&PortableGraph { workspaces: vec![incoming], folders: vec![look_alike], ..Default::default() });
    let listed = format!("folder 'Orders' ({})", folder.meta.id);

    let preview = a.import_preview(&bytes, Some(EXPORT_PASS), ConflictPolicy::Replace).unwrap();
    assert_eq!(preview.plan.foreign_objects, vec![listed.clone()]);
    assert!(preview.plan.existing_workspaces.is_empty(), "{:?}", preview.plan);
    let e = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Replace).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains(&listed)), "{e}");
    assert_eq!(a.workspaces().unwrap().len(), 1, "nothing was imported");
    assert_eq!(a.folder(&folder.meta.id).unwrap(), folder, "the folder stays in its workspace, unchanged");

    // Merge keeps the stored folder.
    let rep = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    assert_eq!(rep.plan.foreign_objects, vec![listed]);
    assert_eq!(a.folder(&folder.meta.id).unwrap(), folder);
}

#[test]
fn a_request_is_prepared_only_in_its_own_workspace_and_folders() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let other = a.create_workspace("Other").unwrap();
    // The request names a secret of the other workspace.
    let token = a.set_secret(&other.meta.id, "bearer", TOKEN).unwrap();
    let request = a.create_request(&ws.meta.id, None, "Check token", bearer(&token, "https://api.example.test/")).unwrap();

    // Prepared as if it were in the other workspace, it would resolve that
    // workspace's secrets: refused.
    let Err(e) = a.build_context(Some(request.meta.id), &other.meta.id, None, &SendOptions::default()) else {
        panic!("a request was prepared in another workspace")
    };
    assert!(matches!(&e, AppError::Invalid(m) if m.contains("request 'Check token' is not in this workspace")), "{e}");
    // In its own workspace it is prepared as usual.
    let ctx = a.build_context(Some(request.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
    assert_eq!(ctx.workspace_id, Some(ws.meta.id));

    // A request whose folder is in another workspace takes nothing from it.
    let folder = a.create_folder(&other.meta.id, None, "Orders").unwrap();
    let mut stray = request.clone();
    stray.meta = Meta::new();
    stray.folder_id = Some(folder.meta.id);
    a.store.put(kind::REQUEST, &stray.meta.id, Some(&ws.meta.id), stray.folder_id.as_ref(), stray.sort_key, &stray).unwrap();
    let Err(e) = a.build_context(Some(stray.meta.id), &ws.meta.id, None, &SendOptions::default()) else {
        panic!("a folder of another workspace was followed")
    };
    assert!(matches!(&e, AppError::Invalid(m) if m.contains("folder 'Orders' is not in this workspace")), "{e}");
}

#[test]
fn a_secret_needs_a_stored_workspace() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let e = a.set_secret(&Id::new(), "bearer", TOKEN).unwrap_err();
    assert!(matches!(e, AppError::NotFound(_)), "{e}");
    assert!(a.store.list_secret_ids(None).unwrap().is_empty(), "nothing was stored");
}

#[test]
fn every_stored_workspace_a_bundle_claims_needs_approval() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let payments = a.create_workspace("Payments").unwrap();
    let billing = a.create_workspace("Billing").unwrap();

    // A bundle that claims both stored workspaces and adds a request to one.
    let request = request_in(billing.meta.id, "Probe", RequestSpec::http("GET", "https://elsewhere.example.test/"));
    let g = PortableGraph { workspaces: vec![payments.clone(), billing.clone()], requests: vec![request], ..Default::default() };
    let bytes = encrypted(&g);
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
        let preview = a.import_preview(&bytes, Some(EXPORT_PASS), policy).unwrap();
        assert_eq!(preview.plan.existing_workspaces.len(), 2, "{policy:?}");
        // Approving only one of them refuses the whole import, naming the other.
        let e = a.import_approved(&bytes, Some(EXPORT_PASS), policy, &into(&payments.meta.id, &bytes)).unwrap_err();
        assert!(
            matches!(&e, AppError::Invalid(m) if m.contains("existing workspace 'Billing'") && !m.contains("'Payments'")),
            "{policy:?}: {e}"
        );
    }
    assert!(a.requests(&billing.meta.id).unwrap().is_empty(), "nothing was imported");
    assert!(a.requests(&payments.meta.id).unwrap().is_empty(), "nothing was imported");

    // Approving both, Merge writes into them.
    let both = ImportApproval::for_file(&bytes, vec![payments.meta.id, billing.meta.id]);
    a.import_approved(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge, &both).unwrap();
    assert_eq!(a.requests(&billing.meta.id).unwrap().len(), 1);
}

#[test]
fn replace_never_overwrites_a_revision_of_another_workspace() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let request = a.create_request(&ws.meta.id, None, "Charge", RequestSpec::http("POST", "https://api.example.test/charge")).unwrap();
    let rid = request.revision_id.expect("a saved request has a revision");
    let revision = a.revision(&rid).unwrap();

    // A bundle with a workspace and a request of its own whose revision
    // reuses the stored revision's id, with a spec of its own.
    let incoming = Workspace { meta: Meta::new(), name: "Incoming".into(), ..ws.clone() };
    let mut look_alike = request_in(incoming.meta.id, "Look-alike", RequestSpec::http("GET", "https://elsewhere.example.test/"));
    look_alike.revision_id = Some(rid);
    let rev = RequestRevision { request_id: look_alike.meta.id, spec: look_alike.spec.clone(), ..revision.clone() };
    let g = PortableGraph { workspaces: vec![incoming], requests: vec![look_alike], revisions: vec![rev], ..Default::default() };
    let bytes = encrypted(&g);
    let listed = format!("revision 'Look-alike' ({rid})");

    let preview = a.import_preview(&bytes, Some(EXPORT_PASS), ConflictPolicy::Replace).unwrap();
    assert_eq!(preview.plan.foreign_objects, vec![listed.clone()]);
    let e = a.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Replace).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains(&listed)), "{e}");
    assert_eq!(a.workspaces().unwrap().len(), 1, "nothing was imported");
    assert_eq!(a.revision(&rid).unwrap(), revision, "the revision stays with its request, unchanged");
    assert_eq!(a.request(&request.meta.id).unwrap(), request);
}

#[tokio::test]
async fn a_scenario_never_runs_with_a_dataset_of_another_workspace() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let rows = a.create_dataset(&ws.meta.id, "customers", DatasetFormat::Csv, b"card\nplaceholder-card\n", vec![]).unwrap();

    // A bundle with a workspace of its own whose dataset reuses the stored
    // dataset's id, and a scenario there that sends each row.
    let incoming = Workspace { meta: Meta::new(), name: "Incoming".into(), ..ws.clone() };
    let look_alike = Dataset { workspace_id: incoming.meta.id, ..rows.clone() };
    let send_row = request_in(incoming.meta.id, "Send row", RequestSpec::http("POST", "http://127.0.0.1:9/{{card}}"));
    let scenario = Scenario {
        meta: Meta::new(),
        workspace_id: incoming.meta.id,
        name: "Smoke".into(),
        description: String::new(),
        steps: vec![ScenarioStep { request_id: send_row.meta.id, enabled: true, delay_ms: 0 }],
        dataset_id: Some(rows.meta.id),
        iterations: 0,
        stop_on_failure: false,
        trusted: false,
    };
    let mut g = PortableGraph {
        workspaces: vec![incoming.clone()],
        requests: vec![send_row],
        datasets: vec![look_alike],
        scenarios: vec![scenario.clone()],
        ..Default::default()
    };
    g.attachments.insert(sha(&rows.attachment), b"card\nplaceholder-card\n".to_vec());
    let rep = a.import(&encrypted(&g), Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    assert_eq!(rep.plan.foreign_objects, vec![format!("dataset 'customers' ({})", rows.meta.id)]);
    // Merge keeps the stored dataset in its own workspace and adds the scenario.
    assert_eq!(a.dataset(&rows.meta.id).unwrap(), rows);
    assert_eq!(a.scenario(&scenario.meta.id).unwrap().workspace_id, incoming.meta.id);

    // Even allowed to run, the imported scenario never reads the stored rows.
    let settings = RunSettings { allow_untrusted: true, record_history: true, persist_report: false, ..Default::default() };
    let Err(e) = a.run_scenario(&scenario.meta.id, settings, CancellationToken::new()).await else {
        panic!("a scenario ran with a dataset of another workspace")
    };
    assert!(matches!(&e, AppError::Invalid(m) if m.contains("the dataset belongs to another workspace")), "{e}");
    assert!(a.store.list_history(None, None, 10).unwrap().is_empty(), "nothing was sent");
    // Nor can it be saved with it.
    let Err(e) = a.update_scenario(a.scenario(&scenario.meta.id).unwrap()) else {
        panic!("a scenario was saved with a dataset of another workspace")
    };
    assert!(matches!(&e, AppError::Invalid(m) if m.contains("the dataset belongs to another workspace")), "{e}");
}

fn sha(a: &AttachmentRef) -> String {
    match a {
        AttachmentRef::Stored { sha256, .. } => sha256.clone(),
        other => panic!("unexpected attachment {other:?}"),
    }
}

fn upload(body: Body) -> RequestSpec {
    RequestSpec { body, ..RequestSpec::http("POST", "http://127.0.0.1:9/upload") }
}

fn file_part(attachment: AttachmentRef) -> MultipartPart {
    MultipartPart {
        name: "file".into(),
        enabled: true,
        content: MultipartContent::File { attachment, file_name: None },
        content_type: None,
    }
}

#[test]
fn a_stored_attachment_is_imported_only_with_its_bytes() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let rows = a.create_dataset(&ws.meta.id, "customers", DatasetFormat::Csv, b"card\nplaceholder-card\n", vec![]).unwrap();
    let file = a.put_attachment("statement.bin", b"placeholder statement", None).unwrap();
    let binary = upload(Body::Binary { attachment: file.clone(), content_type: None });
    let multipart = upload(Body::Multipart { parts: vec![file_part(file.clone())] });
    a.create_request(&ws.meta.id, None, "Binary", binary.clone()).unwrap();
    a.create_request(&ws.meta.id, None, "Multipart", multipart.clone()).unwrap();

    // Bundles with a workspace of their own that name those attachments by
    // content hash without carrying their bytes.
    let incoming = Workspace { meta: Meta::new(), name: "Incoming".into(), ..ws.clone() };
    let theirs = incoming.meta.id;
    let only = |edit: &dyn Fn(&mut PortableGraph)| {
        let mut g = PortableGraph { workspaces: vec![incoming.clone()], ..Default::default() };
        edit(&mut g);
        encrypted(&g)
    };
    let bundles = [
        ("dataset", only(&|g| g.datasets.push(Dataset { meta: Meta::new(), workspace_id: theirs, ..rows.clone() }))),
        ("binary body", only(&|g| g.requests.push(request_in(theirs, "Binary", binary.clone())))),
        ("multipart part", only(&|g| g.requests.push(request_in(theirs, "Multipart", multipart.clone())))),
    ];
    for (label, bytes) in &bundles {
        let e = a.import_preview(bytes, Some(EXPORT_PASS), ConflictPolicy::Duplicate).unwrap_err();
        assert!(e.to_string().contains("uses a stored attachment that the bundle does not carry"), "{label}: {e}");
        for policy in [ConflictPolicy::Duplicate, ConflictPolicy::Merge] {
            let e = a.import(bytes, Some(EXPORT_PASS), policy).unwrap_err();
            assert!(e.to_string().contains("uses a stored attachment that the bundle does not carry"), "{label}: {e}");
        }
    }
    assert_eq!(a.workspaces().unwrap().len(), 1, "nothing was imported");

    // An exported workspace carries the bytes of every attachment it uses.
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, false).unwrap();
    for (name, policy) in [("duplicate", ConflictPolicy::Duplicate), ("merge", ConflictPolicy::Merge)] {
        let b = new_app(root.path(), name);
        let rep = b.import(&bytes, None, policy).unwrap();
        let copy: Id = rep.workspace_ids[0].parse().unwrap();
        let data = b.datasets(&copy).unwrap().pop().unwrap();
        assert_eq!(b.run_dataset(&data).unwrap().rows.len(), 1, "{name}");
        assert_eq!(b.get_attachment(&sha(&file)).unwrap().as_deref(), Some(&b"placeholder statement"[..]), "{name}");
        assert_eq!(b.requests(&copy).unwrap().len(), 2, "{name}");
    }
    let rep = a.import(&bytes, None, ConflictPolicy::Duplicate).unwrap();
    assert_eq!(a.datasets(&rep.workspace_ids[0].parse().unwrap()).unwrap().len(), 1);
}

#[test]
fn a_stored_attachment_whose_content_is_not_stored_here_imports_with_a_warning() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    // A stored attachment whose content this profile does not hold, as after
    // the loss of its blob or a request created through the API.
    let lost = b"content that is not stored here";
    let sha256 = hex::encode(sha2::Sha256::digest(lost));
    let missing = AttachmentRef::Stored { sha256: sha256.clone(), size: lost.len() as u64, file_name: "lost.bin".into(), media_type: None };
    a.create_request(&ws.meta.id, None, "Upload", upload(Body::Binary { attachment: missing, content_type: None })).unwrap();

    // The export says which request travels without its file.
    let preview = a.export_preview(Some(&ws.meta.id), ExportMode::EncryptedTransfer, false).unwrap();
    let excluded = &preview.manifest.excluded;
    assert!(excluded.iter().any(|x| x.contains("a stored file of request 'Upload'")), "{excluded:?}");
    let (bytes, written) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    assert_eq!(written.manifest.excluded, preview.manifest.excluded);

    // A profile that does not store that content imports the bundle, with a
    // warning naming the request.
    let warning = "request 'Upload' uses a stored file that the bundle does not include; it will fail until the file is attached again.";
    let b = new_app(root.path(), "b");
    let preview = b.import_preview(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    assert!(preview.warnings.iter().any(|w| w == warning), "{:?}", preview.warnings);
    let rep = b.import(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    assert!(rep.warnings.iter().any(|w| w == warning), "{:?}", rep.warnings);
    assert_eq!(b.requests(&ws.meta.id).unwrap().len(), 1);
    assert!(b.get_attachment(&sha256).unwrap().is_none(), "nothing stands in for the missing content");

    // A profile that stores that content refuses the same bundle under every
    // policy: the request would send those bytes.
    let c = new_app(root.path(), "c");
    c.put_attachment("mine.bin", lost, None).unwrap();
    let needle = "request 'Upload' uses a stored attachment that the bundle does not carry";
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace, ConflictPolicy::Duplicate] {
        let e = c.import_preview(&bytes, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(e.to_string().contains(needle), "{policy:?}: {e}");
        let e = c.import(&bytes, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(e.to_string().contains(needle), "{policy:?}: {e}");
    }
    assert!(c.workspaces().unwrap().is_empty(), "nothing was imported");
}

#[test]
fn bundles_describing_a_full_backup_are_never_written_or_restored() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
    // Full backups are ANVILBAK files; bundle exports refuse the mode.
    for scope in [Some(&ws.meta.id), None] {
        let e = a.export(scope, ExportMode::FullBackup, Some(EXPORT_PASS), false).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::FullBackupNotABundle)), "{e}");
        let e = a.export_preview(scope, ExportMode::FullBackup, false).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::FullBackupNotABundle)), "{e}");
    }
    // A bundle of every workspace is a workspace bundle, not a backup.
    let (all, preview) = a.export(None, ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();
    assert_eq!(preview.manifest.kind, BundleKind::Workspace);

    // The zip full backup of early builds: an authentic vault, and a manifest
    // naming the backup kind and mode.
    let legacy = edit_manifest(&all, |m| {
        m["kind"] = "backup".into();
        m["mode"] = "full_backup".into();
    });
    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "b");
    let before = b.backup_contents().unwrap();
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace, ConflictPolicy::Duplicate] {
        let e = b.import_preview(&legacy, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::LegacyFullBackup)), "{e}");
        assert!(e.to_string().contains("legacy full backups are not supported; restore from an ANVILBAK backup"), "{e}");
        let e = b.import(&legacy, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::LegacyFullBackup)), "{e}");
    }
    // Nor is it taken for an ANVILBAK backup.
    assert!(!anvil_app::backup::is_backup(&legacy));
    assert!(b.restore(&legacy, Some(EXPORT_PASS), ConflictPolicy::Merge).is_err());
    assert!(b.workspaces().unwrap().is_empty(), "nothing was restored");
    assert!(b.store.list_secret_ids(None).unwrap().is_empty(), "no secret was restored");
    assert!(b.backup_contents().unwrap() == before, "a refused legacy backup changed the profile");

    // The same bundle with its own manifest imports.
    b.import(&all, Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    assert_eq!(b.workspaces().unwrap().len(), 1);
}

fn load_plan(ws: Id, request: Id) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: ws,
        name: "smoke".into(),
        workload: Workload::Iterations { iterations: 2, concurrency: 1 },
        chain: vec![request],
        mix: vec![],
        dataset_id: None,
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

#[tokio::test]
async fn an_import_stores_the_load_plans_and_history_the_bundle_carries() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let request = a.create_request(&ws.meta.id, None, "Echo", RequestSpec::http("GET", &fx.url("/echo"))).unwrap();
    let opts = SendOptions { record_history: true, ..Default::default() };
    a.send(Some(request.meta.id), &ws.meta.id, None, opts, EventCtx::none(), CancellationToken::new()).await.unwrap();
    let sent = a.store.list_history(Some(&ws.meta.id), None, 10).unwrap();
    assert_eq!(sent.len(), 1);
    let plan = a.save_load_plan(load_plan(ws.meta.id, request.meta.id)).unwrap();
    // A plan whose request was deleted since would make the bundle
    // unimportable; it stays behind, listed among the excluded items.
    let gone = a.create_request(&ws.meta.id, None, "Gone", RequestSpec::http("GET", &fx.url("/echo"))).unwrap();
    a.save_load_plan(LoadPlan { name: "stale".into(), ..load_plan(ws.meta.id, gone.meta.id) }).unwrap();
    a.delete_request(&gone.meta.id).unwrap();
    let (bytes, preview) = a.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, true).unwrap();
    assert_eq!((preview.manifest.counts["load_plans"], preview.manifest.counts["history"]), (1, 1));
    let excluded = &preview.manifest.excluded;
    assert!(excluded.iter().any(|x| x.starts_with("load plan 'stale'")), "{excluded:?}");
    assert!(!excluded.iter().any(|x| x.contains("'smoke'")), "{excluded:?}");
    let planned = a.export_preview(Some(&ws.meta.id), ExportMode::ShareSafely, true).unwrap();
    assert_eq!(planned.manifest.excluded, preview.manifest.excluded);

    // Into another profile, under the bundle's own ids.
    let b = new_app(root.path(), "b");
    let rep = b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    assert!(rep.plan.conflicts.is_empty(), "nothing is stored there yet: {:?}", rep.plan.conflicts);
    let plans = b.load_plans(&ws.meta.id).unwrap();
    assert_eq!(plans.iter().map(|p| p.id).collect::<Vec<_>>(), vec![plan.id]);
    assert!(!plans[0].trusted, "an imported plan never starts on its own");
    let history = b.store.list_history(Some(&ws.meta.id), Some(&request.meta.id), 10).unwrap();
    assert_eq!(history.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(), vec![sent[0].id.as_str()]);
    // Merging the same bundle again keeps what is there.
    let again = b.import_approved(&bytes, None, ConflictPolicy::Merge, &into(&ws.meta.id, &bytes)).unwrap();
    assert!(again.plan.conflicts.contains(&format!("history ({})", sent[0].id)), "{:?}", again.plan.conflicts);
    assert!(again.plan.conflicts.contains(&format!("load_plan 'smoke' ({})", plan.id)), "{:?}", again.plan.conflicts);
    assert_eq!(b.load_plans(&ws.meta.id).unwrap().len(), 1);
    assert_eq!(b.store.list_history(Some(&ws.meta.id), None, 10).unwrap().len(), 1);

    // A Duplicate copy gets its own plan and record, linked to the copied request.
    let dup = a.import(&bytes, None, ConflictPolicy::Duplicate).unwrap();
    let copy: Id = dup.workspace_ids[0].parse().unwrap();
    let copy_request = a.requests(&copy).unwrap().remove(0);
    let copy_plan = a.load_plans(&copy).unwrap().remove(0);
    assert_ne!(copy_plan.id, plan.id);
    assert_eq!(copy_plan.chain, vec![copy_request.meta.id]);
    let copied = a.store.list_history(Some(&copy), None, 10).unwrap();
    assert_eq!(copied.len(), 1);
    assert_ne!(copied[0].id, sent[0].id, "a copied record never reuses the source's id");
    assert_eq!(copied[0].request_id, Some(copy_request.meta.id.to_string()));
    let source = a.store.list_history(Some(&ws.meta.id), None, 10).unwrap();
    assert_eq!(source.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(), vec![sent[0].id.as_str()], "the source's history is untouched");
    assert_eq!(a.load_plans(&ws.meta.id).unwrap().len(), 2, "and so are its plans");
}

#[tokio::test]
async fn an_imported_history_record_is_never_dated_after_its_import() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let request = a.create_request(&ws.meta.id, None, "Echo", RequestSpec::http("GET", &fx.url("/echo"))).unwrap();
    let opts = SendOptions { record_history: true, ..Default::default() };
    a.send(Some(request.meta.id), &ws.meta.id, None, opts, EventCtx::none(), CancellationToken::new()).await.unwrap();
    let mut g = a.graph(Some(&ws.meta.id), false, true).unwrap();
    assert_eq!(g.history.len(), 1);
    g.history[0]["started_at"] = "2999-01-01T00:00:00Z".into();
    let opts = ExportOptions {
        kind: BundleKind::Workspace,
        mode: ExportMode::ShareSafely,
        passphrase: None,
        include_history: true,
        kdf: KdfParams::testing(),
        app_version: "test",
    };
    let (bytes, _) = bundle::write(&g, &opts).unwrap();

    let b = new_app(root.path(), "b");
    let before = chrono::Utc::now();
    b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    let after = chrono::Utc::now();
    let stored = b.store.list_history(Some(&ws.meta.id), None, 10).unwrap();
    assert_eq!(stored.len(), 1);
    let at = stored[0].started_at;
    assert!(before.timestamp_millis() <= at && at <= after.timestamp_millis(), "stored at {at}");
    let (record, _) = b.store.get_history::<anvil_domain::execution::ExecutionRecord>(&stored[0].id).unwrap().unwrap();
    assert_eq!(record.started_at.timestamp_millis(), at);
}

#[test]
fn an_approval_holds_only_for_the_previewed_file() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    let probe = request_in(ws.meta.id, "Probe", RequestSpec::http("GET", "https://api.example.test/"));
    let previewed = encrypted(&PortableGraph { workspaces: vec![ws.clone()], requests: vec![probe], ..Default::default() });
    // Another file that claims the same workspace, as if the previewed one
    // were replaced before the import was applied.
    let other = request_in(ws.meta.id, "Other", RequestSpec::http("GET", "https://elsewhere.example.test/"));
    let replaced = encrypted(&PortableGraph { workspaces: vec![ws.clone()], requests: vec![other], ..Default::default() });

    let preview = a.import_preview(&previewed, Some(EXPORT_PASS), ConflictPolicy::Merge).unwrap();
    assert_eq!(preview.bundle_sha256, anvil_app::port::file_sha256(&previewed));
    assert_eq!(preview.plan.existing_workspaces.len(), 1);
    let approval = ImportApproval { existing_workspaces: vec![ws.meta.id], bundle_sha256: Some(preview.bundle_sha256.clone()) };
    let e = a.import_approved(&replaced, Some(EXPORT_PASS), ConflictPolicy::Merge, &approval).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains("not the one that was previewed")), "{e}");
    // An approval of a stored workspace that names no file approves nothing.
    let unbound = ImportApproval { existing_workspaces: vec![ws.meta.id], bundle_sha256: None };
    let e = a.import_approved(&previewed, Some(EXPORT_PASS), ConflictPolicy::Merge, &unbound).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains("bundle_sha256")), "{e}");
    assert!(a.requests(&ws.meta.id).unwrap().is_empty(), "nothing was imported");

    // The previewed file imports under the approval given for it.
    let rep = a.import_approved(&previewed, Some(EXPORT_PASS), ConflictPolicy::Merge, &approval).unwrap();
    assert_eq!(rep.bundle_sha256, preview.bundle_sha256);
    let names: Vec<String> = a.requests(&ws.meta.id).unwrap().into_iter().map(|r| r.name).collect();
    assert_eq!(names, vec!["Probe".to_string()]);
}

#[test]
fn a_passphrase_is_refused_for_a_bundle_that_is_not_encrypted() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    a.create_request(&ws.meta.id, None, "Probe", RequestSpec::http("GET", "https://api.example.test/")).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, false).unwrap();
    let b = new_app(root.path(), "b");
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace, ConflictPolicy::Duplicate] {
        let e = b.import_preview(&bytes, Some(EXPORT_PASS), policy).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::NotEncrypted)), "{policy:?}: {e}");
        let e = b.import_approved(&bytes, Some(EXPORT_PASS), policy, &ImportApproval::default()).unwrap_err();
        assert!(matches!(e, AppError::Bundle(BundleError::NotEncrypted)), "{policy:?}: {e}");
    }
    assert!(b.workspaces().unwrap().is_empty(), "nothing was imported");
    // Without one, it imports.
    b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    assert_eq!(b.requests(&ws.meta.id).unwrap().len(), 1);
}

#[tokio::test]
async fn a_secret_moved_into_another_workspace_on_disk_does_not_resolve_there() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let (owner, other) = (a.create_workspace("Payments").unwrap(), a.create_workspace("Sandbox").unwrap());
    let token = a.set_secret(&owner.meta.id, "bearer", TOKEN).unwrap();
    let request = a.create_request(&other.meta.id, None, "Use token", bearer(&token, "https://api.example.test/")).unwrap();
    refused_auth(&a, &other.meta.id, &request.meta.id).await;

    // The owner column changed in the database file itself.
    let db = rusqlite::Connection::open(a.dir.join(anvil_storage::store::DB_FILE)).unwrap();
    let sql = "UPDATE secrets SET workspace_id=?1 WHERE id=?2";
    let moved = db.execute(sql, rusqlite::params![other.meta.id.to_string(), token.id.to_string()]);
    assert_eq!(moved.unwrap(), 1);
    refused_auth(&a, &other.meta.id, &request.meta.id).await;
}

#[test]
fn an_import_declined_once_its_bundle_is_open_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("Payments").unwrap();
    a.set_secret(&ws.meta.id, "bearer", TOKEN).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::EncryptedTransfer, Some(EXPORT_PASS), false).unwrap();

    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "b");
    let none = ImportApproval::default();
    let asked = std::cell::Cell::new(0);
    let decline = || {
        asked.set(asked.get() + 1);
        false
    };
    // A bundle that does not open fails before the import is asked.
    let e = b.import_approved_if(&bytes, Some("another passphrase"), ConflictPolicy::Merge, &none, &decline).unwrap_err();
    assert!(!matches!(e, AppError::Canceled), "{e}");
    assert_eq!(asked.get(), 0);
    // Declined once the key is derived: nothing is written, not even a checkpoint.
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace, ConflictPolicy::Duplicate] {
        let e = b.import_approved_if(&bytes, Some(EXPORT_PASS), policy, &none, &decline).unwrap_err();
        assert!(matches!(e, AppError::Canceled), "{policy:?}: {e}");
    }
    assert_eq!(asked.get(), 3);
    assert!(b.workspaces().unwrap().is_empty());
    assert!(b.store.list_secret_ids(None).unwrap().is_empty());
    assert!(!b.dir.join("checkpoints").exists(), "no checkpoint was taken");

    let rep = b.import_approved_if(&bytes, Some(EXPORT_PASS), ConflictPolicy::Merge, &none, &|| true).unwrap();
    assert_eq!(rep.workspace_ids, vec![ws.meta.id.to_string()]);
    assert_eq!(b.store.list_secret_ids(Some(&ws.meta.id)).unwrap().len(), 1);
}
