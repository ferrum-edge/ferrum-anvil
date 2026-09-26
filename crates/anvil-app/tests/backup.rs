//! Full backups: every stored entity round-trips into a clean profile, the
//! whole file is encrypted and authenticated, a restore refuses anything
//! modified, malformed or pointing outside the backup before writing, and it
//! writes into a workspace stored here only once the user approves it.

use anvil_app::backup::{self, BackupContents, BackupError, NOT_CARRIED_KINDS, OBJECT_KINDS, TABLES};
use anvil_app::exec::SendOptions;
use anvil_app::linked_files::LinkedFileReferrer;
use anvil_app::port::ImportApproval;
use anvil_app::profiles::ProfileManager;
use anvil_app::runner::RunSettings;
use anvil_app::specs::SpecTarget;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::execution::ExecutionRecord;
use anvil_domain::load::{LoadPlan, Workload};
use anvil_domain::request::{AttachmentRef, Body, KeyValue, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::{DnsOverride, EarlyDataPolicy, RedirectPolicy, Theme};
use anvil_domain::workspace::{DatasetFormat, Meta, ProtectionMode, Scenario, ScenarioStep, UserProfile, Variable};
use anvil_import::ImportOptions;
use anvil_portability::ExportMode;
use anvil_portability::plan::{ConflictPolicy, ExistingWorkspace};
use anvil_storage::{KdfParams, kind};
use anvil_transport::recorder::EventCtx;
use serde_json::json;
use std::collections::BTreeSet;
use tokio_util::sync::CancellationToken;

const PASS: &str = "backup passphrase 1";
/// Distinct plaintext planted in every kind of stored content.
const MARKERS: &[&str] = &[
    "ws-name-marker-5521",
    "header-marker-7310",
    "body-marker-8804",
    "ws-secret-marker-1197",
    "profile-secret-marker-6642",
    "dataset-marker-2250",
    "redaction-marker-9471",
    "history-body-marker-3308",
];

const SPEC: &str = r#"
openapi: 3.1.0
info: { title: Orders API, version: "1" }
servers: [{ url: "https://orders.example.com/v1" }]
paths:
  /orders:
    get:
      operationId: listOrders
      responses: { "200": { description: ok } }
"#;

fn new_app(root: &std::path::Path, name: &str) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase(name, "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

fn export(app: &App) -> Vec<u8> {
    app.export_backup_with(PASS, KdfParams::testing()).unwrap().0
}

/// Approval to write into the stored workspace `ws`.
fn into(ws: &Id, file: &[u8]) -> ImportApproval {
    ImportApproval::for_file(file, vec![*ws])
}

/// The `pub const NAME: &str = "value";` values of `mod kind` in the store source.
fn kind_constants(src: &str) -> Vec<String> {
    let body = src.split("pub mod kind {").nth(1).expect("the kind module").split("\n}\n").next().unwrap_or_default();
    body.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("pub const ") && l.contains(": &str = \""))
        .filter_map(|l| l.split('"').nth(1).map(str::to_string))
        .collect()
}

#[test]
fn every_store_table_and_object_kind_is_classified() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "t");
    let actual: BTreeSet<String> = app.store.table_names().unwrap().into_iter().collect();
    let declared: BTreeSet<String> = anvil_storage::store::TABLES.iter().map(|t| t.to_string()).collect();
    assert_eq!(actual, declared, "anvil_storage::store::TABLES lists every table the migrations create");
    let covered: BTreeSet<String> = TABLES.iter().map(|(t, _)| t.to_string()).collect();
    assert_eq!(covered, declared, "every store table is carried by a full backup or listed with its reason in anvil_app::backup::TABLES");

    let kinds = kind_constants(include_str!("../../anvil-storage/src/store.rs"));
    assert!(kinds.len() > kind::ALL.len(), "parsed the kind constants: {kinds:?}");
    let carried = |k: &str| OBJECT_KINDS.contains(&k);
    let left_out = |k: &str| NOT_CARRIED_KINDS.iter().any(|(n, _)| *n == k);
    for k in kinds.iter().map(String::as_str).chain(kind::ALL.iter().copied()) {
        assert!(
            carried(k) ^ left_out(k),
            "object kind '{k}' must be in exactly one of backup::OBJECT_KINDS (and restored) or backup::NOT_CARRIED_KINDS"
        );
    }
}

fn plan(ws: Id, req: Id) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: ws,
        name: "smoke".into(),
        workload: Workload::Iterations { iterations: 2, concurrency: 1 },
        chain: vec![req],
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

/// A source profile with at least one row of every carried object kind,
/// workspace and profile-level secrets, attachments, more than 1,000 history
/// records with bodies, a load report and a token-file binding.
async fn populated(root: &std::path::Path, fixture_url: &str, token_file: &std::path::Path) -> App {
    let a = new_app(root, "source");
    let ws = a.create_workspace(MARKERS[0]).unwrap();
    let folder = a.create_folder(&ws.meta.id, None, "Orders").unwrap();
    let ws_secret = a.set_secret(&ws.meta.id, "api key", MARKERS[3]).unwrap();
    // A secret no workspace owns, as older builds stored them.
    let profile_secret = SecretRef { id: Id::new(), label: "profile token".into() };
    a.store.put_secret(&profile_secret.id, None, &profile_secret.label, MARKERS[4]).unwrap();
    a.create_environment(&ws.meta.id, "lab", vec![Variable::plain("base", fixture_url)]).unwrap();

    let mut spec = RequestSpec::http("POST", &format!("{fixture_url}/echo"));
    spec.headers.push(KeyValue::new("X-Marker", MARKERS[1]));
    spec.body = Body::Json { text: format!("{{\"note\":\"{}\"}}", MARKERS[2]) };
    let value = SensitiveValue::Secret { secret: ws_secret };
    spec.auth = AuthConfig::ApiKey { name: "X-API-Key".into(), value, location: KeyLocation::Header };
    let req = a.create_request(&ws.meta.id, Some(folder.meta.id), "Echo", spec).unwrap();
    let mut edited = req.clone();
    edited.spec.headers.push(KeyValue::new("X-Revision", "2"));
    let edited = a.save_request(edited).unwrap();
    assert_ne!(edited.revision_id, req.revision_id, "two revisions");
    let mut other = RequestSpec::http("GET", "https://api.example.invalid/");
    other.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: profile_secret }, prefix: "Bearer".into() };
    a.create_request(&ws.meta.id, None, "Profile secret user", other).unwrap();

    let now = chrono::Utc::now();
    let common = |name: &str| json!({"id": Id::new(), "workspace_id": ws.meta.id, "name": name, "created_at": now, "updated_at": now});
    a.save_tls_profile(serde_json::from_value(common("lab tls")).unwrap()).unwrap();
    let mut proxy = common("lab proxy");
    proxy["kind"] = json!("http");
    proxy["address"] = json!("127.0.0.1:3128");
    a.save_proxy_profile(serde_json::from_value(proxy).unwrap()).unwrap();
    let mut gateway = common("lab gateway");
    gateway["kind"] = json!("ferrum_gateway");
    gateway["hosts"] = json!([]);
    gateway["compatibility_id"] = json!("ferrum-edge-0.9.5");
    a.save_integration(serde_json::from_value(gateway).unwrap()).unwrap();
    a.create_dataset(&ws.meta.id, "users", DatasetFormat::Csv, format!("name\n{}\n", MARKERS[5]).as_bytes(), vec![]).unwrap();

    // A collection run: history records and a run report. Imports and
    // restores leave scenarios untrusted, so the source is made so too.
    let steps = vec![ScenarioStep { request_id: edited.meta.id, enabled: true, delay_ms: 0 }];
    let sc = a.create_scenario(&ws.meta.id, "Smoke", steps).unwrap();
    let run = a.run_scenario(&sc.meta.id, RunSettings::default(), CancellationToken::new()).await.unwrap();
    assert!(run.passed(), "{run:#?}");
    a.save_scenario(Scenario { trusted: false, ..sc }).unwrap();

    // A load run: a load report. The plan is saved untrusted afterwards, as a
    // restore would leave it.
    let p = a.save_load_plan(plan(ws.meta.id, edited.meta.id)).unwrap();
    let job = a.load_job(&p).unwrap();
    let opts = anvil_load::RunOptions { acknowledged: true, ..Default::default() };
    let report = anvil_load::LoadRun::prepare(p.clone(), job, opts).unwrap().execute(CancellationToken::new(), None).await;
    a.save_load_report(&report).unwrap();
    a.save_load_plan(LoadPlan { trusted: false, ..p }).unwrap();

    let mut settings = a.settings().unwrap();
    settings.theme = Theme::Dark;
    settings.redaction_names.push(MARKERS[6].into());
    a.save_settings(&settings).unwrap();

    // Provenance of a spec import: its own workspace, requests and the stored original.
    a.spec_import(SPEC.as_bytes(), "orders.yaml", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    // No command writes user profiles yet; the backup still carries them.
    let user = UserProfile { meta: Meta::new(), display_name: "me".into(), protection: ProtectionMode::Passphrase, linked_identity: None };
    a.store.put(kind::USER_PROFILE, &user.meta.id, None, None, 0.0, &user).unwrap();
    // Device-bound: listed, never carried.
    a.bind_token_file(token_file).unwrap();

    // More history than a single listing page, each with its own body.
    let first = a.store.list_history(None, None, 1).unwrap().remove(0);
    let (rec, _) = a.store.get_history::<ExecutionRecord>(&first.id).unwrap().unwrap();
    for i in 0..1_050i64 {
        let mut r = rec.clone();
        r.id = Id::new();
        r.started_at = chrono::DateTime::from_timestamp_millis(now.timestamp_millis() - i).unwrap();
        let body = format!("{}-{i}", MARKERS[7]);
        let (ws_id, req_id, at) = (r.workspace_id, r.request_id, r.started_at.timestamp_millis());
        a.store.add_history(&r.id, ws_id.as_ref(), req_id.as_ref(), at, &r, Some(body.as_bytes())).unwrap();
    }
    a
}

#[tokio::test]
async fn full_backup_restores_every_entity_into_a_clean_profile() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let files = tempfile::tempdir().unwrap();
    let token = files.path().join("jwt_svid.token");
    std::fs::write(&token, "token-file-content").unwrap();
    let a_root = tempfile::tempdir().unwrap();
    let a = populated(a_root.path(), &fx.url(""), &token).await;
    let before = a.backup_contents().unwrap();

    // Inventory of the source: every carried kind, both kinds of secret,
    // attachments, all history (no 1,000 cap), bodies and load reports.
    for k in OBJECT_KINDS {
        assert!(before.objects.iter().any(|o| o.kind == *k), "the fixture has no '{k}' row");
    }
    assert!(before.objects.iter().filter(|o| o.kind == kind::REVISION).count() >= 2, "every revision, not only the current one");
    assert!(before.secrets.iter().any(|s| s.workspace_id.is_none()), "profile-level secret");
    assert!(before.secrets.iter().any(|s| s.workspace_id.is_some()), "workspace secret");
    assert!(before.attachments.len() >= 2, "dataset and spec source attachments");
    assert!(before.history.len() > 1_050, "{} history records", before.history.len());
    assert!(before.history.iter().filter(|h| h.body_b64.is_some()).count() >= 1_050, "stored response bodies");
    assert_eq!(before.load_reports.len(), 1);

    let (bytes, preview) = a.export_backup_with(PASS, KdfParams::testing()).unwrap();
    assert_eq!(preview.manifest.mode, ExportMode::FullBackup);
    assert_eq!(preview.manifest.counts["history"], before.history.len());
    assert_eq!(preview.secrets_included, 2);
    assert!(preview.manifest.device_bindings.iter().any(|d| d.contains("token-file")), "{:?}", preview.manifest.device_bindings);
    assert!(backup::is_backup(&bytes));

    // Nothing is readable without the passphrase.
    let text = String::from_utf8_lossy(&bytes);
    for m in MARKERS {
        assert!(!text.contains(m), "{m} is readable in the backup file");
    }
    for plain in ["orders.example.com", "Profile secret user", "\"workspace_id\"", "\"kind\":\"secret\""] {
        assert!(!text.contains(plain), "{plain} is readable in the backup file");
    }

    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "target");
    let dry = b.restore_preview(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(b.workspaces().unwrap().is_empty(), "a preview changes nothing");
    assert!(dry.missing_secrets.is_empty(), "{:?}", dry.missing_secrets);
    let rep = b.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(rep.secrets_restored && rep.checkpoint.is_some());
    assert_eq!(rep.workspaces.len(), 2);

    // The restored profile holds exactly what the source held.
    let after = b.backup_contents().unwrap();
    let inventory = |c: &BackupContents| -> BTreeSet<(String, String)> {
        let mut v: BTreeSet<_> = c.objects.iter().map(|o| (o.kind.clone(), o.id.clone())).collect();
        v.extend(c.secrets.iter().map(|s| ("secret".to_string(), s.id.clone())));
        v.extend(c.attachments.iter().map(|x| ("attachment".to_string(), x.sha256.clone())));
        v.extend(c.history.iter().map(|h| ("history".to_string(), h.id.clone())));
        v.extend(c.load_reports.iter().map(|r| ("load_report".to_string(), r["run_id"].to_string())));
        v
    };
    let (src, dst) = (inventory(&before), inventory(&after));
    assert_eq!(src.difference(&dst).collect::<Vec<_>>(), Vec::<&(String, String)>::new(), "missing after restore");
    assert_eq!(dst.difference(&src).collect::<Vec<_>>(), Vec::<&(String, String)>::new(), "added by restore");
    for (x, y) in before.objects.iter().zip(&after.objects) {
        assert!(x == y, "{} {} differs after restore", x.kind, x.id);
    }
    assert!(before == after, "secrets, attachments, history or load reports differ after restore");
    assert_eq!(b.settings().unwrap().theme, Theme::Dark);
    assert!(b.token_file_bindings().unwrap().is_empty(), "token-file bindings stay on their device");

    // The restored request sends with its restored secret.
    let ws_b = b.find_workspace(MARKERS[0]).unwrap();
    let req_b = b.find_request(&ws_b.meta.id, "Orders/Echo").unwrap();
    let out =
        b.send(Some(req_b.meta.id), &ws_b.meta.id, None, SendOptions::default(), EventCtx::none(), CancellationToken::new()).await.unwrap();
    assert_eq!(out.record.response.as_ref().unwrap().status, 200, "{:?}", out.record.findings);
    let seen = fx.log.last_request_headers().unwrap();
    assert!(seen.iter().any(|(n, v)| n == "x-api-key" && v == MARKERS[3]), "the workspace secret was restored");
}

/// A small profile: one workspace, request and secret.
fn small(root: &std::path::Path, name: &str) -> App {
    let a = new_app(root, name);
    let ws = a.create_workspace("W").unwrap();
    let secret = a.set_secret(&ws.meta.id, "key", "small-secret-value").unwrap();
    let mut spec = RequestSpec::http("GET", "https://original.example.invalid/");
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret }, prefix: "Bearer".into() };
    a.create_request(&ws.meta.id, None, "R", spec).unwrap();
    a
}

fn split_header(bytes: &[u8]) -> (serde_json::Value, Vec<u8>) {
    let len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    (serde_json::from_slice(&bytes[12..12 + len]).unwrap(), bytes[12 + len..].to_vec())
}

fn with_header(header: &serde_json::Value, envelope: &[u8]) -> Vec<u8> {
    let h = serde_json::to_vec(header).unwrap();
    let mut out = b"ANVILBAK".to_vec();
    out.extend_from_slice(&u32::try_from(h.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(envelope);
    out
}

/// Every attempt fails and leaves the target exactly as it was.
fn assert_refused(target: &App, bytes: &[u8], why: &str) {
    let before = target.backup_contents().unwrap();
    assert!(target.restore_preview(bytes, Some(PASS), ConflictPolicy::Replace).is_err(), "preview accepted: {why}");
    assert!(target.restore(bytes, Some(PASS), ConflictPolicy::Replace).is_err(), "restore accepted: {why}");
    assert!(target.backup_contents().unwrap() == before, "a refused restore changed the profile: {why}");
}

#[test]
fn any_modification_of_the_file_is_refused_before_anything_is_written() {
    let root = tempfile::tempdir().unwrap();
    let a = small(root.path(), "a");
    let bytes = export(&a);
    let b = new_app(root.path(), "b");
    b.create_workspace("Local").unwrap();
    // The untouched file restores.
    b.restore_preview(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();

    let (header, envelope) = split_header(&bytes);
    let header_end = bytes.len() - envelope.len();
    // Every byte of the signature, length and header, and bytes spread across
    // the encrypted payload, including its first and last.
    let mut positions: Vec<usize> = (0..header_end).collect();
    positions.extend((header_end..bytes.len()).step_by((envelope.len() / 48).max(1)));
    positions.push(bytes.len() - 1);
    for i in positions {
        let mut t = bytes.clone();
        t[i] ^= 0x01;
        assert_refused(&b, &t, &format!("bit flip at byte {i}"));
    }
    assert_refused(&b, &bytes[..bytes.len() - 1], "truncated by one byte");
    assert_refused(&b, &bytes[..header_end + 20], "truncated payload");
    let mut longer = bytes.clone();
    longer.push(0);
    assert_refused(&b, &longer, "extra trailing byte");

    // A re-encoded header, even one naming valid costs, no longer matches.
    let mut cheaper = header.clone();
    cheaper["kdf"]["m_cost"] = json!(2048);
    assert_refused(&b, &with_header(&cheaper, &envelope), "changed key-derivation costs");
    let mut reordered = serde_json::Map::new();
    for (k, v) in header.as_object().unwrap().iter().rev() {
        reordered.insert(k.clone(), v.clone());
    }
    assert_refused(&b, &with_header(&serde_json::Value::Object(reordered), &envelope), "re-serialized header");

    // The header of one backup never opens the payload of another, even
    // under the same passphrase.
    let other = export(&small(root.path(), "c"));
    let (other_header, other_envelope) = split_header(&other);
    assert_refused(&b, &with_header(&header, &other_envelope), "payload from another backup");
    assert_refused(&b, &with_header(&other_header, &envelope), "header from another backup");
}

#[test]
fn passphrase_format_and_costs_are_checked() {
    let root = tempfile::tempdir().unwrap();
    let a = small(root.path(), "a");
    let bytes = export(&a);
    let b = new_app(root.path(), "b");
    let policy = ConflictPolicy::Replace;
    assert!(matches!(b.restore(&bytes, None, policy), Err(AppError::Backup(BackupError::PassphraseRequired))));
    assert!(matches!(b.restore(&bytes, Some("wrong passphrase"), policy), Err(AppError::Backup(BackupError::Authentication))));
    assert!(matches!(b.restore(&bytes, Some(PASS), ConflictPolicy::Duplicate), Err(AppError::Backup(BackupError::DuplicateUnsupported))));
    assert!(b.workspaces().unwrap().is_empty());

    let (header, envelope) = split_header(&bytes);
    for (field, value) in [("m_cost", json!(u32::MAX)), ("t_cost", json!(1_000)), ("p_cost", json!(64)), ("t_cost", json!(0))] {
        let mut h = header.clone();
        h["kdf"][field] = value;
        let r = b.restore(&with_header(&h, &envelope), Some(PASS), policy);
        assert!(matches!(r, Err(AppError::Backup(BackupError::UnsupportedKdf(_)))), "{field}: {:?}", r.err());
    }
    let mut h = header.clone();
    h["salt_b64"] = json!("AAAA");
    assert!(matches!(b.restore(&with_header(&h, &envelope), Some(PASS), policy), Err(AppError::Backup(BackupError::UnsupportedKdf(_)))));
    let mut h = header.clone();
    h["format_version"] = json!(backup::FORMAT_VERSION + 1);
    assert!(matches!(b.restore(&with_header(&h, &envelope), Some(PASS), policy), Err(AppError::Backup(BackupError::FutureFormat { .. }))));
    assert!(matches!(b.restore(b"PK\x03\x04 not a backup", Some(PASS), policy), Err(AppError::Backup(BackupError::NotABackup(_)))));

    // Exports refuse weak passphrases and out-of-bounds costs.
    assert!(matches!(a.export_backup_with("short", KdfParams::testing()), Err(AppError::Backup(BackupError::WeakPassphrase))));
    let costly = KdfParams { m_cost: backup::MAX_KDF_MEMORY_KIB + 1, ..KdfParams::interactive() };
    assert!(matches!(a.export_backup_with(PASS, costly), Err(AppError::Backup(BackupError::UnsupportedKdf(_)))));
    // A zip bundle is not mistaken for a full backup.
    let (zip, _) = a.export(None, ExportMode::ShareSafely, None, false).unwrap();
    assert!(!backup::is_backup(&zip));
}

/// Re-seal authentic contents after `edit`, as someone holding the
/// passphrase could.
fn resealed(bytes: &[u8], edit: impl FnOnce(&mut backup::BackupManifest, &mut BackupContents)) -> Vec<u8> {
    let (mut manifest, mut contents) = backup::open(bytes, Some(PASS)).unwrap();
    edit(&mut manifest, &mut contents);
    backup::seal(&manifest, &contents, PASS, KdfParams::testing()).unwrap()
}

#[test]
fn a_stored_attachment_without_its_content_is_restored_only_where_that_content_is_not_stored() {
    let root = tempfile::tempdir().unwrap();
    let a = small(root.path(), "a");
    let ws = a.workspaces().unwrap().remove(0);
    let rows = a.create_dataset(&ws.meta.id, "rows", DatasetFormat::Csv, b"card\nplaceholder-card\n", vec![]).unwrap();
    let file = a.put_attachment("statement.bin", b"placeholder statement", None).unwrap();
    let upload = |attachment: &AttachmentRef| RequestSpec {
        body: Body::Binary { attachment: attachment.clone(), content_type: None },
        ..RequestSpec::http("POST", "https://original.example.invalid/")
    };
    a.create_request(&ws.meta.id, None, "Upload", upload(&file)).unwrap();
    // A request whose stored content this profile never held, as one created
    // through the API can be: the backup is still written.
    let never = AttachmentRef::Stored { sha256: "0".repeat(64), size: 1, file_name: "never.bin".into(), media_type: None };
    a.create_request(&ws.meta.id, None, "Orphan", upload(&never)).unwrap();
    let bytes = export(&a);
    // The target stores the same content in a workspace of its own.
    let b = new_app(root.path(), "b");
    let local = b.create_workspace("Local").unwrap();
    b.create_dataset(&local.meta.id, "cards", DatasetFormat::Csv, b"card\nplaceholder-card\n", vec![]).unwrap();
    b.put_attachment("mine.bin", b"placeholder statement", None).unwrap();

    // A backup naming stored content by hash without carrying it, as after
    // the loss of a stored blob.
    let items = [(&rows.attachment, "dataset 'rows'"), (&file, "request 'Upload'")];
    for (i, (attachment, item)) in items.into_iter().enumerate() {
        let AttachmentRef::Stored { sha256, .. } = attachment else { panic!("{item}: a stored attachment") };
        let without = resealed(&bytes, |_, c| c.attachments.retain(|x| x.sha256 != *sha256));
        // Where that content is stored, the reference would resolve to it: refused.
        assert_refused(&b, &without, item);
        let e = b.restore(&without, Some(PASS), ConflictPolicy::Merge).unwrap_err();
        assert!(e.to_string().contains(&format!("{item} uses a stored attachment that the backup does not carry")), "{e}");
        // Where it is not, the backup restores, with a warning naming the item.
        let fresh = new_app(root.path(), &format!("fresh-{i}"));
        let warning = format!("{item} uses a stored file that the backup does not include; it will fail until the file is attached again.");
        let dry = fresh.restore_preview(&without, Some(PASS), ConflictPolicy::Replace).unwrap();
        assert!(dry.warnings.contains(&warning), "{:?}", dry.warnings);
        let rep = fresh.restore(&without, Some(PASS), ConflictPolicy::Replace).unwrap();
        assert!(rep.warnings.contains(&warning), "{:?}", rep.warnings);
        assert!(fresh.get_attachment(sha256).unwrap().is_none(), "nothing stands in for the missing content");
        assert_eq!(fresh.find_workspace("W").unwrap().meta.id, ws.meta.id);
    }
    // With its content, the same backup restores; only the request whose
    // content was never stored is named.
    let rep = b.restore(&bytes, Some(PASS), ConflictPolicy::Merge).unwrap();
    let named: Vec<&String> = rep.warnings.iter().filter(|w| w.contains("does not include")).collect();
    assert_eq!(named.len(), 1, "{named:?}");
    assert!(named[0].starts_with("request 'Orphan'"), "{named:?}");
    assert_eq!(b.run_dataset(&b.dataset(&rows.meta.id).unwrap()).unwrap().rows.len(), 1);
}

#[test]
fn a_backup_that_claims_a_stored_workspace_is_refused_until_approved() {
    let root = tempfile::tempdir().unwrap();
    let a = small(root.path(), "a");
    let ws = a.workspaces().unwrap().remove(0);
    let b = new_app(root.path(), "b");
    // Into a profile without that workspace, nothing needs approving.
    let first = b.restore_preview(&export(&a), Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(first.plan.existing_workspaces.is_empty(), "{:?}", first.plan);
    b.restore(&export(&a), Some(PASS), ConflictPolicy::Replace).unwrap();

    // A later backup that names the stored workspace's id and adds a request there.
    a.create_request(&ws.meta.id, None, "Probe", RequestSpec::http("GET", "https://elsewhere.example.invalid/")).unwrap();
    let bytes = export(&a);
    let expected = vec![ExistingWorkspace { id: ws.meta.id, name: "W".into() }];
    let before = b.backup_contents().unwrap();
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
        // The preview names the stored workspace...
        let preview = b.restore_preview(&bytes, Some(PASS), policy).unwrap();
        assert_eq!(preview.plan.existing_workspaces, expected, "{policy:?}");
        assert!(preview.full_backup);
        // ...and restoring without approving it, or approving another one, is refused.
        let e = b.restore(&bytes, Some(PASS), policy).unwrap_err();
        assert!(matches!(&e, AppError::Invalid(m) if m.contains("existing workspace 'W'")), "{policy:?}: {e}");
        let e = b.restore_approved(&bytes, Some(PASS), policy, &into(&Id::new(), &bytes)).unwrap_err();
        assert!(matches!(&e, AppError::Invalid(m) if m.contains("existing workspace 'W'")), "{policy:?}: {e}");
        assert!(b.backup_contents().unwrap() == before, "a refused restore changed the profile ({policy:?})");
    }
    assert_eq!(b.requests(&ws.meta.id).unwrap().len(), 1, "nothing was restored");

    // An approval holds only for the backup that was previewed.
    let preview = b.restore_preview(&bytes, Some(PASS), ConflictPolicy::Merge).unwrap();
    assert_eq!(preview.bundle_sha256, anvil_app::port::file_sha256(&bytes));
    let later = export(&a);
    let e = b.restore_approved(&later, Some(PASS), ConflictPolicy::Merge, &into(&ws.meta.id, &bytes)).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains("not the one that was previewed")), "{e}");
    assert!(b.backup_contents().unwrap() == before, "a refused restore changed the profile");

    // Once the user approves the stored workspace, the restore writes into it.
    let rep = b.restore_approved(&bytes, Some(PASS), ConflictPolicy::Merge, &into(&ws.meta.id, &bytes)).unwrap();
    assert_eq!(rep.workspace_ids, vec![ws.meta.id.to_string()]);
    assert_eq!(b.requests(&ws.meta.id).unwrap().len(), 2);
}

#[test]
fn every_stored_workspace_a_backup_claims_needs_approval() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "a");
    let payments = a.create_workspace("Payments").unwrap();
    let billing = a.create_workspace("Billing").unwrap();
    let b = new_app(root.path(), "b");
    b.restore(&export(&a), Some(PASS), ConflictPolicy::Merge).unwrap();

    // A later backup that adds a request to one of the two stored workspaces.
    a.create_request(&billing.meta.id, None, "Probe", RequestSpec::http("GET", "https://elsewhere.example.invalid/")).unwrap();
    let bytes = export(&a);
    for policy in [ConflictPolicy::Merge, ConflictPolicy::Replace] {
        let preview = b.restore_preview(&bytes, Some(PASS), policy).unwrap();
        assert_eq!(preview.plan.existing_workspaces.len(), 2, "{policy:?}");
        // Approving only one of them refuses the whole restore, naming the other.
        let e = b.restore_approved(&bytes, Some(PASS), policy, &into(&payments.meta.id, &bytes)).unwrap_err();
        assert!(
            matches!(&e, AppError::Invalid(m) if m.contains("existing workspace 'Billing'") && !m.contains("'Payments'")),
            "{policy:?}: {e}"
        );
    }
    assert!(b.requests(&billing.meta.id).unwrap().is_empty(), "nothing was restored");

    // Approving both, Replace writes into them.
    let both = ImportApproval::for_file(&bytes, vec![payments.meta.id, billing.meta.id]);
    b.restore_approved(&bytes, Some(PASS), ConflictPolicy::Replace, &both).unwrap();
    assert_eq!(b.requests(&billing.meta.id).unwrap().len(), 1);
}

#[test]
fn a_restore_never_overwrites_an_object_or_secret_of_another_workspace() {
    let root = tempfile::tempdir().unwrap();
    let b = new_app(root.path(), "b");
    let payments = b.create_workspace("Payments").unwrap();
    let folder = b.create_folder(&payments.meta.id, None, "Orders").unwrap();
    let token = b.set_secret(&payments.meta.id, "bearer", "placeholder-token-here").unwrap();

    // A backup with a workspace of its own whose folder and secret reuse
    // the stored folder's and secret's ids.
    let a = new_app(root.path(), "a");
    let incoming = a.create_workspace("Incoming").unwrap();
    let mut look_alike = folder.clone();
    look_alike.workspace_id = incoming.meta.id;
    a.store.put(kind::FOLDER, &folder.meta.id, Some(&incoming.meta.id), None, folder.sort_key, &look_alike).unwrap();
    a.store.put_secret(&token.id, Some(&incoming.meta.id), "bearer", "placeholder-token-there").unwrap();
    let bytes = export(&a);
    let object = format!("folder 'Orders' ({})", folder.meta.id);
    let secret = format!("secret 'bearer' ({})", token.id);

    let preview = b.restore_preview(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert_eq!(preview.plan.foreign_objects, vec![object.clone()]);
    assert_eq!(preview.plan.foreign_secrets, vec![secret.clone()]);
    assert!(preview.plan.existing_workspaces.is_empty(), "{:?}", preview.plan);
    let before = b.backup_contents().unwrap();
    let e = b.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains(&object)), "{e}");
    assert!(b.backup_contents().unwrap() == before, "a refused restore changed the profile");
    // Reusing only the secret's id is refused too.
    let secret_only = resealed(&bytes, |_, c| c.objects.retain(|o| o.kind != kind::FOLDER));
    let e = b.restore(&secret_only, Some(PASS), ConflictPolicy::Replace).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains(&secret)), "{e}");
    assert!(b.backup_contents().unwrap() == before, "a refused restore changed the profile");

    // Merge keeps both where they are, unchanged.
    let rep = b.restore(&bytes, Some(PASS), ConflictPolicy::Merge).unwrap();
    assert_eq!(rep.plan.foreign_objects, vec![object]);
    assert_eq!(b.folder(&folder.meta.id).unwrap(), folder);
    assert_eq!(b.store.get_secret(&token.id).unwrap().unwrap().1.as_str(), "placeholder-token-here");
    assert_eq!(b.store.list_secret_ids(Some(&payments.meta.id)).unwrap(), vec![token.id.to_string()]);
}

#[test]
fn authentic_contents_are_still_validated_and_normalised() {
    let root = tempfile::tempdir().unwrap();
    let a = small(root.path(), "a");
    let ws = a.workspaces().unwrap().remove(0);
    let now = chrono::Utc::now();
    let tls = json!({"id": Id::new(), "workspace_id": ws.meta.id, "name": "bypass", "verify": false, "created_at": now, "updated_at": now});
    a.save_tls_profile(serde_json::from_value(tls).unwrap()).unwrap();
    let bytes = export(&a);
    let b = new_app(root.path(), "b");
    let local = b.create_workspace("Local").unwrap();

    let obj = |c: &BackupContents, k: &str| c.objects.iter().position(|o| o.kind == k).unwrap();
    let device_bound = resealed(&bytes, |_, c| {
        let mut row = c.objects[obj(c, kind::WORKSPACE)].clone();
        row.kind = kind::TOKEN_FILE.into();
        c.objects.push(row);
    });
    assert_refused(&b, &device_bound, "a device-bound kind");
    let linked_binding = resealed(&bytes, |_, c| {
        let mut row = c.objects[obj(c, kind::WORKSPACE)].clone();
        row.kind = kind::LINKED_FILE.into();
        c.objects.push(row);
    });
    assert_refused(&b, &linked_binding, "a linked-file binding");
    let foreign_object = resealed(&bytes, |_, c| {
        let i = obj(c, kind::TLS_PROFILE);
        c.objects[i].value["workspace_id"] = json!(local.meta.id);
    });
    assert_refused(&b, &foreign_object, "an object owned by a workspace outside the backup");
    let foreign = local.meta.id.to_string();
    let foreign_secret = resealed(&bytes, |_, c| c.secrets[0].workspace_id = Some(foreign));
    assert_refused(&b, &foreign_secret, "a secret owned by a workspace outside the backup");
    let wrong_id = resealed(&bytes, |_, c| {
        let i = obj(c, kind::REQUEST);
        c.objects[i].id = Id::new().to_string();
    });
    assert_refused(&b, &wrong_id, "a row id that is not its object's id");
    let wrong_type = resealed(&bytes, |_, c| {
        let i = obj(c, kind::REQUEST);
        c.objects[i].value["spec"] = json!(42);
    });
    assert_refused(&b, &wrong_type, "an object that does not match its type");
    let repeated = resealed(&bytes, |_, c| {
        let row = c.objects[obj(c, kind::REQUEST)].clone();
        c.objects.push(row);
    });
    assert_refused(&b, &repeated, "a repeated object");
    let bad_attachment = resealed(&bytes, |_, c| {
        c.attachments.push(backup::AttachmentRow { sha256: "0".repeat(64), content_b64: "aGVsbG8=".into() });
    });
    assert_refused(&b, &bad_attachment, "an attachment that does not match its hash");
    let newer_object = resealed(&bytes, |_, c| {
        let i = obj(c, kind::REQUEST);
        c.objects[i].value["schema_version"] = json!(anvil_domain::SCHEMA_VERSION + 1);
    });
    assert_refused(&b, &newer_object, "an object written by a newer schema");
    assert_refused(&b, &resealed(&bytes, |m, _| m.schema_version += 1), "a newer object schema");
    assert_refused(&b, &resealed(&bytes, |m, _| m.mode = ExportMode::EncryptedTransfer), "a manifest for another mode");
    let foreign_revision = resealed(&bytes, |_, c| {
        let i = obj(c, kind::REVISION);
        c.objects[i].workspace_id = Some(local.meta.id.to_string());
    });
    assert_refused(&b, &foreign_revision, "a revision stored under a workspace outside the backup");

    // A revision whose request is not in the backup is left out, with a warning.
    let orphan_id = Id::new();
    let orphan = resealed(&bytes, |_, c| {
        let mut row = c.objects[obj(c, kind::REVISION)].clone();
        let request = Id::new();
        row.id = orphan_id.to_string();
        row.parent_id = Some(request.to_string());
        row.value["id"] = json!(orphan_id);
        row.value["request_id"] = json!(request);
        c.objects.push(row);
    });
    let fresh = new_app(root.path(), "c");
    let rep = fresh.restore(&orphan, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("request revision(s)")), "{:?}", rep.warnings);
    let restored = fresh.backup_contents().unwrap();
    assert!(restored.objects.iter().all(|o| o.id != orphan_id.to_string()), "an orphaned revision is not restored");
    assert!(restored.objects.iter().any(|o| o.kind == kind::REVISION), "the request's own revision is restored");

    // Accepted, with the bundle-import safety normalisation applied.
    let rep = b.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("certificate verification")), "{:?}", rep.warnings);
    let ws_b = b.find_workspace("W").unwrap();
    assert!(b.tls_profiles(&ws_b.meta.id).unwrap().iter().all(|t| t.verify), "a restore never activates a TLS bypass");
}

#[test]
fn merge_keeps_local_items_and_replace_restores_the_backup() {
    let root = tempfile::tempdir().unwrap();
    let a = small(root.path(), "a");
    let mut settings = a.settings().unwrap();
    settings.theme = Theme::Light;
    a.save_settings(&settings).unwrap();
    let bytes = export(&a);
    let b = new_app(root.path(), "b");
    b.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();

    let mut ws = b.find_workspace("W").unwrap();
    ws.name = "Edited here".into();
    b.save_workspace(ws.clone()).unwrap();
    let mut s = b.settings().unwrap();
    s.theme = Theme::Dark;
    b.save_settings(&s).unwrap();

    // The backup writes into the workspace restored above, which the user approves.
    let merge = b.restore_approved(&bytes, Some(PASS), ConflictPolicy::Merge, &into(&ws.meta.id, &bytes)).unwrap();
    assert_eq!(merge.plan.to_create, 0);
    assert!(merge.plan.skipped_existing >= 4, "{:?}", merge.plan);
    assert_eq!(b.workspace(&ws.meta.id).unwrap().name, "Edited here");
    assert_eq!(b.settings().unwrap().theme, Theme::Dark, "merge keeps this profile's settings");

    let replace = b.restore_approved(&bytes, Some(PASS), ConflictPolicy::Replace, &into(&ws.meta.id, &bytes)).unwrap();
    assert_eq!(replace.plan.to_replace, merge.plan.skipped_existing);
    assert_eq!(b.workspace(&ws.meta.id).unwrap().name, "W");
    assert_eq!(b.settings().unwrap().theme, Theme::Light);
    assert_eq!(b.workspaces().unwrap().len(), 1, "a restore never duplicates");
}

#[test]
fn linked_file_bindings_stay_on_their_device_and_a_replace_drops_overwritten_ones() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let path = files.path().join("upload.bin");
    std::fs::write(&path, "linked-file-content").unwrap();
    let path = std::fs::canonicalize(&path).unwrap();
    let a = new_app(root.path(), "a");
    let ws = a.create_workspace("W").unwrap();
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9/x");
    spec.body = Body::Binary { attachment: AttachmentRef::LinkedFile { path: path.display().to_string() }, content_type: None };
    let r = a.create_request(&ws.meta.id, None, "upload", spec).unwrap();
    a.bind_linked_file(LinkedFileReferrer::Request { id: r.meta.id }, &path).unwrap();
    let (bytes, preview) = a.export_backup_with(PASS, KdfParams::testing()).unwrap();
    let notes = &preview.manifest.device_bindings;
    assert!(notes.iter().any(|d| d.contains("linked-file binding")), "{notes:?}");
    assert!(a.backup_contents().unwrap().objects.iter().all(|o| o.kind != kind::LINKED_FILE));

    // A clean profile gets the request and a listing of its linked file, never the binding.
    let b = new_app(root.path(), "b");
    let dry = b.restore_preview(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert_eq!(dry.linked_files.len(), 1, "{:?}", dry.linked_files);
    assert!(dry.linked_files[0].starts_with("request 'upload'"), "{:?}", dry.linked_files);
    b.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(b.linked_file_bindings().unwrap().is_empty(), "a restore never binds a linked file");

    // Merge keeps the stored request and its binding; Replace overwrites the
    // request, which is not what the file was chosen for. The backup is this
    // profile's own, so writing into its workspace is approved.
    a.restore_approved(&bytes, Some(PASS), ConflictPolicy::Merge, &into(&ws.meta.id, &bytes)).unwrap();
    assert_eq!(a.linked_file_bindings().unwrap().len(), 1);
    a.restore_approved(&bytes, Some(PASS), ConflictPolicy::Replace, &into(&ws.meta.id, &bytes)).unwrap();
    assert!(a.linked_file_bindings().unwrap().is_empty());
}

#[test]
fn replace_keeps_app_settings_while_the_profile_holds_a_workspace_the_backup_does_not_claim() {
    let root = tempfile::tempdir().unwrap();
    let a = small(root.path(), "a");
    let mut settings = a.settings().unwrap();
    settings.theme = Theme::Light;
    settings.defaults.dns_overrides.push(DnsOverride { host: "api.example.invalid".into(), addresses: vec!["192.0.2.10".into()] });
    settings.defaults.redirects = Some(RedirectPolicy { follow: true, max: 5, forward_credentials_cross_origin: true });
    settings.defaults.early_data = Some(EarlyDataPolicy { enabled: true, extra_methods: vec![] });
    a.save_settings(&settings).unwrap();
    let bytes = export(&a);
    let kept = "Replace keeps this profile's app settings";

    // App settings apply to every workspace's requests. A profile with a
    // workspace the backup does not claim needs nothing approved, and keeps
    // its own app settings.
    let b = new_app(root.path(), "b");
    b.create_workspace("Local").unwrap();
    let before = b.settings().unwrap();
    let dry = b.restore_preview(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(dry.plan.existing_workspaces.is_empty(), "{:?}", dry.plan);
    assert!(dry.warnings.iter().any(|w| w.starts_with(kept)), "{:?}", dry.warnings);
    assert_eq!((dry.plan.to_replace, dry.plan.skipped_existing), (0, 1), "the settings are counted as kept: {:?}", dry.plan);
    let rep = b.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(rep.warnings.iter().any(|w| w.starts_with(kept)), "{:?}", rep.warnings);
    assert_eq!(b.settings().unwrap(), before, "the backup's app settings never reach a workspace it does not claim");
    b.find_workspace("W").expect("the rest of the backup is restored");

    // Into a profile holding only the backup's own workspaces, Replace
    // restores them, normalised like workspace, folder and request settings.
    let c = new_app(root.path(), "c");
    let rep = c.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(!rep.warnings.iter().any(|w| w.starts_with(kept)), "{:?}", rep.warnings);
    assert!(rep.warnings.iter().any(|w| w.contains("forwarded credentials to other origins")), "{:?}", rep.warnings);
    assert!(rep.warnings.iter().any(|w| w.contains("0-RTT early data")), "{:?}", rep.warnings);
    let restored = c.settings().unwrap();
    assert_eq!(restored.theme, Theme::Light);
    assert_eq!(restored.defaults.dns_overrides, settings.defaults.dns_overrides);
    assert!(restored.defaults.redirects.is_some_and(|r| !r.forward_credentials_cross_origin), "{:?}", restored.defaults.redirects);
    assert!(restored.defaults.early_data.as_ref().is_some_and(|e| !e.enabled), "{:?}", restored.defaults.early_data);
}

#[test]
fn an_attachment_whose_stored_content_is_gone_is_left_out_with_a_warning() {
    let root = tempfile::tempdir().unwrap();
    let a = small(root.path(), "a");
    // An attachment index entry whose stored content no longer exists.
    let sha = "ab".repeat(32);
    a.store.put(kind::IMPORT_SOURCE, &Id::new(), None, None, 0.0, &json!({"attachment": sha, "blob": "missing-blob"})).unwrap();
    let (bytes, preview) = a.export_backup_with(PASS, KdfParams::testing()).unwrap();
    let note = format!("attachment {sha} (its stored content is missing)");
    assert_eq!(preview.manifest.excluded, vec![note.clone()]);

    let b = new_app(root.path(), "b");
    let rep = b.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    assert!(rep.warnings.contains(&format!("Not in the backup: {note}")), "{:?}", rep.warnings);
    assert!(b.get_attachment(&sha).unwrap().is_none(), "nothing stands in for the missing content");
    assert!(b.backup_contents().unwrap().attachments.is_empty());
    b.find_workspace("W").expect("the rest of the backup is restored");
}

#[tokio::test]
async fn replace_never_overwrites_records_or_reports_of_another_workspace() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let files = tempfile::tempdir().unwrap();
    let token = files.path().join("jwt_svid.token");
    std::fs::write(&token, "token-file-content").unwrap();
    let root = tempfile::tempdir().unwrap();
    let a = populated(root.path(), &fx.url(""), &token).await;
    let contents = a.backup_contents().unwrap();
    let bytes = export(&a);

    // A profile storing, in a workspace of its own, a spec import, a run
    // report, a history record and a load report under the backup's ids.
    let b = new_app(root.path(), "b");
    let payments = b.create_workspace("Payments").unwrap();
    let mut reused = Vec::new();
    for k in [kind::SPEC_SOURCE, kind::RUN_REPORT] {
        let o = contents.objects.iter().find(|o| o.kind == k).unwrap();
        let mut v = o.value.clone();
        v["workspace_id"] = json!(payments.meta.id);
        b.store.put(k, &o.id.parse::<Id>().unwrap(), Some(&payments.meta.id), None, 0.0, &v).unwrap();
        reused.push((k.to_string(), o.id.clone()));
    }
    let h = &contents.history[0];
    let mut rec: ExecutionRecord = serde_json::from_value(h.record.clone()).unwrap();
    rec.workspace_id = Some(payments.meta.id);
    b.store.add_history(&rec.id, rec.workspace_id.as_ref(), None, h.started_at, &rec, None).unwrap();
    reused.push(("history".to_string(), h.id.clone()));
    let report = &contents.load_reports[0];
    let run_id: Id = serde_json::from_value(report["run_id"].clone()).unwrap();
    b.store.put_load_report(&run_id, Some(&payments.meta.id), 0, report).unwrap();
    reused.push(("load_report".to_string(), run_id.to_string()));

    // Each is listed, and Replace is refused before anything is written.
    let preview = b.restore_preview(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap();
    let foreign = &preview.plan.foreign_objects;
    assert_eq!(foreign.len(), reused.len(), "{foreign:?}");
    for (label, id) in &reused {
        assert!(foreign.iter().any(|f| f.starts_with(label.as_str()) && f.ends_with(&format!("({id})"))), "{label} {id}: {foreign:?}");
    }
    let before = b.backup_contents().unwrap();
    let e = b.restore(&bytes, Some(PASS), ConflictPolicy::Replace).unwrap_err();
    assert!(matches!(&e, AppError::Invalid(m) if m.contains("belong to another workspace")), "{e}");
    assert!(b.backup_contents().unwrap() == before, "a refused restore changed the profile");

    // Merge keeps them where they are.
    b.restore(&bytes, Some(PASS), ConflictPolicy::Merge).unwrap();
    let history = b.store.list_history(Some(&payments.meta.id), None, 10).unwrap();
    assert!(history.iter().any(|x| x.id == h.id), "the stored history record stays in its workspace");
    assert_eq!(b.store.list_load_reports::<serde_json::Value>(Some(&payments.meta.id)).unwrap().len(), 1);

    // A history record of a workspace that is not in the backup (deleted
    // since) is left out with a warning, never written.
    let outside = contents.history[1].id.clone();
    let edited = resealed(&bytes, |_, c| {
        let row = c.history.iter_mut().find(|x| x.id == outside).unwrap();
        row.record["workspace_id"] = json!(Id::new());
    });
    let fresh = new_app(root.path(), "fresh");
    let rep = fresh.restore(&edited, Some(PASS), ConflictPolicy::Replace).unwrap();
    let warning = "1 history record(s) of workspaces that are not in the backup were left out.";
    assert!(rep.warnings.iter().any(|w| w == warning), "{:?}", rep.warnings);
    let restored = fresh.backup_contents().unwrap();
    assert!(restored.history.iter().all(|x| x.id != outside), "the record is not restored");
    assert_eq!(restored.history.len(), contents.history.len() - 1);
}
