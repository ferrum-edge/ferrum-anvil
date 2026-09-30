//! API standards kept in the profile: rulesets are checked in context when
//! added or changed, layered in order, and used to lint imported specs.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_app::specs::SpecTarget;
use anvil_contract::Severity;
use anvil_import::ImportOptions;
use anvil_storage::{KdfParams, kind};
use std::path::Path;

fn new_app(root: &Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

const SPEC: &str =
    "openapi: 3.1.0\ninfo: { title: Pets, version: '1' }\npaths:\n  /pets:\n    get:\n      responses: { '200': { description: ok } }\n";

const TEAM: &str = "anvil_ruleset: 1\nname: Team\nversion: '3'\nrules:\n  info-contact: error\n  team-summary:\n    severity: error\n    given: operation\n    then: { field: summary, function: truthy }\n";

const OVERLAY: &str = "anvil_ruleset: 1\nname: Overlay\nrules:\n  team-summary: off\n";

#[test]
fn rulesets_layer_in_order_and_lint_imported_specs() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let defaults = app.api_standards().unwrap();
    assert!(defaults.include_recommended && defaults.rulesets.is_empty());

    let imported = app.spec_import(SPEC.as_bytes(), "pets.yaml", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    let r = app.lint_imported_spec(&imported.import_id).unwrap();
    let info_contact = r.findings.iter().find(|f| f.rule == "info-contact").unwrap();
    assert_eq!(info_contact.severity, Severity::Warn);
    assert_eq!(info_contact.line, Some(2));

    let team = app.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    assert_eq!((team.name.as_str(), team.version.as_deref()), ("Team", Some("3")));
    let r = app.lint_imported_spec(&imported.import_id).unwrap();
    assert_eq!(r.findings.iter().find(|f| f.rule == "info-contact").unwrap().severity, Severity::Error);
    assert!(r.findings.iter().any(|f| f.rule == "team-summary"));
    assert_eq!(r.rulesets.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["Anvil recommended", "Team"]);

    // An overlay turns a team rule off; disabling the team ruleset would
    // leave the overlay naming a rule nobody defines, so it is refused.
    let overlay = app.add_api_ruleset("overlay.yaml", OVERLAY.as_bytes()).unwrap();
    assert!(!app.lint_spec(SPEC.as_bytes()).unwrap().findings.iter().any(|f| f.rule == "team-summary"));
    let err = app.set_api_ruleset_enabled(&team.id, false).unwrap_err();
    assert!(err.to_string().contains("team-summary"), "{err}");
    assert!(app.api_standards().unwrap().rulesets.iter().all(|r| r.enabled), "a refused change writes nothing");
    app.set_api_ruleset_enabled(&overlay.id, false).unwrap();
    assert!(app.lint_spec(SPEC.as_bytes()).unwrap().findings.iter().any(|f| f.rule == "team-summary"));

    // Without the recommended rules only the team's own apply.
    app.remove_api_ruleset(&overlay.id).unwrap();
    let err = app.set_api_standards_recommended(false).unwrap_err();
    assert!(err.to_string().contains("info-contact"), "Team overrides a recommended rule: {err}");
    let view = app.standards_view().unwrap();
    assert!(view.rules.iter().any(|r| r.id == "team-summary" && r.ruleset == "Team"));
    assert_eq!(view.standards.rulesets.len(), 1);

    // Replacing keeps the id, position and enabled state.
    let v2 = TEAM.replace("version: '3'", "version: '4'");
    let replaced = app.replace_api_ruleset(&team.id, "team-v4.yaml", v2.as_bytes()).unwrap();
    assert_eq!(replaced.id, team.id);
    let stored = app.api_standards().unwrap();
    assert_eq!(stored.rulesets[0].version.as_deref(), Some("4"));
    assert_eq!(stored.rulesets[0].file_name, "team-v4.yaml");
}

#[test]
fn invalid_rulesets_and_specs_are_refused_before_anything_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    for bad in [
        "rules: {}\n",
        "anvil_ruleset: 1\nrules:\n  x: { given: nope, then: { function: truthy } }\n",
        "anvil_ruleset: 1\nrules:\n  unknown-rule: warn\n",
    ] {
        assert!(app.add_api_ruleset("bad.yaml", bad.as_bytes()).is_err(), "{bad}");
    }
    let big = format!("anvil_ruleset: 1\n# {}\n", "x".repeat(anvil_app::standards::MAX_STORED_RULESET_BYTES));
    assert!(app.add_api_ruleset("big.yaml", big.as_bytes()).unwrap_err().to_string().contains("at most"));
    assert!(app.api_standards().unwrap().rulesets.is_empty());
    assert!(app.lint_spec(b"{\"info\": {\"_postman_id\": \"x\"}, \"item\": []}").is_err());
}

#[test]
fn a_reimported_spec_is_linted_by_its_latest_version() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let first = app.spec_import(SPEC.as_bytes(), "pets.yaml", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    let v2 = SPEC.replace("    get:\n", "    get:\n      summary: List pets\n");
    app.spec_reimport_apply(&first.import_id, v2.as_bytes(), "pets.yaml", &Default::default()).unwrap();
    // The earlier id still finds the record; the original is the newer file.
    let r = app.lint_imported_spec(&first.import_id).unwrap();
    assert!(!r.findings.iter().any(|f| f.rule == "operation-summary"));
    assert_eq!(app.spec_original(&first.import_id).unwrap(), v2.as_bytes());
}

#[test]
fn a_settings_save_from_elsewhere_keeps_the_standards() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let stale = app.settings().unwrap();
    app.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    let mut edited = stale.clone();
    edited.autosave = true;
    app.save_settings_keeping_standards(&edited).unwrap();
    let now = app.settings().unwrap();
    assert!(now.autosave);
    assert_eq!(app.api_standards().unwrap().rulesets.len(), 1, "the dialog's stale copy did not drop the ruleset");
}

#[test]
fn stored_standards_that_do_not_load_can_still_be_seen_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let good = app.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    // A restore from another build can store a ruleset this build refuses.
    let mut bad = good.clone();
    bad.id = anvil_domain::Id::new();
    bad.text = "anvil_ruleset: 2\n".into();
    app.store.put(anvil_storage::kind::API_RULESET, &bad.id, None, None, 1.0, &bad).unwrap();
    let view = app.standards_view().unwrap();
    assert!(view.error.as_deref().unwrap().contains("version 2"), "{:?}", view.error);
    assert!(view.rules.is_empty() && view.standards.rulesets.len() == 2);
    assert!(app.lint_spec(SPEC.as_bytes()).is_err());
    app.remove_api_ruleset(&bad.id).unwrap();
    let view = app.standards_view().unwrap();
    assert!(view.error.is_none());
    assert_eq!(view.standards.rulesets[0].id, good.id);
}

#[test]
fn old_settings_rulesets_migrate_once_on_profile_open() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let ruleset = app.add_api_ruleset("legacy.yaml", TEAM.as_bytes()).unwrap();
    app.store.delete(kind::API_RULESET, &ruleset.id).unwrap();
    let mut settings = app.settings().unwrap();
    settings.api_standards.legacy_rulesets.push(ruleset.clone());
    app.store.put(kind::APP_SETTINGS, &anvil_app::settings_id(), None, None, 0.0, &settings).unwrap();
    let path = app.dir.clone();
    drop(app);

    let manager = ProfileManager::new(dir.path());
    let (header, key) = ProfileManager::unlock(&path, anvil_app::profiles::Unlock::Passphrase("correct horse battery")).unwrap();
    let migrated = App::open(path.clone(), header, key).unwrap();
    assert_eq!(migrated.api_standards().unwrap().rulesets, [ruleset.clone()]);
    assert!(migrated.settings().unwrap().api_standards.legacy_rulesets.is_empty());
    drop(migrated);

    let (header, key) = ProfileManager::unlock(&path, anvil_app::profiles::Unlock::Passphrase("correct horse battery")).unwrap();
    let reopened = App::open(path, header, key).unwrap();
    assert_eq!(reopened.api_standards().unwrap().rulesets, [ruleset]);
    assert_eq!(manager.list().len(), 1);
}

#[test]
fn rulesets_export_import_and_merge_conflicts_follow_object_kind_rules() {
    let root = tempfile::tempdir().unwrap();
    let source = new_app(root.path());
    let ws = source.create_workspace("Standards workspace").unwrap();
    let ruleset = source.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    let (bundle, _) =
        source.export(Some(&ws.meta.id), anvil_portability::ExportMode::EncryptedTransfer, Some("bundle passphrase"), false).unwrap();

    let target = new_app(root.path());
    let preview = target.import_preview(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert_eq!(preview.plan.to_create, 2, "workspace and ruleset are separate importable objects");
    let mut changed = ruleset.clone();
    changed.name = "Local version".into();
    target.store.put(kind::API_RULESET, &changed.id, None, None, 0.0, &changed).unwrap();
    let conflict = target.import_preview(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert!(conflict.plan.conflicts.iter().any(|c| c.contains("api_ruleset 'Team'")), "{:?}", conflict.plan.conflicts);
    target.import(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert_eq!(target.api_standards().unwrap().rulesets[0].name, "Local version");

    let round_trip = new_app(root.path());
    round_trip.import(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert_eq!(round_trip.api_standards().unwrap().rulesets, [ruleset]);
}

#[test]
fn one_mebibyte_rulesets_are_stored_as_individual_records() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let body = format!("{TEAM}#{}\n", "x".repeat(anvil_app::standards::MAX_STORED_RULESET_BYTES - TEAM.len() - 2));
    assert_eq!(body.len(), anvil_app::standards::MAX_STORED_RULESET_BYTES);
    let stored = app.add_api_ruleset("large.yaml", body.as_bytes()).unwrap();
    assert_eq!(app.store.get::<anvil_domain::settings::StoredRuleset>(kind::API_RULESET, &stored.id).unwrap(), Some(stored.clone()));

    let too_large = format!("{body} ");
    assert!(app.add_api_ruleset("too-large.yaml", too_large.as_bytes()).is_err());
    let updated = app.replace_api_ruleset(&stored.id, "large-v2.yaml", TEAM.as_bytes()).unwrap();
    assert_eq!(updated.id, stored.id);
    assert_eq!(app.store.get::<anvil_domain::settings::StoredRuleset>(kind::API_RULESET, &stored.id).unwrap(), Some(updated));
    app.remove_api_ruleset(&stored.id).unwrap();
    assert!(app.store.get::<anvil_domain::settings::StoredRuleset>(kind::API_RULESET, &stored.id).unwrap().is_none());
}
