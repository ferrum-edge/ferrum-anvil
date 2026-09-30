//! API standards kept in the profile: rulesets are checked in context when
//! added or changed, layered in order, and used to lint imported specs.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_app::specs::SpecTarget;
use anvil_contract::Severity;
use anvil_import::ImportOptions;
use anvil_storage::{KdfParams, kind};
use sha2::Digest;
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

    // TEAM has no `extends`; its info-contact severity override therefore
    // fails to layer once the recommended ruleset that defines the rule is
    // removed.
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
    let big = format!("anvil_ruleset: 1\n# {}\n", "x".repeat(anvil_domain::settings::MAX_STORED_RULESET_BYTES));
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
    assert_eq!(migrated.api_standards().unwrap().rulesets, std::slice::from_ref(&ruleset));
    assert!(migrated.settings().unwrap().api_standards.legacy_rulesets.is_empty());
    drop(migrated);

    let (header, key) = ProfileManager::unlock(&path, anvil_app::profiles::Unlock::Passphrase("correct horse battery")).unwrap();
    let reopened = App::open(path, header, key).unwrap();
    assert_eq!(reopened.api_standards().unwrap().rulesets, [ruleset]);
    assert_eq!(manager.list().len(), 1);
}

#[test]
fn migration_keeps_all_legacy_rulesets_over_limits_and_the_profile_can_be_trimmed() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let mut legacy = Vec::new();
    for index in 0..=anvil_domain::settings::MAX_STORED_RULESETS {
        legacy.push(anvil_domain::settings::StoredRuleset {
            id: anvil_domain::Id::new(),
            name: format!("Legacy {index}"),
            file_name: format!("legacy-{index}.yaml"),
            text: TEAM.into(),
            sha256: hex::encode(sha2::Sha256::digest(TEAM.as_bytes())),
            enabled: true,
            version: None,
            added_at: chrono::Utc::now(),
        });
    }
    let mut settings = app.settings().unwrap();
    settings.api_standards.legacy_rulesets = legacy.clone();
    app.store.put(kind::APP_SETTINGS, &anvil_app::settings_id(), None, None, 0.0, &settings).unwrap();
    let path = app.dir.clone();
    drop(app);

    let (header, key) = ProfileManager::unlock(&path, anvil_app::profiles::Unlock::Passphrase("correct horse battery")).unwrap();
    let opened = App::open(path, header, key).unwrap();
    let records = opened.api_standards().unwrap().rulesets;
    assert_eq!(records, legacy);
    assert!(opened.settings().unwrap().api_standards.legacy_rulesets.is_empty());
    assert!(opened.add_api_ruleset("extra.yaml", TEAM.as_bytes()).is_err());

    opened.set_api_ruleset_enabled(&records[0].id, false).unwrap();
    opened.remove_api_ruleset(&records[1].id).unwrap();
    let mut settings = opened.settings().unwrap();
    settings.autosave = true;
    opened.save_settings(&settings).unwrap();
    let saved = opened.api_standards().unwrap().rulesets;
    assert_eq!(saved.len(), anvil_domain::settings::MAX_STORED_RULESETS);
    assert!(!saved.iter().find(|ruleset| ruleset.id == records[0].id).unwrap().enabled);
    assert!(!saved.iter().any(|ruleset| ruleset.id == records[1].id));
    assert!(saved.iter().all(|ruleset| records.iter().any(|original| original.id == ruleset.id)));
    assert!(opened.settings().unwrap().autosave);
}

#[test]
fn existing_ruleset_wins_legacy_id_collision_regardless_of_legacy_timestamp() {
    for offset in [-60, 60] {
        let dir = tempfile::tempdir().unwrap();
        let app = new_app(dir.path());
        let existing = app.add_api_ruleset("stored.yaml", TEAM.as_bytes()).unwrap();
        let mut legacy = existing.clone();
        legacy.name = "Legacy copy".into();
        legacy.added_at += chrono::Duration::seconds(offset);
        let mut settings = app.settings().unwrap();
        settings.api_standards.legacy_rulesets.push(legacy);
        app.store.put(kind::APP_SETTINGS, &anvil_app::settings_id(), None, None, 0.0, &settings).unwrap();
        let path = app.dir.clone();
        drop(app);

        let (header, key) = ProfileManager::unlock(&path, anvil_app::profiles::Unlock::Passphrase("correct horse battery")).unwrap();
        let migrated = App::open(path, header, key).unwrap();
        assert_eq!(migrated.api_standards().unwrap().rulesets, [existing]);
        assert!(migrated.settings().unwrap().api_standards.legacy_rulesets.is_empty());
    }
}

#[test]
fn rulesets_export_import_and_merge_conflicts_follow_object_kind_rules() {
    let root = tempfile::tempdir().unwrap();
    let source = new_app(root.path());
    let ws = source.create_workspace("Standards workspace").unwrap();
    let ruleset = source.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    source.add_api_ruleset("overlay.yaml", OVERLAY.as_bytes()).unwrap();
    let (bundle, _) = source
        .export_with_standards(Some(&ws.meta.id), anvil_portability::ExportMode::EncryptedTransfer, Some("bundle passphrase"), false, true)
        .unwrap();

    let target = new_app(root.path());
    let preview = target.import_preview(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert_eq!(preview.plan.to_create, 3, "workspace and rulesets are separate importable objects");
    let mut changed = ruleset.clone();
    changed.name = "Local version".into();
    target.store.put(kind::API_RULESET, &changed.id, None, None, 0.0, &changed).unwrap();
    let conflict = target.import_preview(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert!(conflict.plan.conflicts.iter().any(|c| c.contains("api_ruleset 'Team'")), "{:?}", conflict.plan.conflicts);
    target.import(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert_eq!(target.api_standards().unwrap().rulesets[0].name, "Local version");

    let round_trip = new_app(root.path());
    round_trip.set_api_standards_recommended(false).unwrap();
    round_trip.import(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert!(!round_trip.api_standards().unwrap().include_recommended, "import keeps the local recommended-rules setting");
    let mut imported = ruleset;
    imported.enabled = false;
    let carried = round_trip.api_standards().unwrap();
    assert_eq!(carried.rulesets[0], imported);
    assert_eq!(carried.rulesets[1].name, "Overlay");
    assert!(!carried.rulesets[1].enabled);
}

#[test]
fn replace_import_keeps_enabled_state_and_sort_order_for_matching_ruleset_id() {
    let root = tempfile::tempdir().unwrap();
    let source = new_app(root.path());
    let ws = source.create_workspace("Replace standards workspace").unwrap();
    let ruleset = source.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    source.add_api_ruleset("overlay.yaml", OVERLAY.as_bytes()).unwrap();
    let (bundle, _) = source
        .export_with_standards(Some(&ws.meta.id), anvil_portability::ExportMode::EncryptedTransfer, Some("bundle passphrase"), false, true)
        .unwrap();

    let target = new_app(root.path());
    let mut local = ruleset.clone();
    local.enabled = true;
    target.store.put(kind::API_RULESET, &local.id, None, None, 7.0, &local).unwrap();
    target.import(&bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Replace).unwrap();

    let imported = target.api_standards().unwrap().rulesets;
    assert_eq!(imported.len(), 2);
    assert!(imported[0].enabled, "Replace keeps the matching local enabled flag");
    assert!(!imported[1].enabled, "new rulesets arrive disabled in Replace imports");
    assert_eq!(imported[0].text, ruleset.text);
    let meta = target.store.object_meta(kind::API_RULESET).unwrap();
    assert_eq!(meta.iter().find(|row| row.id == ruleset.id.to_string()).unwrap().sort_key, 7.0);
}

#[test]
fn replace_import_checks_changed_rulesets_at_their_stored_position() {
    let root = tempfile::tempdir().unwrap();
    let source = new_app(root.path());
    let ws = source.create_workspace("Replace ordering source").unwrap();
    let team = source.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    let unchanged_bundle = source
        .export_with_standards(Some(&ws.meta.id), anvil_portability::ExportMode::EncryptedTransfer, Some("bundle passphrase"), false, true)
        .unwrap()
        .0;

    let mut changed = team.clone();
    changed.text = "anvil_ruleset: 1\nname: Team\nversion: '4'\nrules:\n  info-contact: error\n".into();
    changed.sha256 = hex::encode(sha2::Sha256::digest(changed.text.as_bytes()));
    source.store.put(kind::API_RULESET, &changed.id, None, None, 0.0, &changed).unwrap();
    let changed_bundle = source
        .export_with_standards(Some(&ws.meta.id), anvil_portability::ExportMode::EncryptedTransfer, Some("bundle passphrase"), false, true)
        .unwrap()
        .0;

    let target = new_app(root.path());
    target.store.put(kind::API_RULESET, &team.id, None, None, 7.0, &team).unwrap();
    let overlay = target.add_api_ruleset("overlay.yaml", OVERLAY.as_bytes()).unwrap();
    target.store.put(kind::API_RULESET, &overlay.id, None, None, 9.0, &overlay).unwrap();

    let preview =
        target.import_preview(&changed_bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Replace).unwrap();
    assert!(preview.warnings.iter().any(|warning| warning.contains("would not load")), "{:?}", preview.warnings);
    let report = target.import(&changed_bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Replace).unwrap();
    assert!(report.warnings.iter().any(|warning| warning.contains("would not load")), "{:?}", report.warnings);

    let unchanged = new_app(root.path());
    unchanged.store.put(kind::API_RULESET, &team.id, None, None, 7.0, &team).unwrap();
    let unchanged_overlay = unchanged.add_api_ruleset("overlay.yaml", OVERLAY.as_bytes()).unwrap();
    unchanged.store.put(kind::API_RULESET, &unchanged_overlay.id, None, None, 9.0, &unchanged_overlay).unwrap();
    let preview =
        unchanged.import_preview(&unchanged_bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Replace).unwrap();
    assert!(!preview.warnings.iter().any(|warning| warning.contains("would not load")), "{:?}", preview.warnings);
    let report = unchanged.import(&unchanged_bundle, Some("bundle passphrase"), anvil_portability::plan::ConflictPolicy::Replace).unwrap();
    assert!(!report.warnings.iter().any(|warning| warning.contains("would not load")), "{:?}", report.warnings);
}

#[test]
fn share_safe_bundles_exclude_standards_unless_explicitly_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let ws = app.create_workspace("Standards option").unwrap();
    let ruleset = app.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    let overlay = app.add_api_ruleset("overlay.yaml", OVERLAY.as_bytes()).unwrap();

    let (excluded, preview) =
        app.export_with_standards(Some(&ws.meta.id), anvil_portability::ExportMode::ShareSafely, None, false, false).unwrap();
    assert_eq!(preview.manifest.counts["api_standards"], 0);
    assert!(anvil_portability::bundle::open(&excluded, None).unwrap().graph.rulesets.is_empty());

    let (included, preview) =
        app.export_with_standards(Some(&ws.meta.id), anvil_portability::ExportMode::ShareSafely, None, false, true).unwrap();
    assert_eq!(preview.manifest.counts["api_standards"], 2);
    let carried = anvil_portability::bundle::open(&included, None).unwrap().graph.rulesets;
    assert_eq!(carried.iter().map(|r| r.id).collect::<Vec<_>>(), [ruleset.id, overlay.id]);

    let mut tampered = ruleset.clone();
    tampered.sha256 = "incorrect incoming hash".into();
    app.store.put(kind::API_RULESET, &tampered.id, None, None, 0.0, &tampered).unwrap();
    let (mismatched, _) =
        app.export_with_standards(Some(&ws.meta.id), anvil_portability::ExportMode::ShareSafely, None, false, true).unwrap();
    let target = new_app(dir.path());
    target.import(&mismatched, None, anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    let imported = target.api_standards().unwrap().rulesets;
    assert_eq!(imported.iter().map(|r| r.id).collect::<Vec<_>>(), [ruleset.id, overlay.id]);
    assert_eq!(imported[0].sha256, ruleset.sha256);
    assert!(imported.iter().all(|r| !r.enabled));
}

#[test]
fn one_mebibyte_rulesets_are_stored_as_individual_records() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let body = format!("{TEAM}#{}\n", "x".repeat(anvil_domain::settings::MAX_STORED_RULESET_BYTES - TEAM.len() - 2));
    assert_eq!(body.len(), anvil_domain::settings::MAX_STORED_RULESET_BYTES);
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

#[test]
fn over_limit_rule_count_still_allows_disabling_and_removing_records() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let template = app.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    for index in 1..=anvil_domain::settings::MAX_STORED_RULESETS {
        let mut copy = template.clone();
        copy.id = anvil_domain::Id::new();
        copy.name = format!("Team {index}");
        app.store.put(kind::API_RULESET, &copy.id, None, None, index as f64, &copy).unwrap();
    }
    let records = app.api_standards().unwrap().rulesets;
    assert_eq!(records.len(), anvil_domain::settings::MAX_STORED_RULESETS + 1);
    app.set_api_ruleset_enabled(&records[0].id, false).unwrap();
    app.remove_api_ruleset(&records[1].id).unwrap();
    assert_eq!(app.api_standards().unwrap().rulesets.len(), anvil_domain::settings::MAX_STORED_RULESETS);
}

#[test]
fn over_limit_total_size_still_allows_disabling_rulesets() {
    let dir = tempfile::tempdir().unwrap();
    let app = new_app(dir.path());
    let size = anvil_domain::settings::MAX_STORED_RULESET_BYTES - 1;
    let text = format!("{TEAM}#{}\n", "x".repeat(size - TEAM.len() - 2));
    let template = app.add_api_ruleset("large.yaml", text.as_bytes()).unwrap();
    for index in 1..9 {
        let mut copy = template.clone();
        copy.id = anvil_domain::Id::new();
        copy.name = format!("Large {index}");
        app.store.put(kind::API_RULESET, &copy.id, None, None, index as f64, &copy).unwrap();
    }
    let records = app.api_standards().unwrap().rulesets;
    assert!(records.iter().map(|r| r.text.len()).sum::<usize>() > anvil_domain::settings::MAX_STORED_RULESETS_BYTES);
    app.set_api_ruleset_enabled(&records[0].id, false).unwrap();
}

#[test]
fn duplicate_import_skips_matching_ruleset_hashes_and_combined_limits_refuse_excess() {
    let dir = tempfile::tempdir().unwrap();
    let source = new_app(dir.path());
    let ws = source.create_workspace("Standards source").unwrap();
    source.add_api_ruleset("team.yaml", TEAM.as_bytes()).unwrap();
    let (bundle, _) =
        source.export_with_standards(Some(&ws.meta.id), anvil_portability::ExportMode::ShareSafely, None, false, true).unwrap();

    let duplicate_target = new_app(dir.path());
    duplicate_target.add_api_ruleset("local.yaml", TEAM.as_bytes()).unwrap();
    duplicate_target.import(&bundle, None, anvil_portability::plan::ConflictPolicy::Duplicate).unwrap();
    assert_eq!(duplicate_target.api_standards().unwrap().rulesets.len(), 1);

    let full_target = new_app(dir.path());
    let local = full_target.add_api_ruleset("local.yaml", TEAM.as_bytes()).unwrap();
    for index in 1..anvil_domain::settings::MAX_STORED_RULESETS {
        let mut copy = local.clone();
        copy.id = anvil_domain::Id::new();
        copy.name = format!("Local {index}");
        copy.text = format!("{TEAM}# local {index}\n");
        full_target.store.put(kind::API_RULESET, &copy.id, None, None, index as f64, &copy).unwrap();
    }
    let preview = full_target.import_preview(&bundle, None, anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert!(preview.warnings.iter().any(|warning| warning.contains("the import will be refused")), "{:?}", preview.warnings);
    let err = full_target.import(&bundle, None, anvil_portability::plan::ConflictPolicy::Merge).unwrap_err();
    assert!(err.to_string().contains("32 rulesets"));
    let backup = source.export_backup_with("backup passphrase", anvil_storage::KdfParams::testing()).unwrap().0;
    let preview = full_target.restore_preview(&backup, Some("backup passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert!(preview.warnings.iter().any(|warning| warning.contains("the restore will be refused")), "{:?}", preview.warnings);
    assert!(preview.warnings.iter().any(|warning| warning.contains("remove rulesets from this profile or from the backup")), "{:?}", preview.warnings);
    let err = full_target.restore(&backup, Some("backup passphrase"), anvil_portability::plan::ConflictPolicy::Merge).unwrap_err();
    assert!(err.to_string().contains("32 rulesets"));
}
