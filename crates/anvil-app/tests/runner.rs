//! Collection runs through the application services: frozen contexts from
//! the encrypted store, history recording, saved reports, trust gating of
//! imported scenarios, datasets and lock behaviour — over real sockets.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_app::runner::RunSettings;
use anvil_domain::assertions::{Extraction, ExtractionSource};
use anvil_domain::auth::{AuthConfig, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::runner::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{DatasetFormat, Meta, Scenario, ScenarioStep, Variable};
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn new_app(root: &std::path::Path, name: &str) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase(name, "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

fn step(id: anvil_domain::Id) -> ScenarioStep {
    ScenarioStep { request_id: id, enabled: true, delay_ms: 0 }
}

fn history_text(app: &App, ws: &anvil_domain::Id) -> String {
    let mut out = String::new();
    for h in app.store.list_history(Some(ws), None, 1000).unwrap() {
        let (rec, body) = app.store.get_history::<serde_json::Value>(&h.id).unwrap().unwrap();
        out.push_str(&rec.to_string());
        if let Some(b) = body {
            out.push_str(&String::from_utf8_lossy(&b));
        }
    }
    out
}

#[tokio::test]
async fn oversized_extractions_preserve_deferred_vault_variable_bindings() {
    anvil_fixtures::init();
    for multiple_layers in [false, true] {
        let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
        let root = tempfile::tempdir().unwrap();
        let app = new_app(root.path(), "vault-bindings");
        let mut ws = app.create_workspace("Vault bindings").unwrap();
        let removed_value = "removed-vault-canary-928374";
        let kept_value = "retained-vault-canary-615243";
        let also_kept_value = "other-retained-vault-canary-417263";
        let removed = app.set_secret(&ws.meta.id, "removed", removed_value).unwrap();
        let kept = app.set_secret(&ws.meta.id, "kept", kept_value).unwrap();
        let also_kept = app.set_secret(&ws.meta.id, "also kept", also_kept_value).unwrap();
        let vault = |name: &str, secret: &anvil_domain::secret::SecretRef| Variable {
            name: name.into(),
            value: SensitiveValue::Secret { secret: secret.clone() },
            secret: true,
            enabled: true,
            description: String::new(),
        };
        ws.variables = vec![vault("session", &removed), Variable::plain("label", "public")];
        if multiple_layers {
            ws.variables.insert(1, vault("also_removed", &removed));
            ws.variables.push(vault("kept", &kept));
            ws.variables.push(vault("also_kept", &also_kept));
            let env = app
                .create_environment(
                    &ws.meta.id,
                    "active",
                    vec![
                        vault("session", &removed),
                        Variable::plain("also_removed", "outer fallback"),
                        vault("kept", &kept),
                        vault("also_kept", &also_kept),
                        Variable::plain("label", "environment-public"),
                    ],
                )
                .unwrap();
            ws.active_environment_id = Some(env.meta.id);
        }
        app.save_workspace(ws.clone()).unwrap();

        let mut trigger = RequestSpec::http("POST", &f.url("/echo"));
        trigger.body =
            Body::Raw { text: "x".repeat(anvil_engine::MAX_SENSITIVE_EXTRACTION_BYTES + 1), content_type: Some("text/plain".into()) };
        for name in if multiple_layers { vec!["session", "also_removed"] } else { vec!["session"] } {
            trigger.extractions.push(Extraction {
                variable: name.into(),
                source: ExtractionSource::JsonPath { path: "$.body".into() },
                sensitive: true,
            });
        }
        let trigger = app.create_request(&ws.meta.id, None, "Oversized extraction", trigger).unwrap();
        let mut use_vars = RequestSpec::http("GET", &f.url("/echo"));
        use_vars.auth = AuthConfig::OAuth2 {
            config: OAuth2Config {
                grant: OAuthGrant::ClientCredentials,
                token_url: f.url("/oauth/token"),
                authorization_url: String::new(),
                client_id: "anvil-client".into(),
                client_secret: SensitiveValue::template("anvil-secret"),
                scope: String::new(),
                audience: String::new(),
                client_auth: OAuthClientAuth::RequestBody,
                token_cache_id: None,
                refresh_skew_secs: 30,
            },
        };
        use_vars.headers.push(KeyValue::new("X-Label", "{{label}}"));
        if multiple_layers {
            use_vars.headers.push(KeyValue::new("X-Kept", "{{kept}}"));
            use_vars.headers.push(KeyValue::new("X-Also-Kept", "{{also_kept}}"));
        }
        let use_vars = app.create_request(&ws.meta.id, None, "Retained variables", use_vars).unwrap();
        let mut scenario = app
            .create_scenario(&ws.meta.id, "Continue after extraction failure", vec![step(trigger.meta.id), step(use_vars.meta.id)])
            .unwrap();
        scenario.stop_on_failure = false;
        scenario.iterations = 2;
        app.update_scenario(scenario.clone()).unwrap();

        let report = app.run_scenario(&scenario.meta.id, RunSettings::default(), CancellationToken::new()).await.unwrap();
        assert_eq!(report.iterations.len(), 2);
        for iteration in &report.iterations {
            assert_eq!(iteration.steps[0].status, RunStepStatus::Failed, "the oversized extraction must trigger filtering");
            assert_eq!(iteration.steps[1].status, RunStepStatus::Passed, "retained variables must remain usable: {report:#?}");
        }
        let headers = f.log.last_request_headers().unwrap();
        let label = if multiple_layers { "environment-public" } else { "public" };
        assert!(headers.iter().any(|(name, value)| name == "x-label" && value == label), "{headers:?}");
        assert!(!headers.iter().any(|(_, value)| value == removed_value), "removed vault value reached the peer");
        if multiple_layers {
            for (name, expected) in [("x-kept", kept_value), ("x-also-kept", also_kept_value)] {
                assert!(headers.iter().any(|(header, value)| header == name && value == expected), "{headers:?}");
            }
        }
        let stored = history_text(&app, &ws.meta.id) + &anvil_runner::to_json(&report);
        assert!(!stored.contains(removed_value), "removed vault secret was retained in history or the report");
        // Captured response bodies retain the peer's bytes. Verify the normal
        // exact-value redaction contract on the structured execution records.
        for history in app.store.list_history(Some(&ws.meta.id), None, 10).unwrap() {
            let (record, _) = app.store.get_history::<serde_json::Value>(&history.id).unwrap().unwrap();
            let record = record.to_string();
            assert!(!record.contains(kept_value), "legitimate vault substitutions must still be redacted");
            assert!(!record.contains(also_kept_value), "other legitimate vault substitutions must still be redacted");
        }
        assert!(stored.contains(label), "the ordinary variable remains public");
    }
}

#[tokio::test]
async fn scenario_run_chains_records_history_and_saves_a_redacted_report() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "runner");
    let ws = app.create_workspace("Shop").unwrap();
    let env = app.create_environment(&ws.meta.id, "lab", vec![Variable::plain("base", &f.url(""))]).unwrap();
    let mut w = app.workspace(&ws.meta.id).unwrap();
    w.active_environment_id = Some(env.meta.id);
    app.save_workspace(w).unwrap();

    let token = "sess-TOKEN-5150-abc";
    let mut login = RequestSpec::http("POST", "{{base}}/status/200");
    login.params.push(KeyValue::new("body", format!(r#"{{"session":"{token}"}}"#)));
    login.extractions.push(Extraction {
        variable: "session".into(),
        source: ExtractionSource::JsonPath { path: "$.session".into() },
        sensitive: true,
    });
    let login = app.create_request(&ws.meta.id, None, "Login", login).unwrap();
    let mut me = RequestSpec::http("GET", "{{base}}/echo");
    me.headers.push(KeyValue::new("X-Session", "{{session}}"));
    let me = app.create_request(&ws.meta.id, None, "Me", me).unwrap();
    let sc = app.create_scenario(&ws.meta.id, "Login flow", vec![step(login.meta.id), step(me.meta.id)]).unwrap();
    assert!(sc.trusted, "locally authored scenarios are trusted");

    let r = app.run_scenario(&sc.meta.id, RunSettings::default(), CancellationToken::new()).await.unwrap();
    assert!(r.passed(), "{r:#?}");
    assert_eq!(r.environment_name.as_deref(), Some("lab"));
    assert!(matches!(&r.source, RunSource::Scenario { name, untrusted_override: false, .. } if name == "Login flow"));
    let seen = f.log.last_request_headers().unwrap();
    assert!(seen.iter().any(|(n, v)| n == "x-session" && v == token), "the fixture received the chained value");
    let steps = &r.iterations[0].steps;
    assert_eq!(steps[0].revision_id, login.revision_id, "the exact saved revision is recorded");

    // History: one record per executed step, linked from the report.
    let hist = app.store.list_history(Some(&ws.meta.id), None, 10).unwrap();
    assert_eq!(hist.len(), 2);
    for s in steps {
        let id = s.execution_id.unwrap().to_string();
        assert!(hist.iter().any(|h| h.id == id), "step record {id} is in history");
    }
    assert!(!history_text(&app, &ws.meta.id).contains(token), "history never stores the sensitive extracted value");

    // The report is saved encrypted and round-trips.
    let saved = app.run_reports(&ws.meta.id).unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(app.run_report(&r.run_id).unwrap(), r);
    assert!(!anvil_runner::to_json(&r).contains(token));
    // Nothing readable at rest: database, WAL and any side file.
    for entry in std::fs::read_dir(app.store.dir()).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            let bytes = std::fs::read(&p).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("Login flow") && !text.contains(token), "{} holds plaintext run data", p.display());
        }
    }
}

#[tokio::test]
async fn imported_scenarios_never_run_until_trusted_or_explicitly_allowed() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let a_root = tempfile::tempdir().unwrap();
    let a = new_app(a_root.path(), "author");
    let ws = a.create_workspace("Shared").unwrap();
    let req = a.create_request(&ws.meta.id, None, "Ping", RequestSpec::http("GET", &f.url("/count/imported"))).unwrap();
    a.create_scenario(&ws.meta.id, "Smoke", vec![step(req.meta.id)]).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, false).unwrap();

    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "recipient");
    b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    let ws_b = b.find_workspace("Shared").unwrap();
    let sc = b.find_scenario(&ws_b.meta.id, "smoke").unwrap();
    assert!(!sc.trusted, "import marks scenarios untrusted");
    assert_eq!(*f.state.counters.lock().get("imported").unwrap_or(&0), 0, "nothing ran on import");

    let e = b.run_scenario(&sc.meta.id, RunSettings::default(), CancellationToken::new()).await.unwrap_err();
    assert!(e.to_string().contains("not trusted"), "{e}");
    assert_eq!(*f.state.counters.lock().get("imported").unwrap_or(&0), 0, "refused runs send nothing");
    assert!(b.run_reports(&ws_b.meta.id).unwrap().is_empty());

    let once = RunSettings { allow_untrusted: true, ..Default::default() };
    let r = b.run_scenario(&sc.meta.id, once, CancellationToken::new()).await.unwrap();
    assert!(matches!(r.source, RunSource::Scenario { untrusted_override: true, .. }));
    assert!(!b.scenario(&sc.meta.id).unwrap().trusted, "a one-off override does not trust the scenario");

    b.trust_scenario(&sc.meta.id).unwrap();
    let r = b.run_scenario(&sc.meta.id, RunSettings::default(), CancellationToken::new()).await.unwrap();
    assert!(r.passed());
    assert_eq!(*f.state.counters.lock().get("imported").unwrap(), 2);
}

#[tokio::test]
async fn folder_runs_follow_tree_order_and_scenario_datasets_come_from_the_store() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "folders");
    let ws = app.create_workspace("Tree").unwrap();
    let orders = app.create_folder(&ws.meta.id, None, "Orders").unwrap();
    let refunds = app.create_folder(&ws.meta.id, Some(orders.meta.id), "Refunds").unwrap();
    app.create_request(&ws.meta.id, None, "Outside", RequestSpec::http("GET", &f.url("/count/outside"))).unwrap();
    app.create_request(&ws.meta.id, Some(orders.meta.id), "List", RequestSpec::http("GET", &f.url("/count/list"))).unwrap();
    app.create_request(&ws.meta.id, Some(refunds.meta.id), "Refund", RequestSpec::http("GET", &f.url("/count/refund"))).unwrap();

    assert_eq!(app.find_folder(&ws.meta.id, "orders/refunds").unwrap(), Some(refunds.meta.id));
    assert_eq!(app.find_folder(&ws.meta.id, "/").unwrap(), None);
    assert!(app.find_folder(&ws.meta.id, "Orders/Nope").is_err());

    let r = app.run_folder(&ws.meta.id, Some(orders.meta.id), RunSettings::default(), CancellationToken::new()).await.unwrap();
    assert!(matches!(&r.source, RunSource::Folder { path, .. } if path == "Orders"));
    let names: Vec<&str> = r.iterations[0].steps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["Refund", "List"], "subfolders first, then requests — the sidebar order");
    let paths: Vec<String> = f.log.requests().into_iter().map(|(_, p)| p).collect();
    assert_eq!(paths, vec!["/count/refund".to_string(), "/count/list".to_string()]);

    // A stored dataset with a sensitive column drives a scenario.
    f.log.clear();
    let mut spec = RequestSpec::http("GET", &f.url("/echo"));
    spec.params.push(KeyValue::new("sku", "{{sku}}"));
    spec.headers.push(KeyValue::new("X-Card", "{{card}}"));
    let buy = app.create_request(&ws.meta.id, None, "Buy", spec).unwrap();
    let bad = app.create_dataset(&ws.meta.id, "cards", DatasetFormat::Csv, b"sku,card\n", vec![]);
    assert!(bad.unwrap_err().to_string().contains("no rows"));
    assert!(app.create_dataset(&ws.meta.id, "cards", DatasetFormat::Csv, b"sku,card\na,b\n", vec!["cvv".into()]).is_err());
    let ds = app
        .create_dataset(
            &ws.meta.id,
            "cards",
            DatasetFormat::Csv,
            b"sku,card\nA-1,4111-1111-1111-1111\nB-2,5500-0000-0000-0004\nC-3,3400-0000-0000-009\n",
            vec!["card".into()],
        )
        .unwrap();
    let mut sc = app.create_scenario(&ws.meta.id, "Buy all", vec![step(buy.meta.id)]).unwrap();
    sc.dataset_id = Some(ds.meta.id);
    let sc = app.update_scenario(sc).unwrap();
    let r = app.run_scenario(&sc.meta.id, RunSettings::default(), CancellationToken::new()).await.unwrap();
    assert_eq!(r.totals.iterations_planned, 3);
    assert_eq!(f.log.count_requests(), 3);
    let text = anvil_runner::to_json(&r) + &anvil_runner::to_html(&r) + &anvil_runner::to_junit(&r) + &history_text(&app, &ws.meta.id);
    for card in ["4111-1111-1111-1111", "5500-0000-0000-0004", "3400-0000-0000-009"] {
        assert!(!text.contains(card), "sensitive dataset value leaked");
    }
    assert!(text.contains("sku=A-1"));

    // Bad scenario definitions are rejected at save time.
    let foreign = app.create_workspace("Other").unwrap();
    let e = app.create_scenario(&foreign.meta.id, "Cross", vec![step(buy.meta.id)]).unwrap_err();
    assert!(e.to_string().contains("another workspace"), "{e}");
}

#[tokio::test]
async fn locking_mid_run_aborts_with_a_partial_report() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = Arc::new(new_app(root.path(), "lock"));
    let ws = app.create_workspace("Lock").unwrap();
    let a = app.create_request(&ws.meta.id, None, "First", RequestSpec::http("GET", &f.url("/count/first"))).unwrap();
    let b = app.create_request(&ws.meta.id, None, "Second", RequestSpec::http("GET", &f.url("/count/second"))).unwrap();
    let sc = Scenario {
        meta: Meta::new(),
        workspace_id: ws.meta.id,
        name: "Locks".into(),
        description: String::new(),
        steps: vec![step(a.meta.id), step(b.meta.id)],
        dataset_id: None,
        iterations: 5,
        stop_on_failure: false,
        trusted: true,
    };
    app.save_scenario(sc.clone()).unwrap();
    let app2 = app.clone();
    let sink: anvil_runner::RunEventSink = Arc::new(move |e| {
        if let RunEvent::StepFinished { step: 0, .. } = e {
            app2.lock();
        }
    });
    let r =
        app.run_scenario(&sc.meta.id, RunSettings { events: Some(sink), ..Default::default() }, CancellationToken::new()).await.unwrap();
    assert_eq!(r.completion, RunnerCompletion::Aborted);
    assert!(r.partial);
    assert_eq!(r.totals.iterations_started, 1);
    assert!(r.notes.iter().any(|n| n.contains("not saved")), "{:?}", r.notes);
    assert_eq!(*f.state.counters.lock().get("second").unwrap_or(&0), 0, "nothing is sent after the lock");
}

/// As the desktop runs it: on a multi-thread runtime, where each step's
/// history record waits on the store through `block_in_place`, and the
/// steps are prepared and the report saved on a blocking thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_on_a_multi_thread_runtime_records_every_step_and_its_report() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "multi");
    let ws = app.create_workspace("Multi").unwrap();
    app.create_request(&ws.meta.id, None, "First", RequestSpec::http("GET", &f.url("/count/multi-first"))).unwrap();
    app.create_request(&ws.meta.id, None, "Second", RequestSpec::http("GET", &f.url("/count/multi-second"))).unwrap();
    let r = app.run_folder(&ws.meta.id, None, RunSettings::default(), CancellationToken::new()).await.unwrap();
    assert_eq!(r.completion, RunnerCompletion::Completed, "{r:#?}");
    assert_eq!(app.store.list_history(Some(&ws.meta.id), None, 10).unwrap().len(), 2);
    assert_eq!(app.run_report(&r.run_id).unwrap(), r);
}

/// The desktop shell spawns runs on the async runtime: the run futures must be `Send`.
#[allow(dead_code)]
fn run_futures_are_send(app: &App, id: &anvil_domain::Id) {
    fn is_send<T: Send>(_: T) {}
    is_send(app.run_scenario(id, RunSettings::default(), CancellationToken::new()));
    is_send(app.run_folder(id, None, RunSettings::default(), CancellationToken::new()));
}
