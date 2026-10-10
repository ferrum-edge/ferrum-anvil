use anvil_app::{App, exec::SendOptions, profiles::ProfileManager};
use anvil_domain::{
    Id,
    auth::AuthConfig,
    request::RequestSpec,
    secret::SensitiveValue,
    settings::ProxySelection,
    tls::{ProxyProfile, TlsProfile},
    workspace::{Environment, Meta, Variable},
};
use anvil_engine::{Engine, ExecutionContext};
use anvil_storage::{KdfParams, kind, store::DB_FILE, vault};
use anvil_transport::recorder::EventCtx;
use serde_json::json;
use tokio_util::sync::CancellationToken;

fn app() -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let (s, k, _) = ProfileManager::new(root.path()).create_passphrase("test", "correct horse battery", KdfParams::testing()).unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    let a = App::open(s.dir, h, k).unwrap();
    (root, a)
}
fn context(app: &App, ws: &Id, spec: RequestSpec) -> ExecutionContext {
    app.build_context(None, ws, Some(spec), &SendOptions::default()).unwrap()
}
fn tls(app: &App, ws: Id) -> TlsProfile {
    app.save_tls_profile(
        serde_json::from_value(
            json!({"id":Id::new(),"workspace_id":ws,"name":"trust","created_at":chrono::Utc::now(),"updated_at":chrono::Utc::now()}),
        )
        .unwrap(),
    )
    .unwrap()
}
fn proxy(app: &App, ws: Id, tls: Option<Id>) -> ProxyProfile {
    app.save_proxy_profile(serde_json::from_value(json!({"id":Id::new(),"workspace_id":ws,"name":"proxy","kind":"http","address":"http://127.0.0.1:9","no_proxy":"","tls_profile_id":tls,"created_at":chrono::Utc::now(),"updated_at":chrono::Utc::now()})).unwrap()).unwrap()
}
fn valid(ctx: &ExecutionContext) {
    ctx.secrets.validate_context().unwrap();
}
fn stale(ctx: &ExecutionContext, app: &App) {
    let error = ctx.secrets.validate_context().unwrap_err();
    assert!(error.contains("configuration changed"), "{error}");
    assert!(!error.contains("secret-canary"));
    assert!(!app.is_locked());
}
#[test]
fn unrelated_request_revision_workspace_profiles_and_credentials_preserve_context() {
    let (_root, app) = app();
    let ws = app.create_workspace("selected").unwrap();
    let req = app.create_request(&ws.meta.id, None, "selected", RequestSpec::http("GET", "https://example.invalid/")).unwrap();
    let ctx = app.build_context(Some(req.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
    let mut other = app.create_request(&ws.meta.id, None, "other", req.spec.clone()).unwrap();
    other.spec = RequestSpec::http("POST", "https://example.invalid/changed");
    app.save_request(other).unwrap();
    valid(&ctx);
    let foreign = app.create_workspace("foreign").unwrap();
    app.set_secret(&foreign.meta.id, "foreign", "secret-canary").unwrap();
    valid(&ctx);
    app.create_environment(&ws.meta.id, "unused", vec![Variable::plain("unused", "value")]).unwrap();
    let unused_tls = tls(&app, ws.meta.id);
    proxy(&app, ws.meta.id, Some(unused_tls.id));
    app.set_secret(&ws.meta.id, "unused", "secret-canary").unwrap();
    valid(&ctx);
    app.store.put_load_report(&Id::new(), Some(&ws.meta.id), 0, &json!({"plan":{"workspace_id":ws.meta.id}})).unwrap();
    app.store.put_blob(b"unrelated").unwrap();
    valid(&ctx);
    app.save_request(req).unwrap();
    stale(&ctx, &app);
}
#[test]
fn selected_profiles_and_proxy_tls_stale_while_unused_profiles_do_not() {
    for select_proxy in [false, true] {
        let (_root, app) = app();
        let ws = app.create_workspace("workspace").unwrap();
        let selected_tls = tls(&app, ws.meta.id);
        let selected_proxy = proxy(&app, ws.meta.id, Some(selected_tls.id));
        let mut spec = RequestSpec::http("GET", "https://example.invalid/");
        if select_proxy {
            spec.settings.proxy_profile_id = Some(ProxySelection::Profile { id: selected_proxy.id });
        } else {
            spec.settings.tls_profile_id = Some(selected_tls.id);
        }
        let ctx = context(&app, &ws.meta.id, spec);
        tls(&app, ws.meta.id);
        proxy(&app, ws.meta.id, None);
        valid(&ctx);
        app.save_tls_profile(selected_tls).unwrap();
        stale(&ctx, &app);
    }
}
#[test]
fn negative_default_environment_and_selected_missing_tls_are_captured() {
    for environment in [true, false] {
        let (_root, app) = app();
        let mut ws = app.create_workspace("workspace").unwrap();
        let missing = Id::new();
        let mut spec = RequestSpec::http("GET", "https://example.invalid/");
        if environment {
            ws.active_environment_id = Some(missing);
            app.save_workspace(ws.clone()).unwrap();
        } else {
            spec.settings.tls_profile_id = Some(missing);
        }
        let ctx = context(&app, &ws.meta.id, spec);
        valid(&ctx);
        if environment {
            let env = Environment {
                meta: Meta { id: missing, ..Meta::new() },
                workspace_id: ws.meta.id,
                name: "appeared".into(),
                variables: vec![],
            };
            app.save_environment(env).unwrap();
        } else {
            let profile: TlsProfile = serde_json::from_value(json!({"id":missing,"workspace_id":ws.meta.id,"name":"appeared","created_at":chrono::Utc::now(),"updated_at":chrono::Utc::now()})).unwrap();
            app.save_tls_profile(profile).unwrap();
        }
        stale(&ctx, &app);
    }
}
#[test]
fn cached_and_deferred_aliases_do_not_resolve_changed_or_uncaptured_credentials() {
    for deferred in [false, true] {
        let (_root, app) = app();
        let ws = app.create_workspace("workspace").unwrap();
        let secret = app.set_secret(&ws.meta.id, "used", "secret-canary").unwrap();
        let other = app.set_secret(&ws.meta.id, "unused", "other-canary").unwrap();
        let mut spec = RequestSpec::http("GET", "https://example.invalid/");
        spec.auth = if deferred {
            serde_json::from_value(
                json!({"type":"oauth2","config":{"grant":"client_credentials","client_id":"test","token_url":"{{issuer}}","client_secret":{"kind":"secret","secret":secret}}}),
            )
            .unwrap()
        } else {
            AuthConfig::Bearer { token: SensitiveValue::Secret { secret: secret.clone() }, prefix: "Bearer".into() }
        };
        let ctx = context(&app, &ws.meta.id, spec);
        assert!(ctx.secrets.resolve(&other).is_err());
        if !deferred {
            assert_eq!(ctx.secrets.resolve(&secret).unwrap().as_str(), "secret-canary");
        }
        app.store.put_secret(&other.id, Some(&ws.meta.id), "unused", "changed other").unwrap();
        valid(&ctx);
        app.store.put_secret(&secret.id, Some(&ws.meta.id), "used", "replacement").unwrap();
        stale(&ctx, &app);
        assert!(ctx.secrets.resolve(&secret).is_err());
    }
}
#[test]
fn deny_presence_and_confinement_configuration_are_dependencies() {
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let spec = RequestSpec::http("GET", "https://example.invalid/");
    let ctx = context(&app, &ws.meta.id, spec.clone());
    app.store
        .put(
            kind::DEVICE_IDENTITY_SEAL,
            &ws.meta.id,
            Some(&ws.meta.id),
            None,
            0.0,
            &anvil_app::device_identity::DeviceIdentitySeal { workspace_id: ws.meta.id, sealed_at: chrono::Utc::now() },
        )
        .unwrap();
    stale(&ctx, &app);
    let sealed = context(&app, &ws.meta.id, spec.clone());
    app.allow_device_identity(&ws.meta.id).unwrap();
    stale(&sealed, &app);
    let unconfined = context(&app, &ws.meta.id, spec);
    app.confine_token_files();
    stale(&unconfined, &app);
}
#[test]
fn ancestor_and_app_settings_are_relevant_but_sibling_folders_are_not() {
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let parent = app.create_folder(&ws.meta.id, None, "parent").unwrap();
    let req = app.create_request(&ws.meta.id, Some(parent.meta.id), "child", RequestSpec::http("GET", "https://example.invalid/")).unwrap();
    let build = || app.build_context(Some(req.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
    let ctx = build();
    let sibling = app.create_folder(&ws.meta.id, None, "sibling").unwrap();
    app.save_folder(sibling).unwrap();
    valid(&ctx);
    app.save_folder(parent).unwrap();
    stale(&ctx, &app);
    let ctx = build();
    app.save_settings(&app.settings().unwrap()).unwrap();
    stale(&ctx, &app);
}
#[test]
fn unrelated_raw_replay_locks_even_a_no_auth_context_and_its_clone() {
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let unused = app.set_secret(&ws.meta.id, "unused", "secret-canary").unwrap();
    let ctx = context(&app, &ws.meta.id, RequestSpec::http("GET", "https://example.invalid/"));
    let cloned = ctx.clone();
    let raw = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    raw.execute("DELETE FROM secrets WHERE id=?1", [unused.id.to_string()]).unwrap();
    let error = cloned.secrets.validate_context().unwrap_err();
    assert!(!error.contains("secret-canary"));
    assert!(app.is_locked());
}

struct Echo {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Echo {
    async fn start() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 8192];
                let _ = stream.read(&mut buffer).await.unwrap();
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
            }
        });
        Self { url, task }
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_save_and_automatic_collection_report_preserve_real_http_effects() {
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let echo = Echo::start().await;
    let req = app.create_request(&ws.meta.id, None, "send", RequestSpec::http("GET", &echo.url)).unwrap();
    let ctx = app.build_context(Some(req.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
    app.create_request(&ws.meta.id, None, "other", req.spec.clone()).unwrap();
    let output = Engine::new().execute(&ctx, EventCtx::none(), CancellationToken::new()).await;
    assert_eq!(output.record.response.unwrap().status, 200);
    let settings = anvil_app::runner::RunSettings { record_history: true, persist_report: true, ..Default::default() };
    let report = app.run_folder(&ws.meta.id, None, settings, CancellationToken::new()).await.unwrap();
    assert!(
        report
            .iterations
            .iter()
            .flat_map(|iteration| iteration.steps.iter())
            .all(|step| step.status == anvil_domain::runner::RunStepStatus::Passed)
    );
    let output = Engine::new().execute(&ctx, EventCtx::none(), CancellationToken::new()).await;
    assert_eq!(output.record.response.unwrap().status, 200);
    let mut changed = req;
    changed.name = "changed".into();
    app.save_request(changed).unwrap();
    let output = Engine::new().execute(&ctx, EventCtx::none(), CancellationToken::new()).await;
    assert!(output.record.response.is_none());
    assert!(output.record.attempts.last().unwrap().failure.as_ref().unwrap().message.contains("configuration changed"));
}

#[test]
fn gateway_candidate_order_and_dynamic_diagnostic_aliases_are_dependencies() {
    use anvil_domain::integration::{DiagnosticDetailAccess, IntegrationKind, IntegrationProfile};
    use anvil_domain::tls::HostBinding;
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let credential = app.set_secret(&ws.meta.id, "diagnostics", "secret-canary").unwrap();
    let gateway = app
        .save_integration(IntegrationProfile {
            id: Id::new(),
            workspace_id: ws.meta.id,
            name: "dynamic gateway".into(),
            kind: IntegrationKind::FerrumGateway {
                hosts: vec![HostBinding { host: "gateway.test".into(), port: None }],
                compatibility_id: "ferrum-edge-0.9.15".into(),
                require_verified_tls: true,
                detail: Some(DiagnosticDetailAccess {
                    base_url: "https://admin.test".into(),
                    credential: SensitiveValue::Secret { secret: credential.clone() },
                    namespace: None,
                }),
                console_url: None,
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
    // No explicit integration id: engine selects by the eventual expanded host.
    let ctx = context(&app, &ws.meta.id, RequestSpec::http("GET", "https://{{host}}/"));
    assert_eq!(ctx.secrets.resolve(&credential).unwrap().as_str(), "secret-canary");
    app.store.put_secret(&credential.id, Some(&ws.meta.id), "diagnostics", "replacement").unwrap();
    stale(&ctx, &app);
    let ctx = context(&app, &ws.meta.id, RequestSpec::http("GET", "https://{{host}}/"));
    let mut shadow = gateway;
    shadow.id = Id::new();
    shadow.name = "shadow candidate".into();
    app.save_integration(shadow).unwrap();
    stale(&ctx, &app);
}
#[test]
fn linked_permission_query_is_referrer_scoped_and_cached_file_reads_refuse_revocation() {
    use anvil_app::linked_files::{LinkedFileBinding, LinkedFileReferrer};
    use anvil_domain::request::{AttachmentRef, Body};
    let (root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let path = root.path().join("chosen");
    std::fs::write(&path, b"file-canary").unwrap();
    let path = path.canonicalize().unwrap();
    let attachment = AttachmentRef::LinkedFile { path: path.display().to_string() };
    let mut spec = RequestSpec::http("POST", "https://example.invalid/");
    spec.body = Body::Binary { attachment: attachment.clone(), content_type: None };
    // Native-authorized save path. Ordinary App request creation permits linked
    // references; only dispatch requires the local grant.
    let req = app.create_request(&ws.meta.id, None, "linked", spec).unwrap();
    let binding = app.bind_linked_file(LinkedFileReferrer::Request { id: req.meta.id }, &path).unwrap();
    let ctx = app.build_context(Some(req.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
    assert_eq!(ctx.attachments.load(&attachment).unwrap().as_ref(), b"file-canary");
    let other = LinkedFileBinding {
        id: Id::new(),
        referrer: LinkedFileReferrer::Request { id: Id::new() },
        path: path.display().to_string(),
        bound_at: chrono::Utc::now(),
    };
    app.store.put(kind::LINKED_FILE, &other.id, None, None, 0.0, &other).unwrap();
    valid(&ctx);
    app.store.delete(kind::LINKED_FILE, &binding.id).unwrap();
    stale(&ctx, &app);
    assert!(ctx.attachments.load(&attachment).is_err());
}
#[test]
fn token_permission_query_depends_on_the_selected_trimmed_path() {
    let (root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    app.confine_token_files();
    let selected = root.path().join("selected-token");
    let other = root.path().join("other-token");
    std::fs::write(&selected, b"not a credential").unwrap();
    std::fs::write(&other, b"not a credential").unwrap();
    let binding = app.bind_token_file(&selected).unwrap();
    let mut spec = RequestSpec::http("GET", "https://example.invalid/");
    spec.auth = serde_json::from_value(
        json!({"type":"jwt_svid","config":{"source":{"kind":"file","path":format!(" {} ", selected.display())},"audiences":["api"]}}),
    )
    .unwrap();
    let ctx = context(&app, &ws.meta.id, spec);
    app.bind_token_file(&other).unwrap();
    valid(&ctx);
    app.remove_token_file_binding(&binding.id).unwrap();
    stale(&ctx, &app);
}
#[test]
fn worker_admission_keeps_plan_dataset_and_request_dependencies_without_global_root_invalidation() {
    use anvil_domain::load::{LoadPlan, Workload};
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let request = app.create_request(&ws.meta.id, None, "load", RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap();
    let plan = app
        .save_load_plan(LoadPlan {
            id: Id::new(),
            workspace_id: ws.meta.id,
            name: "load".into(),
            workload: Workload::Iterations { iterations: 1, concurrency: 1 },
            chain: vec![request.meta.id],
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
        })
        .unwrap();
    let (worker, authority) = app.worker_job_with_authority(&plan, true).unwrap();
    app.create_request(&ws.meta.id, None, "other", request.spec.clone()).unwrap();
    authority.check().unwrap();
    app.save_load_plan(plan).unwrap();
    assert!(authority.check().is_err());
    // An already admitted detached worker still has the acknowledged snapshot.
    assert!(worker.into_load_job().is_ok());
    let current = app.load_plans(&ws.meta.id).unwrap().remove(0);
    let (_, authority) = app.worker_job_with_authority(&current, true).unwrap();
    app.save_request(request).unwrap();
    assert!(authority.check().is_err());
    // Saved-plan producers retain the original observation through preparation.
    // A new proof of the present row must not bless an older selected workload.
    for delete in [false, true] {
        let current = app.save_load_plan(current.clone()).unwrap();
        let (observed, observation) = app.load_plan_with_authority(&current.id).unwrap();
        app.load_preflight(&observed).unwrap();
        if delete {
            app.delete_load_plan(&current.id).unwrap();
        } else {
            let mut changed = current.clone();
            changed.workload = Workload::Iterations { iterations: 2, concurrency: 1 };
            app.save_load_plan(changed).unwrap();
        }
        let (_, present) = app.worker_job_with_authority(&observed, true).unwrap();
        present.check().unwrap();
        assert!(observation.check().unwrap_err().to_string().contains("configuration changed"));
    }
}

#[test]
fn stored_attachment_index_and_load_dataset_remain_live_dependencies() {
    use anvil_domain::load::{LoadPlan, Workload};
    use anvil_domain::request::{AttachmentRef, Body};
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let attachment = app.put_attachment("chosen", b"attachment-canary", None).unwrap();
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9/");
    spec.body = Body::Binary { attachment: attachment.clone(), content_type: None };
    let req = app.create_request(&ws.meta.id, None, "attached", spec).unwrap();
    let ctx = app.build_context(Some(req.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
    app.put_attachment("unused", b"unused", None).unwrap();
    valid(&ctx);
    assert_eq!(ctx.attachments.load(&attachment).unwrap().as_ref(), b"attachment-canary");
    let sha = match &attachment {
        AttachmentRef::Stored { sha256, .. } => sha256,
        _ => unreachable!(),
    };
    let index_id = app
        .store
        .object_meta(kind::IMPORT_SOURCE)
        .unwrap()
        .into_iter()
        .find_map(|row| {
            let id: Id = row.id.parse().unwrap();
            let index: serde_json::Value = app.store.get(kind::IMPORT_SOURCE, &id).unwrap().unwrap();
            (index["attachment"].as_str() == Some(sha.as_str())).then_some(id)
        })
        .unwrap();
    app.store.delete(kind::IMPORT_SOURCE, &index_id).unwrap();
    stale(&ctx, &app);
    assert!(ctx.attachments.load(&attachment).is_err());
    let dataset = app.create_dataset(&ws.meta.id, "rows", anvil_domain::workspace::DatasetFormat::Csv, b"row\none\n", vec![]).unwrap();
    let request = app.create_request(&ws.meta.id, None, "load", RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap();
    let plan = app
        .save_load_plan(LoadPlan {
            id: Id::new(),
            workspace_id: ws.meta.id,
            name: "load".into(),
            workload: Workload::Iterations { iterations: 1, concurrency: 1 },
            chain: vec![request.meta.id],
            mix: vec![],
            dataset_id: Some(dataset.meta.id),
            environment_id: None,
            connection_mode: Default::default(),
            warmup_secs: 0,
            abort: None,
            seed: 1,
            trusted: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
    let job = app.load_job(&plan).unwrap();
    let (_, proof) = app.worker_job_with_authority(&plan, true).unwrap();
    app.create_dataset(&ws.meta.id, "unused rows", anvil_domain::workspace::DatasetFormat::Csv, b"other\ntwo\n", vec![]).unwrap();
    proof.check().unwrap();
    app.save_dataset(dataset).unwrap();
    assert!(proof.check().is_err());
    stale(job.requests.get(&request.meta.id).unwrap(), &app);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_source_changes_refuse_later_steps_and_unrelated_writes_do_not() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for relevant in [false, true] {
        let (_root, app) = app();
        let app = Arc::new(app);
        let ws = app.create_workspace("workspace").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let one = app.create_request(&ws.meta.id, None, "one", RequestSpec::http("GET", &url)).unwrap();
        let two = app.create_request(&ws.meta.id, None, "two", one.spec.clone()).unwrap();
        let scenario = app
            .create_scenario(
                &ws.meta.id,
                "scenario",
                vec![
                    anvil_domain::workspace::ScenarioStep { request_id: one.meta.id, enabled: true, delay_ms: 0 },
                    anvil_domain::workspace::ScenarioStep { request_id: two.meta.id, enabled: true, delay_ms: 0 },
                ],
            )
            .unwrap();
        let changing = app.clone();
        let scenario_change = scenario.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 8192];
                stream.read(&mut buffer).await.unwrap();
                if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                    if relevant {
                        changing.update_scenario(scenario_change.clone()).unwrap();
                    } else {
                        changing.create_workspace("unrelated autosave during run").unwrap();
                    }
                }
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
            }
        });
        let report = app.run_scenario(&scenario.meta.id, Default::default(), CancellationToken::new()).await.unwrap();
        server.abort();
        let steps = &report.iterations[0].steps;
        assert_eq!(steps[0].status, anvil_domain::runner::RunStepStatus::Passed);
        if relevant {
            assert_ne!(steps[1].status, anvil_domain::runner::RunStepStatus::Passed);
            let failed: anvil_domain::execution::ExecutionRecord = app
                .store
                .get_history::<anvil_domain::execution::ExecutionRecord>(&steps[1].execution_id.unwrap().to_string())
                .unwrap()
                .unwrap()
                .0;
            assert!(failed.attempts.last().unwrap().failure.as_ref().unwrap().message.contains("configuration changed"));
            assert_eq!(count.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(steps[1].status, anvil_domain::runner::RunStepStatus::Passed);
            assert_eq!(count.load(Ordering::SeqCst), 2);
        }
        assert!(!app.is_locked());
    }
}
