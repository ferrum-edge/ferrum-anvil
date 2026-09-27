//! A workspace delete stops that workspace's load runs, and a lock stops
//! every load run, so no run's engines keep a deleted workspace's pooled
//! connections, sessions or secrets until the run ends.

use anvil_app::load::LoadRunGuard;
use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::load::{LoadPlan, LoadReport, RunCompletion, Workload};
use anvil_domain::request::RequestSpec;
use anvil_fixtures::http::Fixture;
use anvil_storage::KdfParams;
use std::time::Duration;

fn new_app(root: &std::path::Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("load", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

/// A plan that keeps sending until it is stopped.
fn endless(ws: Id, req: Id) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: ws,
        name: "endless".into(),
        workload: Workload::Iterations { iterations: 100_000_000, concurrency: 2 },
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

/// Run `p` in-process, driven by `guard` as the desktop drives its worker (a
/// workspace delete cancels it, a lock stops it for the lock), while `stop`
/// runs once it sends. Returns its report once it has ended.
async fn run_until_stopped(app: &App, fx: &Fixture, p: &LoadPlan, guard: &LoadRunGuard, stop: impl FnOnce()) -> LoadReport {
    let job = app.load_job(p).unwrap();
    let opts = anvil_load::RunOptions { acknowledged: true, ..Default::default() };
    let run = anvil_load::LoadRun::prepare(p.clone(), job, opts).unwrap();
    let (deleted, locked) = (guard.workspace_deleted().clone(), guard.locked().clone());
    let stopping = async {
        while fx.log.count_requests() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        stop();
    };
    let both = async { tokio::join!(run.execute_lockable(deleted, locked, None), stopping).0 };
    tokio::time::timeout(Duration::from_secs(60), both).await.expect("the run sends, then stops")
}

/// Once a stopped run's report is in, nothing more reaches the destination.
async fn assert_quiet(fx: &Fixture) {
    let sent = fx.log.count_requests();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fx.log.count_requests(), sent, "the stopped run still sends");
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_workspace_stops_its_running_load_run() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let a = app.create_workspace("A").unwrap().meta.id;
    let b = app.create_workspace("B").unwrap().meta.id;
    let req = app.create_request(&a, None, "slow", RequestSpec::http("GET", &fx.url("/delay-headers/20"))).unwrap();
    let p = app.save_load_plan(endless(a, req.meta.id)).unwrap();
    let other = app.register_load_run(&b);

    let guard = app.register_load_run(&a);
    assert!(!guard.is_stopped());
    let report = run_until_stopped(&app, &fx, &p, &guard, || app.delete_workspace(&a).unwrap()).await;
    assert!(guard.workspace_deleted().is_cancelled(), "the delete reaches the run");
    assert!(!guard.locked().is_cancelled());
    assert_eq!(report.completion, RunCompletion::CanceledByUser);
    assert!(report.counts.started > 0);
    assert_quiet(&fx).await;
    // Nothing of the deleted workspace is kept, its report included.
    let Err(AppError::NotFound(_)) = app.save_load_report(&report) else { panic!("a report of a deleted workspace was saved") };
    assert!(app.load_reports(&a).unwrap().is_empty());

    // Another workspace's run goes on.
    assert!(!other.is_stopped(), "a run of another workspace was stopped");
    // A run registered after the delete is stopped already: its job is never
    // handed to a worker.
    assert!(app.register_load_run(&a).workspace_deleted().is_cancelled());
}

#[tokio::test(flavor = "multi_thread")]
async fn locking_stops_every_load_run() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let a = app.create_workspace("A").unwrap().meta.id;
    let b = app.create_workspace("B").unwrap().meta.id;
    let req = app.create_request(&a, None, "slow", RequestSpec::http("GET", &fx.url("/delay-headers/20"))).unwrap();
    let p = app.save_load_plan(endless(a, req.meta.id)).unwrap();
    let other = app.register_load_run(&b);
    let guard = app.register_load_run(&a);
    let report = run_until_stopped(&app, &fx, &p, &guard, || app.lock()).await;
    assert!(guard.locked().is_cancelled() && other.locked().is_cancelled(), "the lock reaches every run");
    assert_eq!(report.completion, RunCompletion::StoppedByLock);
    assert_quiet(&fx).await;
    // A run registered once the profile is locked is stopped already.
    assert!(app.register_load_run(&a).locked().is_cancelled());
}

#[test]
fn a_finished_run_is_no_longer_reached() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let a = app.create_workspace("A").unwrap().meta.id;
    let finished = app.register_load_run(&a);
    let token = finished.workspace_deleted().clone();
    drop(finished);
    app.delete_workspace(&a).unwrap();
    assert!(!token.is_cancelled(), "a dropped registration is gone");
}
