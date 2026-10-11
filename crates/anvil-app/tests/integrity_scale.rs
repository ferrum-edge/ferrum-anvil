//! Timed scale harness for the protected-record catalogue: how open/unlock,
//! reads, writes, secret resolution and a collection run cost on a large
//! profile. Ignored by default; run it in release mode and read the printed
//! table:
//!
//! ```text
//! cargo test --release -p anvil-app --test integrity_scale -- --ignored --nocapture
//! ```
//!
//! `ANVIL_SCALE_REQUESTS`, `ANVIL_SCALE_VERSIONS`, `ANVIL_SCALE_SECRETS` and
//! `ANVIL_SCALE_RUN_STEPS` resize the profile (defaults: 5000 requests with
//! 10 saved versions each, 200 vault secrets, a 100-step run).

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::runner::RunSettings;
use anvil_domain::Id;
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{Meta, RequestDefinition, RequestRevision, ScenarioStep, Variable};
use anvil_storage::{KdfParams, kind};
use anvil_transport::recorder::EventCtx;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const WORKSPACES: usize = 5;
const ENVIRONMENTS_PER_WORKSPACE: usize = 4;
const FOLDERS_PER_WORKSPACE: usize = 10;
const SECRETS_PER_REQUEST: usize = 10;
const BATCH: usize = 250;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn vault(name: &str, secret: &anvil_domain::secret::SecretRef) -> Variable {
    Variable {
        name: name.into(),
        value: SensitiveValue::Secret { secret: secret.clone() },
        secret: true,
        enabled: true,
        description: String::new(),
    }
}

/// Run `f` `n` times; returns the median duration.
fn median(n: usize, mut f: impl FnMut()) -> Duration {
    let mut samples: Vec<Duration> = (0..n)
        .map(|_| {
            let start = Instant::now();
            f();
            start.elapsed()
        })
        .collect();
    samples.sort();
    samples[samples.len() / 2]
}

fn row(name: &str, d: Duration) {
    println!("| {name:<44} | {:>12.3} ms |", d.as_secs_f64() * 1000.0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "timed scale harness; run manually in release mode with --ignored --nocapture"]
async fn protected_catalogue_cost_scales_with_touched_records() {
    anvil_fixtures::init();
    let requests = env_usize("ANVIL_SCALE_REQUESTS", 5000);
    let versions = env_usize("ANVIL_SCALE_VERSIONS", 10).max(1);
    let secrets = env_usize("ANVIL_SCALE_SECRETS", 200).max(SECRETS_PER_REQUEST * WORKSPACES);
    let run_steps = env_usize("ANVIL_SCALE_RUN_STEPS", 100);

    let server = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (summary, dek, _recovery) = pm.create_passphrase("scale", "correct horse battery", KdfParams::testing()).unwrap();
    let header = anvil_storage::vault::read_header(&summary.dir).unwrap();
    let key_bytes = dek.as_bytes().to_vec();
    let app = App::open(summary.dir.clone(), header.clone(), dek).unwrap();

    // ---------------------------------------------------------- build
    let build = Instant::now();
    let mut hot = None;
    for w in 0..WORKSPACES {
        let mut ws = app.create_workspace(&format!("Workspace {w}")).unwrap();
        let mut refs = Vec::new();
        for s in 0..secrets / WORKSPACES {
            refs.push(app.set_secret(&ws.meta.id, &format!("secret {s}"), &format!("value-{w}-{s}")).unwrap());
        }
        let mut active = None;
        for e in 0..ENVIRONMENTS_PER_WORKSPACE {
            let vars = (0..SECRETS_PER_REQUEST).map(|i| vault(&format!("s{i}"), &refs[(e + i) % refs.len()])).collect();
            let env = app.create_environment(&ws.meta.id, &format!("env {e}"), vars).unwrap();
            active.get_or_insert(env.meta.id);
        }
        ws.active_environment_id = active;
        let ws = app.save_workspace(ws).unwrap();
        let folders: Vec<Id> =
            (0..FOLDERS_PER_WORKSPACE).map(|f| app.create_folder(&ws.meta.id, None, &format!("folder {f}")).unwrap().meta.id).collect();
        let per_ws = requests / WORKSPACES;
        let mut ids = Vec::with_capacity(per_ws);
        for chunk in (0..per_ws).collect::<Vec<_>>().chunks(BATCH) {
            app.store
                .atomically(|tx| {
                    for &i in chunk {
                        let mut spec = RequestSpec::http("GET", &server.url("/echo"));
                        for s in 0..SECRETS_PER_REQUEST {
                            spec.headers.push(KeyValue::new(format!("X-S{s}"), format!("{{{{s{s}}}}}")));
                        }
                        let mut r = RequestDefinition {
                            meta: Meta::new(),
                            workspace_id: ws.meta.id,
                            folder_id: Some(folders[i % folders.len()]),
                            name: format!("request {i}"),
                            description: String::new(),
                            tags: vec![],
                            favorite: false,
                            sort_key: i as f64,
                            spec: spec.clone(),
                            revision_id: None,
                        };
                        tx.put(kind::REQUEST, &r.meta.id, Some(&ws.meta.id), r.folder_id.as_ref(), r.sort_key, &r)?;
                        for v in 0..versions {
                            let mut spec = spec.clone();
                            spec.headers.push(KeyValue::new("X-Version", v.to_string()));
                            let rev = RequestRevision {
                                id: Id::new(),
                                request_id: r.meta.id,
                                created_at: chrono::Utc::now(),
                                spec_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&spec).unwrap())),
                                spec,
                            };
                            tx.put(kind::REVISION, &rev.id, Some(&ws.meta.id), Some(&r.meta.id), 0.0, &rev)?;
                            r.revision_id = Some(rev.id);
                        }
                        tx.put(kind::REQUEST, &r.meta.id, Some(&ws.meta.id), r.folder_id.as_ref(), r.sort_key, &r)?;
                        ids.push(r.meta.id);
                    }
                    Ok(())
                })
                .unwrap();
        }
        if hot.is_none() {
            hot = Some((ws.meta.id, ids));
        }
    }
    let (hot_ws, hot_requests) = hot.unwrap();
    let records = requests * (versions + 1) + secrets + WORKSPACES * (1 + ENVIRONMENTS_PER_WORKSPACE + FOLDERS_PER_WORKSPACE);
    println!("\nprofile: {requests} requests x {versions} versions, {secrets} secrets, ~{records} protected records");
    println!("built in {:.1} s\n", build.elapsed().as_secs_f64());
    println!("| operation                                    |       median |");
    println!("|----------------------------------------------|--------------|");

    // ---------------------------------------------------------- open/unlock
    drop(app);
    let open = median(3, || {
        let key = anvil_storage::Key::from_bytes(&key_bytes).unwrap();
        drop(App::open(summary.dir.clone(), header.clone(), key).unwrap());
    });
    row("open profile (App::open)", open);
    let app = App::open(summary.dir.clone(), header.clone(), anvil_storage::Key::from_bytes(&key_bytes).unwrap()).unwrap();
    let unlock = median(3, || {
        app.store.lock();
        app.store.unlock(anvil_storage::Key::from_bytes(&key_bytes).unwrap()).unwrap();
    });
    row("lock + unlock (Store::unlock)", unlock);

    // ---------------------------------------------------------- read/write
    let target = hot_requests[hot_requests.len() / 2];
    let _ = app.request(&target).unwrap();
    row("single read (App::request)", median(20, || drop(app.request(&target).unwrap())));
    let mut n = 0;
    row(
        "single write (save_request + new version)",
        median(10, || {
            let mut r = app.request(&target).unwrap();
            n += 1;
            r.spec.headers.push(KeyValue::new("X-Edit", n.to_string()));
            app.save_request(r).unwrap();
        }),
    );

    // ---------------------------------------------------------- resolve
    let runtime = tokio::runtime::Handle::current();
    let send_one = |id: Id| {
        let out = tokio::task::block_in_place(|| {
            runtime.block_on(app.send(
                Some(id),
                &hot_ws,
                None,
                SendOptions { record_history: false, ..Default::default() },
                EventCtx::none(),
                CancellationToken::new(),
            ))
        })
        .unwrap();
        assert!(out.record.response.is_some(), "the request reached the fixture");
    };
    send_one(target);
    row("send request resolving 10 vault secrets", median(10, || send_one(target)));

    // Another connection's commit makes the next check re-read the
    // catalogue and compare every protected row once.
    let other = anvil_storage::Store::open(&summary.dir, anvil_storage::Key::from_bytes(&key_bytes).unwrap()).unwrap();
    row(
        "send after another connection's commit",
        median(3, || {
            other.put_secret(&Id::new(), None, "foreign", "write").unwrap();
            send_one(target);
        }),
    );
    drop(other);

    // ---------------------------------------------------------- run
    let steps =
        (0..run_steps).map(|i| ScenarioStep { request_id: hot_requests[i % hot_requests.len()], enabled: true, delay_ms: 0 }).collect();
    let scenario = app.create_scenario(&hot_ws, "scale run", steps).unwrap();
    let run = median(3, || {
        let report = tokio::task::block_in_place(|| {
            runtime.block_on(app.run_scenario(
                &scenario.meta.id,
                RunSettings { record_history: true, ..Default::default() },
                CancellationToken::new(),
            ))
        })
        .unwrap();
        assert_eq!(report.totals.steps_executed, run_steps as u64);
        assert!(report.passed(), "{:?}", report.totals);
    });
    row(&format!("{run_steps}-step collection run (history on)"), run);
}
