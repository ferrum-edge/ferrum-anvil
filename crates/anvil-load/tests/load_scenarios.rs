#![allow(unsafe_code)] // one libc::kill to simulate a crashed worker
//! Load-engine scenarios against loopback fixtures. Each test is small
//! (≤ a few hundred requests, a few seconds) and the tests run one at a time
//! so timing assertions do not compete for CPU. Fixture ground truth (what
//! the server actually received) is used to verify conditions were reached.

use anvil_domain::Id;
use anvil_domain::assertions::{Assertion, AssertionKind, Extraction, ExtractionSource};
use anvil_domain::auth::{AuthConfig, HmacConfig, KeyLocation, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::load::*;
use anvil_domain::request::{Body, KeyValue, PayloadEncoding, Protocol, RequestSpec, StreamPayload, UdpSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::TlsProfile;
use anvil_engine::context::MemorySecrets;
use anvil_engine::{Engine, ExecutionContext};
use anvil_fixtures::GroundTruth;
use anvil_fixtures::http as fx;
use anvil_load::report::{check_balance, check_protocol_balance, check_request_balance};
use anvil_load::worker::WorkerMessage;
use anvil_load::{Dataset, DatasetFormat, LoadController, LoadJob, LoadRun, RunOptions, WorkerJob};
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Load tests run one at a time (an async mutex is runtime-agnostic and is
/// released on panic unwind, so one failure does not cascade).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    anvil_transport::init();
    anvil_fixtures::init();
    SERIAL.lock().await
}

fn stages(rate_or_vus: u64, secs: u64) -> Vec<Stage> {
    vec![Stage { duration_secs: 0, target: rate_or_vus }, Stage { duration_secs: secs, target: rate_or_vus }]
}

fn plan(workload: Workload, chain: Vec<Id>) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "fixture plan".into(),
        workload,
        chain,
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: ConnectionMode::Persistent,
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn opts() -> RunOptions {
    RunOptions { acknowledged: true, graceful_stop_ms: 3_000, cancel_drain_ms: 1_000, progress_interval_ms: 250, ..Default::default() }
}

fn ctx(spec: RequestSpec) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    c.isolation = "ws-load-test".into();
    c
}

fn get(url: &str) -> ExecutionContext {
    ctx(RequestSpec::http("GET", url))
}

async fn run(plan: LoadPlan, requests: Vec<(Id, ExecutionContext)>, dataset: Option<Dataset>) -> LoadReport {
    let job = LoadJob { requests: requests.into_iter().collect(), dataset };
    let r = LoadRun::prepare(plan, job, opts()).expect("valid plan").execute(CancellationToken::new(), None).await;
    assert_balanced(&r);
    r
}

fn assert_balanced(r: &LoadReport) {
    check_balance(&r.counts).unwrap_or_else(|e| panic!("iteration ledger: {e}: {:?}", r.counts));
    check_request_balance(&r.requests).unwrap_or_else(|e| panic!("send ledger: {e}: {:?}", r.requests));
    check_protocol_balance(r).unwrap_or_else(|e| panic!("protocol denominators: {e}: {:?}", r.protocol_metrics));
}

fn received(f: &fx::Fixture, prefix: &str) -> Vec<Vec<(String, String)>> {
    f.log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::RequestReceived { path, headers, .. } if path.starts_with(prefix) => Some(headers),
            _ => None,
        })
        .collect()
}

fn connections(f: &fx::Fixture) -> usize {
    f.log.entries().iter().filter(|e| matches!(e.event, GroundTruth::ConnectionAccepted { .. })).count()
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_001_open_arrivals_balance_with_drops_and_lag() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let id = Id::new();
    // 20 arrivals/s for 3 s against a 200 ms backend with at most 2 in
    // flight: capacity is ~10/s, so about half the arrivals must be dropped.
    let p = plan(Workload::OpenArrivalRate { stages: stages(20, 3), max_in_flight: 2 }, vec![id]);
    let r = run(p, vec![(id, get(&f.url("/delay-headers/200")))], None).await;
    let c = &r.counts;
    assert_eq!(c.scheduled, 60, "arrivals follow the schedule, independent of response time");
    assert_eq!(c.scheduled, c.started + c.dropped);
    assert!(c.dropped >= 15 && c.started >= 15, "{c:?}");
    assert_eq!((c.canceled, c.in_flight_at_end, c.transport_failures, c.timeouts), (0, 0, 0, 0));
    assert_eq!(c.completed, c.started);
    assert_eq!(
        received(&f, "/delay-headers/").len() as u64,
        r.requests.started,
        "ground truth: every started send reached the fixture, no dropped one did"
    );
    assert!(r.latency_success.p50_us >= 195_000, "dropped arrivals are not hidden as fast successes: {:?}", r.latency_success);
    assert!((r.offered_rate_per_sec.unwrap() - 20.0).abs() < 1.0);
    assert!(r.generator.target_not_achieved);
    assert!(r.generator.p99_schedule_lag_us < 100_000, "start lag measured: {:?}", r.generator);
    assert_eq!(r.timeline.iter().map(|b| b.dropped).sum::<u64>(), c.dropped);
    assert!(r.timeline.iter().all(|b| b.in_flight <= 2));
    assert!(!r.partial && r.completion == RunCompletion::Completed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_002_closed_vus_rate_falls_with_slow_backend() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut rates = vec![];
    for path in ["/delay-headers/0", "/delay-headers/100"] {
        let id = Id::new();
        let p = plan(Workload::ClosedVirtualUsers { stages: stages(2, 2), think_time_ms: 20 }, vec![id]);
        let r = run(p, vec![(id, get(&f.url(path)))], None).await;
        assert!(r.workload_label.contains("slowing responses reduce the offered rate"), "{}", r.workload_label);
        assert_eq!(r.offered_rate_per_sec, None, "a closed workload has no offered rate");
        assert!(!r.generator.target_not_achieved);
        assert_eq!(r.counts.dropped, 0);
        rates.push(r.achieved_rate_per_sec);
    }
    let (fast, slow) = (rates[0], rates[1]);
    assert!(slow < fast * 0.5, "slow backend must lower the closed-workload rate: fast {fast:.1}/s slow {slow:.1}/s");
    assert!((10.0..=20.0).contains(&slow), "2 VUs / (100 ms + 20 ms think) ≈ 16.7/s, got {slow:.1}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_004_timeouts_are_censored_and_counted_separately() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let timeout =
        SettingsOverrides { timeouts: Some(TimeoutOverrides { total_ms: Some(Some(150)), ..Default::default() }), ..Default::default() };
    let mk = |path: &str| {
        let mut s = RequestSpec::http("GET", &f.url(path));
        s.settings = timeout.clone();
        ctx(s)
    };
    let (fast, slow) = (Id::new(), Id::new());
    let mut p = plan(Workload::Iterations { iterations: 40, concurrency: 8 }, vec![]);
    p.mix = vec![WeightedStep { request_id: fast, weight: 3 }, WeightedStep { request_id: slow, weight: 1 }];
    p.seed = 11;
    let expected_slow = (0..40).filter(|i| anvil_load::executor::pick_weighted(11, &[3, 4], *i) == 1).count() as u64;
    assert!(expected_slow > 0);
    let r = run(p, vec![(fast, mk("/delay-headers/0")), (slow, mk("/delay-headers/2000"))], None).await;
    assert_eq!(r.counts.timeouts, expected_slow);
    assert_eq!(r.requests.timeouts, expected_slow);
    assert_eq!(r.timeouts_censored.count, expected_slow);
    assert_eq!(r.timeouts_censored.deadline_ms_max, Some(150));
    assert!(r.timeouts_censored.elapsed_at_timeout.min_us >= 140_000, "{:?}", r.timeouts_censored);
    assert!(r.timeouts_censored.label.contains("lower bound"));
    assert_eq!(r.latency_failure.count, 0, "timeouts are not failure latencies");
    assert_eq!(r.latency_success.count, 40 - expected_slow);
    assert!(r.latency_success.max_us < 150_000, "censored values never enter the success distribution");
    let cat = r.failure_categories.iter().find(|c| c.category.starts_with("timeout")).expect("timeout category");
    assert_eq!(cat.count, expected_slow);
    assert!(r.notes.iter().any(|n| n.contains("timed out")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_005_fresh_hmac_nonce_and_valid_signature_per_send() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let body = r#"{"order":42}"#;
    let mut s = RequestSpec::http("POST", &f.url("/echo"));
    s.body = Body::Json { text: body.into() };
    s.auth = AuthConfig::Hmac {
        config: HmacConfig {
            profile: Default::default(),
            username: "load-user".into(),
            secret: SensitiveValue::template("fixture-hmac-secret"),
            algorithm: Default::default(),
            digest_header: Default::default(),
            namespace: String::new(),
            allow_unsafe_legacy: false,
        },
    };
    let id = Id::new();
    let r = run(plan(Workload::Iterations { iterations: 60, concurrency: 8 }, vec![id]), vec![(id, ctx(s))], None).await;
    assert_eq!(r.status_distribution, vec![(200, 60)]);
    let got = received(&f, "/echo");
    assert_eq!(got.len(), 60);
    let digest = anvil_auth::digest::header(Default::default(), anvil_auth::digest::DigestAlg::Sha256, body.as_bytes()).1;
    let mut nonces = HashSet::new();
    for h in &got {
        let auth = header(h, "authorization").expect("signed");
        let field = |k: &str| auth.split(&format!("{k}=\"")).nth(1).and_then(|x| x.split('"').next()).unwrap().to_string();
        let (nonce, sig) = (field("nonce"), field("signature"));
        assert_eq!(header(h, "content-digest"), Some(digest.as_str()), "digest covers the final body bytes");
        let ss = anvil_auth::hmac_sig::signing_string(
            Default::default(),
            "ferrum",
            "load-user",
            header(h, "host").unwrap(),
            "POST",
            "/echo",
            "",
            header(h, "date").unwrap(),
            &digest,
            Some(&nonce),
        );
        let want = base64::engine::general_purpose::STANDARD.encode(anvil_auth::hmac_sig::mac(
            Default::default(),
            b"fixture-hmac-secret",
            ss.as_bytes(),
        ));
        assert_eq!(sig, want, "each send carries a valid signature over its own nonce and date");
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 60, "a fresh nonce for every actual send — no replayed prepared signature");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_006_oauth_refresh_is_single_flight_under_load() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    *f.state.oauth_expires_in.lock() = 2;
    let mut s = RequestSpec::http("GET", &f.url("/echo"));
    s.auth = AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::ClientCredentials,
            token_url: f.url("/oauth/token"),
            authorization_url: String::new(),
            client_id: "anvil-client".into(),
            client_secret: SensitiveValue::template("anvil-secret"),
            scope: String::new(),
            audience: String::new(),
            client_auth: OAuthClientAuth::BasicHeader,
            token_cache_id: None,
            refresh_skew_secs: 1,
        },
    };
    let id = Id::new();
    // 40 arrivals/s for 4 s over up to 16 concurrent slots (16 engines); the
    // token is usable for ~1 s, so it expires several times mid-run.
    let p = plan(Workload::OpenArrivalRate { stages: stages(40, 4), max_in_flight: 16 }, vec![id]);
    let r = run(p, vec![(id, ctx(s))], None).await;
    let token_requests = *f.state.oauth_token_requests.lock();
    let sends = received(&f, "/echo");
    assert_eq!(sends.len() as u64, r.requests.started);
    assert!(r.requests.started >= 150);
    assert!(
        sends.iter().all(|h| header(h, "authorization").is_some_and(|a| a.starts_with("Bearer fx-token-"))),
        "no send went out without a token"
    );
    assert!(
        (2..=8).contains(&token_requests),
        "refreshed, but single-flight across slots: {token_requests} token requests for {} sends",
        sends.len()
    );
    assert_eq!(r.requests.completed, r.requests.started);
    assert_eq!(r.latency_setup.count, r.requests.started, "setup (incl. token acquisition) is measured separately from request latency");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_007_generator_saturation_is_reported_not_blamed_on_target() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let id = Id::new();
    let p = plan(Workload::OpenArrivalRate { stages: stages(50, 1), max_in_flight: 1 }, vec![id]);
    let r = run(p, vec![(id, get(&f.url("/delay-headers/100")))], None).await;
    assert!(r.generator.target_not_achieved);
    assert!(r.counts.dropped > 30, "{:?}", r.counts);
    let notes = r.generator.notes.join("\n");
    assert!(notes.contains("does not establish the target's capacity"), "{notes}");
    assert!(notes.contains("dropped"), "{notes}");
    if cfg!(unix) {
        assert!(r.generator.peak_rss_bytes.is_some() && r.generator.peak_open_fds.is_some());
    }
    assert!(anvil_load::html::to_html(&r).contains("Target not achieved"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_008_load_sends_the_same_request_as_manual_send() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let key = SecretRef { id: Id::new(), label: "api key".into() };
    let mut s = RequestSpec::http("POST", &f.url("/echo?x=1"));
    s.headers = vec![KeyValue::new("X-Custom", "a"), KeyValue::new("X-Custom", "b")];
    s.body = Body::Json { text: r#"{"a":1}"#.into() };
    s.auth = AuthConfig::ApiKey {
        name: "x-api-key".into(),
        value: SensitiveValue::Secret { secret: key.clone() },
        location: KeyLocation::Header,
    };
    let mut c = ctx(s);
    c.secrets = Arc::new(MemorySecrets(HashMap::from([(key.id, Zeroizing::new("k-123".to_string()))])));
    let manual = Engine::new().execute(&c, EventCtx::none(), CancellationToken::new()).await;
    assert_eq!(manual.record.response.as_ref().map(|r| r.status), Some(200));
    let manual_headers = received(&f, "/echo").pop().unwrap();
    f.log.clear();
    let id = Id::new();
    let r = run(plan(Workload::Iterations { iterations: 3, concurrency: 1 }, vec![id]), vec![(id, c.clone())], None).await;
    assert_eq!(r.requests.completed, 3);
    for h in received(&f, "/echo") {
        assert_eq!(h, manual_headers, "identical header bytes, order and auth");
    }

    // TLS: an untrusted server fails identically under load (no silent
    // fallback), and the same TLS profile makes both succeed.
    let pki = anvil_fixtures::LabPki::generate();
    let tf = fx::serve("127.0.0.1:0", Some(anvil_fixtures::TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone())))
        .await
        .unwrap();
    let strict = get(&tf.url("/"));
    let manual = Engine::new().execute(&strict, EventCtx::none(), CancellationToken::new()).await;
    assert!(manual.record.response.is_none());
    let id = Id::new();
    let r = run(plan(Workload::Iterations { iterations: 3, concurrency: 1 }, vec![id]), vec![(id, strict.clone())], None).await;
    assert_eq!((r.requests.completed, r.requests.transport_failures), (0, 3));
    let top = manual.record.findings.iter().max_by_key(|f| f.severity).unwrap().code.clone();
    assert!(r.failure_categories[0].category.contains(&top), "{} vs {top}", r.failure_categories[0].category);
    assert!(received(&tf, "/").is_empty(), "nothing was sent over the unverified channel");

    let profile = TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab ca".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki.ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let mut trusted = strict.clone();
    trusted.settings_layers.push(("workspace".into(), SettingsOverrides { tls_profile_id: Some(profile.id), ..Default::default() }));
    trusted.tls_profiles = vec![profile];
    let id = Id::new();
    let r = run(plan(Workload::Iterations { iterations: 3, concurrency: 1 }, vec![id]), vec![(id, trusted)], None).await;
    assert_eq!(r.requests.completed, 3);
}

fn open_job(url: &str, secret: Option<&str>, secs: u64) -> (WorkerJob, SecretRef) {
    let key = SecretRef { id: Id::new(), label: "api key".into() };
    let mut s = RequestSpec::http("GET", url);
    s.auth = AuthConfig::ApiKey {
        name: "x-api-key".into(),
        value: SensitiveValue::Secret { secret: key.clone() },
        location: KeyLocation::Header,
    };
    let mut c = ctx(s);
    c.secrets = Arc::new(MemorySecrets(HashMap::from([(key.id, Zeroizing::new(secret.unwrap_or("k").to_string()))])));
    let id = Id::new();
    let p = plan(Workload::OpenArrivalRate { stages: stages(20, secs), max_in_flight: 8 }, vec![id]);
    let job = LoadJob { requests: HashMap::from([(id, c)]), dataset: None };
    (WorkerJob::from_load_job(&p, &job, opts()).unwrap(), key)
}

const WORKER: &str = env!("CARGO_BIN_EXE_anvil-load-worker");

async fn wait_progress(c: &mut LoadController, n: usize) -> anvil_load::Progress {
    let mut last = None;
    for _ in 0..n {
        last =
            Some(tokio::time::timeout(Duration::from_secs(5), c.next_progress()).await.expect("progress in time").expect("worker alive"));
    }
    last.unwrap()
}

async fn traffic_stopped(f: &fx::Fixture) -> bool {
    let n1 = f.log.count_requests();
    tokio::time::sleep(Duration::from_millis(600)).await;
    f.log.count_requests() == n1
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_009_worker_crash_yields_partial_report_from_last_progress() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let (job, _) = open_job(&f.url("/delay-headers/20"), None, 8);
    let mut c = LoadController::spawn(WORKER.as_ref(), &job).await.unwrap();
    // Timeline buckets are finalized one bucket late (so their percentiles
    // are complete); run past 2 s so at least one has been delivered.
    let p = wait_progress(&mut c, 10).await;
    assert!(p.snapshot.counts.started > 0);
    assert!(p.elapsed_secs >= 2.0);
    let pid = c.pid().unwrap() as i32;
    // SAFETY: sending a signal to the child process we spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    let t = Instant::now();
    let r = c.wait().await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_eq!(r.completion, RunCompletion::WorkerCrashed);
    assert!(r.partial);
    assert_balanced(&r);
    assert!(r.counts.started >= p.snapshot.counts.started, "metrics come from the last snapshot");
    assert!(r.counts.started < 160, "never presented as the full planned run");
    assert!(!r.timeline.is_empty(), "timeline rebuilt from progress deltas");
    assert!(r.notes.iter().any(|n| n.contains("exited without a final report")), "{:?}", r.notes);
    assert!(anvil_load::html::to_html(&r).contains("Partial report"));
    assert!(traffic_stopped(&f).await, "killing the worker stops traffic");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_009_cancel_through_controller_drains_and_reports_partial() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let secret = "sk-live-TOPSECRET-4242";
    let (job, _) = open_job(&f.url("/delay-headers/20"), Some(secret), 8);
    let mut c = LoadController::spawn(WORKER.as_ref(), &job).await.unwrap();
    wait_progress(&mut c, 3).await;
    let pid = c.pid().unwrap();
    let ps = std::process::Command::new("ps").args(["-ww", "-o", "command=", "-p", &pid.to_string()]).output().unwrap();
    let cmdline = String::from_utf8_lossy(&ps.stdout);
    assert!(cmdline.contains("anvil-load-worker"), "{cmdline}");
    assert!(!cmdline.contains(secret) && !cmdline.contains('{'), "no job or secret in argv: {cmdline}");
    let t = Instant::now();
    c.cancel().await;
    let r = c.wait().await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(4), "bounded drain");
    assert_eq!(r.completion, RunCompletion::CanceledByUser);
    assert!(r.partial);
    assert_balanced(&r);
    assert!(r.counts.started > 0 && r.counts.started < 160);
    assert!(r.measured_duration_secs < 7.0);
    assert!(!serde_json::to_string(&r).unwrap().contains(secret), "secrets never reach the report");
    assert!(traffic_stopped(&f).await);
    let echoed: Vec<_> = received(&f, "/delay-headers/").into_iter().filter(|h| header(h, "x-api-key") == Some(secret)).collect();
    assert_eq!(echoed.len() as u64, r.requests.started, "the scoped secret was used for every send");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_009_stdin_eof_cancels_worker_and_bad_jobs_do_not_echo_content() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let (job, _) = open_job(&f.url("/delay-headers/10"), None, 8);
    let mut child = tokio::process::Command::new(WORKER)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(serde_json::to_string(&job).unwrap().as_bytes()).await.unwrap();
    stdin.write_all(b"\n").await.unwrap();
    stdin.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    drop(stdin); // parent "goes away"
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut report = None;
    let mut saw_started = false;
    while let Ok(Ok(Some(l))) = tokio::time::timeout(Duration::from_secs(6), lines.next_line()).await {
        match serde_json::from_str::<WorkerMessage>(&l).unwrap() {
            WorkerMessage::Started { .. } => saw_started = true,
            WorkerMessage::Report { report: r } => report = Some(*r),
            _ => {}
        }
    }
    let r = report.expect("final report after EOF");
    assert!(saw_started);
    assert_eq!(r.completion, RunCompletion::CanceledByUser);
    assert!(r.partial);
    assert_balanced(&r);
    assert!(child.wait().await.unwrap().success());

    // A malformed job is refused without quoting any of its content.
    let mut child =
        tokio::process::Command::new(WORKER).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(br#"{"protocol_version":"sk-live-LEAKME","plan":1}"#).await.unwrap();
    stdin.write_all(b"\n").await.unwrap();
    drop(stdin);
    let out = child.wait_with_output().await.unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("\"type\":\"error\""), "{text}");
    assert!(!text.contains("LEAKME"), "{text}");
    assert_eq!(out.status.code(), Some(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_010_bounded_samples_under_sustained_failures_and_large_bodies() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let id = Id::new();
    let r =
        run(plan(Workload::Iterations { iterations: 300, concurrency: 16 }, vec![id]), vec![(id, get(&f.url("/status/500")))], None).await;
    assert_eq!(r.requests.application_failures, 300);
    assert_eq!(r.counts.application_failures, 300);
    assert_eq!(r.counts.completed, 300, "application failures are complete responses");
    assert_eq!(r.latency_failure.count, 300);
    assert_eq!(r.latency_success.count, 0);
    assert_eq!(r.failure_categories.len(), 1);
    assert_eq!(r.failure_categories[0].count, 300);
    assert!(r.failure_categories[0].examples.len() <= anvil_load::metrics::MAX_EXAMPLES);
    assert!(r.failure_categories[0].examples.iter().all(|e| e.chars().count() <= anvil_load::metrics::MAX_EXAMPLE_CHARS + 1));

    let id = Id::new();
    let n = 2 * 1024 * 1024u64;
    let r =
        run(plan(Workload::Iterations { iterations: 16, concurrency: 4 }, vec![id]), vec![(id, get(&f.url(&format!("/bytes/{n}"))))], None)
            .await;
    assert_eq!(r.requests.completed, 16, "bodies larger than the in-memory capture are still read completely");
    assert!(r.bytes_received >= 16 * n);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_011_report_roundtrip_and_html_escape_response_content() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    // The response header value is attacker-controlled; the failed header
    // assertion quotes it into the failure sample.
    let mut s = RequestSpec::http("GET", &f.url("/status/200?header=X-Note%3A%3Cscript%3Ealert(1)%3C%2Fscript%3E"));
    s.assertions = vec![Assertion {
        enabled: true,
        label: String::new(),
        kind: AssertionKind::Header { name: "x-note".into(), comparison: anvil_domain::assertions::Comparison::Equals, value: "ok".into() },
    }];
    let id = Id::new();
    let r = run(plan(Workload::Iterations { iterations: 5, concurrency: 1 }, vec![id]), vec![(id, ctx(s))], None).await;
    assert_eq!(r.requests.assertion_failures, 5);
    let sample = r.failure_categories[0].examples.join("\n");
    assert!(sample.contains("<script>alert(1)</script>"), "response-derived text reaches the sample: {sample}");
    let html = anvil_load::html::to_html(&r);
    assert!(!html.to_ascii_lowercase().contains("<script"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    let json = anvil_load::report::to_json(&r);
    let (back, integrity) = anvil_load::report::open_json(&json).unwrap();
    assert_eq!(integrity, anvil_load::report::Integrity::Verified);
    assert_eq!(back, r);
    assert_eq!(anvil_load::html::to_html(&back), html, "reopened report renders identically offline");
    let csv = anvil_load::report::summary_csv(&back);
    assert!(csv.contains("sends,assertion_failures,5"));
}

fn udp_ctx(addr: std::net::SocketAddr, datagrams: &[&str], window_ms: u64) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", &format!("udp://{addr}"));
    s.protocol = Protocol::Udp;
    s.udp = Some(UdpSpec {
        dtls: false,
        datagrams: datagrams.iter().map(|d| StreamPayload { data: d.to_string(), encoding: PayloadEncoding::Text }).collect(),
        response_window_ms: window_ms,
        max_datagrams: 100,
        masque: None,
        proxy_protocol: None,
    });
    ctx(s)
}

fn datagrams_received(log: &anvil_fixtures::GroundTruthLog) -> u64 {
    log.entries().iter().filter(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })).count() as u64
}

fn datagram_metrics(r: &LoadReport) -> DatagramLoadMetrics {
    let p = r.protocol_metrics.as_ref().expect("protocol metrics");
    assert_eq!(p.unit, LoadUnitKind::UdpExchange);
    p.datagram.clone().expect("datagram block")
}

/// LOAD-013: a UDP load that sends more than it receives keeps sent and
/// received as separate counts, infers no acknowledgement, and never claims
/// that sent equals delivered — nor that silence is a failure or a loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_013_udp_sends_more_than_it_receives_and_never_claims_delivery() {
    let _g = serial().await;
    // The fixture answers every other datagram it receives.
    let lossy = anvil_fixtures::streams::udp("127.0.0.1:0", anvil_fixtures::streams::UdpMode::DropEveryOther).await.unwrap();
    let id = Id::new();
    let r = run(
        plan(Workload::Iterations { iterations: 6, concurrency: 1 }, vec![id]),
        vec![(id, udp_ctx(lossy.addr, &["d0", "d1", "d2", "d3"], 300))],
        None,
    )
    .await;
    let d = datagram_metrics(&r);
    assert_eq!(d.datagrams_sent, 24);
    assert_eq!(datagrams_received(&lossy.log), 24, "ground truth: the fixture got every datagram — Anvil must not claim so");
    assert_eq!(d.datagrams_received, 12, "received is its own count, never inferred from sent");
    assert_eq!((d.exchanges_with_response, d.exchanges_silent, d.echoed_payloads), (6, 0, 12));
    assert_eq!((r.requests.completed, r.requests.transport_failures, r.requests.application_failures), (6, 0, 0));
    assert_eq!(r.latency_success.count, 6, "time to first response of each responding exchange");
    assert!(r.latency_success.max_us < 300_000, "the response window is not a latency: {:?}", r.latency_success);
    assert!(r.notes.iter().any(|n| n.contains("never a delivery or loss rate")), "{:?}", r.notes);
    let html = anvil_load::html::to_html(&r);
    assert!(html.contains("Received per sent (observed ratio, not a delivery rate)"));
    let csv = anvil_load::report::summary_csv(&r);
    assert!(
        csv.contains("datagram,sent,24")
            && csv.contains("datagram,received,12")
            && csv.contains("datagram,observed_received_per_sent,0.5000")
    );

    // Silence: completed exchanges with no response observed — neither
    // successes nor failures, with no latency and no percentile.
    let silent = anvil_fixtures::streams::udp("127.0.0.1:0", anvil_fixtures::streams::UdpMode::Silent).await.unwrap();
    let id = Id::new();
    let r =
        run(plan(Workload::Iterations { iterations: 4, concurrency: 2 }, vec![id]), vec![(id, udp_ctx(silent.addr, &["?"], 150))], None)
            .await;
    let d = datagram_metrics(&r);
    assert_eq!((d.datagrams_sent, d.datagrams_received, d.exchanges_silent), (4, 0, 4));
    assert_eq!(datagrams_received(&silent.log), 4);
    assert_eq!((r.requests.completed, r.requests.transport_failures, r.requests.application_failures), (4, 0, 0));
    assert_eq!((r.latency_success.count, r.latency_failure.count), (0, 0));
    assert!(r.failure_categories.is_empty(), "silence is not a failure: {:?}", r.failure_categories);
    assert!(anvil_load::html::to_html(&r).contains("<div class=\"value\">—</div>"), "no response → no percentile, never 0 µs");

    // Duplicated replies are counted as repeated payloads (an observation).
    let dup = anvil_fixtures::streams::udp("127.0.0.1:0", anvil_fixtures::streams::UdpMode::Duplicate).await.unwrap();
    let id = Id::new();
    let r = run(
        plan(Workload::Iterations { iterations: 3, concurrency: 1 }, vec![id]),
        vec![(id, udp_ctx(dup.addr, &["u0", "u1"], 200))],
        None,
    )
    .await;
    let d = datagram_metrics(&r);
    assert_eq!((d.datagrams_sent, d.datagrams_received, d.repeated_payloads, d.echoed_payloads), (6, 12, 6, 12));

    // Nothing listening: the exchange makes no delivery claim. Unix reports
    // the loopback ICMP port unreachable to the connected socket (counted);
    // Windows surfaces it differently, and the adapter records it only as
    // the OS reports `ConnectionRefused` (as in the transport's PROTO-020 test).
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let id = Id::new();
    let r = run(plan(Workload::Iterations { iterations: 2, concurrency: 1 }, vec![id]), vec![(id, udp_ctx(port, &["x"], 150))], None).await;
    let d = datagram_metrics(&r);
    assert_eq!(d.datagrams_received, 0, "{d:?}");
    if cfg!(unix) {
        assert_eq!(d.icmp_unreachable_exchanges, 2, "{d:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_data_requests_are_refused_before_a_load_run() {
    let _g = serial().await;
    let mut s = RequestSpec::http("GET", "https://127.0.0.1:9/");
    s.settings.early_data = Some(anvil_domain::settings::EarlyDataPolicy { enabled: true, extra_methods: vec![] });
    let id = Id::new();
    let job = LoadJob { requests: HashMap::from([(id, ctx(s))]), dataset: None };
    match LoadRun::prepare(plan(Workload::Iterations { iterations: 1, concurrency: 1 }, vec![id]), job, opts()) {
        Err(anvil_load::LoadError::Refused(r)) => {
            assert_eq!(r.code, anvil_load::protocol::RefusalCode::EarlyData);
            assert_eq!(r.request_id, Some(id));
            assert!(r.message.contains("0-RTT early data"), "{}", r.message);
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("load runs must refuse early data before any traffic"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chain_extraction_feeds_next_step_with_dataset_rows() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut first = RequestSpec::http("GET", &f.url(r#"/status/200?body={"next":"{{k}}-x"}"#));
    first.extractions =
        vec![Extraction { variable: "next".into(), source: ExtractionSource::JsonPath { path: "$.next".into() }, sensitive: false }];
    let second = RequestSpec::http("GET", &f.url("/count/{{next}}"));
    let (a, b) = (Id::new(), Id::new());
    let data = Dataset::parse(DatasetFormat::Csv, b"k\nalpha\nbeta\ngamma\n".to_vec()).unwrap();
    let sha = data.sha256.clone();
    let mut p = plan(Workload::Iterations { iterations: 30, concurrency: 3 }, vec![a, b]);
    p.dataset_id = Some(Id::new());
    let r = run(p, vec![(a, ctx(first)), (b, ctx(second))], Some(data)).await;
    assert_eq!(r.counts.started, 30);
    assert_eq!(r.requests.started, 60, "two sends per chained iteration");
    assert_eq!(r.counts.completed, 30);
    let counters = f.state.counters.lock().clone();
    for k in ["alpha-x", "beta-x", "gamma-x"] {
        assert_eq!(counters.get(k), Some(&10), "{counters:?}");
    }
    assert_eq!(r.dataset_sha256, Some(sha));
}

fn extracting_tok(url: &str) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.extractions =
        vec![Extraction { variable: "tok".into(), source: ExtractionSource::JsonPath { path: "$.tok".into() }, sensitive: false }];
    s
}

/// A request prepared under a sealed import root (`ExecutionContext::scope`).
fn scoped(spec: RequestSpec, root: Id) -> ExecutionContext {
    let mut c = ctx(spec);
    c.scope = Some(root);
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chain_values_stay_on_their_side_of_an_import_root() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let root = Id::new();
    let (a, b, c, d) = (Id::new(), Id::new(), Id::new(), Id::new());
    let requests = HashMap::from([
        (a, ctx(extracting_tok(&f.url(r#"/status/200?body={"tok":"user-{{k}}"}"#)))),
        (b, scoped(extracting_tok(&f.url(r#"/status/200?body={"tok":"imported"}"#)), root)),
        (c, scoped(RequestSpec::http("GET", &f.url("/count/sealed-{{tok}}")), root)),
        (d, ctx(RequestSpec::http("GET", &f.url("/count/user-{{tok}}")))),
    ]);
    let data = Dataset::parse(DatasetFormat::Csv, b"k\nalpha\nbeta\ngamma\n".to_vec()).unwrap();
    let mut p = plan(Workload::Iterations { iterations: 30, concurrency: 3 }, vec![a, b, c, d]);
    p.dataset_id = Some(Id::new());
    // Through the worker's wire format, as a worker run receives it.
    let job = LoadJob { requests, dataset: Some(data) };
    let wire = serde_json::to_vec(&WorkerJob::from_load_job(&p, &job, opts()).unwrap()).unwrap();
    let (p, job, o) = serde_json::from_slice::<WorkerJob>(&wire).unwrap().into_load_job().unwrap();
    assert_eq!((job.requests[&a].scope, job.requests[&b].scope), (None, Some(root)));
    let r = LoadRun::prepare(p, job, o).expect("valid plan").execute(CancellationToken::new(), None).await;
    assert_balanced(&r);
    assert_eq!(r.counts.completed, 30);
    // The root's steps saw only what the root extracted; the workspace's
    // steps only what the workspace extracted.
    let counters = f.state.counters.lock().clone();
    let mut expected = HashMap::new();
    for (k, n) in [("sealed-imported", 30), ("user-user-alpha", 10), ("user-user-beta", 10), ("user-user-gamma", 10)] {
        expected.insert(k.to_string(), n);
    }
    assert_eq!(counters, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_under_an_import_root_never_sends_a_workspace_value() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let root = Id::new();
    let (login, leak, row) = (Id::new(), Id::new(), Id::new());
    let requests = vec![
        (login, ctx(extracting_tok(&f.url(r#"/status/200?body={"tok":"user-session"}"#)))),
        (leak, scoped(RequestSpec::http("GET", &f.url("/count/leak-{{tok}}")), root)),
        (row, scoped(RequestSpec::http("GET", &f.url("/count/row-{{k}}")), root)),
    ];
    for chain in [vec![login, leak], vec![row]] {
        let data = Dataset::parse(DatasetFormat::Csv, b"k\nalpha\n".to_vec()).unwrap();
        let mut p = plan(Workload::Iterations { iterations: 4, concurrency: 1 }, chain);
        p.dataset_id = Some(Id::new());
        let r = run(p, requests.clone(), Some(data)).await;
        assert_eq!(r.counts.started, 4);
    }
    assert_eq!(received(&f, "/status/").len(), 4, "the workspace's own step ran");
    assert!(received(&f, "/count/").is_empty(), "{:?}", f.state.counters.lock());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn weighted_mix_follows_seeded_weights() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let (a, b) = (Id::new(), Id::new());
    let mut p = plan(Workload::Iterations { iterations: 80, concurrency: 4 }, vec![]);
    p.mix = vec![WeightedStep { request_id: a, weight: 3 }, WeightedStep { request_id: b, weight: 1 }];
    p.seed = 5;
    let want_a = (0..80).filter(|i| anvil_load::executor::pick_weighted(5, &[3, 4], *i) == 0).count() as u64;
    run(p, vec![(a, get(&f.url("/count/a"))), (b, get(&f.url("/count/b")))], None).await;
    let c = f.state.counters.lock().clone();
    assert_eq!(c.get("a"), Some(&want_a));
    assert_eq!(c.get("b"), Some(&(80 - want_a)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_modes_fresh_and_persistent() {
    let _g = serial().await;
    for (mode, check) in [(ConnectionMode::Fresh, 30usize..=30), (ConnectionMode::Persistent, 1usize..=4)] {
        let f = fx::serve("127.0.0.1:0", None).await.unwrap();
        let id = Id::new();
        let mut p = plan(Workload::Iterations { iterations: 30, concurrency: 2 }, vec![id]);
        p.connection_mode = mode;
        let r = run(p, vec![(id, get(&f.url("/")))], None).await;
        let accepted = connections(&f);
        assert!(check.contains(&accepted), "{mode:?}: {accepted} connections");
        assert_eq!(r.requests.connections_opened as usize, accepted, "engine evidence matches fixture ground truth");
        assert_eq!(r.requests.connections_opened + r.requests.connections_reused, 30);
    }
}

/// A persistent chain over more destinations than the smallest per-slot
/// idle cap (4) reuses every step's connection on the next iteration: the
/// cap follows the plan, so no step's connection is closed just before its
/// reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_persistent_chain_over_six_destinations_reuses_every_connection() {
    let _g = serial().await;
    let mut fixtures = Vec::new();
    for _ in 0..6 {
        fixtures.push(fx::serve("127.0.0.1:0", None).await.unwrap());
    }
    let requests: Vec<(Id, ExecutionContext)> = fixtures.iter().map(|f| (Id::new(), get(&f.url("/")))).collect();
    let chain = requests.iter().map(|(id, _)| *id).collect();
    let r = run(plan(Workload::Iterations { iterations: 5, concurrency: 1 }, chain), requests, None).await;
    assert_eq!((r.counts.started, r.counts.completed), (5, 5));
    for (i, f) in fixtures.iter().enumerate() {
        assert_eq!(f.log.count_requests(), 5, "destination {i}");
        assert_eq!(connections(f), 1, "destination {i}: its connection was not reused across iterations");
    }
    assert_eq!((r.requests.connections_opened, r.requests.connections_reused), (6, 24));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warmup_is_excluded_from_metrics() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let id = Id::new();
    let mut p = plan(Workload::ClosedVirtualUsers { stages: stages(1, 2), think_time_ms: 50 }, vec![id]);
    p.warmup_secs = 1;
    let r = run(p, vec![(id, get(&f.url("/")))], None).await;
    let total = f.log.count_requests() as u64;
    assert!(r.warmup_iterations_excluded > 5);
    assert_eq!(total, r.requests.started + r.warmup_sends_excluded, "every send is either measured or excluded warmup");
    assert_eq!(r.latency_success.count, r.requests.completed);
    assert!(!r.warmup_included_in_metrics);
    assert!(r.timeline[0].warmup && !r.timeline.last().unwrap().warmup);
    assert!((r.measured_duration_secs - 1.0).abs() < 0.2, "{}", r.measured_duration_secs);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abort_rule_stops_a_failing_run() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let id = Id::new();
    let mut p = plan(Workload::OpenArrivalRate { stages: stages(50, 5), max_in_flight: 16 }, vec![id]);
    p.abort = Some(AbortRule { max_failure_permille: 500, window_secs: 1 });
    let t = Instant::now();
    let r = run(p, vec![(id, get(&f.url("/status/503")))], None).await;
    assert!(t.elapsed() < Duration::from_secs(4), "aborted early");
    assert_eq!(r.completion, RunCompletion::AbortedByRule);
    assert!(r.partial);
    assert!(r.notes.iter().any(|n| n.starts_with("Aborted by rule")), "{:?}", r.notes);
    assert!(r.counts.scheduled < 150);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn iterations_fewer_than_concurrency_use_only_allocated_slots() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let id = Id::new();
    let r = run(plan(Workload::Iterations { iterations: 2, concurrency: 64 }, vec![id]), vec![(id, get(&f.url("/")))], None).await;
    assert_eq!((r.counts.started, r.counts.completed), (2, 2));
    assert_eq!(f.log.count_requests(), 2);
}

/// DATA-016: locking the vault during an active run stops it under the
/// stop-runs-on-lock policy: traffic stops, the report is partial and says
/// why, and the job's secret never appears in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_016_lock_during_load_stops_run_with_partial_report() {
    let _g = serial().await;
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let secret = "sk-live-LOCKTEST-9191";
    let (job, _) = open_job(&f.url("/delay-headers/20"), Some(secret), 8);
    let mut c = LoadController::spawn(WORKER.as_ref(), &job).await.unwrap();
    wait_progress(&mut c, 3).await;
    let t = Instant::now();
    c.cancel_for_lock().await;
    let r = c.wait().await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(4), "bounded drain");
    assert_eq!(r.completion, RunCompletion::StoppedByLock);
    assert!(r.partial);
    assert_balanced(&r);
    assert!(r.notes.iter().any(|n| n.contains("vault locked")), "{:?}", r.notes);
    assert!(!anvil_load::report::to_json(&r).contains(secret), "no secret in the report");
    assert!(traffic_stopped(&f).await, "no hidden traffic after lock");
}
