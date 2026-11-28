//! Round trip with a real Apache JMeter (LOAD-012), against the repository's
//! loopback fixture server. Ignored by default; `.github/workflows/jmeter.yml`
//! downloads the pinned, checksum-verified JMeter release and runs
//!
//! ```text
//! ANVIL_JMETER_HOME=<jmeter dir> cargo test --locked -p anvil-jmeter --test jmeter_roundtrip -- --ignored --test-threads=1
//! ```
//!
//! Each test exports an Anvil plan, runs it with `jmeter -n`, imports the
//! result file and checks it against the fixture's own record of what it
//! received and, where it applies, against the same plan run by Anvil's
//! native engine.

mod common;

use anvil_domain::assertions::{AssertionKind, Comparison, Extraction, ExtractionSource};
use anvil_domain::auth::AuthConfig;
use anvil_domain::load::ConnectionMode;
use anvil_domain::load::{LoadReport, Stage, WeightedStep, Workload};
use anvil_domain::request::{Body, KeyValue, LintSendPolicy, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, RedirectPolicy};
use anvil_fixtures::GroundTruth;
use anvil_fixtures::http as fx;
use anvil_jmeter::{ExportOptions, JtlLimits, JtlOptions, import_jtl};
use anvil_load::report::{check_balance, check_protocol_balance, check_request_balance};
use anvil_load::{LoadJob, LoadRun, RunOptions};
use common::*;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

const SECRET: &str = "tok-roundtrip-SENSITIVE";

fn jmeter() -> PathBuf {
    let home =
        std::env::var_os("ANVIL_JMETER_HOME").expect("ANVIL_JMETER_HOME names the JMeter installation (see .github/workflows/jmeter.yml)");
    let bin = if cfg!(windows) { "jmeter.bat" } else { "jmeter" };
    Path::new(&home).join("bin").join(bin)
}

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

/// What a JMeter run left behind.
struct Run {
    dir: tempfile::TempDir,
    log: String,
}

impl Run {
    fn jtl(&self) -> PathBuf {
        self.dir.path().join("results.jtl")
    }
}

/// Write the export into a fresh folder and run it with `jmeter -n`.
async fn run_jmeter(out: &anvil_jmeter::Export, format: &str, secrets: bool) -> Run {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("plan.jmx"), &out.jmx).unwrap();
    if let Some(csv) = &out.dataset_csv {
        std::fs::write(dir.path().join("plan.dataset.csv"), csv).unwrap();
    }
    let mut cmd = tokio::process::Command::new(jmeter());
    cmd.current_dir(dir.path()).args(["-n", "-t", "plan.jmx", "-l", "results.jtl", "-j", "jmeter.log"]);
    for (k, v) in &out.report.jmeter_properties {
        cmd.arg(format!("-J{k}={v}"));
    }
    if !format.is_empty() {
        cmd.arg(format!("-Jjmeter.save.saveservice.output_format={format}"));
        if format == "csv" {
            cmd.arg("-Jjmeter.save.saveservice.url=true");
        }
    }
    if secrets && let Some(props) = &out.secrets_properties {
        std::fs::write(dir.path().join("secrets.properties"), props.as_bytes()).unwrap();
        cmd.args(["-q", "secrets.properties"]);
    }
    let output = cmd.output().await.expect("JMeter starts");
    let log = std::fs::read_to_string(dir.path().join("jmeter.log")).unwrap_or_default();
    let tail = |s: &str| s[s.char_indices().rev().nth(5999).map_or(0, |(i, _)| i)..].to_string();
    assert!(
        output.status.success() && !log.contains("Error in NonGUIDriver"),
        "JMeter failed ({}):\nstdout: {}\nstderr: {}\nlog: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        tail(&log)
    );
    Run { dir, log }
}

fn import(run: &Run, fx: &Fx) -> LoadReport {
    let file = std::fs::File::open(run.jtl()).expect("JMeter wrote a result file");
    let opts = JtlOptions {
        workspace_id: fx.plan.workspace_id,
        plan: Some(fx.plan.clone()),
        source_name: "results.jtl".into(),
        jmeter_version: Some(anvil_jmeter::JMETER_VERSION.into()),
        warmup_secs: None,
        limits: JtlLimits::default(),
    };
    let r = import_jtl(file, &opts).unwrap_or_else(|e| panic!("import: {e}\nlog: {}", run.log));
    check_balance(&r.counts).unwrap();
    check_request_balance(&r.requests).unwrap();
    check_protocol_balance(&r).unwrap();
    r
}

async fn native(fx: &Fx) -> LoadReport {
    let job = LoadJob { requests: fx.job.requests.clone(), dataset: fx.job.dataset.clone() };
    let opts = RunOptions { acknowledged: true, ..Default::default() };
    LoadRun::prepare(fx.plan.clone(), job, opts).expect("valid plan").execute(CancellationToken::new(), None).await
}

fn received(f: &fx::Fixture, prefix: &str) -> Vec<(String, Vec<(String, String)>)> {
    f.log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::RequestReceived { path, headers, .. } if path.starts_with(prefix) => Some((path, headers)),
            _ => None,
        })
        .collect()
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// A two-step chain: a POST with a JSON body from the dataset, a secret
/// bearer token, a header from the environment, assertions and an
/// extraction, then a GET whose status comes from the dataset (every other
/// iteration a 404) and whose query uses the extracted value.
fn chain_plan(f: &fx::Fixture) -> Fx {
    let mut login = RequestSpec::http("POST", &f.url("/echo"));
    login.params.push(KeyValue::new("user", "{{user}}"));
    login.headers.push(KeyValue::new("X-Run", "{{run}}"));
    login.body = Body::Json { text: r#"{"user":"{{user}}","iteration":{{anvil.iteration}}}"#.into() };
    // Per-iteration values in a JSON body are exported under a non-blocking lint policy.
    login.lint_policy = LintSendPolicy::Warn;
    login.auth = AuthConfig::Bearer { token: SensitiveValue::template("{{token}}"), prefix: "Bearer".into() };
    login.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    login.assertions.push(assertion(AssertionKind::Status { comparison: Comparison::Equals, value: "200".into() }));
    login.assertions.push(assertion(AssertionKind::JsonPath {
        path: "$.method".into(),
        comparison: Comparison::Equals,
        value: "POST".into(),
    }));
    login.extractions.push(Extraction {
        variable: "verb".into(),
        source: ExtractionSource::JsonPath { path: "$.method".into() },
        sensitive: false,
    });
    let (a, mut ca) = step(login);
    ca.var_layers.push(layer("workspace", &[("token", SECRET, true), ("run", "nightly", false)]));
    let mut status = RequestSpec::http("GET", &f.url("/status/{{code}}?via={{verb}}"));
    status.assertions.push(assertion(AssertionKind::Header {
        name: "Content-Type".into(),
        comparison: Comparison::Exists,
        value: String::new(),
    }));
    let (b, cb) = step(status);
    Fx::new(iterations(10, 2), vec![(a, ca, "login"), (b, cb, "status")], Some(dataset("user,code\nalice,200\nbob,404\n")))
}

fn export_opts(include_secrets: bool) -> ExportOptions {
    ExportOptions { include_secrets, dataset_file: "plan.dataset.csv".into() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Apache JMeter (ANVIL_JMETER_HOME); run by .github/workflows/jmeter.yml"]
async fn load_012_jmeter_runs_the_exported_chain_and_the_import_matches_anvil() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let plan = chain_plan(&f);
    let out = plan.export(&export_opts(true)).expect("exported");
    assert!(!out.jmx.contains("SENSITIVE"), "the secret is a property, not in the .jmx");
    assert_eq!(out.report.expected_samples, Some(20));

    for format in ["csv", "xml"] {
        f.log.clear();
        let run = run_jmeter(&out, format, true).await;
        let jmeter = import(&run, &plan);
        let q = &jmeter.requests;
        assert_eq!((q.started, q.completed, q.transport_failures, q.timeouts), (20, 20, 0, 0), "{format}: {q:?}\n{}", run.log);
        assert_eq!((q.application_failures, q.assertion_failures), (5, 0), "{format}: {q:?}");
        assert_eq!(jmeter.status_distribution, vec![(200, 15), (404, 5)], "{format}");
        assert!(jmeter.engine_version.ends_with(&format!("+jtl-{format}")));

        // The fixture's ground truth: what JMeter actually sent.
        let echo = received(&f, "/echo");
        let status = received(&f, "/status/");
        assert_eq!((echo.len(), status.len()), (10, 10), "{format}");
        for (path, h) in &echo {
            assert_eq!(header(h, "authorization"), Some(format!("Bearer {SECRET}").as_str()), "{format}: {path}");
            assert_eq!(header(h, "x-run"), Some("nightly"));
            assert_eq!(header(h, "content-type"), Some("application/json"));
            assert!(header(h, "user-agent").is_some_and(|ua| ua.starts_with("Ferrum-Anvil/")));
            assert!(path == "/echo?user=alice" || path == "/echo?user=bob", "{path}");
        }
        assert_eq!(status.iter().filter(|(p, _)| p.starts_with("/status/404")).count(), 5);
        assert!(status.iter().all(|(p, _)| p.ends_with("?via=POST")), "the extracted value reached step 2: {status:?}");
    }

    // The same plan run by Anvil's native engine counts the same units.
    f.log.clear();
    let anvil = native(&plan).await;
    let q = &anvil.requests;
    assert_eq!((q.started, q.completed, q.application_failures, q.assertion_failures), (20, 20, 5, 0), "{q:?}");
    assert_eq!(anvil.status_distribution, vec![(200, 15), (404, 5)]);
    assert_eq!(received(&f, "/echo").len(), 10);

    // A 1-iteration run with secrets + dataset + {{anvil.iteration}} proves
    // SetupThreadGroup neither advances CSVDataSet past row 0 (`alice`) nor
    // advances CounterConfig past iteration `0`.
    let mut one_req = RequestSpec::http("GET", &f.url("/echo"));
    one_req.params.push(KeyValue::new("user", "{{user}}"));
    one_req.headers.push(KeyValue::new("X-Iter", "{{anvil.iteration}}"));
    one_req.auth = AuthConfig::Bearer { token: SensitiveValue::template("{{token}}"), prefix: "Bearer".into() };
    one_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let (one_id, mut one_c) = step(one_req);
    one_c.var_layers.push(layer("workspace", &[("token", SECRET, true)]));
    let one_fx = Fx::new(iterations(1, 1), vec![(one_id, one_c, "one")], Some(dataset("user\nalice\nbob\n")));
    let one_out = one_fx.export(&export_opts(true)).expect("exported");
    f.log.clear();
    let _one_run = run_jmeter(&one_out, "xml", true).await;
    let one_got = received(&f, "/echo");
    assert_eq!(one_got.len(), 1, "{one_got:?}");
    assert_eq!(one_got[0].0, "/echo?user=alice", "SetupThreadGroup must not consume CSV row 0");
    assert_eq!(header(&one_got[0].1, "x-iter"), Some("0"), "SetupThreadGroup must not advance anvil.iteration past 0");

    // Leading-space dataset filename + uneven iterations (5 across 3 threads):
    // proves `./ ` prefix survives JMeter's `.trim()` and discarded iterations
    // never consume CSV rows.
    let mut gated_req = RequestSpec::http("GET", &f.url("/echo"));
    gated_req.params.push(KeyValue::new("user", "{{user}}"));
    gated_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let (gd_id, gd_c) = step(gated_req);
    let gd_fx = Fx::new(iterations(5, 3), vec![(gd_id, gd_c, "gated")], Some(dataset("user\nalice\nbob\n")));
    let leading_csv_name = " leading space.dataset.csv";
    let gd_out = gd_fx.export(&ExportOptions { include_secrets: false, dataset_file: leading_csv_name.into() }).expect("exported");
    f.log.clear();
    {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(" leading space.jmx"), &gd_out.jmx).unwrap();
        std::fs::write(dir.path().join(leading_csv_name), gd_out.dataset_csv.as_ref().unwrap()).unwrap();
        let mut cmd = tokio::process::Command::new(jmeter());
        cmd.current_dir(dir.path()).args(["-n", "-t", " leading space.jmx", "-l", "results.jtl", "-j", "jmeter.log"]);
        for (k, v) in &gd_out.report.jmeter_properties {
            cmd.arg(format!("-J{k}={v}"));
        }
        let output = cmd.output().await.expect("JMeter starts");
        assert!(output.status.success(), "leading-space dataset run failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let gd_got = received(&f, "/echo");
    assert_eq!(gd_got.len(), 5, "exact 5 gated iterations sent: {gd_got:?}");
    let gd_alice = gd_got.iter().filter(|(p, _)| p == "/echo?user=alice").count();
    let gd_bob = gd_got.iter().filter(|(p, _)| p == "/echo?user=bob").count();
    assert_eq!((gd_alice, gd_bob), (3, 2), "uneven gate must not discard CSV rows: {gd_got:?}");

    // Different engines: compared, with the difference named and latency deltas withheld.
    let f2 = std::fs::File::open(run_jmeter(&out, "csv", true).await.jtl()).unwrap();
    let jmeter = import_jtl(
        f2,
        &JtlOptions {
            workspace_id: plan.plan.workspace_id,
            plan: Some(plan.plan.clone()),
            source_name: "results.jtl".into(),
            jmeter_version: Some(anvil_jmeter::JMETER_VERSION.into()),
            warmup_secs: None,
            limits: JtlLimits::default(),
        },
    )
    .unwrap();
    let cmp = anvil_load::compare(&anvil, &jmeter);
    assert!(!cmp.compatible);
    assert!(cmp.differences.iter().any(|d| d.aspect == "engine"), "{:?}", cmp.differences);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Apache JMeter (ANVIL_JMETER_HOME); run by .github/workflows/jmeter.yml"]
async fn load_012_jmeter_without_the_secret_properties_stops_before_any_traffic() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let plan = chain_plan(&f);
    let out = plan.export(&export_opts(false)).expect("exported");
    assert!(out.secrets_properties.is_none());
    let run = run_jmeter(&out, "csv", false).await;
    assert_eq!(f.log.count_requests(), 0, "nothing reached the target without the secret properties");
    let samples = std::fs::read_to_string(run.jtl()).unwrap_or_default().lines().filter(|l| !l.starts_with("timeStamp")).count();
    assert_eq!(samples, 0, "{}", run.log);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Apache JMeter (ANVIL_JMETER_HOME); run by .github/workflows/jmeter.yml"]
async fn load_012_jmeter_accepts_an_untrusted_certificate_so_strict_tls_is_refused() {
    init();
    let pki = anvil_fixtures::LabPki::generate();
    let tf = fx::serve("127.0.0.1:0", Some(anvil_fixtures::TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone())))
        .await
        .unwrap();
    let mut spec = RequestSpec::http("GET", &tf.url("/"));
    spec.settings.http_version = Some(HttpVersionPolicy::Http1Only);

    // Anvil verifies the server certificate: the lab CA is not trusted, so
    // the native engine refuses every connection...
    let (id, c) = step(spec.clone());
    let strict = Fx::new(iterations(4, 1), vec![(id, c, "root")], None);
    let anvil = native(&strict).await;
    assert_eq!((anvil.requests.started, anvil.requests.completed), (4, 0), "{:?}", anvil.requests);
    // ...and the export refuses the plan rather than let JMeter accept it.
    let e = match strict.export(&export_opts(false)) {
        Ok(_) => panic!("a strict TLS request must not be exported"),
        Err(e) => e,
    };
    assert_eq!(e.reasons.iter().map(|r| r.code).collect::<Vec<_>>(), ["strict_tls"]);

    // With verification turned off in Anvil the plan is exported, and JMeter
    // completes every request against the same untrusted certificate:
    // evidence that a JMeter run never verifies, which is why the strict
    // plan above is refused.
    let (id, mut c) = step(spec);
    with_tls_profile(&mut c, false);
    let unverified = Fx::new(iterations(4, 1), vec![(id, c, "root")], None);
    let out = unverified.export(&export_opts(false)).expect("exported");
    tf.log.clear();
    let run = run_jmeter(&out, "csv", false).await;
    let r = import(&run, &unverified);
    assert_eq!((r.requests.started, r.requests.completed), (4, 4), "{:?}\n{}", r.requests, run.log);
    assert_eq!(tf.log.count_requests(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Apache JMeter (ANVIL_JMETER_HOME); run by .github/workflows/jmeter.yml"]
async fn load_012_jmeter_runs_closed_open_and_mixed_workloads() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();

    // Closed: 1 virtual user, then a ramp to 3 over 2 s, held to 4 s, with think time.
    let (id, c) = step(RequestSpec::http("GET", &f.url("/")));
    let closed = Workload::ClosedVirtualUsers {
        stages: vec![Stage { duration_secs: 0, target: 1 }, Stage { duration_secs: 2, target: 3 }, Stage { duration_secs: 2, target: 3 }],
        think_time_ms: 100,
    };
    let fx_closed = Fx::new(closed, vec![(id, c.clone(), "root")], None);
    let out = fx_closed.export(&export_opts(false)).expect("exported");
    f.log.clear();
    let r = import(&run_jmeter(&out, "csv", false).await, &fx_closed);
    assert!(r.requests.started > 5 && r.requests.completed == r.requests.started, "{:?}", r.requests);
    assert_eq!(f.log.count_requests() as u64, r.requests.started);

    // Open: 5 arrivals/s for 3 s.
    let open = Workload::OpenArrivalRate {
        stages: vec![Stage { duration_secs: 0, target: 5 }, Stage { duration_secs: 3, target: 5 }],
        // The cap covers 5/s × the default 120 s deadline; connections are fresh.
        max_in_flight: 1_000,
    };
    let mut fx_open = Fx::new(open, vec![(id, c, "root")], None);
    fx_open.plan.connection_mode = ConnectionMode::Fresh;
    let out = fx_open.export(&export_opts(false)).expect("exported");
    f.log.clear();
    let r = import(&run_jmeter(&out, "csv", false).await, &fx_open);
    assert_eq!(r.requests.started, 15, "even arrivals: 5/s for 3 s");
    assert_eq!(f.log.count_requests(), 15);

    // Weighted mix: 3:1 over 40 iterations.
    let (a, ca) = step(RequestSpec::http("GET", &f.url("/status/200")));
    let (b, cb) = step(RequestSpec::http("GET", &f.url("/status/201")));
    let mut mix = Fx::new(iterations(40, 4), vec![(a, ca, "a"), (b, cb, "b")], None);
    mix.plan.chain.clear();
    mix.plan.mix = vec![WeightedStep { request_id: a, weight: 3 }, WeightedStep { request_id: b, weight: 1 }];
    let out = mix.export(&export_opts(false)).expect("exported");
    f.log.clear();
    let r = import(&run_jmeter(&out, "csv", false).await, &mix);
    assert_eq!(r.requests.started, 40, "exactly one request per iteration");
    let twohundred = r.status_distribution.iter().find(|(s, _)| *s == 200).map(|(_, n)| *n).unwrap_or(0);
    assert!((15..=40).contains(&twohundred), "the heavier request dominates: {:?}", r.status_distribution);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Apache JMeter (ANVIL_JMETER_HOME); run by .github/workflows/jmeter.yml"]
async fn load_012_jmeter_redirect_to_an_untrusted_https_target_is_refused_or_matches() {
    init();
    let pki = anvil_fixtures::LabPki::generate();
    let tf = fx::serve("127.0.0.1:0", Some(anvil_fixtures::TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone())))
        .await
        .unwrap();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let to = url_escape(&tf.url("/"));
    let mut spec = RequestSpec::http("GET", &f.url(&format!("/redirect?status=302&to={to}")));
    spec.settings.redirects = Some(RedirectPolicy::default());

    // Following: Anvil refuses the untrusted certificate at the https hop...
    let (id, c) = step(spec.clone());
    let following = Fx::new(iterations(3, 1), vec![(id, c, "hop")], None);
    let anvil = native(&following).await;
    assert_eq!((anvil.requests.started, anvil.requests.completed), (3, 0), "{:?}", anvil.requests);
    // ...and the export refuses the plan, which JMeter would complete.
    let e = match following.export(&export_opts(false)) {
        Ok(_) => panic!("a redirect that can reach an untrusted https target must not be exported"),
        Err(e) => e,
    };
    assert_eq!(e.reasons.iter().map(|r| r.code).collect::<Vec<_>>(), ["redirect_destination_policy", "redirect_tls"]);

    // Not following: both record the redirect itself, and nothing reaches the https target.
    spec.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let (id, c) = step(spec);
    let plain = Fx::new(iterations(3, 1), vec![(id, c, "hop")], None);
    tf.log.clear();
    let anvil = native(&plain).await;
    assert_eq!(anvil.status_distribution, vec![(302, 3)]);
    let out = plain.export(&export_opts(false)).expect("exported");
    let jmeter = import(&run_jmeter(&out, "csv", false).await, &plain);
    assert_eq!(jmeter.status_distribution, vec![(302, 3)]);
    assert_eq!(tf.log.count_requests(), 0);
}

/// `s` percent-encoded for a query value.
fn url_escape(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Apache JMeter (ANVIL_JMETER_HOME); run by .github/workflows/jmeter.yml"]
async fn load_012_default_export_properties_do_not_write_url_credentials_to_jtl() {
    use anvil_domain::auth::KeyLocation;
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let path_secret = "path-SENSITIVE-token";
    let query_secret = "qkey-SENSITIVE-value";
    let ds_secret_cell = "ds-SAMPLEVAR-value";
    let mut spec = RequestSpec::http("GET", &f.url("/echo/{{secret_seg}}"));
    spec.auth = AuthConfig::ApiKey { name: "api_key".into(), value: SensitiveValue::template("{{qkey}}"), location: KeyLocation::Query };
    spec.headers.push(KeyValue::new("X-User", "{{user}}"));
    spec.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    // Also attach a failing body assertion on the echoed response (which echoes
    // both secrets) to prove default XML save properties write neither URLs,
    // response messages, nor assertion failure messages into the JTL.
    spec.assertions.push(assertion(AssertionKind::Body { comparison: Comparison::Contains, value: "NEVER-MATCHES".into() }));
    let (id, mut c) = step(spec);
    c.var_layers.push(layer("workspace", &[("secret_seg", path_secret, true), ("qkey", query_secret, true)]));
    let plan = Fx::new(iterations(3, 1), vec![(id, c, "url-secret")], Some(dataset(&format!("user\n{ds_secret_cell}\n"))));
    let out = plan.export(&export_opts(true)).expect("exported");
    assert!(!out.jmx.contains("SENSITIVE"), "no secret material in .jmx");
    // Run JMeter with a noisy local properties file enabling response/header/samplerData
    // and sample_variables capture, overridden ONLY by our exported default `-J` properties,
    // to prove none of the echoed credentials, headers, or dataset variables leak into results.jtl.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("plan.jmx"), &out.jmx).unwrap();
    std::fs::write(dir.path().join("plan.dataset.csv"), out.dataset_csv.as_ref().unwrap()).unwrap();
    std::fs::write(dir.path().join("secrets.properties"), out.secrets_properties.as_ref().unwrap().as_bytes()).unwrap();
    std::fs::write(
        dir.path().join("noisy.properties"),
        "jmeter.save.saveservice.response_data=true\n\
         jmeter.save.saveservice.response_data.on_error=true\n\
         jmeter.save.saveservice.samplerData=true\n\
         jmeter.save.saveservice.requestHeaders=true\n\
         jmeter.save.saveservice.responseHeaders=true\n\
         sample_variables=anvil_ds_0\n",
    )
    .unwrap();
    let mut cmd = tokio::process::Command::new(jmeter());
    cmd.current_dir(dir.path()).args([
        "-n",
        "-t",
        "plan.jmx",
        "-l",
        "results.jtl",
        "-j",
        "jmeter.log",
        "-q",
        "noisy.properties",
        "-q",
        "secrets.properties",
    ]);
    for (k, v) in &out.report.jmeter_properties {
        cmd.arg(format!("-J{k}={v}"));
    }
    let output = cmd.output().await.expect("JMeter starts");
    let log = std::fs::read_to_string(dir.path().join("jmeter.log")).unwrap_or_default();
    assert!(output.status.success() && !log.contains("Error in NonGUIDriver"), "JMeter failed: {log}");
    let run = Run { dir, log };
    let raw_jtl = std::fs::read_to_string(run.jtl()).expect("JMeter wrote results.jtl");
    assert!(!raw_jtl.contains(path_secret), "URL path secret leaked into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains(query_secret), "query API key leaked into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains(ds_secret_cell), "sample_variables leaked dataset value into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains("anvil_ds_0="), "sample_variables attribute leaked into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains("<assertionResult>"), "assertion result body leaked into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains("<responseData"), "response body leaked into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains("<requestHeader"), "request headers leaked into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains("<responseHeader"), "response headers leaked into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains("<samplerData"), "samplerData leaked into JTL: {raw_jtl}");
    assert!(!raw_jtl.contains(" rm="), "response message attribute leaked into JTL: {raw_jtl}");
    let report = import(&run, &plan);
    assert_eq!((report.requests.started, report.requests.completed), (3, 3));
    // With `jmeter.save.saveservice.assertions=false`, JMeter omits `<assertionResult>`
    // so a failed body assertion on HTTP 200 is imported as an application failure.
    assert_eq!((report.requests.application_failures, report.requests.assertion_failures), (3, 0));
    assert_eq!(report.status_distribution, vec![(200, 3)]);
    assert!(report.engine_version.ends_with("+jtl-xml"));
    // Ground truth: JMeter actually sent both resolved secrets to the fixture.
    let got = received(&f, "/echo/");
    assert_eq!(got.len(), 3);
    assert!(got.iter().all(|(p, _)| p.contains(path_secret) && p.contains(query_secret)), "{got:?}");

    // Wire-level path fidelity: Anvil sends `/echo//seg` verbatim, whereas
    // JMeter's HttpClient 4 collapses `//`, so export refuses it with `url_path`.
    let mut dbl_spec = RequestSpec::http("GET", &f.url("/echo//seg"));
    dbl_spec.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let (dbl_id, dbl_c) = step(dbl_spec);
    let dbl_plan = Fx::new(iterations(1, 1), vec![(dbl_id, dbl_c, "dbl")], None);
    f.log.clear();
    let _ = native(&dbl_plan).await;
    let dbl_got = received(&f, "/echo");
    assert_eq!(dbl_got.len(), 1, "{dbl_got:?}");
    assert_eq!(dbl_got[0].0, "/echo//seg", "Anvil sends empty path segments verbatim");
    let Err(dbl_err) = dbl_plan.export(&export_opts(false)) else {
        panic!("empty segment path must be refused");
    };
    assert!(dbl_err.reasons.iter().any(|r| r.code == "url_path"), "{dbl_err:?}");

    // Wire-level query encoding note coverage: `*` and `~` in a per-iteration
    // query value are encoded differently by JMeter's __urlencode vs Anvil's
    // RFC 3986 percent-encoding, and the export report documents both.
    let mut enc_spec = RequestSpec::http("GET", &f.url("/echo"));
    enc_spec.params.push(KeyValue::new("v", "{{val}}"));
    enc_spec.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let (enc_id, enc_c) = step(enc_spec);
    let enc_plan = Fx::new(iterations(1, 1), vec![(enc_id, enc_c, "enc")], Some(dataset("val\na*b~c d\n")));
    let enc_out = enc_plan.export(&export_opts(false)).expect("exported");
    assert!(
        enc_out.report.differences.iter().any(|d| d.contains("'*'") && d.contains("'~'") && d.contains("'+'")),
        "query encoding note must mention space, '*', and '~': {:?}",
        enc_out.report.differences
    );
    f.log.clear();
    let _ = native(&enc_plan).await;
    let anvil_enc = received(&f, "/echo");
    assert_eq!(anvil_enc.len(), 1, "{anvil_enc:?}");
    assert_eq!(anvil_enc[0].0, "/echo?v=a%2Ab~c%20d", "Anvil RFC 3986 encoding");
    f.log.clear();
    let _ = run_jmeter(&enc_out, "xml", false).await;
    let jmeter_enc = received(&f, "/echo");
    assert_eq!(jmeter_enc.len(), 1, "{jmeter_enc:?}");
    assert_eq!(jmeter_enc[0].0, "/echo?v=a*b%7Ec+d", "JMeter __urlencode form encoding");
}
