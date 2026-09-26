//! Collection-runner scenarios over real sockets: fixtures + the shared
//! engine. The provider hands the runner in-memory contexts; nothing about
//! the engine is mocked. Fixture ground truth is used only to check what
//! actually reached the peer.

use anvil_domain::Id;
use anvil_domain::assertions::{Assertion, AssertionKind, Comparison, Extraction, ExtractionSource};
use anvil_domain::outcome::{ApplicationState, AssertionState, TransportState};
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::runner::*;
use anvil_domain::settings::{Limits, SettingsOverrides};
use anvil_domain::workspace::DatasetFormat;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::GroundTruth;
use anvil_fixtures::http as fx;
use anvil_runner::provider::MemoryProvider;
use anvil_runner::{PlannedStep, ProvidedStep, RunDataset, RunError, RunOptions, RunPlan, StepError, StepProvider};
use parking_lot::Mutex;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn assertion(kind: AssertionKind) -> Assertion {
    Assertion { enabled: true, label: String::new(), kind }
}

/// Records what the runner hands over for history, like the app does.
#[derive(Default)]
struct Recording {
    inner: MemoryProvider,
    records: Mutex<Vec<(String, Vec<u8>)>>,
}

impl Recording {
    fn add(&mut self, name: &str, spec: RequestSpec) -> Id {
        let id = Id::new();
        let mut ctx = ExecutionContext::standalone(spec);
        ctx.request_id = Some(id);
        self.inner.insert(id, name, ctx);
        id
    }

    /// A step prepared under a sealed import root (`ExecutionContext::scope`).
    fn add_scoped(&mut self, name: &str, spec: RequestSpec, scope: Option<Id>) -> Id {
        let id = Id::new();
        let mut ctx = ExecutionContext::standalone(spec);
        ctx.request_id = Some(id);
        ctx.scope = scope;
        self.inner.insert(id, name, ctx);
        id
    }

    fn add_with(&mut self, name: &str, spec: RequestSpec, settings: SettingsOverrides) -> Id {
        let id = Id::new();
        let mut ctx = ExecutionContext::standalone(spec);
        ctx.request_id = Some(id);
        ctx.settings_layers.push(("request".into(), settings));
        self.inner.insert(id, name, ctx);
        id
    }

    fn history_text(&self) -> String {
        self.records.lock().iter().map(|(r, b)| format!("{r}\n{}", String::from_utf8_lossy(b))).collect::<Vec<_>>().join("\n")
    }
}

impl StepProvider for Recording {
    fn step(&self, request_id: &Id) -> Result<ProvidedStep, StepError> {
        self.inner.step(request_id)
    }

    fn record(&self, out: &ExecutionOutput) -> Result<(), StepError> {
        self.records.lock().push((serde_json::to_string(&out.record).unwrap(), out.body.to_vec()));
        Ok(())
    }
}

fn plan(steps: &[(Id, &str)]) -> RunPlan {
    let mut p = RunPlan::folder(Id::new(), None, "Tests", steps.iter().map(|(i, n)| (*i, n.to_string())).collect());
    p.name = "Runner test".into();
    p
}

fn exports(r: &RunReport) -> (String, String, String) {
    (anvil_runner::to_json(r), anvil_runner::to_junit(r), anvil_runner::to_html(r))
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn chaining_extracts_a_token_and_the_next_step_sends_it() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = Recording::default();
    let mut login = RequestSpec::http("POST", &f.url("/status/200"));
    login.params.push(KeyValue::new("body", r#"{"token":"tok-chain-0001","user":"alice"}"#));
    login.extractions.push(Extraction {
        variable: "auth_token".into(),
        source: ExtractionSource::JsonPath { path: "$.token".into() },
        sensitive: false,
    });
    login.assertions.push(assertion(AssertionKind::Status { comparison: Comparison::Equals, value: "200".into() }));
    let login_id = p.add("Login", login);
    let mut me = RequestSpec::http("GET", &f.url("/echo"));
    me.headers.push(KeyValue::new("X-Token", "{{auth_token}}"));
    me.headers.push(KeyValue::new("X-Step", "{{anvil.iteration}}/{{anvil.step}}"));
    let me_id = p.add("Me", me);

    let engine = Engine::new();
    let r = anvil_runner::run(&engine, &p, plan(&[(login_id, "Login"), (me_id, "Me")]), RunOptions::default(), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(r.completion, RunnerCompletion::Completed);
    assert!(r.passed(), "{r:#?}");
    assert_eq!(r.totals.steps_executed, 2);
    let steps = &r.iterations[0].steps;
    assert_eq!(steps[0].extracted, vec!["auth_token".to_string()]);
    assert_eq!(steps[0].assertions, Some(AssertionState::Pass));
    assert_eq!(steps[1].status, RunStepStatus::Passed);
    assert!(steps[0].execution_id.is_some() && steps[0].execution_id != steps[1].execution_id);
    // Ground truth: the fixture received the extracted token on step 2.
    let seen = f.log.last_request_headers().unwrap();
    assert_eq!(header(&seen, "x-token"), Some("tok-chain-0001"));
    assert_eq!(header(&seen, "x-step"), Some("0/1"), "anvil.iteration / anvil.step builtins");
    assert_eq!(p.records.lock().len(), 2, "each executed step is handed over for history");
}

fn token_login(f: &fx::Fixture, token: &str) -> RequestSpec {
    let mut s = RequestSpec::http("POST", &f.url("/status/200"));
    s.params.push(KeyValue::new("body", format!(r#"{{"token":"{token}"}}"#)));
    s.extractions.push(Extraction {
        variable: "auth_token".into(),
        source: ExtractionSource::JsonPath { path: "$.token".into() },
        sensitive: true,
    });
    s
}

fn step_echo(f: &fx::Fixture, step: &str, headers: &[(&str, &str)]) -> RequestSpec {
    let mut s = RequestSpec::http("GET", &f.url("/echo"));
    s.headers.push(KeyValue::new("X-Step", step));
    for (name, value) in headers {
        s.headers.push(KeyValue::new(*name, *value));
    }
    s
}

/// `(X-Step, X-Token, X-Pass)` of every request the fixture received.
fn received_steps(f: &fx::Fixture) -> Vec<(String, Option<String>, Option<String>)> {
    f.log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::RequestReceived { headers, .. } => {
                let get = |n: &str| header(&headers, n).map(str::to_string);
                Some((get("x-step")?, get("x-token"), get("x-pass")))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn extracted_values_and_dataset_rows_stay_on_their_side_of_an_import_root() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let root = Some(Id::new());
    let mut p = Recording::default();
    let login = p.add("Login", token_login(&f, "tok-user-0001"));
    // Under a sealed import root: a value extracted outside it and the run's
    // dataset row are not there, so these two are never sent.
    let leak = p.add_scoped("Leak", step_echo(&f, "leak", &[("X-Token", "{{auth_token}}")]), root);
    let row = p.add_scoped("Row", step_echo(&f, "row", &[("X-Pass", "{{password}}")]), root);
    // What the root's own steps extract stays under it.
    let own = p.add_scoped("Own", token_login(&f, "tok-imported-0002"), root);
    let imported = p.add_scoped("Imported", step_echo(&f, "imported", &[("X-Token", "{{auth_token}}")]), root);
    let me = p.add("Me", step_echo(&f, "me", &[("X-Token", "{{auth_token}}"), ("X-Pass", "{{password}}")]));
    let mut pl = plan(&[(login, "Login"), (leak, "Leak"), (row, "Row"), (own, "Own"), (imported, "Imported"), (me, "Me")]);
    pl.dataset = Some(RunDataset::parse("users", DatasetFormat::Csv, b"password\npw-row-secret-1\n", &["password".into()]).unwrap());

    let engine = Engine::new();
    let r = anvil_runner::run(&engine, &p, pl, RunOptions::default(), CancellationToken::new()).await.unwrap();
    let steps = &r.iterations[0].steps;
    assert_ne!(steps[1].status, RunStepStatus::Passed);
    assert_ne!(steps[2].status, RunStepStatus::Passed);
    assert_eq!(steps[4].status, RunStepStatus::Passed, "{r:#?}");
    assert_eq!(steps[5].status, RunStepStatus::Passed, "{r:#?}");
    // Ground truth: what reached the peer.
    let some = |s: &str| Some(s.to_string());
    let expected = [
        ("imported".to_string(), some("tok-imported-0002"), None),
        ("me".to_string(), some("tok-user-0001"), some("pw-row-secret-1")),
    ];
    assert_eq!(received_steps(&f), expected);
}

#[tokio::test]
async fn csv_and_json_datasets_drive_iterations_and_sensitive_columns_stay_out_of_reports() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    for (format, bytes) in [
        (DatasetFormat::Csv, b"user,password\nalice,pw-alice-secret-1\nbob,pw-bob-secret-22\n".to_vec()),
        (
            DatasetFormat::Json,
            br#"[{"user":"alice","password":"pw-alice-secret-1"},{"user":"bob","password":"pw-bob-secret-22"}]"#.to_vec(),
        ),
    ] {
        f.log.clear();
        let mut p = Recording::default();
        let mut spec = RequestSpec::http("GET", &f.url("/echo"));
        spec.params.push(KeyValue::new("user", "{{user}}"));
        spec.params.push(KeyValue::new("pw", "{{password}}"));
        spec.headers.push(KeyValue::new("X-Pass", "{{password}}"));
        // The echo body carries the password back; this assertion's observed
        // value therefore contains it.
        spec.assertions.push(assertion(AssertionKind::JsonPath {
            path: "$.target".into(),
            comparison: Comparison::Contains,
            value: "no-such-thing".into(),
        }));
        let id = p.add("Echo {{user}}", spec);
        let mut pl = plan(&[(id, "Echo")]);
        pl.dataset = Some(RunDataset::parse("users", format, &bytes, &["password".into()]).unwrap());
        let engine = Engine::new();
        let r = anvil_runner::run(&engine, &p, pl, RunOptions::default(), CancellationToken::new()).await.unwrap();
        assert_eq!(r.totals.iterations_planned, 2, "iterations default to the dataset rows");
        assert_eq!(r.iterations.iter().map(|i| i.dataset_row).collect::<Vec<_>>(), vec![Some(1), Some(2)]);
        assert_eq!(r.totals.assertion_failures, 2);
        assert_eq!(r.totals.transport_failures + r.totals.application_failures, 0);
        let ds = r.dataset.as_ref().unwrap();
        assert_eq!((ds.rows, ds.sensitive_columns.clone()), (2, vec!["password".to_string()]));

        // Ground truth: each row reached the fixture with its real values.
        let reqs = f.log.requests();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0].1.contains("user=alice") && reqs[0].1.contains("pw=pw-alice-secret-1"), "{reqs:?}");
        assert!(reqs[1].1.contains("user=bob"));
        let seen = f.log.last_request_headers().unwrap();
        assert_eq!(header(&seen, "x-pass"), Some("pw-bob-secret-22"));

        let (json, junit, html) = exports(&r);
        for (label, text) in [("json", &json), ("junit", &junit), ("html", &html), ("history", &p.history_text())] {
            assert!(
                !text.contains("pw-alice-secret-1") && !text.contains("pw-bob-secret-22"),
                "{format:?} {label} leaked a sensitive column"
            );
        }
        assert!(json.contains("user=alice"), "non-sensitive values are kept");
    }
}

#[tokio::test]
async fn sensitive_extraction_is_redacted_from_report_junit_html_and_history() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let token = "tok-SENSITIVE-9876";
    let mut p = Recording::default();
    let mut login = RequestSpec::http("POST", &f.url("/status/200"));
    login.params.push(KeyValue::new("body", format!(r#"{{"access":"{token}"}}"#)));
    login.params.push(KeyValue::new("header", format!("X-Issued:{token}")));
    login.extractions.push(Extraction {
        variable: "access".into(),
        source: ExtractionSource::JsonPath { path: "$.access".into() },
        sensitive: true,
    });
    // Fails, and its observed value is the token itself — which the engine
    // cannot know is sensitive yet (it is extracted by this very step).
    login.assertions.push(assertion(AssertionKind::Header { name: "X-Issued".into(), comparison: Comparison::Equals, value: "x".into() }));
    let login_id = p.add("Login", login);
    let mut use_it = RequestSpec::http("GET", &f.url("/echo"));
    use_it.params.push(KeyValue::new("t", "{{access}}"));
    use_it.headers.push(KeyValue::new("X-Custom-Auth", "{{access}}"));
    use_it.assertions.push(assertion(AssertionKind::JsonPath {
        path: "$.target".into(),
        comparison: Comparison::Equals,
        value: "x".into(),
    }));
    let use_id = p.add("Use", use_it);

    let engine = Engine::new();
    let r = anvil_runner::run(&engine, &p, plan(&[(login_id, "Login"), (use_id, "Use")]), RunOptions::default(), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(r.totals.steps_executed, 2);
    assert_eq!(r.totals.assertion_failures, 2);
    let seen = f.log.last_request_headers().unwrap();
    assert_eq!(header(&seen, "x-custom-auth"), Some(token), "the real value is sent");
    let (json, junit, html) = exports(&r);
    for (label, text) in [("json", &json), ("junit", &junit), ("html", &html), ("history", &p.history_text())] {
        assert!(!text.contains(token), "{label} leaked the sensitive extracted value");
    }
    assert!(json.contains(anvil_domain::secret::REDACTED), "values are replaced, not dropped silently");
    assert_eq!(p.records.lock().len(), 2);
}

#[tokio::test]
async fn stop_on_failure_stops_only_the_iteration_and_fail_on_is_configurable() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = Recording::default();
    let ok = p.add("OK", RequestSpec::http("GET", &f.url("/status/200")));
    let boom = p.add("Boom", RequestSpec::http("GET", &f.url("/status/500")));
    let after = p.add("After", RequestSpec::http("GET", &f.url("/count/after")));
    let engine = Engine::new();

    let mut pl = plan(&[(ok, "OK"), (boom, "Boom"), (after, "After")]);
    pl.stop_on_failure = true;
    pl.iterations = 2;
    let r = anvil_runner::run(&engine, &p, pl.clone(), RunOptions::default(), CancellationToken::new()).await.unwrap();
    assert_eq!(r.completion, RunnerCompletion::Completed, "stop_on_failure ends iterations, not the run");
    assert_eq!(r.iterations.len(), 2);
    for it in &r.iterations {
        assert_eq!(it.status, RunIterationStatus::Failed);
        assert_eq!(it.stopped_at_step, Some(1));
        assert_eq!(it.steps[1].status, RunStepStatus::Failed);
        assert_eq!(it.steps[1].failed_dimensions, vec![OutcomeDimension::Application]);
        assert_eq!(it.steps[1].transport, Some(TransportState::Completed), "the exchange itself completed");
        assert_eq!(it.steps[2].status, RunStepStatus::Skipped);
        assert!(it.steps[2].execution_id.is_none());
    }
    assert_eq!(*f.state.counters.lock().get("after").unwrap_or(&0), 0, "ground truth: the step after the failure was never sent");
    assert_eq!((r.totals.steps_skipped, r.totals.steps_failed, r.totals.steps_passed), (2, 2, 2));

    // Application failures not counted: step 2 passes, step 3 runs.
    let opts = RunOptions { fail_on: FailOn { application: false, ..FailOn::default() }, ..Default::default() };
    let r = anvil_runner::run(&engine, &p, pl, opts, CancellationToken::new()).await.unwrap();
    assert!(r.passed());
    assert_eq!(r.iterations[0].steps[1].status, RunStepStatus::Passed);
    assert_eq!(r.iterations[0].steps[1].failed_dimensions, vec![OutcomeDimension::Application], "the dimension is still reported");
    assert_eq!(r.totals.application_failures, 2);
    assert_eq!(*f.state.counters.lock().get("after").unwrap(), 2);
}

#[tokio::test]
async fn assertion_failures_are_distinct_from_transport_failures() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut p = Recording::default();
    let mut wrong = RequestSpec::http("GET", &f.url("/status/200"));
    wrong.assertions.push(assertion(AssertionKind::Status { comparison: Comparison::Equals, value: "201".into() }));
    let a = p.add("Wrong status", wrong);
    let b = p.add("Nobody home", RequestSpec::http("GET", &format!("http://127.0.0.1:{closed}/")));
    let engine = Engine::new();
    let r =
        anvil_runner::run(&engine, &p, plan(&[(a, "Wrong status"), (b, "Nobody home")]), RunOptions::default(), CancellationToken::new())
            .await
            .unwrap();
    let s = &r.iterations[0].steps;
    assert_eq!(s[0].status, RunStepStatus::Failed);
    assert_eq!(s[0].failed_dimensions, vec![OutcomeDimension::Assertions]);
    assert_eq!(
        (s[0].transport, s[0].application, s[0].assertions),
        (Some(TransportState::Completed), Some(ApplicationState::Success), Some(AssertionState::Fail))
    );
    assert_eq!(s[1].status, RunStepStatus::Failed);
    assert_eq!(s[1].failed_dimensions, vec![OutcomeDimension::Transport]);
    assert_eq!((s[1].transport, s[1].application), (Some(TransportState::Failed), Some(ApplicationState::NotEvaluated)));
    assert!(s[1].message.is_some(), "the typed transport failure is surfaced");
    assert_eq!((r.totals.transport_failures, r.totals.application_failures, r.totals.assertion_failures), (1, 0, 1));

    let junit = anvil_runner::to_junit(&r);
    let doc = roxmltree::Document::parse(&junit).unwrap();
    let cases: Vec<_> = doc.descendants().filter(|n| n.has_tag_name("testcase")).collect();
    assert_eq!(cases.len(), 2);
    let failure = cases[0].children().find(|n| n.has_tag_name("failure")).expect("assertion failure is a JUnit failure");
    assert_eq!(failure.attribute("type"), Some("assertion"));
    let error = cases[1].children().find(|n| n.has_tag_name("error")).expect("transport failure is a JUnit error");
    assert_eq!(error.attribute("type"), Some("transport"));
    let root = doc.root_element();
    assert_eq!((root.attribute("failures"), root.attribute("errors")), (Some("1"), Some("1")));
}

#[tokio::test]
async fn untrusted_scenarios_are_refused_unless_explicitly_allowed() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = Recording::default();
    let id = p.add("Imported", RequestSpec::http("GET", &f.url("/status/200")));
    let scenario = anvil_domain::workspace::Scenario {
        meta: Default::default(),
        workspace_id: Id::new(),
        name: "Imported flow".into(),
        description: String::new(),
        steps: vec![anvil_domain::workspace::ScenarioStep { request_id: id, enabled: true, delay_ms: 0 }],
        dataset_id: None,
        iterations: 1,
        stop_on_failure: false,
        trusted: false,
    };
    let pl = RunPlan::from_scenario(&scenario, &|_| "Imported".into(), None);
    let engine = Engine::new();
    let e = anvil_runner::run(&engine, &p, pl.clone(), RunOptions::default(), CancellationToken::new()).await.unwrap_err();
    assert!(matches!(e, RunError::Untrusted(_)), "{e}");
    assert!(e.to_string().contains("Nothing was sent"));
    assert_eq!(f.log.count_requests(), 0, "ground truth: nothing reached the peer");

    let r = anvil_runner::run(&engine, &p, pl, RunOptions { allow_untrusted: true, ..Default::default() }, CancellationToken::new())
        .await
        .unwrap();
    assert!(matches!(r.source, RunSource::Scenario { untrusted_override: true, .. }));
    assert!(r.notes.iter().any(|n| n.contains("not trusted")));
    assert!(anvil_runner::to_html(&r).contains("Untrusted scenario"));
    assert_eq!(f.log.count_requests(), 1);
}

#[tokio::test]
async fn cancellation_mid_run_finishes_with_a_partial_report() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = Recording::default();
    let fast = p.add("Fast", RequestSpec::http("GET", &f.url("/status/200")));
    let slow = p.add("Slow", RequestSpec::http("GET", &f.url("/delay-headers/10000")));
    let never = p.add("Never", RequestSpec::http("GET", &f.url("/count/never")));
    let mut pl = plan(&[(fast, "Fast"), (slow, "Slow"), (never, "Never")]);
    pl.iterations = 3;
    let cancel = CancellationToken::new();
    let events: Arc<Mutex<Vec<RunEvent>>> = Arc::default();
    let (ev2, c2) = (events.clone(), cancel.clone());
    let sink: anvil_runner::RunEventSink = Arc::new(move |e: RunEvent| {
        if let RunEvent::StepStarted { step: 1, .. } = &e {
            let c = c2.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                c.cancel();
            });
        }
        ev2.lock().push(e);
    });
    let engine = Engine::new();
    let t = std::time::Instant::now();
    let r = anvil_runner::run(&engine, &p, pl, RunOptions { events: Some(sink), ..Default::default() }, cancel).await.unwrap();
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "cancel is prompt");
    assert_eq!(r.completion, RunnerCompletion::Canceled);
    assert!(r.partial && !r.passed());
    assert_eq!((r.totals.iterations_planned, r.totals.iterations_started, r.totals.iterations_incomplete), (3, 1, 1));
    let s = &r.iterations[0].steps;
    assert_eq!(s[0].status, RunStepStatus::Passed);
    assert_eq!(s[1].status, RunStepStatus::Canceled);
    assert_eq!(s[1].transport, Some(TransportState::Canceled));
    assert!(s[1].execution_id.is_some(), "the in-flight step still has its record");
    assert_eq!(s[2].status, RunStepStatus::Canceled);
    assert!(s[2].execution_id.is_none());
    assert_eq!((r.totals.steps_canceled_in_flight, r.totals.steps_canceled), (1, 1));
    assert_eq!(*f.state.counters.lock().get("never").unwrap_or(&0), 0, "ground truth: nothing after the cancel was sent");
    let ev = events.lock();
    assert!(matches!(ev.first(), Some(RunEvent::RunStarted { .. })));
    assert!(matches!(ev.last(), Some(RunEvent::RunFinished { completion: RunnerCompletion::Canceled, .. })));
    let (_, junit, html) = exports(&r);
    roxmltree::Document::parse(&junit).unwrap();
    assert!(html.contains("Partial report"));
}

#[tokio::test]
async fn junit_is_well_formed_with_hostile_names_and_html_escapes_response_markup() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = Recording::default();
    let script = "<script>alert('x')</script>";
    let mut spec = RequestSpec::http("GET", &f.url("/status/200"));
    spec.params.push(KeyValue::new("body", format!(r#"{{"msg":"{script}","n":"]]> & \u0001"}}"#)));
    spec.params.push(KeyValue::new("header", format!("X-Note:{script}")));
    spec.assertions.push(assertion(AssertionKind::Header { name: "X-Note".into(), comparison: Comparison::Equals, value: "ok".into() }));
    spec.assertions.push(assertion(AssertionKind::JsonPath { path: "$.msg".into(), comparison: Comparison::Equals, value: "ok".into() }));
    spec.assertions.push(assertion(AssertionKind::JsonPath { path: "$.n".into(), comparison: Comparison::Equals, value: "ok".into() }));
    let hostile = "Login <b>&amp;</b> \"q\" 'a' \u{1} ]]> --";
    let id = p.add(hostile, spec);
    let engine = Engine::new();
    let mut pl = plan(&[(id, hostile)]);
    pl.name = format!("Suite {script}");
    let r = anvil_runner::run(&engine, &p, pl, RunOptions::default(), CancellationToken::new()).await.unwrap();
    let step = &r.iterations[0].steps[0];
    assert!(
        step.assertion_results.iter().any(|a| a.actual.as_deref() == Some(script)),
        "the response-derived markup is in the report: {step:#?}"
    );

    let (_, junit, html) = exports(&r);
    let doc = roxmltree::Document::parse(&junit).expect("JUnit XML is well-formed");
    let case = doc.descendants().find(|n| n.has_tag_name("testcase")).unwrap();
    assert!(case.attribute("name").unwrap().contains("Login <b>&amp;</b>"), "names round-trip through escaping");
    assert!(case.children().any(|n| n.has_tag_name("failure")));

    let lower = html.to_ascii_lowercase();
    assert!(!lower.contains("<script"), "no script element can appear");
    assert!(lower.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
    assert!(!lower.contains(" src=") && !lower.contains(" href=") && !lower.contains("<link") && !lower.contains("<img"));
    assert!(html.contains("Content-Security-Policy") && html.contains("default-src 'none'"));
    assert!(!html.contains('\u{1}'));
}

#[tokio::test]
async fn report_is_bounded_and_events_are_throttled_without_losing_totals() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = Recording::default();
    let a = p.add("A", RequestSpec::http("GET", &f.url("/status/200")));
    let b = p.add("B", RequestSpec::http("GET", &f.url("/status/404")));
    let mut pl = plan(&[(a, "A"), (b, "B")]);
    pl.iterations = 6;
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let n2 = n.clone();
    let sink: anvil_runner::RunEventSink = Arc::new(move |_| {
        n2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    let engine = Engine::new();
    let r = anvil_runner::run(
        &engine,
        &p,
        pl,
        RunOptions { max_report_steps: Some(3), events: Some(sink), ..Default::default() },
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!((r.totals.steps_passed, r.totals.steps_failed), (6, 6), "totals count everything");
    let retained: usize = r.iterations.iter().map(|i| i.steps.len()).sum();
    let omitted: u32 = r.iterations.iter().map(|i| i.steps_omitted).sum();
    assert_eq!(retained + omitted as usize, 12);
    assert!(omitted > 0 && r.notes.iter().any(|x| x.contains("at most 3")));
    // Failed steps are kept preferentially.
    assert!(r.iterations.iter().flat_map(|i| &i.steps).filter(|s| s.status == RunStepStatus::Failed).count() == 6);
    assert!(n.load(std::sync::atomic::Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn provider_errors_are_step_errors_and_fatal_errors_abort() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    struct Flaky {
        inner: Recording,
        missing: Id,
        fatal: Id,
    }
    impl StepProvider for Flaky {
        fn step(&self, id: &Id) -> Result<ProvidedStep, StepError> {
            if *id == self.missing {
                return Err(StepError::Step("request was deleted".into()));
            }
            if *id == self.fatal {
                return Err(StepError::Fatal("Anvil locked during the run".into()));
            }
            self.inner.step(id)
        }
    }
    let mut inner = Recording::default();
    let ok = inner.add("OK", RequestSpec::http("GET", &f.url("/status/200")));
    let (missing, fatal) = (Id::new(), Id::new());
    let p = Flaky { inner, missing, fatal };
    let steps = vec![
        PlannedStep { request_id: missing, name: "Gone".into(), enabled: true, delay_ms: 0 },
        PlannedStep { request_id: ok, name: "OK".into(), enabled: true, delay_ms: 0 },
        PlannedStep { request_id: ok, name: "Disabled".into(), enabled: false, delay_ms: 0 },
        PlannedStep { request_id: fatal, name: "Locked".into(), enabled: true, delay_ms: 0 },
        PlannedStep { request_id: ok, name: "After".into(), enabled: true, delay_ms: 0 },
    ];
    let mut pl = plan(&[]);
    pl.steps = steps;
    pl.iterations = 2;
    let engine = Engine::new();
    let r = anvil_runner::run(&engine, &p, pl, RunOptions::default(), CancellationToken::new()).await.unwrap();
    assert_eq!(r.completion, RunnerCompletion::Aborted);
    assert_eq!(r.abort_reason.as_deref(), Some("Anvil locked during the run"));
    let s = &r.iterations[0].steps;
    assert_eq!(
        s.iter().map(|x| x.status).collect::<Vec<_>>(),
        vec![RunStepStatus::Error, RunStepStatus::Passed, RunStepStatus::Skipped, RunStepStatus::Error, RunStepStatus::Canceled]
    );
    assert_eq!(r.iterations.len(), 1, "no further iteration after an abort");
    assert_eq!(f.log.count_requests(), 1);
    assert_eq!((r.totals.steps_errored, r.totals.steps_skipped, r.totals.steps_canceled), (2, 1, 1));
}

#[tokio::test]
async fn invalid_plans_are_rejected_before_any_traffic() {
    let p = Recording::default();
    let engine = Engine::new();
    let mut pl = plan(&[(Id::new(), "x")]);
    pl.steps[0].enabled = false;
    assert!(matches!(anvil_runner::run(&engine, &p, pl, RunOptions::default(), CancellationToken::new()).await, Err(RunError::Invalid(_))));
    let pl = plan(&[(Id::new(), "x")]);
    let e = anvil_runner::run(&engine, &p, pl.clone(), RunOptions { iterations: Some(0), ..Default::default() }, CancellationToken::new())
        .await;
    assert!(matches!(e, Err(RunError::Invalid(_))));
    let e = anvil_runner::run(
        &engine,
        &p,
        pl.clone(),
        RunOptions { iterations: Some(1_000_000), ..Default::default() },
        CancellationToken::new(),
    )
    .await;
    assert!(matches!(e, Err(RunError::Invalid(m)) if m.contains("limit")));
    let mut slow = pl;
    slow.steps[0].delay_ms = anvil_runner::MAX_DELAY_MS + 1;
    assert!(anvil_runner::run(&engine, &p, slow, RunOptions::default(), CancellationToken::new()).await.is_err());
}

/// A run whose dataset makes `fixture payload` (text inside the fixture's
/// gzip body) a sensitive run value, with one step: the response body kept
/// for history and the report notes.
async fn encoded_body_run(path: &str, settings: SettingsOverrides) -> (Vec<u8>, Vec<String>) {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = Recording::default();
    let id = p.add_with("Encoded", RequestSpec::http("GET", &f.url(path)), settings);
    let mut pl = plan(&[(id, "Encoded")]);
    pl.dataset = Some(RunDataset::parse("rows", DatasetFormat::Csv, b"marker\nfixture payload\n", &["marker".into()]).unwrap());
    let engine = Engine::new();
    let r = anvil_runner::run(&engine, &p, pl, RunOptions::default(), CancellationToken::new()).await.unwrap();
    assert_eq!(r.totals.steps_executed, 1);
    let records = p.records.lock();
    assert_eq!(records.len(), 1);
    (records[0].1.clone(), r.notes.clone())
}

fn assert_body_dropped(body: &[u8], notes: &[String]) {
    assert!(body.is_empty(), "a content-encoded body that could not be checked was kept: {} bytes", body.len());
    assert!(notes.iter().any(|n| n.contains("not kept in history")), "{notes:?}");
}

#[tokio::test]
async fn encoded_body_with_a_secret_past_the_decode_limit_is_not_kept() {
    // The decoded prefix ("compr") holds no secret, but the compressed bytes do.
    let limits = Limits { max_decoded_bytes: 5, ..Limits::default() };
    let (body, notes) = encoded_body_run("/gzip", SettingsOverrides { limits: Some(limits), ..Default::default() }).await;
    assert_body_dropped(&body, &notes);
}

#[tokio::test]
async fn malformed_compressed_body_is_not_kept() {
    let path = "/status/200?header=Content-Encoding:gzip&body=not-gzip%20fixture%20payload&ct=text/plain";
    let (body, notes) = encoded_body_run(path, SettingsOverrides::default()).await;
    assert_body_dropped(&body, &notes);
}

#[tokio::test]
async fn encoded_body_is_not_kept_when_decompression_is_off() {
    let (body, notes) = encoded_body_run("/gzip", SettingsOverrides { decompress: Some(false), ..Default::default() }).await;
    assert_body_dropped(&body, &notes);
}

#[tokio::test]
async fn completely_decoded_body_without_a_run_secret_is_kept() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut p = Recording::default();
    let id = p.add("Gzip", RequestSpec::http("GET", &f.url("/gzip")));
    let mut pl = plan(&[(id, "Gzip")]);
    pl.dataset = Some(RunDataset::parse("rows", DatasetFormat::Csv, b"marker\nnot-in-the-body\n", &["marker".into()]).unwrap());
    let engine = Engine::new();
    let r = anvil_runner::run(&engine, &p, pl, RunOptions::default(), CancellationToken::new()).await.unwrap();
    assert!(!r.notes.iter().any(|n| n.contains("not kept in history")), "{:?}", r.notes);
    assert!(!p.records.lock()[0].1.is_empty(), "the compressed body is kept");
}
