//! `anvil run` / `anvil scenario` end to end: the real binary, a real
//! profile on disk and a real fixture server.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::assertions::{Assertion, AssertionKind, Comparison, Extraction, ExtractionSource};
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::runner::{RunReport, RunnerCompletion};
use anvil_domain::workspace::{Meta, Scenario, ScenarioStep, Variable};
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::Output;

const PASS: &str = "cli-run-passphrase-1";
const TOKEN: &str = "cli-SESSION-TOKEN-4242";

fn setup(root: &Path, base: &str, closed_port: u16) {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let ws = app.create_workspace("Shop").unwrap();
    app.create_environment(&ws.meta.id, "lab", vec![Variable::plain("base", base)]).unwrap();

    let mut login = RequestSpec::http("POST", "{{base}}/status/200");
    login.params.push(KeyValue::new("body", format!(r#"{{"session":"{TOKEN}"}}"#)));
    login.extractions.push(Extraction {
        variable: "session".into(),
        source: ExtractionSource::JsonPath { path: "$.session".into() },
        sensitive: true,
    });
    app.create_request(&ws.meta.id, None, "Login", login).unwrap();
    let mut me = RequestSpec::http("GET", "{{base}}/echo");
    me.headers.push(KeyValue::new("X-Session", "{{session}}"));
    app.create_request(&ws.meta.id, None, "Me", me).unwrap();
    let ping = app.create_request(&ws.meta.id, None, "Ping", RequestSpec::http("GET", "{{base}}/count/ping")).unwrap();
    let mut greet = RequestSpec::http("GET", "{{base}}/echo");
    greet.params.push(KeyValue::new("u", "{{user}}"));
    greet.headers.push(KeyValue::new("X-Pin", "{{pin}}"));
    app.create_request(&ws.meta.id, None, "Greet", greet).unwrap();

    let checks = app.create_folder(&ws.meta.id, None, "Checks").unwrap();
    let mut wrong = RequestSpec::http("GET", "{{base}}/status/200");
    wrong.assertions.push(Assertion {
        enabled: true,
        label: String::new(),
        kind: AssertionKind::Status { comparison: Comparison::Equals, value: "201".into() },
    });
    app.create_request(&ws.meta.id, Some(checks.meta.id), "Wrong status", wrong).unwrap();
    let broken = app.create_folder(&ws.meta.id, None, "Broken").unwrap();
    app.create_request(&ws.meta.id, Some(broken.meta.id), "Refused", RequestSpec::http("GET", &format!("http://127.0.0.1:{closed_port}/")))
        .unwrap();

    // What an import leaves behind: an untrusted scenario.
    app.save_scenario(Scenario {
        meta: Meta::new(),
        workspace_id: ws.meta.id,
        name: "Imported".into(),
        description: String::new(),
        steps: vec![ScenarioStep { request_id: ping.meta.id, enabled: true, delay_ms: 0 }],
        dataset_id: None,
        iterations: 1,
        stop_on_failure: false,
        trusted: false,
    })
    .unwrap();
}

async fn anvil(data: &Path, args: &[&str]) -> Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .output()
        .await
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn ping_count(f: &anvil_fixtures::http::Fixture) -> u64 {
    *f.state.counters.lock().get("ping").unwrap_or(&0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_and_scenario_commands_end_to_end() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    setup(&data, &f.url(""), closed);
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let p = |n: &str| out.join(n).to_string_lossy().into_owned();

    // scenario create / list / show
    let o = anvil(&data, &["scenario", "create", "Shop", "Flow", "--step", "Login", "--step", "Me"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = anvil(&data, &["scenario", "list", "Shop"]).await;
    let listing = text(&o);
    assert!(listing.contains("Flow") && listing.contains("UNTRUSTED") && listing.contains("Imported"), "{listing}");
    let o = anvil(&data, &["scenario", "show", "Shop", "flow"]).await;
    assert!(text(&o).contains("Login POST {{base}}/status/200"), "{}", text(&o));

    // A passing chained run with all three exports.
    let o = anvil(
        &data,
        &["run", "Shop", "--scenario", "Flow", "--env", "lab", "--json", &p("r.json"), "--junit", &p("r.xml"), "--html", &p("r.html")],
    )
    .await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let report: RunReport = serde_json::from_slice(&std::fs::read(p("r.json")).unwrap()).unwrap();
    assert_eq!(report.completion, RunnerCompletion::Completed);
    assert_eq!(report.totals.steps_passed, 2);
    let junit = std::fs::read_to_string(p("r.xml")).unwrap();
    roxmltree::Document::parse(&junit).expect("well-formed JUnit");
    let html = std::fs::read_to_string(p("r.html")).unwrap();
    for (what, t) in [("json", std::fs::read_to_string(p("r.json")).unwrap()), ("junit", junit), ("html", html), ("console", text(&o))] {
        assert!(!t.contains(TOKEN), "{what} leaked the sensitive extracted token");
    }
    assert!(f.log.last_request_headers().unwrap().iter().any(|(n, v)| n == "x-session" && v == TOKEN));

    // Assertion failure → 2; transport failure → 1 (with a JUnit <error>).
    let o = anvil(&data, &["run", "Shop", "--folder", "Checks", "--env", "lab", "-q"]).await;
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let o = anvil(&data, &["run", "Shop", "--folder", "Broken", "--env", "lab", "--junit", &p("b.xml"), "-q"]).await;
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(std::fs::read_to_string(p("b.xml")).unwrap().contains("<error type=\"transport\""));
    // Counting only assertions: the transport failure no longer fails the run.
    let o = anvil(&data, &["run", "Shop", "--folder", "Broken", "--env", "lab", "--fail-on", "assertions", "-q"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));

    // Untrusted scenario: refused (3) without traffic, then an explicit
    // one-off override, then trusted for good.
    let o = anvil(&data, &["run", "Shop", "--scenario", "Imported", "--env", "lab"]).await;
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("not trusted"));
    assert_eq!(ping_count(&f), 0);
    let o = anvil(&data, &["run", "Shop", "--scenario", "Imported", "--env", "lab", "--allow-untrusted", "-q"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("not trusted"), "the override is called out in the output");
    assert_eq!(ping_count(&f), 1);
    let o = anvil(&data, &["scenario", "trust", "Shop", "Imported"]).await;
    assert_eq!(o.status.code(), Some(0));
    let o = anvil(&data, &["run", "Shop", "--scenario", "Imported", "--env", "lab", "-q"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(ping_count(&f), 2);

    // Datasets: stored with the scenario, and overridden from a file.
    std::fs::write(p("rows.csv"), "user,pin\nann,pin-000111\nbo,pin-000222\ncy,pin-000333\n").unwrap();
    std::fs::write(p("one.json"), r#"[{"user":"zed","pin":"pin-999999"}]"#).unwrap();
    let o =
        anvil(&data, &["scenario", "create", "Shop", "Rows", "--step", "Greet", "--dataset", &p("rows.csv"), "--sensitive-column", "pin"])
            .await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = anvil(&data, &["run", "Shop", "--scenario", "Rows", "--env", "lab", "--json", &p("rows.json")]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let rows = std::fs::read_to_string(p("rows.json")).unwrap();
    let report: RunReport = serde_json::from_str(&rows).unwrap();
    assert_eq!(report.totals.iterations_planned, 3);
    for pin in ["pin-000111", "pin-000222", "pin-000333"] {
        assert!(!rows.contains(pin) && !text(&o).contains(pin), "sensitive column leaked");
    }
    let o = anvil(
        &data,
        &[
            "run",
            "Shop",
            "--scenario",
            "Rows",
            "--env",
            "lab",
            "--dataset",
            &p("one.json"),
            "--sensitive-column",
            "pin",
            "--json",
            &p("one.out.json"),
            "-q",
        ],
    )
    .await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let one: RunReport = serde_json::from_slice(&std::fs::read(p("one.out.json")).unwrap()).unwrap();
    assert_eq!(one.totals.iterations_planned, 1);
    assert!(f.log.requests().iter().any(|(_, path)| path.contains("u=zed")));

    // Usage and local errors are 3; help is 0.
    for args in [
        vec!["run", "Shop"],
        vec!["run", "Shop", "--scenario", "Flow", "--folder", "Checks"],
        vec!["run", "Shop", "--scenario", "Nope"],
        vec!["run", "Shop", "--folder", "Checks", "--dataset", "/definitely/missing.csv"],
    ] {
        let o = anvil(&data, &args).await;
        assert_eq!(o.status.code(), Some(3), "{args:?}: {}", text(&o));
    }
    let o = anvil(&data, &["run", "--help"]).await;
    assert_eq!(o.status.code(), Some(0));
}
