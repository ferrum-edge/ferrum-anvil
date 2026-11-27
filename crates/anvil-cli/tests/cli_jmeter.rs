//! `anvil load export-jmx` and `anvil load import-jtl` (LOAD-012) through
//! the real binary and a real profile on disk. Nothing is sent: the export
//! only prepares the requests, and the import reads a result file.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::request::RequestSpec;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::Output;

const PASS: &str = "cli-jmeter-passphrase-1";

fn setup(root: &Path) {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let ws = app.create_workspace("Shop").unwrap();
    app.create_request(&ws.meta.id, None, "Echo", RequestSpec::http("GET", "http://127.0.0.1:9/echo")).unwrap();
    app.create_request(&ws.meta.id, None, "Secure", RequestSpec::http("GET", "https://api.example.test/")).unwrap();
}

fn anvil(data: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[test]
fn load_012_cli_exports_a_plan_refuses_strict_tls_and_imports_results() {
    let root = tempfile::tempdir().unwrap();
    setup(root.path());
    let data = root.path();
    let out = tempfile::tempdir().unwrap();

    let o = anvil(data, &["load", "create", "Shop", "echo", "--request", "Echo", "--iterations", "4", "--concurrency", "2"]);
    assert!(o.status.success(), "{}", text(&o));
    let jmx = out.path().join("echo.jmx");
    let report = out.path().join("echo.report.json");
    let o = anvil(data, &["load", "export-jmx", "Shop", "echo", "--out", jmx.to_str().unwrap(), "--report", report.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("run: jmeter -n -t"), "{}", text(&o));
    let plan = std::fs::read_to_string(&jmx).unwrap();
    assert!(plan.contains("<HTTPSamplerProxy") && plan.contains("jmeterTestPlan"), "{plan}");
    let r: serde_json::Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(r["expected_samples"], 4);
    assert_eq!(r["jmeter_version"], anvil_jmeter::JMETER_VERSION);

    // A request Anvil sends with certificate verification is refused, and nothing is written.
    let o = anvil(data, &["load", "create", "Shop", "strict", "--request", "Secure", "--iterations", "1"]);
    assert!(o.status.success(), "{}", text(&o));
    let refused = out.path().join("strict.jmx");
    let o = anvil(data, &["load", "export-jmx", "Shop", "strict", "--out", refused.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("strict_tls"), "{}", text(&o));
    assert!(!refused.exists());

    // A JMeter result file becomes a saved report of the plan.
    let jtl = out.path().join("results.jtl");
    let mut csv = String::from(
        "timeStamp,elapsed,label,responseCode,responseMessage,threadName,dataType,success,failureMessage,bytes,sentBytes,grpThreads,allThreads,URL,Latency,IdleTime,Connect\n",
    );
    for (i, code) in ["200", "200", "200", "500"].iter().enumerate() {
        let ok = *code == "200";
        csv += &format!(
            "{},{},1. Echo,{code},m,G 1-1,text,{ok},,10,10,2,2,http://127.0.0.1:9/echo,1,0,0\n",
            1_790_000_000_000i64 + i as i64 * 10,
            5 + i
        );
    }
    std::fs::write(&jtl, csv).unwrap();
    let json = out.path().join("imported.json");
    let o = anvil(
        data,
        &[
            "load",
            "import-jtl",
            "Shop",
            "--file",
            jtl.to_str().unwrap(),
            "--plan",
            "echo",
            "--jmeter-version",
            "5.6.3",
            "--json",
            json.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("imported 4 JMeter sample(s)"), "{}", text(&o));
    let (r, _) = anvil_load::report::open_json(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!((r.requests.completed, r.requests.application_failures), (4, 1));
    assert_eq!(r.plan.name, "echo");
    let o = anvil(data, &["load", "reports", "Shop"]);
    assert!(text(&o).contains(&r.run_id.to_string()), "{}", text(&o));

    // A file that is not a JTL is refused with the reason.
    std::fs::write(&jtl, "<!DOCTYPE x [<!ENTITY a \"b\">]><testResults/>").unwrap();
    let o = anvil(data, &["load", "import-jtl", "Shop", "--file", jtl.to_str().unwrap()]);
    assert!(!o.status.success());
    assert!(text(&o).contains("DOCTYPE"), "{}", text(&o));
}
