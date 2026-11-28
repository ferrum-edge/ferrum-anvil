//! `anvil load export-jmx` and `anvil load import-jtl` (LOAD-012) through
//! the real binary and a real profile on disk. Nothing is sent: the export
//! only prepares the requests, and the import reads a result file.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::request::RequestSpec;
use anvil_domain::settings::RedirectPolicy;
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
    // A request that follows redirects is exported only when every hop
    // behaves as in JMeter; this one does not follow them.
    let mut echo = RequestSpec::http("GET", "http://127.0.0.1:9/echo");
    echo.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let echo = app.create_request(&ws.meta.id, None, "Echo", echo).unwrap();
    // A plan with a dataset, for the dataset file written beside the plan.
    let attachment = app.put_attachment("users.csv", b"user\nalice\n", None).unwrap();
    let dataset = app
        .save_dataset(anvil_domain::workspace::Dataset {
            meta: anvil_domain::workspace::Meta::new(),
            workspace_id: ws.meta.id,
            name: "users".into(),
            format: anvil_domain::workspace::DatasetFormat::Csv,
            attachment,
            sensitive_columns: vec![],
        })
        .unwrap();
    let now = anvil_domain::Timestamp::now();
    app.save_load_plan(anvil_domain::load::LoadPlan {
        id: anvil_domain::Id::new(),
        workspace_id: ws.meta.id,
        name: "withdata".into(),
        workload: anvil_domain::load::Workload::Iterations { iterations: 2, concurrency: 1 },
        chain: vec![echo.meta.id],
        mix: vec![],
        dataset_id: Some(dataset.meta.id),
        environment_id: None,
        connection_mode: Default::default(),
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: now,
        updated_at: now,
    })
    .unwrap();
    let mut echo_secret = RequestSpec::http("GET", "http://127.0.0.1:9/echo");
    echo_secret.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    echo_secret.auth = anvil_domain::auth::AuthConfig::Bearer {
        token: anvil_domain::secret::SensitiveValue::template("cli-secret-token"),
        prefix: "Bearer".into(),
    };
    let echo_secret = app.create_request(&ws.meta.id, None, "SecretEcho", echo_secret).unwrap();
    app.save_load_plan(anvil_domain::load::LoadPlan {
        id: anvil_domain::Id::new(),
        workspace_id: ws.meta.id,
        name: "withdata_and_secret".into(),
        workload: anvil_domain::load::Workload::Iterations { iterations: 2, concurrency: 1 },
        chain: vec![echo_secret.meta.id],
        mix: vec![],
        dataset_id: Some(dataset.meta.id),
        environment_id: None,
        connection_mode: Default::default(),
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: now,
        updated_at: now,
    })
    .unwrap();
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
    // A name with a space: the printed command quotes it.
    let jmx = out.path().join("echo plan.jmx");
    let report = out.path().join("echo.report.json");
    let o = anvil(data, &["load", "export-jmx", "Shop", "echo", "--out", jmx.to_str().unwrap(), "--report", report.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out_txt = text(&o);
    let quoted = format!("'{}'", jmx.display());
    let shell_label = if cfg!(windows) { "PowerShell" } else { "sh" };
    let expected_bin = if cfg!(windows) {
        "& java -jar $(if ($env:JMETER_HOME) { Join-Path $env:JMETER_HOME 'bin\\ApacheJMeter.jar' } else { Join-Path (Split-Path -Parent (Get-Command jmeter -ErrorAction Stop).Source) 'ApacheJMeter.jar' })"
    } else {
        "jmeter"
    };
    assert!(out_txt.contains(&format!("run ({shell_label}): {expected_bin} -n -t {quoted} -l ")), "{out_txt}");
    assert!(out_txt.contains("-Jjmeter.save.saveservice.output_format=xml"), "{out_txt}");
    assert!(out_txt.contains("-Jjmeter.save.saveservice.url=false"), "{out_txt}");
    assert!(!out_txt.contains(" -l results.jtl"), "must print a fresh per-run JTL filename: {out_txt}");
    let plan = std::fs::read_to_string(&jmx).unwrap();
    assert!(plan.contains("<HTTPSamplerProxy") && plan.contains("jmeterTestPlan"), "{plan}");
    let r: serde_json::Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(r["expected_samples"], 4);
    assert_eq!(r["jmeter_version"], anvil_jmeter::JMETER_VERSION);

    // An existing dataset file beside the plan is replaced only with --force.
    let with_data = out.path().join("d.jmx");
    let sibling = out.path().join("d.dataset.csv");
    std::fs::write(&sibling, b"unrelated").unwrap();
    let o = anvil(data, &["load", "export-jmx", "Shop", "withdata", "--out", with_data.to_str().unwrap()]);
    assert!(!o.status.success() && text(&o).contains("--force"), "{}", text(&o));
    assert!(!with_data.exists());
    assert_eq!(std::fs::read(&sibling).unwrap(), b"unrelated");
    let o = anvil(data, &["load", "export-jmx", "Shop", "withdata", "--out", with_data.to_str().unwrap(), "--force"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(std::fs::read_to_string(&sibling).unwrap(), "\"user\"\n\"alice\"\n");
    let ds_txt = text(&o);
    if cfg!(windows) {
        assert!(
            ds_txt.contains("Set-Location -LiteralPath ")
                && ds_txt.contains(&format!("-ErrorAction Stop; {expected_bin} -n -t d.jmx"))
                && ds_txt.contains("Set-Location -LiteralPath $__p.Path }")
                && !ds_txt.contains(r"\\?\"),
            "{ds_txt}"
        );
        // Metacharacters that cmd.exe would interpret in jmeter.bat are safe because PowerShell invokes java.exe directly.
        let meta = out.path().join("a & %TEMP% ^ !x!.jmx");
        let om = anvil(data, &["load", "export-jmx", "Shop", "echo", "--out", meta.to_str().unwrap()]);
        assert_eq!(om.status.code(), Some(0), "{}", text(&om));
        let meta_txt = text(&om);
        assert!(meta_txt.contains(&format!("{expected_bin} -n -t '")), "{meta_txt}");
    } else {
        assert!(ds_txt.contains("(cd -- ") && ds_txt.contains("&& jmeter -n -t d.jmx"), "{ds_txt}");
    }

    // Two destinations naming one file are refused before anything is written.
    let same = out.path().join("same.jmx");
    let o = anvil(data, &["load", "export-jmx", "Shop", "echo", "--out", same.to_str().unwrap(), "--report", same.to_str().unwrap()]);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("name the same file"), "{}", text(&o));
    assert!(!same.exists());

    // Secret output needs an owner-only file, which only Unix creates here.
    let secrets = out.path().join("echo.secrets.properties");
    let o = anvil(
        data,
        &[
            "load",
            "export-jmx",
            "Shop",
            "echo",
            "--out",
            out.path().join("s.jmx").to_str().unwrap(),
            "--secrets-file",
            secrets.to_str().unwrap(),
        ],
    );
    if cfg!(unix) {
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
        assert!(text(&o).contains("-q <the --secrets-file you chose>") || !secrets.exists(), "{}", text(&o));
    } else {
        assert!(!o.status.success() && text(&o).contains("refused on this platform"), "{}", text(&o));
        assert!(!secrets.exists());
    }

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
    std::fs::write(&jtl, &csv).unwrap();
    // Refusing --json or --html that aliases --file protects the source JTL from overwrite.
    for flag in ["--json", "--html"] {
        let o = anvil(data, &["load", "import-jtl", "Shop", "--file", jtl.to_str().unwrap(), flag, jtl.to_str().unwrap()]);
        assert!(!o.status.success() && text(&o).contains("same path"), "{}", text(&o));
        assert_eq!(std::fs::read_to_string(&jtl).unwrap(), csv, "{flag} must not overwrite --file");
    }
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

    // Symlinked destinations (aliased report or dangling dataset sidecar) are
    // refused before writing so nothing is overwritten or followed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let real_jmx = out.path().join("alias.jmx");
        std::fs::write(&real_jmx, b"keep-me").unwrap();
        let report_link = out.path().join("alias-report.json");
        symlink(&real_jmx, &report_link).unwrap();
        let o = anvil(
            data,
            &["load", "export-jmx", "Shop", "echo", "--out", real_jmx.to_str().unwrap(), "--report", report_link.to_str().unwrap()],
        );
        assert!(!o.status.success() && text(&o).contains("symbolic link"), "{}", text(&o));
        assert_eq!(std::fs::read(&real_jmx).unwrap(), b"keep-me");

        let plan_with_dangling = out.path().join("dangling.jmx");
        let dangling_ds = out.path().join("dangling.dataset.csv");
        symlink(out.path().join("nonexistent-target.csv"), &dangling_ds).unwrap();
        let o = anvil(data, &["load", "export-jmx", "Shop", "withdata", "--out", plan_with_dangling.to_str().unwrap()]);
        assert!(!o.status.success() && text(&o).contains("symbolic link"), "{}", text(&o));
        assert!(!plan_with_dangling.exists());

        // Verify shell quoting with real `sh -c` preserves `$HOME`, spaces, and quotes verbatim.
        let tricky = out.path().join("plan $HOME 'x'.jmx");
        let o = anvil(data, &["load", "export-jmx", "Shop", "echo", "--out", tricky.to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
        let line = text(&o).lines().find(|l| l.contains("run (sh): ")).unwrap().to_string();
        let after_t = line.split(" -t ").nth(1).unwrap().split(" -l ").next().unwrap();
        let evaluated = std::process::Command::new("sh").arg("-c").arg(format!("printf %s {after_t}")).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&evaluated.stdout), tricky.to_string_lossy());
        let first_jtl = line.split(" -l ").nth(1).unwrap().split(' ').next().unwrap().to_string();

        // Back-to-back export of the same plan produces a distinct fresh JTL name.
        let o2 = anvil(data, &["load", "export-jmx", "Shop", "echo", "--out", tricky.to_str().unwrap()]);
        assert_eq!(o2.status.code(), Some(0), "{}", text(&o2));
        let line2 = text(&o2).lines().find(|l| l.contains("run (sh): ")).unwrap().to_string();
        let second_jtl = line2.split(" -l ").nth(1).unwrap().split(' ').next().unwrap().to_string();
        assert_ne!(first_jtl, second_jtl, "repeated exports must generate distinct JTL filenames");

        // An invalid --out (an existing directory) must fail BEFORE publishing --secrets-file or dataset.
        let out_dir = out.path().join("already-a-dir");
        std::fs::create_dir(&out_dir).unwrap();
        let secrets = out.path().join("must-not-exist.properties");
        let o = anvil(
            data,
            &[
                "load",
                "export-jmx",
                "Shop",
                "withdata_and_secret",
                "--out",
                out_dir.to_str().unwrap(),
                "--secrets-file",
                secrets.to_str().unwrap(),
            ],
        );
        assert!(!o.status.success() && text(&o).contains("directory"), "{}", text(&o));
        assert!(!secrets.exists(), "invalid --out must not leave secrets sidecar behind");
        assert!(!out.path().join("already-a-dir.dataset.csv").exists(), "invalid --out must not leave dataset behind");
    }
}
