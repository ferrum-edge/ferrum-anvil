//! JTL import (LOAD-012): JMeter's CSV and XML result files become Anvil
//! load reports with balanced ledgers; untrusted input is bounded and
//! entity expansion is impossible.

use anvil_domain::Id;
use anvil_domain::load::LoadReport;
use anvil_jmeter::{JtlError, JtlLimits, JtlOptions, import_jtl};
use anvil_load::report::{Integrity, check_balance, check_protocol_balance, check_request_balance, open_json, to_json};
use std::io::Cursor;

const T0: i64 = 1_790_000_000_000;

fn opts() -> JtlOptions {
    JtlOptions {
        workspace_id: Id::new(),
        plan: None,
        source_name: "results.jtl".into(),
        jmeter_version: Some("5.6.3".into()),
        warmup_secs: None,
        limits: JtlLimits::default(),
    }
}

fn import(text: &str, o: &JtlOptions) -> Result<LoadReport, JtlError> {
    import_jtl(Cursor::new(text.as_bytes().to_vec()), o)
}

fn balanced(r: &LoadReport) {
    check_balance(&r.counts).unwrap();
    check_request_balance(&r.requests).unwrap();
    check_protocol_balance(r).unwrap();
}

const CSV_HEADER: &str = "timeStamp,elapsed,label,responseCode,responseMessage,threadName,dataType,success,failureMessage,bytes,sentBytes,grpThreads,allThreads,URL,Latency,IdleTime,Connect\n";

/// Six samples: two successes, a 404, an assertion failure on a 200, a
/// refused connection and a read timeout.
fn csv_results() -> String {
    let row = |dt: i64, el: u64, code: &str, ok: bool, fail: &str, url: &str| {
        format!("{},{el},1. login,{code},msg,G 1-1,text,{ok},{fail},120,80,2,2,{url},1,0,0\n", T0 + dt)
    };
    let mut s = String::from(CSV_HEADER);
    s += &row(0, 10, "200", true, "", "http://127.0.0.1:8080/echo?user=alice");
    s += &row(100, 30, "200", true, "", "http://127.0.0.1:8080/echo");
    s += &row(1_200, 20, "404", false, "", "http://127.0.0.1:8080/status/404");
    s += &row(1_300, 25, "200", false, "\"Test failed: text expected to contain /x/\"", "http://127.0.0.1:8080/echo");
    s += &row(2_100, 3, "Non HTTP response code: java.net.ConnectException", false, "\"Connection refused\"", "http://127.0.0.1:8080/echo");
    s += &row(
        2_200,
        5_000,
        "Non HTTP response code: java.net.SocketTimeoutException",
        false,
        "\"Read timed out\"",
        "http://127.0.0.1:8080/slow",
    );
    s
}

fn xml_results() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<testResults version="1.2">
<httpSample t="10" it="0" lt="1" ct="0" ts="{a}" s="true" lb="1. login" rc="200" rm="OK" tn="G 1-1" dt="text" by="120" sby="80" ng="2" na="2">
  <java.net.URL>http://127.0.0.1:8080/echo?user=alice&amp;x=1</java.net.URL>
</httpSample>
<httpSample t="30" it="0" lt="1" ct="0" ts="{b}" s="true" lb="1. login" rc="200" rm="OK" tn="G 1-1" dt="text" by="120" sby="80" ng="2" na="2">
  <httpSample t="5" ts="{b}" s="true" lb="1. login-0" rc="302" rm="Found" by="10" sby="10"/>
  <httpSample t="25" ts="{b}" s="true" lb="1. login-1" rc="200" rm="OK" by="110" sby="70"><responseData class="java.lang.String">body</responseData></httpSample>
</httpSample>
<httpSample t="20" ts="{c}" s="false" lb="1. login" rc="404" rm="Not Found" by="120" sby="80" na="2"/>
<httpSample t="25" ts="{d}" s="false" lb="1. login" rc="200" rm="OK" by="120" sby="80" na="2">
  <assertionResult>
    <name>body &lt;contains&gt; x</name>
    <failure>true</failure>
    <error>false</error>
    <failureMessage>Test failed: text expected to contain /x/</failureMessage>
  </assertionResult>
</httpSample>
<httpSample t="3" ts="{e}" s="false" lb="1. login" rc="Non HTTP response code: java.net.ConnectException" rm="Connection refused" by="120" sby="80" na="2"/>
<httpSample t="5000" ts="{f}" s="false" lb="1. login" rc="Non HTTP response code: java.net.SocketTimeoutException" rm="Read timed out" by="120" sby="80" na="2"/>
</testResults>
"#,
        a = T0,
        b = T0 + 100,
        c = T0 + 1_200,
        d = T0 + 1_300,
        e = T0 + 2_100,
        f = T0 + 2_200
    )
}

fn check_six(r: &LoadReport) {
    balanced(r);
    let q = &r.requests;
    assert_eq!((q.started, q.completed, q.transport_failures, q.timeouts), (6, 4, 1, 1), "{q:?}");
    assert_eq!((q.application_failures, q.assertion_failures), (1, 1), "{q:?}");
    assert_eq!(r.counts.started, 6);
    assert_eq!(r.status_distribution, vec![(200, 3), (404, 1)]);
    assert_eq!(r.latency_success.count, 2);
    assert_eq!((r.latency_success.min_us, r.latency_success.max_us), (10_000, 30_000));
    // Failed units: the 404, the assertion failure and the refused connection.
    assert_eq!(r.latency_failure.count, 3);
    assert_eq!(r.timeouts_censored.count, 1);
    assert_eq!(r.timeouts_censored.elapsed_at_timeout.max_us, 5_000_000);
    assert_eq!(r.engine, "apache-jmeter");
    assert_eq!(r.destination_summary, vec!["http://127.0.0.1:8080".to_string()]);
    assert_eq!(r.protocols, vec![("http/1.1".to_string(), 6)]);
    assert_eq!(r.bytes_received, 6 * 120);
    let cats: Vec<&str> = r.failure_categories.iter().map(|c| c.category.as_str()).collect();
    assert!(cats.contains(&"application_failure: http 404"), "{cats:?}");
    assert!(cats.contains(&"transport_failure: java.net.ConnectException"), "{cats:?}");
    assert!(cats.contains(&"timeout: java.net.SocketTimeoutException"), "{cats:?}");
    assert!(cats.iter().any(|c| c.starts_with("assertion_failure: ")), "{cats:?}");
    // Failure messages (which can quote response bodies) are never kept.
    let examples = serde_json::to_string(&r.failure_categories).unwrap();
    assert!(!examples.contains("expected to contain"), "{examples}");
    // Timeline: 3 seconds of samples, every sample started once.
    assert_eq!(r.timeline.iter().map(|b| b.started).sum::<u64>(), 6);
    assert!(r.timeline.len() >= 3 && r.timeline.len() <= 9, "{}", r.timeline.len());
    let p = r.protocol_metrics.as_ref().unwrap();
    assert!(p.semantics.latency_means.contains("whole milliseconds"));
    // The report is sealed and reopens verified.
    let (back, integrity) = open_json(&to_json(r)).unwrap();
    assert_eq!(integrity, Integrity::Verified);
    assert_eq!(back.requests, r.requests);
}

#[test]
fn load_012_jtl_csv_import_counts_like_the_unit_ledger() {
    let r = import(&csv_results(), &opts()).unwrap();
    check_six(&r);
    assert!(r.engine_version.contains("5.6.3") && r.engine_version.ends_with("+jtl-csv"), "{}", r.engine_version);
    assert!(!r.plan.trusted, "a synthesized plan is never trusted");
}

#[test]
fn load_012_jtl_xml_import_matches_csv_and_skips_sub_results() {
    let r = import(&xml_results(), &opts()).unwrap();
    check_six(&r);
    assert!(r.engine_version.ends_with("+jtl-xml"));
    assert!(r.notes.iter().any(|n| n.contains("2 sub-result(s)")), "{:?}", r.notes);
    let cats: Vec<&str> = r.failure_categories.iter().map(|c| c.category.as_str()).collect();
    assert!(cats.contains(&"assertion_failure: body <contains> x"), "{cats:?}");
}

#[test]
fn load_012_jtl_import_carries_the_plan_and_excludes_its_warmup() {
    let mut o = opts();
    let mut plan = anvil_domain::load::LoadPlan {
        id: Id::new(),
        workspace_id: o.workspace_id,
        name: "exported".into(),
        workload: anvil_domain::load::Workload::Iterations { iterations: 6, concurrency: 2 },
        chain: vec![Id::new()],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: Default::default(),
        warmup_secs: 1,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: anvil_domain::Timestamp::now(),
        updated_at: anvil_domain::Timestamp::now(),
    };
    o.plan = Some(plan.clone());
    let r = import(&csv_results(), &o).unwrap();
    balanced(&r);
    assert_eq!(r.plan.id, plan.id);
    assert_eq!(r.warmup_sends_excluded, 2);
    assert_eq!(r.requests.started, 4);
    assert!(r.timeline[0].warmup && !r.timeline[2].warmup);
    plan.warmup_secs = 0;
    o.plan = Some(plan);
    o.warmup_secs = Some(0);
    assert_eq!(import(&csv_results(), &o).unwrap().requests.started, 6);
}

#[test]
fn load_012_jtl_refuses_doctype_and_never_expands_entities() {
    let laughs = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<testResults version="1.2"><httpSample t="1" ts="1790000000000" s="true" lb="&lol2;" rc="200"/></testResults>"#;
    let e = import(laughs, &opts()).unwrap_err();
    assert!(e.to_string().contains("DOCTYPE"), "{e}");

    let external = r#"<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<testResults><httpSample t="1" ts="1790000000000" s="true" lb="&xxe;" rc="200"/></testResults>"#;
    assert!(import(external, &opts()).unwrap_err().to_string().contains("DOCTYPE"));

    // Without a DTD an undeclared entity is an error, never expanded.
    let undeclared = r#"<testResults><httpSample t="1" ts="1790000000000" s="true" lb="&xxe;" rc="200"/></testResults>"#;
    assert!(matches!(import(undeclared, &opts()).unwrap_err(), JtlError::Invalid(_)));
    let in_text = r#"<testResults><httpSample t="1" ts="1790000000000" s="true" lb="a" rc="200"><java.net.URL>&xxe;</java.net.URL></httpSample></testResults>"#;
    assert!(import(in_text, &opts()).unwrap_err().to_string().contains("never expanded"));
}

#[test]
fn load_012_jtl_limits_are_enforced_with_clear_errors() {
    let small = |f: fn(&mut JtlLimits)| {
        let mut o = opts();
        f(&mut o.limits);
        o
    };
    let e = import(&csv_results(), &small(|l| l.max_bytes = 100)).unwrap_err();
    assert!(matches!(e, JtlError::TooLarge { limit: 100 }), "{e}");
    let e = import(&csv_results(), &small(|l| l.max_samples = 5)).unwrap_err();
    assert!(matches!(e, JtlError::TooManySamples { limit: 5 }), "{e}");

    // One enormous record is refused while it is read.
    let mut huge = String::from(CSV_HEADER);
    huge += &format!("{T0},1,{},200,OK,t,text,true,,1,1,1,1,http://h/,1,0,0\n", "x".repeat(300 * 1024));
    let e = import(&huge, &small(|l| l.max_record_bytes = 128 * 1024)).unwrap_err();
    assert!(matches!(e, JtlError::RecordTooLong { .. }), "{e}");
    let tag = format!(r#"<testResults><httpSample t="1" ts="{T0}" s="true" lb="{}" rc="200"/></testResults>"#, "x".repeat(300 * 1024));
    let e = import(&tag, &small(|l| l.max_record_bytes = 128 * 1024)).unwrap_err();
    assert!(matches!(e, JtlError::RecordTooLong { .. }), "{e}");

    let deep = format!("<testResults>{}</testResults>", "<a>".repeat(40) + &"</a>".repeat(40));
    assert!(import(&deep, &opts()).is_err());
}

#[test]
fn load_012_jtl_rejects_what_it_cannot_read_faithfully() {
    // A formatted timestamp instead of milliseconds.
    let mut s = String::from(CSV_HEADER);
    s += "2026/11/27 10:00:00,1,a,200,OK,t,text,true,,1,1,1,1,http://h/,1,0,0\n";
    let e = import(&s, &opts()).unwrap_err();
    assert!(e.to_string().contains("timestamp_format"), "{e}");
    // Missing required columns.
    let e = import("timeStamp,elapsed,label\n1790000000000,1,a\n", &opts()).unwrap_err();
    assert!(e.to_string().contains("responseCode"), "{e}");
    // A non-HTTP sample.
    let e = import(r#"<testResults><sample t="1" ts="1790000000000" s="true" lb="jdbc" rc="200"/></testResults>"#, &opts()).unwrap_err();
    assert!(e.to_string().contains("non-HTTP"), "{e}");
    let mut s = String::from(CSV_HEADER);
    s += &format!("{T0},1,jdbc,200,OK,t,text,true,,1,1,1,1,null,1,0,0\n");
    assert!(import(&s, &opts()).unwrap_err().to_string().contains("not an HTTP URL"));
    // Empty input and a file with only a header.
    assert!(import("", &opts()).is_err());
    assert!(import(CSV_HEADER, &opts()).unwrap_err().to_string().contains("no samples"));
    // A ragged CSV row.
    let mut s = String::from(CSV_HEADER);
    s += &format!("{T0},1,a,200\n");
    assert!(import(&s, &opts()).is_err());
}

#[test]
fn load_012_jtl_truncated_xml_is_never_a_completed_run() {
    let full = xml_results();
    // An interrupted run: no closing </testResults>.
    let cut = full.trim_end().strip_suffix("</testResults>").unwrap().to_string();
    let e = import(&cut, &opts()).unwrap_err();
    assert!(e.to_string().contains("truncated"), "{e}");
    // A sample still open at the end.
    let open = format!(r#"<testResults><httpSample t="1" ts="{T0}" s="true" lb="a" rc="200"><assertionResult>"#);
    assert!(import(&open, &opts()).unwrap_err().to_string().contains("truncated"));
    // Anything after the root.
    let after = format!("{full}<testResults/>");
    assert!(import(&after, &opts()).unwrap_err().to_string().contains("after </testResults>"));
}

#[test]
fn load_012_jtl_csv_samples_must_show_they_are_http() {
    // No URL column: nothing shows the samples are HTTP (a JDBC sample also writes 200).
    let e = import(&format!("timeStamp,elapsed,label,responseCode,success\n{T0},1,jdbc,200,true\n"), &opts()).unwrap_err();
    assert!(e.to_string().contains("'URL' column") && e.to_string().contains("XML"), "{e}");
    // An empty URL.
    let mut s = String::from(CSV_HEADER);
    s += &format!("{T0},1,jdbc,200,OK,t,text,true,,1,1,1,1,,1,0,0\n");
    assert!(import(&s, &opts()).unwrap_err().to_string().contains("has no URL"));
}

#[test]
fn load_012_jtl_record_limit_is_exact() {
    let mut o = opts();
    o.limits.max_record_bytes = 1_000;
    let row = |label_len: usize| format!("{T0},1,{},200,OK,t,text,true,,1,1,1,1,http://h/,1,0,0\n", "x".repeat(label_len));
    // Under the limit: accepted; just over it (within the read-ahead allowance): refused.
    assert!(import(&format!("{CSV_HEADER}{}", row(900)), &o).is_ok());
    let e = import(&format!("{CSV_HEADER}{}", row(1_000)), &o).unwrap_err();
    assert!(matches!(e, JtlError::RecordTooLong { limit: 1_000, .. }), "{e}");
    let tag = |n: usize| format!(r#"<testResults><httpSample t="1" ts="{T0}" s="true" lb="{}" rc="200"/></testResults>"#, "x".repeat(n));
    assert!(import(&tag(900), &o).is_ok());
    assert!(matches!(import(&tag(1_000), &o).unwrap_err(), JtlError::RecordTooLong { limit: 1_000, .. }));
    // The CSV header row itself obeys max_record_bytes.
    let huge_header = format!("timeStamp,elapsed,label,responseCode,success,URL,{}\n{T0},1,a,200,true,http://h/,v\n", "c".repeat(1_000));
    assert!(matches!(import(&huge_header, &o).unwrap_err(), JtlError::RecordTooLong { limit: 1_000, .. }));
}

#[test]
fn load_012_jtl_url_credentials_are_never_retained_and_empty_depth_and_overflow_are_enforced() {
    // Rejected non-HTTP URL with credentials must not quote the credential in the error.
    let mut bad = String::from(CSV_HEADER);
    bad += &format!("{T0},1,a,200,OK,t,text,true,,1,1,1,1,ftp://user:TOPSECRET@example.test/x,1,0,0\n");
    let err = import(&bad, &opts()).unwrap_err().to_string();
    assert!(err.contains("not an HTTP URL") && !err.contains("TOPSECRET"), "{err}");

    // Long userinfo (> 1024 chars) before '@' must be stripped before bounding,
    // never turning the userinfo into a destination.
    let long_user = format!("u:{}SECRET", "a".repeat(1200));
    let mut csv_u = String::from(CSV_HEADER);
    csv_u += &format!("{T0},1,a,200,OK,t,text,true,,1,1,1,1,http://{long_user}@127.0.0.1:8080/path?api_key=KSECRET,1,0,0\n");
    let r = import(&csv_u, &opts()).unwrap();
    assert_eq!(r.destination_summary, vec!["http://127.0.0.1:8080".to_string()]);
    assert!(!serde_json::to_string(&r).unwrap().contains("SECRET"));

    // XML empty element at depth + 1 > max_depth inside a valid sample is rejected by depth check.
    let mut o = opts();
    o.limits.max_depth = 3;
    let empty_deep = format!(
        r#"<testResults><httpSample t="1" ts="{T0}" s="true" lb="a" rc="200"><assertionResult><name/></assertionResult></httpSample></testResults>"#
    );
    let err = import(&empty_deep, &o).unwrap_err().to_string();
    assert!(err.contains("nest deeper than 3"), "{err}");

    // Aggregate byte counts that overflow u64 are rejected cleanly instead of panicking/wrapping.
    let mut ovf = String::from(CSV_HEADER);
    ovf += &format!("{T0},1,a,200,OK,t,text,true,,{},1,1,1,http://127.0.0.1:8080/,1,0,0\n", u64::MAX);
    ovf += &format!("{},1,a,200,OK,t,text,true,,10,1,1,1,http://127.0.0.1:8080/,1,0,0\n", T0 + 10);
    let err = import(&ovf, &opts()).unwrap_err().to_string();
    assert!(err.contains("overflows"), "{err}");
}
