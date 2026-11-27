//! JMX export (LOAD-012): what is exported, how it maps to JMeter elements,
//! and what is refused. The hosted round trip with a real Apache JMeter is
//! `tests/jmeter_roundtrip.rs` (`.github/workflows/jmeter.yml`).

mod common;

use anvil_domain::assertions::{Assertion, AssertionKind, Comparison, Extraction, ExtractionSource};
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::load::{AbortRule, Stage, WeightedStep, Workload};
use anvil_domain::request::{Body, KeyValue, Protocol, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, RedirectPolicy, SettingsOverrides};
use anvil_jmeter::{ExportOptions, ExportRefused, export};
use common::*;

fn refused(r: Result<anvil_jmeter::Export, ExportRefused>) -> ExportRefused {
    match r {
        Ok(_) => panic!("the export should have been refused"),
        Err(e) => e,
    }
}

fn codes(e: &ExportRefused) -> Vec<&'static str> {
    e.reasons.iter().map(|r| r.code).collect()
}

#[test]
fn load_012_strict_tls_request_is_refused_never_exported() {
    // Default TLS: Anvil verifies the certificate and host name.
    let (id, c) = step(RequestSpec::http("GET", "https://api.example.test/health"));
    let fx = Fx::new(iterations(4, 2), vec![(id, c, "health")], None);
    let e = refused(fx.export(&ExportOptions::default()));
    assert!(codes(&e).contains(&"strict_tls"), "{e}");
    assert!(e.to_string().contains("accept any certificate"), "{e}");

    // A TLS profile that verifies is refused the same way.
    let mut spec = RequestSpec::http("GET", "https://api.example.test/health");
    spec.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id, mut c) = step(spec);
    with_tls_profile(&mut c, true);
    let fx = Fx::new(iterations(4, 2), vec![(id, c, "health")], None);
    let e = refused(fx.export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["strict_tls"], "{e}");
}

#[test]
fn load_012_unverified_tls_profile_exports_with_the_difference_listed() {
    let mut spec = RequestSpec::http("GET", "https://127.0.0.1:8443/health");
    spec.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id, mut c) = step(spec);
    with_tls_profile(&mut c, false);
    let fx = Fx::new(iterations(4, 2), vec![(id, c, "health")], None);
    let out = fx.export(&ExportOptions::default()).expect("exported");
    assert!(out.report.differences.iter().any(|d| d.contains("turns certificate verification off")), "{:?}", out.report.differences);
    let doc = Doc::parse(&out.jmx);
    let sampler = doc.first("HTTPSamplerProxy");
    assert_eq!(doc.prop(sampler, "HTTPSampler.protocol"), "https");
    assert_eq!(doc.prop(sampler, "HTTPSampler.port"), "8443");

    // Over https the automatic version policy would negotiate HTTP/2.
    let (id, mut c) = step(RequestSpec::http("GET", "https://127.0.0.1:8443/health"));
    with_tls_profile(&mut c, false);
    let fx = Fx::new(iterations(4, 2), vec![(id, c, "health")], None);
    assert_eq!(codes(&refused(fx.export(&ExportOptions::default()))), ["http_version"]);
}

#[test]
fn load_012_unsupported_protocols_and_settings_are_refused_with_every_reason() {
    let mut ws = RequestSpec::http("GET", "ws://127.0.0.1:9/ws");
    ws.protocol = Protocol::WebSocket;
    let (id, c) = step(ws);
    let e = refused(Fx::new(iterations(1, 1), vec![(id, c, "socket")], None).export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["unsupported_protocol"], "{e}");

    let mut h2 = RequestSpec::http("POST", "http://127.0.0.1:9/graphql");
    h2.settings.http_version = Some(HttpVersionPolicy::H2c);
    h2.body = Body::GraphQl { query: "{ a }".into(), variables: String::new(), operation_name: None };
    h2.auth = AuthConfig::Multi { profiles: vec![AuthConfig::None] };
    h2.extractions.push(Extraction {
        variable: "x".into(),
        source: ExtractionSource::Regex { pattern: "a(b)".into(), group: 1 },
        sensitive: false,
    });
    let (id, c) = step(h2);
    let mut fx = Fx::new(
        Workload::ClosedVirtualUsers {
            stages: vec![Stage { duration_secs: 5, target: 4 }, Stage { duration_secs: 5, target: 1 }],
            think_time_ms: 0,
        },
        vec![(id, c, "graphql")],
        None,
    );
    fx.plan.abort = Some(AbortRule { max_failure_permille: 100, window_secs: 10 });
    let e = refused(fx.export(&ExportOptions::default()));
    let got = codes(&e);
    for want in ["abort_rule", "http_version", "body", "auth", "workload"] {
        assert!(got.contains(&want), "missing {want} in {e}");
    }
    assert!(e.reasons.iter().all(|r| !r.message.is_empty()));
}

#[test]
fn load_012_chain_maps_to_samplers_with_dataset_assertions_and_extraction() {
    let mut login = RequestSpec::http("POST", "http://127.0.0.1:8080/echo");
    login.params.push(KeyValue::new("user", "{{user}}"));
    login.headers.push(KeyValue::new("X-Run", "{{run}}"));
    login.body = Body::Json { text: r#"{"user":"{{user}}","n":{{anvil.iteration}},"price":"$5"}"#.into() };
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
    ca.var_layers.push(layer("environment", &[("run", "nightly", false)]));
    let mut next = RequestSpec::http("GET", "http://127.0.0.1:8080/status/{{code}}?via={{verb}}");
    next.assertions.push(assertion(AssertionKind::Header {
        name: "Content-Type".into(),
        comparison: Comparison::Exists,
        value: String::new(),
    }));
    let (b, cb) = step(next);
    let fx = Fx::new(iterations(10, 2), vec![(a, ca, "login"), (b, cb, "status")], Some(dataset("user,code\nalice,200\nbob,404\n")));
    let opts = ExportOptions { include_secrets: false, dataset_file: "plan.dataset.csv".into() };
    let out = fx.export(&opts).expect("exported");
    assert_eq!(out.report.expected_samples, Some(20));
    assert_eq!(out.dataset_csv.as_deref(), Some(&b"\"user\",\"code\"\n\"alice\",\"200\"\n\"bob\",\"404\"\n"[..]));
    let doc = Doc::parse(&out.jmx);

    let csv = doc.first("CSVDataSet");
    assert_eq!(doc.prop(csv, "filename"), "plan.dataset.csv");
    assert_eq!(doc.prop(csv, "variableNames"), "anvil_ds_0,anvil_ds_1");
    assert_eq!(doc.prop(csv, "shareMode"), "shareMode.all");
    let tg = doc.first("ThreadGroup");
    assert_eq!(doc.prop(tg, "ThreadGroup.num_threads"), "2");
    assert_eq!(doc.prop(tg, "LoopController.loops"), "5");

    let samplers = doc.all("HTTPSamplerProxy");
    assert_eq!(samplers.len(), 2);
    let first = samplers[0];
    assert_eq!(doc.attr(first, "testname"), "1. login");
    assert_eq!(doc.prop(first, "HTTPSampler.method"), "POST");
    assert_eq!(doc.prop(first, "HTTPSampler.domain"), "127.0.0.1");
    assert_eq!(doc.prop(first, "HTTPSampler.path"), "/echo?user=${__urlencode(${anvil_ds_0})}");
    // Literal `$` becomes ${__char(36)} because the body holds expressions.
    assert_eq!(doc.prop(first, "Argument.value"), r#"{"user":"${anvil_ds_0}","n":${anvil_iteration},"price":"${__char(36)}5"}"#);
    let headers = doc.headers(first);
    assert!(headers.contains(&("X-Run".to_string(), "nightly".to_string())), "{headers:?}");
    assert!(headers.contains(&("Content-Type".to_string(), "application/json".to_string())), "{headers:?}");
    assert!(headers.iter().any(|(n, v)| n == "User-Agent" && v.starts_with("Ferrum-Anvil/")), "{headers:?}");
    assert!(headers.contains(&("Accept-Encoding".to_string(), "gzip, deflate, br, zstd".to_string())), "{headers:?}");
    assert_eq!(doc.prop(doc.child(first, "ResponseAssertion"), "Assertion.test_field"), "Assertion.response_code");
    let json = doc.child(first, "JSONPathAssertion");
    assert_eq!(doc.prop(json, "JSON_PATH"), "$.method");
    assert_eq!(doc.prop(json, "ISREGEX"), "true");
    assert_eq!(doc.prop(doc.child(first, "JSONPostProcessor"), "JSONPostProcessor.referenceNames"), "anvil_x_0");
    // The chain gate: every step records its status for the next one.
    assert!(doc.children(first, "RegexExtractor").iter().any(|r| doc.prop(*r, "RegexExtractor.refname") == "anvil_rc"));

    let second = samplers[1];
    assert_eq!(doc.prop(second, "HTTPSampler.path"), "/status/${anvil_ds_1}?via=${anvil_x_0}");
    let gate = doc.parent_of(second, "IfController");
    assert_eq!(doc.prop(gate, "IfController.condition"), r#"${__jexl3("${anvil_rc}" != "none")}"#);
    assert_eq!(doc.prop(gate, "IfController.useExpression"), "true");
    let counter = doc.first("CounterConfig");
    assert_eq!(doc.prop(counter, "CounterConfig.name"), "anvil_iteration");
    assert!(out.report.secret_properties.is_empty() && out.secrets_properties.is_none());
    assert!(out.report.mapping.iter().any(|m| m.anvil.contains("dataset")));
}

#[test]
fn load_012_secrets_are_properties_and_written_only_on_the_secret_export_path() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/echo");
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::template("{{token}}"), prefix: "Bearer".into() };
    spec.headers.push(KeyValue::new("X-Api-Key", "literal-key-SENSITIVE"));
    spec.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let (id, mut c) = step(spec);
    c.var_layers.push(layer("workspace", &[("token", "tok-SENSITIVE-value", true)]));
    let fx = Fx::new(iterations(2, 1), vec![(id, c, "echo")], None);
    let out = fx.export(&ExportOptions::default()).expect("exported");
    assert!(!out.jmx.contains("SENSITIVE"), "no secret material in the .jmx");
    assert!(out.secrets_properties.is_none());
    let names: Vec<&str> = out.report.secret_properties.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"anvil.secret.var.token"), "{names:?}");
    assert!(names.iter().any(|n| n.starts_with("anvil.secret.header.echo.x-api-key")), "{names:?}");
    let doc = Doc::parse(&out.jmx);
    let headers = doc.headers(doc.first("HTTPSamplerProxy"));
    assert!(headers.contains(&("Authorization".to_string(), "Bearer ${__P(anvil.secret.var.token,)}".to_string())), "{headers:?}");
    // The guard stops the test before any traffic when a property is missing.
    let guard = doc.first("SetupThreadGroup");
    let cond = doc.prop(doc.child(guard, "IfController"), "IfController.condition");
    assert!(cond.contains("!${__isPropDefined(anvil.secret.var.token)}"), "{cond}");

    let out = fx.export(&ExportOptions { include_secrets: true, ..Default::default() }).expect("exported");
    assert!(!out.jmx.contains("SENSITIVE"));
    let props = out.secrets_properties.expect("secrets written");
    assert!(props.contains("anvil.secret.var.token=tok-SENSITIVE-value\n"), "{}", props.as_str());
    assert!(props.contains("=literal-key-SENSITIVE\n"), "{}", props.as_str());
    assert!(out.report.secrets_written);
}

#[test]
fn load_012_credentials_that_follow_redirects_are_refused() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/echo");
    spec.auth = AuthConfig::ApiKey { name: "X-Key".into(), value: SensitiveValue::template("{{k}}"), location: KeyLocation::Header };
    let (id, mut c) = step(spec);
    c.var_layers.push(layer("workspace", &[("k", "v", true)]));
    let e = refused(Fx::new(iterations(1, 1), vec![(id, c, "echo")], None).export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["redirect_credentials"], "{e}");
}

#[test]
fn load_012_workloads_become_thread_groups() {
    let (id, c) = step(RequestSpec::http("GET", "http://127.0.0.1:8080/"));
    // Closed: a step to 2, a ramp to 6 over 10 s, a hold: two thread groups.
    let closed = Workload::ClosedVirtualUsers {
        stages: vec![Stage { duration_secs: 0, target: 2 }, Stage { duration_secs: 10, target: 6 }, Stage { duration_secs: 20, target: 6 }],
        think_time_ms: 250,
    };
    let out = Fx::new(closed, vec![(id, c.clone(), "root")], None).export(&ExportOptions::default()).expect("exported");
    let doc = Doc::parse(&out.jmx);
    let groups = doc.all("ThreadGroup");
    assert_eq!(groups.len(), 2);
    let read = |g, p| doc.prop(g, p);
    assert_eq!((read(groups[0], "ThreadGroup.num_threads"), read(groups[0], "ThreadGroup.ramp_time")), ("2".into(), "0".into()));
    assert_eq!((read(groups[0], "ThreadGroup.delay"), read(groups[0], "ThreadGroup.duration")), ("0".into(), "30".into()));
    assert_eq!((read(groups[1], "ThreadGroup.num_threads"), read(groups[1], "ThreadGroup.ramp_time")), ("4".into(), "10".into()));
    assert_eq!((read(groups[1], "ThreadGroup.delay"), read(groups[1], "ThreadGroup.duration")), ("0".into(), "30".into()));
    assert_eq!(read(groups[0], "ThreadGroup.scheduler"), "true");
    let think = doc.child(groups[0], "TestAction");
    assert_eq!((read(think, "ActionProcessor.action"), read(think, "ActionProcessor.duration")), ("1".into(), "250".into()));

    // Open: the open model's schedule, with Anvil's 5 s graceful stop.
    let open = Workload::OpenArrivalRate {
        stages: vec![Stage { duration_secs: 0, target: 5 }, Stage { duration_secs: 30, target: 5 }],
        max_in_flight: 50,
    };
    let out = Fx::new(open, vec![(id, c.clone(), "root")], None).export(&ExportOptions::default()).expect("exported");
    let doc = Doc::parse(&out.jmx);
    let g = doc.first("OpenModelThreadGroup");
    assert_eq!(doc.prop(g, "OpenModelThreadGroup.schedule"), "rate(0/s) rate(5/s) even_arrivals(30 s) rate(5/s) pause(5 s)");
    assert!(out.report.differences.iter().any(|d| d.contains("drops (and counts) an arrival")));

    // Iterations that do not divide among the lanes: a shared counter gate.
    let out = Fx::new(iterations(7, 3), vec![(id, c, "root")], None).export(&ExportOptions::default()).expect("exported");
    let doc = Doc::parse(&out.jmx);
    let tg = doc.first("ThreadGroup");
    assert_eq!((doc.prop(tg, "ThreadGroup.num_threads"), doc.prop(tg, "LoopController.loops")), ("3".into(), "3".into()));
    let gate = doc.child(tg, "IfController");
    assert_eq!(doc.prop(gate, "IfController.condition"), "${__jexl3(${__counter(FALSE,)} <= 7)}");
}

#[test]
fn load_012_weighted_mix_uses_a_random_variable_and_if_controllers() {
    let (a, ca) = step(RequestSpec::http("GET", "http://127.0.0.1:8080/a"));
    let (b, cb) = step(RequestSpec::http("GET", "http://127.0.0.1:8080/b"));
    let mut fx = Fx::new(iterations(10, 2), vec![(a, ca, "a"), (b, cb, "b")], None);
    fx.plan.chain.clear();
    fx.plan.mix = vec![WeightedStep { request_id: a, weight: 3 }, WeightedStep { request_id: b, weight: 1 }];
    let out = fx.export(&ExportOptions::default()).expect("exported");
    let doc = Doc::parse(&out.jmx);
    assert_eq!(doc.prop(doc.first("RandomVariableConfig"), "maximumValue"), "4");
    let ifs: Vec<String> = doc.all("IfController").into_iter().map(|n| doc.prop(n, "IfController.condition")).collect();
    assert_eq!(ifs, ["${__jexl3(${anvil_pick} > 0 && ${anvil_pick} <= 3)}", "${__jexl3(${anvil_pick} > 3 && ${anvil_pick} <= 4)}"]);
    assert_eq!(out.report.expected_samples, Some(10));
}

#[test]
fn load_012_dynamic_helpers_map_or_are_refused_where_used() {
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:8080/echo");
    spec.body = Body::Raw { text: "{{$uuid}} {{$randomInt 1 6}} {{$timestamp}}".into(), content_type: Some("text/plain".into()) };
    let (id, mut c) = step(spec);
    // An unsupported helper in an unused variable does not matter.
    c.var_layers.push(layer("workspace", &[("unused", "{{$isoTimestamp}}", false)]));
    let out = Fx::new(iterations(1, 1), vec![(id, c, "echo")], None).export(&ExportOptions::default()).expect("exported");
    let doc = Doc::parse(&out.jmx);
    assert_eq!(doc.prop(doc.first("HTTPSamplerProxy"), "Argument.value"), "${__UUID()} ${__Random(1,6,)} ${__time(/1000,)}");

    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/echo?at={{$isoTimestamp}}");
    spec.method = "GET".into();
    let (id, c) = step(spec);
    let e = refused(Fx::new(iterations(1, 1), vec![(id, c, "echo")], None).export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["dynamic_helper"], "{e}");
}

#[test]
fn load_012_basic_auth_uses_a_scoped_authorization_manager() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/auth/basic");
    spec.auth = AuthConfig::Basic { username: "ann".into(), password: SensitiveValue::template("{{pw}}") };
    let (id, mut c) = step(spec);
    c.var_layers.push(layer("workspace", &[("pw", "pw-SENSITIVE", true)]));
    let out = Fx::new(iterations(1, 1), vec![(id, c, "basic")], None).export(&ExportOptions::default()).expect("exported");
    assert!(!out.jmx.contains("SENSITIVE"));
    let doc = Doc::parse(&out.jmx);
    let auth = doc.child(doc.first("HTTPSamplerProxy"), "AuthManager");
    assert_eq!(doc.prop(auth, "Authorization.url"), "http://127.0.0.1:8080/");
    assert_eq!(doc.prop(auth, "Authorization.username"), "ann");
    assert_eq!(doc.prop(auth, "Authorization.password"), "${__P(anvil.secret.var.pw,)}");
}

#[test]
fn load_012_assertions_without_an_equivalent_are_refused() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/");
    spec.assertions.push(assertion(AssertionKind::Body { comparison: Comparison::Matches, value: "a+".into() }));
    spec.assertions.push(assertion(AssertionKind::JsonPath {
        path: "$..a[?(@.b)]".into(),
        comparison: Comparison::Exists,
        value: String::new(),
    }));
    spec.assertions.push(assertion(AssertionKind::JsonSchema { schema: "{}".into() }));
    let (id, c) = step(spec);
    let e = refused(Fx::new(iterations(1, 1), vec![(id, c, "root")], None).export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["assertion", "assertion", "assertion"], "{e}");
}

#[test]
fn load_012_a_plan_settings_override_layer_is_respected() {
    // Settings come from every layer, as at send: a workspace layer that
    // turns on HTTP/2 refuses the plan even though the request is silent.
    let (id, mut c) = step(RequestSpec::http("GET", "http://127.0.0.1:8080/"));
    c.settings_layers
        .insert(0, ("workspace".into(), SettingsOverrides { http_version: Some(HttpVersionPolicy::Http2Only), ..Default::default() }));
    let e = refused(Fx::new(iterations(1, 1), vec![(id, c, "root")], None).export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["http_version"]);
}
