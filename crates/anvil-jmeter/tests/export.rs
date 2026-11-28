//! JMX export (LOAD-012): what is exported, how it maps to JMeter elements,
//! and what is refused. The hosted round trip with a real Apache JMeter is
//! `tests/jmeter_roundtrip.rs` (`.github/workflows/jmeter.yml`).

mod common;

use anvil_domain::assertions::{AssertionKind, Comparison, Extraction, ExtractionSource};
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::load::{AbortRule, ConnectionMode, Stage, WeightedStep, Workload};
use anvil_domain::request::{Body, KeyValue, LintSendPolicy, Protocol, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, RedirectPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_jmeter::{ExportOptions, ExportRefused};
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
    // Per-iteration values in a JSON body need a non-blocking lint policy.
    login.lint_policy = LintSendPolicy::Warn;
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
    assert_eq!(doc.prop(csv, "filename"), "./plan.dataset.csv");
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
    assert!(headers.contains(&("Accept-Encoding".to_string(), "gzip, deflate, br".to_string())), "{headers:?}");
    assert!(out.report.differences.iter().any(|d| d.contains("cannot decode zstd")));
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
    // Never printed, even on failure.
    assert!(props.contains("anvil.secret.var.token=tok-SENSITIVE-value\n"));
    assert!(props.contains("=literal-key-SENSITIVE\n"));
    assert!(out.report.secrets_written);
}

#[test]
fn load_012_credentials_that_follow_redirects_are_refused() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/echo");
    spec.auth = AuthConfig::ApiKey { name: "X-Key".into(), value: SensitiveValue::template("{{k}}"), location: KeyLocation::Header };
    spec.settings.redirects = Some(RedirectPolicy::default());
    spec.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id, mut c) = step(spec);
    with_tls_profile(&mut c, false);
    c.var_layers.push(layer("workspace", &[("k", "v", true)]));
    let e = refused(Fx::new(iterations(1, 1), vec![(id, c, "echo")], None).export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["redirect_credentials", "redirect_destination_policy"], "{e}");
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
        // 5/s × the default 120 s total deadline: Anvil's cap never binds.
        max_in_flight: 600,
    };
    let mut fx = Fx::new(open, vec![(id, c.clone(), "root")], None);
    fx.plan.connection_mode = ConnectionMode::Fresh;
    let out = fx.export(&ExportOptions::default()).expect("exported");
    let doc = Doc::parse(&out.jmx);
    let g = doc.first("OpenModelThreadGroup");
    assert_eq!(doc.prop(g, "OpenModelThreadGroup.schedule"), "rate(0/s) rate(5/s) even_arrivals(30 s) rate(5/s) pause(5 s)");
    assert!(out.report.differences.iter().any(|d| d.contains("never drops an arrival")));

    // Iterations that do not divide among the lanes: gated by the same shared CounterConfig.
    let out = Fx::new(iterations(7, 3), vec![(id, c, "root")], None).export(&ExportOptions::default()).expect("exported");
    let doc = Doc::parse(&out.jmx);
    let tg = doc.first("ThreadGroup");
    assert_eq!((doc.prop(tg, "ThreadGroup.num_threads"), doc.prop(tg, "LoopController.loops")), ("3".into(), "3".into()));
    let counter = doc.child(tg, "CounterConfig");
    assert_eq!(doc.prop(counter, "CounterConfig.start"), "0");
    assert_eq!(doc.prop(counter, "CounterConfig.name"), "anvil_iteration");
    let gate = doc.child(tg, "IfController");
    assert_eq!(doc.prop(gate, "IfController.condition"), "${__jexl3(${anvil_iteration} < 7)}");
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

// ------------------------------------------------------------ review findings

fn export_codes(fx: &Fx) -> Vec<&'static str> {
    match fx.export(&ExportOptions::default()) {
        Ok(_) => vec![],
        Err(e) => e.reasons.iter().map(|r| r.code).collect(),
    }
}

fn following(spec: &mut RequestSpec) {
    spec.settings.redirects = Some(RedirectPolicy::default());
}

#[test]
fn load_012_redirects_that_can_reach_https_are_refused_unless_https_behaves_alike() {
    // A cleartext request that follows redirects: refused both because JMeter
    // cannot enforce Anvil's per-hop destination network-zone policy AND
    // because a redirect can lead to https, which Anvil verifies and JMeter would not.
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/redirect");
    following(&mut spec);
    let (id, c) = step(spec.clone());
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "r")], None)), ["redirect_destination_policy", "redirect_tls"]);
    // A TLS profile that verifies is not enough, nor HTTP/1.1 alone.
    spec.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id, mut c) = step(spec.clone());
    with_tls_profile(&mut c, true);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "r")], None)), ["redirect_destination_policy", "redirect_tls"]);
    // Even with verification off and HTTP/1.1 only, redirect-following is still
    // refused because JMeter cannot enforce Anvil's per-hop destination policy.
    let (id, mut c) = step(spec);
    with_tls_profile(&mut c, false);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "r")], None)), ["redirect_destination_policy"]);
}

#[test]
fn load_012_redirected_methods_other_than_get_and_head_are_refused() {
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:8080/echo");
    following(&mut spec);
    spec.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id, mut c) = step(spec);
    with_tls_profile(&mut c, false);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "post")], None)), ["redirect_destination_policy", "redirect_method"]);
}

#[test]
fn load_012_credentials_in_the_url_query_never_reach_the_test_plan() {
    let (id, c) = step(RequestSpec::http("GET", "http://127.0.0.1:8080/echo?page=2&access%5Ftoken=lit-SENSITIVE"));
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "q")], None)), ["url_credential"]);
    // A secret variable there becomes a property.
    let (id, mut c) = step(RequestSpec::http("GET", "http://127.0.0.1:8080/echo?access_token={{tok}}"));
    c.var_layers.push(layer("workspace", &[("tok", "tok-SENSITIVE", true)]));
    let out = Fx::new(iterations(1, 1), vec![(id, c, "q")], None).export(&ExportOptions::default()).expect("exported");
    assert!(!out.jmx.contains("SENSITIVE"));
    let doc = Doc::parse(&out.jmx);
    assert_eq!(doc.prop(doc.first("HTTPSamplerProxy"), "HTTPSampler.path"), "/echo?access_token=${__P(anvil.secret.var.tok,)}");
}

#[test]
fn load_012_open_workloads_need_a_cap_that_never_binds_and_fresh_connections() {
    let open = |cap: u64| Workload::OpenArrivalRate {
        stages: vec![Stage { duration_secs: 0, target: 10 }, Stage { duration_secs: 5, target: 10 }],
        max_in_flight: cap,
    };
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/");
    spec.settings.timeouts = Some(TimeoutOverrides { total_ms: Some(Some(2_000)), ..Default::default() });
    let (id, c) = step(spec);
    let fx = |cap: u64, mode: ConnectionMode| {
        let mut f = Fx::new(open(cap), vec![(id, c.clone(), "root")], None);
        f.plan.connection_mode = mode;
        f
    };
    // 10/s for 5 s = 50 total possible arrivals. JMeter's socket read timeout
    // does not bound a slow-streaming response, so 20 (10/s * 2s) is NOT safe;
    // only a cap >= 50 guarantees Anvil's cap never binds.
    assert_eq!(export_codes(&fx(5, ConnectionMode::Fresh)), ["open_cap"]);
    assert_eq!(export_codes(&fx(20, ConnectionMode::Fresh)), ["open_cap"]);
    assert!(export_codes(&fx(50, ConnectionMode::Fresh)).is_empty());
    assert_eq!(export_codes(&fx(50, ConnectionMode::Persistent)), ["open_connections"]);
}

#[test]
fn load_012_accept_encoding_jmeter_cannot_decode_is_refused() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/");
    spec.headers.push(KeyValue::new("Accept-Encoding", "zstd, gzip"));
    let (id, c) = step(spec);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "root")], None)), ["accept_encoding"]);
    // Asked for, but left encoded by Anvil (decompression off): JMeter would decode.
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/");
    spec.headers.push(KeyValue::new("Accept-Encoding", "gzip"));
    spec.settings.decompress = Some(false);
    let (id, c) = step(spec);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "root")], None)), ["accept_encoding"]);
}

#[test]
fn load_012_per_iteration_json_under_a_blocking_lint_policy_is_refused() {
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:8080/echo");
    spec.body = Body::Json { text: r#"{"user":"{{user}}"}"#.into() };
    let (id, c) = step(spec.clone());
    let fx = Fx::new(iterations(2, 1), vec![(id, c, "json")], Some(dataset("user\na\"b\n")));
    assert_eq!(export_codes(&fx), ["lint"]);
    spec.lint_policy = LintSendPolicy::Warn;
    let (id, c) = step(spec);
    let fx = Fx::new(iterations(2, 1), vec![(id, c, "json")], Some(dataset("user\na\n")));
    assert!(export_codes(&fx).is_empty());
}

#[test]
fn load_012_repeated_credential_fields_keep_their_own_values() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/echo");
    spec.params.push(KeyValue::new("api_key", "first-SENSITIVE"));
    spec.params.push(KeyValue::new("api_key", "second-SENSITIVE"));
    let (id, c) = step(spec);
    let fx = Fx::new(iterations(1, 1), vec![(id, c, "dup")], None);
    let out = fx.export(&ExportOptions { include_secrets: true, ..Default::default() }).expect("exported");
    assert_eq!(out.report.secret_properties.len(), 2);
    assert!(!out.jmx.contains("SENSITIVE"));
    let props = out.secrets_properties.expect("secrets written");
    assert!(props.contains("=first-SENSITIVE\n") && props.contains("=second-SENSITIVE\n"));
}

#[test]
fn load_012_credential_fragments_never_stay_in_jmx_and_mixed_per_run_is_refused() {
    // Alphabetic literal fragment joined to a secret variable in a non-Authorization
    // header or API key must move into a secret property, never stay in the JMX.
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/echo");
    spec.headers.push(KeyValue { sensitive: true, ..KeyValue::new("X-Custom-Token", "secretprefix{{tok}}") });
    spec.headers.push(KeyValue::new("Authorization", "secretprefix{{tok}}"));
    spec.headers.push(KeyValue::new("X-Api-Key", "Bearer {{tok}}"));
    spec.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let (id, mut c) = step(spec);
    c.var_layers.push(layer("workspace", &[("tok", "VAL-SENSITIVE", true)]));
    let out = Fx::new(iterations(1, 1), vec![(id, c, "frag")], None)
        .export(&ExportOptions { include_secrets: true, ..Default::default() })
        .expect("static fragments become properties");
    assert!(!out.jmx.contains("secretprefix"), "literal credential fragment leaked into JMX");
    assert!(!out.jmx.contains("Bearer ${"), "non-Authorization header must not keep scheme prefix in JMX");
    let props = out.secrets_properties.expect("secrets written");
    assert!(props.contains("=secretprefixVAL-SENSITIVE\n"));
    assert!(props.contains("=Bearer VAL-SENSITIVE\n"));

    // Mixed literal credential fragment with a per-iteration dataset value must be refused.
    let mut mixed = RequestSpec::http("GET", "http://127.0.0.1:8080/echo");
    mixed.headers.push(KeyValue { sensitive: true, ..KeyValue::new("X-Custom-Token", "secretprefix{{user}}") });
    mixed.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    let (id, c) = step(mixed);
    let e = refused(Fx::new(iterations(1, 1), vec![(id, c, "mixed")], Some(dataset("user\nalice\n"))).export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["secret_mixed"], "{e}");
}

#[test]
fn load_012_sensitive_dataset_and_extraction_values_trigger_redirect_refusal() {
    // A normally-named header carrying a sensitive dataset column must be refused
    // when redirects are followed without cross-origin credential forwarding.
    let mut ds = dataset("user,secret_col\nalice,tok-1\n");
    ds.sensitive_columns = vec!["secret_col".into()];
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/echo");
    spec.headers.push(KeyValue::new("X-Context", "{{secret_col}}"));
    spec.settings.redirects = Some(RedirectPolicy::default());
    spec.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id, mut c) = step(spec);
    with_tls_profile(&mut c, false);
    let e = refused(
        Fx::new(iterations(1, 1), vec![(id, c, "ds")], Some(ds)).export(&ExportOptions { include_secrets: true, ..Default::default() }),
    );
    assert_eq!(codes(&e), ["redirect_credentials", "redirect_destination_policy"], "{e}");

    // A normally-named header carrying a sensitive extraction from an earlier
    // chain step must also be refused when redirects are followed.
    let mut step1 = RequestSpec::http("GET", "http://127.0.0.1:8080/login");
    step1.settings.redirects = Some(RedirectPolicy { follow: false, max: 10, forward_credentials_cross_origin: false });
    step1.extractions.push(Extraction {
        variable: "session_tok".into(),
        source: ExtractionSource::JsonPath { path: "$.token".into() },
        sensitive: true,
    });
    let mut step2 = RequestSpec::http("GET", "http://127.0.0.1:8080/profile");
    step2.headers.push(KeyValue::new("X-Context", "{{session_tok}}"));
    step2.settings.redirects = Some(RedirectPolicy::default());
    step2.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id1, c1) = step(step1);
    let (id2, mut c2) = step(step2);
    with_tls_profile(&mut c2, false);
    let e = refused(Fx::new(iterations(1, 1), vec![(id1, c1, "login"), (id2, c2, "profile")], None).export(&ExportOptions::default()));
    assert_eq!(codes(&e), ["redirect_credentials", "redirect_destination_policy"], "{e}");
}

#[test]
fn load_012_templated_accept_encoding_header_is_validated_not_overwritten() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/");
    spec.headers.push(KeyValue::new("{{ae_header}}", "zstd"));
    let (id, mut c) = step(spec);
    c.var_layers.push(layer("workspace", &[("ae_header", "Accept-Encoding", false)]));
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "ae")], None)), ["accept_encoding"]);

    // A second Accept-Encoding header offering zstd must also be validated and refused.
    let mut dup = RequestSpec::http("GET", "http://127.0.0.1:8080/");
    dup.headers.push(KeyValue::new("Accept-Encoding", "gzip"));
    dup.headers.push(KeyValue::new("Accept-Encoding", "zstd"));
    let (id2, c2) = step(dup);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id2, c2, "dup-ae")], None)), ["accept_encoding"]);
}

#[test]
fn load_012_bearer_unrecognized_prefix_moves_to_secret_property() {
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/");
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::template("{{tok}}"), prefix: "CustomSecretPrefix-SENSITIVE".into() };
    let (id, mut c) = step(spec);
    c.var_layers.push(layer("workspace", &[("tok", "secret-val", true)]));
    let out = Fx::new(iterations(1, 1), vec![(id, c, "bearer")], None)
        .export(&ExportOptions { include_secrets: true, ..Default::default() })
        .expect("exported");
    assert!(!out.jmx.contains("CustomSecretPrefix"), "unrecognized Bearer prefix leaked into JMX");
    assert!(!out.jmx.contains("SENSITIVE"), "secret text leaked into JMX");
    let props = out.secrets_properties.as_deref().expect("secrets properties");
    assert!(props.contains("CustomSecretPrefix-SENSITIVE"), "prefix must be resolved into secrets.properties");
}

#[test]
fn load_012_query_api_key_with_redirects_and_oversized_mix_weights_are_refused() {
    // Query API key on a redirect-following request is refused because JMeter
    // does not reapply query auth on same-origin redirect hops.
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    spec.auth = AuthConfig::ApiKey { name: "api_key".into(), value: SensitiveValue::template("k"), location: KeyLocation::Query };
    spec.settings.redirects = Some(RedirectPolicy { follow: true, max: 5, forward_credentials_cross_origin: true });
    spec.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id, mut c) = step(spec);
    with_tls_profile(&mut c, false);
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id, c, "qauth")], None)),
        ["redirect_destination_policy", "redirect_query_auth"]
    );

    // Same query API key with follow=false exports cleanly.
    let mut no_follow = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    no_follow.auth = AuthConfig::ApiKey { name: "api_key".into(), value: SensitiveValue::template("k"), location: KeyLocation::Query };
    no_follow.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_nf, c_nf) = step(no_follow);
    assert!(Fx::new(iterations(1, 1), vec![(id_nf, c_nf, "qauth-nf")], None).export(&ExportOptions::default()).is_ok());

    // Inherited workspace/folder query API key is also refused when redirects are followed.
    let mut inherited = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    inherited.auth = AuthConfig::Inherit;
    inherited.settings.redirects = Some(RedirectPolicy { follow: true, max: 5, forward_credentials_cross_origin: true });
    inherited.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id_inh, mut c_inh) = step(inherited);
    c_inh.auth_layers.insert(
        0,
        (
            "workspace".into(),
            AuthConfig::ApiKey { name: "api_key".into(), value: SensitiveValue::template("k"), location: KeyLocation::Query },
        ),
    );
    with_tls_profile(&mut c_inh, false);
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_inh, c_inh, "qauth-inh")], None)),
        ["redirect_destination_policy", "redirect_query_auth"]
    );

    // Explicit Host and Mcp-Session-Id headers are stripped by Anvil on redirect hops
    // (Host on every hop, Mcp-Session-Id on cross-origin hops even with credential forwarding).
    let mut host_redir = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    host_redir.headers.push(KeyValue::new("Host", "api.example.test:8080"));
    host_redir.settings.redirects = Some(RedirectPolicy { follow: true, max: 5, forward_credentials_cross_origin: true });
    host_redir.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id_host, mut c_host) = step(host_redir);
    with_tls_profile(&mut c_host, false);
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_host, c_host, "host-redir")], None)),
        ["redirect_destination_policy", "redirect_host_header"]
    );

    // Even with redirects disabled, an explicit Host that HttpClient 4 would
    // rewrite (portless on non-default port, explicit default port, or templated)
    // is refused, while Host matching HC4's wire form exports cleanly.
    let mut host_portless = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    host_portless.headers.push(KeyValue::new("Host", "api.example.test"));
    host_portless.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_hp, c_hp) = step(host_portless);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_hp, c_hp, "host-portless")], None)), ["host_header"]);

    let mut host_default_port = RequestSpec::http("GET", "http://127.0.0.1:80/items");
    host_default_port.headers.push(KeyValue::new("Host", "api.example.test:80"));
    host_default_port.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_hdp, c_hdp) = step(host_default_port);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_hdp, c_hdp, "host-defport")], None)), ["host_header"]);

    let mut host_tmpl = RequestSpec::http("GET", "http://127.0.0.1:80/items");
    host_tmpl.headers.push(KeyValue::new("Host", "t-{{anvil.iteration}}.example.test"));
    host_tmpl.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_ht, c_ht) = step(host_tmpl);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_ht, c_ht, "host-tmpl")], None)), ["host_header"]);

    let mut host_ok_nondef = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    host_ok_nondef.headers.push(KeyValue::new("Host", "api.example.test:8080"));
    host_ok_nondef.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_hok1, c_hok1) = step(host_ok_nondef);
    assert!(Fx::new(iterations(1, 1), vec![(id_hok1, c_hok1, "host-ok1")], None).export(&ExportOptions::default()).is_ok());

    let mut host_ok_def = RequestSpec::http("GET", "http://127.0.0.1:80/items");
    host_ok_def.headers.push(KeyValue::new("Host", "api.example.test"));
    host_ok_def.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_hok2, c_hok2) = step(host_ok_def);
    assert!(Fx::new(iterations(1, 1), vec![(id_hok2, c_hok2, "host-ok2")], None).export(&ExportOptions::default()).is_ok());

    let mut mcp_redir = RequestSpec::http("GET", "http://127.0.0.1:8080/mcp");
    mcp_redir.headers.push(KeyValue::new("Mcp-Session-Id", "sess-123"));
    mcp_redir.settings.redirects = Some(RedirectPolicy { follow: true, max: 5, forward_credentials_cross_origin: true });
    mcp_redir.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id_mcp, mut c_mcp) = step(mcp_redir);
    with_tls_profile(&mut c_mcp, false);
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_mcp, c_mcp, "mcp-redir")], None)),
        ["redirect_destination_policy", "redirect_mcp_session"]
    );

    // Basic auth with redirects followed is refused because JMeter scopes AuthManager
    // to the initial origin rather than matching Anvil's cross-origin/sticky stripping rules.
    let mut basic_redir = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    basic_redir.auth = AuthConfig::Basic { username: "ann".into(), password: SensitiveValue::template("pw") };
    basic_redir.settings.redirects = Some(RedirectPolicy { follow: true, max: 5, forward_credentials_cross_origin: true });
    basic_redir.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id_basic, mut c_basic) = step(basic_redir);
    with_tls_profile(&mut c_basic, false);
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_basic, c_basic, "basic-redir")], None)),
        ["redirect_destination_policy", "redirect_basic_auth"]
    );

    // Explicit Content-Length is discarded by JMeter's HttpClient 4 sampler even with redirects off.
    let mut cl_no_redir = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    cl_no_redir.headers.push(KeyValue::new("Content-Length", "0"));
    cl_no_redir.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_cl, c_cl) = step(cl_no_redir);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_cl, c_cl, "cl")], None)), ["content_length_header"]);

    let mut ct_redir = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    ct_redir.headers.push(KeyValue::new("Content-Type", "application/json"));
    ct_redir.settings.redirects = Some(RedirectPolicy { follow: true, max: 5, forward_credentials_cross_origin: true });
    ct_redir.settings.http_version = Some(HttpVersionPolicy::Http1Only);
    let (id_ct, mut c_ct) = step(ct_redir);
    with_tls_profile(&mut c_ct, false);
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_ct, c_ct, "ct-redir")], None)),
        ["redirect_destination_policy", "redirect_content_type"]
    );

    // Redirect-following is refused even on a clean GET with unverified TLS
    // because JMeter cannot enforce Anvil's per-hop destination network-zone policy;
    // with redirects off, the 3xx-without-Location difference is still reported.
    let mut ok_no_redir = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    ok_no_redir.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_ok, c_ok) = step(ok_no_redir);
    let exported_no_redir =
        Fx::new(iterations(1, 1), vec![(id_ok, c_ok, "ok-no-redir")], None).export(&ExportOptions::default()).expect("exported");
    assert!(
        exported_no_redir.report.differences.iter().any(|d| d.contains("Redirect responses without Location")),
        "{:?}",
        exported_no_redir.report.differences
    );

    // Basic auth replaces any explicit Authorization header in Anvil (even a
    // mixed-template stale value like `stale-{{anvil.iteration}}`); export must
    // neither refuse with `secret_mixed` nor emit an Authorization HeaderManager entry.
    let mut basic_override = RequestSpec::http("GET", "http://127.0.0.1:8080/auth/basic");
    basic_override.auth = AuthConfig::Basic { username: "ann".into(), password: SensitiveValue::template("pw") };
    basic_override.headers.push(KeyValue::new("Authorization", "stale-{{anvil.iteration}}"));
    basic_override.headers.push(KeyValue::new("X-Keep", "yes"));
    basic_override.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_bo, c_bo) = step(basic_override);
    let out_bo =
        Fx::new(iterations(1, 1), vec![(id_bo, c_bo, "basic-override")], None).export(&ExportOptions::default()).expect("exported");
    let doc_bo = Doc::parse(&out_bo.jmx);
    let emitted_header_names: Vec<String> = doc_bo
        .all("elementProp")
        .into_iter()
        .filter(|n| n.attribute("elementType") == Some("Header"))
        .map(|n| doc_bo.prop(n, "Header.name"))
        .collect();
    assert!(
        !emitted_header_names.iter().any(|h| h.eq_ignore_ascii_case("authorization")),
        "overridden Authorization header must not appear in HeaderManager: {emitted_header_names:?}"
    );
    assert!(emitted_header_names.iter().any(|h| h == "X-Keep"));
    assert!(out_bo.jmx.contains("AuthManager"));

    // CSVDataSet is scoped inside each load ThreadGroup (not at TestPlan or
    // SetupThreadGroup scope) so the secrets check never consumes dataset row 0.
    let ds = dataset("item\nfirst\nsecond\n");
    let mut ds_sec = RequestSpec::http("GET", "http://127.0.0.1:8080/items/{{item}}");
    ds_sec.auth = AuthConfig::Bearer { token: SensitiveValue::template("tok"), prefix: "Bearer".into() };
    ds_sec.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_ds, c_ds) = step(ds_sec);
    let out_ds = Fx::new(iterations(1, 1), vec![(id_ds, c_ds, "ds-sec")], Some(ds)).export(&ExportOptions::default()).expect("exported");
    let doc_ds = Doc::parse(&out_ds.jmx);
    assert!(doc_ds.all("SetupThreadGroup").len() == 1, "secrets check SetupThreadGroup present");
    let csv_node = doc_ds.first("CSVDataSet");
    // In JMX XML, a child of ThreadGroup sits inside the <hashTree> that immediately
    // follows <ThreadGroup> (whose parent <hashTree> holds ThreadGroup and SetupThreadGroup).
    let csv_parent_prev_tag = csv_node.parent().and_then(|ht| ht.prev_sibling_element()).map(|el| el.tag_name().name().to_string());
    assert_eq!(
        csv_parent_prev_tag.as_deref(),
        Some("ThreadGroup"),
        "CSVDataSet must be scoped inside load ThreadGroup, not TestPlan or SetupThreadGroup"
    );

    // JSONPath extraction with a semicolon is refused because JMeter's JSONPostProcessor
    // splits jsonPathExprs on ';'.
    let mut semi_jp = RequestSpec::http("GET", "http://127.0.0.1:8080/data");
    semi_jp.extractions.push(Extraction {
        variable: "val".into(),
        source: ExtractionSource::JsonPath { path: "$['a;b']".into() },
        sensitive: false,
    });
    let (id_jp, c_jp) = step(semi_jp);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_jp, c_jp, "semi-jp")], None)), ["extraction"]);

    // Large u64 weighted-mix seed is formatted as a signed Java long so JMeter
    // preserves the bit pattern instead of falling back to an unseeded RNG.
    let mut s1 = RequestSpec::http("GET", "http://127.0.0.1:8080/a");
    s1.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let mut s2 = RequestSpec::http("GET", "http://127.0.0.1:8080/b");
    s2.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (ids1, cs1) = step(s1);
    let (ids2, cs2) = step(s2);
    let mut fx_seed = Fx::new(iterations(2, 1), vec![(ids1, cs1, "a"), (ids2, cs2, "b")], None);
    fx_seed.plan.chain.clear();
    fx_seed.plan.mix = vec![WeightedStep { request_id: ids1, weight: 1 }, WeightedStep { request_id: ids2, weight: 1 }];
    fx_seed.plan.seed = u64::MAX;
    let out_seed = fx_seed.export(&ExportOptions::default()).expect("exported");
    let doc_seed = Doc::parse(&out_seed.jmx);
    assert_eq!(doc_seed.prop(doc_seed.first("RandomVariableConfig"), "randomSeed"), "-1");

    // Weighted mix whose total weight exceeds i32::MAX (JMeter RandomVariableConfig limit) is refused.
    let mut a = RequestSpec::http("GET", "http://127.0.0.1:8080/a");
    a.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let mut b = RequestSpec::http("GET", "http://127.0.0.1:8080/b");
    b.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (ida, ca) = step(a);
    let (idb, cb) = step(b);
    let mut fx = Fx::new(iterations(1, 1), vec![(ida, ca, "a"), (idb, cb, "b")], None);
    fx.plan.chain.clear();
    fx.plan.mix = vec![
        anvil_domain::load::WeightedStep { request_id: ida, weight: i32::MAX as u32 },
        anvil_domain::load::WeightedStep { request_id: idb, weight: 1 },
    ];
    assert_eq!(export_codes(&fx), ["mix_weight_range"]);

    // Cross-request secret variable isolation: step 0 overrides workspace `token`
    // in a folder layer; step 1 uses workspace `token`. Both properties must
    // resolve to their own layer's value (never shadowed by step 0's folder).
    let mut st0 = RequestSpec::http("GET", "http://127.0.0.1:8080/step0");
    st0.headers.push(KeyValue::new("X-Token", "{{token}}"));
    st0.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_st0, mut c_st0) = step(st0);
    c_st0.var_layers.push(layer("workspace", &[("token", "workspace-SECRET-val", true)]));
    c_st0.var_layers.push(layer("folder", &[("token", "folder-OVERRIDE-val", true)]));

    let mut st1 = RequestSpec::http("GET", "http://127.0.0.1:8080/step1");
    st1.headers.push(KeyValue::new("X-Token", "{{token}}"));
    st1.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_st1, mut c_st1) = step(st1);
    c_st1.var_layers.push(layer("workspace", &[("token", "workspace-SECRET-val", true)]));

    let out_iso = Fx::new(iterations(1, 1), vec![(id_st0, c_st0, "step0"), (id_st1, c_st1, "step1")], None)
        .export(&ExportOptions { include_secrets: true, ..ExportOptions::default() })
        .expect("exported");
    let props_iso = out_iso.secrets_properties.as_deref().expect("secrets written");
    assert!(props_iso.contains("=folder-OVERRIDE-val\n"), "step 0 folder override missing: {props_iso}");
    assert!(props_iso.contains("=workspace-SECRET-val\n"), "step 1 workspace secret overwritten by step 0 folder: {props_iso}");
    assert_eq!(out_iso.report.secret_properties.len(), 2, "distinct secret properties required");

    // Templated header name resolving to `Authorization` is overridden by Basic/Bearer auth.
    let mut tmpl_auth_hdr = RequestSpec::http("GET", "http://127.0.0.1:8080/auth/tmpl");
    tmpl_auth_hdr.auth = AuthConfig::Bearer { token: SensitiveValue::template("tok"), prefix: "Bearer".into() };
    tmpl_auth_hdr.headers.push(KeyValue::new("{{hdr_name}}", "stale-{{anvil.iteration}}"));
    tmpl_auth_hdr.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_tah, mut c_tah) = step(tmpl_auth_hdr);
    c_tah.var_layers.push(layer("workspace", &[("hdr_name", "Authorization", false)]));
    assert!(
        Fx::new(iterations(1, 1), vec![(id_tah, c_tah, "tmpl-auth")], None).export(&ExportOptions::default()).is_ok(),
        "templated header resolving to Authorization must not trigger secret_mixed when overridden by Bearer auth"
    );

    // CounterConfig and RandomVariableConfig stay out of SetupThreadGroup:
    // - single load group: scoped inside the load ThreadGroup with start 0;
    // - multi-stage closed workload with secrets: TestPlan CounterConfig starts at -1
    //   so SetupThreadGroup consumes -1 and load traffic starts at 0.
    let mut iter_sec = RequestSpec::http("GET", "http://127.0.0.1:8080/i/{{anvil.iteration}}");
    iter_sec.auth = AuthConfig::Bearer { token: SensitiveValue::template("tok"), prefix: "Bearer".into() };
    iter_sec.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_is, c_is) = step(iter_sec.clone());
    let out_single_iter =
        Fx::new(iterations(2, 1), vec![(id_is, c_is.clone(), "iter-sec")], None).export(&ExportOptions::default()).expect("exported");
    let doc_single = Doc::parse(&out_single_iter.jmx);
    let counter_single = doc_single.first("CounterConfig");
    assert_eq!(doc_single.prop(counter_single, "CounterConfig.start"), "0");
    let counter_parent_tag = counter_single.parent().and_then(|ht| ht.prev_sibling_element()).map(|el| el.tag_name().name().to_string());
    assert_eq!(counter_parent_tag.as_deref(), Some("ThreadGroup"), "single-group CounterConfig must live inside ThreadGroup");

    let multi_closed = Workload::ClosedVirtualUsers {
        stages: vec![Stage { duration_secs: 0, target: 1 }, Stage { duration_secs: 2, target: 3 }],
        think_time_ms: 0,
    };
    let out_multi_iter = Fx::new(multi_closed, vec![(id_is, c_is, "iter-sec")], None).export(&ExportOptions::default()).expect("exported");
    let doc_multi = Doc::parse(&out_multi_iter.jmx);
    assert_eq!(doc_multi.prop(doc_multi.first("CounterConfig"), "CounterConfig.start"), "-1");

    // Open workload whose stages round down to 0 arrivals in JMeter (e.g., 0 -> 1 over 1 s = 0.5 -> 0) is refused.
    let mut open_zero_req = RequestSpec::http("GET", "http://127.0.0.1:8080/open");
    open_zero_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_oz, c_oz) = step(open_zero_req);
    let mut fx_oz = Fx::new(
        Workload::OpenArrivalRate { stages: vec![Stage { duration_secs: 1, target: 1 }], max_in_flight: 10 },
        vec![(id_oz, c_oz, "open-zero")],
        None,
    );
    fx_oz.plan.connection_mode = ConnectionMode::Fresh;
    assert_eq!(export_codes(&fx_oz), ["workload"]);

    // Unspecified/reserved IP literal is refused with `destination_policy`, and
    // ordinary exports note that JMeter resolves DNS without Anvil's destination-zone checks.
    let mut unspec_req = RequestSpec::http("GET", "http://0.0.0.0:8080/items");
    unspec_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_unspec, c_unspec) = step(unspec_req);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_unspec, c_unspec, "unspec")], None)), ["destination_policy"]);
    assert!(
        exported_no_redir.report.differences.iter().any(|d| d.contains("Destination policy")),
        "{:?}",
        exported_no_redir.report.differences
    );

    // Non-canonical Host port (leading zero) and explicit Transfer-Encoding are refused.
    let mut host_zero_port = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    host_zero_port.headers.push(KeyValue::new("Host", "api.example.test:08080"));
    host_zero_port.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_hzp, c_hzp) = step(host_zero_port);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_hzp, c_hzp, "host-08080")], None)), ["host_header"]);

    let mut te_req = RequestSpec::http("POST", "http://127.0.0.1:8080/items");
    te_req.headers.push(KeyValue::new("Transfer-Encoding", "chunked"));
    te_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_te, c_te) = step(te_req);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_te, c_te, "te")], None)), ["transfer_encoding_header"]);

    // Mixed template secret variable (`prefix-{{suffix}}`) must expand through
    // native variable resolution rather than writing raw `{{suffix}}` into secrets.properties.
    let mut mixed_sec = RequestSpec::http("GET", "http://127.0.0.1:8080/sec");
    mixed_sec.headers.push(KeyValue::new("X-Api-Key", "{{token}}"));
    mixed_sec.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_ms, mut c_ms) = step(mixed_sec);
    c_ms.var_layers.push(layer("workspace", &[("suffix", "resolved-tail", false), ("token", "prefix-{{suffix}}", true)]));
    let out_ms = Fx::new(iterations(1, 1), vec![(id_ms, c_ms, "mixed-sec")], None)
        .export(&ExportOptions { include_secrets: true, ..ExportOptions::default() })
        .expect("exported");
    let props_ms = out_ms.secrets_properties.as_deref().expect("secrets written");
    assert!(props_ms.contains("=prefix-resolved-tail\n"), "mixed secret variable must expand recursively: {props_ms}");
    assert!(!props_ms.contains("{{suffix}}"), "unresolved template leaked into secrets.properties: {props_ms}");

    // Secret variable depending on a per-iteration value is refused with `secret_mixed`.
    let mut dyn_sec = RequestSpec::http("GET", "http://127.0.0.1:8080/sec");
    dyn_sec.headers.push(KeyValue::new("X-Api-Key", "{{token}}"));
    dyn_sec.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_dsec, mut c_dsec) = step(dyn_sec);
    c_dsec.var_layers.push(layer("workspace", &[("token", "prefix-{{anvil.iteration}}", true)]));
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_dsec, c_dsec, "dyn-sec")], None)), ["secret_mixed"]);

    // Closed workload that holds 0 VUs until the very end produces 0 thread groups and is refused.
    let mut zc_req = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    zc_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_zc, c_zc) = step(zc_req);
    let zero_closed = Workload::ClosedVirtualUsers {
        stages: vec![Stage { duration_secs: 1, target: 0 }, Stage { duration_secs: 0, target: 1 }],
        think_time_ms: 0,
    };
    assert_eq!(export_codes(&Fx::new(zero_closed, vec![(id_zc, c_zc, "zero-closed")], None)), ["workload"]);

    // `decompress = false` is refused even without an explicit Accept-Encoding header.
    let mut decomp_req = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    decomp_req.settings.decompress = Some(false);
    decomp_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_dc, c_dc) = step(decomp_req);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_dc, c_dc, "no-decompress")], None)), ["accept_encoding"]);

    // Nested secret variable referencing another secret variable with `{{$uuid}}` is refused (`secret_mixed`).
    let mut nested_sec = RequestSpec::http("GET", "http://127.0.0.1:8080/sec");
    nested_sec.headers.push(KeyValue::new("X-Api-Key", "{{outer}}"));
    nested_sec.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_ns, mut c_ns) = step(nested_sec);
    c_ns.var_layers.push(layer("workspace", &[("inner", "tok-{{$uuid}}", true), ("outer", "{{inner}}", true)]));
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_ns, c_ns, "nested-sec")], None)), ["secret_mixed"]);

    // Whole-field credential template referencing a secret variable with `{{$uuid}}` is refused (`secret_mixed`).
    let mut tmpl_sec = RequestSpec::http("GET", "http://127.0.0.1:8080/sec");
    tmpl_sec.auth = AuthConfig::Bearer { token: SensitiveValue::template("prefix-{{inner}}"), prefix: "Bearer".into() };
    tmpl_sec.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_ts, mut c_ts) = step(tmpl_sec);
    c_ts.var_layers.push(layer("workspace", &[("inner", "dyn-{{$uuid}}", true)]));
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_ts, c_ts, "tmpl-sec")], None)), ["secret_mixed"]);

    // Uneven iterations + dataset places CSVDataSet inside a 1-loop LoopController
    // underneath the IfController gate so discarded iterations never advance the CSV cursor,
    // and prefixes leading-space dataset filenames with `./` so JMeter `.trim()` preserves them.
    let mut gated_ds_req = RequestSpec::http("GET", "http://127.0.0.1:8080/u/{{user}}");
    gated_ds_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_gd, c_gd) = step(gated_ds_req);
    let out_gd = Fx::new(iterations(5, 3), vec![(id_gd, c_gd, "gated-ds")], Some(dataset("user\nalice\nbob\n")))
        .export(&ExportOptions { include_secrets: false, dataset_file: " report.dataset.csv".into() })
        .expect("exported");
    let doc_gd = Doc::parse(&out_gd.jmx);
    let csv_gd = doc_gd.first("CSVDataSet");
    assert_eq!(doc_gd.prop(csv_gd, "filename"), "./ report.dataset.csv");
    let csv_gd_parent = csv_gd.parent().and_then(|ht| ht.prev_sibling_element()).expect("gated LoopController");
    assert_eq!(csv_gd_parent.tag_name().name(), "LoopController", "gated CSVDataSet must live inside the gated 1-loop LoopController");
    assert_eq!(doc_gd.prop(csv_gd_parent, "LoopController.continue_forever"), "true");
    assert_eq!(doc_gd.prop(csv_gd_parent, "LoopController.loops"), "1");

    // Default jmeter_properties explicitly disable response/header/samplerData/on_error/sample_variables capture.
    for prop in [
        "jmeter.save.saveservice.response_data",
        "jmeter.save.saveservice.response_data.on_error",
        "jmeter.save.saveservice.samplerData",
        "jmeter.save.saveservice.requestHeaders",
        "jmeter.save.saveservice.responseHeaders",
    ] {
        assert!(
            out_gd.report.jmeter_properties.iter().any(|(k, v)| k == prop && v == "false"),
            "missing default capture-disable property {prop}=false: {:?}",
            out_gd.report.jmeter_properties
        );
    }
    assert!(
        out_gd.report.jmeter_properties.iter().any(|(k, v)| k == "sample_variables" && v.is_empty()),
        "missing default sample_variables= clearing property: {:?}",
        out_gd.report.jmeter_properties
    );

    // $randomInt upper bound i64::MAX overflows JMeter's __Random (max + 1) and must be refused.
    let mut rmax_req = RequestSpec::http("GET", "http://example.test/{{$randomInt 0 9223372036854775807}}");
    rmax_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_rmax, c_rmax) = step(rmax_req);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_rmax, c_rmax, "rmax")], None)), ["dynamic_helper"]);

    // Repeated request ID in a chain: one extraction-bearing context used twice in the chain.
    // Step 0 sees static `tok` and extracts `tok`; step 1 sees extracted `tok` through non-literal
    // secret `wrap = "{{tok}}"` and must be refused as `secret_mixed` rather than reusing step 0's key.
    let mut rep_req = RequestSpec::http("GET", "http://example.test/items");
    rep_req.headers.push(KeyValue::new("X-Api-Key", "prefix-{{wrap}}"));
    rep_req.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    rep_req.extractions.push(Extraction {
        variable: "tok".into(),
        source: ExtractionSource::Header { name: "X-Next-Token".into() },
        sensitive: false,
    });
    let (shared_id, mut c_rep) = step(rep_req);
    c_rep.var_layers.push(layer("env", &[("tok", "initial-static", false), ("wrap", "{{tok}}", true)]));
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(shared_id, c_rep.clone(), "rep-0"), (shared_id, c_rep, "rep-1")], None)),
        ["secret_mixed"]
    );

    // Dynamic query/form field names conservatively protect literal values as secret properties,
    // and dynamic raw URL query names with literal values are refused as `url_credential`.
    let mut dyn_param = RequestSpec::http("GET", "http://example.test/search");
    dyn_param.params.push(KeyValue::new("{{key_name}}", "top-secret-literal"));
    dyn_param.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_dp, c_dp) = step(dyn_param);
    let out_dp = Fx::new(iterations(1, 1), vec![(id_dp, c_dp, "dyn-param")], Some(dataset("key_name\napi_key\n")))
        .export(&ExportOptions::default())
        .expect("dynamic param name protects literal value as property");
    assert!(!out_dp.jmx.contains("top-secret-literal"), "literal value under dynamic query name must not appear in JMX");
    assert_eq!(out_dp.report.secret_properties.len(), 1);

    let mut dyn_raw_q = RequestSpec::http("GET", "http://example.test/search?{{key_name}}=top-secret-literal");
    dyn_raw_q.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_dq, c_dq) = step(dyn_raw_q);
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_dq, c_dq, "dyn-raw-q")], Some(dataset("key_name\napi_key\n")))),
        ["url_credential"]
    );

    // Paths containing empty segments (`//`) are sent verbatim by Anvil but normalized by
    // JMeter's HttpClient 4 sampler, so export refuses them with `url_path` — for static
    // paths, dataset rows, secret-backed path segments, and unverifiable runtime values.
    let mut dbl_slash = RequestSpec::http("GET", "http://example.test/a//b");
    dbl_slash.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_ds, c_ds) = step(dbl_slash);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_ds, c_ds, "dbl-slash")], None)), ["url_path"]);

    let mut ds_path = RequestSpec::http("GET", "http://example.test/items/{{seg}}/detail");
    ds_path.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_dsp, c_dsp) = step(ds_path);
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_dsp, c_dsp.clone(), "ds-dot")], Some(dataset("seg\nok\n..\n")))),
        ["url_path"]
    );
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_dsp, c_dsp.clone(), "ds-dbl")], Some(dataset("seg\nx//y\n")))),
        ["url_path"]
    );
    assert_eq!(
        export_codes(&Fx::new(iterations(1, 1), vec![(id_dsp, c_dsp.clone(), "ds-query")], Some(dataset("seg\n..?x=1\n")))),
        ["url_path"]
    );
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_dsp, c_dsp, "ds-frag")], Some(dataset("seg\na#b\n")))), ["url_path"]);

    let mut sec_path = RequestSpec::http("GET", "http://example.test/items/{{sec_seg}}/detail");
    sec_path.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_sp, mut c_sp) = step(sec_path.clone());
    c_sp.var_layers.push(layer("env", &[("sec_seg", "..", true)]));
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_sp, c_sp, "sec-dot")], None)), ["url_path"]);
    let (id_spq, mut c_spq) = step(sec_path.clone());
    c_spq.var_layers.push(layer("env", &[("sec_seg", "..?x=1", true)]));
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_spq, c_spq, "sec-query")], None)), ["url_path"]);
    let (id_spf, mut c_spf) = step(sec_path);
    c_spf.var_layers.push(layer("env", &[("sec_seg", "a#b", true)]));
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_spf, c_spf, "sec-frag")], None)), ["url_path"]);

    // Cookie API keys follow RFC 6265 validation just like `anvil-auth` and refuse
    // invalid names, invalid static/secret values, and dynamic values.
    let mut bad_ck_name = RequestSpec::http("GET", "http://example.test/items");
    bad_ck_name.auth =
        AuthConfig::ApiKey { name: "bad;name".into(), value: SensitiveValue::template("okval"), location: KeyLocation::Cookie };
    bad_ck_name.settings.cookies = Some(false);
    bad_ck_name.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_bcn, c_bcn) = step(bad_ck_name);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_bcn, c_bcn, "bad-ck-name")], None)), ["auth"]);

    let mut bad_ck_val = RequestSpec::http("GET", "http://example.test/items");
    bad_ck_val.auth =
        AuthConfig::ApiKey { name: "sid".into(), value: SensitiveValue::template("ok;injected=1"), location: KeyLocation::Cookie };
    bad_ck_val.settings.cookies = Some(false);
    bad_ck_val.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_bcv, c_bcv) = step(bad_ck_val);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_bcv, c_bcv, "bad-ck-val")], None)), ["auth"]);

    let mut dyn_ck_val = RequestSpec::http("GET", "http://example.test/items");
    dyn_ck_val.auth = AuthConfig::ApiKey { name: "sid".into(), value: SensitiveValue::template("{{tok}}"), location: KeyLocation::Cookie };
    dyn_ck_val.settings.cookies = Some(false);
    dyn_ck_val.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_dcv, c_dcv) = step(dyn_ck_val);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_dcv, c_dcv, "dyn-ck-val")], Some(dataset("tok\nabc\n")))), ["auth"]);

    // JSONPath `NotExists` is refused because JMeter's inverted JSONPathAssertion
    // passes on malformed non-JSON responses where Anvil fails.
    let mut jp_not_exists = RequestSpec::http("GET", "http://example.test/items");
    jp_not_exists.assertions.push(assertion(AssertionKind::JsonPath {
        path: "$.error".into(),
        comparison: Comparison::NotExists,
        value: String::new(),
    }));
    jp_not_exists.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_jpne, c_jpne) = step(jp_not_exists);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_jpne, c_jpne, "jp-not-exists")], None)), ["assertion"]);

    // Explicit port 0 is refused because JMeter treats port 0 as the scheme's default port.
    let mut port_zero = RequestSpec::http("GET", "http://127.0.0.1:0/items");
    port_zero.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    let (id_p0, c_p0) = step(port_zero);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_p0, c_p0, "port-zero")], None)), ["url_port"]);

    // Mapped finite timeouts outside 1..=i32::MAX ms are refused.
    let mut zero_to = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    zero_to.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    zero_to.settings.timeouts = Some(TimeoutOverrides { connect_ms: Some(Some(0)), ..TimeoutOverrides::default() });
    let (id_zt, c_zt) = step(zero_to);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_zt, c_zt, "zero-to")], None)), ["timeout"]);

    let mut huge_to = RequestSpec::http("GET", "http://127.0.0.1:8080/items");
    huge_to.settings.redirects = Some(RedirectPolicy { follow: false, max: 0, forward_credentials_cross_origin: false });
    huge_to.settings.timeouts =
        Some(TimeoutOverrides { response_headers_ms: Some(Some(i32::MAX as u64 + 1)), ..TimeoutOverrides::default() });
    let (id_ht, c_ht) = step(huge_to);
    assert_eq!(export_codes(&Fx::new(iterations(1, 1), vec![(id_ht, c_ht, "huge-to")], None)), ["timeout"]);

    // Default jmeter_properties pin start timestamps in epoch milliseconds.
    assert!(
        out_gd.report.jmeter_properties.iter().any(|(k, v)| k == "sampleresult.timestamp.start" && v == "true"),
        "missing sampleresult.timestamp.start=true: {:?}",
        out_gd.report.jmeter_properties
    );
    assert!(
        out_gd.report.jmeter_properties.iter().any(|(k, v)| k == "jmeter.save.saveservice.timestamp_format" && v == "ms"),
        "missing jmeter.save.saveservice.timestamp_format=ms: {:?}",
        out_gd.report.jmeter_properties
    );
}
