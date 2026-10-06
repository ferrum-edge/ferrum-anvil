//! App-level spec import / reimport and load-plan services.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_app::specs::SpecTarget;
use anvil_domain::Id;
use anvil_domain::assertions::{Extraction, ExtractionSource};
use anvil_domain::auth::{AuthConfig, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::load::{LoadPlan, Workload};
use anvil_domain::request::{Body, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::DnsOverride;
use anvil_domain::workspace::DatasetFormat;
use anvil_import::{ImportOptions, ReimportApproval};
use anvil_storage::KdfParams;
use tokio_util::sync::CancellationToken;

fn new_app(root: &std::path::Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

const SPEC_V1: &str = r#"
openapi: 3.1.0
info: { title: Orders API, version: "1" }
servers: [{ url: "https://orders.example.com/v1" }]
paths:
  /orders:
    get:
      operationId: listOrders
      tags: [orders]
      responses: { "200": { description: ok } }
  /orders/{id}:
    get:
      operationId: getOrder
      tags: [orders]
      parameters: [{ name: id, in: path, required: true, schema: { type: integer } }]
      responses: { "200": { description: ok } }
"#;

const SPEC_V2: &str = r#"
openapi: 3.1.0
info: { title: Orders API, version: "2" }
servers: [{ url: "https://orders.example.com/v1" }]
paths:
  /orders:
    get:
      operationId: listOrders
      tags: [orders]
      parameters: [{ name: limit, in: query, required: true, schema: { type: integer } }]
      responses: { "200": { description: ok } }
  /orders/{id}:
    get:
      operationId: getOrder
      tags: [orders]
      parameters: [{ name: id, in: path, required: true, schema: { type: integer } }]
      responses: { "200": { description: ok } }
  /refunds:
    post:
      operationId: createRefund
      tags: [refunds]
      responses: { "201": { description: created } }
"#;

#[test]
fn spec_import_new_workspace_records_provenance_and_nothing_runs() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let preview = app.spec_preview(SPEC_V1.as_bytes(), &ImportOptions::default()).unwrap();
    assert_eq!(preview.requests, 2);
    let done = app.spec_import(SPEC_V1.as_bytes(), "orders.yaml", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    assert_eq!(done.requests, 2);
    assert_eq!(app.requests(&done.workspace_id).unwrap().len(), 2);
    let sources = app.spec_sources(&done.workspace_id).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].file_name, "orders.yaml");
    // Original bytes are retained as a content-addressed attachment.
    assert!(app.get_attachment(&sources[0].original_sha256).unwrap().is_some());
    // Importing sends nothing: history stays empty.
    assert!(app.store.list_history(Some(&done.workspace_id), None, 10).unwrap().is_empty());
}

#[test]
fn spec_import_into_existing_workspace_nests_under_a_new_folder() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Mine").unwrap();
    let done = app
        .spec_import(SPEC_V1.as_bytes(), "orders.yaml", &ImportOptions::default(), SpecTarget::Workspace { workspace_id: ws.meta.id })
        .unwrap();
    let rootf = done.root_folder_id.unwrap();
    let tree = app.tree(&ws.meta.id).unwrap();
    assert_eq!(tree.len(), 1, "one new top-level folder");
    assert_eq!(tree[0].id, rootf);
    assert_eq!(app.requests(&ws.meta.id).unwrap().len(), 2);
}

#[test]
fn data_012_spec_reimport_adds_new_operations_and_preserves_user_edits() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = app.spec_import(SPEC_V1.as_bytes(), "orders.yaml", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    // The user edits listOrders.
    let mut edited = app
        .requests(&done.workspace_id)
        .unwrap()
        .into_iter()
        .find(|r| r.name.contains("listOrders") || r.spec.url.ends_with("/orders"))
        .unwrap();
    edited.spec.headers.push(anvil_domain::request::KeyValue::new("X-Mine", "1"));
    app.save_request(edited.clone()).unwrap();

    let plan = app.spec_reimport_plan(&done.import_id, SPEC_V2.as_bytes()).unwrap();
    assert_eq!(plan.added.len(), 1, "createRefund is new");
    assert_eq!(plan.conflicts.len(), 1, "listOrders changed upstream and was edited locally");
    let n = app.spec_reimport_apply(&done.import_id, SPEC_V2.as_bytes(), "spec-v2.yaml", &ReimportApproval::default()).unwrap();
    assert_eq!(n, 3);
    let after = app.requests(&done.workspace_id).unwrap();
    assert_eq!(after.len(), 3);
    let kept = after.iter().find(|r| r.meta.id == edited.meta.id).unwrap();
    assert!(kept.spec.headers.iter().any(|h| h.name == "X-Mine"), "user edit kept without explicit overwrite approval");
    // A second reimport still finds the linked requests.
    let again = app.spec_reimport_plan(&app.spec_sources(&done.workspace_id).unwrap()[0].source.import_id, SPEC_V2.as_bytes()).unwrap();
    assert!(again.added.is_empty());
}

fn plan(ws: Id, req: Id) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: ws,
        name: "smoke".into(),
        workload: Workload::Iterations { iterations: 20, concurrency: 4 },
        chain: vec![req],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: Default::default(),
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// A workspace for the preflight's per-run value tests. The environment names
/// a loopback `host`, and the dataset has a `host` column too, so its value
/// shadows the environment's on every iteration that uses the dataset.
fn preflight_workspace(app: &App) -> (Id, Id, Id) {
    use anvil_domain::workspace::Variable;
    let ws = app.create_workspace("Load").unwrap();
    let vars = vec![Variable::plain("host", "127.0.0.1"), Variable::plain("base", "http://{{$randomFrom 127.0.0.1|example.org}}")];
    let env = app.create_environment(&ws.meta.id, "lab", vars).unwrap();
    let rows = b"host,qaRow,rowId,verb,port\n192.0.2.10,first,1,POST,8080\n198.51.100.7,second,2,PUT,8081\n";
    let dataset = app.create_dataset(&ws.meta.id, "rows", DatasetFormat::Csv, rows, vec![]).unwrap();
    (ws.meta.id, env.meta.id, dataset.meta.id)
}

fn chain_plan(ws: Id, env: Id, chain: Vec<Id>, dataset: Option<Id>) -> LoadPlan {
    LoadPlan { chain, dataset_id: dataset, environment_id: Some(env), ..plan(ws, Id::new()) }
}

fn extracting(mut spec: RequestSpec, variable: &str) -> RequestSpec {
    let source = ExtractionSource::JsonPath { path: "$.value".into() };
    spec.extractions.push(Extraction { variable: variable.into(), source, sensitive: false });
    spec
}

fn leaves_machine(warnings: &[String]) -> bool {
    warnings.iter().any(|w| w.contains("Traffic leaves this machine"))
}

/// The preflight refuses `p` because a per-run value from `source` reaches
/// the `part` of a URL's origin, and shows neither the value nor a stand-in.
fn assert_refused(app: &App, p: &LoadPlan, part: &str, source: &str) {
    let error = app.load_preflight(p).unwrap_err().to_string();
    assert!(error.contains("cannot prove that a variable URL origin stays on loopback"), "{error}");
    assert!(error.contains(&format!("the {part} of the")), "{error}");
    assert!(error.contains(source), "{error}");
    for shown in ["anvil-preflight", "192.0.2.10", "198.51.100.7", "first", "second", "example.org"] {
        assert!(!error.contains(shown), "'{shown}' shown in: {error}");
    }
}

/// #288: dataset columns, values extracted by earlier chain steps, iteration
/// variables and dynamic helpers may fill the path, query, body and method of
/// a fixed loopback URL. The preflight confirms it as local without
/// validating those per-run values (a JSON number from a dataset is not JSON
/// until the row is applied).
#[test]
fn load_preflight_allows_per_run_values_outside_a_fixed_loopback_origin() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (ws, env, dataset) = preflight_workspace(&app);
    let producer_spec = extracting(RequestSpec::http("GET", "http://127.0.0.1:8080/token"), "token");
    let producer = app.create_request(&ws, None, "producer", producer_spec).unwrap();
    let url = "http://127.0.0.1:8080/items/{{rowId}}?row={{qaRow}}&token={{token}}&i={{anvil.iteration}}&vu={{ anvil.vu }}&u={{$uuid}}";
    let mut spec = RequestSpec::http("{{verb}}", url);
    spec.body = Body::Json { text: r#"{"id": {{rowId}}, "row": "{{qaRow}}", "token": "{{token}}"}"#.into() };
    let consumer = app.create_request(&ws, None, "consumer", spec).unwrap();
    let p = app.save_load_plan(chain_plan(ws, env, vec![producer.meta.id, consumer.meta.id], Some(dataset))).unwrap();
    let pre = app.load_preflight(&p).unwrap();
    assert_eq!(pre.dataset_rows, Some(2));
    assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:8080".to_string(), "{{verb}} http://127.0.0.1:8080".to_string()]);
    assert!(!leaves_machine(&pre.warnings), "{:?}", pre.warnings);

    // A per-run port after a fixed loopback host can change the port, never
    // the host: allowed, and shown as a per-iteration port.
    for (url, destination) in [
        ("http://127.0.0.1:{{port}}/items/{{rowId}}", "GET http://127.0.0.1:<per-iteration port>"),
        ("http://[::1]:{{port}}/", "GET http://[::1]:<per-iteration port>"),
        ("localhost:{{port}}/x", "GET https://localhost:<per-iteration port>"),
        ("http://127.0.0.1:{{$randomInt 8000 9000}}/", "GET http://127.0.0.1:<per-iteration port>"),
        // Fixed digits beside the value are part of the per-run port; the
        // preflight never shows or parses a port it made up (`99991`).
        ("http://127.0.0.1:9999{{port}}/", "GET http://127.0.0.1:<per-iteration port>"),
    ] {
        let req = app.create_request(&ws, None, "per-run port", RequestSpec::http("GET", url)).unwrap();
        let p = app.save_load_plan(chain_plan(ws, env, vec![req.meta.id], Some(dataset))).unwrap();
        let pre = app.load_preflight(&p).unwrap();
        assert_eq!(pre.destinations, vec![destination.to_string()], "{url}");
        assert!(!leaves_machine(&pre.warnings), "{url}: {:?}", pre.warnings,);
    }

    // A dynamic helper in the method is shown as written, not as one draw.
    let spec = RequestSpec::http("{{$randomFrom GET|POST}}", "http://127.0.0.1:8080/x");
    let helper_method = app.create_request(&ws, None, "helper method", spec).unwrap();
    let p = app.save_load_plan(chain_plan(ws, env, vec![helper_method.meta.id], None)).unwrap();
    assert_eq!(app.load_preflight(&p).unwrap().destinations, vec!["{{$randomFrom GET|POST}} http://127.0.0.1:8080".to_string()]);
}

#[test]
fn load_preflight_uses_transport_dns_overrides_for_loopback_judgments() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("DNS preflight").unwrap();
    let mut workspace = app.workspace(&ws.meta.id).unwrap();
    workspace.settings.dns_overrides.push(DnsOverride { host: "localhost".into(), addresses: vec!["198.51.100.7".into()] });
    app.save_workspace(workspace).unwrap();
    let req = app.create_request(&ws.meta.id, None, "local name", RequestSpec::http("GET", "http://localhost:8080/")).unwrap();
    let p = app.save_load_plan(plan(ws.meta.id, req.meta.id)).unwrap();
    let pre = app.load_preflight(&p).unwrap();
    assert!(leaves_machine(&pre.warnings), "{:?}", pre.warnings);

    let mut workspace = app.workspace(&ws.meta.id).unwrap();
    workspace.settings.dns_overrides[0].addresses = vec!["127.0.0.1".into(), "::1".into()];
    app.save_workspace(workspace).unwrap();
    let pre = app.load_preflight(&p).unwrap();
    assert!(!leaves_machine(&pre.warnings), "{:?}", pre.warnings);
}

#[test]
fn localhost_names_are_local_only_with_system_dns_and_without_overrides() {
    use anvil_domain::settings::ResolverMode;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Localhost names").unwrap().meta.id;

    for host in ["localhost", "api.localhost", "api.localhost."] {
        let req = app.create_request(&ws, None, host, RequestSpec::http("GET", &format!("http://{host}:8080/api"))).unwrap();
        let p = app.save_load_plan(plan(ws, req.meta.id)).unwrap();
        assert!(!leaves_machine(&app.load_preflight(&p).unwrap().warnings), "{host}");
    }

    let req = app.create_request(&ws, None, "overridden", RequestSpec::http("GET", "http://api.localhost:8080/api")).unwrap();
    let p = app.save_load_plan(plan(ws, req.meta.id)).unwrap();
    let mut workspace = app.workspace(&ws).unwrap();
    workspace.settings.dns_overrides.push(DnsOverride { host: "api.localhost".into(), addresses: vec!["198.51.100.7".into()] });
    app.save_workspace(workspace).unwrap();
    assert!(leaves_machine(&app.load_preflight(&p).unwrap().warnings), "public localhost override is remote");
    let mut workspace = app.workspace(&ws).unwrap();
    workspace.settings.dns_overrides[0].addresses = vec!["127.0.0.1".into()];
    app.save_workspace(workspace).unwrap();
    assert!(!leaves_machine(&app.load_preflight(&p).unwrap().warnings), "loopback localhost override is local");

    let mut workspace = app.workspace(&ws).unwrap();
    workspace.settings.dns_overrides.clear();
    workspace.settings.resolver = Some(ResolverMode::Custom { nameservers: vec!["127.0.0.1:53".into()] });
    app.save_workspace(workspace).unwrap();
    let req = app.create_request(&ws, None, "custom DNS", RequestSpec::http("GET", "http://api.localhost:8080/api")).unwrap();
    let p = app.save_load_plan(plan(ws, req.meta.id)).unwrap();
    assert!(leaves_machine(&app.load_preflight(&p).unwrap().warnings), "custom DNS does not prove locality");
}

#[test]
fn load_preflight_checks_oauth_urls_with_per_run_values() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (ws, env, dataset) = preflight_workspace(&app);
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:8080/resource");
    spec.auth = AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::ClientCredentials,
            token_url: "https://{{host}}/token".into(),
            authorization_url: String::new(),
            client_id: "client".into(),
            client_secret: SensitiveValue::default(),
            scope: String::new(),
            audience: String::new(),
            client_auth: OAuthClientAuth::RequestBody,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    };
    let req = app.create_request(&ws, None, "OAuth", spec.clone()).unwrap();
    let p = app.save_load_plan(chain_plan(ws, env, vec![req.meta.id], Some(dataset))).unwrap();
    let error = app.load_preflight(&p).unwrap_err().to_string();
    assert!(error.contains("OAuth token URL"), "{error}");
    assert!(error.contains("dataset column"), "{error}");
    assert!(!error.contains("anvil-preflight"), "{error}");

    spec.auth = AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::AuthorizationCodePkce,
            token_url: "http://127.0.0.1:8080/token/{{rowId}}".into(),
            authorization_url: "http://127.0.0.1:8080/authorize/{{rowId}}".into(),
            client_id: "client".into(),
            client_secret: SensitiveValue::default(),
            scope: String::new(),
            audience: String::new(),
            client_auth: OAuthClientAuth::RequestBody,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    };
    let req = app.create_request(&ws, None, "Local OAuth", spec.clone()).unwrap();
    let p = app.save_load_plan(chain_plan(ws, env, vec![req.meta.id], Some(dataset))).unwrap();
    let pre = app.load_preflight(&p).unwrap();
    assert!(pre.destinations.iter().any(|d| d.starts_with("OAuth token URL http://127.0.0.1:8080")), "{:?}", pre.destinations);
    assert!(pre.destinations.iter().any(|d| { d.starts_with("OAuth authorization URL http://127.0.0.1:8080") }), "{:?}", pre.destinations);
    assert!(!leaves_machine(&pre.warnings), "{:?}", pre.warnings);

    if let AuthConfig::OAuth2 { config } = &mut spec.auth {
        config.grant = OAuthGrant::RefreshToken;
        config.authorization_url.clear();
    }
    let req = app.create_request(&ws, None, "Optional authorization URL", spec).unwrap();
    let p = app.save_load_plan(chain_plan(ws, env, vec![req.meta.id], Some(dataset))).unwrap();
    let pre = app.load_preflight(&p).unwrap();
    assert!(!pre.destinations.iter().any(|d| d.starts_with("OAuth authorization URL")), "{:?}", pre.destinations);
    assert!(!leaves_machine(&pre.warnings), "{:?}", pre.warnings);
}

/// A per-run value is layered above workspace, environment and folder
/// variables, as the worker layers it: a dataset column or an extracted value
/// named like a loopback environment variable decides the origin on every
/// iteration, so the preflight refuses it.
#[test]
fn load_preflight_refuses_a_per_run_value_that_shadows_a_loopback_origin() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (ws, env, dataset) = preflight_workspace(&app);
    let create = |name: &str, spec: RequestSpec| app.create_request(&ws, None, name, spec).unwrap().meta.id;
    let save = |chain: Vec<Id>, dataset: Option<Id>| app.save_load_plan(chain_plan(ws, env, chain, dataset)).unwrap();
    let by_host = create("by host", RequestSpec::http("GET", "http://{{host}}:8080/x"));

    // The environment alone names loopback.
    let pre = app.load_preflight(&save(vec![by_host], None)).unwrap();
    assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:8080".to_string()]);
    assert!(!leaves_machine(&pre.warnings), "{:?}", pre.warnings);
    // A dataset column of the same name wins.
    assert_refused(&app, &save(vec![by_host], Some(dataset)), "host", "a dataset column");
    // So does a value an earlier chain step extracted.
    let producer = create("producer", extracting(RequestSpec::http("GET", "http://127.0.0.1:8080/next"), "host"));
    assert_refused(&app, &save(vec![producer, by_host], None), "host", "a value extracted by a chain step");

    // A step that extracts the name its own origin uses sees only the
    // environment's value when it runs once. Repeated, a later position sees
    // what an earlier position of the same request extracted.
    let steering = create("steering", extracting(RequestSpec::http("GET", "http://{{host}}:8080/next"), "host"));
    let fixed = create("fixed", RequestSpec::http("GET", "http://127.0.0.1:8080/x"));
    let pre = app.load_preflight(&save(vec![steering], None)).unwrap();
    assert!(!leaves_machine(&pre.warnings), "{:?}", pre.warnings);
    assert_refused(&app, &save(vec![steering, steering], None), "host", "a value extracted by a chain step");
    assert_refused(&app, &save(vec![steering, fixed, steering], None), "host", "a value extracted by a chain step");

    // Every part of the origin is judged, and a per-run port only after a
    // fixed loopback host.
    let iteration = create("by vu", RequestSpec::http("GET", "http://10.0.0.{{ anvil.vu }}:8080/x"));
    assert_refused(&app, &save(vec![iteration], None), "host", "an iteration variable");
    let scheme = create("by scheme", RequestSpec::http("GET", "http{{rowId}}://127.0.0.1:8080/x"));
    assert_refused(&app, &save(vec![scheme], Some(dataset)), "scheme", "a dataset column");
    let userinfo = create("by userinfo", RequestSpec::http("GET", "http://{{qaRow}}@127.0.0.1:8080/x"));
    assert_refused(&app, &save(vec![userinfo], Some(dataset)), "host", "a dataset column");
    let remote_port = create("remote port", RequestSpec::http("GET", "http://192.0.2.1:{{port}}/x"));
    let remote = save(vec![remote_port], Some(dataset));
    assert_refused(&app, &remote, "port", "a dataset column");
    assert!(app.load_preflight(&remote).unwrap_err().to_string().contains("only after a fixed loopback host"));
    // Only fixed digits may share the port with a per-run value: anything
    // else (here a userinfo marker the engine would refuse anyway) is refused
    // by the preflight itself.
    let port_userinfo = create("port userinfo", RequestSpec::http("GET", "http://127.0.0.1:{{port}}@example.net/x"));
    let shared = save(vec![port_userinfo], Some(dataset));
    assert_refused(&app, &shared, "port", "a dataset column");
    assert!(app.load_preflight(&shared).unwrap_err().to_string().contains("only fixed digits may share the port"));
}

/// Dynamic helpers draw a new value on every send, so one preview's loopback
/// draw proves nothing: a helper in the origin is refused, whitespace inside
/// the braces or reached through a variable's value.
#[test]
fn load_preflight_refuses_a_dynamic_helper_in_the_origin() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (ws, env, _) = preflight_workspace(&app);
    for url in
        ["http://{{$randomFrom 127.0.0.1|example.org}}/echo", "http://{{ $randomFrom 127.0.0.1|127.0.0.2 }}:8080/echo", "{{base}}/echo"]
    {
        let req = app.create_request(&ws, None, "helper", RequestSpec::http("GET", url)).unwrap();
        assert_refused(&app, &app.save_load_plan(chain_plan(ws, env, vec![req.meta.id], None)).unwrap(), "host", "a dynamic helper");
    }
}

fn udp_via_masque(proxy_url: &str) -> RequestSpec {
    use anvil_domain::request::{MASQUE_DEFAULT_TEMPLATE, MasqueSpec, PayloadEncoding, Protocol, StreamPayload, UdpSpec};
    let mut udp = RequestSpec::http("GET", "udp://127.0.0.1:9");
    udp.protocol = Protocol::Udp;
    udp.udp = Some(UdpSpec {
        dtls: false,
        datagrams: vec![StreamPayload { data: "x".into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 100,
        max_datagrams: 1,
        masque: Some(MasqueSpec {
            proxy_url: proxy_url.into(),
            uri_template: MASQUE_DEFAULT_TEMPLATE.into(),
            datagrams: Default::default(),
        }),
        proxy_protocol: None,
    });
    udp
}

/// Session protocols get the same per-run layering: a dataset column that
/// shadows a loopback WebSocket host, a per-run scheme or a helper choosing a
/// MASQUE proxy is refused; per-run values in a fixed loopback session URL's
/// path, or its port, are not.
#[test]
fn load_preflight_judges_per_run_values_in_session_urls() {
    use anvil_domain::request::Protocol;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (ws, env, dataset) = preflight_workspace(&app);
    let session = |protocol: Protocol, url: &str| {
        let mut s = RequestSpec::http("GET", url);
        s.protocol = protocol;
        app.create_request(&ws, None, "session", s).unwrap().meta.id
    };
    let save = |chain: Vec<Id>, dataset: Option<Id>| app.save_load_plan(chain_plan(ws, env, chain, dataset)).unwrap();
    let local = |chain: Vec<Id>, dataset: Option<Id>, destination: &str| {
        let pre = app.load_preflight(&save(chain, dataset)).unwrap();
        assert_eq!(pre.destinations, vec![destination.to_string()]);
        assert!(!leaves_machine(&pre.warnings), "{destination}: {:?}", pre.warnings);
    };

    let by_host = session(Protocol::WebSocket, "ws://{{host}}:9000/socket");
    local(vec![by_host], None, "WebSocket ws://127.0.0.1:9000");
    assert_refused(&app, &save(vec![by_host], Some(dataset)), "host", "a dataset column");
    let by_path = session(Protocol::WebSocket, "ws://127.0.0.1:9000/rows/{{qaRow}}?i={{anvil.iteration}}");
    local(vec![by_path], Some(dataset), "WebSocket ws://127.0.0.1:9000");

    // A per-run port after a fixed loopback host, for a special and a
    // non-special scheme, and for a MASQUE proxy URL.
    let ws_port = session(Protocol::WebSocket, "ws://127.0.0.1:{{port}}/socket");
    local(vec![ws_port], Some(dataset), "WebSocket ws://127.0.0.1:<per-iteration port>");
    let tcp_port = session(Protocol::Tcp, "tcp://[::1]:{{port}}");
    local(vec![tcp_port], Some(dataset), "TCP tcp://[::1]:<per-iteration port>");
    let masque_port = app.create_request(&ws, None, "masque port", udp_via_masque("https://127.0.0.1:{{port}}")).unwrap();
    local(vec![masque_port.meta.id], Some(dataset), "UDP udp://127.0.0.1:9 via MASQUE proxy https://127.0.0.1:<per-iteration port>");

    // The scheme, a port after a remote host, and anything but fixed digits
    // beside a per-run port are refused for sessions too.
    let scheme = session(Protocol::Tcp, "{{verb}}://127.0.0.1:9000");
    assert_refused(&app, &save(vec![scheme], Some(dataset)), "scheme", "a dataset column");
    let remote_port = session(Protocol::WebSocket, "ws://192.0.2.1:{{port}}/socket");
    assert_refused(&app, &save(vec![remote_port], Some(dataset)), "port", "a dataset column");
    let port_userinfo = session(Protocol::WebSocket, "ws://127.0.0.1:{{port}}@example.net/socket");
    let shared = save(vec![port_userinfo], Some(dataset));
    assert_refused(&app, &shared, "port", "a dataset column");
    assert!(app.load_preflight(&shared).unwrap_err().to_string().contains("only fixed digits may share the port"));

    let helper_proxy = udp_via_masque("https://{{ $randomFrom 127.0.0.1|example.org }}:4433");
    let tunneled = app.create_request(&ws, None, "via masque", helper_proxy).unwrap();
    let p = save(vec![tunneled.meta.id], None);
    assert_refused(&app, &p, "host", "a dynamic helper");
    assert!(app.load_preflight(&p).unwrap_err().to_string().contains("MASQUE proxy URL"));
}

/// A per-run port honours `NO_PROXY` as far as it can: an entry without a
/// port bypasses the proxy on every port, so a loopback host it lists is
/// sent directly. An entry naming one port cannot cover a per-run port, so
/// the proxy is assumed to carry it.
#[test]
fn load_preflight_applies_port_free_no_proxy_entries_to_a_per_run_port() {
    use anvil_domain::settings::ProxySelection;
    use anvil_domain::tls::{ProxyKind, ProxyProfile};
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let preflight = |no_proxy: &str| {
        let proxy = app
            .save_proxy_profile(ProxyProfile {
                id: Id::new(),
                workspace_id: ws.meta.id,
                name: "proxy".into(),
                kind: ProxyKind::Http,
                address: "proxy.example.test:3128".into(),
                username: None,
                password: None,
                no_proxy: no_proxy.into(),
                tls_profile_id: None,
                hbone: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .unwrap();
        let mut spec = RequestSpec::http("GET", "http://127.0.0.1:{{$randomInt 8000 9000}}/x");
        spec.settings.proxy_profile_id = Some(ProxySelection::Profile { id: proxy.id });
        let req = app.create_request(&ws.meta.id, None, "req", spec).unwrap();
        app.load_preflight(&app.save_load_plan(plan(ws.meta.id, req.meta.id)).unwrap()).unwrap()
    };

    for no_proxy in ["localhost,127.0.0.1", "127.0.0.0/8", "*"] {
        let pre = preflight(no_proxy);
        assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:<per-iteration port>".to_string()], "{no_proxy}");
        assert!(!leaves_machine(&pre.warnings), "{no_proxy}: {:?}", pre.warnings);
    }
    for no_proxy in ["", "127.0.0.1:8080", "localhost"] {
        let pre = preflight(no_proxy);
        let destination = "GET http://127.0.0.1:<per-iteration port> via HTTP proxy proxy.example.test:3128";
        assert_eq!(pre.destinations, vec![destination.to_string()], "{no_proxy}");
        assert!(leaves_machine(&pre.warnings), "{no_proxy}: {:?}", pre.warnings);
    }
}

/// A step under a sealed import root sees no dataset row and no value
/// extracted outside the root, so neither can shadow the root's own
/// variables there, while the same URL outside the root is refused.
#[test]
fn load_preflight_keeps_per_run_values_out_of_a_sealed_import_root() {
    use anvil_domain::workspace::Variable;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (ws, env, dataset) = preflight_workspace(&app);
    let target = SpecTarget::Workspace { workspace_id: ws };
    let done = app.spec_import(SPEC_V1.as_bytes(), "orders.yaml", &ImportOptions::default(), target).unwrap();
    let mut sealed = app.folder(&done.root_folder_id.unwrap()).unwrap();
    assert!(sealed.import_root && !sealed.use_workspace_scope);
    sealed.variables.push(Variable::plain("host", "127.0.0.1"));
    let sealed = app.save_folder(sealed).unwrap();
    let by_host = || RequestSpec::http("GET", "http://{{host}}:8080/x");
    let inside = app.create_request(&ws, Some(sealed.meta.id), "inside", by_host()).unwrap().meta.id;
    let outside = app.create_request(&ws, None, "outside", by_host()).unwrap().meta.id;
    let producer_spec = extracting(RequestSpec::http("GET", "http://127.0.0.1:8080/next"), "host");
    let producer = app.create_request(&ws, None, "producer", producer_spec).unwrap().meta.id;

    let p = app.save_load_plan(chain_plan(ws, env, vec![producer, inside], Some(dataset))).unwrap();
    let pre = app.load_preflight(&p).unwrap();
    assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:8080".to_string()]);
    assert!(!leaves_machine(&pre.warnings), "{:?}", pre.warnings);
    let p = app.save_load_plan(chain_plan(ws, env, vec![outside], Some(dataset))).unwrap();
    assert_refused(&app, &p, "host", "a dataset column");
    let p = app.save_load_plan(chain_plan(ws, env, vec![producer, outside], None)).unwrap();
    assert_refused(&app, &p, "host", "a value extracted by a chain step");
}

#[test]
fn a_load_plan_runs_only_requests_of_its_own_workspace() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let other = app.create_workspace("Other").unwrap();
    let req = app.create_request(&ws.meta.id, None, "echo", RequestSpec::http("GET", "https://api.example.test/")).unwrap();
    let stray = plan(other.meta.id, req.meta.id);
    let Err(e) = app.save_load_plan(stray.clone()) else { panic!("a plan saved another workspace's request") };
    assert!(e.to_string().contains("request 'echo' in this load plan belongs to another workspace"), "{e}");
    assert!(app.load_plans(&other.meta.id).unwrap().is_empty());
    // A plan that was never saved here (or was imported) is checked again
    // before any request is prepared.
    let Err(e) = app.load_job(&stray) else { panic!("a plan prepared another workspace's request") };
    assert!(e.to_string().contains("belongs to another workspace"), "{e}");
    app.save_load_plan(plan(ws.meta.id, req.meta.id)).unwrap();
}

#[tokio::test]
async fn load_plan_requires_acknowledgement_runs_and_stores_report() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let req = app.create_request(&ws.meta.id, None, "echo", RequestSpec::http("GET", &fx.url("/echo"))).unwrap();

    let empty = LoadPlan { chain: vec![], ..plan(ws.meta.id, req.meta.id) };
    assert!(app.save_load_plan(empty).is_err(), "a plan without requests is rejected at save time");
    let p = app.save_load_plan(plan(ws.meta.id, req.meta.id)).unwrap();

    let pre = app.load_preflight(&p).unwrap();
    assert_eq!(pre.destinations.len(), 1);
    assert!(pre.destinations[0].starts_with("GET http://127.0.0.1:"), "{:?}", pre.destinations);
    assert!(app.worker_job(&p, false).is_err(), "never runs without explicit acknowledgement");
    let untrusted = LoadPlan { trusted: false, ..p.clone() };
    assert!(app.worker_job(&untrusted, true).is_err(), "imported plans must be reviewed first");

    // Run in-process (the desktop/CLI use the worker process; semantics are identical).
    let job = app.load_job(&p).unwrap();
    let run = anvil_load::LoadRun::prepare(p.clone(), job, anvil_load::RunOptions { acknowledged: true, ..Default::default() }).unwrap();
    let report = run.execute(CancellationToken::new(), None).await;
    assert_eq!(report.counts.started, 20);
    assert_eq!(report.counts.completed, 20);
    app.save_load_report(&report).unwrap();
    let list = app.load_reports(&ws.meta.id).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(app.load_report(&report.run_id).unwrap().counts.started, 20);
    app.delete_load_report(&report.run_id).unwrap();
    assert!(app.load_reports(&ws.meta.id).unwrap().is_empty());
}

/// LOAD-013 at the app boundary: the editor's plan check names the unit (or
/// the typed refusal) and the preflight shows protocol destinations and
/// refuses unsupported plans before the user can start traffic.
#[tokio::test]
async fn load_plan_check_names_the_unit_and_preflight_refuses_mixed_protocols() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let mut s = RequestSpec::http("GET", &format!("ws://{}/ws", fx.addr));
    s.protocol = anvil_domain::request::Protocol::WebSocket;
    let wsreq = app.create_request(&ws.meta.id, None, "socket", s).unwrap();
    let http = app.create_request(&ws.meta.id, None, "echo", RequestSpec::http("GET", &fx.url("/echo"))).unwrap();

    let p = app.save_load_plan(plan(ws.meta.id, wsreq.meta.id)).unwrap();
    let check = app.load_plan_check(&p).unwrap();
    assert_eq!(check.unit, Some(anvil_domain::load::LoadUnitKind::WebsocketSession));
    assert!(check.refusal.is_none());
    assert_eq!(check.semantics.unwrap().unit_plural, "sessions");
    let pre = app.load_preflight(&p).unwrap();
    assert_eq!(pre.destinations, vec![format!("WebSocket ws://{}", fx.addr)]);
    assert_eq!(pre.unit_label, "WebSocket sessions");
    assert!(pre.warnings.iter().any(|w| w.contains("connection mode does not apply")), "{:?}", pre.warnings);

    let mixed = app.save_load_plan(LoadPlan { chain: vec![http.meta.id, wsreq.meta.id], ..plan(ws.meta.id, http.meta.id) }).unwrap();
    let check = app.load_plan_check(&mixed).unwrap();
    assert_eq!(check.unit, None);
    assert_eq!(check.refusal.as_ref().unwrap().code, anvil_load::RefusalCode::MixedUnitKinds);
    assert_eq!(check.protocols.len(), 2);
    let err = app.load_preflight(&mixed).unwrap_err().to_string();
    assert!(err.contains("LOAD-013"), "{err}");
    assert!(fx.log.entries().is_empty(), "checks and preflights send nothing");
}

/// Datagram tunnels at the app boundary: the plan check describes one tunnel
/// per exchange, the preflight names the proxy every exchange reaches first,
/// and a plan mixing direct and tunneled exchanges is refused.
#[test]
fn load_preflight_names_the_masque_proxy_and_refuses_mixed_datagram_paths() {
    use anvil_domain::request::{MASQUE_DEFAULT_TEMPLATE, MasqueSpec, PayloadEncoding, Protocol, StreamPayload, UdpSpec};
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let udp = |masque: bool| {
        let mut s = RequestSpec::http("GET", "udp://127.0.0.1:9");
        s.protocol = Protocol::Udp;
        s.udp = Some(UdpSpec {
            dtls: false,
            datagrams: vec![StreamPayload { data: "x".into(), encoding: PayloadEncoding::Text }],
            response_window_ms: 100,
            max_datagrams: 1,
            masque: masque.then(|| MasqueSpec {
                proxy_url: "https://127.0.0.1:4433".into(),
                uri_template: MASQUE_DEFAULT_TEMPLATE.into(),
                datagrams: Default::default(),
            }),
            proxy_protocol: None,
        });
        s
    };
    let tunneled = app.create_request(&ws.meta.id, None, "via masque", udp(true)).unwrap();
    let direct = app.create_request(&ws.meta.id, None, "direct", udp(false)).unwrap();

    let p = app.save_load_plan(plan(ws.meta.id, tunneled.meta.id)).unwrap();
    let check = app.load_plan_check(&p).unwrap();
    assert_eq!(check.unit, Some(anvil_domain::load::LoadUnitKind::UdpExchange));
    let sem = check.semantics.unwrap();
    assert!(sem.connection_mode_means.contains("its own MASQUE (CONNECT-UDP) tunnel"), "{}", sem.connection_mode_means);
    let pre = app.load_preflight(&p).unwrap();
    assert_eq!(pre.destinations, vec!["UDP udp://127.0.0.1:9 via MASQUE proxy https://127.0.0.1:4433".to_string()]);
    assert!(!pre.warnings.iter().any(|w| w.contains("Traffic leaves")), "target and proxy are both local: {:?}", pre.warnings);
    assert!(pre.semantics.completed_means.contains("never an exchange with no response observed"));

    let mixed = app.save_load_plan(LoadPlan { chain: vec![direct.meta.id, tunneled.meta.id], ..plan(ws.meta.id, direct.meta.id) }).unwrap();
    let check = app.load_plan_check(&mixed).unwrap();
    let r = check.refusal.expect("mixed datagram paths are refused");
    assert_eq!(r.code, anvil_load::RefusalCode::MixedTunnels);
    assert_eq!(r.request_id, Some(tunneled.meta.id));
    assert!(app.load_preflight(&mixed).is_err());
}

/// The "traffic leaves this machine" warning judges the target and a
/// tunnel's proxy each on its own host: a loopback address in one never
/// hides the other. The MASQUE proxy URL resolves variables like the target.
#[test]
fn load_preflight_warns_when_either_the_target_or_the_tunnel_proxy_is_remote() {
    use anvil_domain::request::{MASQUE_DEFAULT_TEMPLATE, MasqueSpec, PayloadEncoding, Protocol, StreamPayload, UdpSpec};
    use anvil_domain::settings::ProxySelection;
    use anvil_domain::tls::{ProxyKind, ProxyProfile};
    use anvil_domain::workspace::Variable;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let env = app
        .create_environment(
            &ws.meta.id,
            "lab",
            vec![Variable::plain("local_proxy", "127.0.0.1:4433"), Variable::plain("remote_proxy", "proxy.example.test:4433")],
        )
        .unwrap();
    let udp = |url: &str, proxy_url: Option<&str>| {
        let mut s = RequestSpec::http("GET", url);
        s.protocol = Protocol::Udp;
        s.udp = Some(UdpSpec {
            dtls: false,
            datagrams: vec![StreamPayload { data: "x".into(), encoding: PayloadEncoding::Text }],
            response_window_ms: 100,
            max_datagrams: 1,
            masque: proxy_url.map(|u| MasqueSpec {
                proxy_url: u.into(),
                uri_template: MASQUE_DEFAULT_TEMPLATE.into(),
                datagrams: Default::default(),
            }),
            proxy_protocol: None,
        });
        s
    };
    let preflight = |spec: RequestSpec| {
        let req = app.create_request(&ws.meta.id, None, "udp", spec).unwrap();
        let p = app.save_load_plan(LoadPlan { environment_id: Some(env.meta.id), ..plan(ws.meta.id, req.meta.id) }).unwrap();
        app.load_preflight(&p).unwrap()
    };
    let leaves = |w: &[String]| w.iter().any(|w| w.contains("Traffic leaves this machine"));

    // A remote target through a local MASQUE proxy (named by a variable).
    let pre = preflight(udp("udp://192.0.2.10:9", Some("https://{{local_proxy}}")));
    assert_eq!(pre.destinations, vec!["UDP udp://192.0.2.10:9 via MASQUE proxy https://127.0.0.1:4433".to_string()]);
    assert!(leaves(&pre.warnings), "{:?}", pre.warnings);
    // A local target through a remote MASQUE proxy.
    let pre = preflight(udp("udp://127.0.0.1:9", Some("https://{{remote_proxy}}")));
    assert_eq!(pre.destinations, vec!["UDP udp://127.0.0.1:9 via MASQUE proxy https://proxy.example.test:4433".to_string()]);
    assert!(leaves(&pre.warnings), "{:?}", pre.warnings);
    // A target routed through the proxy cannot use its own loopback name as
    // proof that the proxy reaches this machine.
    let pre = preflight(udp("udp://[::1]:9", Some("https://[::1]:4433")));
    assert!(!leaves(&pre.warnings), "{:?}", pre.warnings);
    let pre = preflight(udp("udp://[::1]:9", Some("https://localhost:4433")));
    assert!(!leaves(&pre.warnings), "{:?}", pre.warnings);

    // A local target through a remote HBONE proxy profile, whose host merely
    // contains "localhost".
    let hbone = |address: &str| {
        let profile = app
            .save_proxy_profile(ProxyProfile {
                id: Id::new(),
                workspace_id: ws.meta.id,
                name: "mesh".into(),
                kind: ProxyKind::Hbone,
                address: address.into(),
                username: None,
                password: None,
                no_proxy: String::new(),
                tls_profile_id: None,
                hbone: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .unwrap();
        let mut s = udp("udp://127.0.0.1:9", None);
        s.settings.proxy_profile_id = Some(ProxySelection::Profile { id: profile.id });
        s
    };
    let pre = preflight(hbone("localhost.example.test:15008"));
    assert_eq!(pre.destinations, vec!["UDP udp://127.0.0.1:9 via HBONE proxy localhost.example.test:15008".to_string()]);
    assert!(leaves(&pre.warnings), "{:?}", pre.warnings);
    // A remote target through a local HBONE proxy profile.
    let mut s = hbone("[::1]:15008");
    s.url = "udp://203.0.113.7:9".into();
    let pre = preflight(s);
    assert_eq!(pre.destinations, vec!["UDP udp://203.0.113.7:9 via HBONE proxy [::1]:15008".to_string()]);
    assert!(leaves(&pre.warnings), "{:?}", pre.warnings);
    let pre = preflight(hbone("127.0.0.1:15008"));
    assert!(!leaves(&pre.warnings), "{:?}", pre.warnings);
}

/// The local-traffic warning judges the proxy profile the engine actually
/// routes through, whatever its kind: a loopback target behind a remote
/// HTTP or SOCKS5 proxy leaves this machine. A target the profile's
/// NO_PROXY list bypasses is sent directly: it is labelled without the
/// proxy, and the proxy's host is not judged.
#[test]
fn load_preflight_judges_every_proxy_profile_after_no_proxy() {
    use anvil_domain::request::{PayloadEncoding, Protocol, StreamPayload, UdpSpec};
    use anvil_domain::settings::ProxySelection;
    use anvil_domain::tls::{ProxyKind, ProxyProfile};
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let profile = |kind: ProxyKind, address: &str, no_proxy: &str| {
        app.save_proxy_profile(ProxyProfile {
            id: Id::new(),
            workspace_id: ws.meta.id,
            name: "proxy".into(),
            kind,
            address: address.into(),
            username: None,
            password: None,
            no_proxy: no_proxy.into(),
            tls_profile_id: None,
            hbone: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap()
    };
    let preflight = |mut spec: RequestSpec, proxy: &ProxyProfile| {
        spec.settings.proxy_profile_id = Some(ProxySelection::Profile { id: proxy.id });
        let req = app.create_request(&ws.meta.id, None, "req", spec).unwrap();
        let p = app.save_load_plan(plan(ws.meta.id, req.meta.id)).unwrap();
        app.load_preflight(&p).unwrap()
    };
    let leaves = |w: &[String]| w.iter().any(|w| w.contains("Traffic leaves this machine"));
    let http = || RequestSpec::http("GET", "http://127.0.0.1:8080/x");

    // A loopback target behind a remote HTTP proxy.
    let pre = preflight(http(), &profile(ProxyKind::Http, "proxy.example.test:3128", ""));
    assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:8080 via HTTP proxy proxy.example.test:3128".to_string()]);
    assert!(leaves(&pre.warnings), "{:?}", pre.warnings);
    // A loopback target behind a remote SOCKS5 proxy.
    let pre = preflight(http(), &profile(ProxyKind::Socks5, "192.0.2.10:1080", ""));
    assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:8080 via SOCKS5 proxy 192.0.2.10:1080".to_string()]);
    assert!(leaves(&pre.warnings), "{:?}", pre.warnings);
    // A remote proxy whose NO_PROXY list bypasses the loopback target.
    let pre = preflight(http(), &profile(ProxyKind::Http, "proxy.example.test:3128", "localhost,127.0.0.1"));
    assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:8080".to_string()]);
    assert!(!leaves(&pre.warnings), "{:?}", pre.warnings);
    // Both fixed loopback literals: no warning.
    let pre = preflight(http(), &profile(ProxyKind::Socks5, "127.0.0.1:1080", ""));
    assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:8080 via SOCKS5 proxy 127.0.0.1:1080".to_string()]);
    assert!(!leaves(&pre.warnings), "{:?}", pre.warnings);
    let pre = preflight(http(), &profile(ProxyKind::Socks5, "localhost:1080", ""));
    assert!(!leaves(&pre.warnings), "{:?}", pre.warnings);

    // A datagram target a remote HBONE profile's NO_PROXY bypasses is sent
    // directly: no "via HBONE proxy" label and no warning.
    let mut udp = RequestSpec::http("GET", "udp://127.0.0.1:9");
    udp.protocol = Protocol::Udp;
    udp.udp = Some(UdpSpec {
        dtls: false,
        datagrams: vec![StreamPayload { data: "x".into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 100,
        max_datagrams: 1,
        masque: None,
        proxy_protocol: None,
    });
    let pre = preflight(udp.clone(), &profile(ProxyKind::Hbone, "mesh.example.test:15008", "127.0.0.0/8"));
    assert_eq!(pre.destinations, vec!["UDP udp://127.0.0.1:9".to_string()]);
    assert!(!leaves(&pre.warnings), "{:?}", pre.warnings);
    // Without the bypass the same profile carries it, and it is remote.
    let pre = preflight(udp, &profile(ProxyKind::Hbone, "mesh.example.test:15008", ""));
    assert_eq!(pre.destinations, vec!["UDP udp://127.0.0.1:9 via HBONE proxy mesh.example.test:15008".to_string()]);
    assert!(leaves(&pre.warnings), "{:?}", pre.warnings);
}
