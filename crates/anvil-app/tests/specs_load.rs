//! App-level spec import / reimport and load-plan services.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_app::specs::SpecTarget;
use anvil_domain::Id;
use anvil_domain::assertions::{Extraction, ExtractionSource};
use anvil_domain::load::{LoadPlan, Workload};
use anvil_domain::request::{Body, RequestSpec};
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

/// Preflight supplies synthetic iteration values to the preview, so values in
/// a fixed loopback URL's path/query do not prevent confirmation. It refuses
/// an origin selected by those same values.
#[tokio::test]
async fn load_preflight_resolves_iteration_values_but_refuses_dynamic_origins() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let dataset = app
        .create_dataset(&ws.meta.id, "rows", DatasetFormat::Csv, b"qaRow\nfirst\nsecond\n", vec![])
        .unwrap();

    let mut producer_spec = RequestSpec::http("GET", &fx.url("/echo"));
    producer_spec.extractions.push(Extraction {
        variable: "qaMethod".into(),
        source: ExtractionSource::JsonPath { path: "$.method".into() },
        sensitive: false,
    });
    let producer = app.create_request(&ws.meta.id, None, "producer", producer_spec).unwrap();
    let mut consumer_spec = RequestSpec::http(
        "GET",
        &fx.url("/echo?method={{qaMethod}}&row={{qaRow}}&iteration={{anvil.iteration}}&vu={{anvil.vu}}"),
    );
    consumer_spec.body = Body::Raw { text: "row={{qaRow}}".into(), content_type: None };
    let consumer = app.create_request(&ws.meta.id, None, "consumer", consumer_spec).unwrap();
    let p = app
        .save_load_plan(LoadPlan {
            chain: vec![producer.meta.id, consumer.meta.id],
            dataset_id: Some(dataset.meta.id),
            ..plan(ws.meta.id, producer.meta.id)
        })
        .unwrap();

    let preflight = app.load_preflight(&p).unwrap();
    assert_eq!(preflight.dataset_rows, Some(2));
    assert!(preflight.destinations.iter().any(|d| d == &format!("GET http://{}", fx.addr)));
    assert!(!preflight.warnings.iter().any(|w| w.contains("Traffic leaves this machine")), "{:?}", preflight.warnings);

    let dynamic = app
        .create_request(&ws.meta.id, None, "dynamic target", RequestSpec::http("GET", "http://{{qaRow}}/echo"))
        .unwrap();
    let p = app
        .save_load_plan(LoadPlan {
            chain: vec![dynamic.meta.id],
            dataset_id: Some(dataset.meta.id),
            ..plan(ws.meta.id, dynamic.meta.id)
        })
        .unwrap();
    let error = app.load_preflight(&p).unwrap_err().to_string();
    assert!(error.contains("cannot prove that a variable URL origin stays on loopback"), "{error}");
    assert!(!error.contains("first") && !error.contains("second"), "dataset values leaked into preflight: {error}");

    let dynamic_extracted = app
        .create_request(
            &ws.meta.id,
            None,
            "extracted target",
            RequestSpec::http("GET", "http://{{qaMethod}}/echo"),
        )
        .unwrap();
    let p = app
        .save_load_plan(LoadPlan {
            chain: vec![producer.meta.id, dynamic_extracted.meta.id],
            ..plan(ws.meta.id, producer.meta.id)
        })
        .unwrap();
    let error = app.load_preflight(&p).unwrap_err().to_string();
    assert!(error.contains("cannot prove that a variable URL origin stays on loopback"), "{error}");

    let dynamic_helper = app
        .create_request(
            &ws.meta.id,
            None,
            "dynamic helper target",
            RequestSpec::http("GET", "http://{{$randomFrom 127.0.0.1|example.org}}/echo"),
        )
        .unwrap();
    let p = app.save_load_plan(plan(ws.meta.id, dynamic_helper.meta.id)).unwrap();
    let error = app.load_preflight(&p).unwrap_err().to_string();
    assert!(error.contains("cannot prove that a variable URL origin stays on loopback"), "{error}");
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
    // Both local, including IPv6 loopback and `localhost`: no warning.
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
    // Both local: no warning.
    let pre = preflight(http(), &profile(ProxyKind::Socks5, "localhost:1080", ""));
    assert_eq!(pre.destinations, vec!["GET http://127.0.0.1:8080 via SOCKS5 proxy localhost:1080".to_string()]);
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
