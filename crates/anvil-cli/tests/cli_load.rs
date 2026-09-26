//! `anvil load …` for protocol units (LOAD-013) end to end: the real binary
//! (which re-launches itself as the load worker), a real profile on disk and
//! real fixtures.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::load::LoadReport;
use anvil_domain::request::{PayloadEncoding, Protocol, RequestSpec, StreamPayload, UdpSpec, WsBootstrap, WsMessage, WsSpec};
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::Output;

const PASS: &str = "cli-load-passphrase-1";

fn setup(root: &Path, http: &str, udp: std::net::SocketAddr) {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let ws = app.create_workspace("Streams").unwrap();
    let mut socket = RequestSpec::http("GET", &format!("ws://{http}/ws"));
    socket.protocol = Protocol::WebSocket;
    socket.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![WsMessage::Text { text: "hello".into() }, WsMessage::Text { text: "again".into() }],
        expect_messages: 2,
        max_message_bytes: 1 << 20,
        idle_close_ms: 2_000,
    });
    app.create_request(&ws.meta.id, None, "Socket", socket).unwrap();
    let mut dgram = RequestSpec::http("GET", &format!("udp://{udp}"));
    dgram.protocol = Protocol::Udp;
    dgram.udp = Some(UdpSpec {
        dtls: false,
        datagrams: vec![StreamPayload { data: "ping".into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 200,
        max_datagrams: 10,
        masque: None,
        proxy_protocol: None,
    });
    app.create_request(&ws.meta.id, None, "Datagram", dgram).unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_protocol_commands_end_to_end() {
    anvil_transport::init();
    anvil_fixtures::init();
    let http = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let udp = anvil_fixtures::streams::udp("127.0.0.1:0", anvil_fixtures::streams::UdpMode::Silent).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    setup(root.path(), &http.addr.to_string(), udp.addr);
    let data = root.path();

    // WebSocket sessions: the plan names its unit, and the run reports sessions and messages.
    let o = anvil(data, &["load", "create", "Streams", "sockets", "--request", "Socket", "--iterations", "6", "--concurrency", "2"]).await;
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("load unit: WebSocket sessions"), "{}", text(&o));
    let o = anvil(data, &["load", "check", "Streams", "sockets"]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("\"unit\": \"websocket_session\""), "{}", text(&o));
    let o = anvil(data, &["load", "run", "Streams", "sockets"]).await;
    assert_eq!(o.status.code(), Some(3), "never starts without --i-am-authorized: {}", text(&o));
    assert!(text(&o).contains("load unit: WebSocket sessions"));
    let json = data.join("sockets.json");
    let o = anvil(data, &["load", "run", "Streams", "sockets", "--i-am-authorized", "--json", json.to_str().unwrap()]).await;
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = text(&o);
    assert!(
        out.contains("websocket: 6 opened, 0 handshake rejected, 0 not opened, 6 closed cleanly; messages 12 sent / 12 received"),
        "{out}"
    );
    assert!(out.contains("websocket rtt: 12 pair(s)"), "{out}");
    let (r, _) = anvil_load::report::open_json(&std::fs::read_to_string(&json).unwrap()).unwrap();
    let r: LoadReport = r;
    assert_eq!(r.protocol_metrics.unwrap().websocket.unwrap().opened, 6);

    // UDP against a silent peer: sent and received stay separate; silence is
    // neither success nor failure, so the run itself did not fail.
    let o =
        anvil(data, &["load", "create", "Streams", "datagrams", "--request", "Datagram", "--iterations", "3", "--concurrency", "1"]).await;
    assert!(o.status.success(), "{}", text(&o));
    let o = anvil(data, &["load", "run", "Streams", "datagrams", "--i-am-authorized"]).await;
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert!(out.contains("datagrams: 3 sent / 0 received (separate counts; no delivery is inferred)"), "{out}");
    assert!(out.contains("3 with no response observed"), "{out}");

    // Mixed protocols in one plan: refused, typed, before anything is sent.
    let before = http.log.entries().len();
    let o = anvil(data, &["load", "create", "Streams", "mixed", "--request", "Socket", "--request", "Datagram", "--iterations", "1"]).await;
    assert!(text(&o).contains("refused for load"), "{}", text(&o));
    let o = anvil(data, &["load", "check", "Streams", "mixed"]).await;
    assert_eq!(o.status.code(), Some(3));
    assert!(text(&o).contains("mixed_unit_kinds"), "{}", text(&o));
    let o = anvil(data, &["load", "run", "Streams", "mixed", "--i-am-authorized"]).await;
    assert!(!o.status.success());
    assert!(text(&o).contains("LOAD-013"), "{}", text(&o));
    assert_eq!(http.log.entries().len(), before, "a refused plan sends nothing");
}
