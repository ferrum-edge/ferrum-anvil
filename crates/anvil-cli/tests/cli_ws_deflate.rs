//! `anvil send` of saved WebSocket requests with permessage-deflate: the
//! real binary, a real profile on disk and the fixture's RFC 7692 peer. The
//! CLI prints the same extension evidence and findings as the desktop app.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::request::{Protocol, RequestSpec, WsBootstrap, WsDeflateOffer, WsMessage, WsSpec};
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::Output;

const PASS: &str = "cli-ws-deflate-passphrase-1";

fn ws(url: String, deflate: bool) -> RequestSpec {
    let mut s = RequestSpec::http("GET", &url);
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![WsMessage::Text { text: "compress me ".repeat(100) }],
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_000,
        permessage_deflate: WsDeflateOffer { enabled: deflate, ..Default::default() },
    });
    s
}

fn setup(root: &Path, port: u16) {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let w = app.create_workspace("Sockets").unwrap();
    app.create_request(&w.meta.id, None, "Deflate", ws(format!("ws://127.0.0.1:{port}/ws?close_after=1"), true)).unwrap();
    app.create_request(&w.meta.id, None, "Declined", ws(format!("ws://127.0.0.1:{port}/ws?pmd=decline&close_after=1"), true)).unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_prints_the_negotiation_and_the_compression_totals() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    setup(&data, f.addr.port());

    let o = anvil(&data, &["send", "Deflate", "--workspace", "Sockets", "--no-history"]).await;
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert!(out.contains("permessage-deflate: negotiated"), "{out}");
    assert!(out.contains("offered:  permessage-deflate; client_max_window_bits"), "{out}");
    assert!(out.contains("answered: permessage-deflate"), "{out}");
    assert!(out.contains("sent: 1 message(s), 1 compressed, 1200 payload bytes"), "{out}");

    let o = anvil(&data, &["send", "Declined", "--workspace", "Sockets", "--no-history"]).await;
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "an offer that is not accepted is not a failure: {out}");
    assert!(out.contains("permessage-deflate: offered, not negotiated"), "{out}");
    assert!(out.contains("answered: no extension"), "{out}");
    assert!(out.contains("permessage-deflate was offered but not negotiated"), "the info finding is printed: {out}");
}
