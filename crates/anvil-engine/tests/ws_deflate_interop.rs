//! Interoperability of Anvil's permessage-deflate (RFC 7692) with an
//! independent implementation: the Python `websockets` library, whose codec
//! is CPython's C zlib. Offline, but it needs a Python with `websockets`
//! installed, so it is ignored by default:
//!
//! ```text
//! ANVIL_INTEROP_PYTHON=python3.11 cargo test -p anvil-engine --test ws_deflate_interop -- --ignored
//! ```
//!
//! Without such a Python the test fails (it never passes silently).

use anvil_domain::execution::Direction;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus, WsExtensions, WsNegotiation};
use anvil_domain::request::*;
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_transport::recorder::EventCtx;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use tokio_util::sync::CancellationToken;

/// An echo server with the given `ServerPerMessageDeflateFactory` arguments.
const SERVER: &str = r#"
import asyncio, json, sys
import websockets
from websockets.extensions.permessage_deflate import ServerPerMessageDeflateFactory

kwargs = json.loads(sys.argv[1])

async def echo(ws, path=None):
    print("negotiated", repr(ws.extensions), flush=True)
    async for m in ws:
        await ws.send(m)

async def main():
    factory = ServerPerMessageDeflateFactory(**kwargs)
    async with websockets.serve(echo, "127.0.0.1", 0, extensions=[factory], compression=None, max_size=1 << 20) as server:
        print(server.sockets[0].getsockname()[1], flush=True)
        await asyncio.Future()

asyncio.run(main())
"#;

struct PyServer {
    child: Child,
    port: u16,
}

impl Drop for PyServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn python() -> String {
    std::env::var("ANVIL_INTEROP_PYTHON").unwrap_or_else(|_| "python3".into())
}

fn start(kwargs: &str) -> PyServer {
    let py = python();
    let mut child = Command::new(&py)
        .args(["-c", SERVER, kwargs])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {py}: {e} (set ANVIL_INTEROP_PYTHON to a Python with `websockets`)"));
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    let port =
        line.trim().parse().unwrap_or_else(|_| panic!("{py} did not start a websockets server (is `websockets` installed?): {line:?}"));
    PyServer { child, port }
}

fn ctx(port: u16, deflate: WsDeflateOffer, messages: Vec<WsMessage>) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", &format!("ws://127.0.0.1:{port}/"));
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages,
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 800,
        permessage_deflate: deflate,
    });
    let mut c = ExecutionContext::standalone(s);
    let t = TimeoutOverrides {
        connect_ms: Some(Some(3_000)),
        response_headers_ms: Some(Some(5_000)),
        total_ms: Some(Some(20_000)),
        ..Default::default()
    };
    c.settings_layers.push(("run".into(), SettingsOverrides { timeouts: Some(t), ..Default::default() }));
    c
}

fn ext(o: &ExecutionOutput) -> &WsExtensions {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { extensions: Some(e), .. } => e,
        other => panic!("{other:?}"),
    }
}

fn text(n: usize, seed: &str) -> String {
    let unit = format!("{seed} interop over permessage-deflate; ");
    unit.repeat(n / unit.len() + 1)[..n].to_string()
}

#[tokio::test]
#[ignore = "needs a Python with the `websockets` library (ANVIL_INTEROP_PYTHON); run with --ignored"]
async fn permessage_deflate_interoperates_with_python_websockets() {
    anvil_transport::init();
    let offer = WsDeflateOffer { enabled: true, ..Default::default() };
    // (server factory arguments, Anvil's offer, expected answer, Anvil compresses)
    let cases: Vec<(&str, WsDeflateOffer, &str, bool)> = vec![
        ("{}", offer.clone(), "permessage-deflate", true),
        (
            r#"{"server_no_context_takeover": true, "client_no_context_takeover": true}"#,
            offer.clone(),
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            true,
        ),
        (
            r#"{"server_max_window_bits": 10, "client_max_window_bits": 9}"#,
            offer.clone(),
            "permessage-deflate; server_max_window_bits=10; client_max_window_bits=9",
            true,
        ),
        (
            "{}",
            WsDeflateOffer {
                server_no_context_takeover: true,
                client_no_context_takeover: true,
                server_max_window_bits: Some(11),
                ..offer.clone()
            },
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=11",
            true,
        ),
        (r#"{"client_max_window_bits": 8}"#, offer.clone(), "permessage-deflate; client_max_window_bits=8", false),
    ];
    for (kwargs, deflate, answer, compresses) in cases {
        let server = start(kwargs);
        let messages = vec![
            WsMessage::Text { text: text(3000, "one") },
            WsMessage::Text { text: text(3000, "one") },
            WsMessage::Text { text: String::new() },
            WsMessage::Binary { hex: "00ff".repeat(700) },
            WsMessage::Text { text: text(2500, "two") },
        ];
        let sizes = [3000u64, 3000, 0, 1400, 2500];
        let o = Engine::new().execute(&ctx(server.port, deflate, messages), EventCtx::none(), CancellationToken::new()).await;
        let a = o.record.attempts.last().unwrap();
        assert!(a.failure.is_none(), "{kwargs}: {:?}", a.failure);
        let e = ext(&o);
        assert_eq!(e.negotiation, WsNegotiation::Negotiated, "{kwargs}");
        assert_eq!(e.answered.as_deref(), Some(answer), "{kwargs}");
        assert_eq!(e.deflate.as_ref().unwrap().client_compresses, compresses, "{kwargs}");
        let s = o.record.stream.as_ref().unwrap();
        let got: Vec<u64> = s
            .messages
            .iter()
            .filter(|m| m.direction == Direction::Received && (m.kind == "text" || m.kind == "binary"))
            .map(|m| m.size)
            .collect();
        assert_eq!(got, sizes, "{kwargs}: every message came back intact");
        let t = e.traffic.as_ref().unwrap();
        assert_eq!(t.sent.compressed_messages, if compresses { 5 } else { 0 }, "{kwargs}");
        assert_eq!(t.received.compressed_messages, 5, "{kwargs}: websockets compresses every message");
        assert!(t.received.wire_bytes < t.received.payload_bytes / 4, "{kwargs}: {t:?}");
        match &o.record.outcome.protocol_status {
            ProtocolStatus::WebSocket { close_code, closed_by, .. } => {
                assert_eq!((*close_code, *closed_by), (Some(1000), ClosedBy::Client))
            }
            other => panic!("{other:?}"),
        }
        eprintln!("interop {kwargs}: answer {answer:?}, sent {:?}, received {:?}", t.sent, t.received);
    }
}
