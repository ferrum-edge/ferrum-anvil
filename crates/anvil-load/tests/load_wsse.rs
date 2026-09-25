//! AUTH-029 under load: WS-Security UsernameToken credentials are generated
//! after final serialization for every actual send — a fresh nonce and a
//! `Created` taken at send time — and never replayed from a prepared request.
//!
//! A small capture server records every request body it receives (the
//! generic fixture logs only body sizes), so the test checks exactly what
//! reached the wire.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, WsseConfig, WssePasswordType};
use anvil_domain::load::*;
use anvil_domain::request::{Body, RequestSpec, SoapVersion};
use anvil_domain::secret::SensitiveValue;
use anvil_engine::ExecutionContext;
use anvil_load::report::{check_balance, check_request_balance};
use anvil_load::{LoadJob, LoadRun, RunOptions};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "fixture-wsse-password";
const ENVELOPE: &str = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:Ping xmlns:m="urn:anvil:lab">1</m:Ping></soap:Body></soap:Envelope>"#;

/// (receive time, body) for every request.
type Captured = Arc<Mutex<Vec<(DateTime<Utc>, String)>>>;

async fn capture_server() -> (String, Captured) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Captured = Arc::default();
    let s2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let seen = s2.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    // One request: head, then Content-Length bytes.
                    let head_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        if buf.len() > 1 << 20 {
                            return;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let len: usize =
                        head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))).unwrap_or(0);
                    while buf.len() < head_end + len {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).into_owned();
                    seen.lock().push((Utc::now(), body));
                    buf.drain(..head_end + len);
                    let reply = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok";
                    if sock.write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (format!("http://{addr}/soap"), seen)
}

fn between<'a>(s: &'a str, open_prefix: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open_prefix)?;
    let after_tag = start + s[start..].find('>')? + 1;
    let end = after_tag + s[after_tag..].find(close)?;
    Some(&s[after_tag..end])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_029_load_sends_fresh_wsse_nonce_and_created_per_iteration() {
    anvil_transport::init();
    let (url, seen) = capture_server().await;
    let mut spec = RequestSpec::http("POST", &url);
    spec.body = Body::Soap { version: SoapVersion::Soap11, envelope: ENVELOPE.into(), action: Some("urn:anvil:lab#Ping".into()) };
    spec.auth = AuthConfig::Wsse {
        config: WsseConfig {
            username: "load-user".into(),
            password: SensitiveValue::template(PASSWORD),
            password_type: WssePasswordType::PasswordDigest,
            timestamp_ttl_secs: Some(60),
            saml_assertion: None,
        },
    };
    let mut ctx = ExecutionContext::standalone(spec);
    ctx.isolation = "ws-load-wsse".into();
    let id = Id::new();
    // Two virtual users with think time over ~2.5 s: the sends span several
    // wall-clock seconds, so a prepared-once `Created` would be visible.
    let plan = LoadPlan {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "wsse freshness".into(),
        workload: Workload::ClosedVirtualUsers {
            stages: vec![Stage { duration_secs: 0, target: 2 }, Stage { duration_secs: 3, target: 2 }],
            think_time_ms: 300,
        },
        chain: vec![id],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: ConnectionMode::Persistent,
        warmup_secs: 0,
        abort: None,
        seed: 7,
        trusted: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let opts =
        RunOptions { acknowledged: true, graceful_stop_ms: 3_000, cancel_drain_ms: 1_000, progress_interval_ms: 250, ..Default::default() };
    let job = LoadJob { requests: vec![(id, ctx)].into_iter().collect(), dataset: None };
    let report = LoadRun::prepare(plan, job, opts).expect("valid plan").execute(CancellationToken::new(), None).await;
    check_balance(&report.counts).expect("iteration ledger");
    check_request_balance(&report.requests).expect("send ledger");

    let got = seen.lock().clone();
    assert!(got.len() >= 8, "enough sends to observe freshness: {}", got.len());
    assert!(report.status_distribution.iter().all(|(s, _)| *s == 200), "{:?}", report.status_distribution);
    let mut nonces = HashSet::new();
    let mut createds = HashSet::new();
    for (received_at, body) in &got {
        assert!(!body.contains(PASSWORD), "PasswordDigest never puts the password on the wire");
        assert!(body.contains(r#"<m:Ping xmlns:m="urn:anvil:lab">1</m:Ping>"#), "the envelope body is preserved byte for byte");
        let nonce_b64 = between(body, "<wsse:Nonce", "</wsse:Nonce>").expect("nonce");
        let ut = &body[body.find("<wsse:UsernameToken").expect("username token")..];
        let created = between(ut, "<wsu:Created", "</wsu:Created>").expect("created");
        let digest = between(ut, "<wsse:Password", "</wsse:Password>").expect("password digest");
        let nonce = base64::engine::general_purpose::STANDARD.decode(nonce_b64).expect("base64 nonce");
        assert_eq!(nonce.len(), 16);
        assert_eq!(
            digest,
            anvil_auth::wsse::password_digest(&nonce, created, PASSWORD),
            "each digest is computed over its own nonce and Created"
        );
        let ts_created = between(body, "<wsu:Timestamp", "</wsu:Created>").and_then(|t| t.rsplit('>').next()).expect("timestamp");
        assert_eq!(ts_created, created, "Timestamp and UsernameToken share the send time");
        let c: DateTime<Utc> = created.parse().expect("RFC 3339 Created");
        let age = (*received_at - c).num_milliseconds();
        assert!((-1_000..=2_000).contains(&age), "Created is taken at send time, not at preparation (age {age} ms)");
        nonces.insert(nonce_b64.to_string());
        createds.insert(created.to_string());
    }
    assert_eq!(nonces.len(), got.len(), "a fresh nonce for every actual send — no replayed envelope");
    assert!(createds.len() >= 2, "Created advances with wall-clock time across the run: {createds:?}");
}
