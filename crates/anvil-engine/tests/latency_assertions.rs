//! Latency assertions evaluate the whole exchange: every attempt of a send
//! (redirect hops, retries, protocol fallback), the same definition as the
//! runner's `exchange_ms` and load latency. A slow attempt before a fast final
//! one is still time the request took. Real loopback sockets, no mocks.

use anvil_domain::Id;
use anvil_domain::assertions::{Assertion, AssertionKind};
use anvil_domain::execution::*;
use anvil_domain::outcome::AssertionState;
use anvil_domain::request::RequestSpec;
use anvil_domain::settings::{HttpVersionPolicy, RetryPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// How long the slow attempt takes, and the budget it must not fit in.
const SLOW_MS: u64 = 800;
const BUDGET_MS: u64 = 500;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn with_budget(url: &str) -> ExecutionContext {
    let mut spec = RequestSpec::http("GET", url);
    spec.assertions = vec![Assertion { enabled: true, label: String::new(), kind: AssertionKind::LatencyMs { max: BUDGET_MS } }];
    ExecutionContext::standalone(spec)
}

fn run_layer(c: &mut ExecutionContext, o: SettingsOverrides) {
    c.settings_layers.push(("run".into(), o));
}

/// The one latency assertion's result, checked against the shared exchange
/// time of the record.
fn latency_result(o: &ExecutionOutput) -> (bool, u64) {
    assert_eq!(o.record.assertion_results.len(), 1);
    let r = &o.record.assertion_results[0];
    let actual = r.actual.as_deref().and_then(|a| a.strip_suffix(" ms")).and_then(|a| a.parse::<u64>().ok()).expect("latency in ms");
    let exchange_ms = exchange_duration_us(&o.record.attempts).expect("attempts") / 1000;
    assert_eq!(actual, exchange_ms, "the assertion sees the same exchange time as the runner and load metrics");
    (r.passed, actual)
}

/// One scripted connection: wait after reading the request head, then answer
/// (or close without a response) and close the connection.
struct Step {
    delay_ms: u64,
    response: Option<String>,
}

fn respond(status: &str, extra: &str) -> Option<String> {
    Some(format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 2\r\nConnection: close\r\n\r\nok"))
}

/// A loopback HTTP/1.1 server that plays `steps`, one per accepted connection.
async fn scripted(steps: Vec<Step>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let steps = Arc::new(Mutex::new(VecDeque::from(steps)));
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let Some(step) = steps.lock().unwrap().pop_front() else { return };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                tokio::time::sleep(Duration::from_millis(step.delay_ms)).await;
                if let Some(r) = step.response {
                    let _ = s.write_all(r.as_bytes()).await;
                }
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn latency_assertion_counts_a_slow_hop_before_a_fast_redirect() {
    init();
    let port = scripted(vec![
        Step { delay_ms: SLOW_MS, response: respond("302 Found", "Location: /final\r\n") },
        Step { delay_ms: 0, response: respond("200 OK", "") },
    ])
    .await;
    let o = run(&Engine::new(), &with_budget(&format!("http://127.0.0.1:{port}/first"))).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(o.record.attempts[1].reason, AttemptReason::Redirect { status: 302 });
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
    assert!(o.record.attempts[0].duration_us >= SLOW_MS * 1000, "the first hop was slow: {:?}", o.record.attempts[0].duration_us);
    assert!(o.record.attempts[1].duration_us < BUDGET_MS * 1000, "the final hop alone fits the budget");
    let (passed, actual) = latency_result(&o);
    assert!(!passed, "{actual} ms exceeds the {BUDGET_MS} ms budget");
    assert!(actual >= SLOW_MS);
    assert_eq!(o.record.outcome.assertions, AssertionState::Fail);
}

#[tokio::test]
async fn latency_assertion_counts_a_slow_attempt_before_a_retry() {
    init();
    // The first connection reads the request, waits, then closes without a
    // response; the idempotent GET is retried and answered immediately.
    let port = scripted(vec![Step { delay_ms: SLOW_MS, response: None }, Step { delay_ms: 0, response: respond("200 OK", "") }]).await;
    let mut c = with_budget(&format!("http://127.0.0.1:{port}/"));
    run_layer(
        &mut c,
        SettingsOverrides { retries: Some(RetryPolicy { max_retries: 1, backoff_ms: 0, only_safe: true }), ..Default::default() },
    );
    let o = run(&Engine::new(), &c).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert!(matches!(o.record.attempts[1].reason, AttemptReason::Retry { .. }), "{:?}", o.record.attempts[1].reason);
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
    assert!(o.record.attempts[1].duration_us < BUDGET_MS * 1000, "the final attempt alone fits the budget");
    let (passed, actual) = latency_result(&o);
    assert!(!passed, "{actual} ms exceeds the {BUDGET_MS} ms budget");
    assert!(actual >= SLOW_MS);
    assert_eq!(o.record.outcome.assertions, AssertionState::Fail);
}

#[tokio::test]
async fn single_fast_attempts_still_pass_the_latency_budget() {
    init();
    // A fast redirect chain and a fast single request both fit.
    let port = scripted(vec![
        Step { delay_ms: 0, response: respond("302 Found", "Location: /final\r\n") },
        Step { delay_ms: 0, response: respond("200 OK", "") },
        Step { delay_ms: 0, response: respond("200 OK", "") },
    ])
    .await;
    let e = Engine::new();
    let o = run(&e, &with_budget(&format!("http://127.0.0.1:{port}/first"))).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert!(latency_result(&o).0);
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass);
    let o = run(&e, &with_budget(&format!("http://127.0.0.1:{port}/"))).await;
    assert_eq!(o.record.attempts.len(), 1);
    assert!(latency_result(&o).0);
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass);
}

#[tokio::test]
async fn a_single_slow_attempt_fails_the_latency_budget() {
    init();
    let port = scripted(vec![Step { delay_ms: SLOW_MS, response: respond("200 OK", "") }]).await;
    let o = run(&Engine::new(), &with_budget(&format!("http://127.0.0.1:{port}/"))).await;
    assert_eq!(o.record.attempts.len(), 1);
    let (passed, actual) = latency_result(&o);
    assert!(!passed && actual >= SLOW_MS, "{actual} ms");
    assert_eq!(o.record.outcome.assertions, AssertionState::Fail);
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn lab_trust(c: &mut ExecutionContext) {
    let p = TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let id = p.id;
    c.tls_profiles.push(p);
    run_layer(c, SettingsOverrides { tls_profile_id: Some(id), ..Default::default() });
}

#[tokio::test]
async fn latency_assertion_counts_the_failed_http3_attempt_before_a_tcp_fallback() {
    init();
    // A TCP-only TLS server: HTTP/3 times out its handshake, then TCP answers.
    let tls = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    let f = fx::serve("127.0.0.1:0", Some(tls)).await.unwrap();
    let mut c = with_budget(&format!("https://127.0.0.1:{}/", f.addr.port()));
    lab_trust(&mut c);
    run_layer(
        &mut c,
        SettingsOverrides {
            http_version: Some(HttpVersionPolicy::Http3WithFallback),
            timeouts: Some(TimeoutOverrides { tls_handshake_ms: Some(Some(SLOW_MS)), ..Default::default() }),
            ..Default::default()
        },
    );
    let o = run(&Engine::new(), &c).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(o.record.attempts[0].failure.as_ref().unwrap().kind, FailureKind::QuicHandshakeTimeout);
    assert_eq!(o.record.attempts[1].reason, AttemptReason::ProtocolFallback { from: "h3".into() });
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
    assert!(o.record.attempts[1].duration_us < BUDGET_MS * 1000, "the fallback attempt alone fits the budget");
    let (passed, actual) = latency_result(&o);
    assert!(!passed, "{actual} ms exceeds the {BUDGET_MS} ms budget");
    assert!(actual >= SLOW_MS - 100, "the timed-out HTTP/3 attempt is part of the latency: {actual} ms");
    assert_eq!(o.record.outcome.assertions, AssertionState::Fail);
}
