//! What a lock ([`Engine::clear_sensitive_state`]) clears stays cleared when
//! a response that was in flight arrives afterwards: its cookies are not
//! stored and its connection is not pooled again. A gate
//! (`anvil_fixtures::gate`) holds the request until the test has locked.

use anvil_domain::request::RequestSpec;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::{gate, http as fx};
use anvil_transport::recorder::EventCtx;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn get(url: &str) -> ExecutionContext {
    ExecutionContext::standalone(RequestSpec::http("GET", url))
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

fn cookie_seen(f: &fx::Fixture) -> Option<String> {
    f.log.last_request_headers()?.into_iter().find(|(n, _)| n.eq_ignore_ascii_case("cookie")).map(|(_, v)| v)
}

#[tokio::test]
async fn a_response_that_arrives_after_a_lock_leaves_no_cookie_and_no_pooled_connection() {
    init();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let gate = gate::tcp(api.addr, 0).await.unwrap();
    let base = format!("http://{}", gate.addr.unwrap());
    let e = Arc::new(Engine::new());
    let set = get(&format!("{base}/set-cookie?name=sid&value=before-lock"));
    let task = {
        let (e, c) = (e.clone(), set.clone());
        tokio::spawn(async move { run(&e, &c).await })
    };
    tokio::time::timeout(Duration::from_secs(10), gate.held()).await.expect("the request never connected");
    e.clear_sensitive_state();
    gate.release();
    let o = task.await.unwrap();
    // Not canceled: the request completes, and its answer set the cookie.
    assert_eq!(status(&o), Some(200));
    let set_cookie = o.record.response.as_ref().unwrap().header_values("set-cookie").join("; ");
    assert!(set_cookie.starts_with("sid=before-lock"), "{set_cookie}");
    assert_eq!(e.http.pool.stats().connections, 0, "the connection in use at the lock was pooled again");

    // The next request (a new connection, not held) carries nothing from before the lock.
    let o = run(&e, &get(&format!("{base}/echo"))).await;
    assert_eq!(status(&o), Some(200));
    assert_eq!(cookie_seen(&api), None, "the cookie of the answer that arrived after the lock was kept");

    // After unlock, connections and cookies are kept again.
    assert_eq!(e.http.pool.stats().connections, 1);
    assert_eq!(status(&run(&e, &get(&format!("{base}/set-cookie?name=sid&value=after-unlock"))).await), Some(200));
    assert_eq!(status(&run(&e, &get(&format!("{base}/echo"))).await), Some(200));
    assert_eq!(cookie_seen(&api).as_deref(), Some("sid=after-unlock"));
    assert_eq!(e.http.pool.stats().connections, 1, "one connection, reused");
}
