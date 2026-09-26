//! Scenarios for the `cpdp` profile: a real Ferrum Edge control plane (CP,
//! SQLite) and data planes (DP) that receive their configuration only over
//! the CP's gRPC config sync. The stale-configuration fence (GW-005) is
//! produced for real — by stopping the CP, by partitioning the DP from a CP
//! that keeps running, and by a DP whose CP never existed — never by a
//! backend-authored or injected `config_stale` header (the backend-authored
//! copy is the lookalike, and must not be diagnosed as a stale fence).
//!
//! Operator-side ground truth (DP/CP admin `/health`, the DP's stale WARN log
//! line, fixture logs) is compared with what Anvil concluded; it is never
//! given to the engine.

use crate::fixtures_cpdp::CpdpFixtures;
use crate::gateway::{self, Gateway, Instance, Readiness, http_get};
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::request::RequestSpec;
use anvil_domain::tls::HostBinding;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_transport::recorder::EventCtx;
use anyhow::{Context, Result, bail};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const DP: &str = "127.0.0.1:18780";
const DP_ADMIN: &str = "127.0.0.1:18791";
const CP_ADMIN: &str = "127.0.0.1:18790";
const ORPHAN: &str = "127.0.0.1:18770";
const ORPHAN_ADMIN: &str = "127.0.0.1:18771";
/// The orphan DP's configured control plane (deliberately unbound).
const ORPHAN_CP: &str = "127.0.0.1:18799";
/// `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` in cpdp-dp.conf.
const MAX_STALE: Duration = Duration::from_secs(5);
const STALE_BODY: &str = r#"{"error":"Gateway configuration stale"}"#;

struct Secrets {
    admin_jwt: String,
    cp_dp_grpc: String,
}

pub struct Env {
    engine: Engine,
    fx: CpdpFixtures,
    /// The CP is stopped and restarted by scenarios.
    cp: Mutex<Option<Gateway>>,
    dp: Gateway,
    secrets: Secrets,
    trusted: bool,
    ticks: AtomicU32,
    /// Public signature of the last stale refusal (partition), compared with
    /// the CP-stopped refusal: different root causes, identical signal.
    stale_signature: Mutex<Option<String>>,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<std::path::PathBuf> {
        let run = gateway::repo_root().join("lab/.run");
        vec![self.dp.log_path.clone(), run.join("cpdp-cp/gateway.log"), run.join("cpdp-dp-orphan/gateway.log")]
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

// ---------------------------------------------------------- admin access ---

/// HS256 admin JWT for the CP Admin API (iss=ferrum-edge, role=admin). The
/// secret is generated per run and never logged.
fn admin_jwt(secret: &str) -> String {
    use base64::Engine as _;
    use hmac::{Hmac, KeyInit, Mac};
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let now = chrono::Utc::now().timestamp();
    let header = b64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "iss": "ferrum-edge", "sub": "anvil-lab", "role": "admin",
        "iat": now, "nbf": now - 5, "exp": now + 600, "jti": gateway::random_secret(),
    });
    let payload = b64.encode(claims.to_string().as_bytes());
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(format!("{header}.{payload}").as_bytes());
    let sig = b64.encode(mac.finalize().into_bytes());
    format!("{header}.{payload}.{sig}")
}

/// Minimal authenticated HTTP/1.1 request to the CP Admin API (loopback).
async fn admin(secret: &str, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
    let token = admin_jwt(secret);
    let mut s = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(CP_ADMIN)).await??;
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {CP_ADMIN}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = status_of(&text).context("no HTTP status from the CP admin API")?;
    Ok((status, text))
}

fn status_of(resp: &str) -> Option<u16> {
    resp.split_whitespace().nth(1)?.parse().ok()
}

/// Status and raw text of a plain GET (polling only; not diagnostic evidence).
async fn raw(addr: &str, path: &str) -> (Option<u16>, String) {
    match http_get(addr, path).await {
        Ok(t) => (status_of(&t), t),
        Err(e) => (None, e.to_string()),
    }
}

async fn wait_until(addr: &str, path: &str, max: Duration, pred: impl Fn(Option<u16>, &str) -> bool) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < max {
        let (s, t) = raw(addr, path).await;
        if pred(s, &t) {
            return Some(start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

fn is_stale(s: Option<u16>, t: &str) -> bool {
    s == Some(503) && t.contains("Gateway configuration stale")
}

/// Publish a new configuration version through the CP (a new route) and wait
/// until the DP serves it: the DP's last-applied snapshot is now fresh.
async fn tick(env: &Env) -> Result<Instant> {
    let n = env.ticks.fetch_add(1, Ordering::SeqCst);
    let body = serde_json::json!({
        "id": format!("cpdp-tick-{n}"), "listen_path": format!("/cpdp/tick-{n}"),
        "backend_scheme": "http", "backend_host": "127.0.0.1", "backend_port": 19701,
        "strip_listen_path": true, "pool_enable_http2": false,
    })
    .to_string();
    let (st, text) = admin(&env.secrets.admin_jwt, "POST", "/proxies", Some(&body)).await?;
    if !(200..300).contains(&st) {
        bail!("CP rejected the tick route: {}", text.lines().last().unwrap_or_default());
    }
    wait_until(DP, &format!("/cpdp/tick-{n}/"), Duration::from_secs(20), |s, _| s == Some(200))
        .await
        .context("the DP did not apply the new snapshot within 20 s")?;
    Ok(Instant::now())
}

async fn start_cp(env_vars: &[(&str, String)], append_log: bool) -> Result<Gateway> {
    let run = gateway::repo_root().join("lab/.run/cpdp").display().to_string();
    Gateway::launch(Instance {
        name: "cpdp-cp",
        mode: "cp",
        conf: "cpdp-cp.conf",
        yaml: None,
        vars: &[("LAB_RUN", run)],
        admin_port: 18790,
        env: env_vars,
        readiness: Readiness::Ready,
        append_log,
    })
    .await
}

fn secret_env(s: &Secrets) -> Vec<(&'static str, String)> {
    vec![("FERRUM_ADMIN_JWT_SECRET", s.admin_jwt.clone()), ("FERRUM_CP_DP_GRPC_JWT_SECRET", s.cp_dp_grpc.clone())]
}

// ------------------------------------------------------------- requests ---

fn ctx(env: &Env, addr: &str, path: &str) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(RequestSpec::http("GET", &format!("http://{addr}{path}")));
    c.isolation = "lab-cpdp".into();
    if env.trusted {
        c.integrations.push(IntegrationProfile {
            id: Id::new(),
            workspace_id: Id::new(),
            name: "lab cpdp data planes".into(),
            kind: IntegrationKind::FerrumGateway {
                hosts: vec![
                    HostBinding { host: "127.0.0.1".into(), port: Some(18780) },
                    HostBinding { host: "127.0.0.1".into(), port: Some(18770) },
                ],
                compatibility_id: crate::gateway::compatibility_id(),
                require_verified_tls: false,
                detail: None,
                console_url: None,
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
    }
    c
}

async fn send(env: &Env, addr: &str, path: &str) -> ExecutionOutput {
    // A fresh connection per observation: the fence is per request, and a
    // pooled keep-alive connection must not be what the scenario measures.
    env.engine.http.pool.clear();
    env.engine.execute(&ctx(env, addr, path), EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn header(o: &ExecutionOutput, name: &str) -> Vec<String> {
    o.record.response.as_ref().map(|r| r.header_values(name).iter().map(|s| s.to_string()).collect()).unwrap_or_default()
}

fn body(o: &ExecutionOutput) -> String {
    String::from_utf8_lossy(o.decoded_body.as_ref().unwrap_or(&o.body)).into_owned()
}

/// What a client can see of a refusal (the Date header excluded).
fn signature(o: &ExecutionOutput) -> String {
    let r = o.record.response.as_ref();
    let mut names: Vec<String> =
        r.map(|r| r.headers.iter().map(|h| h.name.to_ascii_lowercase()).filter(|n| n != "date").collect()).unwrap_or_default();
    names.sort();
    format!("{:?} {:?} {:?} {}", r.map(|r| r.status), header(o, "x-gateway-error"), names, body(o))
}

/// New DP operator-log lines since `from` that concern staleness.
fn stale_log(log: &[String], from: usize) -> Vec<String> {
    log.iter().skip(from).filter(|l| l.contains("stale") || l.contains("ConfigSync") || l.contains("CP [")).take(6).cloned().collect()
}

/// Public-evidence checks shared by every genuine stale refusal.
fn stale_checks(c: &mut Checks, o: &ExecutionOutput, trusted: bool) {
    c.status_in(o, &[503]);
    c.add(CheckKind::GroundTruth, "gateway body is the stale-fence literal", body(o).trim() == STALE_BODY, body(o));
    c.token(o, "ferrum.token.config_stale", trusted);
    c.scope(o, "ferrum.token.config_stale", SourceScope::GatewayAdmission);
    c.max_confidence(o, "ferrum.token.config_stale", Confidence::Likely);
    if trusted {
        let f = o.record.findings.iter().find(|f| f.code == "ferrum.token.config_stale");
        c.add(
            CheckKind::Diagnosis,
            "the caller is told the request itself is not the problem",
            f.map(|f| f.does_not_prove.iter().any(|d| d.contains("payload"))).unwrap_or(false),
            "",
        );
    }
    c.absent_prefix(o, "client.");
    c.no_confirmed_claim(o, "crash");
    c.no_confirmed_claim(o, "control plane");
    c.add(
        CheckKind::Diagnosis,
        "no Anvil finding blames authentication or the request body",
        !codes(o).iter().any(|x| x.starts_with("auth.") || x == "http.unauthorized" || x == "http.forbidden"),
        format!("{:?}", codes(o)),
    );
    // What the DP does NOT expose to a client.
    c.add(
        CheckKind::GroundTruth,
        "no Retry-After, no snapshot age and no CP identity in the public response",
        header(o, "retry-after").is_empty() && !body(o).contains("age") && !body(o).contains("18795") && !body(o).contains("control"),
        format!("{:?}", o.record.response.as_ref().map(|r| &r.headers)),
    );
}

async fn dp_recovered(env: &Env, c: &mut Checks, max: Duration) -> Option<ExecutionOutput> {
    match wait_until(DP, "/cpdp/echo/", max, |s, _| s == Some(200)).await {
        Some(t) => {
            let r = send(env, DP, "/cpdp/echo/").await;
            c.success(CheckKind::Recovery, &r);
            c.absent_prefix(&r, "ferrum.token");
            c.add(CheckKind::Recovery, "DP served the CP-delivered route again", true, format!("after {:.1} s", t.as_secs_f32()));
            Some(r)
        }
        None => {
            c.add(CheckKind::Recovery, "DP recovered after the fault was removed", false, format!("not within {max:?}"));
            None
        }
    }
}

// ------------------------------------------------------------- scenarios ---

fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let o = send(env, DP, "/cpdp/echo/").await;
        c.success(CheckKind::Diagnosis, &o);
        c.absent_prefix(&o, "ferrum.token");
        c.add(CheckKind::GroundTruth, "backend received the request", env.fx.echo.log.count_requests() > before, "");
        let (_, h) = raw(DP_ADMIN, "/health").await;
        c.add(
            CheckKind::GroundTruth,
            "DP /health is ready",
            h.contains("\"ready\":true"),
            h.lines().last().unwrap_or_default().to_string(),
        );
        match admin(&env.secrets.admin_jwt, "GET", "/proxies", None).await {
            Ok((st, t)) => c.add(
                CheckKind::GroundTruth,
                "the route exists only in the CP database (the DP has no local config)",
                st == 200 && t.contains("\"cpdp-echo\""),
                format!("CP /proxies {st}"),
            ),
            Err(e) => c.add(CheckKind::GroundTruth, "CP admin API reachable", false, e.to_string()),
        }
        Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
    })
}

fn lookalike(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.fx.echo.log.count_requests();
        let b: String = url::form_urlencoded::byte_serialize(STALE_BODY.as_bytes()).collect();
        // The backend itself answers 503 with the fence's exact body and tries to set the marker.
        let o = send(env, DP, &format!("/cpdp/echo/status/503?body={b}&header=X-Gateway-Error:config_stale")).await;
        c.status_in(&o, &[503]);
        c.add(CheckKind::GroundTruth, "the backend produced this 503", env.fx.echo.log.count_requests() > before, "");
        let (_, h) = raw(DP_ADMIN, "/health").await;
        c.add(CheckKind::GroundTruth, "the DP is fresh (ready), not fenced", h.contains("\"ready\":true"), "");
        let markers = header(&o, "x-gateway-error");
        c.add(
            CheckKind::GroundTruth,
            "the gateway replaced the backend's config_stale marker",
            !markers.iter().any(|m| m.contains("config_stale")),
            format!("{markers:?}"),
        );
        c.add(
            CheckKind::Diagnosis,
            "a backend-authored stale body is not diagnosed as a stale fence",
            !codes(&o).iter().any(|x| x.contains("config_stale"))
                && !o.record.findings.iter().any(|f| f.evidence.iter().any(|e| e.value.contains("gateway.admission.config_stale"))),
            format!("{:?}", codes(&o)),
        );
        c.no_confirmed_claim(&o, "stale");
        c.token(&o, "ferrum.token.backend_error", env.trusted);
        let r = send(env, DP, "/cpdp/echo/").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: vec![] }
    })
}

fn partition(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.dp.log_lines().len();
        let fresh = match tick(env).await {
            Ok(t) => t,
            Err(e) => {
                c.add(CheckKind::GroundTruth, "publish a fresh snapshot before the partition", false, e.to_string());
                return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
            }
        };
        env.fx.cp_path.cut();
        // Within the freshness window the DP keeps serving its last snapshot and shows nothing.
        let early = send(env, DP, "/cpdp/echo/").await;
        let early_age = fresh.elapsed();
        c.add(
            CheckKind::Diagnosis,
            "inside the window (CP unreachable, snapshot fresh) the DP answers normally and nothing is claimed",
            early_age < MAX_STALE
                && early.record.response.as_ref().map(|r| r.status) == Some(200)
                && !codes(&early).iter().any(|x| x.starts_with("ferrum.")),
            format!("{:.1} s after the snapshot: {:?}", early_age.as_secs_f32(), codes(&early)),
        );
        let fenced = wait_until(DP, "/cpdp/echo/", Duration::from_secs(30), is_stale).await;
        let since_snapshot = fresh.elapsed();
        c.add(
            CheckKind::GroundTruth,
            "the fence appeared only after the configured stale bound elapsed",
            fenced.is_some() && since_snapshot >= MAX_STALE - Duration::from_millis(500),
            format!("fenced={fenced:?}, {:.1} s after the last snapshot", since_snapshot.as_secs_f32()),
        );
        let before = env.fx.echo.log.count_requests();
        let o = send(env, DP, "/cpdp/echo/").await;
        stale_checks(&mut c, &o, env.trusted);
        c.add(CheckKind::GroundTruth, "the refused request never reached the backend", env.fx.echo.log.count_requests() == before, "");
        let (_, dph) = raw(DP_ADMIN, "/health").await;
        c.add(
            CheckKind::GroundTruth,
            "DP /health reports unavailable",
            dph.contains("\"ready\":false"),
            dph.lines().last().unwrap_or_default().to_string(),
        );
        let (_, cph) = raw(CP_ADMIN, "/health").await;
        c.add(CheckKind::GroundTruth, "the CP itself is up and ready (a partition, not a crash)", cph.contains("\"ready\":true"), "");
        let log = env.dp.log_lines();
        c.add(
            CheckKind::GroundTruth,
            "DP operator log: stale beyond the bound, new traffic blocked",
            log.iter().skip(from).any(|l| l.contains("stale beyond the configured bound") && l.contains("\"new_traffic_blocked\":true")),
            "",
        );
        *env.stale_signature.lock().expect("signature lock") = Some(signature(&o));
        env.fx.cp_path.heal();
        let r = dp_recovered(env, &mut c, Duration::from_secs(90)).await;
        Outcome { main: Some(o), recovery: r, checks: c, operator_log: stale_log(&log, from) }
    })
}

fn cp_stopped(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.dp.log_lines().len();
        let fresh = match tick(env).await {
            Ok(t) => t,
            Err(e) => {
                c.add(CheckKind::GroundTruth, "publish a fresh snapshot before killing the CP", false, e.to_string());
                return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
            }
        };
        let cp = env.cp.lock().expect("cp lock").take();
        if let Some(cp) = cp {
            cp.kill().await;
        }
        let early = send(env, DP, "/cpdp/echo/").await;
        let early_age = fresh.elapsed();
        c.add(
            CheckKind::Diagnosis,
            "inside the window (CP killed, snapshot fresh) the DP answers normally and nothing is claimed",
            early_age < MAX_STALE
                && early.record.response.as_ref().map(|r| r.status) == Some(200)
                && !codes(&early).iter().any(|x| x.starts_with("ferrum.")),
            format!("{:.1} s after the snapshot: {:?}", early_age.as_secs_f32(), codes(&early)),
        );
        let fenced = wait_until(DP, "/cpdp/echo/", Duration::from_secs(30), is_stale).await;
        c.add(
            CheckKind::GroundTruth,
            "the fence appeared only after the configured stale bound elapsed",
            fenced.is_some() && fresh.elapsed() >= MAX_STALE - Duration::from_millis(500),
            format!("fenced={fenced:?}"),
        );
        let before = env.fx.echo.log.count_requests();
        let o = send(env, DP, "/cpdp/echo/").await;
        stale_checks(&mut c, &o, env.trusted);
        c.add(CheckKind::GroundTruth, "the refused request never reached the backend", env.fx.echo.log.count_requests() == before, "");
        let (cp_status, _) = raw(CP_ADMIN, "/health").await;
        c.add(CheckKind::GroundTruth, "the CP process is gone (its admin port refuses)", cp_status.is_none(), format!("{cp_status:?}"));
        let log = env.dp.log_lines();
        c.add(
            CheckKind::GroundTruth,
            "DP operator log: stale beyond the bound, new traffic blocked",
            log.iter().skip(from).any(|l| l.contains("stale beyond the configured bound") && l.contains("\"new_traffic_blocked\":true")),
            "",
        );
        if let Some(prev) = env.stale_signature.lock().expect("signature lock").clone() {
            c.add(
                CheckKind::Diagnosis,
                "CP crash and DP partition are indistinguishable to the client (identical public signal)",
                prev == signature(&o),
                format!("partition: {prev} | cp killed: {}", signature(&o)),
            );
        }
        // Recovery: restart the CP on the same database; the DP reconnects and re-applies.
        let recovery = match start_cp(&secret_env(&env.secrets), true).await {
            Ok(cp) => {
                *env.cp.lock().expect("cp lock") = Some(cp);
                dp_recovered(env, &mut c, Duration::from_secs(90)).await
            }
            Err(e) => {
                c.add(CheckKind::Recovery, "restart the CP", false, e.to_string());
                None
            }
        };
        Outcome { main: Some(o), recovery, checks: c, operator_log: stale_log(&log, from) }
    })
}

fn orphan(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let dp = match Gateway::launch(Instance {
            name: "cpdp-dp-orphan",
            mode: "dp",
            conf: "cpdp-dp-orphan.conf",
            yaml: None,
            vars: &[],
            admin_port: 18771,
            env: &secret_env(&env.secrets),
            readiness: Readiness::Live,
            append_log: false,
        })
        .await
        {
            Ok(g) => g,
            Err(e) => {
                c.add(CheckKind::GroundTruth, "start the orphan data plane", false, e.to_string());
                return Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
            }
        };
        let started = Instant::now();
        // Before its bound elapses, the config-less DP answers every path with a route miss.
        let early = send(env, ORPHAN, "/cpdp/echo/").await;
        c.add(
            CheckKind::Diagnosis,
            "the orphan's early 404 is a plain route miss to the client; no stale claim",
            early.record.response.as_ref().map(|r| r.status) == Some(404)
                && codes(&early).contains(&"http.not_found".to_string())
                && !codes(&early).iter().any(|x| x.contains("config_stale")),
            format!("{:.1} s after start: {:?}", started.elapsed().as_secs_f32(), codes(&early)),
        );
        let fenced = wait_until(ORPHAN, "/cpdp/echo/", Duration::from_secs(20), is_stale).await;
        c.add(
            CheckKind::GroundTruth,
            "the fence appeared without any CP ever being authoritative",
            fenced.is_some(),
            format!("{fenced:?}"),
        );
        let o = send(env, ORPHAN, "/cpdp/echo/").await;
        stale_checks(&mut c, &o, env.trusted);
        let (_, h) = raw(ORPHAN_ADMIN, "/health").await;
        c.add(
            CheckKind::GroundTruth,
            "orphan /health reports unavailable",
            h.contains("\"ready\":false"),
            h.lines().last().unwrap_or_default().to_string(),
        );
        let unbound = tokio::net::TcpStream::connect(ORPHAN_CP).await.is_err();
        c.add(CheckKind::GroundTruth, "nothing listens on the orphan's configured CP address", unbound, ORPHAN_CP);
        let log = dp.log_lines();
        c.add(
            CheckKind::GroundTruth,
            "orphan operator log: stale beyond the bound, new traffic blocked",
            log.iter().any(|l| l.contains("stale beyond the configured bound") && l.contains("\"new_traffic_blocked\":true")),
            "",
        );
        dp.stop().await;
        // No recovery exists for a DP whose CP never existed; the CP-backed DP is unaffected.
        let r = send(env, DP, "/cpdp/echo/").await;
        c.success(CheckKind::Recovery, &r);
        Outcome { main: Some(o), recovery: Some(r), checks: c, operator_log: stale_log(&log, 0) }
    })
}

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-CPDP", title: "Positive control: DP serves a route delivered by the CP", run: ctrl },
        Def { id: "GW-005-lookalike", title: "Backend-authored stale body and marker (not a fence)", run: lookalike },
        Def { id: "GW-005-partition", title: "Stale DP fence: DP partitioned from a running CP", run: partition },
        Def { id: "GW-005", title: "Stale DP fence: CP killed (crash), then restarted", run: cp_stopped },
        Def { id: "GW-005-orphan", title: "Stale DP fence: DP whose CP never existed", run: orphan },
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "cpdp",
        about: "Control plane + data planes: genuine stale-configuration fences (DP 18780, CP admin 18790, orphan DP 18770)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> Result<Env> {
    let run = gateway::repo_root().join("lab/.run/cpdp");
    std::fs::create_dir_all(&run)?;
    for f in ["cpdp-cp.db", "cpdp-cp.db-wal", "cpdp-cp.db-shm", "cpdp-cp.db-journal"] {
        let _ = std::fs::remove_file(run.join(f));
    }
    let fx = CpdpFixtures::start().await?;
    let secrets = Secrets { admin_jwt: gateway::random_secret(), cp_dp_grpc: gateway::random_secret() };
    let env_vars = secret_env(&secrets);
    let cp = start_cp(&env_vars, false).await?;
    // Seed the CP (route + global access log) through its Admin API.
    let root = gateway::repo_root().join("lab/gateway");
    for (path, file) in [("/proxies", "cpdp-seed-proxy.json"), ("/plugins/config", "cpdp-seed-plugin.json")] {
        let body = std::fs::read_to_string(root.join(file))?;
        let (st, text) = admin(&secrets.admin_jwt, "POST", path, Some(&body)).await?;
        if !(200..300).contains(&st) {
            bail!("seeding {file} into the CP failed ({st}): {}", text.lines().last().unwrap_or_default());
        }
    }
    // The DP reports ready only after applying a CP snapshot.
    let dp = Gateway::launch(Instance {
        name: "cpdp-dp",
        mode: "dp",
        conf: "cpdp-dp.conf",
        yaml: None,
        vars: &[],
        admin_port: 18791,
        env: &env_vars,
        readiness: Readiness::Ready,
        append_log: false,
    })
    .await?;
    if wait_until(DP, "/cpdp/echo/", Duration::from_secs(30), |s, _| s == Some(200)).await.is_none() {
        bail!("the data plane never served the CP-delivered route");
    }
    // Let the DP's own backend capability probe settle, then forget it.
    tokio::time::sleep(Duration::from_secs(2)).await;
    fx.echo.log.clear();
    Ok(Env {
        engine: Engine::new(),
        fx,
        cp: Mutex::new(Some(cp)),
        dp,
        secrets,
        trusted: true,
        ticks: AtomicU32::new(0),
        stale_signature: Mutex::new(None),
    })
}

async fn stop(env: Env) {
    env.dp.stop().await;
    let cp = env.cp.lock().expect("cp lock").take();
    if let Some(cp) = cp {
        cp.stop().await;
    }
}

async fn run(args: RunArgs) -> Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("cpdp")?;
    let mut env = start().await?;
    let results = harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await;
    let finished = match &results {
        Ok(r) => harness::finish(&ctx, &env, r).map(|_| ()),
        Err(_) => Ok(()),
    };
    stop(env).await;
    finished?;
    results
}

async fn up() -> Result<()> {
    let env = start().await?;
    println!("cpdp lab running: DP http://{DP} (admin {DP_ADMIN}), CP admin {CP_ADMIN} (gRPC 127.0.0.1:18795 via relay 127.0.0.1:19795)");
    println!("route /cpdp/echo/ is delivered by the CP; operator logs under lab/.run/cpdp-*/gateway.log");
    harness::wait_for_shutdown().await?;
    stop(env).await;
    Ok(())
}
