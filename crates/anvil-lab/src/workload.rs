//! The `workload` lab profile: Anvil as a client of the real Ferrum Edge
//! SPIFFE Workload API (gRPC over a Unix socket), using what it issues —
//! X.509-SVIDs as TLS client identities and JWT-SVIDs as bearer tokens —
//! against the same release's mesh and proxy listeners. No SPIRE, no
//! Kubernetes, no control plane:
//!
//! * **workload-mesh** (`lab/gateway/workload-mesh.{conf,json}`): mesh mode,
//!   sidecar topology, `FERRUM_MESH_CA_BACKEND=internal` with the dev-only
//!   self-signed root, and the in-process Workload API
//!   (`FERRUM_MESH_WORKLOAD_API_ENABLED=true`, off by default) on a socket.
//!   Its attestation rule maps **Anvil's own uid** (the kernel `SO_PEERCRED`
//!   uid the server reads from the socket) to
//!   `spiffe://anvil.lab/ns/lab/sa/anvil-client`. Its STRICT inbound mTLS
//!   listener 127.0.0.1:17406 fronts the echo workload on 127.0.0.1:17501.
//!   JWT-SVIDs live 5 s here (`FERRUM_MESH_JWT_SVID_TTL_SECONDS`), so an
//!   issued token can expire during the run.
//! * **workload-foreign**: the same, except its rule maps *another* uid, so
//!   attestation refuses Anvil (`PERMISSION_DENIED`).
//! * **workload-proxy** (`lab/gateway/workload-proxy.{conf,yaml}`): file mode;
//!   route `/wl/jwt` → echo 127.0.0.1:17502 protected by `jwks_auth` with the
//!   trust domain's JWKS as the workload-mesh Workload API returned it
//!   (`FetchJWTBundles`, through Anvil's own client) and one audience.
//!
//! The socket must satisfy Ferrum's socket contract (listener.rs
//! `WorkloadApiSocketConfig::validate`): a parent of at most 74 bytes whose
//! every ancestor is owned by this user or root and is not group/world
//! writable without the sticky bit. The lab uses `lab/.run/workload/wapi`
//! when it qualifies and otherwise a private `0700` directory under the
//! system temporary directory (`/private/tmp` on macOS, where `/tmp` is a
//! symlink), and records which.
//!
//! Ground truth, never given to the engine: the echo fixtures' request logs,
//! each gateway's operator log (transaction lines; the Workload API's debug
//! `workload attested` / `minted JWT-SVID` lines and its `workload
//! attestation failed` warning), and the lookalike fixture's log.

use crate::fixtures_policy::{codes, send, skips};
use crate::gateway::{self, Gateway, Instance, Readiness};
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::auth::AuthConfig;
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ClientIdentity, HostBinding, ServerSpiffeIdentity, TlsMinVersion, TlsProfile};
use anvil_domain::workload::*;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_transport::workload_api::{WorkloadClient, resolve_endpoint};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

/// workload-mesh sidecar inbound mTLS listener.
pub const MESH_INBOUND: u16 = 17406;
const MESH_ADMIN: u16 = 17490;
const FOREIGN_ADMIN: u16 = 17492;
/// workload-proxy HTTP listener.
pub const PROXY_PORT: u16 = 17480;
const PROXY_ADMIN: u16 = 17491;
/// The mesh workload (echo), the API behind the proxy (echo), and a
/// lookalike that answers like the proxy's jwks_auth refusal.
pub const MESH_BACKEND: u16 = 17501;
pub const API_BACKEND: u16 = 17502;
pub const LOOKALIKE: u16 = 17503;
const SVC_ID: &str = "spiffe://anvil.lab/ns/lab/sa/workload-svc";
const CLIENT_ID: &str = "spiffe://anvil.lab/ns/lab/sa/anvil-client";
const FOREIGN_ID: &str = "spiffe://anvil.lab/ns/lab/sa/another-user";
const SVC_HOST: &str = "svc.ferrum.svc.cluster.local";
/// The audience the proxy's jwks_auth accepts, and one it does not.
const AUDIENCE: &str = "spiffe://anvil.lab/api/orders";
const WRONG_AUDIENCE: &str = "spiffe://anvil.lab/api/billing";
/// JWT-SVID lifetime on workload-mesh (seconds).
const JWT_TTL: u64 = 5;
/// The proxy's public refusal body for any rejected JWT (jwks_auth.rs).
const JWKS_REFUSAL: &str = r#"{"error":"Invalid or unrecognized JWT"}"#;

pub struct Env {
    pub engine: Engine,
    pub mesh: Gateway,
    pub foreign: Gateway,
    pub proxy: Gateway,
    pub mesh_backend: fx::Fixture,
    pub api_backend: fx::Fixture,
    pub lookalike: fx::Fixture,
    pub mesh_socket: PathBuf,
    pub foreign_socket: PathBuf,
    /// A path where no Workload API listens (the default posture:
    /// `FERRUM_MESH_WORKLOAD_API_ENABLED=false` binds nothing).
    pub missing_socket: PathBuf,
    pub socket_note: String,
    /// Key id of the trust domain's JWT signing key (from its JWKS).
    pub kid: String,
    expired: tokio::sync::OnceCell<Zeroizing<String>>,
    pub trusted: bool,
    n: AtomicU64,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<PathBuf> {
        vec![self.mesh.log_path.clone(), self.foreign.log_path.clone(), self.proxy.log_path.clone()]
    }
}

fn uri(p: &Path) -> String {
    format!("unix://{}", p.display())
}

impl Env {
    fn base(&self, spec: RequestSpec) -> ExecutionContext {
        let mut c = ExecutionContext::standalone(spec);
        c.isolation = format!("lab-workload-{}", self.n.fetch_add(1, Ordering::Relaxed));
        if self.trusted {
            c.integrations.push(IntegrationProfile {
                id: anvil_domain::Id::new(),
                workspace_id: anvil_domain::Id::new(),
                name: "lab workload gateways".into(),
                kind: IntegrationKind::FerrumGateway {
                    hosts: [MESH_INBOUND, PROXY_PORT].iter().map(|p| HostBinding { host: "127.0.0.1".into(), port: Some(*p) }).collect(),
                    compatibility_id: gateway::compatibility_id(),
                    require_verified_tls: false,
                    detail: None,
                    console_url: None,
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            });
        }
        c.settings_layers.push((
            "run".into(),
            SettingsOverrides {
                timeouts: Some(TimeoutOverrides {
                    connect_ms: Some(Some(3_000)),
                    tls_handshake_ms: Some(Some(3_000)),
                    response_headers_ms: Some(Some(5_000)),
                    total_ms: Some(Some(15_000)),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ));
        c
    }

    /// HTTPS to the mesh inbound listener with an X.509-SVID from `socket`,
    /// the server verified by SPIFFE ID against the Workload API's bundle.
    fn mesh_request(&self, socket: &Path, path: &str) -> ExecutionContext {
        let mut spec = RequestSpec::http("GET", &format!("https://127.0.0.1:{MESH_INBOUND}{path}"));
        spec.headers.push(KeyValue::new("Host", SVC_HOST));
        let mut c = self.base(spec);
        let tls = TlsProfile {
            id: anvil_domain::Id::new(),
            workspace_id: anvil_domain::Id::new(),
            name: "Workload API identity".into(),
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![],
            client_identity: Some(ClientIdentity::WorkloadApi { endpoint: uri(socket), spiffe_id: None, trust_bundle: true }),
            bindings: vec![],
            min_version: TlsMinVersion::Tls12,
            server_name_override: None,
            server_spiffe: Some(ServerSpiffeIdentity { expected_server_spiffe_id: Some(SVC_ID.into()), trust_domain: None }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        if let Some((_, o)) = c.settings_layers.last_mut() {
            o.tls_profile_id = Some(tls.id);
        }
        c.tls_profiles.push(tls);
        c
    }

    /// A JWT-SVID auth request to `url`.
    fn jwt_request(&self, url: &str, config: JwtSvidConfig) -> ExecutionContext {
        let mut spec = RequestSpec::http("GET", url);
        spec.auth = AuthConfig::JwtSvid { config };
        self.base(spec)
    }

    fn jwt_config(&self, source: JwtSvidSource, audience: &str) -> JwtSvidConfig {
        JwtSvidConfig {
            source,
            audiences: vec![audience.into()],
            endpoint: uri(&self.mesh_socket),
            spiffe_id: None,
            verify_with_bundles: true,
            send_despite_failed_checks: false,
            header_name: "Authorization".into(),
            prefix: "Bearer".into(),
        }
    }

    /// A JWT-SVID the real Workload API issued for `AUDIENCE`, fetched with
    /// Anvil's client and kept until it has expired (once per run).
    async fn expired_token(&self) -> Zeroizing<String> {
        self.expired
            .get_or_init(|| async {
                let endpoint = resolve_endpoint(&uri(&self.mesh_socket)).expect("mesh socket endpoint");
                let t = WorkloadClient::new(endpoint, Duration::from_secs(5))
                    .fetch_jwt_svid(&[AUDIENCE.to_string()], None)
                    .await
                    .result
                    .expect("FetchJWTSVID from workload-mesh");
                tokio::time::sleep(Duration::from_secs(JWT_TTL + 1)).await;
                t.token
            })
            .await
            .clone()
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

// ------------------------------------------------------------- helpers ---

fn failure(o: &ExecutionOutput) -> Option<FailureKind> {
    o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind)
}

fn evidence(o: &ExecutionOutput) -> Option<&WorkloadApiEvidence> {
    o.record.prepared.workload_api.as_ref()
}

fn op_lines(gw: &Gateway, from: usize, needles: &[&str]) -> Vec<String> {
    gw.log_lines()
        .into_iter()
        .skip(from)
        .filter(|l| needles.iter().all(|n| l.contains(n)))
        .map(|l| l.chars().take(700).collect())
        .take(5)
        .collect()
}

async fn wait_op_lines(gw: &Gateway, from: usize, needles: &[&str]) -> Vec<String> {
    for _ in 0..30 {
        let l = op_lines(gw, from, needles);
        if !l.is_empty() {
            return l;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    vec![]
}

fn transactions(gw: &Gateway, from: usize) -> Vec<String> {
    op_lines(gw, from, &["\"http_method\""])
}

fn received(c: &mut Checks, f: &fx::Fixture, before: usize, path: &str, what: &str) {
    let reqs = f.log.requests();
    let got = reqs.len() == before + 1 && reqs.last().is_some_and(|(_, p)| p == path);
    c.add(CheckKind::GroundTruth, format!("{what} received {path}"), got, format!("{:?}", reqs.iter().skip(before).collect::<Vec<_>>()));
}

fn unchanged(c: &mut Checks, f: &fx::Fixture, before: usize, what: &str) {
    let now = f.log.count_requests();
    c.add(CheckKind::GroundTruth, format!("{what} received nothing"), now == before, format!("{before} → {now} requests"));
}

fn not_dispatched(c: &mut Checks, o: &ExecutionOutput) {
    c.add(
        CheckKind::Diagnosis,
        "dispatch is not_dispatched (nothing reached the destination)",
        o.record.outcome.dispatch == DispatchState::NotDispatched && o.record.response.is_none(),
        format!("{:?}", o.record.outcome.dispatch),
    );
}

fn failure_kind(c: &mut Checks, o: &ExecutionOutput, kind: FailureKind) {
    let got = failure(o);
    c.add(CheckKind::Diagnosis, format!("typed failure {kind:?}"), got == Some(kind), format!("{got:?}"));
}

fn confirmed_local(c: &mut Checks, o: &ExecutionOutput, code: &str) {
    c.has(o, code);
    c.scope(o, code, SourceScope::LocalClient);
    let conf = o.record.findings.iter().find(|f| f.code == code).map(|f| f.confidence);
    c.add(
        CheckKind::Diagnosis,
        format!("{code} is confirmed (a local observation)"),
        conf == Some(Confidence::Confirmed),
        format!("{conf:?}"),
    );
}

/// A refusal before traffic blames neither the destination nor the network.
fn no_destination_blame(c: &mut Checks, o: &ExecutionOutput) {
    let bad: Vec<String> = codes(o)
        .into_iter()
        .filter(|x| x.starts_with("http.") || x.starts_with("client.") || x.starts_with("ferrum.") || x.starts_with("upstream."))
        .collect();
    c.add(CheckKind::Diagnosis, "no destination, network or gateway finding", bad.is_empty(), format!("{bad:?}"));
}

fn call_result(c: &mut Checks, o: &ExecutionOutput, rpc: WorkloadRpc, socket: &Path, ok: bool) {
    let call = evidence(o).and_then(|e| e.calls.iter().find(|x| x.rpc == rpc));
    c.add(
        CheckKind::Diagnosis,
        format!("evidence records {} at {} ({})", rpc.method(), socket.display(), if ok { "OK" } else { "failed" }),
        call.is_some_and(|x| x.endpoint == uri(socket) && (x.result == WorkloadCallResult::Ok) == ok),
        format!("{:?}", call.map(|x| (&x.endpoint, &x.result))),
    );
}

fn jwt_summary(o: &ExecutionOutput) -> Option<&JwtSvidSummary> {
    evidence(o).and_then(|e| e.jwt_svid.as_ref())
}

fn check_is(c: &mut Checks, o: &ExecutionOutput, kind: JwtSvidCheckKind, want: CheckResult) {
    let got = jwt_summary(o).and_then(|j| j.check(kind)).map(|x| x.result);
    c.add(CheckKind::Diagnosis, format!("local {kind:?} check {want:?}"), got == Some(want), format!("{got:?}"));
}

/// The token Anvil used never appears in the record.
fn token_not_recorded(c: &mut Checks, o: &ExecutionOutput, token: &str) {
    let text = serde_json::to_string(&o.record).unwrap_or_default();
    c.add(CheckKind::Diagnosis, "the JWT-SVID never appears in the execution record", !token.is_empty() && !text.contains(token), "");
}

fn outcome(o: ExecutionOutput, c: Checks, log: Vec<String>) -> Outcome {
    Outcome { main: Some(o), recovery: None, checks: c, operator_log: log }
}

// ----------------------------------------------------------- scenarios ---

/// WL-001: X.509-SVID from the Workload API as the client identity on the
/// STRICT mesh inbound listener, the server verified by SPIFFE ID against
/// the bundle the Workload API returned.
fn wl001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.mesh.log_lines().len(), env.mesh_backend.log.count_requests());
        let o = send(&env.engine, &env.mesh_request(&env.mesh_socket, "/echo")).await;
        c.success(CheckKind::Diagnosis, &o);
        call_result(&mut c, &o, WorkloadRpc::FetchX509Svid, &env.mesh_socket, true);
        let svid = evidence(&o).and_then(|e| e.x509_svids.first());
        c.add(
            CheckKind::Diagnosis,
            "the X.509-SVID is the attested identity and its trust-domain bundle was trusted",
            svid.is_some_and(|s| s.spiffe_id == CLIENT_ID && s.bundle_trusted && s.bundle_certificates >= 1),
            format!("{:?}", svid.map(|s| (&s.spiffe_id, s.bundle_trusted))),
        );
        let tls = o.record.attempts.last().and_then(|a| a.connection.as_ref()).and_then(|x| x.tls.as_ref());
        c.add(
            CheckKind::Diagnosis,
            "server verified by exact SPIFFE ID with the Workload API bundle",
            tls.is_some_and(|t| {
                t.verification == TlsVerification::Verified
                    && matches!(&t.identity_check, Some(PeerIdentityCheck::SpiffeId { .. }))
                    && t.peer_spiffe_id.as_deref() == Some(SVC_ID)
            }),
            format!("{:?}", tls.map(|t| (&t.verification, &t.peer_spiffe_id))),
        );
        c.add(
            CheckKind::Diagnosis,
            "the Workload API SVID was presented as the client certificate",
            tls.and_then(|t| t.client_certificate_presented.as_ref())
                .is_some_and(|p| p.subject_alt_names.iter().any(|s| s == &format!("URI:{CLIENT_ID}"))),
            "",
        );
        let text = serde_json::to_string(&o.record).unwrap_or_default();
        c.add(CheckKind::Diagnosis, "no private key material in the record", !text.contains("PRIVATE KEY"), "");
        received(&mut c, &env.mesh_backend, b0, "/echo", "the workload (echo)");
        let mut log = wait_op_lines(&env.mesh, from, &["\"request_path\":\"/echo\"", "\"response_status_code\":200"]).await;
        c.add(CheckKind::GroundTruth, "operator log: 200 inbound transaction for /echo", !log.is_empty(), "");
        // A cached SVID (an earlier pass fetched it; it is reused until half
        // its lifetime) was attested by that earlier call.
        let cached = evidence(&o).and_then(|e| e.calls.first()).is_some_and(|x| x.cached);
        let attested = op_lines(&env.mesh, if cached { 0 } else { from }, &["workload attested", CLIENT_ID]);
        c.add(
            CheckKind::GroundTruth,
            "operator log: the Workload API attested Anvil's uid as the client ID",
            !attested.is_empty(),
            if cached { "SVID reused from Anvil's cache; attested by the earlier fetch" } else { "fetched by this request" },
        );
        log.extend(attested);
        outcome(o, c, log)
    })
}

/// WL-002: JWT-SVID from the Workload API through the proxy's jwks_auth
/// (the trust domain's JWKS, the right audience): accepted.
fn wl002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, mfrom, b0) = (env.proxy.log_lines().len(), env.mesh.log_lines().len(), env.api_backend.log.count_requests());
        let o = send(
            &env.engine,
            &env.jwt_request(&format!("http://127.0.0.1:{PROXY_PORT}/wl/jwt/echo"), env.jwt_config(JwtSvidSource::WorkloadApi, AUDIENCE)),
        )
        .await;
        c.success(CheckKind::Diagnosis, &o);
        call_result(&mut c, &o, WorkloadRpc::FetchJwtSvid, &env.mesh_socket, true);
        call_result(&mut c, &o, WorkloadRpc::FetchJwtBundles, &env.mesh_socket, true);
        for k in [JwtSvidCheckKind::Subject, JwtSvidCheckKind::Audience, JwtSvidCheckKind::Expiry, JwtSvidCheckKind::Signature] {
            check_is(&mut c, &o, k, CheckResult::Passed);
        }
        let j = jwt_summary(&o);
        c.add(
            CheckKind::Diagnosis,
            "the JWT-SVID names the attested identity, the audience, ES256",
            j.is_some_and(|j| {
                j.subject.as_deref() == Some(CLIENT_ID) && j.audiences == [AUDIENCE] && j.algorithm.as_deref() == Some("ES256")
            }),
            format!("{:?}", j.map(|j| (&j.subject, &j.audiences, &j.algorithm))),
        );
        let sent = env.api_backend.log.last_request_headers();
        received(&mut c, &env.api_backend, b0, "/echo", "the API (echo)");
        let token = sent.and_then(|h| h.into_iter().find(|(n, _)| n.eq_ignore_ascii_case("authorization")).map(|(_, v)| v));
        if let Some(t) = token.as_deref().and_then(|t| t.strip_prefix("Bearer ")) {
            token_not_recorded(&mut c, &o, t);
        }
        let mut log = wait_op_lines(&env.proxy, from, &["\"proxy_id\":\"wl-jwt-svid\"", "\"response_status_code\":200"]).await;
        c.add(CheckKind::GroundTruth, "operator log: 200 transaction on wl-jwt-svid", !log.is_empty(), "");
        c.add(
            CheckKind::GroundTruth,
            "operator log: jwks_auth authenticated the JWT-SVID's subject",
            log.iter()
                .any(|l| l.contains(&format!("\"consumer_username\":\"{CLIENT_ID}\"")) && l.contains("\"auth_method\":\"jwks_auth\"")),
            "",
        );
        let minted = op_lines(&env.mesh, mfrom, &["minted JWT-SVID", CLIENT_ID]);
        c.add(CheckKind::GroundTruth, "operator log: the Workload API minted a JWT-SVID for the client ID", !minted.is_empty(), "");
        log.extend(minted);
        outcome(o, c, log)
    })
}

/// WL-003: a JWT-SVID for another audience: Anvil's own audience check
/// passes (it asked for that audience); the proxy refuses 401 with its
/// generic body, and Anvil claims no precise reason.
fn wl003(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.proxy.log_lines().len(), env.api_backend.log.count_requests());
        let o = send(
            &env.engine,
            &env.jwt_request(
                &format!("http://127.0.0.1:{PROXY_PORT}/wl/jwt/echo"),
                env.jwt_config(JwtSvidSource::WorkloadApi, WRONG_AUDIENCE),
            ),
        )
        .await;
        c.status_in(&o, &[401]);
        c.not_success(&o);
        check_is(&mut c, &o, JwtSvidCheckKind::Audience, CheckResult::Passed);
        check_is(&mut c, &o, JwtSvidCheckKind::Signature, CheckResult::Passed);
        c.has(&o, "auth.jwt_svid_rejected");
        c.scope(&o, "auth.jwt_svid_rejected", SourceScope::Unknown);
        c.max_confidence(&o, "auth.jwt_svid_rejected", Confidence::Unknown);
        let f = o.record.findings.iter().find(|f| f.code == "auth.jwt_svid_rejected");
        c.add(
            CheckKind::Diagnosis,
            "the finding quotes the public body and lists the audience as evidence",
            f.is_some_and(|f| {
                f.explanation.contains("Invalid or unrecognized JWT")
                    && f.evidence.iter().any(|e| e.key == "jwt_svid.aud" && e.value == WRONG_AUDIENCE)
                    && f.alternatives.iter().any(|a| a.contains("expects a different audience"))
            }),
            "",
        );
        c.absent_prefix(&o, "auth.jwt_svid_audience");
        let body = String::from_utf8_lossy(o.decoded_body.as_ref().unwrap_or(&o.body)).into_owned();
        c.add(CheckKind::GroundTruth, "public body is the jwks_auth refusal", body.contains("Invalid or unrecognized JWT"), body.clone());
        unchanged(&mut c, &env.api_backend, b0, "the API (echo)");
        let log = wait_op_lines(&env.proxy, from, &["\"proxy_id\":\"wl-jwt-svid\"", "\"response_status_code\":401"]).await;
        c.add(CheckKind::GroundTruth, "operator log: 401 transaction on wl-jwt-svid", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// WL-004: a JWT-SVID the Workload API issued that has since expired, from
/// a variable: refused locally before anything is sent.
fn wl004(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let token = env.expired_token().await;
        let (from, b0) = (env.proxy.log_lines().len(), env.api_backend.log.count_requests());
        let source = JwtSvidSource::Value { token: SensitiveValue::template(token.as_str()) };
        let o =
            send(&env.engine, &env.jwt_request(&format!("http://127.0.0.1:{PROXY_PORT}/wl/jwt/echo"), env.jwt_config(source, AUDIENCE)))
                .await;
        failure_kind(&mut c, &o, FailureKind::JwtSvidRejectedLocally);
        confirmed_local(&mut c, &o, "auth.jwt_svid_expired");
        check_is(&mut c, &o, JwtSvidCheckKind::Expiry, CheckResult::Failed);
        check_is(&mut c, &o, JwtSvidCheckKind::Signature, CheckResult::Passed);
        not_dispatched(&mut c, &o);
        no_destination_blame(&mut c, &o);
        token_not_recorded(&mut c, &o, &token);
        unchanged(&mut c, &env.api_backend, b0, "the API (echo)");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tx = transactions(&env.proxy, from);
        c.add(CheckKind::GroundTruth, "operator log: no transaction (nothing reached the proxy)", tx.is_empty(), format!("{tx:?}"));
        outcome(o, c, vec![])
    })
}

/// WL-005: the same expired JWT-SVID with "send despite failed checks": the
/// local finding stays (a warning) and the proxy's 401 is explained
/// generically, the failed expiry check listed as one alternative.
fn wl005(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let token = env.expired_token().await;
        let (from, b0) = (env.proxy.log_lines().len(), env.api_backend.log.count_requests());
        let mut cfg = env.jwt_config(JwtSvidSource::Value { token: SensitiveValue::template(token.as_str()) }, AUDIENCE);
        cfg.send_despite_failed_checks = true;
        let o = send(&env.engine, &env.jwt_request(&format!("http://127.0.0.1:{PROXY_PORT}/wl/jwt/echo"), cfg)).await;
        c.status_in(&o, &[401]);
        c.not_success(&o);
        c.has(&o, "auth.jwt_svid_expired");
        let sev = o.record.findings.iter().find(|f| f.code == "auth.jwt_svid_expired").map(|f| f.severity);
        c.add(
            CheckKind::Diagnosis,
            "the expiry finding is a warning once sent",
            sev == Some(anvil_domain::diagnostics::Severity::Warning),
            format!("{sev:?}"),
        );
        c.has(&o, "auth.jwt_svid_rejected");
        c.max_confidence(&o, "auth.jwt_svid_rejected", Confidence::Unknown);
        let f = o.record.findings.iter().find(|f| f.code == "auth.jwt_svid_rejected");
        c.add(
            CheckKind::Diagnosis,
            "the 401 lists Anvil's failed expiry check as an alternative, not as the cause",
            f.is_some_and(|f| f.alternatives.iter().any(|a| a.contains("expiry check had failed")) && f.confidence == Confidence::Unknown),
            "",
        );
        c.add(
            CheckKind::Diagnosis,
            "evidence marks the token as sent despite failed checks",
            jwt_summary(&o).is_some_and(|j| j.sent_despite_failed_checks),
            "",
        );
        token_not_recorded(&mut c, &o, &token);
        unchanged(&mut c, &env.api_backend, b0, "the API (echo)");
        let log = wait_op_lines(&env.proxy, from, &["\"proxy_id\":\"wl-jwt-svid\"", "\"response_status_code\":401"]).await;
        c.add(CheckKind::GroundTruth, "operator log: 401 transaction on wl-jwt-svid", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// WL-006: no Workload API at the endpoint (the default: disabled, nothing
/// bound): a typed local failure, nothing sent to the proxy.
fn wl006(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.proxy.log_lines().len(), env.api_backend.log.count_requests());
        let mut cfg = env.jwt_config(JwtSvidSource::WorkloadApi, AUDIENCE);
        cfg.endpoint = uri(&env.missing_socket);
        let o = send(&env.engine, &env.jwt_request(&format!("http://127.0.0.1:{PROXY_PORT}/wl/jwt/echo"), cfg)).await;
        failure_kind(&mut c, &o, FailureKind::WorkloadApiUnavailable);
        confirmed_local(&mut c, &o, "local.workload_api_unavailable");
        call_result(&mut c, &o, WorkloadRpc::FetchJwtSvid, &env.missing_socket, false);
        let f = o.record.findings.iter().find(|f| f.code == "local.workload_api_unavailable");
        c.add(
            CheckKind::Diagnosis,
            "the finding names the socket and the missing-socket cause",
            f.is_some_and(|f| f.explanation.contains(&uri(&env.missing_socket)) && f.explanation.contains("no Workload API socket exists")),
            f.map(|f| f.explanation.clone()).unwrap_or_default(),
        );
        not_dispatched(&mut c, &o);
        no_destination_blame(&mut c, &o);
        c.add(CheckKind::GroundTruth, "no socket exists at the endpoint", !env.missing_socket.exists(), "");
        unchanged(&mut c, &env.api_backend, b0, "the API (echo)");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tx = transactions(&env.proxy, from);
        c.add(CheckKind::GroundTruth, "operator log: no transaction", tx.is_empty(), format!("{tx:?}"));
        outcome(o, c, vec![])
    })
}

/// WL-007: a Workload API whose attestation rule names another uid: no
/// identity for Anvil (PERMISSION_DENIED), nothing sent.
fn wl007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, mfrom, b0) = (env.foreign.log_lines().len(), env.mesh.log_lines().len(), env.mesh_backend.log.count_requests());
        let o = send(&env.engine, &env.mesh_request(&env.foreign_socket, "/echo")).await;
        failure_kind(&mut c, &o, FailureKind::WorkloadApiDenied);
        confirmed_local(&mut c, &o, "local.workload_api_denied");
        call_result(&mut c, &o, WorkloadRpc::FetchX509Svid, &env.foreign_socket, false);
        let f = o.record.findings.iter().find(|f| f.code == "local.workload_api_denied");
        c.add(
            CheckKind::Diagnosis,
            "PERMISSION_DENIED and Anvil's uid are evidence",
            f.is_some_and(|f| {
                f.evidence.iter().any(|e| e.key == "grpc.status" && e.value.contains("PERMISSION_DENIED"))
                    && f.evidence.iter().any(|e| e.key == "process.uid")
            }),
            format!("{:?}", f.map(|f| &f.evidence)),
        );
        not_dispatched(&mut c, &o);
        no_destination_blame(&mut c, &o);
        unchanged(&mut c, &env.mesh_backend, b0, "the workload (echo)");
        let log = wait_op_lines(&env.foreign, from, &["workload attestation failed"]).await;
        c.add(CheckKind::GroundTruth, "operator log (workload-foreign): workload attestation failed", !log.is_empty(), "");
        let tx = transactions(&env.mesh, mfrom);
        c.add(CheckKind::GroundTruth, "operator log (workload-mesh): no transaction", tx.is_empty(), format!("{tx:?}"));
        outcome(o, c, log)
    })
}

/// WL-008: a token signed by a key outside the trust domain's JWT bundle
/// (same kid, another key): Anvil's bundle check refuses it before sending.
fn wl008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.proxy.log_lines().len(), env.api_backend.log.count_requests());
        let kid = env.kid.clone();
        let key = anvil_auth::dpop::generate_key_pem().expect("P-256 key");
        let now = chrono::Utc::now().timestamp();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(kid);
        header.typ = Some("JWT".into());
        let forged = jsonwebtoken::encode(
            &header,
            &serde_json::json!({"sub": CLIENT_ID, "aud": [AUDIENCE], "exp": now + 300, "iat": now}),
            &jsonwebtoken::EncodingKey::from_ec_pem(key.as_bytes()).expect("key"),
        )
        .expect("sign");
        let o = send(
            &env.engine,
            &env.jwt_request(
                &format!("http://127.0.0.1:{PROXY_PORT}/wl/jwt/echo"),
                env.jwt_config(JwtSvidSource::Value { token: SensitiveValue::template(forged.clone()) }, AUDIENCE),
            ),
        )
        .await;
        failure_kind(&mut c, &o, FailureKind::JwtSvidRejectedLocally);
        confirmed_local(&mut c, &o, "auth.jwt_svid_invalid");
        call_result(&mut c, &o, WorkloadRpc::FetchJwtBundles, &env.mesh_socket, true);
        check_is(&mut c, &o, JwtSvidCheckKind::Signature, CheckResult::Failed);
        check_is(&mut c, &o, JwtSvidCheckKind::Expiry, CheckResult::Passed);
        not_dispatched(&mut c, &o);
        token_not_recorded(&mut c, &o, &forged);
        unchanged(&mut c, &env.api_backend, b0, "the API (echo)");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tx = transactions(&env.proxy, from);
        c.add(CheckKind::GroundTruth, "operator log: no transaction", tx.is_empty(), format!("{tx:?}"));
        outcome(o, c, vec![])
    })
}

/// WL-009: lookalike — a backend (not the gateway) answering the jwks_auth
/// body byte for byte: the same generic refusal, no gateway attribution.
fn wl009(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let b0 = env.lookalike.log.count_requests();
        let body = crate::fixtures_policy::enc(JWKS_REFUSAL);
        let o = send(
            &env.engine,
            &env.jwt_request(
                &format!("http://127.0.0.1:{LOOKALIKE}/status/401?body={body}"),
                env.jwt_config(JwtSvidSource::WorkloadApi, AUDIENCE),
            ),
        )
        .await;
        c.status_in(&o, &[401]);
        c.has(&o, "auth.jwt_svid_rejected");
        c.max_confidence(&o, "auth.jwt_svid_rejected", Confidence::Unknown);
        c.scope(&o, "auth.jwt_svid_rejected", SourceScope::Unknown);
        c.absent_prefix(&o, "ferrum.token");
        c.absent_prefix(&o, "ferrum.outcome");
        c.no_confirmed_claim(&o, "gateway");
        let r = o.record.response.as_ref().map(|r| r.status);
        c.add(
            CheckKind::GroundTruth,
            "the lookalike fixture (not a gateway) answered",
            env.lookalike.log.count_requests() == b0 + 1,
            format!("{r:?}"),
        );
        outcome(o, c, vec![])
    })
}

fn all() -> Vec<Def> {
    vec![
        Def {
            id: "WL-001",
            title: "X.509-SVID from the Workload API as mTLS client identity; server verified by SPIFFE ID with its bundle",
            run: wl001,
        },
        Def { id: "WL-002", title: "JWT-SVID from the Workload API accepted by jwks_auth (trust-domain JWKS, audience)", run: wl002 },
        Def { id: "WL-003", title: "JWT-SVID for another audience: generic 401, local audience check as evidence", run: wl003 },
        Def { id: "WL-004", title: "Expired JWT-SVID (issued by the Workload API): refused locally, nothing sent", run: wl004 },
        Def { id: "WL-005", title: "Expired JWT-SVID sent anyway (explicit): 401, local expiry kept as a warning", run: wl005 },
        Def { id: "WL-006", title: "No Workload API at the endpoint (disabled/socket missing): typed local failure", run: wl006 },
        Def { id: "WL-007", title: "Workload API attests another uid: no identity for Anvil (PERMISSION_DENIED)", run: wl007 },
        Def { id: "WL-008", title: "Token outside the trust domain's JWT bundle: bundle check refuses before sending", run: wl008 },
        Def { id: "WL-009", title: "Lookalike backend 401 with the jwks_auth body: no gateway attribution", run: wl009 },
    ]
}

const SKIPPED: &[(&str, &str, &str)] = &[];

pub fn profile() -> Profile {
    Profile {
        name: "workload",
        about: "SPIFFE Workload API: X.509-SVID mTLS on mesh inbound 17406, JWT-SVID via jwks_auth on 17480, sockets under lab/.run/workload",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

// ------------------------------------------------------------- sockets ---

#[cfg(unix)]
fn own_uid(probe: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(probe)?.uid())
}

/// Why `dir` cannot hold a Ferrum Edge Workload API socket, if it cannot
/// (the gateway's socket contract, checked before starting it).
#[cfg(unix)]
fn socket_dir_problem(dir: &Path, uid: u32) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let len = dir.as_os_str().len();
    if len > 74 {
        return Some(format!("{} is {len} bytes; the gateway requires the socket's parent to be at most 74", dir.display()));
    }
    for a in dir.ancestors() {
        let Ok(m) = std::fs::symlink_metadata(a) else { continue };
        if m.file_type().is_symlink() {
            return Some(format!("{} is a symlink", a.display()));
        }
        if m.uid() != uid && m.uid() != 0 {
            return Some(format!("{} is owned by uid {}", a.display(), m.uid()));
        }
        if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
            return Some(format!("{} is group- or world-writable without the sticky bit", a.display()));
        }
    }
    None
}

#[cfg(unix)]
fn private_dir(dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// `(socket directory, note, uid)`: `lab/.run/workload/wapi` when it meets
/// the gateway's socket contract, else a private temporary directory.
#[cfg(unix)]
fn socket_dir() -> anyhow::Result<(PathBuf, String, u32)> {
    let preferred = run_root().join("wapi");
    private_dir(&preferred)?;
    let uid = own_uid(&preferred)?;
    let Some(why) = socket_dir_problem(&preferred, uid) else {
        return Ok((preferred, "sockets in lab/.run/workload/wapi".into(), uid));
    };
    let tmp = if cfg!(target_os = "macos") { PathBuf::from("/private/tmp") } else { PathBuf::from("/tmp") };
    let fallback = tmp.join(format!("anvil-lab-wl-{uid}"));
    private_dir(&fallback)?;
    if let Some(p) = socket_dir_problem(&fallback, uid) {
        anyhow::bail!("no directory meets Ferrum Edge's Workload API socket contract: {why}; {p}");
    }
    Ok((fallback.clone(), format!("sockets in {} ({why})", fallback.display()), uid))
}

#[cfg(not(unix))]
fn socket_dir() -> anyhow::Result<(PathBuf, String, u32)> {
    anyhow::bail!("the workload profile needs Unix domain sockets (Ferrum Edge's Workload API listener is Unix-only)")
}

#[cfg(unix)]
fn run_root() -> PathBuf {
    gateway::repo_root().join("lab/.run/workload")
}

// ------------------------------------------------------------- lifecycle ---

async fn launch_mesh(name: &'static str, socket: &Path, rule: String, ports: [u16; 6], key_pem: &str) -> anyhow::Result<Gateway> {
    let [inbound, outbound, hbone, egress, dns, admin] = ports;
    let run = gateway::repo_root().join("lab/.run").join(name);
    let vars = [
        ("LAB_RUN", run.display().to_string()),
        ("SOCKET", socket.display().to_string()),
        ("UID_RULE", rule),
        ("JWT_TTL", JWT_TTL.to_string()),
        ("INBOUND_PORT", inbound.to_string()),
        ("OUTBOUND_PORT", outbound.to_string()),
        ("HBONE_PORT", hbone.to_string()),
        ("EGRESS_PORT", egress.to_string()),
        ("DNS_PORT", dns.to_string()),
        ("ADMIN_PORT", admin.to_string()),
    ];
    // Debug for the identity module only: attestation and JWT minting are
    // logged at debug level (operator ground truth).
    let env = [
        ("RUST_LOG", "info,ferrum_edge::identity=debug".to_string()),
        ("FERRUM_MESH_CA_BOOTSTRAP_DEV", "true".to_string()),
        ("FERRUM_MESH_JWT_SIGNING_KEY_PEM", key_pem.to_string()),
    ];
    Gateway::launch(Instance {
        name,
        mode: "mesh",
        conf: "workload-mesh.conf",
        yaml: Some("workload-mesh.json"),
        vars: &vars,
        admin_port: admin,
        env: &env,
        readiness: Readiness::Ready,
        append_log: false,
    })
    .await
}

async fn start() -> anyhow::Result<Env> {
    let (dir, socket_note, uid) = socket_dir()?;
    let mesh_socket = dir.join("mesh.sock");
    let foreign_socket = dir.join("foreign.sock");
    let missing_socket = dir.join("disabled.sock");
    let _ = std::fs::remove_file(&missing_socket);
    let key = Zeroizing::new(anvil_auth::dpop::generate_key_pem().map_err(|e| anyhow::anyhow!("{e}"))?);
    let mesh_backend = fx::serve(&format!("127.0.0.1:{MESH_BACKEND}"), None).await?;
    let api_backend = fx::serve(&format!("127.0.0.1:{API_BACKEND}"), None).await?;
    let lookalike = fx::serve(&format!("127.0.0.1:{LOOKALIKE}"), None).await?;
    let mesh = launch_mesh(
        "workload-mesh",
        &mesh_socket,
        format!("uid:{uid}={CLIENT_ID}"),
        [MESH_INBOUND, 17401, 17408, 17409, 17453, MESH_ADMIN],
        &key,
    )
    .await?;
    let foreign = match launch_mesh(
        "workload-foreign",
        &foreign_socket,
        format!("uid:{}={FOREIGN_ID}", uid.wrapping_add(1)),
        [17426, 17421, 17428, 17429, 17455, FOREIGN_ADMIN],
        &key,
    )
    .await
    {
        Ok(g) => g,
        Err(e) => {
            mesh.stop().await;
            return Err(e);
        }
    };
    // The relying gateway trusts exactly the JWKS the Workload API publishes.
    let jwks = async {
        let endpoint = resolve_endpoint(&uri(&mesh_socket)).map_err(|e| anyhow::anyhow!("{e}"))?;
        let bundles = WorkloadClient::new(endpoint, Duration::from_secs(5))
            .fetch_jwt_bundles()
            .await
            .result
            .map_err(|e| anyhow::anyhow!("FetchJWTBundles from workload-mesh: {e}"))?;
        let jwks = bundles.get("anvil.lab").ok_or_else(|| anyhow::anyhow!("no anvil.lab JWT bundle: {:?}", bundles.keys()))?;
        let v: serde_json::Value = serde_json::from_slice(jwks)?;
        let kid = v["keys"][0]["kid"].as_str().unwrap_or_default().to_string();
        anyhow::Ok((serde_json::to_string(&v)?, kid))
    }
    .await;
    let mut kid = String::new();
    let proxy = match jwks {
        Ok((jwks, k)) => {
            kid = k;
            Gateway::start(
                "workload-proxy",
                "workload-proxy.conf",
                "workload-proxy.yaml",
                &[("JWKS", jwks), ("AUDIENCE", AUDIENCE.to_string())],
                PROXY_ADMIN,
                &[],
            )
            .await
        }
        Err(e) => Err(e),
    };
    let proxy = match proxy {
        Ok(g) => g,
        Err(e) => {
            mesh.stop().await;
            foreign.stop().await;
            return Err(e);
        }
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    eprintln!("workload lab: {socket_note}");
    Ok(Env {
        engine: Engine::new(),
        mesh,
        foreign,
        proxy,
        mesh_backend,
        api_backend,
        lookalike,
        mesh_socket,
        foreign_socket,
        missing_socket,
        socket_note,
        kid,
        expired: tokio::sync::OnceCell::new(),
        trusted: true,
        n: AtomicU64::new(0),
    })
}

async fn stop(env: Env) {
    env.mesh.stop().await;
    env.foreign.stop().await;
    env.proxy.stop().await;
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("workload")?;
    let mut env = start().await?;
    std::fs::write(ctx.out_dir.join("sockets.txt"), format!("{}\n", env.socket_note)).ok();
    let mut results = match harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await {
        Ok(r) => r,
        Err(e) => {
            stop(env).await;
            return Err(e);
        }
    };
    results.extend(skips(&ctx, &args.only, SKIPPED));
    let finished = harness::finish(&ctx, &env, &results);
    stop(env).await;
    finished?;
    Ok(results)
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    println!("workload lab running (Ferrum Edge Workload API, internal CA, dev bootstrap):");
    println!("  Workload API          {}  (attests this uid as {CLIENT_ID})", uri(&env.mesh_socket));
    println!("  Workload API (denies) {}", uri(&env.foreign_socket));
    println!("  mesh inbound mTLS     https://127.0.0.1:{MESH_INBOUND}  (Host: {SVC_HOST}; server SPIFFE {SVC_ID})");
    println!("  jwks_auth route       http://127.0.0.1:{PROXY_PORT}/wl/jwt/echo  (audience {AUDIENCE})");
    println!("  {}", env.socket_note);
    harness::wait_for_shutdown().await?;
    stop(env).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::gateway::repo_root;

    /// Every workload-profile listener stays on loopback inside the 174xx
    /// gateway block (fixtures 175xx); no default 150xx mesh port is bound.
    #[test]
    fn workload_instances_stay_inside_their_port_blocks() {
        for f in ["workload-mesh.conf", "workload-proxy.conf"] {
            let conf = std::fs::read_to_string(repo_root().join("lab/gateway").join(f)).unwrap();
            let conf = crate::gateway::render(
                &conf,
                &[
                    ("INBOUND_PORT", "17426".into()),
                    ("OUTBOUND_PORT", "17421".into()),
                    ("HBONE_PORT", "17428".into()),
                    ("EGRESS_PORT", "17429".into()),
                    ("DNS_PORT", "17455".into()),
                    ("ADMIN_PORT", "17492".into()),
                ],
            );
            for line in conf.lines().filter(|l| !l.starts_with('#')) {
                if line.contains("_PORT =") {
                    let port: u16 = line.rsplit('=').next().unwrap().trim().parse().unwrap();
                    assert!(port == 0 || (17400..17500).contains(&port), "{f}: {line}");
                }
                if line.contains("LISTEN_ADDR =") {
                    let addr = line.rsplit('=').next().unwrap().trim();
                    let port: u16 = addr.strip_prefix("127.0.0.1:").expect("loopback listener").parse().unwrap();
                    assert!((17400..17500).contains(&port), "{f}: {line}");
                }
                if line.contains("BIND_ADDRESS") {
                    assert!(line.trim_end().ends_with("127.0.0.1"), "{f} binds beyond loopback: {line}");
                }
                assert!(!line.contains(":150"), "{f} uses a default 150xx port: {line}");
            }
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(repo_root().join("lab/gateway/workload-mesh.json")).unwrap()).unwrap();
        for w in doc["mesh"]["workloads"].as_array().unwrap() {
            for p in w["ports"].as_array().unwrap() {
                assert!((17500..17600).contains(&p["port"].as_u64().unwrap()), "workload port outside 175xx");
            }
        }
        for p in [super::MESH_BACKEND, super::API_BACKEND, super::LOOKALIKE] {
            assert!((17500..17600).contains(&p));
        }
    }

    #[cfg(unix)]
    #[test]
    fn socket_directories_follow_the_gateway_contract() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("anvil-wl-contract-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let uid = super::own_uid(&base).unwrap();
        let long = base.join("x".repeat(80));
        assert!(super::socket_dir_problem(&long, uid).unwrap().contains("at most 74"));
        let open = base.join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let p = super::socket_dir_problem(&open, uid);
        // An ancestor of the temp dir may already fail (for example a
        // symlinked /var on macOS); the open directory must fail either way.
        assert!(p.is_some());
        std::fs::remove_dir_all(&base).ok();
    }
}
