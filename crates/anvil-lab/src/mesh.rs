//! The `mesh` lab profile: Anvil as a Ferrum Mesh client against the real
//! Ferrum Edge release in mesh mode — no Kubernetes, no control plane, no
//! traffic capture. Three gateway processes run the documented localized
//! file source (`FERRUM_MESH_CONFIG_PROTOCOL=file`) with file-based SVIDs
//! from a per-run SPIFFE PKI (`anvil_fixtures::mesh_pki`):
//!
//! * **sidecar** (`lab/gateway/mesh-sidecar.{conf,json}`, STRICT): the
//!   inbound mTLS listener (15006-equivalent) on 127.0.0.1:17606 fronts the
//!   local workload `anvil-lab-svc` = the echo fixture on 127.0.0.1:17801,
//!   with one MeshPolicy DENY for the lab client on `/denied/*`. It also
//!   relays an authenticated bare HTTP/2 CONNECT (the HBONE wire shape)
//!   through the inbound relay destination guard.
//! * **sidecar-permissive** (same files, PERMISSIVE): inbound on
//!   127.0.0.1:17626, so a certificate-less TLS client reaches the CONNECT
//!   gate (`hbone_unauthenticated_peer`) for a destination the relay admits.
//! * **ambient** (`lab/gateway/mesh-ambient.{conf,json}`, STRICT): the HBONE
//!   listener (15008-equivalent) on 127.0.0.1:17618.
//!
//! Ferrum Edge 0.9.7 refuses a CONNECT whose authority the terminator does
//! not own at relay synthesis with a generic `404 {"error":"Not Found"}`
//! (debug operator line), not the documented `403
//! hbone_relay_destination_denied` (that 403 is the post-plugin re-check).
//! The lab asserts the observed public signal and records the difference.
//!
//! Anvil verifies every mesh listener by SPIFFE identity (no bypass) and
//! presents the lab client SVID. Ground truth is the echo fixture's request
//! log and each gateway's operator log; neither is ever given to the engine.

use crate::fixtures_policy::{codes, send, skips};
use crate::gateway::{self, Gateway, Instance, Readiness};
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::request::{KeyValue, PayloadEncoding, Protocol, RequestSpec, StreamPayload, UdpSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{ProxySelection, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{
    ClientIdentity, HboneMarker, HboneOptions, HostBinding, ProxyKind, ProxyProfile, ServerSpiffeIdentity, TlsMinVersion, TlsProfile,
};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::dtls::{self, DtlsFixture, DtlsServerOptions};
use anvil_fixtures::http as fx;
use anvil_fixtures::mesh_pki::{self as ids, MeshPki};
use anvil_fixtures::pki::Pem;
use anvil_fixtures::streams::{self, StreamFixture, UdpMode};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

/// Sidecar inbound mTLS listener (FERRUM_MESH_INBOUND_LISTEN_ADDR in mesh-sidecar.conf).
pub const SIDECAR_PORT: u16 = 17606;
/// Ambient HBONE listeners (FERRUM_MESH_HBONE_LISTEN_ADDR per instance).
pub const AMBIENT_HBONE_PORT: u16 = 17618;
/// PERMISSIVE sidecar inbound listener.
pub const PERMISSIVE_PORT: u16 = 17626;
/// The workload's application: the echo fixture (mesh-*.json workload port).
pub const BACKEND_PORT: u16 = 17801;
/// The workload's UDP ports (mesh-sidecar.json `udp` ports): an echo, a
/// silent receiver, one that closes after its first reply (bound per
/// scenario), and a declared port nothing listens on.
pub const UDP_ECHO_PORT: u16 = 17802;
pub const UDP_SILENT_PORT: u16 = 17803;
pub const UDP_CLOSING_PORT: u16 = 17804;
pub const UDP_UNBOUND_PORT: u16 = 17805;
/// The workload's DTLS applications (mesh-sidecar.json `udp` ports, reached
/// through the datagram relay): a DTLS echo presenting the workload's SVID
/// and requiring a mesh client certificate, and one presenting an SVID from
/// a root the mesh does not trust (mesh_dtls.rs).
pub const DTLS_ECHO_PORT: u16 = 17806;
pub const DTLS_UNTRUSTED_PORT: u16 = 17807;
/// A port no workload declares (relay destination guard stimulus; unbound).
const UNDECLARED_PORT: u16 = 17899;
const SIDECAR_ADMIN: u16 = 17690;
const AMBIENT_ADMIN: u16 = 17691;
const PERMISSIVE_ADMIN: u16 = 17692;
/// The service host the sidecar's materialized inbound route matches.
const SVC_HOST: &str = "svc.ferrum.svc.cluster.local";
/// East-west SNI passthrough name shape (outbound_.PORT_._.HOST).
const EAST_WEST_SNI: &str = "outbound_.17801_._.svc.ferrum.svc.cluster.local";
/// TEST-NET-1 (RFC 5737): a destination no lab terminator owns; never dialed.
const TEST_NET: &str = "192.0.2.10";
const COMPAT: &str = "ferrum-edge-0.9.5";

pub struct Env {
    pub engine: Engine,
    pub pki: MeshPki,
    pub backend: fx::Fixture,
    /// The workload's UDP applications (mesh_udp.rs): echo and silent.
    pub udp_echo: StreamFixture,
    pub udp_silent: StreamFixture,
    /// The workload's DTLS applications (mesh_dtls.rs): echo and untrusted.
    pub dtls_echo: DtlsFixture,
    pub dtls_untrusted: DtlsFixture,
    pub sidecar: Gateway,
    pub ambient: Gateway,
    pub permissive: Gateway,
    pub trusted: bool,
    n: AtomicU64,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<PathBuf> {
        vec![self.sidecar.log_path.clone(), self.ambient.log_path.clone(), self.permissive.log_path.clone()]
    }
}

/// Which client SVID the TLS profile presents.
#[derive(Clone, Copy)]
pub(crate) enum Svid {
    /// `spiffe://cluster.local/ns/ferrum/sa/anvil-lab-client` (mesh root).
    Client,
    None,
    /// `spiffe://partner.example/...` from a root the mesh does not trust.
    Partner,
}

impl Env {
    fn isolation(&self) -> String {
        format!("lab-mesh-{}", self.n.fetch_add(1, Ordering::Relaxed))
    }

    /// A verified TLS profile: trust the lab mesh bundle, verify the server
    /// by `expect_id` (SPIFFE), present `svid`.
    pub(crate) fn tls(&self, name: &str, svid: Svid, expect_id: &str, sni: Option<&str>) -> TlsProfile {
        let identity = |leaf: &Pem, ca: &Pem| ClientIdentity::Pem {
            cert_chain_pem: leaf.chain_with(ca),
            private_key_pem: SensitiveValue::template(leaf.key.clone()),
        };
        TlsProfile {
            id: anvil_domain::Id::new(),
            workspace_id: anvil_domain::Id::new(),
            name: name.into(),
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![self.pki.ca.cert.clone()],
            client_identity: match svid {
                Svid::Client => Some(identity(&self.pki.client, &self.pki.ca)),
                Svid::Partner => Some(identity(&self.pki.foreign_client, &self.pki.foreign_ca)),
                Svid::None => None,
            },
            bindings: vec![],
            min_version: TlsMinVersion::Tls12,
            server_name_override: sni.map(String::from),
            server_spiffe: Some(ServerSpiffeIdentity { expected_server_spiffe_id: Some(expect_id.into()), trust_domain: None }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    pub(crate) fn base(&self, spec: RequestSpec) -> (ExecutionContext, SettingsOverrides) {
        let mut c = ExecutionContext::standalone(spec);
        c.isolation = self.isolation();
        if self.trusted {
            c.integrations.push(IntegrationProfile {
                id: anvil_domain::Id::new(),
                workspace_id: anvil_domain::Id::new(),
                name: "lab mesh listeners".into(),
                kind: IntegrationKind::FerrumGateway {
                    hosts: [SIDECAR_PORT, AMBIENT_HBONE_PORT, PERMISSIVE_PORT]
                        .iter()
                        .map(|p| HostBinding { host: "127.0.0.1".into(), port: Some(*p) })
                        .collect(),
                    compatibility_id: COMPAT.into(),
                    require_verified_tls: true,
                    detail: None,
                    console_url: None,
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            });
        }
        let o = SettingsOverrides {
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(3_000)),
                tls_handshake_ms: Some(Some(3_000)),
                response_headers_ms: Some(Some(5_000)),
                total_ms: Some(Some(15_000)),
                ..Default::default()
            }),
            ..Default::default()
        };
        (c, o)
    }

    /// Direct request to the sidecar inbound listener (`https://127.0.0.1:17606`).
    fn direct(&self, scheme: &str, path: &str, tls: Option<TlsProfile>) -> ExecutionContext {
        let mut spec = RequestSpec::http("GET", &format!("{scheme}://127.0.0.1:{SIDECAR_PORT}{path}"));
        spec.headers.push(KeyValue::new("Host", SVC_HOST));
        let (mut c, mut o) = self.base(spec);
        if let Some(t) = tls {
            o.tls_profile_id = Some(t.id);
            c.tls_profiles.push(t);
        }
        c.settings_layers.push(("run".into(), o));
        c
    }

    /// `http://<authority><path>` through an HBONE proxy at 127.0.0.1:`endpoint`.
    fn via_hbone(&self, endpoint: u16, authority: &str, path: &str, tls: TlsProfile, marker: HboneMarker) -> ExecutionContext {
        let (mut c, mut o) = self.base(RequestSpec::http("GET", &format!("http://{authority}{path}")));
        let proxy = ProxyProfile {
            id: anvil_domain::Id::new(),
            workspace_id: anvil_domain::Id::new(),
            name: "lab mesh HBONE".into(),
            kind: ProxyKind::Hbone,
            address: format!("127.0.0.1:{endpoint}"),
            username: None,
            password: None,
            no_proxy: String::new(),
            tls_profile_id: Some(tls.id),
            hbone: Some(HboneOptions { marker, baggage: None, extra_headers: vec![] }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        o.proxy_profile_id = Some(ProxySelection::Profile { id: proxy.id });
        c.proxy_profiles.push(proxy);
        c.tls_profiles.push(tls);
        c.settings_layers.push(("run".into(), o));
        c
    }

    /// `udp://<authority>` with `datagrams` through an HBONE proxy at
    /// 127.0.0.1:`endpoint` (a datagram tunnel: the CONNECT carries the
    /// `udp` marker, whatever `marker` says about its header name).
    pub(crate) fn via_hbone_udp(
        &self,
        endpoint: u16,
        authority: &str,
        datagrams: &[&str],
        window_ms: u64,
        tls: TlsProfile,
        marker: HboneMarker,
    ) -> ExecutionContext {
        let mut spec = RequestSpec::http("GET", &format!("udp://{authority}"));
        spec.protocol = Protocol::Udp;
        spec.udp = Some(UdpSpec {
            dtls: false,
            datagrams: datagrams.iter().map(|d| StreamPayload { data: d.to_string(), encoding: PayloadEncoding::Text }).collect(),
            response_window_ms: window_ms,
            max_datagrams: 100,
            masque: None,
            proxy_protocol: None,
        });
        let (mut c, mut o) = self.base(spec);
        let proxy = ProxyProfile {
            id: anvil_domain::Id::new(),
            workspace_id: anvil_domain::Id::new(),
            name: "lab mesh HBONE (UDP)".into(),
            kind: ProxyKind::Hbone,
            address: format!("127.0.0.1:{endpoint}"),
            username: None,
            password: None,
            no_proxy: String::new(),
            tls_profile_id: Some(tls.id),
            hbone: Some(HboneOptions { marker, baggage: None, extra_headers: vec![] }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        o.proxy_profile_id = Some(ProxySelection::Profile { id: proxy.id });
        c.proxy_profiles.push(proxy);
        c.tls_profiles.push(tls);
        c.settings_layers.push(("run".into(), o));
        c
    }

    /// `dtls://<authority>` through an HBONE proxy at 127.0.0.1:`endpoint`:
    /// the datagram tunnel of [`Self::via_hbone_udp`] with DTLS inside it.
    /// `hbone_tls` is the proxy profile's (the endpoint leg), `dtls_tls` the
    /// request's (the DTLS peer).
    pub(crate) fn via_hbone_dtls(
        &self,
        endpoint: u16,
        authority: &str,
        datagrams: &[&str],
        window_ms: u64,
        hbone_tls: TlsProfile,
        dtls_tls: TlsProfile,
    ) -> ExecutionContext {
        let mut c = self.via_hbone_udp(endpoint, authority, datagrams, window_ms, hbone_tls, HboneMarker::None);
        c.spec.url = format!("dtls://{authority}");
        c.settings_layers.push(("dtls".into(), SettingsOverrides { tls_profile_id: Some(dtls_tls.id), ..Default::default() }));
        c.tls_profiles.push(dtls_tls);
        c
    }
}

pub(crate) type Def = harness::Def<Env>;
pub(crate) type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

// ------------------------------------------------------------- helpers ---

pub(crate) fn attempt(o: &ExecutionOutput) -> Option<&AttemptObservation> {
    o.record.attempts.last()
}

fn tls_of(o: &ExecutionOutput) -> Option<&TlsObservation> {
    attempt(o).and_then(|a| a.connection.as_ref()).and_then(|c| c.tls.as_ref())
}

pub(crate) fn tunnel_of(o: &ExecutionOutput) -> Option<&TunnelObservation> {
    attempt(o).and_then(|a| a.connection.as_ref()).and_then(|c| c.tunnel.as_ref())
}

/// Operator-log lines since `from` that contain every needle (ground truth).
pub(crate) fn op_lines(gw: &Gateway, from: usize, needles: &[&str]) -> Vec<String> {
    gw.log_lines()
        .into_iter()
        .skip(from)
        .filter(|l| needles.iter().all(|n| l.contains(n)))
        .map(|l| l.chars().take(700).collect())
        .take(5)
        .collect()
}

/// Like [`op_lines`], polling up to 3 s: access lines are written when the
/// exchange (or the tunnel relay) ends, just after Anvil's own result.
pub(crate) async fn wait_op_lines(gw: &Gateway, from: usize, needles: &[&str]) -> Vec<String> {
    for _ in 0..30 {
        let l = op_lines(gw, from, needles);
        if !l.is_empty() {
            return l;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    vec![]
}

/// The v0.9.7 relay-synthesis refusal (debug operator line) with its reason.
pub(crate) const SYNTHESIS_REFUSAL: &str = "not one this proxy terminates for";

/// Transaction (access) lines since `from`.
pub(crate) fn transactions(gw: &Gateway, from: usize) -> Vec<String> {
    op_lines(gw, from, &["\"http_method\""])
}

fn backend_unchanged(c: &mut Checks, env: &Env, before: usize) {
    let now = env.backend.log.count_requests();
    c.add(CheckKind::GroundTruth, "the workload (echo fixture) received nothing", now == before, format!("{before} → {now} requests"));
}

fn backend_received(c: &mut Checks, env: &Env, before: usize, path: &str) {
    let reqs = env.backend.log.requests();
    let got = reqs.len() == before + 1 && reqs.last().map(|(_, p)| p == path).unwrap_or(false);
    c.add(
        CheckKind::GroundTruth,
        format!("the workload received {path}"),
        got,
        format!("{:?}", reqs.iter().skip(before).collect::<Vec<_>>()),
    );
}

pub(crate) fn not_dispatched(c: &mut Checks, o: &ExecutionOutput) {
    c.add(
        CheckKind::Diagnosis,
        "dispatch is not_dispatched (nothing reached the destination)",
        o.record.outcome.dispatch == DispatchState::NotDispatched,
        format!("{:?}", o.record.outcome.dispatch),
    );
}

pub(crate) fn failure_kind(c: &mut Checks, o: &ExecutionOutput, kind: FailureKind) {
    let got = attempt(o).and_then(|a| a.failure.as_ref()).map(|f| f.kind);
    c.add(CheckKind::Diagnosis, format!("typed failure {kind:?}"), got == Some(kind), format!("{got:?}"));
}

/// An mTLS refusal on the tunnel leg: typed as the endpoint's TLS failure,
/// or (alert lost) as an HTTP/2 failure right after the handshake.
pub(crate) fn tunnel_leg_failure(c: &mut Checks, o: &ExecutionOutput) {
    let got = attempt(o).and_then(|a| a.failure.as_ref()).map(|f| f.kind);
    c.add(
        CheckKind::Diagnosis,
        "typed tunnel-leg failure (HboneEndpointTlsFailed, or HboneProtocolError when the TLS 1.3 alert was lost)",
        matches!(got, Some(FailureKind::HboneEndpointTlsFailed | FailureKind::HboneProtocolError)),
        format!("{got:?}"),
    );
}

fn tunnel_refused(c: &mut Checks, o: &ExecutionOutput, status: u16, body: &str) {
    failure_kind(c, o, FailureKind::HboneConnectRefused);
    c.has(o, "hbone.tunnel_refused");
    c.scope(o, "hbone.tunnel_refused", SourceScope::ForwardProxy);
    let t = tunnel_of(o);
    c.add(
        CheckKind::Diagnosis,
        format!("CONNECT status {status} and the refusal body are kept as tunnel evidence"),
        t.map(|t| t.connect_status == Some(status) && t.refusal_body.as_deref().is_some_and(|b| b.contains(body))).unwrap_or(false),
        format!("{:?} {:?}", t.and_then(|t| t.connect_status), t.and_then(|t| t.refusal_body.clone())),
    );
    let explained = o.record.findings.iter().any(|f| f.code == "hbone.tunnel_refused" && f.explanation.contains(body));
    c.add(CheckKind::Diagnosis, "the finding quotes the public body", explained, "");
    no_destination_blame(c, o);
}

/// A tunnel-leg outcome never reports the inner destination as failed.
fn no_destination_blame(c: &mut Checks, o: &ExecutionOutput) {
    let bad: Vec<String> = codes(o)
        .into_iter()
        .filter(|x| x.starts_with("http.") || x.starts_with("client.connect") || x.starts_with("client.dns") || x.starts_with("upstream."))
        .collect();
    c.add(
        CheckKind::Diagnosis,
        "the inner destination is not reported as failed",
        bad.is_empty() && o.record.response.is_none(),
        format!("{bad:?}"),
    );
    not_dispatched(c, o);
}

pub(crate) fn outcome(o: ExecutionOutput, c: Checks, log: Vec<String>) -> Outcome {
    Outcome { main: Some(o), recovery: None, checks: c, operator_log: log }
}

// ----------------------------------------------------------- scenarios ---

/// MESH-001: sidecar inbound mTLS, server verified by SPIFFE ID, client SVID presented.
fn mesh001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.sidecar.log_lines().len(), env.backend.log.count_requests());
        let o =
            send(&env.engine, &env.direct("https", "/echo", Some(env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None))))
                .await;
        c.success(CheckKind::Diagnosis, &o);
        let t = tls_of(&o);
        c.add(
            CheckKind::Diagnosis,
            "server identity verified by exact SPIFFE ID (not host name)",
            t.is_some_and(|t| {
                t.verification == TlsVerification::Verified && matches!(&t.identity_check, Some(PeerIdentityCheck::SpiffeId { .. }))
            }),
            format!("{:?}", t.map(|t| (&t.verification, &t.identity_check))),
        );
        c.add(
            CheckKind::Diagnosis,
            "peer SPIFFE ID recorded",
            t.and_then(|t| t.peer_spiffe_id.as_deref()) == Some(ids::SVC_SPIFFE_ID),
            format!("{:?}", t.and_then(|t| t.peer_spiffe_id.clone())),
        );
        c.add(
            CheckKind::Diagnosis,
            "client SVID presented",
            t.and_then(|t| t.client_certificate_presented.as_ref())
                .is_some_and(|p| p.subject_alt_names.iter().any(|s| s.contains(ids::CLIENT_SPIFFE_ID))),
            "",
        );
        backend_received(&mut c, env, b0, "/echo");
        let log = wait_op_lines(&env.sidecar, from, &["\"request_path\":\"/echo\"", "\"response_status_code\":200"]).await;
        c.add(CheckKind::GroundTruth, "operator log: 200 transaction for /echo", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-002: a wrong expected server SPIFFE ID fails on the client side; nothing is sent.
fn mesh002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.sidecar.log_lines().len(), env.backend.log.count_requests());
        let o = send(
            &env.engine,
            &env.direct("https", "/echo", Some(env.tls("expects another workload", Svid::Client, ids::OTHER_SPIFFE_ID, None))),
        )
        .await;
        failure_kind(&mut c, &o, FailureKind::TlsSpiffeIdMismatch);
        c.has(&o, "client.tls.spiffe_id_mismatch");
        c.scope(&o, "client.tls.spiffe_id_mismatch", SourceScope::ClientToPeer);
        c.add(
            CheckKind::Diagnosis,
            "finding is confirmed (a local verification decision)",
            o.record.findings.iter().any(|f| f.code == "client.tls.spiffe_id_mismatch" && f.confidence == Confidence::Confirmed),
            "",
        );
        c.not_success(&o);
        not_dispatched(&mut c, &o);
        backend_unchanged(&mut c, env, b0);
        let tx = transactions(&env.sidecar, from);
        c.add(CheckKind::GroundTruth, "operator log: no request transaction", tx.is_empty(), format!("{tx:?}"));
        outcome(o, c, op_lines(&env.sidecar, from, &["TLS"]))
    })
}

/// MESH-003: SNI override (east-west name shape) is sent; SPIFFE decides identity.
fn mesh003(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let b0 = env.backend.log.count_requests();
        let o = send(
            &env.engine,
            &env.direct("https", "/echo", Some(env.tls("SNI override", Svid::Client, ids::SVC_SPIFFE_ID, Some(EAST_WEST_SNI)))),
        )
        .await;
        c.success(CheckKind::Diagnosis, &o);
        let t = tls_of(&o);
        c.add(
            CheckKind::Diagnosis,
            "evidence records the SNI sent (override) and the SPIFFE check",
            t.is_some_and(|t| {
                t.sni.as_deref() == Some(EAST_WEST_SNI)
                    && t.server_name_overridden
                    && matches!(t.identity_check, Some(PeerIdentityCheck::SpiffeId { .. }))
            }),
            format!("{:?}", t.map(|t| (&t.sni, t.server_name_overridden))),
        );
        c.has(&o, "client.tls.sni_override");
        backend_received(&mut c, env, b0, "/echo");
        outcome(o, c, vec![])
    })
}

/// MESH-004: a plaintext client is rejected on STRICT.
fn mesh004(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.sidecar.log_lines().len(), env.backend.log.count_requests());
        let o = send(&env.engine, &env.direct("http", "/echo", None)).await;
        c.not_success(&o);
        c.add(CheckKind::Diagnosis, "no HTTP response was accepted as the workload's", o.record.response.is_none(), "");
        c.absent_prefix(&o, "http.");
        backend_unchanged(&mut c, env, b0);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let log = op_lines(&env.sidecar, from, &["TLS handshake failed"]);
        c.add(CheckKind::GroundTruth, "operator log: the STRICT listener refused the plaintext bytes at TLS", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-005: no client SVID is refused at mTLS (STRICT sidecar).
fn mesh005(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.sidecar.log_lines().len(), env.backend.log.count_requests());
        let o =
            send(&env.engine, &env.direct("https", "/echo", Some(env.tls("no client SVID", Svid::None, ids::SVC_SPIFFE_ID, None)))).await;
        c.has_any(&o, &["client.tls.client_cert_required", "client.tls.closed_after_certificate_request"]);
        c.not_success(&o);
        backend_unchanged(&mut c, env, b0);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let log = op_lines(&env.sidecar, from, &["no certificates"]);
        c.add(CheckKind::GroundTruth, "operator log: peer sent no certificates", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-006: a client SVID from an untrusted trust domain is refused at mTLS.
fn mesh006(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.sidecar.log_lines().len(), env.backend.log.count_requests());
        let o =
            send(&env.engine, &env.direct("https", "/echo", Some(env.tls("partner SVID", Svid::Partner, ids::SVC_SPIFFE_ID, None)))).await;
        c.has_any(&o, &["client.tls.client_cert_rejected", "client.tls.closed_after_certificate_request"]);
        c.not_success(&o);
        backend_unchanged(&mut c, env, b0);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let log = op_lines(&env.sidecar, from, &["TLS handshake failed"]);
        c.add(CheckKind::GroundTruth, "operator log: the handshake was refused", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-007: AuthorizationPolicy (MeshPolicy) DENY for this client on /denied/*.
fn mesh007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.sidecar.log_lines().len(), env.backend.log.count_requests());
        let o = send(
            &env.engine,
            &env.direct("https", "/denied/x", Some(env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None))),
        )
        .await;
        c.status_in(&o, &[403]);
        c.not_success(&o);
        let body = o.decoded_body.as_ref().unwrap_or(&o.body);
        c.add(
            CheckKind::GroundTruth,
            "public body: Mesh authorization denied",
            String::from_utf8_lossy(body).contains("Mesh authorization denied"),
            String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned(),
        );
        c.absent_prefix(&o, "client.tls");
        c.no_confirmed_claim(&o, "backend");
        backend_unchanged(&mut c, env, b0);
        let log = wait_op_lines(&env.sidecar, from, &["\"request_path\":\"/denied/x\"", "\"response_status_code\":403"]).await;
        c.add(CheckKind::GroundTruth, "operator log: 403 transaction for /denied/x", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-008: HBONE wire shape (bare HTTP/2 CONNECT over mTLS) on the sidecar
/// inbound listener reaches the workload through the relay.
fn mesh008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.sidecar.log_lines().len(), env.backend.log.count_requests());
        let authority = format!("127.0.0.1:{BACKEND_PORT}");
        let tls = env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let o = send(&env.engine, &env.via_hbone(SIDECAR_PORT, &authority, "/echo", tls, HboneMarker::None)).await;
        c.success(CheckKind::Diagnosis, &o);
        let t = tunnel_of(&o);
        c.add(
            CheckKind::Diagnosis,
            "tunnel evidence: CONNECT 200, endpoint verified by SPIFFE ID, client SVID presented",
            t.is_some_and(|t| {
                t.connect_status == Some(200)
                    && t.authority == authority
                    && t.tls.as_ref().is_some_and(|x| {
                        x.verification == TlsVerification::Verified
                            && x.peer_spiffe_id.as_deref() == Some(ids::SVC_SPIFFE_ID)
                            && x.client_certificate_presented.is_some()
                    })
            }),
            format!("{:?}", t.map(|t| (t.connect_status, &t.authority))),
        );
        c.add(
            CheckKind::Diagnosis,
            "outer phases are separate from the inner ones",
            t.is_some_and(|t| t.phases.iter().any(|p| p.phase == Phase::TlsHandshake))
                && attempt(&o).and_then(|a| a.phase(Phase::ProxyTunnel)).map(|p| p.status) == Some(PhaseStatus::Completed),
            "",
        );
        backend_received(&mut c, env, b0, "/echo");
        let log = wait_op_lines(&env.sidecar, from, &["__mesh-inbound-hbone-relay", "\"response_status_code\":200"]).await;
        c.add(CheckKind::GroundTruth, "operator log: inbound CONNECT relay transaction (200)", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-009: sidecar relay destination guard: a port no local workload
/// declares is refused at relay synthesis (0.9.7: `404`, debug reason
/// `port_not_declared`).
fn mesh009(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.sidecar.log_lines().len(), env.backend.log.count_requests());
        let tls = env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone(SIDECAR_PORT, &format!("127.0.0.1:{UNDECLARED_PORT}"), "/echo", tls, HboneMarker::None)).await;
        tunnel_refused(&mut c, &o, 404, "Not Found");
        backend_unchanged(&mut c, env, b0);
        let log = wait_op_lines(&env.sidecar, from, &[SYNTHESIS_REFUSAL, "port_not_declared"]).await;
        c.add(CheckKind::GroundTruth, "operator log: relay synthesis refused the authority (port_not_declared)", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-010: Ambient HBONE with a valid client SVID: the loopback workload is
/// refused by the relay guard (Ambient never relays to loopback).
fn mesh010(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.ambient.log_lines().len(), env.backend.log.count_requests());
        let tls = env.tls("client SVID → ztunnel", Svid::Client, ids::ZTUNNEL_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone(AMBIENT_HBONE_PORT, &format!("127.0.0.1:{BACKEND_PORT}"), "/echo", tls, HboneMarker::None))
                .await;
        tunnel_refused(&mut c, &o, 404, "Not Found");
        c.add(
            CheckKind::Diagnosis,
            "the HBONE endpoint's identity was verified (mTLS succeeded)",
            tunnel_of(&o).and_then(|t| t.tls.as_ref()).is_some_and(|x| x.verification == TlsVerification::Verified),
            "",
        );
        backend_unchanged(&mut c, env, b0);
        let log = wait_op_lines(&env.ambient, from, &[SYNTHESIS_REFUSAL, "address_not_terminated_here"]).await;
        c.add(
            CheckKind::GroundTruth,
            "operator log: relay synthesis refused the authority (address_not_terminated_here)",
            !log.is_empty(),
            "",
        );
        outcome(o, c, log)
    })
}

/// MESH-011: Ambient HBONE to a destination this proxy does not terminate (TEST-NET): refused, never dialed.
fn mesh011(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.ambient.log_lines().len();
        let tls = env.tls("client SVID → ztunnel", Svid::Client, ids::ZTUNNEL_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone(AMBIENT_HBONE_PORT, &format!("{TEST_NET}:{BACKEND_PORT}"), "/echo", tls, HboneMarker::None))
                .await;
        tunnel_refused(&mut c, &o, 404, "Not Found");
        c.add(
            CheckKind::Diagnosis,
            "Anvil neither resolved nor dialed the inner destination (the endpoint does)",
            attempt(&o).is_some_and(|a| {
                a.phase(Phase::Dns).map(|p| p.status) == Some(PhaseStatus::NotApplicable)
                    && a.phase(Phase::Connect).map(|p| p.status) == Some(PhaseStatus::NotApplicable)
            }),
            "",
        );
        let log = wait_op_lines(&env.ambient, from, &[SYNTHESIS_REFUSAL, TEST_NET]).await;
        c.add(CheckKind::GroundTruth, "operator log: relay synthesis refused the TEST-NET authority (nothing dialed)", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-012: Ambient HBONE without a client SVID is refused at mTLS (STRICT).
fn mesh012(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.ambient.log_lines().len();
        let tls = env.tls("no client SVID", Svid::None, ids::ZTUNNEL_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone(AMBIENT_HBONE_PORT, &format!("127.0.0.1:{BACKEND_PORT}"), "/echo", tls, HboneMarker::None))
                .await;
        // TLS 1.3: the endpoint's certificate_required alert arrives after
        // Anvil's side of the handshake and can be discarded by its reset;
        // both public shapes are accepted, each with its own finding.
        tunnel_leg_failure(&mut c, &o);
        c.has_any(&o, &["hbone.client_svid_required", "hbone.closed_after_certificate_request"]);
        c.scope(&o, "hbone.client_svid_required", SourceScope::ForwardProxy);
        c.scope(&o, "hbone.closed_after_certificate_request", SourceScope::ForwardProxy);
        no_destination_blame(&mut c, &o);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let log = op_lines(&env.ambient, from, &["no certificates"]);
        c.add(CheckKind::GroundTruth, "operator log: peer sent no certificates", !log.is_empty(), "");
        let tx = transactions(&env.ambient, from);
        c.add(CheckKind::GroundTruth, "operator log: no CONNECT transaction", tx.is_empty(), format!("{tx:?}"));
        outcome(o, c, log)
    })
}

/// MESH-013: Ambient HBONE with a client SVID from an untrusted trust domain is refused at mTLS.
fn mesh013(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.ambient.log_lines().len();
        let tls = env.tls("partner SVID", Svid::Partner, ids::ZTUNNEL_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone(AMBIENT_HBONE_PORT, &format!("127.0.0.1:{BACKEND_PORT}"), "/echo", tls, HboneMarker::None))
                .await;
        tunnel_leg_failure(&mut c, &o);
        c.has_any(&o, &["hbone.client_svid_rejected", "hbone.closed_after_certificate_request"]);
        c.absent_prefix(&o, "hbone.endpoint_identity_rejected");
        no_destination_blame(&mut c, &o);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let log = op_lines(&env.ambient, from, &["TLS handshake failed"]);
        c.add(CheckKind::GroundTruth, "operator log: the handshake was refused", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-014: a wrong expected HBONE endpoint SPIFFE ID stops on the client side.
fn mesh014(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.ambient.log_lines().len();
        let tls = env.tls("expects another endpoint", Svid::Client, ids::OTHER_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone(AMBIENT_HBONE_PORT, &format!("127.0.0.1:{BACKEND_PORT}"), "/echo", tls, HboneMarker::None))
                .await;
        failure_kind(&mut c, &o, FailureKind::HboneEndpointTlsFailed);
        c.has(&o, "hbone.endpoint_identity_rejected");
        c.add(
            CheckKind::Diagnosis,
            "tunnel failure is TlsSpiffeIdMismatch at the TLS handshake",
            tunnel_of(&o).and_then(|t| t.failure.as_ref()).is_some_and(|f| f.kind == FailureKind::TlsSpiffeIdMismatch),
            "",
        );
        no_destination_blame(&mut c, &o);
        let tx = transactions(&env.ambient, from);
        c.add(CheckKind::GroundTruth, "operator log: no CONNECT was received", tx.is_empty(), format!("{tx:?}"));
        outcome(o, c, vec![])
    })
}

/// MESH-015: PERMISSIVE sidecar: a marker-only CONNECT without a client SVID
/// (TLS without a certificate) to an admitted destination reaches the
/// CONNECT gate and is refused 403 (`hbone_unauthenticated_peer`).
fn mesh015(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, b0) = (env.permissive.log_lines().len(), env.backend.log.count_requests());
        let tls = env.tls("no client SVID", Svid::None, ids::SVC_SPIFFE_ID, None);
        let o = send(
            &env.engine,
            &env.via_hbone(PERMISSIVE_PORT, &format!("127.0.0.1:{BACKEND_PORT}"), "/echo", tls, HboneMarker::FerrumMeshProtocol),
        )
        .await;
        tunnel_refused(&mut c, &o, 403, "HBONE tunnel requires an authenticated mesh peer");
        c.add(
            CheckKind::Diagnosis,
            "the marker header was sent on the CONNECT",
            tunnel_of(&o).is_some_and(|t| t.connect_headers.iter().any(|h| h.name == "x-ferrum-mesh-protocol" && h.value == "hbone")),
            "",
        );
        c.add(
            CheckKind::Diagnosis,
            "no precise mesh-policy cause is confirmed",
            !o.record.findings.iter().any(|f| f.confidence == Confidence::Confirmed && f.title.contains("policy")),
            "",
        );
        backend_unchanged(&mut c, env, b0);
        let mut log = wait_op_lines(&env.permissive, from, &["no authenticated peer identity"]).await;
        log.extend(wait_op_lines(&env.permissive, from, &["hbone_unauthenticated_peer"]).await);
        c.add(CheckKind::GroundTruth, "operator log: hbone_unauthenticated_peer", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

fn all() -> Vec<Def> {
    let mut v = vec![
        Def { id: "MESH-001", title: "Sidecar inbound mTLS, server verified by SPIFFE ID, client SVID presented", run: mesh001 },
        Def { id: "MESH-002", title: "Wrong expected server SPIFFE ID: client-side failure, nothing sent", run: mesh002 },
        Def { id: "MESH-003", title: "SNI override (east-west name) sent; SPIFFE decides the identity", run: mesh003 },
        Def { id: "MESH-004", title: "Plaintext client rejected by the STRICT inbound listener", run: mesh004 },
        Def { id: "MESH-005", title: "No client SVID refused at mTLS (sidecar STRICT)", run: mesh005 },
        Def { id: "MESH-006", title: "Client SVID from an untrusted trust domain refused at mTLS (sidecar)", run: mesh006 },
        Def { id: "MESH-007", title: "AuthorizationPolicy (MeshPolicy) DENY for the client identity", run: mesh007 },
        Def { id: "MESH-008", title: "HBONE-shaped CONNECT over mTLS on the sidecar inbound reaches the workload", run: mesh008 },
        Def { id: "MESH-009", title: "Relay destination guard (sidecar): undeclared port refused at relay synthesis", run: mesh009 },
        Def { id: "MESH-010", title: "Ambient HBONE, valid SVID: loopback destination refused by the relay guard", run: mesh010 },
        Def { id: "MESH-011", title: "Ambient HBONE: destination this proxy does not terminate is refused, never dialed", run: mesh011 },
        Def { id: "MESH-012", title: "Ambient HBONE without a client SVID refused at mTLS", run: mesh012 },
        Def { id: "MESH-013", title: "Ambient HBONE with an untrusted-trust-domain SVID refused at mTLS", run: mesh013 },
        Def { id: "MESH-014", title: "Wrong expected HBONE endpoint SPIFFE ID: client-side failure", run: mesh014 },
        Def { id: "MESH-015", title: "PERMISSIVE sidecar: marker-only unauthenticated CONNECT refused 403", run: mesh015 },
    ];
    v.extend(crate::mesh_udp::defs());
    v.extend(crate::mesh_dtls::defs());
    v
}

const SKIPPED: &[(&str, &str, &str)] = &[
    (
        "MESH-016",
        "HBONE through the Ambient HBONE listener reaches a workload",
        "infeasible on a loopback-only host without Kubernetes: Ferrum Edge 0.9.7's Ambient inbound relay guard categorically refuses \
     loopback destinations (docs/mesh.md \"Inbound Relay Destination Guard\"; src/modes/mesh/config.rs \
     inbound_relay_destination_decision) and admits only a non-loopback accepted pod address or node-agent-enrolled pod IPs; \
     the lab binds 127.0.0.1 only and has no node agent. MESH-010/011 verify the Ambient guard live; MESH-008 drives the same \
     transparent CONNECT relay to a workload on the Sidecar inbound listener.",
    ),
    (
        "MESH-017",
        "Relay destination guard 403 hbone_relay_destination_denied (post-plugin re-check)",
        "not reachable without a control plane: Ferrum Edge 0.9.7 refuses an authority the terminator does not own at relay \
         synthesis with a generic 404 {\"error\":\"Not Found\"} plus a debug operator line (src/proxy/mod.rs \
         build_inbound_hbone_relay_proxy; MESH-009/010/011 verify it live). The documented 403 with \
         mesh_authz.deny_policy=hbone_relay_destination_denied comes only from the re-check after a before_proxy route \
         override (mesh_route_dispatch from a VirtualService) moved the effective destination, and the localized file \
         source carries no VirtualService (gateway plugin_configs are rejected in mesh file mode). The 403 refusal \
         contract is covered by the HBONE fixture tests (crates/anvil-engine/tests/mesh_hbone.rs).",
    ),
];

pub fn profile() -> Profile {
    Profile {
        name: "mesh",
        about: "Mesh client: SPIFFE-verified sidecar mTLS 17606 (STRICT) / 17626 (PERMISSIVE), HBONE ambient 17618, workload 17801 (UDP 17802-17805, DTLS 17806-17807)",
        scenarios: || {
            let mut v: Vec<(&'static str, &'static str)> = all().into_iter().map(|d| (d.id, d.title)).collect();
            v.extend(SKIPPED.iter().chain(crate::mesh_udp::SKIPPED).map(|(id, t, _)| (*id, *t)));
            v
        },
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

fn run_root() -> PathBuf {
    gateway::repo_root().join("lab/.run/mesh")
}

/// One mesh gateway process from a `mesh-<kind>.{conf,json}` template.
#[allow(clippy::too_many_arguments)]
async fn launch(
    name: &'static str,
    conf: &'static str,
    doc: &'static str,
    mode: &str,
    ports: [u16; 6],
    pki_dir: &str,
    readiness: Readiness,
) -> anyhow::Result<Gateway> {
    let [inbound, outbound, hbone, egress, dns, admin] = ports;
    let run = gateway::repo_root().join("lab/.run").join(name);
    let vars = [
        ("MESH_PKI", pki_dir.to_string()),
        ("LAB_RUN", run.display().to_string()),
        ("MTLS_MODE", mode.to_string()),
        ("INBOUND_PORT", inbound.to_string()),
        ("OUTBOUND_PORT", outbound.to_string()),
        ("HBONE_PORT", hbone.to_string()),
        ("EGRESS_PORT", egress.to_string()),
        ("DNS_PORT", dns.to_string()),
        ("ADMIN_PORT", admin.to_string()),
    ];
    // Debug for the proxy module only: the relay-synthesis refusal reason
    // is logged at debug level (operator ground truth).
    let env = [("RUST_LOG", "info,ferrum_edge::proxy=debug".to_string())];
    Gateway::launch(Instance {
        name,
        mode: "mesh",
        conf,
        yaml: Some(doc),
        vars: &vars,
        admin_port: admin,
        env: &env,
        readiness,
        append_log: false,
    })
    .await
}

async fn start() -> anyhow::Result<Env> {
    let pki = MeshPki::generate();
    let pki_dir = run_root().join("pki");
    pki.write_to(&pki_dir)?;
    let pki_dir = pki_dir.display().to_string();
    let backend = fx::serve(&format!("127.0.0.1:{BACKEND_PORT}"), None).await?;
    let udp_echo = streams::udp(&format!("127.0.0.1:{UDP_ECHO_PORT}"), UdpMode::Echo).await?;
    let udp_silent = streams::udp(&format!("127.0.0.1:{UDP_SILENT_PORT}"), UdpMode::Silent).await?;
    // DTLS workloads (dimpl: ECDSA only, as the lab SVIDs are): the echo
    // presents the workload's SVID and requires a mesh client certificate.
    let dtls_opts = |leaf: &Pem, client_ca: Option<&Pem>| DtlsServerOptions {
        cert_pem: leaf.cert.clone(),
        key_pem: leaf.key.clone(),
        client_ca_pem: client_ca.map(|ca| ca.cert.clone()),
    };
    let dtls_echo = dtls::serve(&format!("127.0.0.1:{DTLS_ECHO_PORT}"), dtls_opts(&pki.svc, Some(&pki.ca))).await?;
    let dtls_untrusted = dtls::serve(&format!("127.0.0.1:{DTLS_UNTRUSTED_PORT}"), dtls_opts(&pki.foreign_server, None)).await?;
    let sidecar = launch(
        "mesh-sidecar",
        "mesh-sidecar.conf",
        "mesh-sidecar.json",
        "strict",
        [SIDECAR_PORT, 17601, 17608, 17609, 17653, SIDECAR_ADMIN],
        &pki_dir,
        Readiness::Ready,
    )
    .await?;
    let permissive = match launch(
        "mesh-sidecar-permissive",
        "mesh-sidecar.conf",
        "mesh-sidecar.json",
        "permissive",
        [PERMISSIVE_PORT, 17621, 17628, 17629, 17655, PERMISSIVE_ADMIN],
        &pki_dir,
        Readiness::Ready,
    )
    .await
    {
        Ok(g) => g,
        Err(e) => {
            sidecar.stop().await;
            return Err(e);
        }
    };
    // The Ambient UDP placement guard withholds /health readiness on hosts
    // without the node-agent netns producer; its listeners still serve.
    let ambient = match launch(
        "mesh-ambient",
        "mesh-ambient.conf",
        "mesh-ambient.json",
        "strict",
        [17616, 17611, AMBIENT_HBONE_PORT, 17619, 17654, AMBIENT_ADMIN],
        &pki_dir,
        Readiness::Live,
    )
    .await
    {
        Ok(g) => g,
        Err(e) => {
            sidecar.stop().await;
            permissive.stop().await;
            return Err(e);
        }
    };
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    Ok(Env {
        engine: Engine::new(),
        pki,
        backend,
        udp_echo,
        udp_silent,
        dtls_echo,
        dtls_untrusted,
        sidecar,
        ambient,
        permissive,
        trusted: true,
        n: AtomicU64::new(0),
    })
}

async fn stop(env: Env) {
    env.sidecar.stop().await;
    env.ambient.stop().await;
    env.permissive.stop().await;
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("mesh")?;
    let mut env = start().await?;
    let mut results = match harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await {
        Ok(r) => r,
        Err(e) => {
            stop(env).await;
            return Err(e);
        }
    };
    results.extend(skips(&ctx, &args.only, SKIPPED));
    results.extend(skips(&ctx, &args.only, crate::mesh_udp::SKIPPED));
    let finished = harness::finish(&ctx, &env, &results);
    stop(env).await;
    finished?;
    Ok(results)
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    let pki = run_root().join("pki");
    println!("mesh lab running (Ferrum Edge mesh mode, localized file source, file SVIDs):");
    println!("  sidecar inbound mTLS  https://127.0.0.1:{SIDECAR_PORT}  (Host: {SVC_HOST}; server SPIFFE {})", ids::SVC_SPIFFE_ID);
    println!("  ambient HBONE STRICT  127.0.0.1:{AMBIENT_HBONE_PORT}  (server SPIFFE {})", ids::ZTUNNEL_SPIFFE_ID);
    println!("  sidecar inbound PERMISSIVE https://127.0.0.1:{PERMISSIVE_PORT}");
    println!("  workload echo         http://127.0.0.1:{BACKEND_PORT}");
    println!("  workload UDP          echo udp://127.0.0.1:{UDP_ECHO_PORT}, silent udp://127.0.0.1:{UDP_SILENT_PORT} (through HBONE)");
    println!(
        "  workload DTLS         echo dtls://127.0.0.1:{DTLS_ECHO_PORT} (server SPIFFE {}, client SVID required), untrusted dtls://127.0.0.1:{DTLS_UNTRUSTED_PORT} (through HBONE)",
        ids::SVC_SPIFFE_ID
    );
    println!("  client SVID {}/client.pem + client.key, trust bundle {}/ca.pem", pki.display(), pki.display());
    harness::wait_for_shutdown().await?;
    stop(env).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::gateway::repo_root;

    /// The mesh profile keeps every gateway listener on loopback inside the
    /// 176xx/177xx block and its workload fixture inside 178xx/179xx; no mesh
    /// listener is left on a default 150xx port.
    #[test]
    fn mesh_instances_stay_inside_their_port_blocks() {
        for f in ["mesh-sidecar.conf", "mesh-ambient.conf"] {
            let conf = std::fs::read_to_string(repo_root().join("lab/gateway").join(f)).unwrap();
            let conf = crate::gateway::render(
                &conf,
                &[
                    ("INBOUND_PORT", "17616".into()),
                    ("OUTBOUND_PORT", "17611".into()),
                    ("HBONE_PORT", "17618".into()),
                    ("EGRESS_PORT", "17619".into()),
                    ("DNS_PORT", "17654".into()),
                    ("ADMIN_PORT", "17691".into()),
                ],
            );
            let mut listeners = 0;
            for line in conf.lines().filter(|l| !l.starts_with('#')) {
                if line.contains("_PORT =") {
                    let port: u16 = line.rsplit('=').next().unwrap().trim().parse().unwrap();
                    assert!(port == 0 || (17600..17800).contains(&port), "{f}: {line}");
                }
                if line.contains("LISTEN_ADDR =") {
                    listeners += 1;
                    let addr = line.rsplit('=').next().unwrap().trim();
                    let port: u16 = addr.strip_prefix("127.0.0.1:").expect("loopback listener").parse().unwrap();
                    assert!((17600..17800).contains(&port), "{f}: {line}");
                }
                if line.contains("BIND_ADDRESS") {
                    assert!(line.trim_end().ends_with("127.0.0.1"), "{f} binds beyond loopback: {line}");
                }
                assert!(!line.contains(":150"), "{f} uses a default 150xx port: {line}");
            }
            assert!(listeners >= 5, "{f}: every mesh listener is remapped explicitly");
        }
        for f in ["mesh-sidecar.json", "mesh-ambient.json"] {
            let text = std::fs::read_to_string(repo_root().join("lab/gateway").join(f)).unwrap().replace("{{MTLS_MODE}}", "strict");
            let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
            for w in doc["mesh"]["workloads"].as_array().unwrap() {
                for p in w["ports"].as_array().unwrap() {
                    assert!((17800..18000).contains(&p["port"].as_u64().unwrap()), "{f}: workload port outside 178xx/179xx");
                }
                // Loopback only; the Ambient UDP scenarios add declared names that never
                // resolve publicly (.test via a gateway DNS override, .invalid not at all).
                for a in w["addresses"].as_array().unwrap() {
                    let a = a.as_str().unwrap();
                    assert!(a == "127.0.0.1" || a.ends_with(".anvil-lab.test") || a.ends_with(".anvil-lab.invalid"), "{f}: {a}");
                }
            }
        }
        assert_eq!(super::BACKEND_PORT, 17801);
    }
}
