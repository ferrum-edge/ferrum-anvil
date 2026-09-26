//! `mesh` profile, DTLS through HBONE: the datagram tunnel of mesh_udp.rs
//! (`CONNECT` with `x-ferrum-mesh-protocol: udp`, `[u16 length][payload]`
//! records) with a DTLS session inside it. Ferrum Edge's datagram relay
//! (`src/proxy/hbone_proxy.rs` `relay_hbone_udp`, identical in v0.9.5 and
//! v0.9.7) forwards each record as one UDP datagram and never looks inside,
//! so the DTLS handshake is end to end between Anvil and the workload.
//!
//! * The STRICT sidecar relays to the workload's declared `udp` ports
//!   17806/17807 (mesh-sidecar.json): a DTLS echo presenting the workload's
//!   SVID and requiring a mesh client certificate (MESH-031), and one
//!   presenting an SVID from a root the mesh does not trust (MESH-032).
//! * A tunnel that never opens attempts no DTLS: the relay-synthesis 404
//!   for an undeclared port (MESH-033) and Ambient's UDP destination 403
//!   (MESH-034) have exactly the UDP-through-HBONE shape.
//!
//! Two TLS profiles, two legs: the proxy profile's client SVID and SPIFFE
//! check for the endpoint, the request's for the DTLS peer. Ground truth: the
//! DTLS fixtures' own logs (handshakes, the client certificate's CN,
//! application datagrams) and the gateway operator logs (relay transaction
//! lines, debug relay lines). Neither is given to the engine.

use crate::fixtures_policy::{codes, send};
use crate::mesh::{AMBIENT_HBONE_PORT, DTLS_ECHO_PORT, DTLS_UNTRUSTED_PORT, Def, Env, Fut, SIDECAR_PORT, SYNTHESIS_REFUSAL, Svid};
use crate::mesh::{attempt, outcome, tunnel_of, wait_op_lines};
use crate::mesh_udp::{
    LOOPBACK_NAME, UNDECLARED_UDP_PORT, channel, check_counts, no_policy_claim, received, tunnel_opened, udp_tunnel_refused,
};
use crate::scenario::{CheckKind, Checks};
use anvil_domain::diagnostics::{Severity, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, TransportState};
use anvil_engine::ExecutionOutput;
use anvil_fixtures::GroundTruth;
use anvil_fixtures::dtls::DtlsFixture;
use anvil_fixtures::mesh_pki as ids;

/// The DTLS workloads' UDP port on Ambient: declared there only as `udp`
/// port 17802 of a name (mesh-ambient.json); Ambient never relays to it.
const AMBIENT_DECLARED_PORT: u16 = crate::mesh::UDP_ECHO_PORT;

fn dtls_of(o: &ExecutionOutput) -> Option<&TlsObservation> {
    attempt(o).and_then(|a| a.connection.as_ref()).and_then(|c| c.tls.as_ref())
}

/// Ground truth from a DTLS fixture's log since entry `from`.
struct DtlsTruth {
    accepted: usize,
    /// Client certificate CN of each completed handshake.
    handshakes: Vec<Option<String>>,
    datagrams: Vec<u64>,
}

fn truth(f: &DtlsFixture, from: usize) -> DtlsTruth {
    let mut t = DtlsTruth { accepted: 0, handshakes: vec![], datagrams: vec![] };
    for e in f.log.entries().into_iter().skip(from) {
        match e.event {
            GroundTruth::ConnectionAccepted { .. } => t.accepted += 1,
            GroundTruth::TlsHandshakeCompleted { client_cert_cn, .. } => t.handshakes.push(client_cert_cn),
            GroundTruth::DatagramReceived { bytes } => t.datagrams.push(bytes),
            _ => {}
        }
    }
    t
}

/// A tunnel that never opened: no DTLS was attempted, nothing about it is reported.
fn no_dtls_attempted(c: &mut Checks, o: &ExecutionOutput) {
    c.add(
        CheckKind::Diagnosis,
        "no DTLS was attempted (no dtls_handshake phase, no DTLS evidence); the attempt still addresses the dtls:// target",
        attempt(o).is_some_and(|a| {
            a.phase(Phase::DtlsHandshake).is_none() && dtls_of(o).is_none() && a.method == "DTLS" && a.url.starts_with("dtls://")
        }),
        format!("{:?}", attempt(o).map(|a| (&a.method, a.phases.iter().map(|p| p.phase).collect::<Vec<_>>()))),
    );
    c.absent_prefix(o, "client.dtls.");
    c.absent_prefix(o, "client.tls.");
}

/// MESH-031: DTLS through HBONE (sidecar) to the workload's DTLS echo, both
/// legs verified by SPIFFE ID and both presenting the client SVID.
fn mesh031(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, d0) = (env.sidecar.log_lines().len(), env.dtls_echo.log.entries().len());
        let authority = format!("127.0.0.1:{DTLS_ECHO_PORT}");
        let hbone_tls = env.tls("client SVID → svc (HBONE endpoint)", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let dtls_tls = env.tls("client SVID → svc (DTLS workload)", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone_dtls(SIDECAR_PORT, &authority, &["mesh-dtls-1", "mesh-dtls-two"], 1_000, hbone_tls, dtls_tls))
                .await;
        check_counts(&mut c, &o, 2, 2);
        c.add(
            CheckKind::Diagnosis,
            "the echoed application datagrams, decrypted, in order",
            received(&o) == vec!["mesh-dtls-1", "mesh-dtls-two"],
            format!("{:?}", received(&o)),
        );
        c.add(
            CheckKind::Diagnosis,
            "transport completed, dispatch sent, no failure",
            o.record.outcome.transport == TransportState::Completed
                && o.record.outcome.dispatch == DispatchState::Sent
                && attempt(&o).is_some_and(|a| a.failure.is_none()),
            o.record.outcome.summary.clone(),
        );
        c.add(
            CheckKind::Diagnosis,
            "no warning or error finding",
            !o.record.findings.iter().any(|f| f.severity >= Severity::Warning),
            format!("{:?}", codes(&o)),
        );
        let t = dtls_of(&o);
        c.add(
            CheckKind::Diagnosis,
            "DTLS evidence about the workload: DTLS 1.2, verified by exact SPIFFE ID, client certificate requested and presented",
            t.is_some_and(|t| {
                t.version.as_deref() == Some("DTLSv1_2")
                    && t.verification == TlsVerification::Verified
                    && matches!(&t.identity_check, Some(PeerIdentityCheck::SpiffeId { .. }))
                    && t.peer_spiffe_id.as_deref() == Some(ids::SVC_SPIFFE_ID)
                    && t.client_certificate_requested == Some(true)
                    && t.client_certificate_presented.as_ref().is_some_and(|p| p.subject.contains("anvil-lab-client"))
            }),
            format!("{:?}", t.map(|t| (&t.version, &t.verification, &t.peer_spiffe_id, t.client_certificate_requested))),
        );
        tunnel_opened(&mut c, &o, &authority);
        c.add(
            CheckKind::Diagnosis,
            "the attempt is the DTLS session: dns/connect not applicable, one proxy_tunnel phase, then dtls_handshake and session",
            attempt(&o).is_some_and(|a| {
                a.method == "DTLS"
                    && a.phase(Phase::Dns).map(|p| p.status) == Some(PhaseStatus::NotApplicable)
                    && a.phase(Phase::ProxyTunnel).map(|p| p.status) == Some(PhaseStatus::Completed)
                    && a.phase(Phase::DtlsHandshake).map(|p| p.status) == Some(PhaseStatus::Completed)
                    && a.phase(Phase::TlsHandshake).is_none()
            }),
            "",
        );
        c.add(
            CheckKind::Diagnosis,
            "the datagram channel carried the DTLS records (handshake flights included); Anvil ended the tunnel",
            channel(&o).is_some_and(|ch| ch.records_sent >= 4 && ch.records_received >= 4 && ch.closed_by == ClosedBy::Client),
            format!("{:?}", channel(&o)),
        );
        let g = truth(&env.dtls_echo, d0);
        c.add(
            CheckKind::GroundTruth,
            "the DTLS workload completed one handshake with the client SVID (CN anvil-lab-client) and got 11 and 13 bytes",
            g.accepted == 1 && g.handshakes == vec![Some("anvil-lab-client".to_string())] && g.datagrams == vec![11, 13],
            format!("accepted {} handshakes {:?} datagrams {:?}", g.accepted, g.handshakes, g.datagrams),
        );
        let target = format!("\"backend_target\":\"udp://{authority}\"");
        let log = wait_op_lines(&env.sidecar, from, &["__mesh-inbound-hbone-relay", &target]).await;
        c.add(CheckKind::GroundTruth, "operator log: relay transaction for udp://127.0.0.1:17806 (the DTLS records)", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-032: DTLS through HBONE to a workload presenting an SVID from a root
/// the mesh does not trust: Anvil rejects the DTLS peer; the tunnel is fine.
fn mesh032(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, d0) = (env.sidecar.log_lines().len(), env.dtls_untrusted.log.entries().len());
        let authority = format!("127.0.0.1:{DTLS_UNTRUSTED_PORT}");
        let hbone_tls = env.tls("client SVID → svc (HBONE endpoint)", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let dtls_tls = env.tls("client SVID → svc (DTLS workload)", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let o = send(&env.engine, &env.via_hbone_dtls(SIDECAR_PORT, &authority, &["must not arrive"], 800, hbone_tls, dtls_tls)).await;
        let f = attempt(&o).and_then(|a| a.failure.as_ref());
        c.add(
            CheckKind::Diagnosis,
            "Anvil rejected the DTLS peer's certificate: typed tls_untrusted_trust_domain in dtls_handshake",
            f.is_some_and(|f| f.kind == FailureKind::TlsUntrustedTrustDomain && f.phase == Phase::DtlsHandshake),
            format!("{:?}", f.map(|f| (f.kind, f.phase))),
        );
        c.add(
            CheckKind::Diagnosis,
            "the DTLS evidence keeps the presented partner.example SVID; the endpoint leg verified",
            dtls_of(&o).is_some_and(|t| {
                matches!(t.verification, TlsVerification::Failed { .. }) && t.peer_spiffe_id.as_deref() == Some(ids::PARTNER_SVC_SPIFFE_ID)
            }) && tunnel_of(&o).and_then(|t| t.tls.as_ref()).is_some_and(|t| t.verification == TlsVerification::Verified),
            format!("{:?}", dtls_of(&o).map(|t| (&t.verification, &t.peer_spiffe_id))),
        );
        c.has(&o, "client.tls.untrusted_trust_domain");
        c.scope(&o, "client.tls.untrusted_trust_domain", SourceScope::ClientToPeer);
        let fnd = o.record.findings.iter().find(|f| f.code == "client.tls.untrusted_trust_domain");
        c.add(
            CheckKind::Diagnosis,
            "the finding is about the DTLS workload, not the HBONE endpoint",
            fnd.is_some_and(|f| f.explanation.contains("127.0.0.1") && !f.explanation.contains(&SIDECAR_PORT.to_string())),
            format!("{:?}", fnd.map(|f| &f.explanation)),
        );
        c.absent_prefix(&o, "hbone.");
        c.add(
            CheckKind::Diagnosis,
            "no application datagram was sent; Anvil ended the tunnel",
            o.record.outcome.dispatch == DispatchState::NotDispatched
                && o.record.stream.is_none()
                && channel(&o).is_some_and(|ch| ch.closed_by == ClosedBy::Client && ch.records_sent >= 1),
            format!("{:?} {:?}", o.record.outcome.dispatch, channel(&o)),
        );
        let g = truth(&env.dtls_untrusted, d0);
        c.add(
            CheckKind::GroundTruth,
            "the untrusted workload saw the handshake through the relay but completed none and got no application data",
            g.accepted == 1 && g.handshakes.is_empty() && g.datagrams.is_empty(),
            format!("accepted {} handshakes {:?} datagrams {:?}", g.accepted, g.handshakes, g.datagrams),
        );
        let target = format!("\"backend_target\":\"udp://{authority}\"");
        let log = wait_op_lines(&env.sidecar, from, &["__mesh-inbound-hbone-relay", &target]).await;
        c.add(CheckKind::GroundTruth, "operator log: the relay did run for udp://127.0.0.1:17807", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-033: DTLS to an undeclared port at the sidecar: the relay-synthesis
/// 404 before any tunnel, exactly as for UDP; no DTLS attempted.
fn mesh033(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.sidecar.log_lines().len();
        let hbone_tls = env.tls("client SVID → svc (HBONE endpoint)", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let dtls_tls = env.tls("client SVID → svc (DTLS workload)", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let authority = format!("127.0.0.1:{UNDECLARED_UDP_PORT}");
        let o = send(&env.engine, &env.via_hbone_dtls(SIDECAR_PORT, &authority, &["x"], 800, hbone_tls, dtls_tls)).await;
        udp_tunnel_refused(&mut c, &o, 404, "Not Found");
        no_dtls_attempted(&mut c, &o);
        no_policy_claim(&mut c, &o);
        let log = wait_op_lines(&env.sidecar, from, &[SYNTHESIS_REFUSAL, "port_not_declared"]).await;
        c.add(CheckKind::GroundTruth, "operator log: relay synthesis refused the authority (port_not_declared)", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-034: DTLS at Ambient to a declared name whose DNS answer is
/// loopback: the datagram relay's 403, exactly as for UDP; no DTLS attempted.
fn mesh034(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.ambient.log_lines().len();
        let hbone_tls = env.tls("client SVID → ztunnel (HBONE endpoint)", Svid::Client, ids::ZTUNNEL_SPIFFE_ID, None);
        let dtls_tls = env.tls("client SVID → svc (DTLS workload)", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let authority = format!("{LOOPBACK_NAME}:{AMBIENT_DECLARED_PORT}");
        let o = send(&env.engine, &env.via_hbone_dtls(AMBIENT_HBONE_PORT, &authority, &["x"], 800, hbone_tls, dtls_tls)).await;
        udp_tunnel_refused(&mut c, &o, 403, "HBONE UDP relay destination not allowed");
        no_dtls_attempted(&mut c, &o);
        no_policy_claim(&mut c, &o);
        let log = wait_op_lines(&env.ambient, from, &["hbone_udp_relay_destination_denied"]).await;
        c.add(
            CheckKind::GroundTruth,
            "operator log: hbone_udp_relay_destination_denied (the resolved loopback answer)",
            !log.is_empty(),
            "",
        );
        outcome(o, c, log)
    })
}

pub(crate) fn defs() -> Vec<Def> {
    vec![
        Def {
            id: "MESH-031",
            title: "DTLS through HBONE (sidecar): verified DTLS session with the workload inside the tunnel",
            run: mesh031,
        },
        Def { id: "MESH-032", title: "DTLS through HBONE to a workload with an untrusted SVID: Anvil rejects the DTLS peer", run: mesh032 },
        Def { id: "MESH-033", title: "DTLS through HBONE to an undeclared port: relay-synthesis 404, no DTLS attempted", run: mesh033 },
        Def { id: "MESH-034", title: "Ambient DTLS to a name resolving to loopback: UDP destination 403, no DTLS attempted", run: mesh034 },
    ]
}
