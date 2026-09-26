//! `mesh` profile, UDP through HBONE (Ferrum Mesh datagram-over-HBONE):
//! Anvil opens an HTTP/2 `CONNECT` with `x-ferrum-mesh-protocol: udp` on a
//! mesh inbound listener and exchanges `[u16 length][payload]` records with
//! the relay, which forwards each datagram to a local UDP socket connected
//! to the `:authority` (Ferrum Edge `src/proxy/hbone_proxy.rs`
//! `handle_hbone_udp_request` / `relay_hbone_udp`,
//! `src/proxy/mesh_udp_frame.rs`; identical in v0.9.5 and v0.9.7).
//!
//! * The STRICT sidecar relays to the workload's declared `udp` ports on
//!   loopback (mesh-sidecar.json 17802-17805): an echo (MESH-018), a silent
//!   receiver (MESH-019), one that closes after its first reply (MESH-026)
//!   and one nothing listens on (MESH-027). The mTLS refusals (MESH-020/021),
//!   the PERMISSIVE sidecar's UDP authenticated-peer gate (MESH-022) and the
//!   relay-synthesis 404 for an undeclared port (MESH-023) are the byte
//!   tunnel's, with the UDP-specific public bodies where they differ.
//! * Ambient never relays to loopback, so only its refusals are reachable:
//!   loopback 404 (MESH-028), a declared name whose DNS answer is loopback
//!   403 (MESH-024) and an unresolvable declared name 502 (MESH-025).
//!
//! Ground truth: the UDP fixtures' own logs (datagrams and sizes), and the
//! gateway operator logs (relay transaction lines, gate warnings, debug relay
//! lines). Neither is given to the engine.

use crate::fixtures_policy::{codes, send};
use crate::mesh::{
    AMBIENT_HBONE_PORT, Def, Env, Fut, PERMISSIVE_PORT, SIDECAR_PORT, SYNTHESIS_REFUSAL, Svid, UDP_CLOSING_PORT, UDP_ECHO_PORT,
    UDP_SILENT_PORT, UDP_UNBOUND_PORT, attempt, not_dispatched, op_lines, outcome, transactions, tunnel_leg_failure, tunnel_of,
    wait_op_lines,
};
use crate::scenario::{CheckKind, Checks};
use anvil_domain::diagnostics::{Confidence, Severity, SourceScope};
use anvil_domain::events::SessionCommand;
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus, TransportState};
use anvil_domain::tls::HboneMarker;
use anvil_engine::ExecutionOutput;
use anvil_fixtures::GroundTruth;
use anvil_fixtures::mesh_pki as ids;
use anvil_fixtures::streams::{self, StreamFixture, UdpMode};
use anvil_transport::recorder::EventCtx;
use std::time::Duration;

/// Not declared by any workload (relay-synthesis refusal stimulus; unbound).
pub(crate) const UNDECLARED_UDP_PORT: u16 = 17899;
/// Ambient's declared names (mesh-ambient.json / .conf).
pub(crate) const LOOPBACK_NAME: &str = "udp-loopback.anvil-lab.test";
const UNRESOLVABLE_NAME: &str = "udp-unresolvable.anvil-lab.invalid";

pub(crate) fn counts(o: &ExecutionOutput) -> Option<(u64, u64)> {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, masque: None, .. } => Some((*datagrams_sent, *datagrams_received)),
        _ => None,
    }
}

pub(crate) fn channel(o: &ExecutionOutput) -> Option<&HboneDatagramChannel> {
    tunnel_of(o).and_then(|t| t.datagrams.as_ref())
}

pub(crate) fn received(o: &ExecutionOutput) -> Vec<String> {
    o.record
        .stream
        .as_ref()
        .map(|s| {
            s.messages.iter().filter(|m| m.direction == Direction::Received && m.kind == "datagram").map(|m| m.preview.clone()).collect()
        })
        .unwrap_or_default()
}

/// Sizes of the datagrams a UDP fixture received after entry `from`.
fn sizes(f: &StreamFixture, from: usize) -> Vec<u64> {
    f.log
        .entries()
        .into_iter()
        .skip(from)
        .filter_map(|e| match e.event {
            GroundTruth::DatagramReceived { bytes } => Some(bytes),
            _ => None,
        })
        .collect()
}

pub(crate) fn check_counts(c: &mut Checks, o: &ExecutionOutput, sent: u64, received: u64) {
    c.add(
        CheckKind::Diagnosis,
        format!("{sent} datagram(s) sent, {received} received"),
        counts(o) == Some((sent, received)),
        format!("{:?}", counts(o)),
    );
}

/// The tunnel was opened with the datagram marker over verified mTLS.
pub(crate) fn tunnel_opened(c: &mut Checks, o: &ExecutionOutput, authority: &str) {
    let t = tunnel_of(o);
    c.add(
        CheckKind::Diagnosis,
        "tunnel evidence: CONNECT 200 with x-ferrum-mesh-protocol: udp, endpoint verified by SPIFFE ID, client SVID presented",
        t.is_some_and(|t| {
            t.connect_status == Some(200)
                && t.authority == authority
                && t.connect_headers.iter().any(|h| h.name == "x-ferrum-mesh-protocol" && h.value == "udp")
                && t.tls.as_ref().is_some_and(|x| {
                    x.verification == TlsVerification::Verified
                        && x.peer_spiffe_id.as_deref() == Some(ids::SVC_SPIFFE_ID)
                        && x.client_certificate_presented.is_some()
                })
        }),
        format!("{:?}", t.map(|t| (t.connect_status, &t.authority, &t.connect_headers))),
    );
}

/// A datagram-tunnel CONNECT refusal: the public status and body, forward-proxy
/// scope, the datagram alternatives, nothing sent, the destination never blamed.
pub(crate) fn udp_tunnel_refused(c: &mut Checks, o: &ExecutionOutput, status: u16, body: &str) {
    let code = if status >= 500 { "hbone.tunnel_unavailable" } else { "hbone.tunnel_refused" };
    let got = attempt(o).and_then(|a| a.failure.as_ref()).map(|f| f.kind);
    c.add(CheckKind::Diagnosis, "typed failure HboneConnectRefused", got == Some(FailureKind::HboneConnectRefused), format!("{got:?}"));
    c.has(o, code);
    c.scope(o, code, SourceScope::ForwardProxy);
    let t = tunnel_of(o);
    c.add(
        CheckKind::Diagnosis,
        format!("CONNECT status {status} and the refusal body are kept as tunnel evidence"),
        t.is_some_and(|t| t.connect_status == Some(status) && t.refusal_body.as_deref().is_some_and(|b| b.contains(body))),
        format!("{:?} {:?}", t.and_then(|t| t.connect_status), t.and_then(|t| t.refusal_body.clone())),
    );
    let f = o.record.findings.iter().find(|f| f.code == code);
    c.add(CheckKind::Diagnosis, "the finding quotes the public body", f.is_some_and(|f| f.explanation.contains(body)), "");
    c.add(
        CheckKind::Diagnosis,
        "UDP-tunnel alternatives are listed, never claimed as the cause",
        f.is_some_and(|f| {
            f.alternatives.iter().any(|a| a.contains("UDP") && a.contains("tunnel") || a.contains("does not show whether anything listens"))
        }),
        format!("{:?}", f.map(|f| &f.alternatives)),
    );
    no_destination_blame(c, o);
}

/// Nothing reached the UDP destination and no rule says it failed.
fn no_destination_blame(c: &mut Checks, o: &ExecutionOutput) {
    let bad: Vec<String> = codes(o)
        .into_iter()
        .filter(|x| {
            x.starts_with("udp.")
                || x.starts_with("http.")
                || x.starts_with("exchange.")
                || x.starts_with("client.connect")
                || x.starts_with("client.dns")
                || x.starts_with("upstream.")
        })
        .collect();
    c.add(
        CheckKind::Diagnosis,
        "the UDP destination is not reported on (nothing was sent to it)",
        bad.is_empty() && counts(o) == Some((0, 0)),
        format!("{bad:?} {:?}", counts(o)),
    );
    not_dispatched(c, o);
}

pub(crate) fn no_policy_claim(c: &mut Checks, o: &ExecutionOutput) {
    c.add(
        CheckKind::Diagnosis,
        "no precise mesh-policy cause is confirmed",
        !o.record.findings.iter().any(|f| f.confidence == Confidence::Confirmed && f.title.to_lowercase().contains("policy")),
        "",
    );
}

/// MESH-018: sidecar UDP through HBONE reaches the workload's UDP echo.
fn mesh018(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, d0) = (env.sidecar.log_lines().len(), env.udp_echo.log.entries().len());
        let authority = format!("127.0.0.1:{UDP_ECHO_PORT}");
        let tls = env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let o = send(
            &env.engine,
            &env.via_hbone_udp(SIDECAR_PORT, &authority, &["mesh-udp-1", "", "mesh-udp-three"], 1_000, tls, HboneMarker::None),
        )
        .await;
        check_counts(&mut c, &o, 3, 3);
        c.add(
            CheckKind::Diagnosis,
            "per-datagram boundaries kept through the relay, a zero-length datagram included",
            received(&o) == vec!["mesh-udp-1", "", "mesh-udp-three"],
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
        tunnel_opened(&mut c, &o, &authority);
        c.add(
            CheckKind::Diagnosis,
            "the datagram channel: 3 records each way, Anvil ended the tunnel",
            channel(&o).is_some_and(|ch| ch.records_sent == 3 && ch.records_received == 3 && ch.closed_by == ClosedBy::Client),
            format!("{:?}", channel(&o)),
        );
        c.add(
            CheckKind::Diagnosis,
            "outer leg separate from the inner (no inner TLS; DNS/connect not applicable)",
            attempt(&o).is_some_and(|a| {
                a.phase(Phase::Dns).map(|p| p.status) == Some(PhaseStatus::NotApplicable)
                    && a.phase(Phase::ProxyTunnel).map(|p| p.status) == Some(PhaseStatus::Completed)
                    && a.connection.as_ref().is_some_and(|x| x.tls.is_none())
            }),
            "",
        );
        let got = sizes(&env.udp_echo, d0);
        c.add(CheckKind::GroundTruth, "the UDP echo received 10, 0 and 14 bytes, in order", got == vec![10, 0, 14], format!("{got:?}"));
        let target = format!("\"backend_target\":\"udp://{authority}\"");
        let log =
            wait_op_lines(&env.sidecar, from, &["__mesh-inbound-hbone-relay", &target, "\"bytes_sent\":24", "\"bytes_received\":24"]).await;
        c.add(
            CheckKind::GroundTruth,
            "operator log: relay transaction for udp://127.0.0.1:17802, 24 payload bytes each way",
            !log.is_empty(),
            "",
        );
        outcome(o, c, log)
    })
}

/// MESH-019: the relay delivers to a silent workload: only "no response observed".
fn mesh019(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let d0 = env.udp_silent.log.entries().len();
        let authority = format!("127.0.0.1:{UDP_SILENT_PORT}");
        let tls = env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let o = send(&env.engine, &env.via_hbone_udp(SIDECAR_PORT, &authority, &["anyone there?"], 800, tls, HboneMarker::None)).await;
        check_counts(&mut c, &o, 1, 0);
        c.has(&o, "udp.no_response");
        let f = o.record.findings.iter().find(|f| f.code == "udp.no_response");
        c.add(
            CheckKind::Diagnosis,
            "silence is not claimed as delivery or an outage; the relay's lack of acknowledgement is an alternative",
            f.is_some_and(|f| {
                f.does_not_prove.iter().any(|d| d.contains("delivered"))
                    && f.alternatives.iter().any(|a| a.contains("without acknowledgement"))
            }),
            "",
        );
        c.absent_prefix(&o, "hbone.");
        c.add(CheckKind::Diagnosis, "dispatch may_have_been_sent", o.record.outcome.dispatch == DispatchState::MayHaveBeenSent, "");
        tunnel_opened(&mut c, &o, &authority);
        let got = sizes(&env.udp_silent, d0);
        c.add(CheckKind::GroundTruth, "the silent workload did receive the 13-byte datagram", got == vec![13], format!("{got:?}"));
        outcome(o, c, vec![])
    })
}

/// MESH-020: no client SVID (STRICT sidecar): refused at mTLS before any CONNECT.
fn mesh020(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, d0) = (env.sidecar.log_lines().len(), env.udp_echo.log.entries().len());
        let tls = env.tls("no client SVID", Svid::None, ids::SVC_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone_udp(SIDECAR_PORT, &format!("127.0.0.1:{UDP_ECHO_PORT}"), &["x"], 800, tls, HboneMarker::None))
                .await;
        tunnel_leg_failure(&mut c, &o);
        c.has_any(&o, &["hbone.client_svid_required", "hbone.closed_after_certificate_request"]);
        c.scope(&o, "hbone.client_svid_required", SourceScope::ForwardProxy);
        c.scope(&o, "hbone.closed_after_certificate_request", SourceScope::ForwardProxy);
        no_destination_blame(&mut c, &o);
        c.add(CheckKind::GroundTruth, "the UDP workload received nothing", sizes(&env.udp_echo, d0).is_empty(), "");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let log = op_lines(&env.sidecar, from, &["no certificates"]);
        c.add(CheckKind::GroundTruth, "operator log: peer sent no certificates", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-021: a client SVID from an untrusted trust domain: refused at mTLS.
fn mesh021(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, d0) = (env.sidecar.log_lines().len(), env.udp_echo.log.entries().len());
        let tls = env.tls("partner SVID", Svid::Partner, ids::SVC_SPIFFE_ID, None);
        let o =
            send(&env.engine, &env.via_hbone_udp(SIDECAR_PORT, &format!("127.0.0.1:{UDP_ECHO_PORT}"), &["x"], 800, tls, HboneMarker::None))
                .await;
        tunnel_leg_failure(&mut c, &o);
        c.has_any(&o, &["hbone.client_svid_rejected", "hbone.closed_after_certificate_request"]);
        c.absent_prefix(&o, "hbone.endpoint_identity_rejected");
        no_destination_blame(&mut c, &o);
        c.add(CheckKind::GroundTruth, "the UDP workload received nothing", sizes(&env.udp_echo, d0).is_empty(), "");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let log = op_lines(&env.sidecar, from, &["TLS handshake failed"]);
        c.add(CheckKind::GroundTruth, "operator log: the handshake was refused", !log.is_empty(), "");
        let tx = transactions(&env.sidecar, from);
        c.add(CheckKind::GroundTruth, "operator log: no CONNECT transaction", tx.is_empty(), format!("{tx:?}"));
        outcome(o, c, log)
    })
}

/// MESH-022: PERMISSIVE sidecar, TLS without a client certificate: the UDP
/// relay's own authenticated-peer gate answers 403 with its UDP body.
fn mesh022(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let (from, d0) = (env.permissive.log_lines().len(), env.udp_echo.log.entries().len());
        let tls = env.tls("no client SVID", Svid::None, ids::SVC_SPIFFE_ID, None);
        let o = send(
            &env.engine,
            &env.via_hbone_udp(PERMISSIVE_PORT, &format!("127.0.0.1:{UDP_ECHO_PORT}"), &["x"], 800, tls, HboneMarker::FerrumMeshProtocol),
        )
        .await;
        udp_tunnel_refused(&mut c, &o, 403, "HBONE UDP tunnel requires an authenticated mesh peer");
        no_policy_claim(&mut c, &o);
        c.add(CheckKind::GroundTruth, "the UDP workload received nothing", sizes(&env.udp_echo, d0).is_empty(), "");
        let mut log = wait_op_lines(&env.permissive, from, &["datagram-over-HBONE CONNECT with no authenticated peer identity"]).await;
        log.extend(wait_op_lines(&env.permissive, from, &["hbone_udp_unauthenticated_peer"]).await);
        c.add(CheckKind::GroundTruth, "operator log: hbone_udp_unauthenticated_peer", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-023: sidecar, a UDP port no workload declares: refused at relay
/// synthesis with the generic 404 (debug reason `port_not_declared`).
fn mesh023(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.sidecar.log_lines().len();
        let tls = env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let o = send(
            &env.engine,
            &env.via_hbone_udp(SIDECAR_PORT, &format!("127.0.0.1:{UNDECLARED_UDP_PORT}"), &["x"], 800, tls, HboneMarker::None),
        )
        .await;
        udp_tunnel_refused(&mut c, &o, 404, "Not Found");
        no_policy_claim(&mut c, &o);
        let log = wait_op_lines(&env.sidecar, from, &[SYNTHESIS_REFUSAL, "port_not_declared"]).await;
        c.add(CheckKind::GroundTruth, "operator log: relay synthesis refused the authority (port_not_declared)", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-024: Ambient, a declared name whose DNS answer is loopback: the
/// datagram relay's answer screen refuses it 403 (the UDP destination body).
fn mesh024(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.ambient.log_lines().len();
        let tls = env.tls("client SVID → ztunnel", Svid::Client, ids::ZTUNNEL_SPIFFE_ID, None);
        let o = send(
            &env.engine,
            &env.via_hbone_udp(AMBIENT_HBONE_PORT, &format!("{LOOPBACK_NAME}:{UDP_ECHO_PORT}"), &["x"], 800, tls, HboneMarker::None),
        )
        .await;
        udp_tunnel_refused(&mut c, &o, 403, "HBONE UDP relay destination not allowed");
        no_policy_claim(&mut c, &o);
        let mut log = wait_op_lines(&env.ambient, from, &["resolved destination is not one"]).await;
        log.extend(wait_op_lines(&env.ambient, from, &["hbone_udp_relay_destination_denied"]).await);
        c.add(
            CheckKind::GroundTruth,
            "operator log: the resolved loopback answer was refused (hbone_udp_relay_destination_denied)",
            !log.is_empty(),
            "",
        );
        outcome(o, c, log)
    })
}

/// MESH-025: Ambient, a declared name that does not resolve: 502 with the
/// relay's DNS-failure body; no claim about the destination.
fn mesh025(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.ambient.log_lines().len();
        let tls = env.tls("client SVID → ztunnel", Svid::Client, ids::ZTUNNEL_SPIFFE_ID, None);
        let o = send(
            &env.engine,
            &env.via_hbone_udp(AMBIENT_HBONE_PORT, &format!("{UNRESOLVABLE_NAME}:{UDP_ECHO_PORT}"), &["x"], 800, tls, HboneMarker::None),
        )
        .await;
        udp_tunnel_refused(&mut c, &o, 502, "HBONE UDP destination DNS resolution failed");
        let f = o.record.findings.iter().find(|f| f.code == "hbone.tunnel_unavailable");
        c.add(
            CheckKind::Diagnosis,
            "the 5xx makes no leg claim",
            f.is_some_and(|f| f.confidence == Confidence::Confirmed && f.does_not_prove.iter().any(|d| d.contains("which leg"))),
            "",
        );
        let log = wait_op_lines(&env.ambient, from, &["HBONE UDP backend resolution failed"]).await;
        c.add(CheckKind::GroundTruth, "operator log: HBONE UDP backend resolution failed", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

/// MESH-026: mid-session: the workload closes its socket after its first
/// reply; the relay's next datagram meets a closed port and the endpoint ends
/// the tunnel. Anvil reports the endpoint's end, not a destination fault.
fn mesh026(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.sidecar.log_lines().len();
        let closing = match streams::udp(&format!("127.0.0.1:{UDP_CLOSING_PORT}"), UdpMode::CloseAfterFirst).await {
            Ok(f) => f,
            Err(e) => {
                c.add(CheckKind::GroundTruth, "bind the closing UDP fixture", false, e.to_string());
                return crate::harness::Outcome { main: None, recovery: None, checks: c, operator_log: vec![] };
            }
        };
        let authority = format!("127.0.0.1:{UDP_CLOSING_PORT}");
        let tls = env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let ctx = env.via_hbone_udp(SIDECAR_PORT, &authority, &[], 1_000, tls, HboneMarker::None);
        // Interactive, so the second datagram leaves only after the socket closed.
        let h = env.engine.open_session(ctx, EventCtx::none()).await;
        let _ = h.send(SessionCommand::SendText { text: "first".into() }).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let _ = h.send(SessionCommand::SendText { text: "second".into() }).await;
        for _ in 0..30 {
            if h.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let ended_by_endpoint = h.is_finished();
        let _ = h.close().await;
        let o = h.finish().await;
        c.add(CheckKind::Diagnosis, "the session ended without Anvil closing it", ended_by_endpoint, "");
        c.add(CheckKind::Diagnosis, "the first reply was received", received(&o) == vec!["first"], format!("{:?}", received(&o)));
        c.has(&o, "hbone.udp_tunnel_ended");
        c.scope(&o, "hbone.udp_tunnel_ended", SourceScope::ForwardProxy);
        let f = o.record.findings.iter().find(|f| f.code == "hbone.udp_tunnel_ended");
        c.add(
            CheckKind::Diagnosis,
            "the end is the endpoint's; its cause stays an alternative (ICMP at the endpoint's socket), the destination is not called down",
            f.is_some_and(|f| f.alternatives.iter().any(|a| a.contains("ICMP")) && f.does_not_prove.iter().any(|d| d.contains("down"))),
            format!("{:?}", f.map(|f| (&f.explanation, f.confidence))),
        );
        c.add(
            CheckKind::Diagnosis,
            "the channel records the endpoint's end",
            channel(&o).is_some_and(|ch| matches!(ch.closed_by, ClosedBy::Peer | ClosedBy::Abnormal) && ch.records_received == 1),
            format!("{:?}", channel(&o)),
        );
        c.absent_prefix(&o, "exchange.");
        let got = sizes(&closing, 0);
        let closed = closing.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "udp_socket_closed".into() });
        c.add(
            CheckKind::GroundTruth,
            "the workload got only the first datagram, then closed its socket",
            got == vec![5] && closed,
            format!("{got:?} closed={closed}"),
        );
        // bytes_in: "first" + "second" handed to the (then closed) port; bytes_out: the one reply.
        let log = wait_op_lines(&env.sidecar, from, &["HBONE UDP tunnel relay completed", "\"bytes_in\":11", "\"bytes_out\":5"]).await;
        c.add(
            CheckKind::GroundTruth,
            "operator log (debug): the gateway's UDP relay ended after relaying both datagrams and one reply",
            !log.is_empty(),
            "",
        );
        outcome(o, c, log)
    })
}

/// MESH-027: a declared UDP port nothing listens on: the endpoint relays the
/// datagram, its socket gets the ICMP error, and it ends the tunnel. Anvil
/// reports no response and the endpoint's end; it never sees the ICMP.
fn mesh027(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.sidecar.log_lines().len();
        let free = std::net::UdpSocket::bind(("127.0.0.1", UDP_UNBOUND_PORT)).is_ok();
        c.add(CheckKind::GroundTruth, "nothing listens on udp://127.0.0.1:17805 (the port could be bound)", free, "");
        let authority = format!("127.0.0.1:{UDP_UNBOUND_PORT}");
        let tls = env.tls("client SVID → svc", Svid::Client, ids::SVC_SPIFFE_ID, None);
        let o = send(&env.engine, &env.via_hbone_udp(SIDECAR_PORT, &authority, &["hello?"], 2_000, tls, HboneMarker::None)).await;
        check_counts(&mut c, &o, 1, 0);
        c.has(&o, "udp.no_response");
        c.has(&o, "hbone.udp_tunnel_ended");
        c.absent_prefix(&o, "udp.icmp_port_unreachable");
        c.absent_prefix(&o, "exchange.");
        tunnel_opened(&mut c, &o, &authority);
        let log = wait_op_lines(&env.sidecar, from, &["HBONE UDP tunnel relay completed", "\"bytes_in\":6", "\"bytes_out\":0"]).await;
        c.add(
            CheckKind::GroundTruth,
            "operator log (debug): the gateway's UDP relay ended after relaying the datagram, with nothing back",
            !log.is_empty(),
            "",
        );
        outcome(o, c, log)
    })
}

/// MESH-028: Ambient, the loopback workload over UDP: refused at relay
/// synthesis (Ambient never relays to loopback), 404.
fn mesh028(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let from = env.ambient.log_lines().len();
        let tls = env.tls("client SVID → ztunnel", Svid::Client, ids::ZTUNNEL_SPIFFE_ID, None);
        let o = send(
            &env.engine,
            &env.via_hbone_udp(AMBIENT_HBONE_PORT, &format!("127.0.0.1:{UDP_ECHO_PORT}"), &["x"], 800, tls, HboneMarker::None),
        )
        .await;
        udp_tunnel_refused(&mut c, &o, 404, "Not Found");
        let log = wait_op_lines(&env.ambient, from, &[SYNTHESIS_REFUSAL, "address_not_terminated_here"]).await;
        c.add(CheckKind::GroundTruth, "operator log: relay synthesis refused the loopback authority", !log.is_empty(), "");
        outcome(o, c, log)
    })
}

pub(crate) fn defs() -> Vec<Def> {
    vec![
        Def { id: "MESH-018", title: "UDP through HBONE (sidecar): datagram records reach the workload's UDP echo", run: mesh018 },
        Def { id: "MESH-019", title: "UDP through HBONE to a silent workload: only no response observed", run: mesh019 },
        Def { id: "MESH-020", title: "UDP through HBONE without a client SVID: refused at mTLS (sidecar STRICT)", run: mesh020 },
        Def { id: "MESH-021", title: "UDP through HBONE with an untrusted-trust-domain SVID: refused at mTLS", run: mesh021 },
        Def { id: "MESH-022", title: "PERMISSIVE sidecar: unauthenticated UDP CONNECT refused 403 (UDP body)", run: mesh022 },
        Def { id: "MESH-023", title: "UDP CONNECT to an undeclared port refused at relay synthesis (404)", run: mesh023 },
        Def {
            id: "MESH-024",
            title: "Ambient: declared name resolving to loopback refused 403 (UDP destination not allowed)",
            run: mesh024,
        },
        Def { id: "MESH-025", title: "Ambient: unresolvable declared name refused 502 (UDP DNS resolution failed)", run: mesh025 },
        Def { id: "MESH-026", title: "UDP tunnel mid-session: workload socket closes, the endpoint ends the tunnel", run: mesh026 },
        Def {
            id: "MESH-027",
            title: "UDP tunnel to a declared port nothing listens on: no response, endpoint ends the tunnel",
            run: mesh027,
        },
        Def { id: "MESH-028", title: "Ambient UDP to the loopback workload refused at relay synthesis (404)", run: mesh028 },
    ]
}

pub(crate) const SKIPPED: &[(&str, &str, &str)] = &[
    (
        "MESH-029",
        "UDP through the Ambient HBONE listener reaches a workload",
        "infeasible on a loopback-only host without Kubernetes, for the reason MESH-016 states: the Ambient relay guard refuses \
         loopback authorities (MESH-028), and the datagram relay also drops loopback DNS answers for a declared name (MESH-024; \
         src/proxy/hbone_proxy.rs screen_ordinary_inbound_hbone_relay_dns_candidates); a positive Ambient UDP relay needs a \
         non-loopback pod address or a node-agent-enrolled pod. MESH-018 drives the same datagram relay on the Sidecar inbound \
         listener.",
    ),
    (
        "MESH-030",
        "EgressGateway: allow-listed external UDP relay and its 503 session cap",
        "not in this profile: the EgressGateway relays a udp-marked CONNECT only to MESH_EXTERNAL ServiceEntry UDP destinations \
         with FERRUM_MESH_EGRESS_STREAM_ENABLED (src/proxy/mod.rs mesh_egress_udp_destination_dial_endpoint) and caps them at \
         FERRUM_UDP_MAX_SESSIONS (503 {\"error\":\"UDP egress relay session capacity exhausted\"}); that needs a fourth, \
         EgressGateway-topology instance with a ServiceEntry, which the mesh profile does not run. The 503 refusal shape is \
         covered by the HBONE fixture tests (crates/anvil-engine/tests/mesh_hbone_udp.rs).",
    ),
];
