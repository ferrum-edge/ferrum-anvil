//! UDP datagram exchanges.
//!
//! UDP is connectionless and unacknowledged: Anvil records what it sent and
//! what it received within the response window, per datagram, and never
//! infers delivery. Silence means only "no response observed".
//!
//! The socket is associated with the destination (`connect`), so only
//! datagrams from that address are accepted and the OS can report an ICMP
//! port-unreachable back to the socket; when it does, the transcript says so
//! (that is stronger evidence than silence, but still not proof about the
//! service behind a firewall). Received datagrams that are byte-identical to
//! an earlier one are counted as an observation only: UDP can duplicate
//! datagrams, but a peer can also legitimately send identical replies.

use crate::dns::{self, DnsConfig};
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::settings::Timeouts;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct UdpPlan {
    pub host: String,
    pub port: u16,
    pub dns: DnsConfig,
    pub timeouts: Timeouts,
    pub datagrams: Vec<Bytes>,
    /// How long to wait for responses after the last datagram is sent.
    pub response_window_ms: u64,
    /// Stop receiving after this many datagrams.
    pub max_datagrams: u32,
    pub display_url: String,
    pub transcript: TranscriptLimits,
    pub redact: Option<RedactFn>,
    /// PROXY v2 `DGRAM` envelope prepended to every datagram.
    pub envelope: Option<crate::proxy_protocol::EnvelopePlan>,
}

/// Start the datagram envelope for an open socket (a local, typed refusal
/// when it cannot be built; nothing has been sent yet).
pub(crate) fn start_envelope(
    plan: Option<&crate::proxy_protocol::EnvelopePlan>,
    sock: &UdpSocket,
    remote: SocketAddr,
    redact: Option<RedactFn>,
) -> Result<Option<crate::proxy_protocol::Enveloper>, TransportFailure> {
    let Some(p) = plan else { return Ok(None) };
    p.start(sock.local_addr().ok(), Some(remote))
        .map(|e| Some(e.with_redact(redact)))
        .map_err(|e| TransportFailure::new(Phase::Prepare, FailureKind::BodySerialization, e).with_field("udp.proxy_protocol"))
}

/// The bytes put on the wire for one datagram.
pub(crate) fn wire<'a>(env: &mut Option<crate::proxy_protocol::Enveloper>, d: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
    match env {
        Some(e) => std::borrow::Cow::Owned(e.wrap(d)),
        None => std::borrow::Cow::Borrowed(d),
    }
}

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Resolve and open a UDP socket associated with the destination. Records
/// DNS (or not-applicable) and marks the TCP connect phase not applicable.
pub(crate) async fn open_socket(
    rec: &mut Recorder,
    host: &str,
    port: u16,
    dns_cfg: &DnsConfig,
    timeouts: &Timeouts,
    protocol: &str,
) -> Result<(UdpSocket, SocketAddr, ConnectionObservation), (TransportFailure, ConnectionObservation)> {
    let mut cobs = crate::connector::blank_observation(crate::connector::next_connection_id());
    cobs.protocol = Some(protocol.to_string());
    let dns_idx = rec.start(Phase::Dns);
    let res = match dns::resolve(host, port, dns_cfg, timeouts.dns_ms.map(Duration::from_millis)).await {
        Ok(r) => r,
        Err(f) => {
            rec.finish(dns_idx, if f.kind == FailureKind::DnsTimeout { PhaseStatus::TimedOut } else { PhaseStatus::Failed });
            return Err((f, cobs));
        }
    };
    if res.source == "literal" || res.source == "override" {
        rec.phases[dns_idx].status = PhaseStatus::NotApplicable;
        rec.phases[dns_idx].start_us = None;
        rec.phases[dns_idx].detail = Some(format!("address from {}", res.source));
    } else {
        rec.finish(dns_idx, PhaseStatus::Completed);
    }
    cobs.resolved_addresses = res.addrs.iter().map(|a| a.to_string()).collect();
    cobs.resolution_source = Some(res.source.to_string());
    let Some(addr) = res.addrs.first().copied() else {
        return Err((TransportFailure::new(Phase::Dns, FailureKind::DnsNoRecords, format!("{host} resolved to no usable address")), cobs));
    };
    rec.mark(Phase::Connect, PhaseStatus::NotApplicable, Some("UDP is connectionless; there is no connect handshake"));
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse().expect("v6 any") } else { "0.0.0.0:0".parse().expect("v4 any") };
    let sock = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            let mut f = TransportFailure::new(Phase::Prepare, FailureKind::AddressUnavailable, format!("could not open a UDP socket: {e}"));
            f.io_error_kind = Some(format!("{:?}", e.kind()));
            return Err((f, cobs));
        }
    };
    if let Err(e) = sock.connect(addr).await {
        let mut f = TransportFailure::new(
            Phase::Session,
            crate::errors::classify_connect_io(&e),
            format!("could not associate the UDP socket with {addr}: {e}"),
        );
        f.io_error_kind = Some(format!("{:?}", e.kind()));
        f.os_error_code = e.raw_os_error();
        return Err((f, cobs));
    }
    cobs.remote_address = Some(addr.to_string());
    cobs.local_address = sock.local_addr().ok().map(|a| a.to_string());
    Ok((sock, addr, cobs))
}

pub async fn run(plan: &UdpPlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let mut obs = new_attempt(0, AttemptReason::Initial, "UDP", &plan.display_url);
    let mut facts = SessionFacts::default();
    let (sock, addr, cobs) = match open_socket(&mut rec, &plan.host, plan.port, &plan.dns, &plan.timeouts, "udp").await {
        Ok(x) => x,
        Err((f, cobs)) => {
            obs.connection = Some(cobs);
            return SessionOutput::single(
                fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                None,
                ProtocolStatus::None,
                facts,
            );
        }
    };
    obs.connection = Some(cobs);
    let mut env = match start_envelope(plan.envelope.as_ref(), &sock, addr, plan.redact.clone()) {
        Ok(e) => e,
        Err(f) => {
            return SessionOutput::single(
                fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                None,
                ProtocolStatus::None,
                facts,
            );
        }
    };
    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    if let Some(e) = &env {
        tr.note("proxy_protocol_envelope", &e.summary());
    }
    let s_idx = rec.start(Phase::Session);
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut failure: Option<TransportFailure> = None;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };

    for d in &plan.datagrams {
        let w = wire(&mut env, d);
        match sock.send(&w).await {
            Ok(_) => {
                sent += 1;
                tr.data(Direction::Sent, "datagram", d);
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                facts.icmp_port_unreachable = true;
                tr.note("icmp_port_unreachable", "the OS reported ICMP port unreachable for the destination before this datagram was sent");
                // The error is consumed by this call; retry once so the datagram is still offered.
                if sock.send(&w).await.is_ok() {
                    sent += 1;
                    tr.data(Direction::Sent, "datagram", d);
                }
            }
            Err(e) => {
                let mut f =
                    TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteFailed, format!("sending a datagram failed: {e}"));
                f.io_error_kind = Some(format!("{:?}", e.kind()));
                f.os_error_code = e.raw_os_error();
                failure = Some(f);
                break;
            }
        }
    }

    let window = Duration::from_millis(plan.response_window_ms);
    let mut window_end = Instant::now() + window;
    let mut buf = vec![0u8; 65_535];
    let mut errors = 0u32;
    enum Ev {
        Recv(std::io::Result<usize>),
        Cmd(Option<SessionCommand>),
        WindowEnd,
        Deadline,
        Canceled,
    }
    while failure.is_none() {
        let window_deadline = if interactive { None } else { Some(window_end) };
        let ev = tokio::select! {
            r = sock.recv(&mut buf) => Ev::Recv(r),
            c = next_cmd(&mut commands), if interactive => Ev::Cmd(c),
            _ = sleep_until_opt(window_deadline) => Ev::WindowEnd,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::Recv(Ok(n)) => {
                received += 1;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&Sha256::digest(&buf[..n]));
                if !seen.insert(digest) {
                    facts.repeated_datagrams += 1;
                }
                tr.data(Direction::Received, "datagram", &buf[..n]);
                if received >= plan.max_datagrams as u64 {
                    tr.note("note", &format!("stopped receiving at max_datagrams ({})", plan.max_datagrams));
                    break;
                }
            }
            Ev::Recv(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                errors += 1;
                if !facts.icmp_port_unreachable {
                    facts.icmp_port_unreachable = true;
                    tr.note(
                        "icmp_port_unreachable",
                        "the OS reported ICMP port unreachable for the destination (often: nothing is listening on that UDP port)",
                    );
                }
                if errors > 16 {
                    break;
                }
            }
            Ev::Recv(Err(e)) => {
                errors += 1;
                tr.note("error", &format!("receive error: {e}"));
                if errors > 16 {
                    break;
                }
            }
            Ev::Cmd(c) => match c {
                Some(SessionCommand::SendText { text }) => {
                    if sock.send(&wire(&mut env, text.as_bytes())).await.is_ok() {
                        sent += 1;
                        tr.data(Direction::Sent, "datagram", text.as_bytes());
                    }
                    window_end = Instant::now() + window;
                }
                Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                    Ok(b) => {
                        if sock.send(&wire(&mut env, &b)).await.is_ok() {
                            sent += 1;
                            tr.data(Direction::Sent, "datagram", &b);
                        }
                        window_end = Instant::now() + window;
                    }
                    Err(e) => tr.note("error", &format!("datagram not sent: {e}")),
                },
                Some(SessionCommand::Ping) | Some(SessionCommand::HalfClose) => {
                    tr.note("unsupported_command", "UDP has no ping or half-close; send a datagram or Close")
                }
                Some(SessionCommand::Close { .. }) | None => break,
            },
            Ev::WindowEnd => break,
            Ev::Deadline => {
                failure = Some(
                    TransportFailure::new(Phase::Session, FailureKind::TotalTimeout, "the total deadline elapsed during the UDP exchange")
                        .with_deadline(plan.timeouts.total_ms),
                );
            }
            Ev::Canceled => failure = Some(TransportFailure::new(Phase::Session, FailureKind::Canceled, "the UDP exchange was canceled")),
        }
    }
    if facts.repeated_datagrams > 0 {
        facts.notes.push(format!(
            "{} received datagram(s) were byte-identical to an earlier received datagram (UDP may duplicate datagrams; the peer may also send identical replies)",
            facts.repeated_datagrams
        ));
    }
    rec.finish(
        s_idx,
        match &failure {
            Some(f) => phase_status_for(f.kind),
            None => PhaseStatus::Completed,
        },
    );
    obs.dispatch = if sent == 0 {
        DispatchState::NotDispatched
    } else if received > 0 {
        DispatchState::Sent
    } else {
        DispatchState::MayHaveBeenSent
    };
    obs.failure = failure;
    obs.bytes.request_body = tr.sent_bytes();
    obs.bytes.response_body_wire = Some(tr.received_bytes());
    if let (Some(e), Some(c)) = (&env, obs.connection.as_mut()) {
        c.proxy_header = Some(e.observation());
    }
    let obs = finish_attempt(rec, obs, events);
    let ps = ProtocolStatus::Udp { datagrams_sent: sent, datagrams_received: received, window_ms: plan.response_window_ms, masque: None };
    SessionOutput::single(AttemptOutput { observation: obs, response: None, body: Bytes::new() }, Some(tr.finish()), ps, facts)
}
