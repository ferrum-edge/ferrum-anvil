//! Datagram channels: the path a datagram session runs over.
//!
//! [`DatagramChannel`] is everything the DTLS adapter needs from a path: send
//! one datagram, receive the next one, and the largest datagram the path
//! carries. A channel only moves datagrams; phases, TLS evidence and the
//! transcript stay with the session adapter, and the channel's own evidence
//! (socket addresses, a PROXY envelope, a tunnel) is added to the attempt by
//! whoever opened it.
//!
//! * [`SocketChannel`]: a UDP socket connected to the destination, optionally
//!   prepending a PROXY v2 `DGRAM` envelope to every datagram.
//! * [`crate::masque::MasqueChannel`]: an open RFC 9298 CONNECT-UDP tunnel
//!   through an HTTP/3 proxy (QUIC DATAGRAM frames or DATAGRAM capsules).
//! * [`crate::hbone_udp::HboneChannel`]: an open Ferrum Mesh HBONE datagram
//!   tunnel (`[u16 length][payload]` records on an HTTP/2 `CONNECT` stream).
//!
//! Another path that carries datagrams plugs in by implementing the trait
//! and recording its outer leg as a `TunnelObservation`, as the tunnel
//! channels do.

use crate::proxy_protocol::Enveloper;
use anvil_domain::execution::TransportFailure;
use bytes::Bytes;
use std::future::Future;
use tokio::net::UdpSocket;

/// What arrived on a channel.
#[derive(Debug)]
pub enum Inbound {
    /// One datagram from the peer.
    Datagram(Bytes),
    /// The OS reported ICMP port unreachable for the destination (connected
    /// sockets only).
    PortUnreachable(std::io::Error),
    /// A receive error that does not end the channel.
    Error(std::io::Error),
    /// Something the path received and discarded because it was not a
    /// datagram for this session (described for the transcript).
    Dropped(String),
    /// The path ended; no further datagram can arrive. `failure` is `None`
    /// for a clean close by the path itself (a proxy's FIN), described by
    /// `note`.
    Ended { failure: Option<TransportFailure>, note: String },
}

/// What happened to one outbound datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    /// Handed to the path, with a note worth recording (for example that a
    /// different encoding was used).
    Sent(Option<String>),
    /// Not handed to the path, with the reason.
    NotSent(String),
}

/// A bidirectional datagram path. `recv` must be cancel-safe: it is polled
/// in `select!` loops next to timers and commands.
pub trait DatagramChannel: Send {
    /// Send one datagram. `Err` means the path itself failed.
    fn send(&mut self, datagram: &[u8]) -> impl Future<Output = Result<Sent, TransportFailure>> + Send;
    /// The next inbound item.
    fn recv(&mut self) -> impl Future<Output = Inbound> + Send;
    /// The largest datagram the path carries, when it is smaller than a UDP
    /// datagram (so a session can size its records to fit).
    fn max_datagram(&self) -> Option<usize> {
        None
    }
}

/// A UDP socket connected to the destination.
pub struct SocketChannel {
    sock: UdpSocket,
    envelope: Option<Enveloper>,
    buf: Vec<u8>,
}

impl SocketChannel {
    pub fn new(sock: UdpSocket, envelope: Option<Enveloper>) -> Self {
        SocketChannel { sock, envelope, buf: vec![0u8; 65_535] }
    }

    /// The PROXY envelope wrapping every datagram, if any.
    pub fn envelope(&self) -> Option<&Enveloper> {
        self.envelope.as_ref()
    }
}

impl DatagramChannel for SocketChannel {
    async fn send(&mut self, datagram: &[u8]) -> Result<Sent, TransportFailure> {
        // A failed send on a connected UDP socket (typically a pending ICMP
        // error) does not end the path; the next receive reports it.
        match self.sock.send(&crate::udp::wire(&mut self.envelope, datagram)).await {
            Ok(_) => Ok(Sent::Sent(None)),
            Err(e) => Ok(Sent::NotSent(format!("sending a datagram failed: {e}"))),
        }
    }

    async fn recv(&mut self) -> Inbound {
        match self.sock.recv(&mut self.buf).await {
            Ok(n) => Inbound::Datagram(Bytes::copy_from_slice(&self.buf[..n])),
            Err(e) if crate::udp::is_icmp_port_unreachable(&e) => Inbound::PortUnreachable(e),
            Err(e) => Inbound::Error(e),
        }
    }
}
