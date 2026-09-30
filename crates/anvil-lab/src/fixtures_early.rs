//! The `early` profile's 0-RTT pending-window fixture: a UDP relay in front of
//! the gateway's HTTP/3 listener that holds the client's Handshake-space
//! packets (its TLS Finished) while its 0-RTT packets pass.
//!
//! A QUIC server completes its handshake when it receives the client's
//! Finished (RFC 9001 section 4.1.2). Until the relay forwards it, every
//! request stream the gateway accepts is one it accepted while its handshake
//! was pending: the window EARLY-001 and EARLY-002 test. The relay reads only
//! the parts of a QUIC packet that are never protected (header form, version,
//! long-header type and lengths, RFC 9000 section 17.2); it decrypts nothing.
//!
//! One hold, armed by the scenario ([`Relay::arm`]):
//!
//! 1. *Armed*: everything passes until the client sends a 0-RTT packet.
//! 2. *Holding*: a datagram with only Initial or 0-RTT packets passes; one
//!    carrying a Handshake packet (the Finished, or its retransmission), a
//!    1-RTT packet, or a long-header packet the relay cannot read (it fails
//!    closed) is queued, in order.
//! 3. [`Relay::release`] (the scenario saw the gateway act on the 0-RTT
//!    request, or its cap ran out): the queued datagrams that carry a
//!    Handshake packet go out first. A 1-RTT packet coalesced into one of
//!    them goes out with it; [`HoldStats`] counts such datagrams.
//! 4. *Draining*: the other queued datagrams (1-RTT data such as EARLY-002's
//!    retry after its 425) wait for the first gateway datagram relayed to the
//!    Finished's client address after the release, which normally carries
//!    HANDSHAKE_DONE, then for the relay's `settle` time, or at most
//!    [`DRAIN_CAP`] in all. Releases before v0.9.8 can classify a 1-RTT stream
//!    that becomes ready in the same turn as their handshake completion as
//!    early data (ferrum-edge#5761), so the retry must not arrive with the
//!    Finished; the lab sets `settle` only for them.
//! 5. *Open*: everything passes until the next [`Relay::arm`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};
use tokio::task::{JoinHandle, JoinSet};

/// How long the queued 1-RTT datagrams wait after the Finished went out when
/// no gateway datagram follows it.
pub const DRAIN_CAP: Duration = Duration::from_millis(250);

const QUIC_V1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369) numbers the long-header types differently.
const QUIC_V2: u32 = 0x6b33_43cf;

/// The QUIC packet types of one UDP datagram that the relay's gate reads.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Packets {
    pub zero_rtt: bool,
    pub handshake: bool,
    /// A short-header (1-RTT) packet, always the last one in a datagram.
    pub one_rtt: bool,
    /// A long-header packet the relay could not read (an unknown version, or
    /// lengths past the datagram's end).
    pub unparsed: bool,
}

impl Packets {
    /// Queued while the Finished is held: a Handshake, a 1-RTT or an
    /// unreadable packet.
    fn held(&self) -> bool {
        self.handshake || self.one_rtt || self.unparsed
    }

    /// Waits for the drain after the release: 1-RTT or unreadable data
    /// without a Handshake packet.
    fn after_finished(&self) -> bool {
        (self.one_rtt || self.unparsed) && !self.handshake
    }
}

/// What the relay did during one hold that a check detail should name.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HoldStats {
    /// Datagrams that carried both a Handshake and a 1-RTT packet, released
    /// with the Finished or passed while draining: their 1-RTT data reached
    /// the gateway without waiting for the drain.
    pub coalesced_1rtt: usize,
    /// Datagrams with a long-header packet the relay could not read, held
    /// like 1-RTT data.
    pub unparsed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LongType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// The long-header packet type of a known version (RFC 9000 section 17.2,
/// RFC 9369 section 3.2).
fn long_type(version: u32, first: u8) -> Option<LongType> {
    let order = match version {
        QUIC_V1 => [LongType::Initial, LongType::ZeroRtt, LongType::Handshake, LongType::Retry],
        QUIC_V2 => [LongType::Retry, LongType::Initial, LongType::ZeroRtt, LongType::Handshake],
        _ => return None,
    };
    Some(order[usize::from((first >> 4) & 0x03)])
}

/// A QUIC variable-length integer (RFC 9000 section 16) and its length.
fn varint(d: &[u8]) -> Option<(u64, usize)> {
    let first = *d.first()?;
    let len = 1usize << (first >> 6);
    let rest = d.get(1..len)?;
    Some((rest.iter().fold(u64::from(first & 0x3f), |v, b| (v << 8) | u64::from(*b)), len))
}

/// The long-header packet at the start of `d`: its type and its length,
/// which the Length field gives (a Retry packet runs to the datagram's end).
fn long_packet(d: &[u8]) -> Option<(LongType, usize)> {
    let version = u32::from_be_bytes(d.get(1..5)?.try_into().ok()?);
    let ty = long_type(version, *d.first()?)?;
    let mut at = 6 + usize::from(*d.get(5)?);
    at += 1 + usize::from(*d.get(at)?);
    if ty == LongType::Retry {
        return Some((ty, d.len()));
    }
    if ty == LongType::Initial {
        let (token, n) = varint(d.get(at..)?)?;
        at = at.checked_add(n)?.checked_add(usize::try_from(token).ok()?)?;
    }
    let (len, n) = varint(d.get(at..)?)?;
    let end = at.checked_add(n)?.checked_add(usize::try_from(len).ok()?)?;
    (end <= d.len()).then_some((ty, end))
}

/// The packet types of one datagram, coalesced packets included (RFC 9000
/// section 12.2). Parsing stops at zero padding after the last long-header
/// packet, and at a long-header packet it cannot read (`unparsed`).
pub fn packets(datagram: &[u8]) -> Packets {
    let mut p = Packets::default();
    let mut d = datagram;
    while let Some(&first) = d.first() {
        if first & 0x80 == 0 {
            // A short header runs to the end of the datagram.
            p.one_rtt = d.len() == datagram.len() || d.iter().any(|b| *b != 0);
            break;
        }
        let Some((ty, len)) = long_packet(d) else {
            p.unparsed = true;
            break;
        };
        match ty {
            LongType::ZeroRtt => p.zero_rtt = true,
            LongType::Handshake => p.handshake = true,
            LongType::Initial | LongType::Retry => {}
        }
        d = &d[len..];
    }
    p
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// Everything passes.
    Open,
    /// Everything passes until the client sends a 0-RTT packet.
    Armed,
    /// Handshake and 1-RTT datagrams are queued. `since`: when the first
    /// Handshake one (the Finished) was.
    Holding { since: Option<Instant> },
    /// Released: the queued Handshake datagrams go out next.
    Releasing,
    /// The Finished went out: the other datagrams wait for the next gateway
    /// datagram to `client` (the Finished's sender; `None` once it came, or
    /// when no Finished was queued) and the settle time, or `until`.
    Draining { client: Option<SocketAddr>, until: Instant },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Queued {
    client: SocketAddr,
    datagram: Vec<u8>,
    packets: Packets,
}

/// The relay's gate, apart from its sockets.
#[derive(Debug)]
struct Machine {
    gate: Gate,
    queue: Vec<Queued>,
    /// How long 1-RTT datagrams still wait after the gateway's first datagram
    /// following the Finished.
    settle: Duration,
    /// Since the last [`Machine::arm`].
    stats: HoldStats,
}

impl Machine {
    fn new(settle: Duration) -> Self {
        Machine { gate: Gate::Open, queue: Vec::new(), settle, stats: HoldStats::default() }
    }

    /// Hold the next 0-RTT connection's Finished. Anything still queued goes
    /// out first ([`Machine::due`]).
    fn arm(&mut self) {
        self.gate = Gate::Armed;
        self.stats = HoldStats::default();
    }

    fn disarm(&mut self) {
        self.gate = Gate::Open;
    }

    /// When the Finished has been held since, while it is.
    fn holding_since(&self) -> Option<Instant> {
        match self.gate {
            Gate::Holding { since } => since,
            _ => None,
        }
    }

    /// Start the release of a hold; the number of datagrams queued.
    fn release(&mut self) -> usize {
        if matches!(self.gate, Gate::Holding { .. }) {
            self.gate = Gate::Releasing;
        }
        self.queue.len()
    }

    /// A client datagram: `Some` to forward now, `None` when queued.
    fn client(&mut self, now: Instant, client: SocketAddr, datagram: Vec<u8>) -> Option<Queued> {
        let packets = packets(&datagram);
        if self.gate == Gate::Armed && packets.zero_rtt {
            self.gate = Gate::Holding { since: None };
        }
        let hold = match self.gate {
            Gate::Open | Gate::Armed => false,
            Gate::Holding { .. } | Gate::Releasing => packets.held(),
            Gate::Draining { .. } => {
                self.stats.coalesced_1rtt += usize::from(packets.handshake && packets.one_rtt);
                packets.after_finished()
            }
        };
        let q = Queued { client, datagram, packets };
        if !hold {
            return Some(q);
        }
        self.stats.unparsed += usize::from(packets.unparsed);
        if packets.handshake && self.gate == (Gate::Holding { since: None }) {
            self.gate = Gate::Holding { since: Some(now) };
        }
        self.queue.push(q);
        None
    }

    /// A gateway datagram was relayed to `to`: while draining, the first one
    /// to the Finished's client frees the queue, once the settle time passed.
    fn server(&mut self, now: Instant, to: SocketAddr) -> Vec<Queued> {
        match self.gate {
            Gate::Draining { client: Some(c), until } if c == to => {
                if self.settle.is_zero() {
                    return self.open();
                }
                self.gate = Gate::Draining { client: None, until: until.min(now + self.settle) };
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// What is due now: after a release the queued Handshake datagrams; after
    /// the drain cap, or once disarmed or armed again, everything queued.
    fn due(&mut self, now: Instant) -> Vec<Queued> {
        match self.gate {
            Gate::Releasing => {
                let queue = std::mem::take(&mut self.queue);
                let (handshake, rest): (Vec<Queued>, Vec<Queued>) = queue.into_iter().partition(|q| q.packets.handshake);
                self.stats.coalesced_1rtt += handshake.iter().filter(|q| q.packets.one_rtt).count();
                self.queue = rest;
                self.gate = Gate::Draining { client: handshake.first().map(|q| q.client), until: now + DRAIN_CAP };
                handshake
            }
            Gate::Draining { until, .. } if now >= until => self.open(),
            Gate::Open | Gate::Armed => std::mem::take(&mut self.queue),
            _ => Vec::new(),
        }
    }

    fn open(&mut self) -> Vec<Queued> {
        self.gate = Gate::Open;
        std::mem::take(&mut self.queue)
    }
}

fn step<T>(machine: &Mutex<Machine>, f: impl FnOnce(&mut Machine) -> T) -> T {
    let mut m = machine.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut m)
}

/// The relay: a UDP listener that forwards to the gateway through one socket
/// per client address, and the gateway's datagrams back.
pub struct Relay {
    machine: Arc<Mutex<Machine>>,
    wake: Arc<Notify>,
    task: JoinHandle<()>,
}

impl Relay {
    /// Listen on `listen` and relay to `upstream`; `settle`: see *Draining*.
    pub async fn start(listen: &str, upstream: &str, settle: Duration) -> anyhow::Result<Relay> {
        let front = Arc::new(UdpSocket::bind(listen).await?);
        let upstream: SocketAddr = upstream.parse()?;
        let machine = Arc::new(Mutex::new(Machine::new(settle)));
        let wake = Arc::new(Notify::new());
        let task = tokio::spawn(relay(front, upstream, machine.clone(), wake.clone()));
        Ok(Relay { machine, wake, task })
    }

    fn with<T>(&self, f: impl FnOnce(&mut Machine) -> T) -> T {
        let t = step(&self.machine, f);
        self.wake.notify_one();
        t
    }

    /// Hold the Finished of the next connection that sends 0-RTT data.
    pub fn arm(&self) {
        self.with(Machine::arm)
    }

    /// When the held Finished was queued, while one is held.
    pub fn holding_since(&self) -> Option<Instant> {
        step(&self.machine, |m| m.holding_since())
    }

    /// Release the held Finished; returns the number of datagrams queued.
    pub fn release(&self) -> usize {
        self.with(Machine::release)
    }

    /// Stop holding and forward everything still queued.
    pub fn disarm(&self) {
        self.with(Machine::disarm)
    }

    /// What the relay did since the last [`Relay::arm`].
    pub fn stats(&self) -> HoldStats {
        step(&self.machine, |m| m.stats)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Datagrams = mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>;

/// Forward every datagram `socket` receives into `tx`, tagged with its
/// sender, or with `client` for a socket towards the gateway.
async fn read_into(socket: Arc<UdpSocket>, client: Option<SocketAddr>, tx: Datagrams) {
    let mut buf = vec![0u8; 65_535];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else { continue };
        if tx.send((client.unwrap_or(from), buf[..n].to_vec())).is_err() {
            return;
        }
    }
}

async fn relay(front: Arc<UdpSocket>, upstream: SocketAddr, machine: Arc<Mutex<Machine>>, wake: Arc<Notify>) {
    // Aborting this task drops the set, which aborts every reader.
    let mut readers = JoinSet::new();
    let (client_tx, mut from_client) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    let (gateway_tx, mut from_gateway) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    readers.spawn(read_into(front.clone(), None, client_tx));
    let mut sockets: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(5));
    loop {
        let out: Vec<Queued> = tokio::select! {
            Some((client, datagram)) = from_client.recv() => {
                step(&machine, |m| m.client(Instant::now(), client, datagram)).into_iter().collect()
            }
            Some((client, datagram)) = from_gateway.recv() => {
                let _ = front.send_to(&datagram, client).await;
                step(&machine, |m| m.server(Instant::now(), client))
            }
            _ = wake.notified() => step(&machine, |m| m.due(Instant::now())),
            _ = tick.tick() => step(&machine, |m| m.due(Instant::now())),
        };
        for q in out {
            let socket = match sockets.get(&q.client) {
                Some(s) => s.clone(),
                None => {
                    let Ok(s) = towards(upstream).await else { continue };
                    readers.spawn(read_into(s.clone(), Some(q.client), gateway_tx.clone()));
                    sockets.insert(q.client, s.clone());
                    s
                }
            };
            let _ = socket.send(&q.datagram).await;
        }
    }
}

async fn towards(upstream: SocketAddr) -> std::io::Result<Arc<UdpSocket>> {
    let s = UdpSocket::bind("127.0.0.1:0").await?;
    s.connect(upstream).await?;
    Ok(Arc::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// A long-header packet of `version` with type bits `bits`, an empty
    /// token when `token`, a two-byte Length field and `payload` bytes.
    fn long_with(version: u32, bits: u8, token: bool, payload: usize) -> Vec<u8> {
        let mut p = vec![0xc0 | (bits << 4)];
        p.extend(version.to_be_bytes());
        p.push(CID.len() as u8);
        p.extend(CID);
        p.push(0);
        if token {
            p.push(0);
        }
        p.extend([0x40 | (payload >> 8) as u8, payload as u8]);
        p.extend(std::iter::repeat_n(0xaa, payload));
        p
    }

    const INITIAL: u8 = 0;
    const ZERO_RTT: u8 = 1;
    const HANDSHAKE: u8 = 2;

    /// A QUIC v1 long-header packet.
    fn long(bits: u8, payload: usize) -> Vec<u8> {
        long_with(QUIC_V1, bits, bits == INITIAL, payload)
    }

    fn short(payload: usize) -> Vec<u8> {
        let mut p = vec![0x41];
        p.extend(CID);
        p.extend(std::iter::repeat_n(0xbb, payload));
        p
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    fn zero_rtt() -> Packets {
        Packets { zero_rtt: true, ..Default::default() }
    }

    fn handshake() -> Packets {
        Packets { handshake: true, ..Default::default() }
    }

    #[test]
    fn varints_of_every_length() {
        assert_eq!(varint(&[0x25]), Some((37, 1)));
        assert_eq!(varint(&[0x7b, 0xbd]), Some((15_293, 2)));
        assert_eq!(varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]), Some((151_288_809_941_952_652, 8)));
        assert_eq!(varint(&[0x7b]), None, "truncated");
    }

    #[test]
    fn coalesced_packets_are_all_seen() {
        assert_eq!(packets(&cat(&[long(INITIAL, 40), long(ZERO_RTT, 30)])), zero_rtt());
        let finished = cat(&[long(INITIAL, 20), long(HANDSHAKE, 50), short(12)]);
        assert_eq!(packets(&finished), Packets { handshake: true, one_rtt: true, ..Default::default() });
        assert_eq!(packets(&short(30)), Packets { one_rtt: true, ..Default::default() });
        // Zero padding after the last long-header packet is not a 1-RTT packet.
        assert_eq!(packets(&cat(&[long(INITIAL, 40), vec![0; 900]])), Packets::default());
    }

    /// An Initial's token is skipped (the packet after it is read), and QUIC
    /// v2 numbers the types 0b01 Initial, 0b10 0-RTT, 0b11 Handshake.
    #[test]
    fn an_initial_token_and_quic_v2_types_are_read() {
        let mut with_token = vec![0xc0, 0, 0, 0, 1, 0, 0, 3, 9, 9, 9, 0x05];
        with_token.extend([0xaa; 5]);
        assert_eq!(packets(&cat(&[with_token, long(HANDSHAKE, 4)])), handshake());
        assert_eq!(packets(&long_with(QUIC_V2, 0b01, true, 8)), Packets::default());
        assert_eq!(packets(&cat(&[long_with(QUIC_V2, 0b01, true, 8), long_with(QUIC_V2, 0b10, false, 8)])), zero_rtt());
        assert_eq!(packets(&long_with(QUIC_V2, 0b11, false, 8)), handshake());
    }

    #[test]
    fn unknown_versions_and_truncated_packets_are_unparsed() {
        let unparsed = Packets { unparsed: true, ..Default::default() };
        assert_eq!(packets(&long_with(0x0a0a_0a0a, HANDSHAKE, false, 8)), unparsed);
        let mut cut = long(HANDSHAKE, 8);
        cut.truncate(cut.len() - 1);
        assert_eq!(packets(&cut), unparsed);
        // After a readable packet the flags add up.
        assert_eq!(packets(&cat(&[long(ZERO_RTT, 8), cut])), Packets { zero_rtt: true, unparsed: true, ..Default::default() });
    }

    /// A token longer than 63 bytes has a two-byte length varint.
    #[test]
    fn an_initial_token_with_a_multi_byte_length_is_skipped() {
        let mut initial = vec![0xc0, 0, 0, 0, 1, 0, 0, 0x40, 100];
        initial.extend([7; 100]);
        initial.extend([0x40, 20]);
        initial.extend([0xaa; 20]);
        assert_eq!(packets(&cat(&[initial.clone(), long(ZERO_RTT, 4)])), zero_rtt());
        // One byte short of the token: unreadable, never a 0-RTT packet.
        initial.truncate(9 + 99);
        assert_eq!(packets(&initial), Packets { unparsed: true, ..Default::default() });
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    fn other() -> SocketAddr {
        "127.0.0.1:40001".parse().unwrap()
    }

    fn sent(q: Option<Queued>) -> bool {
        q.is_some()
    }

    #[test]
    fn open_and_armed_relays_pass_everything_until_0rtt() {
        let now = Instant::now();
        let mut m = Machine::new(Duration::ZERO);
        assert!(sent(m.client(now, addr(), cat(&[long(INITIAL, 10), long(HANDSHAKE, 10)]))));
        m.arm();
        assert!(sent(m.client(now, addr(), short(10))), "an earlier connection's 1-RTT data passes");
        assert!(sent(m.client(now, addr(), long(HANDSHAKE, 10))));
        assert_eq!(m.holding_since(), None);
    }

    /// The pending window: the 0-RTT flight passes, the Finished and every
    /// 1-RTT datagram wait; the release sends the Handshake datagrams first
    /// and the 1-RTT ones only after the gateway's next datagram.
    #[test]
    fn the_finished_is_held_until_released_and_1rtt_waits_for_the_gateway() {
        let t0 = Instant::now();
        let mut m = Machine::new(Duration::ZERO);
        m.arm();
        assert!(sent(m.client(t0, addr(), cat(&[long(INITIAL, 1200), long(ZERO_RTT, 80)]))));
        assert!(sent(m.client(t0, addr(), long(ZERO_RTT, 80))), "more 0-RTT data passes");
        assert_eq!(m.holding_since(), None, "nothing held yet");
        let ack = short(20);
        assert!(!sent(m.client(t0, addr(), ack.clone())));
        let t1 = t0 + Duration::from_millis(1);
        let finished = cat(&[long(INITIAL, 20), long(HANDSHAKE, 60)]);
        assert!(!sent(m.client(t1, addr(), finished.clone())));
        assert!(!sent(m.client(t1 + Duration::from_millis(3), addr(), long(HANDSHAKE, 60))), "a retransmission waits too");
        assert_eq!(m.holding_since(), Some(t1));
        assert!(m.server(t1, addr()).is_empty(), "the gateway's 0.5-RTT data frees nothing");
        assert!(m.due(t1).is_empty(), "nothing is due before the release");

        assert_eq!(m.release(), 3);
        assert_eq!(m.holding_since(), None);
        let retry = short(90);
        assert!(!sent(m.client(t1, addr(), retry.clone())), "released but not yet sent: still held");
        let t2 = t1 + Duration::from_millis(5);
        let first: Vec<Vec<u8>> = m.due(t2).into_iter().map(|q| q.datagram).collect();
        assert_eq!(first, vec![finished, long(HANDSHAKE, 60)]);
        assert!(!sent(m.client(t2, addr(), short(30))), "1-RTT data waits for the gateway");
        assert!(sent(m.client(t2, addr(), long(HANDSHAKE, 60))), "Handshake data passes");
        assert!(m.due(t2 + Duration::from_millis(1)).is_empty());
        let rest: Vec<Vec<u8>> = m.server(t2, addr()).into_iter().map(|q| q.datagram).collect();
        assert_eq!(rest, vec![ack, retry, short(30)], "in order");
        assert!(sent(m.client(t2, addr(), short(30))), "open");
    }

    #[test]
    fn without_a_gateway_datagram_the_drain_cap_frees_the_1rtt_data() {
        let t0 = Instant::now();
        let mut m = Machine::new(Duration::ZERO);
        m.arm();
        m.client(t0, addr(), long(ZERO_RTT, 10));
        m.client(t0, addr(), long(HANDSHAKE, 10));
        m.client(t0, addr(), short(10));
        m.release();
        assert_eq!(m.due(t0).len(), 1);
        assert!(m.due(t0 + DRAIN_CAP - Duration::from_millis(1)).is_empty());
        assert_eq!(m.due(t0 + DRAIN_CAP).len(), 1);
        assert!(sent(m.client(t0, addr(), short(10))));
    }

    /// Before v0.9.8: after the gateway's datagram, the 1-RTT data still
    /// waits for the settle time (within the drain cap).
    #[test]
    fn a_settle_time_follows_the_gateway_datagram() {
        let t0 = Instant::now();
        let settle = Duration::from_millis(20);
        let mut m = Machine::new(settle);
        m.arm();
        m.client(t0, addr(), long(ZERO_RTT, 10));
        m.client(t0, addr(), long(HANDSHAKE, 10));
        m.client(t0, addr(), short(10));
        m.release();
        assert_eq!(m.due(t0).len(), 1);
        let t1 = t0 + Duration::from_millis(1);
        assert!(m.server(t1, addr()).is_empty());
        assert!(m.server(t1, addr()).is_empty(), "a second gateway datagram does not cut the settle time short");
        assert!(!sent(m.client(t1, addr(), short(10))));
        assert!(m.due(t1 + settle - Duration::from_millis(1)).is_empty());
        assert_eq!(m.due(t1 + settle).len(), 2);
        assert!(sent(m.client(t1 + settle, addr(), short(10))));
    }

    #[test]
    fn disarming_forwards_everything_in_order() {
        let t0 = Instant::now();
        let mut m = Machine::new(Duration::ZERO);
        m.arm();
        m.client(t0, addr(), long(ZERO_RTT, 10));
        m.client(t0, addr(), short(1));
        m.client(t0, addr(), long(HANDSHAKE, 10));
        m.disarm();
        let all: Vec<Vec<u8>> = m.due(t0).into_iter().map(|q| q.datagram).collect();
        assert_eq!(all, vec![short(1), long(HANDSHAKE, 10)]);
        assert!(sent(m.client(t0, addr(), short(1))));
        assert_eq!(m.release(), 0, "no hold to release");
    }

    /// A 1-RTT packet coalesced into a Handshake datagram goes out with the
    /// Finished, or passes while draining, and the stats count it.
    #[test]
    fn coalesced_1rtt_goes_with_the_finished_and_is_counted() {
        let t0 = Instant::now();
        let mut m = Machine::new(Duration::ZERO);
        m.arm();
        m.client(t0, addr(), long(ZERO_RTT, 10));
        let finished = cat(&[long(HANDSHAKE, 60), short(40)]);
        assert!(!sent(m.client(t0, addr(), finished.clone())));
        assert!(!sent(m.client(t0, addr(), short(9))));
        m.release();
        let first: Vec<Vec<u8>> = m.due(t0).into_iter().map(|q| q.datagram).collect();
        assert_eq!(first, vec![finished]);
        assert_eq!(m.stats, HoldStats { coalesced_1rtt: 1, unparsed: 0 });
        assert!(sent(m.client(t0, addr(), cat(&[long(HANDSHAKE, 60), short(5)]))), "Handshake data passes while draining");
        assert_eq!(m.stats.coalesced_1rtt, 2);
        assert_eq!(m.server(t0, addr()).len(), 1, "the lone 1-RTT datagram waited for the gateway");
    }

    /// Unreadable datagrams are held while the Finished is (fail closed),
    /// wait for the drain after it, and are counted.
    #[test]
    fn unreadable_datagrams_are_held_and_counted() {
        let t0 = Instant::now();
        let mut m = Machine::new(Duration::ZERO);
        m.arm();
        m.client(t0, addr(), long(ZERO_RTT, 10));
        let odd = long_with(0x0a0a_0a0a, HANDSHAKE, false, 8);
        assert!(!sent(m.client(t0, addr(), odd.clone())));
        m.client(t0, addr(), long(HANDSHAKE, 10));
        m.release();
        assert_eq!(m.due(t0).len(), 1, "only the readable Handshake datagram goes first");
        assert!(!sent(m.client(t0, addr(), odd.clone())));
        assert_eq!(m.stats.unparsed, 2);
        assert_eq!(m.server(t0, addr()).len(), 2);
    }

    /// Only a gateway datagram to the Finished's client ends the drain.
    #[test]
    fn the_drain_waits_for_a_datagram_to_the_finisheds_client() {
        let t0 = Instant::now();
        let mut m = Machine::new(Duration::ZERO);
        m.arm();
        m.client(t0, addr(), long(ZERO_RTT, 10));
        m.client(t0, addr(), long(HANDSHAKE, 10));
        m.client(t0, addr(), short(10));
        m.release();
        assert_eq!(m.due(t0).len(), 1);
        assert!(m.server(t0, other()).is_empty(), "another client's datagram");
        assert_eq!(m.server(t0, addr()).len(), 1);
    }

    /// Arming again flushes what an earlier hold left queued, before
    /// anything else; until the 0-RTT packet, everything passes.
    #[test]
    fn arming_flushes_a_leftover_queue_first() {
        let t0 = Instant::now();
        let mut m = Machine::new(Duration::ZERO);
        m.arm();
        m.client(t0, addr(), long(ZERO_RTT, 10));
        m.client(t0, addr(), short(3));
        m.stats.unparsed = 7;
        m.arm();
        assert_eq!(m.stats, HoldStats::default(), "arming resets the stats");
        let left: Vec<Vec<u8>> = m.due(t0).into_iter().map(|q| q.datagram).collect();
        assert_eq!(left, vec![short(3)]);
        assert!(sent(m.client(t0, addr(), long(HANDSHAKE, 10))), "armed: an earlier connection's Finished passes");
        assert!(sent(m.client(t0, addr(), cat(&[long(INITIAL, 40), long(ZERO_RTT, 10)]))));
        assert!(!sent(m.client(t0, addr(), long(HANDSHAKE, 10))), "after the 0-RTT packet the Finished is held");
    }
}
