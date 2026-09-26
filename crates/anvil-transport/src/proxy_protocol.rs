//! PROXY protocol framing written by Anvil acting as a load balancer.
//!
//! * TCP / TCP+TLS: one PROXY v1 (text) or v2 (binary) header at the head of
//!   the connection, written after TCP connect (and any forward-proxy tunnel)
//!   and before the TLS ClientHello.
//! * UDP / DTLS: a PROXY v2 envelope with the `DGRAM` transport prepended to
//!   **every** datagram; for DTLS it wraps each datagram outside the DTLS
//!   records, handshake flights included. Optionally authenticated with an
//!   HMAC-SHA-256 tag (TLV `0xE0`) over the receiving listener's canonical
//!   identity plus the whole datagram with the tag elided, and a freshness
//!   record (TLV `0xE1`: version, sender id, epoch, sequence, timestamp).
//!
//! The byte formats are transcribed from Ferrum Edge v0.9.7 (tag
//! `8fed1346`): `src/proxy/proxy_protocol.rs` (`parse_v1_line`, `parse_v2`,
//! `encode_v2_proxy_header`) and `src/proxy/datagram_client_address.rs`
//! (`encode_datagram_with_metadata`, `DatagramListenerBinding::write_domain`,
//! `DatagramFreshness::encode_value`, `verify_authentication_tag`).
//! [`check_stream_header`] mirrors what that TCP parser accepts, so a
//! deliberately malformed header (`version: raw`) is recorded as such.
//!
//! The datagram secret is held in [`Zeroizing`] memory and never appears in
//! any observation; tag bytes are elided from recorded hex.

use anvil_domain::proxy_protocol::*;
use anvil_domain::secret::REDACTED;
use hmac::{KeyInit, Mac};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use zeroize::Zeroizing;

/// PROXY v2 signature.
pub const V2_SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
/// Ferrum's v1 limit: the whole line including `PROXY ` and CRLF is at most
/// 109 bytes (`V1_MAX_LEN`), i.e. 107 before CRLF.
pub const V1_MAX_LINE: usize = 107;
/// Ferrum's cap on a v2 address block (fixed addresses plus TLVs).
pub const V2_MAX_ADDR_LEN: usize = 512;
/// Authentication tag TLV type and tag length.
pub const AUTH_TLV_TYPE: u8 = 0xE0;
pub const AUTH_TAG_LEN: usize = 32;
/// Freshness TLV type, record version and value length.
pub const FRESHNESS_TLV_TYPE: u8 = 0xE1;
pub const FRESHNESS_VERSION: u8 = 0x01;
pub const FRESHNESS_VALUE_LEN: usize = 29;
/// Minimum secret length Ferrum accepts (`MIN_DATAGRAM_SECRET_BYTES`).
pub const MIN_DATAGRAM_SECRET_BYTES: usize = 32;
/// PROXY v2 TLV type `PP2_TYPE_AUTHORITY`.
pub const PP2_TYPE_AUTHORITY: u8 = 0x02;
/// Versioned domain-separation label absorbed ahead of every MAC input.
const DOMAIN_LABEL: &[u8] = b"ferrum-datagram-proxy-v1";
const DOMAIN_BINDING_VERSION: u8 = 0x01;
const TAG_MARK: &str = "‹tag›";

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// Fold an IPv4-mapped IPv6 address to IPv4 (Ferrum `client_identity::canonical_ip`).
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn canonical(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(a.ip()), a.port())
}

fn to_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Exact-value scrubber supplied by the engine.
pub type Redact<'a> = Option<&'a (dyn Fn(&str) -> String + Send + Sync)>;
/// Owned form of the scrubber (the session adapters' `RedactFn`).
pub type SharedRedact = std::sync::Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Replace bytes that carry a redacted value as a whole (never partially).
fn scrub(bytes: &[u8], redact: Redact<'_>) -> (String, bool) {
    let hex = hex::encode(bytes);
    match redact {
        Some(r) => {
            let lossy = String::from_utf8_lossy(bytes);
            if r(&lossy) != lossy { (REDACTED.to_string(), true) } else { (hex, false) }
        }
        None => (hex, false),
    }
}

/// Scrub the text fields of an observation. A declared address that carries
/// a redacted value is also encoded in the header bytes (in binary for v2),
/// so the recorded hex is replaced as a whole too.
pub fn scrub_observation(o: &mut ProxyHeaderObservation, redact: Redact<'_>) {
    let Some(r) = redact else { return };
    let mut hit = false;
    for f in [&mut o.source, &mut o.destination, &mut o.text] {
        if let Some(v) = f.as_mut()
            && r(v) != *v
        {
            *v = REDACTED.to_string();
            hit = true;
        }
    }
    for t in o.tlvs.iter_mut() {
        if r(t) != *t {
            *t = REDACTED.to_string();
            hit = true;
        }
    }
    if hit {
        o.hex = REDACTED.to_string();
    }
}

// ================================================================ TCP ===

/// A resolved connection-header plan (addresses and TLVs already parsed).
#[derive(Clone, Debug)]
pub struct HeaderPlan {
    pub version: ProxyHeaderVersion,
    pub command: ProxyCommand,
    pub family: ProxyAddressFamily,
    /// `None` = the real local socket address.
    pub source: Option<SocketAddr>,
    /// `None` = the real remote socket address.
    pub destination: Option<SocketAddr>,
    /// v2 TLVs in order (type, value).
    pub tlvs: Vec<(u8, Vec<u8>)>,
    /// `version: raw` bytes.
    pub raw: Vec<u8>,
}

/// Header bytes plus the evidence describing them.
#[derive(Clone, Debug)]
pub struct BuiltHeader {
    pub bytes: Vec<u8>,
    pub observation: ProxyHeaderObservation,
}

fn blank_observation(format: ProxyHeaderFormat) -> ProxyHeaderObservation {
    ProxyHeaderObservation {
        format,
        command: None,
        family: String::new(),
        source: None,
        source_origin: None,
        destination: None,
        destination_origin: None,
        length: 0,
        hex: String::new(),
        text: None,
        tlvs: vec![],
        well_formed: true,
        problem: None,
        authenticated: false,
        listener_binding: None,
        sender_id: None,
        epoch: None,
        first_sequence: None,
        last_sequence: None,
        datagrams: 0,
    }
}

fn pick(configured: Option<SocketAddr>, socket: Option<SocketAddr>, which: &str) -> Result<(SocketAddr, AddressOrigin), String> {
    match (configured, socket) {
        (Some(a), _) => Ok((a, AddressOrigin::Configured)),
        (None, Some(a)) => Ok((a, AddressOrigin::Socket)),
        (None, None) => Err(format!("the real {which} socket address is not known; set the PROXY header {which} explicitly")),
    }
}

impl HeaderPlan {
    /// Build the header for a connection whose socket addresses are
    /// `local` → `remote` (`None` when they are not the addresses the header
    /// should describe, e.g. behind a forward-proxy tunnel).
    pub fn build(&self, local: Option<SocketAddr>, remote: Option<SocketAddr>, redact: Redact<'_>) -> Result<BuiltHeader, String> {
        let mut built = match self.version {
            ProxyHeaderVersion::Raw => Ok(self.build_raw(redact)),
            ProxyHeaderVersion::V1 => self.build_v1(local, remote, redact),
            ProxyHeaderVersion::V2 => self.build_v2(local, remote, redact),
        }?;
        scrub_observation(&mut built.observation, redact);
        Ok(built)
    }

    fn build_raw(&self, redact: Redact<'_>) -> BuiltHeader {
        let mut o = blank_observation(ProxyHeaderFormat::Raw);
        describe_stream_header(&self.raw, &mut o);
        let (hex, redacted) = scrub(&self.raw, redact);
        o.hex = hex;
        if redacted {
            o.text = None;
            o.source = None;
            o.destination = None;
            o.tlvs.clear();
        }
        o.length = self.raw.len() as u32;
        BuiltHeader { bytes: self.raw.clone(), observation: o }
    }

    fn build_v1(&self, local: Option<SocketAddr>, remote: Option<SocketAddr>, redact: Redact<'_>) -> Result<BuiltHeader, String> {
        let mut o = blank_observation(ProxyHeaderFormat::V1);
        if self.command == ProxyCommand::Local {
            return Err("PROXY v1 has no LOCAL command; use v2, or v1 with the UNKNOWN family".into());
        }
        let line = if self.family == ProxyAddressFamily::Unspec {
            o.family = "UNKNOWN".into();
            "PROXY UNKNOWN".to_string()
        } else {
            let (src, so) = pick(self.source, local, "source")?;
            let (dst, dor) = pick(self.destination, remote, "destination")?;
            let (src, dst) = (canonical(src), canonical(dst));
            let proto = match (src.ip(), dst.ip()) {
                (IpAddr::V4(_), IpAddr::V4(_)) => "TCP4",
                (IpAddr::V6(_), IpAddr::V6(_)) => "TCP6",
                _ => return Err(format!("PROXY v1 needs both addresses in one family (source {src}, destination {dst})")),
            };
            o.family = proto.into();
            o.source = Some(src.to_string());
            o.source_origin = Some(so);
            o.destination = Some(dst.to_string());
            o.destination_origin = Some(dor);
            format!("PROXY {proto} {} {} {} {}", src.ip(), dst.ip(), src.port(), dst.port())
        };
        if line.len() > V1_MAX_LINE {
            return Err(format!("the PROXY v1 line is {} bytes; the limit is {V1_MAX_LINE} before CRLF", line.len()));
        }
        let mut bytes = line.clone().into_bytes();
        bytes.extend_from_slice(b"\r\n");
        let (hex, redacted) = scrub(&bytes, redact);
        o.hex = hex;
        o.text = if redacted { Some(REDACTED.to_string()) } else { Some(line) };
        o.length = bytes.len() as u32;
        Ok(BuiltHeader { bytes, observation: o })
    }

    fn build_v2(&self, local: Option<SocketAddr>, remote: Option<SocketAddr>, redact: Redact<'_>) -> Result<BuiltHeader, String> {
        let mut o = blank_observation(ProxyHeaderFormat::V2);
        o.command = Some(self.command);
        let (ver_cmd, fam, fixed): (u8, u8, Vec<u8>) = match (self.command, self.family) {
            // LOCAL: the balancer's own connection; the receiver ignores
            // addresses, so none are sent (Ferrum test `v2_local_command`).
            (ProxyCommand::Local, _) => {
                o.family = "AF_UNSPEC".into();
                (0x20, 0x00, vec![])
            }
            // PROXY + AF_UNSPEC (+ UNSPEC transport): no addresses.
            (ProxyCommand::Proxy, ProxyAddressFamily::Unspec) => {
                o.family = "AF_UNSPEC".into();
                (0x21, 0x00, vec![])
            }
            (ProxyCommand::Proxy, ProxyAddressFamily::Auto) => {
                let (src, so) = pick(self.source, local, "source")?;
                let (dst, dor) = pick(self.destination, remote, "destination")?;
                let (src, dst) = (canonical(src), canonical(dst));
                o.source = Some(src.to_string());
                o.source_origin = Some(so);
                o.destination = Some(dst.to_string());
                o.destination_origin = Some(dor);
                let mut fixed = Vec::with_capacity(36);
                match (src.ip(), dst.ip()) {
                    (IpAddr::V4(s), IpAddr::V4(d)) => {
                        o.family = "AF_INET".into();
                        fixed.extend_from_slice(&s.octets());
                        fixed.extend_from_slice(&d.octets());
                        fixed.extend_from_slice(&src.port().to_be_bytes());
                        fixed.extend_from_slice(&dst.port().to_be_bytes());
                        (0x21, 0x11, fixed)
                    }
                    (s, d) => {
                        // Mixed or IPv6 pairs: one family, IPv4 promoted to its
                        // mapped form (Ferrum `encode_v2_proxy_header`).
                        o.family = "AF_INET6".into();
                        fixed.extend_from_slice(&to_v6(s).octets());
                        fixed.extend_from_slice(&to_v6(d).octets());
                        fixed.extend_from_slice(&src.port().to_be_bytes());
                        fixed.extend_from_slice(&dst.port().to_be_bytes());
                        (0x21, 0x21, fixed)
                    }
                }
            }
        };
        let mut tlv_bytes = Vec::new();
        for (t, v) in &self.tlvs {
            let len = u16::try_from(v.len()).map_err(|_| format!("TLV 0x{t:02x} is {} bytes; a TLV value holds at most 65535", v.len()))?;
            tlv_bytes.push(*t);
            tlv_bytes.extend_from_slice(&len.to_be_bytes());
            tlv_bytes.extend_from_slice(v);
            o.tlvs.push(tlv_summary(*t, v));
        }
        let addr_len = fixed.len() + tlv_bytes.len();
        let addr_len16 =
            u16::try_from(addr_len).map_err(|_| format!("the address block is {addr_len} bytes; PROXY v2 allows at most 65535"))?;
        if addr_len > V2_MAX_ADDR_LEN {
            o.problem = Some(format!(
                "the address block is {addr_len} bytes, above the {V2_MAX_ADDR_LEN}-byte cap some receivers (Ferrum Edge) enforce"
            ));
        }
        let mut bytes = Vec::with_capacity(16 + addr_len);
        bytes.extend_from_slice(V2_SIG);
        bytes.push(ver_cmd);
        bytes.push(fam);
        bytes.extend_from_slice(&addr_len16.to_be_bytes());
        bytes.extend_from_slice(&fixed);
        bytes.extend_from_slice(&tlv_bytes);
        let (hex, redacted) = scrub(&bytes, redact);
        o.hex = hex;
        if redacted {
            o.tlvs = vec![REDACTED.to_string()];
        }
        o.length = bytes.len() as u32;
        Ok(BuiltHeader { bytes, observation: o })
    }
}

fn tlv_summary(t: u8, v: &[u8]) -> String {
    match t {
        PP2_TYPE_AUTHORITY => format!("0x02 authority {:?}", String::from_utf8_lossy(v)),
        0x05 => format!("0x05 unique id ({} bytes)", v.len()),
        _ => format!("0x{t:02x} ({} bytes): {}", v.len(), hex::encode(&v[..v.len().min(32)])),
    }
}

/// What a PROXY header parser (Ferrum Edge semantics) makes of `bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamHeader {
    /// v1 `TCP4`/`TCP6` or v2 PROXY with an address pair.
    Forwarded { v2: bool, src: SocketAddr, dst: SocketAddr, header_len: usize },
    /// v1 `UNKNOWN`, v2 LOCAL, `AF_UNSPEC`, `AF_UNIX` or a non-STREAM transport:
    /// the receiver keeps the socket peer.
    NoAddress { v2: bool, local: bool, header_len: usize },
}

/// Check `bytes` the way Ferrum Edge's TCP parser reads a connection header
/// (`src/proxy/proxy_protocol.rs`): v1 up to CRLF within 109 bytes, v2 with
/// version 2, command LOCAL/PROXY, address block ≤ 512 bytes and a family
/// whose fixed block fits. Bytes after the header are stream data.
pub fn check_stream_header(bytes: &[u8]) -> Result<StreamHeader, String> {
    if bytes.starts_with(b"PROXY ") {
        let limit = bytes.len().min(109);
        let Some(end) = bytes[..limit].windows(2).position(|w| w == b"\r\n") else {
            return Err(if bytes.len() >= 109 {
                "the PROXY v1 line has no CRLF within 109 bytes".into()
            } else {
                "the PROXY v1 line is not terminated by CRLF".into()
            });
        };
        let line = std::str::from_utf8(&bytes[..end]).map_err(|_| "the PROXY v1 line is not UTF-8".to_string())?;
        return check_v1_line(line, end + 2);
    }
    if bytes.len() >= 6 && bytes[..6] == V2_SIG[..6] {
        if bytes.len() < 16 {
            return Err(format!("truncated PROXY v2 header ({} bytes; at least 16 are needed)", bytes.len()));
        }
        if &bytes[..12] != V2_SIG {
            return Err("invalid PROXY v2 signature".into());
        }
        let ver_cmd = bytes[12];
        let fam = bytes[13];
        let addr_len = u16::from_be_bytes([bytes[14], bytes[15]]) as usize;
        if ver_cmd >> 4 != 2 {
            return Err(format!("unsupported PROXY v2 version {}", ver_cmd >> 4));
        }
        if addr_len > V2_MAX_ADDR_LEN {
            return Err(format!("PROXY v2 address block length {addr_len} exceeds the {V2_MAX_ADDR_LEN}-byte cap"));
        }
        if bytes.len() < 16 + addr_len {
            return Err(format!("truncated PROXY v2 address block ({addr_len} declared, {} present)", bytes.len() - 16));
        }
        let header_len = 16 + addr_len;
        let block = &bytes[16..header_len];
        return match ver_cmd & 0x0f {
            0x00 => Ok(StreamHeader::NoAddress { v2: true, local: true, header_len }),
            0x01 => {
                let transport = fam & 0x0f;
                match fam >> 4 {
                    0x00 | 0x03 => Ok(StreamHeader::NoAddress { v2: true, local: false, header_len }),
                    0x01 => {
                        if block.len() < 12 {
                            return Err(format!("AF_INET address block too short: {} bytes", block.len()));
                        }
                        if transport != 0x01 {
                            return Ok(StreamHeader::NoAddress { v2: true, local: false, header_len });
                        }
                        let src = SocketAddr::new(
                            Ipv4Addr::new(block[0], block[1], block[2], block[3]).into(),
                            u16::from_be_bytes([block[8], block[9]]),
                        );
                        let dst = SocketAddr::new(
                            Ipv4Addr::new(block[4], block[5], block[6], block[7]).into(),
                            u16::from_be_bytes([block[10], block[11]]),
                        );
                        Ok(StreamHeader::Forwarded { v2: true, src, dst, header_len })
                    }
                    0x02 => {
                        if block.len() < 36 {
                            return Err(format!("AF_INET6 address block too short: {} bytes", block.len()));
                        }
                        if transport != 0x01 {
                            return Ok(StreamHeader::NoAddress { v2: true, local: false, header_len });
                        }
                        let s: [u8; 16] = block[..16].try_into().expect("16 bytes");
                        let d: [u8; 16] = block[16..32].try_into().expect("16 bytes");
                        let src = SocketAddr::new(Ipv6Addr::from(s).into(), u16::from_be_bytes([block[32], block[33]]));
                        let dst = SocketAddr::new(Ipv6Addr::from(d).into(), u16::from_be_bytes([block[34], block[35]]));
                        Ok(StreamHeader::Forwarded { v2: true, src, dst, header_len })
                    }
                    other => Err(format!("unsupported PROXY v2 address family 0x{other:02x}")),
                }
            }
            other => Err(format!("unsupported PROXY v2 command 0x{other:02x}")),
        };
    }
    if bytes.is_empty() { Err("the header is empty".into()) } else { Err("the bytes do not start with a PROXY v1 or v2 signature".into()) }
}

fn check_v1_line(line: &str, header_len: usize) -> Result<StreamHeader, String> {
    let mut parts = line.split_ascii_whitespace();
    if parts.next() != Some("PROXY") {
        return Err("expected the PROXY keyword".into());
    }
    let proto = parts.next().ok_or("missing protocol field in the v1 header")?;
    match proto {
        "UNKNOWN" => return Ok(StreamHeader::NoAddress { v2: false, local: false, header_len }),
        "TCP4" | "TCP6" => {}
        other => return Err(format!("unsupported v1 protocol {other:?}")),
    }
    let mut field = |name: &str| parts.next().ok_or_else(|| format!("missing {name} in the v1 header"));
    let (s, d, sp, dp) = (field("source address")?, field("destination address")?, field("source port")?, field("destination port")?);
    let sp: u16 = sp.parse().map_err(|_| "invalid source port in the v1 header".to_string())?;
    let dp: u16 = dp.parse().map_err(|_| "invalid destination port in the v1 header".to_string())?;
    let s: IpAddr = s.parse().map_err(|_| format!("invalid source IP {s:?}"))?;
    let d: IpAddr = d.parse().map_err(|_| format!("invalid destination IP {d:?}"))?;
    let v4 = proto == "TCP4";
    if v4 != s.is_ipv4() || v4 != d.is_ipv4() {
        return Err(format!("{proto} addresses must be {}", if v4 { "IPv4" } else { "IPv6" }));
    }
    Ok(StreamHeader::Forwarded { v2: false, src: SocketAddr::new(s, sp), dst: SocketAddr::new(d, dp), header_len })
}

/// Fill an observation from raw header bytes.
fn describe_stream_header(bytes: &[u8], o: &mut ProxyHeaderObservation) {
    match check_stream_header(bytes) {
        Ok(h) => {
            let (v2, len) = match &h {
                StreamHeader::Forwarded { v2, src, dst, header_len } => {
                    o.source = Some(src.to_string());
                    o.destination = Some(dst.to_string());
                    o.source_origin = Some(AddressOrigin::Configured);
                    o.destination_origin = Some(AddressOrigin::Configured);
                    o.family = match (v2, src.is_ipv4()) {
                        (false, true) => "TCP4",
                        (false, false) => "TCP6",
                        (true, true) => "AF_INET",
                        (true, false) => "AF_INET6",
                    }
                    .into();
                    (*v2, *header_len)
                }
                StreamHeader::NoAddress { v2, local, header_len } => {
                    o.family = if *v2 { "AF_UNSPEC".into() } else { "UNKNOWN".into() };
                    if *v2 {
                        o.command = Some(if *local { ProxyCommand::Local } else { ProxyCommand::Proxy });
                    }
                    (*v2, *header_len)
                }
            };
            if !v2 {
                o.text = std::str::from_utf8(&bytes[..len.saturating_sub(2)]).ok().map(str::to_string);
            } else if o.command.is_none() {
                o.command = Some(ProxyCommand::Proxy);
            }
            if len < bytes.len() {
                o.problem = Some(format!("{} byte(s) after the header are sent as stream data", bytes.len() - len));
            }
        }
        Err(e) => {
            o.family = "unparsed".into();
            o.well_formed = false;
            o.problem = Some(e);
        }
    }
}

// =========================================================== datagram ===

/// The exact receiving listener an authenticated envelope is minted for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerBinding {
    pub protocol: DatagramListenerProtocol,
    /// Canonical bind address (IPv4-mapped IPv6 folded to IPv4).
    pub bind_addr: IpAddr,
    pub port: u16,
}

impl ListenerBinding {
    pub fn new(protocol: DatagramListenerProtocol, bind_addr: IpAddr, port: u16) -> Self {
        ListenerBinding { protocol, bind_addr: canonical_ip(bind_addr), port }
    }

    /// `"ferrum-datagram-proxy-v1" | 0x01 | protocol | family | bind octets | port`
    /// (Ferrum `DatagramListenerBinding::write_domain`).
    pub fn canonical_domain(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(DOMAIN_LABEL);
        out.push(DOMAIN_BINDING_VERSION);
        out.push(match self.protocol {
            DatagramListenerProtocol::Udp => 0x01,
            DatagramListenerProtocol::Dtls => 0x02,
        });
        match self.bind_addr {
            IpAddr::V4(v4) => {
                out.push(0x04);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(0x06);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        out
    }

    pub fn label(&self) -> String {
        let p = match self.protocol {
            DatagramListenerProtocol::Udp => "udp",
            DatagramListenerProtocol::Dtls => "dtls",
        };
        format!("{p} {}", SocketAddr::new(self.bind_addr, self.port))
    }
}

/// Freshness record (TLV `0xE1` value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freshness {
    pub sender_id: u32,
    pub epoch: u64,
    pub sequence: u64,
    pub timestamp_ms: u64,
}

impl Freshness {
    /// `version u8 | sender_id u32 | epoch u64 | sequence u64 | timestamp_ms u64`, big-endian.
    pub fn encode_value(&self) -> [u8; FRESHNESS_VALUE_LEN] {
        let mut out = [0u8; FRESHNESS_VALUE_LEN];
        out[0] = FRESHNESS_VERSION;
        out[1..5].copy_from_slice(&self.sender_id.to_be_bytes());
        out[5..13].copy_from_slice(&self.epoch.to_be_bytes());
        out[13..21].copy_from_slice(&self.sequence.to_be_bytes());
        out[21..29].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        out
    }
}

/// Envelope form (Ferrum `DatagramEnvelopeForm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeForm {
    /// `LOCAL`, `fam_transport` 0x00, no addresses.
    Local,
    /// `PROXY` + `AF_UNSPEC` + `DGRAM` (0x02), no addresses.
    Unspec,
    Forwarded {
        source: SocketAddr,
        destination: SocketAddr,
    },
}

/// Authentication material for one envelope. Not `Debug`: it holds the key.
pub struct EnvelopeKey<'a> {
    pub secret: &'a [u8],
    pub binding: &'a ListenerBinding,
    pub freshness: Freshness,
}

/// Build one datagram carrying the envelope (Ferrum `encode_datagram_with_metadata`).
/// Returns the datagram and the offset of the tag value, when authenticated.
pub fn encode_datagram(form: EnvelopeForm, payload: &[u8], auth: Option<&EnvelopeKey<'_>>) -> (Vec<u8>, Option<usize>) {
    let (ver_cmd, fam, fixed): (u8, u8, Vec<u8>) = match form {
        EnvelopeForm::Local => (0x20, 0x00, vec![]),
        EnvelopeForm::Unspec => (0x21, 0x02, vec![]),
        EnvelopeForm::Forwarded { source, destination } => {
            let (s, d) = (canonical(source), canonical(destination));
            let mut fixed = Vec::with_capacity(36);
            match (s.ip(), d.ip()) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    fixed.extend_from_slice(&a.octets());
                    fixed.extend_from_slice(&b.octets());
                    fixed.extend_from_slice(&s.port().to_be_bytes());
                    fixed.extend_from_slice(&d.port().to_be_bytes());
                    (0x21, 0x12, fixed)
                }
                (a, b) => {
                    fixed.extend_from_slice(&to_v6(a).octets());
                    fixed.extend_from_slice(&to_v6(b).octets());
                    fixed.extend_from_slice(&s.port().to_be_bytes());
                    fixed.extend_from_slice(&d.port().to_be_bytes());
                    (0x21, 0x22, fixed)
                }
            }
        }
    };
    let tlv_len = if auth.is_some() { 3 + FRESHNESS_VALUE_LEN + 3 + AUTH_TAG_LEN } else { 0 };
    let addr_len = (fixed.len() + tlv_len) as u16;
    let mut out = Vec::with_capacity(16 + addr_len as usize + payload.len());
    out.extend_from_slice(V2_SIG);
    out.push(ver_cmd);
    out.push(fam);
    out.extend_from_slice(&addr_len.to_be_bytes());
    out.extend_from_slice(&fixed);
    let Some(auth) = auth else {
        out.extend_from_slice(payload);
        return (out, None);
    };
    out.push(FRESHNESS_TLV_TYPE);
    out.extend_from_slice(&(FRESHNESS_VALUE_LEN as u16).to_be_bytes());
    out.extend_from_slice(&auth.freshness.encode_value());
    out.push(AUTH_TLV_TYPE);
    out.extend_from_slice(&(AUTH_TAG_LEN as u16).to_be_bytes());
    let tag_start = out.len();
    out.extend_from_slice(&[0u8; AUTH_TAG_LEN]);
    out.extend_from_slice(payload);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(auth.secret).expect("HMAC accepts any key length");
    mac.update(&auth.binding.canonical_domain());
    mac.update(&out[..tag_start]);
    mac.update(&out[tag_start + AUTH_TAG_LEN..]);
    let tag = mac.finalize().into_bytes();
    out[tag_start..tag_start + AUTH_TAG_LEN].copy_from_slice(&tag);
    (out, Some(tag_start))
}

/// Unix milliseconds now.
pub fn unix_now_millis() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Authentication settings of an envelope plan.
#[derive(Clone)]
pub struct EnvelopeAuthPlan {
    pub secret: Zeroizing<Vec<u8>>,
    pub protocol: DatagramListenerProtocol,
    pub bind_addr: IpAddr,
    /// `None` = the destination port.
    pub port: Option<u16>,
    pub sender_id: u32,
    /// `None` = Unix milliseconds when the session starts.
    pub epoch: Option<u64>,
    pub first_sequence: u64,
    pub timestamp_offset_ms: i64,
}

impl std::fmt::Debug for EnvelopeAuthPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeAuthPlan").field("secret", &REDACTED).field("sender_id", &self.sender_id).finish()
    }
}

/// A resolved datagram-envelope plan.
#[derive(Clone, Debug)]
pub struct EnvelopePlan {
    pub command: ProxyCommand,
    pub family: ProxyAddressFamily,
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
    pub auth: Option<EnvelopeAuthPlan>,
}

struct Minting {
    secret: Zeroizing<Vec<u8>>,
    binding: ListenerBinding,
    sender_id: u32,
    epoch: u64,
    next_sequence: u64,
    timestamp_offset_ms: i64,
}

/// Wraps every outgoing datagram and accounts for what was sent.
pub struct Enveloper {
    form: EnvelopeForm,
    minting: Option<Minting>,
    observation: ProxyHeaderObservation,
    redact: Option<SharedRedact>,
}

impl EnvelopePlan {
    /// Start wrapping for a socket `local` → `remote`.
    pub fn start(&self, local: Option<SocketAddr>, remote: Option<SocketAddr>) -> Result<Enveloper, String> {
        let mut o = blank_observation(ProxyHeaderFormat::V2Datagram);
        o.command = Some(self.command);
        let form = match (self.command, self.family) {
            (ProxyCommand::Local, _) => {
                o.family = "AF_UNSPEC".into();
                EnvelopeForm::Local
            }
            (ProxyCommand::Proxy, ProxyAddressFamily::Unspec) => {
                o.family = "AF_UNSPEC".into();
                EnvelopeForm::Unspec
            }
            (ProxyCommand::Proxy, ProxyAddressFamily::Auto) => {
                let (s, so) = pick(self.source, local, "source")?;
                let (d, dor) = pick(self.destination, remote, "destination")?;
                if s.ip().is_unspecified() {
                    return Err("the local socket address is unspecified; set the envelope source explicitly".into());
                }
                let (s, d) = (canonical(s), canonical(d));
                o.family = if s.is_ipv4() && d.is_ipv4() { "AF_INET" } else { "AF_INET6" }.into();
                o.source = Some(s.to_string());
                o.source_origin = Some(so);
                o.destination = Some(d.to_string());
                o.destination_origin = Some(dor);
                EnvelopeForm::Forwarded { source: s, destination: d }
            }
        };
        let minting = match &self.auth {
            None => None,
            Some(a) => {
                if a.secret.len() < MIN_DATAGRAM_SECRET_BYTES {
                    return Err(format!("the datagram authentication secret must be at least {MIN_DATAGRAM_SECRET_BYTES} bytes"));
                }
                let port = match (a.port, self.destination, remote) {
                    (Some(p), _, _) => p,
                    (None, Some(d), _) => d.port(),
                    (None, None, Some(r)) => r.port(),
                    (None, None, None) => return Err("the listener port is not known; set it explicitly".into()),
                };
                let binding = ListenerBinding::new(a.protocol, a.bind_addr, port);
                let epoch = a.epoch.unwrap_or_else(unix_now_millis);
                o.authenticated = true;
                o.listener_binding = Some(binding.label());
                o.sender_id = Some(a.sender_id);
                o.epoch = Some(epoch);
                o.first_sequence = Some(a.first_sequence);
                Some(Minting {
                    secret: a.secret.clone(),
                    binding,
                    sender_id: a.sender_id,
                    epoch,
                    next_sequence: a.first_sequence,
                    timestamp_offset_ms: a.timestamp_offset_ms,
                })
            }
        };
        Ok(Enveloper { form, minting, observation: o, redact: None })
    }
}

impl Enveloper {
    /// Prepend the envelope to one datagram (each call consumes one sequence).
    pub fn wrap(&mut self, payload: &[u8]) -> Vec<u8> {
        let (datagram, tag_at, fresh) = match &mut self.minting {
            None => {
                let (d, _) = encode_datagram(self.form, payload, None);
                (d, None, None)
            }
            Some(m) => {
                let ts = unix_now_millis().saturating_add_signed(m.timestamp_offset_ms);
                let freshness = Freshness { sender_id: m.sender_id, epoch: m.epoch, sequence: m.next_sequence, timestamp_ms: ts };
                m.next_sequence = m.next_sequence.saturating_add(1);
                let key = EnvelopeKey { secret: &m.secret, binding: &m.binding, freshness };
                let (d, at) = encode_datagram(self.form, payload, Some(&key));
                (d, at, Some(freshness))
            }
        };
        let header_len = datagram.len() - payload.len();
        let o = &mut self.observation;
        if o.datagrams == 0 {
            o.length = header_len as u32;
            o.hex = match tag_at {
                Some(at) => format!("{}{TAG_MARK}", hex::encode(&datagram[..at])),
                None => hex::encode(&datagram[..header_len]),
            };
            if let Some(f) = fresh {
                o.tlvs = vec![
                    format!(
                        "0xE1 freshness v{FRESHNESS_VERSION} sender_id={} epoch={} sequence={} timestamp_ms={}",
                        f.sender_id, f.epoch, f.sequence, f.timestamp_ms
                    ),
                    format!("0xE0 authentication tag ({AUTH_TAG_LEN} bytes, not recorded)"),
                ];
            }
        }
        if let Some(f) = fresh {
            o.last_sequence = Some(f.sequence);
            if f.sequence == u64::MAX {
                o.problem = Some("sequence u64::MAX is reserved; receivers refuse it (the sender must roll its epoch)".into());
            }
        }
        o.datagrams += 1;
        datagram
    }

    /// Scrub recorded text with the engine's exact-value redactor.
    pub fn with_redact(mut self, redact: Option<SharedRedact>) -> Self {
        self.redact = redact;
        self
    }

    /// The evidence so far (scrubbed).
    pub fn observation(&self) -> ProxyHeaderObservation {
        let mut o = self.observation.clone();
        scrub_observation(&mut o, self.redact.as_deref());
        o
    }

    /// One-line summary for transcripts and notes.
    pub fn summary(&self) -> String {
        let o = &self.observation();
        let addrs = match (&o.source, &o.destination) {
            (Some(s), Some(d)) => format!(" {s} → {d}"),
            _ => String::new(),
        };
        let auth = match (&o.listener_binding, o.sender_id, o.epoch) {
            (Some(b), Some(s), Some(e)) => format!("; authenticated for {b}, sender {s}, epoch {e}"),
            _ => "; unauthenticated".into(),
        };
        let cmd = if o.command == Some(ProxyCommand::Local) { "LOCAL" } else { "PROXY" };
        format!("PROXY v2 DGRAM envelope ({cmd} {}{addrs}{auth}) on every datagram", o.family)
    }
}

/// One-line summary of a connection header for the phase detail.
pub fn header_summary(o: &ProxyHeaderObservation) -> String {
    let v = match o.format {
        ProxyHeaderFormat::V1 => "PROXY v1",
        ProxyHeaderFormat::V2 => "PROXY v2",
        ProxyHeaderFormat::Raw => "raw PROXY header",
        ProxyHeaderFormat::V2Datagram => "PROXY v2 DGRAM",
    };
    let cmd = match o.command {
        Some(ProxyCommand::Local) => " LOCAL",
        Some(ProxyCommand::Proxy) if o.format != ProxyHeaderFormat::V1 => " PROXY",
        _ => "",
    };
    let addrs = match (&o.source, &o.destination) {
        (Some(s), Some(d)) => format!(" {s} → {d}"),
        _ => String::new(),
    };
    let wf = if o.well_formed { "" } else { ", malformed" };
    format!("{v}{cmd} {}{addrs} ({} bytes{wf})", o.family, o.length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn plan(version: ProxyHeaderVersion) -> HeaderPlan {
        HeaderPlan {
            version,
            command: ProxyCommand::Proxy,
            family: ProxyAddressFamily::Auto,
            source: None,
            destination: None,
            tlvs: vec![],
            raw: vec![],
        }
    }

    // Vectors from Ferrum Edge v0.9.7 tests/unit/gateway_core/proxy_protocol_tests.rs.

    #[test]
    fn v1_tcp4_matches_the_gateway_test_vector() {
        // `v1_tcp4_happy_path`: b"PROXY TCP4 192.168.1.50 192.168.1.1 12345 80\r\n"
        let mut p = plan(ProxyHeaderVersion::V1);
        p.source = Some(sa("192.168.1.50:12345"));
        p.destination = Some(sa("192.168.1.1:80"));
        let h = p.build(None, None, None).unwrap();
        assert_eq!(h.bytes, b"PROXY TCP4 192.168.1.50 192.168.1.1 12345 80\r\n");
        assert_eq!(h.observation.length, 46);
        assert_eq!(h.observation.text.as_deref(), Some("PROXY TCP4 192.168.1.50 192.168.1.1 12345 80"));
        assert_eq!(h.observation.source_origin, Some(AddressOrigin::Configured));
    }

    #[test]
    fn v1_tcp6_and_unknown_match_the_gateway_test_vectors() {
        // `v1_tcp6_happy_path`: b"PROXY TCP6 2001:db8::1 2001:db8::2 50000 443\r\n"
        let mut p = plan(ProxyHeaderVersion::V1);
        p.source = Some(sa("[2001:db8::1]:50000"));
        p.destination = Some(sa("[2001:db8::2]:443"));
        assert_eq!(p.build(None, None, None).unwrap().bytes, b"PROXY TCP6 2001:db8::1 2001:db8::2 50000 443\r\n");
        // `v1_unknown_without_extra_fields`: b"PROXY UNKNOWN\r\n"
        let mut u = plan(ProxyHeaderVersion::V1);
        u.family = ProxyAddressFamily::Unspec;
        assert_eq!(u.build(None, None, None).unwrap().bytes, b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn v1_defaults_to_the_real_socket_addresses_and_refuses_what_v1_cannot_say() {
        let p = plan(ProxyHeaderVersion::V1);
        let h = p.build(Some(sa("127.0.0.1:50123")), Some(sa("127.0.0.1:18901")), None).unwrap();
        assert_eq!(h.bytes, b"PROXY TCP4 127.0.0.1 127.0.0.1 50123 18901\r\n");
        assert_eq!(h.observation.source_origin, Some(AddressOrigin::Socket));
        let mut mixed = plan(ProxyHeaderVersion::V1);
        mixed.source = Some(sa("[2001:db8::1]:1"));
        assert!(mixed.build(None, Some(sa("10.0.0.1:2")), None).is_err());
        let mut local = plan(ProxyHeaderVersion::V1);
        local.command = ProxyCommand::Local;
        assert!(local.build(Some(sa("127.0.0.1:1")), Some(sa("127.0.0.1:2")), None).is_err());
        assert!(plan(ProxyHeaderVersion::V1).build(None, None, None).is_err(), "no address known: a typed refusal");
    }

    #[test]
    fn v2_tcp4_matches_the_gateway_test_builder() {
        // `v2_header_tcp4([10,0,0,1], [10,0,0,2], 9000, 5432)`: signature, 0x21, 0x11, len 12, addresses.
        let mut p = plan(ProxyHeaderVersion::V2);
        p.source = Some(sa("10.0.0.1:9000"));
        p.destination = Some(sa("10.0.0.2:5432"));
        let h = p.build(None, None, None).unwrap();
        let mut want = b"\r\n\r\n\x00\r\nQUIT\n".to_vec();
        want.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c, 10, 0, 0, 1, 10, 0, 0, 2, 0x23, 0x28, 0x15, 0x38]);
        assert_eq!(h.bytes, want);
        assert_eq!(h.bytes.len(), 28, "Ferrum `encode_v2_ipv4_round_trips_through_parser`: 28 bytes");
        assert_eq!(h.observation.hex, hex::encode(&want));
        assert_eq!(h.observation.family, "AF_INET");
    }

    #[test]
    fn v2_tcp6_local_and_unspec_match_the_gateway_test_builders() {
        // `v2_header_tcp6(::1, ::2, 1234, 5678)`: 0x21, 0x21, len 36.
        let mut p = plan(ProxyHeaderVersion::V2);
        p.source = Some(sa("[::1]:1234"));
        p.destination = Some(sa("[::2]:5678"));
        let b = p.build(None, None, None).unwrap().bytes;
        assert_eq!(&b[12..16], &[0x21, 0x21, 0x00, 0x24]);
        assert_eq!(b[16 + 15], 1);
        assert_eq!(b[32 + 15], 2);
        assert_eq!(&b[48..52], &[0x04, 0xd2, 0x16, 0x2e]);
        assert_eq!(b.len(), 52);
        // `v2_local_command`: 0x20, 0x00, len 0.
        let mut l = plan(ProxyHeaderVersion::V2);
        l.command = ProxyCommand::Local;
        assert_eq!(&l.build(None, None, None).unwrap().bytes[12..], &[0x20, 0x00, 0x00, 0x00]);
        // `v2_unspec_af_returns_no_address`: 0x21, 0x00, len 0.
        let mut u = plan(ProxyHeaderVersion::V2);
        u.family = ProxyAddressFamily::Unspec;
        assert_eq!(&u.build(None, None, None).unwrap().bytes[12..], &[0x21, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn v2_mixed_families_promote_ipv4_to_mapped_like_the_gateway_encoder() {
        // `encode_v2_mixed_family_promotes_to_ipv6_mapped`.
        let mut p = plan(ProxyHeaderVersion::V2);
        p.source = Some(sa("[2001:db8::1]:1000"));
        p.destination = Some(sa("192.168.1.1:5432"));
        let b = p.build(None, None, None).unwrap().bytes;
        assert_eq!(b[13], 0x21);
        assert_eq!(&b[32..48], &"::ffff:192.168.1.1".parse::<Ipv6Addr>().unwrap().octets());
        // A mapped IPv4 pair folds back to AF_INET.
        let mut m = plan(ProxyHeaderVersion::V2);
        m.source = Some(sa("[::ffff:10.0.0.1]:1"));
        m.destination = Some(sa("[::ffff:10.0.0.2]:2"));
        assert_eq!(m.build(None, None, None).unwrap().bytes[13], 0x11);
    }

    #[test]
    fn v2_tlvs_follow_the_address_block() {
        let mut p = plan(ProxyHeaderVersion::V2);
        p.source = Some(sa("10.0.0.1:1"));
        p.destination = Some(sa("10.0.0.2:2"));
        p.tlvs = vec![(PP2_TYPE_AUTHORITY, b"api.example".to_vec())];
        let h = p.build(None, None, None).unwrap();
        assert_eq!(u16::from_be_bytes([h.bytes[14], h.bytes[15]]), 12 + 3 + 11);
        assert_eq!(&h.bytes[28..31], &[0x02, 0x00, 0x0b]);
        assert_eq!(&h.bytes[31..], b"api.example");
        assert_eq!(h.observation.tlvs, vec!["0x02 authority \"api.example\"".to_string()]);
        assert!(matches!(check_stream_header(&h.bytes), Ok(StreamHeader::Forwarded { header_len: 42, .. })));
    }

    #[test]
    fn raw_headers_are_checked_like_the_gateway_parser() {
        let cases: &[(&[u8], bool)] = &[
            (b"PROXY TCP4 192.168.1.50 192.168.1.1 12345 80\r\n", true),
            (b"PROXY UNKNOWN some garbage here\r\n", true),
            (b"PROXY UDP4 1.2.3.4 5.6.7.8 100 200\r\n", false),
            (b"PROXY TCP4 not-an-ip 5.6.7.8 100 200\r\n", false),
            (b"PROXY TCP4 1.2.3.4 5.6.7.8 not-a-port 200\r\n", false),
            (b"PROXY TCP4 2001:db8::1 5.6.7.8 100 200\r\n", false),
            (b"PROXY TCP4 1.2.3.4 5.6.7.8 100\r\n", false),
            (b"HTTP/1.1 200 OK\r\n", false),
            (b"\r\n\r\n\x00\r\nQUIT\n\x11\x11\x00\x00", false),
            (b"\r\n\r\n\x00\r\nQUIT\n\x21\x11\x02\x01", false),
            (b"\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\x01", false),
            (b"\r\n\r\n\x00\r\nQUIT\n\x21\x31\x00\x00", true),
        ];
        for (bytes, ok) in cases {
            let mut p = plan(ProxyHeaderVersion::Raw);
            p.raw = bytes.to_vec();
            let h = p.build(None, None, None).unwrap();
            assert_eq!(h.observation.well_formed, *ok, "{:?}: {:?}", String::from_utf8_lossy(bytes), h.observation.problem);
            assert_eq!(h.bytes, *bytes, "raw bytes are sent verbatim");
        }
        let mut long = String::from("PROXY UNKNOWN ");
        while long.len() < 107 {
            long.push('x');
        }
        assert!(check_stream_header(format!("{long}\r\n").as_bytes()).is_ok(), "`v1_exact_max_length_accepted`");
        assert!(check_stream_header(format!("{long}x\r\n").as_bytes()).is_err(), "`v1_too_long_rejected`");
    }

    #[test]
    fn header_evidence_is_scrubbed_when_it_carries_a_secret() {
        let mut p = plan(ProxyHeaderVersion::V2);
        p.source = Some(sa("10.0.0.1:1"));
        p.destination = Some(sa("10.0.0.2:2"));
        p.tlvs = vec![(PP2_TYPE_AUTHORITY, b"tok-sekret".to_vec())];
        let r = |s: &str| s.replace("tok-sekret", REDACTED);
        let h = p.build(None, None, Some(&r)).unwrap();
        assert_eq!(h.observation.hex, REDACTED);
        assert!(!format!("{:?}", h.observation).contains("sekret"));
        assert!(h.bytes.ends_with(b"tok-sekret"), "the wire still carries the configured value");
        // An address that is itself a redacted value is encoded in binary in
        // v2; the text field and the hex are both replaced.
        let mut a = plan(ProxyHeaderVersion::V2);
        a.source = Some(sa("198.51.100.77:7"));
        let r2 = |s: &str| s.replace("198.51.100.77", REDACTED);
        let h2 = a.build(None, Some(sa("10.0.0.2:2")), Some(&r2)).unwrap();
        assert_eq!(h2.observation.source.as_deref(), Some(REDACTED));
        assert_eq!(h2.observation.hex, REDACTED);
    }

    // Datagram envelope: Ferrum tests/unit/gateway_core/datagram_client_address_tests.rs
    // fixtures (SECRET, 10.0.0.5:5353 UDP binding, 203.0.113.9:41234 source).
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn binding() -> ListenerBinding {
        ListenerBinding::new(DatagramListenerProtocol::Udp, "10.0.0.5".parse().unwrap(), 5353)
    }

    fn v4_form() -> EnvelopeForm {
        EnvelopeForm::Forwarded { source: sa("203.0.113.9:41234"), destination: sa("10.0.0.5:5353") }
    }

    #[test]
    fn canonical_domain_is_the_gateway_binding_serialization() {
        let d = binding().canonical_domain();
        let mut want = b"ferrum-datagram-proxy-v1".to_vec();
        want.extend_from_slice(&[0x01, 0x01, 0x04, 10, 0, 0, 5, 0x14, 0xe9]);
        assert_eq!(d, want);
        let dtls = ListenerBinding::new(DatagramListenerProtocol::Dtls, "::".parse().unwrap(), 5353).canonical_domain();
        assert_eq!(&dtls[24..27], &[0x01, 0x02, 0x06]);
        assert_eq!(dtls.len(), 24 + 3 + 16 + 2);
        // `canonical_listener_identity_folds_ipv4_mapped_bind_addresses`.
        let mapped = ListenerBinding::new(DatagramListenerProtocol::Udp, "::ffff:10.0.0.5".parse().unwrap(), 5353);
        assert_eq!(mapped.canonical_domain(), d);
    }

    #[test]
    fn unauthenticated_forms_match_the_gateway_encoder() {
        let (d, tag) = encode_datagram(v4_form(), b"payload", None);
        assert!(tag.is_none());
        let mut want = b"\r\n\r\n\x00\r\nQUIT\n".to_vec();
        want.extend_from_slice(&[0x21, 0x12, 0x00, 0x0c, 203, 0, 113, 9, 10, 0, 0, 5, 0xa1, 0x12, 0x14, 0xe9]);
        want.extend_from_slice(b"payload");
        assert_eq!(d, want);
        assert_eq!(&encode_datagram(EnvelopeForm::Local, b"p", None).0[12..], &[0x20, 0x00, 0x00, 0x00, b'p']);
        assert_eq!(&encode_datagram(EnvelopeForm::Unspec, b"p", None).0[12..], &[0x21, 0x02, 0x00, 0x00, b'p']);
        let v6 = EnvelopeForm::Forwarded { source: sa("[2001:db8::10]:41234"), destination: sa("[2001:db8::1]:5353") };
        let d6 = encode_datagram(v6, b"", None).0;
        assert_eq!(&d6[12..16], &[0x21, 0x22, 0x00, 0x24]);
        assert_eq!(d6.len(), 16 + 36);
    }

    #[test]
    fn authenticated_layout_is_the_documented_one() {
        // `authenticated_envelope_layout_is_the_documented_one` (sender 41, epoch 7, sequence 3).
        let b = binding();
        let key = EnvelopeKey {
            secret: SECRET,
            binding: &b,
            freshness: Freshness { sender_id: 41, epoch: 7, sequence: 3, timestamp_ms: 1_760_000_000_000 },
        };
        let (d, tag) = encode_datagram(v4_form(), b"payload", Some(&key));
        assert_eq!(&d[12..14], &[0x21, 0x12]);
        let addr_len = u16::from_be_bytes([d[14], d[15]]) as usize;
        assert_eq!(addr_len, 12 + 32 + 3 + 32);
        assert_eq!(&d[28..31], &[0xE1, 0x00, 0x1d]);
        let v = &d[31..60];
        assert_eq!(v[0], 1);
        assert_eq!(u32::from_be_bytes(v[1..5].try_into().unwrap()), 41);
        assert_eq!(u64::from_be_bytes(v[5..13].try_into().unwrap()), 7);
        assert_eq!(u64::from_be_bytes(v[13..21].try_into().unwrap()), 3);
        assert_eq!(u64::from_be_bytes(v[21..29].try_into().unwrap()), 1_760_000_000_000);
        assert_eq!(&d[60..63], &[0xE0, 0x00, 0x20]);
        assert_eq!(tag, Some(63));
        assert_eq!(16 + addr_len, 63 + 32, "payload starts right after the tag");
        assert_eq!(&d[16 + addr_len..], b"payload");
    }

    /// Pinned vector computed independently (Python `hmac`/`hashlib`) from the
    /// gateway's MAC definition: HMAC-SHA-256(secret, domain || datagram with
    /// the 32 tag bytes elided).
    #[test]
    fn authentication_tag_matches_an_independent_computation() {
        let b = binding();
        let key = EnvelopeKey {
            secret: SECRET,
            binding: &b,
            freshness: Freshness { sender_id: 41, epoch: 7, sequence: 3, timestamp_ms: 1_760_000_000_000 },
        };
        let (d, tag) = encode_datagram(v4_form(), b"payload", Some(&key));
        let at = tag.unwrap();
        assert_eq!(hex::encode(&d[at..at + 32]), PINNED_TAG);
        // The tag binds the listener: another port or protocol changes it.
        let other = ListenerBinding::new(DatagramListenerProtocol::Dtls, "10.0.0.5".parse().unwrap(), 5353);
        let k2 = EnvelopeKey { binding: &other, ..key };
        assert_ne!(encode_datagram(v4_form(), b"payload", Some(&k2)).0, d);
    }

    const PINNED_TAG: &str = "af2b6d532adc0876f41f0e40477df0e80fd976be4434bd6a75423c36392466a3";

    #[test]
    fn enveloper_counts_sequences_and_never_records_the_secret_or_tag() {
        let plan = EnvelopePlan {
            command: ProxyCommand::Proxy,
            family: ProxyAddressFamily::Auto,
            source: None,
            destination: None,
            auth: Some(EnvelopeAuthPlan {
                secret: Zeroizing::new(SECRET.to_vec()),
                protocol: DatagramListenerProtocol::Udp,
                bind_addr: "0.0.0.0".parse().unwrap(),
                port: None,
                sender_id: 9,
                epoch: Some(5),
                first_sequence: 10,
                timestamp_offset_ms: 0,
            }),
        };
        let mut e = plan.start(Some(sa("127.0.0.1:40000")), Some(sa("127.0.0.1:18911"))).unwrap();
        let a = e.wrap(b"a");
        let b = e.wrap(b"b");
        let seq = |d: &[u8]| u64::from_be_bytes(d[28 + 3 + 13..28 + 3 + 21].try_into().unwrap());
        assert_eq!((seq(&a), seq(&b)), (10, 11));
        let o = e.observation();
        assert_eq!((o.first_sequence, o.last_sequence, o.datagrams), (Some(10), Some(11), 2));
        assert_eq!(o.listener_binding.as_deref(), Some("udp 0.0.0.0:18911"));
        let tag = hex::encode(&a[63..95]);
        let dump = format!("{o:?} {}", e.summary());
        assert!(!dump.contains(&tag) && !dump.contains("0123456789abcdef"), "{dump}");
        assert!(o.hex.ends_with(TAG_MARK));
        let short = EnvelopePlan {
            auth: plan.auth.clone().map(|mut a| {
                a.secret = Zeroizing::new(b"short".to_vec());
                a
            }),
            ..plan.clone()
        };
        assert!(short.start(Some(sa("127.0.0.1:1")), Some(sa("127.0.0.1:2"))).is_err());
    }
}
