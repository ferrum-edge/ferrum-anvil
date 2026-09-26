//! Client-side PROXY protocol: the HAProxy PROXY v1/v2 connection header a
//! load balancer writes at the head of a TCP connection, and the PROXY v2
//! `DGRAM` envelope it prepends to every UDP datagram.
//!
//! Anvil plays the load balancer so a stream listener that requires the
//! header (Ferrum Edge `stream_proxy_protocol: true`) can be tested. The
//! header is written after TCP connect and before any TLS; the datagram
//! envelope wraps every datagram, including DTLS handshake records.
//!
//! Byte formats follow Ferrum Edge `src/proxy/proxy_protocol.rs` (TCP) and
//! `src/proxy/datagram_client_address.rs` (UDP/DTLS, optional HMAC-SHA-256
//! tag TLV `0xE0` and freshness TLV `0xE1` bound to the receiving listener).

use crate::secret::SensitiveValue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Which connection header Anvil writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyHeaderVersion {
    /// Text header: `PROXY TCP4|TCP6|UNKNOWN … \r\n`.
    V1,
    /// Binary header (12-byte signature, command, family/transport, address block, TLVs).
    #[default]
    V2,
    /// The exact bytes of `raw_hex`, for deliberately malformed headers. Anvil
    /// still checks them against the specification and records the result.
    Raw,
}

/// PROXY v2 command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyCommand {
    /// A relayed connection: the address block names the original client.
    #[default]
    Proxy,
    /// The balancer speaking for itself (health checks): no addresses are
    /// sent and the receiver keeps the socket peer as the client.
    Local,
}

/// Address family of the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAddressFamily {
    /// IPv4 or IPv6 from the addresses (`TCP4`/`TCP6`, `AF_INET`/`AF_INET6`).
    #[default]
    Auto,
    /// No addresses: v1 `UNKNOWN`, v2 `AF_UNSPEC`. The receiver keeps the socket peer.
    Unspec,
}

/// One PROXY v2 TLV (type-length-value) after the address block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProxyTlv {
    /// TLV type code (for example `0x02` authority, `0x05` unique id).
    pub tlv_type: u8,
    /// Value bytes as hex.
    pub value_hex: String,
}

/// PROXY protocol connection header for a TCP / TCP+TLS session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProxyHeaderSpec {
    #[serde(default)]
    pub version: ProxyHeaderVersion,
    /// v2 only (v1 has no LOCAL command).
    #[serde(default)]
    pub command: ProxyCommand,
    #[serde(default)]
    pub family: ProxyAddressFamily,
    /// Declared source `ip:port` (the "original client"). Default: the real
    /// local socket address of this connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Declared destination `ip:port`. Default: the real remote socket address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// v2 `PP2_TYPE_AUTHORITY` (0x02) TLV, e.g. the SNI host name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// Further v2 TLVs, written in order after `authority`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tlvs: Vec<ProxyTlv>,
    /// `version: raw` only: the exact header bytes as hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_hex: Option<String>,
}

/// The receive boundary a datagram listener authenticates envelopes at. Part
/// of the listener identity bound into every authentication tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DatagramListenerProtocol {
    /// Plain UDP receive boundary (a `udp` listener, or DTLS passthrough).
    Udp,
    /// A listener that terminates DTLS (`frontend_tls: true`).
    Dtls,
}

/// Authentication and freshness for the PROXY v2 `DGRAM` envelope.
///
/// The tag is HMAC-SHA-256 keyed with the shared secret over the receiving
/// listener's canonical identity plus the whole datagram (tag elided). The
/// listener identity is **(receive protocol, bind address, port)** exactly as
/// the gateway bound it: a wildcard bind (`0.0.0.0`, `::`) and a specific
/// address are different identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DatagramAuthSpec {
    /// Shared secret (`FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`, at least 32
    /// bytes, used verbatim). Never recorded.
    pub secret: SensitiveValue,
    /// Default: `dtls` when Anvil speaks DTLS, otherwise `udp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_protocol: Option<DatagramListenerProtocol>,
    /// The listener's bind address (Ferrum: `FERRUM_STREAM_PROXY_BIND_ADDRESS`, default `0.0.0.0`).
    #[serde(default = "default_bind_address")]
    pub listener_bind_address: String,
    /// The listener's port. Default: the destination port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_port: Option<u16>,
    /// Stable sender id (the balancer's own identity).
    #[serde(default)]
    pub sender_id: u32,
    /// Sender epoch. Default: Unix milliseconds when the run starts, so every
    /// run is a new epoch. Pin it to replay a sequence on purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// Sequence of the first datagram; each further datagram adds one.
    #[serde(default)]
    pub first_sequence: u64,
    /// Added to the send-time timestamp (negative = in the past), to test the
    /// receiver's freshness horizon.
    #[serde(default)]
    pub timestamp_offset_ms: i64,
}

fn default_bind_address() -> String {
    "0.0.0.0".into()
}

/// PROXY v2 `DGRAM` envelope prepended to every UDP/DTLS datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DatagramEnvelopeSpec {
    #[serde(default)]
    pub command: ProxyCommand,
    #[serde(default)]
    pub family: ProxyAddressFamily,
    /// Declared source `ip:port`. Default: the real local socket address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Declared destination `ip:port`. Default: the real remote socket address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Authenticated envelope (tag + freshness). `None` = the unauthenticated
    /// address-trust posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<DatagramAuthSpec>,
}

// ------------------------------------------------------------- evidence ---

/// Which framing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyHeaderFormat {
    V1,
    V2,
    /// User-supplied bytes.
    Raw,
    /// PROXY v2 `DGRAM` envelope on every datagram.
    V2Datagram,
}

/// Where a declared address came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressOrigin {
    /// The real socket address of this connection.
    Socket,
    /// Set explicitly in the request.
    Configured,
}

/// Exactly what PROXY protocol framing Anvil sent. Secrets never appear: the
/// authentication tag bytes are elided from `hex`, and any header bytes that
/// contain a redacted value are replaced as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProxyHeaderObservation {
    pub format: ProxyHeaderFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<ProxyCommand>,
    /// `TCP4`, `TCP6`, `UNKNOWN`, `AF_INET`, `AF_INET6`, `AF_UNSPEC`, or `unparsed`.
    pub family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_origin: Option<AddressOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_origin: Option<AddressOrigin>,
    /// Header length in bytes (for envelopes: of the first datagram's envelope).
    pub length: u32,
    /// The header bytes as hex (for envelopes: the first datagram's envelope
    /// with the 32 tag bytes replaced by `‹tag›`).
    pub hex: String,
    /// The v1 line without CRLF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// TLVs after the address block, summarized.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tlvs: Vec<String>,
    /// The bytes satisfy the PROXY protocol specification as Anvil checks it.
    pub well_formed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    // ---- datagram envelope ----
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authenticated: bool,
    /// `udp|dtls <bind address>:<port>` the tags were bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<u64>,
    /// Datagrams sent with the envelope (handshake records included for DTLS).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub datagrams: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}
