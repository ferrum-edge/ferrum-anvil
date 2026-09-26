//! Preparation of PROXY protocol framing for TCP/TLS sessions and the
//! connections of HTTP-family requests (connection header), and for UDP/DTLS
//! sessions (per-datagram v2 `DGRAM` envelope).
//!
//! Everything that can be decided locally is decided here, before any
//! traffic: address syntax, v1 limits, TLV encoding, the forward-proxy case
//! (where the real socket addresses describe the proxy hop, not the stream),
//! the listener identity an authenticated envelope is bound to, and the
//! secret's minimum length. The secret comes from the vault (or a
//! `{{variable}}`), is used verbatim, is registered with the redactor, and is
//! never recorded.

use crate::context::{ExecutionContext, resolve_sensitive};
use crate::redact::Redactor;
use crate::vars::Resolver;
use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_domain::proxy_protocol::*;
use anvil_domain::request::{Protocol, WsBootstrap};
use anvil_domain::settings::{EffectiveSettings, HttpVersionPolicy};
use anvil_domain::tls::ProxyKind;
use anvil_transport::connector::ProxyPlan;
use anvil_transport::proxy_protocol::{EnvelopeAuthPlan, EnvelopePlan, HeaderPlan, MIN_DATAGRAM_SECRET_BYTES, PP2_TYPE_AUTHORITY};
use std::net::{IpAddr, SocketAddr};
use zeroize::Zeroizing;

fn invalid(msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, FailureKind::BodySerialization, msg).with_field(field)
}

fn unsupported(msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, FailureKind::UnsupportedCombination, msg).with_field(field)
}

fn addr(r: &Resolver, v: &Option<String>, field: &str) -> Result<Option<SocketAddr>, TransportFailure> {
    let Some(raw) = v else { return Ok(None) };
    let text = r.resolve(raw, field)?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse::<SocketAddr>()
        .map(Some)
        .map_err(|_| invalid(format!("'{text}' is not an address:port (use 203.0.113.7:4242 or [2001:db8::7]:4242)"), field))
}

fn hex_bytes(r: &Resolver, raw: &str, field: &str) -> Result<Vec<u8>, TransportFailure> {
    let text = r.resolve(raw, field)?;
    anvil_transport::session::decode_hex(&text).map_err(|e| invalid(e, field))
}

/// Resolve a connection-header spec configured at `field` (`tcp.proxy_protocol`
/// or `proxy_protocol`). `proxied`: the session goes through a forward proxy,
/// so the socket addresses are not the stream's.
pub(crate) fn header_plan(spec: &ProxyHeaderSpec, r: &Resolver, proxied: bool, field: &str) -> Result<HeaderPlan, TransportFailure> {
    let source = addr(r, &spec.source, &format!("{field}.source"))?;
    let destination = addr(r, &spec.destination, &format!("{field}.destination"))?;
    let mut tlvs = Vec::new();
    if let Some(a) = &spec.authority {
        let a = r.resolve(a, &format!("{field}.authority"))?;
        if !a.is_empty() {
            tlvs.push((PP2_TYPE_AUTHORITY, a.into_bytes()));
        }
    }
    for (i, t) in spec.tlvs.iter().enumerate() {
        tlvs.push((t.tlv_type, hex_bytes(r, &t.value_hex, &format!("{field}.tlvs[{i}].value_hex"))?));
    }
    let raw = match spec.version {
        ProxyHeaderVersion::Raw => {
            let raw = spec.raw_hex.as_deref().unwrap_or_default();
            let bytes = hex_bytes(r, raw, &format!("{field}.raw_hex"))?;
            if bytes.is_empty() {
                return Err(invalid("a raw PROXY header needs its bytes (raw_hex)", &format!("{field}.raw_hex")));
            }
            bytes
        }
        _ => vec![],
    };
    let addressed = spec.version != ProxyHeaderVersion::Raw
        && spec.family == ProxyAddressFamily::Auto
        && (spec.version == ProxyHeaderVersion::V1 || spec.command == ProxyCommand::Proxy);
    if spec.version == ProxyHeaderVersion::V1 {
        if spec.command == ProxyCommand::Local {
            return Err(unsupported("PROXY v1 has no LOCAL command; use v2, or v1 with the unknown family", &format!("{field}.command")));
        }
        if !tlvs.is_empty() {
            return Err(unsupported("TLVs exist only in PROXY v2", &format!("{field}.tlvs")));
        }
        if let (Some(s), Some(d)) = (source, destination) {
            let (s, d) = (anvil_transport::proxy_protocol::canonical_ip(s.ip()), anvil_transport::proxy_protocol::canonical_ip(d.ip()));
            if s.is_ipv4() != d.is_ipv4() {
                return Err(unsupported("PROXY v1 needs the source and destination in one address family", &format!("{field}.source")));
            }
        }
    }
    if addressed && proxied && (source.is_none() || destination.is_none()) {
        return Err(unsupported(
            "through a forward proxy the real socket addresses belong to the proxy hop; set the PROXY header source and destination explicitly",
            &format!("{field}.source"),
        ));
    }
    let plan = HeaderPlan { version: spec.version, command: spec.command, family: spec.family, source, destination, tlvs, raw };
    // Encode once with stand-in socket addresses (of the configured family)
    // to surface local limits (v1 line length, TLV sizes) before any traffic.
    let stand_in = source.or(destination).unwrap_or(SocketAddr::from(([127, 0, 0, 1], 65535)));
    if let Err(e) = plan.build(Some(stand_in), Some(stand_in), None) {
        return Err(invalid(e, field));
    }
    Ok(plan)
}

/// The PROXY header of an HTTP-family request (`RequestSpec::proxy_protocol`),
/// resolved with every refusal decided before traffic:
/// * raw TCP and UDP have their own settings (`tcp.proxy_protocol`,
///   `udp.proxy_protocol`), so the request-level one is refused there;
/// * HTTP/3 (QUIC, including WebSocket over HTTP/3 and both HTTP/3 policies)
///   has no standard carriage for a PROXY header;
/// * through a forward proxy the header would reach the proxy (plain HTTP
///   proxying) or describe the proxy hop (a CONNECT or SOCKS5 tunnel), and
///   an HBONE relay never reads it.
pub(crate) fn request_header(
    spec: &anvil_domain::request::RequestSpec,
    r: &Resolver,
    settings: &EffectiveSettings,
    proxy: Option<&ProxyPlan>,
) -> Result<Option<HeaderPlan>, TransportFailure> {
    const F: &str = "proxy_protocol";
    let Some(h) = &spec.proxy_protocol else { return Ok(None) };
    match spec.protocol {
        Protocol::Tcp => {
            return Err(unsupported(
                "the request-level PROXY header is for HTTP-family requests; a raw TCP session configures its header in the TCP settings (tcp.proxy_protocol)",
                F,
            ));
        }
        Protocol::Udp => {
            return Err(unsupported(
                "a PROXY connection header is TCP-borne; UDP and DTLS use the PROXY v2 datagram envelope in the UDP settings (udp.proxy_protocol)",
                F,
            ));
        }
        _ => {}
    }
    let quic = match spec.protocol {
        Protocol::WebSocket => spec.websocket.as_ref().map(|w| w.bootstrap == WsBootstrap::Http3ExtendedConnect).unwrap_or(false),
        _ => matches!(settings.http_version, HttpVersionPolicy::Http3Only | HttpVersionPolicy::Http3WithFallback),
    };
    if quic {
        return Err(unsupported(
            "a PROXY protocol header cannot be sent over HTTP/3: QUIC has no standard carriage for it. Choose a TCP HTTP version (HTTP/1.1, HTTP/2 or h2c) or turn the header off; nothing was sent",
            F,
        ));
    }
    if let Some(p) = proxy {
        let why = match p.kind {
            ProxyKind::Hbone => "mesh relays carry the peer's identity instead and never read a PROXY header".to_string(),
            ProxyKind::Http | ProxyKind::Https => format!(
                "the header would be written to the proxy '{}' (or describe its tunnel hop) instead of reaching the destination's listener as its first bytes",
                p.label
            ),
            ProxyKind::Socks5 => {
                format!("the header would describe the SOCKS5 hop through '{}', not a connection to the destination's listener", p.label)
            }
        };
        return Err(unsupported(format!("a PROXY protocol header cannot be sent through a proxy: {why}; nothing was sent"), F));
    }
    header_plan(h, r, false, F).map(Some)
}

/// Resolve a datagram-envelope spec. `dtls`: Anvil speaks DTLS to the target.
pub(crate) fn envelope_plan(
    spec: &DatagramEnvelopeSpec,
    ctx: &ExecutionContext,
    r: &Resolver,
    redactor: &mut Redactor,
    dtls: bool,
) -> Result<EnvelopePlan, TransportFailure> {
    const F: &str = "udp.proxy_protocol";
    let source = addr(r, &spec.source, &format!("{F}.source"))?;
    let destination = addr(r, &spec.destination, &format!("{F}.destination"))?;
    if let Some(s) = source
        && s.ip().is_unspecified()
    {
        return Err(invalid("the envelope source address is unspecified", &format!("{F}.source")));
    }
    let auth = match &spec.authentication {
        None => None,
        Some(a) => {
            let field = format!("{F}.authentication.secret");
            let (raw, _) = resolve_sensitive(&a.secret, ctx.secrets.as_ref())
                .map_err(|e| invalid(format!("the datagram secret is not available: {e}"), &field))?;
            let secret = Zeroizing::new(r.resolve(&raw, &field)?);
            // Used verbatim (never trimmed), like the gateway. Never report the
            // value or its length.
            if secret.is_empty() {
                return Err(invalid("the datagram authentication secret is empty", &field));
            }
            redactor.add_secret(&secret);
            if secret.len() < MIN_DATAGRAM_SECRET_BYTES {
                return Err(invalid(
                    format!(
                        "the datagram authentication secret is shorter than {MIN_DATAGRAM_SECRET_BYTES} bytes; Ferrum Edge refuses such secrets at startup, so no listener can verify it"
                    ),
                    &field,
                ));
            }
            let bind_field = format!("{F}.authentication.listener_bind_address");
            let bind_text = r.resolve(&a.listener_bind_address, &bind_field)?;
            let bind_addr: IpAddr = bind_text.trim().trim_start_matches('[').trim_end_matches(']').parse().map_err(|_| {
                invalid(format!("'{}' is not an IP address (the listener's bind address, e.g. 0.0.0.0)", bind_text.trim()), &bind_field)
            })?;
            let protocol = a.listener_protocol.unwrap_or(if dtls { DatagramListenerProtocol::Dtls } else { DatagramListenerProtocol::Udp });
            Some(EnvelopeAuthPlan {
                secret: Zeroizing::new(secret.as_bytes().to_vec()),
                protocol,
                bind_addr,
                port: a.listener_port.or(destination.map(|d| d.port())),
                sender_id: a.sender_id,
                epoch: a.epoch,
                first_sequence: a.first_sequence,
                timestamp_offset_ms: a.timestamp_offset_ms,
            })
        }
    };
    Ok(EnvelopePlan { command: spec.command, family: spec.family, source, destination, auth })
}

/// Inspector note describing the prepared connection header.
pub(crate) fn header_note(spec: &ProxyHeaderSpec) -> String {
    header_note_for(spec, "written after connect and before TLS")
}

/// Inspector note for the header of an HTTP-family request.
pub(crate) fn request_header_note(spec: &ProxyHeaderSpec, listener: &str) -> String {
    header_note_for(
        spec,
        &format!(
            "written once on every new connection to {listener}, after connect and before TLS; a reused connection keeps the header it was opened with, and redirects to another host or port are sent without it"
        ),
    )
}

fn header_note_for(spec: &ProxyHeaderSpec, when: &str) -> String {
    let v = match spec.version {
        ProxyHeaderVersion::V1 => "v1",
        ProxyHeaderVersion::V2 => "v2",
        ProxyHeaderVersion::Raw => "raw bytes",
    };
    let who = match (spec.version, spec.command, spec.family) {
        (ProxyHeaderVersion::Raw, _, _) => "as given".to_string(),
        (ProxyHeaderVersion::V2, ProxyCommand::Local, _) => "LOCAL (no addresses)".to_string(),
        (_, _, ProxyAddressFamily::Unspec) => "without addresses (UNKNOWN / AF_UNSPEC)".to_string(),
        _ => format!(
            "source {}, destination {}",
            spec.source.as_deref().unwrap_or("= this connection's local address"),
            spec.destination.as_deref().unwrap_or("= this connection's remote address")
        ),
    };
    format!("PROXY protocol {v} header {when}: {who}")
}

/// Inspector note describing the prepared datagram envelope.
pub(crate) fn envelope_note(plan: &EnvelopePlan) -> String {
    let auth = match &plan.auth {
        Some(a) => {
            let port = a.port.map(|p| p.to_string()).unwrap_or_else(|| "<destination port>".into());
            let p = match a.protocol {
                DatagramListenerProtocol::Udp => "udp",
                DatagramListenerProtocol::Dtls => "dtls",
            };
            format!("authenticated (HMAC-SHA-256 tag + freshness) for listener {p} {}:{port}, sender {}", a.bind_addr, a.sender_id)
        }
        None => "unauthenticated (address-trust posture)".into(),
    };
    format!("PROXY v2 DGRAM envelope on every datagram, {auth}")
}
