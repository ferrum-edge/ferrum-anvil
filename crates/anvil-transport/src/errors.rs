//! Typed classification of library errors into [`FailureKind`].
//!
//! Classification walks the error source chain and matches on *types*
//! (`io::ErrorKind`, `rustls::Error`, `h2::Reason`, hyper predicates). It
//! never infers a phase from message text such as "handshake".

use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use std::error::Error as StdError;
use std::io;

/// Iterate an error and its sources, also descending into `io::Error`'s
/// wrapped inner error (which `io::Error::source` skips).
pub fn chain<'a>(err: &'a (dyn StdError + 'static)) -> Vec<&'a (dyn StdError + 'static)> {
    let mut out: Vec<&'a (dyn StdError + 'static)> = Vec::new();
    let mut stack: Vec<&'a (dyn StdError + 'static)> = vec![err];
    while let Some(e) = stack.pop() {
        if out.len() > 32 {
            break;
        }
        out.push(e);
        if let Some(ioe) = e.downcast_ref::<io::Error>()
            && let Some(inner) = ioe.get_ref()
        {
            stack.push(inner);
            continue;
        }
        // h2 wraps connection I/O errors (including TLS alerts delivered
        // after the handshake) without exposing them through `source()`.
        if let Some(h2e) = e.downcast_ref::<h2::Error>()
            && let Some(ioe) = h2e.get_io()
        {
            stack.push(ioe);
            continue;
        }
        if let Some(src) = e.source() {
            stack.push(src);
        }
    }
    out
}

pub fn find<'a, T: StdError + 'static>(err: &'a (dyn StdError + 'static)) -> Option<&'a T> {
    chain(err).into_iter().find_map(|e| e.downcast_ref::<T>())
}

/// Sanitized display text for an error chain (display only; never used for rules).
pub fn display_chain(err: &(dyn StdError + 'static)) -> String {
    let mut parts: Vec<String> = Vec::new();
    for e in chain(err) {
        let s = e.to_string();
        if !s.is_empty() && !parts.iter().any(|p| p.contains(&s)) {
            parts.push(s);
        }
    }
    let joined = parts.join(": ");
    if joined.len() > 600 { format!("{}…", &joined[..600]) } else { joined }
}

pub fn io_kind_name(k: io::ErrorKind) -> String {
    format!("{k:?}")
}

/// Map an `io::Error` observed during TCP connect.
pub fn classify_connect_io(e: &io::Error) -> FailureKind {
    use io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => FailureKind::ConnectRefused,
        K::TimedOut => FailureKind::ConnectTimeout,
        K::ConnectionReset | K::ConnectionAborted => FailureKind::ConnectReset,
        K::NetworkUnreachable => FailureKind::NetworkUnreachable,
        K::HostUnreachable => FailureKind::HostUnreachable,
        K::AddrNotAvailable | K::AddrInUse => FailureKind::AddressUnavailable,
        _ => FailureKind::ConnectOther,
    }
}

fn alert_name(a: &rustls::AlertDescription) -> String {
    // RFC 8446 alert names in snake_case (Debug is CamelCase; acronyms stay together).
    let dbg = format!("{a:?}");
    if dbg == "UnknownPSKIdentity" {
        return "unknown_psk_identity".into();
    }
    let chars: Vec<char> = dbg.chars().collect();
    let mut out = String::new();
    for (i, ch) in chars.iter().enumerate() {
        if ch.is_ascii_uppercase() && i > 0 && chars[i - 1].is_ascii_lowercase() {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// Classify a rustls error. `after_handshake` distinguishes alerts the peer
/// sent after the client completed its side of the handshake.
pub fn classify_rustls(e: &rustls::Error, after_handshake: bool) -> (FailureKind, Option<String>) {
    use rustls::CertificateError as C;
    use rustls::Error as R;
    match e {
        R::InvalidCertificate(ce) => {
            let k = match ce {
                C::Expired | C::ExpiredContext { .. } => FailureKind::TlsExpired,
                C::NotValidYet | C::NotValidYetContext { .. } => FailureKind::TlsNotYetValid,
                C::UnknownIssuer => FailureKind::TlsUntrustedIssuer,
                C::NotValidForName | C::NotValidForNameContext { .. } => FailureKind::TlsNameMismatch,
                C::Revoked => FailureKind::TlsRevoked,
                _ => FailureKind::TlsBadCertificate,
            };
            (k, None)
        }
        R::AlertReceived(a) => {
            let name = alert_name(a);
            let k = if matches!(a, rustls::AlertDescription::NoApplicationProtocol) {
                FailureKind::TlsAlpnMismatch
            } else if after_handshake {
                FailureKind::TlsAlertAfterHandshake
            } else {
                FailureKind::TlsAlertReceived
            };
            (k, Some(name))
        }
        R::NoApplicationProtocol => (FailureKind::TlsAlpnMismatch, None),
        R::InvalidMessage(m) => {
            use rustls::InvalidMessage as M;
            match m {
                // The first bytes were not a TLS record: the peer is very likely
                // not speaking TLS on this port (e.g. plaintext HTTP).
                M::InvalidContentType | M::UnknownProtocolVersion | M::MessageTooLarge => (FailureKind::TlsProtocolMismatch, None),
                _ => (FailureKind::TlsOther, None),
            }
        }
        _ => (FailureKind::TlsOther, None),
    }
}

/// Plain-language description of a certificate validation error (never the
/// library's debug text). `None` for errors that are not certificate errors.
pub fn describe_rustls(e: &rustls::Error) -> Option<String> {
    use rustls::CertificateError as C;
    let rustls::Error::InvalidCertificate(ce) = e else { return None };
    Some(
        match ce {
            C::Expired | C::ExpiredContext { .. } => "the certificate has expired",
            C::NotValidYet | C::NotValidYetContext { .. } => "the certificate is not valid yet",
            C::UnknownIssuer => "the certificate was not issued by a trusted certificate authority",
            C::NotValidForName | C::NotValidForNameContext { .. } => "the certificate does not cover this host name",
            C::Revoked => "the certificate has been revoked",
            C::BadEncoding => "the certificate could not be decoded",
            C::BadSignature => "the certificate's signature is invalid",
            C::UnhandledCriticalExtension => "the certificate has a critical extension that cannot be processed",
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => "the certificate is not valid for server authentication (extended key usage)",
            C::ApplicationVerificationFailure => "the certificate failed an additional verification check",
            C::Other(o) if format!("{o:?}").contains("CaUsedAsEndEntity") => {
                "the server presented a CA certificate as its own certificate (typical of a self-signed certificate made without a separate CA); it cannot be accepted as a server certificate"
            }
            C::Other(o) if format!("{o:?}").contains("UnsupportedSignatureAlgorithm") => "the certificate uses an unsupported signature algorithm",
            _ => "the certificate failed validation",
        }
        .to_string(),
    )
}

/// Classify an error returned by a TLS handshake (tokio-rustls `connect`).
pub fn classify_tls_handshake(e: &io::Error) -> TransportFailure {
    let mut f = TransportFailure::new(Phase::TlsHandshake, FailureKind::TlsOther, display_chain(e));
    f.io_error_kind = Some(io_kind_name(e.kind()));
    f.os_error_code = e.raw_os_error();
    if let Some(r) = find::<rustls::Error>(e) {
        let (k, alert) = classify_rustls(r, false);
        f.kind = k;
        f.tls_alert = alert;
        if let Some(d) = describe_rustls(r) {
            f.message = d;
        }
        return f;
    }
    f.kind = match e.kind() {
        io::ErrorKind::UnexpectedEof => FailureKind::TlsPeerClosed,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe => FailureKind::TlsReset,
        io::ErrorKind::TimedOut => FailureKind::TlsHandshakeTimeout,
        _ => FailureKind::TlsOther,
    };
    f
}

/// Where in the HTTP exchange a hyper error surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HyperStage {
    /// While waiting for response headers (includes writing the request).
    AwaitHeaders,
    /// While reading the response body.
    Body,
    /// During HTTP/2 connection handshake.
    Handshake,
}

/// Classify a hyper error with typed predicates and the source chain.
pub fn classify_hyper(e: &hyper::Error, stage: HyperStage) -> TransportFailure {
    let phase = match stage {
        HyperStage::AwaitHeaders => Phase::AwaitResponseHeaders,
        HyperStage::Body => Phase::ResponseBody,
        HyperStage::Handshake => Phase::ProtocolHandshake,
    };
    let mut f = TransportFailure::new(phase, FailureKind::HttpProtocolError, display_chain(e));
    let dynerr: &(dyn StdError + 'static) = e;

    // TLS alerts delivered after the handshake (e.g. TLS 1.3 client-cert rejection).
    if let Some(r) = find::<rustls::Error>(dynerr) {
        let (k, alert) = classify_rustls(r, true);
        f.kind = k;
        f.tls_alert = alert;
        return f;
    }

    if let Some(h2e) = find::<h2::Error>(dynerr)
        && apply_h2(h2e, stage, &mut f)
    {
        return f;
    }

    if let Some(ioe) = find::<io::Error>(dynerr) {
        f.io_error_kind = Some(io_kind_name(ioe.kind()));
        f.os_error_code = ioe.raw_os_error();
        f.kind = io_to_exchange_kind(ioe.kind(), stage);
        if f.kind != FailureKind::HttpProtocolError {
            return f;
        }
    }

    f.kind = if e.is_parse_too_large() {
        FailureKind::ResponseHeadersTooLarge
    } else if e.is_parse() || e.is_parse_status() || e.is_parse_version_h2() {
        FailureKind::HttpProtocolError
    } else if e.is_incomplete_message() {
        match stage {
            HyperStage::Body => FailureKind::BodyIncomplete,
            _ => FailureKind::ClosedBeforeResponse,
        }
    } else if e.is_body_write_aborted() {
        FailureKind::RequestWriteFailed
    } else if e.is_timeout() {
        match stage {
            HyperStage::Body => FailureKind::BodyIdleTimeout,
            _ => FailureKind::ResponseHeadersTimeout,
        }
    } else if e.is_closed() || e.is_canceled() {
        match stage {
            HyperStage::Body => FailureKind::BodyIncomplete,
            _ => FailureKind::ClosedBeforeResponse,
        }
    } else {
        FailureKind::HttpProtocolError
    };
    f
}

/// Type an `h2` error into `f`: a peer `GOAWAY` / `RST_STREAM` (with its
/// code), or the connection's I/O error. `false` when neither applies.
fn apply_h2(h2e: &h2::Error, stage: HyperStage, f: &mut TransportFailure) -> bool {
    if let Some(reason) = h2e.reason() {
        f.h2_error_code = Some(u32::from(reason));
        // Only a GOAWAY / RST_STREAM the *peer* sent is a peer signal. When
        // Anvil's own h2 library detects invalid bytes (e.g. a TLS alert
        // or HTTP/1 answer read as a frame) it raises a local GOAWAY:
        // that is a protocol mismatch, not the server closing.
        let remote = h2e.is_remote();
        f.kind = if remote && reason == h2::Reason::REFUSED_STREAM {
            FailureKind::H2RefusedStream
        } else if remote && h2e.is_go_away() {
            FailureKind::H2GoAway
        } else if remote && h2e.is_reset() {
            FailureKind::H2StreamReset
        } else {
            FailureKind::HttpProtocolError
        };
        return true;
    }
    if h2e.is_io()
        && let Some(ioe) = h2e.get_io()
    {
        f.io_error_kind = Some(io_kind_name(ioe.kind()));
        f.os_error_code = ioe.raw_os_error();
        f.kind = io_to_exchange_kind(ioe.kind(), stage);
        return true;
    }
    false
}

/// Classify an error from `h2` driven directly (the HBONE datagram tunnel)
/// with the same typed rules as [`classify_hyper`].
pub fn classify_h2(e: &h2::Error, stage: HyperStage) -> TransportFailure {
    let phase = match stage {
        HyperStage::AwaitHeaders => Phase::AwaitResponseHeaders,
        HyperStage::Body => Phase::ResponseBody,
        HyperStage::Handshake => Phase::ProtocolHandshake,
    };
    let mut f = TransportFailure::new(phase, FailureKind::HttpProtocolError, display_chain(e));
    // TLS alerts delivered after the handshake (e.g. TLS 1.3 client-cert rejection).
    if let Some(r) = find::<rustls::Error>(e) {
        let (k, alert) = classify_rustls(r, true);
        f.kind = k;
        f.tls_alert = alert;
        return f;
    }
    apply_h2(e, stage, &mut f);
    f
}

fn io_to_exchange_kind(k: io::ErrorKind, stage: HyperStage) -> FailureKind {
    use io::ErrorKind as K;
    match (k, stage) {
        (K::ConnectionReset | K::ConnectionAborted, HyperStage::Body) => FailureKind::BodyReset,
        (K::ConnectionReset | K::ConnectionAborted, _) => FailureKind::ResetBeforeResponse,
        (K::BrokenPipe, HyperStage::Body) => FailureKind::BodyReset,
        (K::BrokenPipe, _) => FailureKind::RequestWriteFailed,
        (K::UnexpectedEof, HyperStage::Body) => FailureKind::BodyIncomplete,
        (K::UnexpectedEof, _) => FailureKind::ClosedBeforeResponse,
        (K::TimedOut, HyperStage::Body) => FailureKind::BodyIdleTimeout,
        (K::TimedOut, _) => FailureKind::ResponseHeadersTimeout,
        _ => FailureKind::HttpProtocolError,
    }
}
