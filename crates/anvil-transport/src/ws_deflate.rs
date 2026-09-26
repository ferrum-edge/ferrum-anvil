//! RFC 7692 `permessage-deflate` for the WebSocket adapter: the offer, the
//! validation of the server's answer, and a frame meter.
//!
//! The per-message codec runs inside tungstenite (vendored with a small
//! patch; see `vendor/README.md`). Negotiation stays here because Anvil does
//! its own handshake for all three bootstraps (HTTP/1.1 Upgrade, RFC 8441
//! and RFC 9220 extended CONNECT):
//!
//! * [`DeflateOffer::header_value`] is the `Sec-WebSocket-Extensions` offer.
//! * [`negotiate`] checks the answer against it. RFC 6455 §4.1 and RFC 7692
//!   §7 require the client to fail the connection when the answer names an
//!   extension that was not offered, repeats a parameter, carries an unknown
//!   parameter or an invalid value, or does not fit the offer. Every such
//!   answer is refused with a typed reason.
//! * [`Metered`] counts data messages and their payload bytes as they cross
//!   the stream, from frame headers alone: the wire side of the evidence,
//!   independent of the codec.

use anvil_domain::outcome::{WsDeflateParams, WsDirectionTotals};
use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tungstenite::protocol::DeflateConfig;

pub const EXTENSION: &str = "permessage-deflate";

/// Anvil's validated offer. Window sizes are base-2 logarithms (8–15).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeflateOffer {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
    pub server_max_window_bits: Option<u8>,
    /// `None`: `client_max_window_bits` without a value.
    pub client_max_window_bits: Option<u8>,
}

impl DeflateOffer {
    /// The `Sec-WebSocket-Extensions` value (RFC 7692 §7.1).
    pub fn header_value(&self) -> String {
        let mut v = EXTENSION.to_string();
        if self.server_no_context_takeover {
            v.push_str("; server_no_context_takeover");
        }
        if self.client_no_context_takeover {
            v.push_str("; client_no_context_takeover");
        }
        if let Some(b) = self.server_max_window_bits {
            v.push_str(&format!("; server_max_window_bits={b}"));
        }
        match self.client_max_window_bits {
            Some(b) => v.push_str(&format!("; client_max_window_bits={b}")),
            None => v.push_str("; client_max_window_bits"),
        }
        v
    }
}

/// The negotiated extension: evidence parameters and the codec setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreed {
    pub params: WsDeflateParams,
    pub codec: DeflateConfig,
}

/// Plain-language summary of agreed parameters (inspector notes, transcript).
pub fn describe(p: &WsDeflateParams) -> String {
    let bits = |b: Option<u8>| format!("2^{}", b.unwrap_or(15));
    format!(
        "permessage-deflate negotiated: server window {} with{} context takeover, Anvil window {} with{} context takeover{}",
        bits(p.server_max_window_bits),
        if p.server_no_context_takeover { "out" } else { "" },
        bits(p.client_max_window_bits),
        if p.client_no_context_takeover { "out" } else { "" },
        if p.client_compresses {
            ""
        } else {
            "; Anvil sends its messages uncompressed because it cannot compress within a 256-byte window"
        }
    )
}

/// One `extension-token *( ";" extension-param )` element.
#[derive(Debug)]
struct Element {
    name: String,
    params: Vec<(String, Option<String>)>,
}

fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_tchar)
}

/// Split on `sep` outside quoted strings.
fn split_outside_quotes(s: &str, sep: char) -> Result<Vec<&str>, String> {
    let (mut parts, mut start, mut quoted, mut escaped) = (Vec::new(), 0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c == sep && !quoted => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if quoted {
        return Err("an unterminated quoted string".into());
    }
    parts.push(&s[start..]);
    Ok(parts)
}

/// Parse `Sec-WebSocket-Extensions` values (RFC 6455 §9.1). Several header
/// fields form one comma-separated list.
fn parse(values: &[&str]) -> Result<Vec<Element>, String> {
    let mut out = Vec::new();
    for value in values {
        for item in split_outside_quotes(value, ',')? {
            if item.trim().is_empty() {
                continue; // RFC 9110 §5.6.1: empty list elements are ignored
            }
            let mut parts = split_outside_quotes(item, ';')?.into_iter();
            let name = parts.next().unwrap_or_default().trim();
            if !is_token(name) {
                return Err(format!("'{name}' is not a valid extension name"));
            }
            let mut params = Vec::new();
            for p in parts {
                let (k, v) = match p.split_once('=') {
                    Some((k, v)) => (k.trim(), Some(v.trim())),
                    None => (p.trim(), None),
                };
                if !is_token(k) {
                    return Err(format!("'{}' is not a valid parameter of {name}", p.trim()));
                }
                let v = match v {
                    None => None,
                    Some(v) if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') => {
                        // RFC 6455 §9.1: an unescaped quoted-string must be a token.
                        let mut s = String::new();
                        let mut esc = false;
                        for c in v[1..v.len() - 1].chars() {
                            if !esc && c == '\\' {
                                esc = true;
                                continue;
                            }
                            esc = false;
                            s.push(c);
                        }
                        if !is_token(&s) {
                            return Err(format!("the value of {k} is not a token"));
                        }
                        Some(s)
                    }
                    Some(v) if is_token(v) => Some(v.to_string()),
                    Some(_) => return Err(format!("the value of {k} is not a token")),
                };
                params.push((k.to_ascii_lowercase(), v));
            }
            out.push(Element { name: name.to_ascii_lowercase(), params });
        }
    }
    Ok(out)
}

/// A window-bits value: a decimal integer 8–15 without leading zeros.
fn window_bits(name: &str, v: &Option<String>) -> Result<u8, String> {
    match v.as_deref() {
        None => Err(format!("{name} has no value, but the answer must give one (8 to 15)")),
        Some(s) if !s.starts_with('0') && s.parse::<u8>().map(|b| (8..=15).contains(&b)).unwrap_or(false) => {
            Ok(s.parse().expect("checked"))
        }
        Some(s) => Err(format!("{name}={s} is not a window size from 8 to 15")),
    }
}

/// Validate the server's `Sec-WebSocket-Extensions` answer against the offer.
///
/// `offer` is `None` when Anvil offered no extension it can run (nothing,
/// or only a user-supplied header). `Ok(None)`: no extension is in use.
pub fn negotiate(offer: Option<&DeflateOffer>, answer: &[&str], raw_offer: bool) -> Result<Option<Agreed>, String> {
    let elements = parse(answer).map_err(|e| format!("the Sec-WebSocket-Extensions answer is malformed: {e}"))?;
    let Some(first) = elements.first() else { return Ok(None) };
    let offer = match offer {
        Some(o) if first.name == EXTENSION => o,
        _ => {
            let why = if raw_offer {
                "; Anvil runs only a permessage-deflate it offered itself, not one offered through a custom Sec-WebSocket-Extensions header"
            } else {
                ""
            };
            return Err(format!("the server accepted the extension '{}', which Anvil did not offer{why}", first.name));
        }
    };
    if let Some(extra) = elements.get(1) {
        return Err(if extra.name == EXTENSION {
            "the answer names permessage-deflate more than once".to_string()
        } else {
            format!("the server accepted the extension '{}', which Anvil did not offer", extra.name)
        });
    }
    let (mut server_nct, mut client_nct, mut server_bits, mut client_bits) = (false, false, None, None);
    let mut seen: Vec<&str> = Vec::new();
    for (k, v) in &first.params {
        if seen.contains(&k.as_str()) {
            return Err(format!("the answer repeats {k}"));
        }
        seen.push(k);
        match k.as_str() {
            "server_no_context_takeover" | "client_no_context_takeover" => {
                if let Some(v) = v {
                    return Err(format!("{k} takes no value, but the answer gives {k}={v}"));
                }
                if k == "server_no_context_takeover" {
                    server_nct = true;
                } else {
                    client_nct = true;
                }
            }
            "server_max_window_bits" => server_bits = Some(window_bits(k, v)?),
            "client_max_window_bits" => client_bits = Some(window_bits(k, v)?),
            other => return Err(format!("{other} is not a permessage-deflate parameter")),
        }
    }
    // RFC 7692 §7.1.1.1: the server accepts server_no_context_takeover by
    // repeating it; an answer without it does not accept this offer.
    if offer.server_no_context_takeover && !server_nct {
        return Err("the offer asked for server_no_context_takeover, but the answer does not include it".into());
    }
    // §7.1.2.1: server_max_window_bits is accepted with the same or a smaller value.
    if let Some(asked) = offer.server_max_window_bits {
        match server_bits {
            None => return Err(format!("the offer asked for server_max_window_bits={asked}, but the answer does not include it")),
            Some(b) if b > asked => {
                return Err(format!("the answer's server_max_window_bits={b} is larger than the {asked} Anvil asked for"));
            }
            _ => {}
        }
    }
    // §7.1.2.2: client_max_window_bits may only shrink Anvil's own limit.
    if let (Some(limit), Some(b)) = (offer.client_max_window_bits, client_bits)
        && b > limit
    {
        return Err(format!("the answer's client_max_window_bits={b} is larger than the {limit} Anvil offered"));
    }
    // Anvil keeps its own promises even when the answer does not repeat them.
    let client_nct = client_nct || offer.client_no_context_takeover;
    let client_window = client_bits.or(offer.client_max_window_bits);
    let bits = client_window.unwrap_or(15);
    let client_compresses = bits >= 9;
    Ok(Some(Agreed {
        params: WsDeflateParams {
            server_no_context_takeover: server_nct,
            client_no_context_takeover: client_nct,
            server_max_window_bits: server_bits,
            client_max_window_bits: client_window,
            client_compresses,
        },
        codec: DeflateConfig {
            compress: client_compresses,
            compress_window_bits: bits.max(9),
            compress_no_context_takeover: client_nct,
            decompress_no_context_takeover: server_nct,
            level: 6,
        },
    }))
}

// ------------------------------------------------------------------ meter ---

/// Frame-header parser for one direction of the stream.
#[derive(Debug, Default)]
struct DirMeter {
    header: [u8; 14],
    have: usize,
    need: usize,
    /// Payload bytes of the current frame still to pass.
    skip: u64,
    /// The current frame is a data frame (text, binary or continuation).
    data: bool,
    totals: WsDirectionTotals,
}

impl DirMeter {
    fn feed(&mut self, mut buf: &[u8]) {
        while !buf.is_empty() {
            if self.skip > 0 {
                let n = (self.skip.min(buf.len() as u64)) as usize;
                if self.data {
                    self.totals.wire_bytes += n as u64;
                }
                self.skip -= n as u64;
                buf = &buf[n..];
                continue;
            }
            if self.need == 0 {
                self.need = 2;
            }
            let n = (self.need - self.have).min(buf.len());
            self.header[self.have..self.have + n].copy_from_slice(&buf[..n]);
            self.have += n;
            buf = &buf[n..];
            if self.have < self.need {
                continue;
            }
            if self.have == 2 {
                let len7 = self.header[1] & 0x7f;
                let extended = match len7 {
                    126 => 2,
                    127 => 8,
                    _ => 0,
                };
                let mask = if self.header[1] & 0x80 != 0 { 4 } else { 0 };
                self.need = 2 + extended + mask;
                if self.have < self.need {
                    continue;
                }
            }
            let opcode = self.header[0] & 0x0f;
            let len = match self.header[1] & 0x7f {
                126 => u16::from_be_bytes([self.header[2], self.header[3]]) as u64,
                127 => u64::from_be_bytes(self.header[2..10].try_into().expect("8 bytes")),
                n => n as u64,
            };
            self.data = matches!(opcode, 0..=2);
            if matches!(opcode, 1 | 2) {
                self.totals.messages += 1;
                if self.header[0] & 0x40 != 0 {
                    self.totals.compressed_messages += 1;
                }
            }
            self.skip = len;
            self.have = 0;
            self.need = 2;
        }
    }
}

/// Wire totals of both directions, filled while the session runs.
#[derive(Debug, Default)]
pub struct FrameMeter {
    read: DirMeter,
    written: DirMeter,
}

impl FrameMeter {
    /// `(sent, received)` totals; `payload_bytes` is left for the caller.
    pub fn totals(&self) -> (WsDirectionTotals, WsDirectionTotals) {
        (self.written.totals, self.read.totals)
    }
}

/// Stream wrapper that feeds a [`FrameMeter`] with the bytes it carries.
pub struct Metered<S> {
    inner: S,
    meter: Arc<Mutex<FrameMeter>>,
}

impl<S> Metered<S> {
    pub fn new(inner: S, meter: Arc<Mutex<FrameMeter>>) -> Self {
        Metered { inner, meter }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            self.meter.lock().read.feed(&buf.filled()[before..]);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            self.meter.lock().written.feed(&data[..*n]);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> DeflateOffer {
        DeflateOffer::default()
    }

    fn ok(o: &DeflateOffer, answer: &[&str]) -> Agreed {
        negotiate(Some(o), answer, false).unwrap().unwrap()
    }

    fn err(o: Option<&DeflateOffer>, answer: &[&str]) -> String {
        negotiate(o, answer, false).unwrap_err()
    }

    #[test]
    fn the_offer_names_every_requested_parameter() {
        assert_eq!(offer().header_value(), "permessage-deflate; client_max_window_bits");
        let o = DeflateOffer {
            server_no_context_takeover: true,
            client_no_context_takeover: true,
            server_max_window_bits: Some(10),
            client_max_window_bits: Some(12),
        };
        assert_eq!(
            o.header_value(),
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=10; client_max_window_bits=12"
        );
    }

    #[test]
    fn plain_answers_negotiate_and_absent_answers_do_not() {
        assert!(negotiate(Some(&offer()), &[], false).unwrap().is_none());
        assert!(negotiate(None, &[], false).unwrap().is_none());
        assert!(negotiate(Some(&offer()), &[" , "], false).unwrap().is_none(), "empty list elements are ignored");
        let a = ok(&offer(), &["permessage-deflate"]);
        assert!(a.codec.compress && a.codec.compress_window_bits == 15);
        assert!(!a.codec.compress_no_context_takeover && !a.codec.decompress_no_context_takeover);
        let a = ok(&offer(), &["Permessage-Deflate; Server_No_Context_Takeover; client_max_window_bits=\"10\""]);
        assert!(a.params.server_no_context_takeover && a.codec.decompress_no_context_takeover);
        assert_eq!((a.params.client_max_window_bits, a.codec.compress_window_bits), (Some(10), 10));
        // The server may announce its own window and client_no_context_takeover unasked.
        let a = ok(&offer(), &["permessage-deflate; server_max_window_bits=9; client_no_context_takeover"]);
        assert_eq!(a.params.server_max_window_bits, Some(9));
        assert!(a.codec.compress_no_context_takeover);
    }

    #[test]
    fn the_answer_must_fit_the_offer() {
        let strict = DeflateOffer {
            server_no_context_takeover: true,
            client_no_context_takeover: true,
            server_max_window_bits: Some(10),
            client_max_window_bits: Some(12),
        };
        assert!(err(Some(&strict), &["permessage-deflate; server_max_window_bits=10"]).contains("server_no_context_takeover"));
        assert!(err(Some(&strict), &["permessage-deflate; server_no_context_takeover"]).contains("server_max_window_bits=10"));
        assert!(
            err(Some(&strict), &["permessage-deflate; server_no_context_takeover; server_max_window_bits=11"])
                .contains("larger than the 10")
        );
        assert!(
            err(Some(&strict), &["permessage-deflate; server_no_context_takeover; server_max_window_bits=10; client_max_window_bits=13"])
                .contains("larger than the 12")
        );
        // Anvil keeps its own offered limits when the answer is silent about them.
        let a = ok(&strict, &["permessage-deflate; server_no_context_takeover; server_max_window_bits=8"]);
        assert!(a.codec.compress_no_context_takeover);
        assert_eq!((a.params.client_max_window_bits, a.codec.compress_window_bits), (Some(12), 12));
    }

    #[test]
    fn an_eight_bit_client_window_means_uncompressed_sends() {
        let a = ok(&offer(), &["permessage-deflate; client_max_window_bits=8"]);
        assert!(!a.params.client_compresses && !a.codec.compress);
        assert!(describe(&a.params).contains("uncompressed"));
    }

    #[test]
    fn malformed_or_unknown_answers_are_refused_with_a_reason() {
        let o = offer();
        let cases: &[(&[&str], &str)] = &[
            (&["permessage-deflate; server_max_window_bits"], "has no value"),
            (&["permessage-deflate; client_max_window_bits=16"], "not a window size"),
            (&["permessage-deflate; client_max_window_bits=7"], "not a window size"),
            (&["permessage-deflate; client_max_window_bits=09"], "not a window size"),
            (&["permessage-deflate; client_max_window_bits=abc"], "not a window size"),
            (&["permessage-deflate; server_no_context_takeover=1"], "takes no value"),
            (&["permessage-deflate; server_no_context_takeover; server_no_context_takeover"], "repeats"),
            (&["permessage-deflate; mystery"], "not a permessage-deflate parameter"),
            (&["permessage-deflate, permessage-deflate"], "more than once"),
            (&["permessage-deflate", "x-webkit-deflate-frame"], "did not offer"),
            (&["x-webkit-deflate-frame"], "did not offer"),
            (&["permessage-deflate; client_max_window_bits=\"1 0\""], "malformed"),
            (&["permessage-deflate; client_max_window_bits=\"10"], "malformed"),
            (&["permessage deflate"], "malformed"),
        ];
        for (answer, want) in cases {
            let e = err(Some(&o), answer);
            assert!(e.contains(want), "{answer:?}: {e}");
        }
    }

    #[test]
    fn an_extension_that_was_not_offered_is_refused() {
        assert!(err(None, &["permessage-deflate"]).contains("did not offer"));
        let raw = negotiate(None, &["permessage-deflate"], true).unwrap_err();
        assert!(raw.contains("custom Sec-WebSocket-Extensions header"), "{raw}");
    }

    #[test]
    fn the_meter_reads_headers_across_any_split() {
        // Server frames: compressed text (7), ping (1), fragmented binary (3 + 2),
        // a 300-byte text with a 16-bit length, and a masked client-style frame.
        let mut wire = vec![0xc1, 0x07, 1, 2, 3, 4, 5, 6, 7, 0x89, 0x01, 9, 0x02, 0x03, 1, 2, 3, 0x80, 0x02, 4, 5, 0x81, 126, 0x01, 0x2c];
        wire.extend(vec![b'x'; 300]);
        wire.extend([0x81, 0x82, 1, 2, 3, 4, 0xaa, 0xbb]);
        for split in [1, 2, 3, 5, 7, 64, wire.len()] {
            let mut m = DirMeter::default();
            for chunk in wire.chunks(split) {
                m.feed(chunk);
            }
            let t = m.totals;
            assert_eq!((t.messages, t.compressed_messages, t.wire_bytes), (4, 1, 7 + 5 + 300 + 2), "split {split}");
        }
    }
}
