//! gRPC-Web wire helpers (gRPC `PROTOCOL-WEB.md`), used by the gRPC adapter.
//!
//! * Media types: `application/grpc-web+proto` (binary) and
//!   `application/grpc-web-text` (the same bytes, base64-encoded).
//! * [`Base64Stream`]: incremental base64 decoding of a text-mode body. Servers
//!   may base64-encode each flush on its own, so `=` padding can appear in the
//!   middle of a body; every 4-character quantum is decoded independently of
//!   the chunk boundaries it arrived in. At most three characters are held.
//! * [`next_frame`]: length-prefixed frames. Besides message frames (`0x00`,
//!   `0x01` compressed), gRPC-Web ends the body with a trailer frame (`0x80`)
//!   whose payload is an HTTP/1-style header block carrying `grpc-status`.
//!   `0x81` (a "compressed" trailer frame) is not defined and is refused.
//! * [`parse_trailer_block`]: `name: value\r\n` lines, bounded.

use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};

/// Request/response media type of binary gRPC-Web.
pub const CT_BINARY: &str = "application/grpc-web+proto";
/// Request/response media type of text (base64) gRPC-Web.
pub const CT_TEXT: &str = "application/grpc-web-text";
/// Flag byte of the frame that carries the terminal metadata.
pub const TRAILER_FLAG: u8 = 0x80;
/// Largest trailer block accepted (status, message and trailing metadata).
pub const MAX_TRAILER_BLOCK: usize = 1024 * 1024;
/// Most entries accepted in one trailer block.
const MAX_TRAILER_ENTRIES: usize = 1024;

fn media_type(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// `application/grpc-web`, `application/grpc-web+proto`, `application/grpc-web-text`, ...
pub fn is_grpc_web(ct: &str) -> bool {
    media_type(ct).starts_with("application/grpc-web")
}

/// `application/grpc-web-text` with any `+suffix`.
pub fn is_grpc_web_text(ct: &str) -> bool {
    media_type(ct).starts_with("application/grpc-web-text")
}

/// Any gRPC family media type (native `application/grpc*` or gRPC-Web).
pub fn is_grpc_family(ct: &str) -> bool {
    media_type(ct).starts_with("application/grpc")
}

/// Base64 (standard alphabet) text of a request body for text mode.
pub fn encode_text(bytes: &[u8]) -> Bytes {
    Bytes::from(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Incremental decoder for a `application/grpc-web-text` body.
#[derive(Debug, Default)]
pub struct Base64Stream {
    /// Characters of an incomplete quantum (at most three).
    pending: Vec<u8>,
}

impl Base64Stream {
    /// Decode `input` (the next chunk of the body) into `out`. ASCII
    /// whitespace is ignored. Each padded quantum ends a segment; decoding
    /// continues with the next quantum, so independently padded flushes
    /// concatenate correctly.
    pub fn push(&mut self, input: &[u8], out: &mut BytesMut) -> Result<(), String> {
        let mut chars = std::mem::take(&mut self.pending);
        chars.extend(input.iter().copied().filter(|b| !b.is_ascii_whitespace()));
        let full = chars.len() / 4 * 4;
        let mut start = 0;
        let mut i = 0;
        while i < full {
            let padded = chars[i + 2] == b'=' || chars[i + 3] == b'=';
            i += 4;
            if padded {
                decode_segment(&chars[start..i], out)?;
                start = i;
            }
        }
        if start < full {
            decode_segment(&chars[start..full], out)?;
        }
        self.pending = chars[full..].to_vec();
        Ok(())
    }

    /// The body ended: a partial quantum left over is a truncated body.
    pub fn finish(&self) -> Result<(), String> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(format!("the body ended inside a base64 quantum ({} character(s) left over)", self.pending.len()))
        }
    }
}

fn decode_segment(seg: &[u8], out: &mut BytesMut) -> Result<(), String> {
    let v = base64::engine::general_purpose::STANDARD.decode(seg).map_err(|e| format!("not valid base64: {e}"))?;
    out.extend_from_slice(&v);
    Ok(())
}

/// One length-prefixed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireFrame {
    Message {
        compressed: bool,
        data: Bytes,
    },
    /// gRPC-Web trailer frame payload (the header block).
    Trailer(Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// A declared length above the local limit.
    TooLarge(String),
    /// Not a valid frame header for this wire format.
    Invalid(String),
}

/// Split the next complete frame out of `buf`. `web` admits the gRPC-Web
/// trailer frame (`0x80`); native gRPC allows only `0x00` and `0x01`.
pub fn next_frame(buf: &mut BytesMut, max: usize, web: bool) -> Result<Option<WireFrame>, FrameError> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let flag = buf[0];
    let trailer = match flag {
        0x00 | 0x01 => false,
        TRAILER_FLAG if web => true,
        0x81 if web => {
            return Err(FrameError::Invalid("a trailer frame with the compressed bit set (0x81) is not defined by gRPC-Web".into()));
        }
        other => {
            return Err(FrameError::Invalid(format!("invalid {} frame flag 0x{other:02x}", if web { "gRPC-Web" } else { "gRPC" })));
        }
    };
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let limit = if trailer { max.min(MAX_TRAILER_BLOCK) } else { max };
    if len > limit {
        return Err(FrameError::TooLarge(format!(
            "a received {} declares {len} bytes, above the local limit of {limit}",
            if trailer { "trailer frame" } else { "message" }
        )));
    }
    if buf.len() < 5 + len {
        return Ok(None);
    }
    buf.advance(5);
    let data = buf.split_to(len).freeze();
    Ok(Some(if trailer { WireFrame::Trailer(data) } else { WireFrame::Message { compressed: flag == 0x01, data } }))
}

/// Parse a trailer block: `name: value` lines separated by CRLF (a bare LF
/// is tolerated). Names are lowercased; surrounding whitespace is trimmed.
pub fn parse_trailer_block(payload: &[u8]) -> Result<Vec<(String, String)>, String> {
    let text = std::str::from_utf8(payload).map_err(|_| "the trailer block is not valid UTF-8".to_string())?;
    let mut out = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("the trailer line {:?} has no ':'", line.chars().take(64).collect::<String>()));
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(format!("the trailer line {:?} has no valid name", line.chars().take(64).collect::<String>()));
        }
        out.push((name, value.trim().to_string()));
        if out.len() > MAX_TRAILER_ENTRIES {
            return Err(format!("the trailer block has more than {MAX_TRAILER_ENTRIES} entries"));
        }
    }
    Ok(out)
}

/// First value of `name` in a parsed trailer block.
pub fn trailer_value<'a>(entries: &'a [(String, String)], name: &str) -> Option<&'a str> {
    entries.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![flag];
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn media_types() {
        assert!(is_grpc_web("application/grpc-web+proto"));
        assert!(is_grpc_web("Application/GRPC-Web-Text; charset=utf-8"));
        assert!(is_grpc_web_text("application/grpc-web-text+proto"));
        assert!(!is_grpc_web_text("application/grpc-web"));
        assert!(!is_grpc_web("application/grpc"));
        assert!(is_grpc_family("application/grpc+proto") && is_grpc_family("application/grpc-web"));
        assert!(!is_grpc_family("application/json"));
    }

    #[test]
    fn base64_is_decoded_across_arbitrary_chunk_boundaries_and_mid_body_padding() {
        let msg = frame(0, b"hello");
        let trailer = frame(TRAILER_FLAG, b"grpc-status: 0\r\n");
        // Each frame encoded on its own: the first ends with padding.
        let b64 = |b: &[u8]| String::from_utf8(encode_text(b).to_vec()).unwrap();
        let text = format!("{}{}", b64(&msg), b64(&trailer));
        assert!(text[..text.len() / 2].contains('='), "padding in the middle of the body: {text}");
        let mut expect = msg.clone();
        expect.extend_from_slice(&trailer);
        for split in 0..text.len() {
            let mut d = Base64Stream::default();
            let mut out = BytesMut::new();
            d.push(&text.as_bytes()[..split], &mut out).unwrap();
            d.push(&text.as_bytes()[split..], &mut out).unwrap();
            d.finish().unwrap();
            assert_eq!(out.as_ref(), expect.as_slice(), "split at {split}");
        }
        // One byte at a time, with whitespace.
        let mut d = Base64Stream::default();
        let mut out = BytesMut::new();
        for b in text.bytes() {
            d.push(&[b, b'\n'], &mut out).unwrap();
        }
        assert_eq!(out.as_ref(), expect.as_slice());
    }

    #[test]
    fn base64_errors_and_truncation_are_reported() {
        let mut d = Base64Stream::default();
        let mut out = BytesMut::new();
        assert!(d.push(b"AA*A", &mut out).is_err());
        let mut d = Base64Stream::default();
        d.push(b"AAAAAA", &mut out).unwrap();
        assert!(d.finish().unwrap_err().contains("2 character"));
    }

    #[test]
    fn frames_messages_and_trailer_frame() {
        let mut b = BytesMut::new();
        b.extend_from_slice(&frame(0, b"abc"));
        b.extend_from_slice(&frame(TRAILER_FLAG, b"grpc-status: 5\r\ngrpc-message: not%20found\r\n"));
        assert_eq!(next_frame(&mut b, 64, true).unwrap(), Some(WireFrame::Message { compressed: false, data: Bytes::from_static(b"abc") }));
        let Some(WireFrame::Trailer(t)) = next_frame(&mut b, 64, true).unwrap() else { panic!("trailer frame") };
        let entries = parse_trailer_block(&t).unwrap();
        assert_eq!(trailer_value(&entries, "grpc-status"), Some("5"));
        assert_eq!(trailer_value(&entries, "grpc-message"), Some("not%20found"));
        assert_eq!(next_frame(&mut b, 64, true).unwrap(), None);
        // Native gRPC has no trailer frame; 0x81 is never valid.
        let mut n = BytesMut::from(&frame(TRAILER_FLAG, b"x")[..]);
        assert!(matches!(next_frame(&mut n, 64, false), Err(FrameError::Invalid(_))));
        let mut c = BytesMut::from(&frame(0x81, b"x")[..]);
        assert!(matches!(next_frame(&mut c, 64, true), Err(FrameError::Invalid(m)) if m.contains("0x81")));
        let mut big = BytesMut::from(&[0u8, 0, 0, 1, 0][..]);
        assert!(matches!(next_frame(&mut big, 16, true), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn trailer_blocks() {
        let e = parse_trailer_block(b"Grpc-Status: 0\r\nx-a:  b \nempty-ok:\r\n\r\n").unwrap();
        assert_eq!(e, vec![("grpc-status".into(), "0".into()), ("x-a".into(), "b".into()), ("empty-ok".into(), "".into())]);
        assert!(parse_trailer_block(b"no colon here").is_err());
        assert!(parse_trailer_block(b": value").is_err());
        assert!(parse_trailer_block(&[0xff, b':']).is_err());
    }
}
