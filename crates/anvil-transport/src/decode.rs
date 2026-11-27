//! Bounded content decoding (gzip, deflate, br, zstd) for display and
//! assertions. The original bytes are always preserved separately; decoding
//! never mutates evidence.

use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeOutcome {
    /// No (or identity) content-coding.
    Identity,
    Decoded {
        bytes: Vec<u8>,
        truncated_at_limit: bool,
    },
    Unsupported {
        coding: String,
    },
    Failed {
        coding: String,
        message: String,
    },
}

/// One content-coding decoder over the bytes it removes the coding from.
trait Layer: Read {
    /// True when input is left after the end of the compressed stream: bytes
    /// the decoder stopped short of, which the decoded body would silently
    /// drop.
    fn has_trailing_input(&mut self) -> bool;
}

impl Layer for flate2::bufread::MultiGzDecoder<&[u8]> {
    fn has_trailing_input(&mut self) -> bool {
        !self.get_ref().is_empty()
    }
}

impl Layer for flate2::bufread::ZlibDecoder<&[u8]> {
    fn has_trailing_input(&mut self) -> bool {
        !self.get_ref().is_empty()
    }
}

impl Layer for flate2::bufread::DeflateDecoder<&[u8]> {
    fn has_trailing_input(&mut self) -> bool {
        !self.get_ref().is_empty()
    }
}

impl Layer for zstd::stream::read::Decoder<'_, &[u8]> {
    fn has_trailing_input(&mut self) -> bool {
        !self.get_ref().is_empty()
    }
}

impl Layer for brotli::Decompressor<&[u8]> {
    fn has_trailing_input(&mut self) -> bool {
        // The decompressor buffers its input: a read past the end of the
        // stream fails when buffered bytes were not consumed.
        !matches!(self.read(&mut [0; 1]), Ok(0)) || !self.get_ref().is_empty()
    }
}

/// Decode `data` according to a `Content-Encoding` header value (codings are
/// applied in listed order, so they are removed in reverse). Only the last
/// layer removed can stop at `limit` and yield a decoded prefix: an earlier
/// layer that exceeds it leaves bytes that are still encoded, so that is
/// reported as [`DecodeOutcome::Failed`]. So is input left after the end of a
/// compressed stream (a gzip body may still hold several members).
pub fn decode(content_encoding: Option<&str>, data: &[u8], limit: u64) -> DecodeOutcome {
    let Some(ce) = content_encoding else {
        return DecodeOutcome::Identity;
    };
    let codings: Vec<String> = ce.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty() && s != "identity").collect();
    if codings.is_empty() {
        return DecodeOutcome::Identity;
    }
    if codings.len() > 4 {
        return DecodeOutcome::Unsupported { coding: ce.to_string() };
    }
    let mut current = data.to_vec();
    let mut truncated = false;
    for (i, coding) in codings.iter().rev().enumerate() {
        let mut out = Vec::new();
        {
            let mut layer: Box<dyn Layer + '_> = match coding.as_str() {
                "gzip" | "x-gzip" => Box::new(flate2::bufread::MultiGzDecoder::new(&current[..])),
                "deflate" => {
                    // RFC 9110 "deflate" is zlib-wrapped; some servers send raw deflate.
                    if current.len() >= 2 && (u16::from(current[0]) << 8 | u16::from(current[1])) % 31 == 0 && current[0] & 0x0F == 8 {
                        Box::new(flate2::bufread::ZlibDecoder::new(&current[..]))
                    } else {
                        Box::new(flate2::bufread::DeflateDecoder::new(&current[..]))
                    }
                }
                "br" => Box::new(brotli::Decompressor::new(&current[..], 4096)),
                "zstd" => match zstd::stream::read::Decoder::with_buffer(&current[..]) {
                    Ok(d) => Box::new(d),
                    Err(e) => {
                        return DecodeOutcome::Failed { coding: coding.clone(), message: e.to_string() };
                    }
                },
                other => {
                    return DecodeOutcome::Unsupported { coding: other.to_string() };
                }
            };
            if let Err(e) = layer.by_ref().take(limit + 1).read_to_end(&mut out) {
                return DecodeOutcome::Failed { coding: coding.clone(), message: e.to_string() };
            }
            // A decoder that stopped at the limit has input left by design.
            if out.len() as u64 <= limit && layer.has_trailing_input() {
                let message = "data follows the end of the compressed stream".to_string();
                return DecodeOutcome::Failed { coding: coding.clone(), message };
            }
        }
        if out.len() as u64 > limit {
            if i + 1 < codings.len() {
                let message = format!("the decoded size exceeded the local limit of {limit} bytes before every content-coding was removed");
                return DecodeOutcome::Failed { coding: coding.clone(), message };
            }
            out.truncate(limit as usize);
            truncated = true;
        }
        current = out;
    }
    DecodeOutcome::Decoded { bytes: current, truncated_at_limit: truncated }
}

/// One content-coding removed incrementally, for a reader that must see the
/// decoded bytes while the body is still arriving (an MCP event stream whose
/// answer ends the read). Feed the coded bytes as they arrive; each push
/// returns what they decode to so far. At most `limit` decoded bytes in all.
/// A chain of several codings, or one Anvil does not decode, has none.
pub struct IncrementalDecoder {
    inner: Incremental,
    produced: u64,
    limit: u64,
}

enum Incremental {
    Identity,
    Gzip(flate2::write::MultiGzDecoder<Vec<u8>>),
    /// `deflate` before its first two bytes say zlib-wrapped or raw.
    DeflatePending(Vec<u8>),
    Zlib(flate2::write::ZlibDecoder<Vec<u8>>),
    RawDeflate(flate2::write::DeflateDecoder<Vec<u8>>),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    Zstd(Box<zstd::stream::write::Decoder<'static, Vec<u8>>>),
}

impl IncrementalDecoder {
    /// The decoder for `content_encoding` (`None` or `identity`: bytes pass
    /// through), or `None` when it is not a single coding Anvil decodes.
    pub fn new(content_encoding: Option<&str>, limit: u64) -> Option<Self> {
        let codings: Vec<String> = content_encoding
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty() && s != "identity")
            .collect();
        let inner = match codings.as_slice() {
            [] => Incremental::Identity,
            [one] => match one.as_str() {
                "gzip" | "x-gzip" => Incremental::Gzip(flate2::write::MultiGzDecoder::new(Vec::new())),
                "deflate" => Incremental::DeflatePending(Vec::new()),
                "br" => Incremental::Brotli(Box::new(brotli::DecompressorWriter::new(Vec::new(), 4096))),
                "zstd" => Incremental::Zstd(Box::new(zstd::stream::write::Decoder::new(Vec::new()).ok()?)),
                _ => return None,
            },
            _ => return None,
        };
        Some(IncrementalDecoder { inner, produced: 0, limit })
    }

    /// The bytes `chunk` decodes to (with what earlier chunks left pending);
    /// an error once the coded stream is broken or the decoded total passes
    /// the limit.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, String> {
        use std::io::Write;
        fn drain<W: Write>(w: &mut W, chunk: &[u8], out: impl FnOnce(&mut W) -> &mut Vec<u8>) -> Result<Vec<u8>, String> {
            w.write_all(chunk).map_err(|e| e.to_string())?;
            w.flush().map_err(|e| e.to_string())?;
            Ok(std::mem::take(out(w)))
        }
        if let Incremental::DeflatePending(held) = &mut self.inner {
            held.extend_from_slice(chunk);
            if held.len() < 2 {
                return Ok(Vec::new());
            }
            let held = std::mem::take(held);
            // RFC 9110 "deflate" is zlib-wrapped; some servers send raw deflate.
            let zlib = (u16::from(held[0]) << 8 | u16::from(held[1])) % 31 == 0 && held[0] & 0x0F == 8;
            self.inner = if zlib {
                Incremental::Zlib(flate2::write::ZlibDecoder::new(Vec::new()))
            } else {
                Incremental::RawDeflate(flate2::write::DeflateDecoder::new(Vec::new()))
            };
            return self.push(&held);
        }
        let out = match &mut self.inner {
            Incremental::Identity => Ok(chunk.to_vec()),
            Incremental::Gzip(d) => drain(d, chunk, |d| d.get_mut()),
            Incremental::Zlib(d) => drain(d, chunk, |d| d.get_mut()),
            Incremental::RawDeflate(d) => drain(d, chunk, |d| d.get_mut()),
            Incremental::Brotli(d) => drain(d.as_mut(), chunk, |d| d.get_mut()),
            Incremental::Zstd(d) => drain(d.as_mut(), chunk, |d| d.get_mut()),
            Incremental::DeflatePending(_) => Ok(Vec::new()),
        }?;
        self.produced = self.produced.saturating_add(out.len() as u64);
        if self.produced > self.limit {
            return Err(format!("the decoded body passed {} bytes", self.limit));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn gzip_roundtrip_and_limit() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&vec![b'a'; 10_000]).unwrap();
        let gz = enc.finish().unwrap();
        match decode(Some("gzip"), &gz, 1_000_000) {
            DecodeOutcome::Decoded { bytes, truncated_at_limit } => {
                assert_eq!(bytes.len(), 10_000);
                assert!(!truncated_at_limit);
            }
            o => panic!("{o:?}"),
        }
        match decode(Some("gzip"), &gz, 100) {
            DecodeOutcome::Decoded { bytes, truncated_at_limit } => {
                assert_eq!(bytes.len(), 100);
                assert!(truncated_at_limit, "decompression bomb bound must apply");
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn limit_hit_before_the_last_layer_is_a_failure() {
        fn gzip(data: &[u8]) -> Vec<u8> {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(data).unwrap();
            enc.finish().unwrap()
        }
        let inner = gzip(&vec![b'a'; 10_000]);
        let twice = gzip(&inner);
        assert!(inner.len() > 10, "gzip framing alone is larger than the limit below");
        match decode(Some("gzip, gzip"), &twice, 10) {
            DecodeOutcome::Failed { coding, message } => {
                assert_eq!(coding, "gzip");
                assert!(message.contains("limit"), "{message}");
            }
            o => panic!("a still-encoded prefix must not be reported as decoded: {o:?}"),
        }
        // Only the last layer stops at the limit: that is a decoded prefix.
        let limit = inner.len() as u64 + 1;
        match decode(Some("gzip, gzip"), &twice, limit) {
            DecodeOutcome::Decoded { bytes, truncated_at_limit } => {
                assert!(truncated_at_limit);
                assert_eq!(bytes, vec![b'a'; limit as usize]);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn data_after_the_end_of_a_compressed_stream_is_a_failure() {
        let body = b"visible part";
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(body).unwrap();
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(body).unwrap();
        let mut br = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut br, 4096, 5, 22);
            w.write_all(body).unwrap();
        }
        let zstd = zstd::encode_all(&body[..], 0).unwrap();
        let streams = [("deflate", zlib.finish().unwrap()), ("deflate", raw.finish().unwrap()), ("br", br), ("zstd", zstd)];
        for (coding, stream) in streams {
            match decode(Some(coding), &stream, 1_000_000) {
                DecodeOutcome::Decoded { bytes, truncated_at_limit: false } => assert_eq!(bytes, body, "{coding}"),
                o => panic!("{coding}: {o:?}"),
            }
            // A zstd body may hold several frames; the other codings hold one stream.
            let second_stream = if coding == "zstd" { None } else { Some(stream.clone()) };
            for trailing in [Some(b"hidden-secret-part".to_vec()), second_stream].into_iter().flatten() {
                let mut data = stream.clone();
                data.extend_from_slice(&trailing);
                match decode(Some(coding), &data, 1_000_000) {
                    DecodeOutcome::Failed { coding: failed, .. } => assert_eq!(failed, coding),
                    o => panic!("{coding}: data after the stream must not be dropped silently: {o:?}"),
                }
            }
        }
    }

    #[test]
    fn several_gzip_members_and_zstd_frames_decode_whole() {
        let mut gz = Vec::new();
        for part in [&b"first "[..], b"second"] {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(part).unwrap();
            gz.extend(enc.finish().unwrap());
        }
        let mut zst = zstd::encode_all(&b"first "[..], 0).unwrap();
        zst.extend(zstd::encode_all(&b"second"[..], 0).unwrap());
        for (coding, data) in [("gzip", gz.clone()), ("zstd", zst)] {
            match decode(Some(coding), &data, 1_000_000) {
                DecodeOutcome::Decoded { bytes, truncated_at_limit: false } => assert_eq!(bytes, b"first second", "{coding}"),
                o => panic!("{coding}: {o:?}"),
            }
        }
        gz.extend_from_slice(b"hidden-secret-part");
        assert!(matches!(decode(Some("gzip"), &gz, 1_000_000), DecodeOutcome::Failed { .. }));
    }

    #[test]
    fn unknown_coding_reported() {
        assert!(matches!(decode(Some("compress"), b"x", 10), DecodeOutcome::Unsupported { .. }));
        assert_eq!(decode(Some("identity"), b"x", 10), DecodeOutcome::Identity);
    }

    #[test]
    fn incremental_decoding_matches_whole_decoding_chunk_by_chunk() {
        use std::io::Write;
        let text = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n".repeat(20);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&text).unwrap();
        let gz = gz.finish().unwrap();
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(&text).unwrap();
        let zlib = zlib.finish().unwrap();
        let zstd = zstd::stream::encode_all(&text[..], 0).unwrap();
        let mut br = Vec::new();
        brotli::BrotliCompress(&mut &text[..], &mut br, &Default::default()).unwrap();
        for (coding, bytes) in [("gzip", gz), ("deflate", zlib), ("zstd", zstd), ("br", br), ("identity", text.clone())] {
            let mut d = IncrementalDecoder::new(Some(coding), 1 << 20).unwrap();
            let mut out = Vec::new();
            for chunk in bytes.chunks(7) {
                out.extend(d.push(chunk).unwrap());
            }
            assert_eq!(out, text, "{coding}");
        }
        assert!(IncrementalDecoder::new(Some("gzip, br"), 1 << 20).is_none());
        assert!(IncrementalDecoder::new(Some("compress"), 1 << 20).is_none());
        let mut small = IncrementalDecoder::new(None, 4).unwrap();
        assert!(small.push(b"12345").is_err(), "over the limit");
    }
}
