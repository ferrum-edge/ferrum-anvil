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
}
