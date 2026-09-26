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

/// Decode `data` according to a `Content-Encoding` header value (codings are
/// applied in listed order, so they are removed in reverse). Only the last
/// layer removed can stop at `limit` and yield a decoded prefix: an earlier
/// layer that exceeds it leaves bytes that are still encoded, so that is
/// reported as [`DecodeOutcome::Failed`].
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
        let reader: Box<dyn Read> = match coding.as_str() {
            "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(&current[..])),
            "deflate" => {
                // RFC 9110 "deflate" is zlib-wrapped; some servers send raw deflate.
                if current.len() >= 2 && (u16::from(current[0]) << 8 | u16::from(current[1])) % 31 == 0 && current[0] & 0x0F == 8 {
                    Box::new(flate2::read::ZlibDecoder::new(&current[..]))
                } else {
                    Box::new(flate2::read::DeflateDecoder::new(&current[..]))
                }
            }
            "br" => Box::new(brotli::Decompressor::new(&current[..], 4096)),
            "zstd" => match zstd::stream::read::Decoder::new(&current[..]) {
                Ok(d) => Box::new(d),
                Err(e) => {
                    return DecodeOutcome::Failed { coding: coding.clone(), message: e.to_string() };
                }
            },
            other => {
                return DecodeOutcome::Unsupported { coding: other.to_string() };
            }
        };
        let mut out = Vec::new();
        {
            let mut limited = reader.take(limit + 1);
            if let Err(e) = limited.read_to_end(&mut out) {
                return DecodeOutcome::Failed { coding: coding.clone(), message: e.to_string() };
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
    fn unknown_coding_reported() {
        assert!(matches!(decode(Some("compress"), b"x", 10), DecodeOutcome::Unsupported { .. }));
        assert_eq!(decode(Some("identity"), b"x", 10), DecodeOutcome::Identity);
    }
}
