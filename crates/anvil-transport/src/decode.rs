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
/// applied in listed order, so they are removed in reverse).
pub fn decode(content_encoding: Option<&str>, data: &[u8], limit: u64) -> DecodeOutcome {
    let Some(ce) = content_encoding else {
        return DecodeOutcome::Identity;
    };
    let codings: Vec<String> = ce
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "identity")
        .collect();
    if codings.is_empty() {
        return DecodeOutcome::Identity;
    }
    if codings.len() > 4 {
        return DecodeOutcome::Unsupported {
            coding: ce.to_string(),
        };
    }
    let mut current = data.to_vec();
    let mut truncated = false;
    for coding in codings.iter().rev() {
        let reader: Box<dyn Read> = match coding.as_str() {
            "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(&current[..])),
            "deflate" => {
                // RFC 9110 "deflate" is zlib-wrapped; some servers send raw deflate.
                if current.len() >= 2
                    && (u16::from(current[0]) << 8 | u16::from(current[1])) % 31 == 0
                    && current[0] & 0x0F == 8
                {
                    Box::new(flate2::read::ZlibDecoder::new(&current[..]))
                } else {
                    Box::new(flate2::read::DeflateDecoder::new(&current[..]))
                }
            }
            "br" => Box::new(brotli::Decompressor::new(&current[..], 4096)),
            "zstd" => match zstd::stream::read::Decoder::new(&current[..]) {
                Ok(d) => Box::new(d),
                Err(e) => {
                    return DecodeOutcome::Failed {
                        coding: coding.clone(),
                        message: e.to_string(),
                    };
                }
            },
            other => {
                return DecodeOutcome::Unsupported {
                    coding: other.to_string(),
                };
            }
        };
        let mut out = Vec::new();
        {
            let mut limited = reader.take(limit + 1);
            if let Err(e) = limited.read_to_end(&mut out) {
                return DecodeOutcome::Failed {
                    coding: coding.clone(),
                    message: e.to_string(),
                };
            }
        }
        if out.len() as u64 > limit {
            out.truncate(limit as usize);
            truncated = true;
        }
        current = out;
        if truncated {
            break;
        }
    }
    DecodeOutcome::Decoded {
        bytes: current,
        truncated_at_limit: truncated,
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
            DecodeOutcome::Decoded {
                bytes,
                truncated_at_limit,
            } => {
                assert_eq!(bytes.len(), 10_000);
                assert!(!truncated_at_limit);
            }
            o => panic!("{o:?}"),
        }
        match decode(Some("gzip"), &gz, 100) {
            DecodeOutcome::Decoded {
                bytes,
                truncated_at_limit,
            } => {
                assert_eq!(bytes.len(), 100);
                assert!(truncated_at_limit, "decompression bomb bound must apply");
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn unknown_coding_reported() {
        assert!(matches!(
            decode(Some("compress"), b"x", 10),
            DecodeOutcome::Unsupported { .. }
        ));
        assert_eq!(decode(Some("identity"), b"x", 10), DecodeOutcome::Identity);
    }
}
