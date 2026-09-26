//! RFC 7692 `permessage-deflate` codec (feature `deflate`).
//!
//! This module only runs the per-message codec for parameters that were
//! already negotiated. Offering the extension and validating the peer's
//! `Sec-WebSocket-Extensions` answer is the caller's job; tungstenite's own
//! handshake neither offers nor accepts extensions.
//!
//! * Sending (RFC 7692 §7.2.1): the payload of every Text/Binary message is
//!   compressed with a sync flush, the trailing `0x00 0x00 0xff 0xff` is
//!   removed and the frame carries RSV1. Control frames are never compressed.
//! * Receiving (§7.2.2): RSV1 on the first frame of a data message marks it
//!   compressed. Each fragment is inflated as it arrives and
//!   `0x00 0x00 0xff 0xff` is appended after the last one.
//!   `max_message_size` limits the *decompressed* message, and inflation
//!   stops as soon as that limit is passed, so a small compressed message
//!   cannot expand without bound.
//! * Context takeover (§7.1.1): without `*_no_context_takeover` the LZ77
//!   window carries over from message to message; with it, the compressor or
//!   decompressor is reset after every message.

use crate::error::{CapacityError, Error, ProtocolError, Result};
use bytes::Bytes;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use std::io;

/// The end of a sync-flushed DEFLATE block (RFC 7692 §7.2.1 and §7.2.2).
const TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// Negotiated `permessage-deflate` parameters, seen from this endpoint.
///
/// For a client the outgoing direction is governed by the `client_*`
/// extension parameters and the incoming direction by the `server_*` ones;
/// for a server it is the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateConfig {
    /// Compress outgoing Text/Binary messages. When `false` they are sent
    /// uncompressed (RSV1 clear), which RFC 7692 §6 allows; incoming
    /// compressed messages are still decoded.
    pub compress: bool,
    /// LZ77 window of the compressor, as a base-2 logarithm (9–15). zlib
    /// cannot produce a 256-byte window, so a value below 9 disables
    /// compression of outgoing messages instead of exceeding the limit.
    pub compress_window_bits: u8,
    /// Reset the compressor after every message (no context takeover).
    pub compress_no_context_takeover: bool,
    /// Reset the decompressor after every message (the peer does not use
    /// context takeover). The decompressor always keeps a 2^15-byte window,
    /// so it decodes any window the peer may use; it does not check that the
    /// peer stays within a smaller window it agreed to.
    pub decompress_no_context_takeover: bool,
    /// DEFLATE compression level (0–9).
    pub level: u32,
}

impl Default for DeflateConfig {
    fn default() -> Self {
        DeflateConfig {
            compress: true,
            compress_window_bits: 15,
            compress_no_context_takeover: false,
            decompress_no_context_takeover: false,
            level: 6,
        }
    }
}

/// Per-connection codec state.
#[derive(Debug)]
pub(crate) struct DeflateCodec {
    config: DeflateConfig,
    compressor: Option<Compress>,
    decompressor: Decompress,
    /// The incoming message being assembled is compressed.
    receiving: bool,
    /// Compressed payload bytes of the incoming message so far.
    received_compressed: usize,
    /// The peer ended its DEFLATE stream (a block with BFINAL set) inside
    /// the current message; the rest of the message is ignored.
    stream_ended: bool,
    scratch: Vec<u8>,
}

impl DeflateCodec {
    pub(crate) fn new(config: DeflateConfig) -> Self {
        let compressor = (config.compress && config.compress_window_bits >= 9).then(|| {
            Compress::new_with_window_bits(
                Compression::new(config.level.min(9)),
                false,
                config.compress_window_bits.min(15),
            )
        });
        DeflateCodec {
            config,
            compressor,
            decompressor: Decompress::new(false),
            receiving: false,
            received_compressed: 0,
            stream_ended: false,
            scratch: vec![0; 16 * 1024],
        }
    }

    /// Compress the payload of an outgoing data message (RFC 7692 §7.2.1).
    /// `None` means the message is sent uncompressed.
    pub(crate) fn compress(&mut self, payload: &[u8]) -> Result<Option<Bytes>> {
        let Some(c) = self.compressor.as_mut() else { return Ok(None) };
        let start = c.total_in();
        let mut out = Vec::with_capacity(payload.len() / 2 + 64);
        loop {
            if out.capacity() - out.len() < 64 {
                out.reserve(out.capacity().max(64));
            }
            let consumed = (c.total_in() - start) as usize;
            c.compress_vec(&payload[consumed..], &mut out, FlushCompress::Sync)
                .map_err(|e| Error::Io(io::Error::other(e)))?;
            // The sync flush is complete once all input is consumed and the
            // compressor stopped with output space left.
            if (c.total_in() - start) as usize == payload.len() && out.len() < out.capacity() {
                break;
            }
        }
        if out.ends_with(&TAIL) {
            out.truncate(out.len() - TAIL.len());
        }
        if out.is_empty() {
            // zlib emits nothing for an empty message right after a flush.
            // An empty payload would leave the peer's decompressor inside a
            // stored block; the header of an empty stored block (§7.2.3.6)
            // completes it with the tail the peer appends.
            out.push(0x00);
        }
        if self.config.compress_no_context_takeover {
            c.reset();
        }
        Ok(Some(out.into()))
    }

    /// Start a compressed incoming message (its first frame had RSV1 set).
    pub(crate) fn begin_message(&mut self) {
        self.receiving = true;
        self.received_compressed = 0;
    }

    /// Whether the incoming message being assembled is compressed.
    pub(crate) fn receiving(&self) -> bool {
        self.receiving
    }

    /// Inflate one fragment of a compressed incoming message (RFC 7692
    /// §7.2.2). `already` is the decompressed size of the message so far;
    /// the result never takes the message more than one byte past
    /// `max_size` before failing.
    pub(crate) fn decompress(
        &mut self,
        fragment: &[u8],
        fin: bool,
        already: usize,
        max_size: Option<usize>,
    ) -> Result<Bytes> {
        let max = max_size.unwrap_or(usize::MAX);
        self.received_compressed = self.received_compressed.saturating_add(fragment.len());
        let mut out = Vec::new();
        self.inflate(fragment, &mut out, already, max)?;
        if fin {
            // A message without any compressed byte is empty. The tail alone
            // would leave the decompressor inside a stored block and corrupt
            // the next message under context takeover.
            if self.received_compressed > 0 {
                self.inflate(&TAIL, &mut out, already, max)?;
            }
            if self.config.decompress_no_context_takeover || self.stream_ended {
                self.decompressor.reset(false);
            }
            self.receiving = false;
            self.stream_ended = false;
        }
        Ok(out.into())
    }

    fn inflate(&mut self, mut input: &[u8], out: &mut Vec<u8>, already: usize, max: usize) -> Result<()> {
        while !self.stream_ended {
            // Room for one byte more than the limit allows, to detect it.
            let room = max
                .saturating_sub(already.saturating_add(out.len()))
                .saturating_add(1)
                .min(self.scratch.len());
            let (in0, out0) = (self.decompressor.total_in(), self.decompressor.total_out());
            let status = self
                .decompressor
                .decompress(input, &mut self.scratch[..room], FlushDecompress::Sync)
                .map_err(|e| {
                    self.receiving = false;
                    Error::Protocol(ProtocolError::InvalidCompressedMessage(
                        e.message().unwrap_or("invalid DEFLATE data").to_string(),
                    ))
                })?;
            let read = (self.decompressor.total_in() - in0) as usize;
            let wrote = (self.decompressor.total_out() - out0) as usize;
            input = &input[read..];
            out.extend_from_slice(&self.scratch[..wrote]);
            if already.saturating_add(out.len()) > max {
                self.receiving = false;
                return Err(Error::Capacity(CapacityError::DecompressedMessageTooLong {
                    compressed_size: self.received_compressed,
                    max_size: max,
                }));
            }
            match status {
                Status::StreamEnd => self.stream_ended = true,
                _ if input.is_empty() && wrote < room => break,
                _ if read == 0 && wrote == 0 => {
                    self.receiving = false;
                    return Err(Error::Protocol(ProtocolError::InvalidCompressedMessage(
                        "the DEFLATE data could not be decoded any further".into(),
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
