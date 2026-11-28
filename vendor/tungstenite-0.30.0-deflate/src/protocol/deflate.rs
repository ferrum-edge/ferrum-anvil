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
use std::sync::OnceLock;
use std::{fmt, io};

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
    /// context takeover).
    pub decompress_no_context_takeover: bool,
    /// LZ77 window the peer agreed to compress within, as a base-2 logarithm
    /// (8–15). Back-references further back than `2^decompress_window_bits`
    /// bytes fail as an invalid compressed message.
    pub decompress_window_bits: u8,
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
            decompress_window_bits: 15,
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
    /// Enforces `decompress_window_bits` when smaller than the 2^15 maximum,
    /// because raw inflate in zlib-rs always allocates a 32 KiB sliding window
    /// without `INFLATE_STRICT`.
    window_checker: Option<DeflateWindowChecker>,
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
        let window_bits = config.decompress_window_bits.clamp(8, 15);
        let window_checker =
            (window_bits < 15).then(|| DeflateWindowChecker::new(1usize << window_bits));
        DeflateCodec {
            config,
            compressor,
            decompressor: Decompress::new(false),
            window_checker,
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
                if let Some(checker) = self.window_checker.as_mut() {
                    checker.reset();
                }
            }
            self.receiving = false;
            self.stream_ended = false;
        }
        Ok(out.into())
    }

    fn inflate(
        &mut self,
        mut input: &[u8],
        out: &mut Vec<u8>,
        already: usize,
        max: usize,
    ) -> Result<()> {
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
            if let Some(checker) = self.window_checker.as_mut() {
                checker.check(&input[..read]).map_err(|err| {
                    self.receiving = false;
                    err
                })?;
            }
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

fn invalid_deflate(msg: &'static str) -> Error {
    Error::Protocol(ProtocolError::InvalidCompressedMessage(msg.into()))
}

const CL_ORDER: [usize; 19] =
    [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

#[derive(Default)]
struct BitBuf {
    bits: u64,
    nbits: u8,
}

impl BitBuf {
    #[inline]
    fn fill(&mut self, input: &mut &[u8]) {
        while self.nbits <= 56 && !input.is_empty() {
            self.bits |= (input[0] as u64) << self.nbits;
            self.nbits += 8;
            *input = &input[1..];
        }
    }

    #[inline]
    fn take(&mut self, n: u8) -> Option<u64> {
        if self.nbits < n {
            return None;
        }
        let val = self.bits & ((1u64 << n) - 1);
        self.bits >>= n;
        self.nbits -= n;
        Some(val)
    }

    #[inline]
    fn align_byte(&mut self) {
        let drop = self.nbits & 7;
        self.bits >>= drop;
        self.nbits -= drop;
    }

    #[inline]
    fn decode(&mut self, table: &HuffmanTable) -> Result<Option<u16>> {
        if self.nbits >= 8 {
            let entry = table.fast[(self.bits & 0xff) as usize];
            if entry != 0 {
                let len = (entry >> 10) as u8;
                self.bits >>= len;
                self.nbits -= len;
                return Ok(Some(entry & 0x3ff));
            }
        }
        if table.max_bits == 0 {
            return Err(invalid_deflate("invalid Huffman code"));
        }
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=table.max_bits {
            if self.nbits < len {
                return Ok(None);
            }
            code = (code << 1) | (((self.bits >> (len - 1)) & 1) as i32);
            let count = table.counts[len as usize] as i32;
            if code - count < first {
                self.bits >>= len;
                self.nbits -= len;
                return Ok(Some(table.symbols[(index + (code - first)) as usize]));
            }
            index += count;
            first = (first + count) << 1;
        }
        Err(invalid_deflate("invalid Huffman code"))
    }
}

struct HuffmanTable {
    counts: [u16; 16],
    symbols: [u16; 288],
    fast: [u16; 256],
    max_bits: u8,
}

impl Default for HuffmanTable {
    fn default() -> Self {
        HuffmanTable {
            counts: [0; 16],
            symbols: [0; 288],
            fast: [0; 256],
            max_bits: 0,
        }
    }
}

impl HuffmanTable {
    fn build(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            if len > 15 {
                return Err(invalid_deflate("invalid Huffman code length"));
            }
            if len > 0 {
                counts[len as usize] += 1;
            }
        }
        let mut left: i32 = 1;
        let mut max_bits: u8 = 0;
        for (bits, &count) in counts.iter().enumerate().skip(1) {
            left = (left << 1) - count as i32;
            if left < 0 {
                return Err(invalid_deflate("oversubscribed Huffman code table"));
            }
            if count > 0 {
                max_bits = bits as u8;
            }
        }
        let mut offsets = [0u16; 16];
        for bits in 1..15 {
            offsets[bits + 1] = offsets[bits] + counts[bits];
        }
        let mut symbols = [0u16; 288];
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                let pos = offsets[len as usize] as usize;
                symbols[pos] = sym as u16;
                offsets[len as usize] += 1;
            }
        }
        let mut fast = [0u16; 256];
        let mut code: u16 = 0;
        let mut idx: usize = 0;
        for (len, &count) in counts.iter().enumerate().take(8usize.min(max_bits as usize) + 1).skip(1)
        {
            let step = 1usize << len;
            for _ in 0..count {
                let sym = symbols[idx];
                let rev = (code.reverse_bits() >> (16 - len)) as usize;
                let entry = ((len as u16) << 10) | sym;
                let mut slot = rev;
                while slot < 256 {
                    fast[slot] = entry;
                    slot += step;
                }
                code += 1;
                idx += 1;
            }
            code <<= 1;
        }
        Ok(HuffmanTable { counts, symbols, fast, max_bits })
    }

    fn fixed_litlen() -> &'static Self {
        static TABLE: OnceLock<HuffmanTable> = OnceLock::new();
        TABLE.get_or_init(|| {
            let mut lengths = [0u8; 288];
            lengths[..144].fill(8);
            lengths[144..256].fill(9);
            lengths[256..280].fill(7);
            lengths[280..288].fill(8);
            Self::build(&lengths).expect("fixed RFC 1951 lit/len table is valid")
        })
    }

    fn fixed_dist() -> &'static Self {
        static TABLE: OnceLock<HuffmanTable> = OnceLock::new();
        TABLE.get_or_init(|| {
            Self::build(&[5u8; 32]).expect("fixed RFC 1951 distance table is valid")
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum CheckerState {
    BlockHeader,
    StoredLen,
    StoredData(usize),
    DynamicHeader,
    DynamicCodeLenLengths,
    DynamicLengths,
    DynamicLengthRepeat(u16),
    Symbol,
    LenExtra(u8),
    DistSymbol,
    DistExtra { base: u16, extra: u8 },
    StreamEnd,
}

/// Streaming RFC 1951 DEFLATE bitstream validator that enforces a maximum
/// LZ77 back-reference distance (`<= 2^decompress_window_bits`) across
/// fragments and context-takeover messages without restricting output
/// batching.
struct DeflateWindowChecker {
    max_distance: usize,
    bitbuf: BitBuf,
    state: CheckerState,
    block_final: bool,
    use_fixed: bool,
    hlit: usize,
    hdist: usize,
    hclen: usize,
    idx: usize,
    cl_lengths: [u8; 19],
    lengths: [u8; 320],
    cl: HuffmanTable,
    litlen: HuffmanTable,
    dist: HuffmanTable,
}

impl fmt::Debug for DeflateWindowChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeflateWindowChecker")
            .field("max_distance", &self.max_distance)
            .field("state", &self.state)
            .finish()
    }
}

impl DeflateWindowChecker {
    fn new(max_distance: usize) -> Self {
        DeflateWindowChecker {
            max_distance,
            bitbuf: BitBuf::default(),
            state: CheckerState::BlockHeader,
            block_final: false,
            use_fixed: false,
            hlit: 0,
            hdist: 0,
            hclen: 0,
            idx: 0,
            cl_lengths: [0; 19],
            lengths: [0; 320],
            cl: HuffmanTable::default(),
            litlen: HuffmanTable::default(),
            dist: HuffmanTable::default(),
        }
    }

    fn reset(&mut self) {
        self.bitbuf = BitBuf::default();
        self.state = CheckerState::BlockHeader;
        self.block_final = false;
        self.use_fixed = false;
    }

    fn check(&mut self, mut input: &[u8]) -> Result<()> {
        loop {
            match self.state {
                CheckerState::StreamEnd => return Ok(()),
                CheckerState::StoredData(mut remaining) => {
                    while remaining > 0 && self.bitbuf.nbits >= 8 {
                        self.bitbuf.bits >>= 8;
                        self.bitbuf.nbits -= 8;
                        remaining -= 1;
                    }
                    let skip = remaining.min(input.len());
                    input = &input[skip..];
                    remaining -= skip;
                    if remaining == 0 {
                        self.state = if self.block_final {
                            CheckerState::StreamEnd
                        } else {
                            CheckerState::BlockHeader
                        };
                    } else {
                        self.state = CheckerState::StoredData(remaining);
                        return Ok(());
                    }
                }
                CheckerState::BlockHeader => {
                    self.bitbuf.fill(&mut input);
                    let Some(hdr) = self.bitbuf.take(3) else {
                        return Ok(());
                    };
                    self.block_final = (hdr & 1) != 0;
                    match (hdr >> 1) & 3 {
                        0 => {
                            self.bitbuf.align_byte();
                            self.state = CheckerState::StoredLen;
                        }
                        1 => {
                            self.use_fixed = true;
                            self.state = CheckerState::Symbol;
                        }
                        2 => {
                            self.use_fixed = false;
                            self.state = CheckerState::DynamicHeader;
                        }
                        _ => return Err(invalid_deflate("invalid DEFLATE block type")),
                    }
                }
                CheckerState::StoredLen => {
                    self.bitbuf.fill(&mut input);
                    let Some(words) = self.bitbuf.take(32) else {
                        return Ok(());
                    };
                    let len = (words & 0xffff) as u16;
                    let nlen = ((words >> 16) & 0xffff) as u16;
                    if len != !nlen {
                        return Err(invalid_deflate("invalid stored block length"));
                    }
                    self.state = CheckerState::StoredData(len as usize);
                }
                CheckerState::DynamicHeader => {
                    self.bitbuf.fill(&mut input);
                    let Some(hdr) = self.bitbuf.take(14) else {
                        return Ok(());
                    };
                    self.hlit = ((hdr & 0x1f) as usize) + 257;
                    self.hdist = (((hdr >> 5) & 0x1f) as usize) + 1;
                    self.hclen = (((hdr >> 10) & 0x0f) as usize) + 4;
                    if self.hlit > 286 || self.hdist > 32 {
                        return Err(invalid_deflate("invalid dynamic Huffman header"));
                    }
                    self.cl_lengths = [0; 19];
                    self.idx = 0;
                    self.state = CheckerState::DynamicCodeLenLengths;
                }
                CheckerState::DynamicCodeLenLengths => {
                    if self.idx == self.hclen {
                        self.cl = HuffmanTable::build(&self.cl_lengths)?;
                        self.lengths[..self.hlit + self.hdist].fill(0);
                        self.idx = 0;
                        self.state = CheckerState::DynamicLengths;
                        continue;
                    }
                    self.bitbuf.fill(&mut input);
                    let Some(bits) = self.bitbuf.take(3) else {
                        return Ok(());
                    };
                    self.cl_lengths[CL_ORDER[self.idx]] = bits as u8;
                    self.idx += 1;
                }
                CheckerState::DynamicLengths => {
                    if self.idx == self.hlit + self.hdist {
                        self.litlen = HuffmanTable::build(&self.lengths[..self.hlit])?;
                        self.dist =
                            HuffmanTable::build(&self.lengths[self.hlit..self.hlit + self.hdist])?;
                        self.state = CheckerState::Symbol;
                        continue;
                    }
                    self.bitbuf.fill(&mut input);
                    let Some(sym) = self.bitbuf.decode(&self.cl)? else {
                        return Ok(());
                    };
                    match sym {
                        0..=15 => {
                            self.lengths[self.idx] = sym as u8;
                            self.idx += 1;
                        }
                        16..=18 => {
                            self.state = CheckerState::DynamicLengthRepeat(sym);
                        }
                        _ => return Err(invalid_deflate("invalid code length symbol")),
                    }
                }
                CheckerState::DynamicLengthRepeat(sym) => {
                    self.bitbuf.fill(&mut input);
                    let (extra_bits, base, val) = match sym {
                        16 => {
                            if self.idx == 0 {
                                return Err(invalid_deflate("invalid Huffman length repeat"));
                            }
                            (2, 3, self.lengths[self.idx - 1])
                        }
                        17 => (3, 3, 0),
                        18 => (7, 11, 0),
                        _ => return Err(invalid_deflate("invalid code length symbol")),
                    };
                    let Some(extra) = self.bitbuf.take(extra_bits) else {
                        return Ok(());
                    };
                    let count = base + extra as usize;
                    if self.idx + count > self.hlit + self.hdist {
                        return Err(invalid_deflate("Huffman code lengths exceed table size"));
                    }
                    self.lengths[self.idx..self.idx + count].fill(val);
                    self.idx += count;
                    self.state = CheckerState::DynamicLengths;
                }
                CheckerState::Symbol => {
                    self.bitbuf.fill(&mut input);
                    let table = if self.use_fixed {
                        HuffmanTable::fixed_litlen()
                    } else {
                        &self.litlen
                    };
                    let Some(sym) = self.bitbuf.decode(table)? else {
                        return Ok(());
                    };
                    match sym {
                        0..=255 => {}
                        256 => {
                            self.state = if self.block_final {
                                CheckerState::StreamEnd
                            } else {
                                CheckerState::BlockHeader
                            };
                        }
                        257..=285 => {
                            let extra = LEN_EXTRA[(sym - 257) as usize];
                            self.state = if extra > 0 {
                                CheckerState::LenExtra(extra)
                            } else {
                                CheckerState::DistSymbol
                            };
                        }
                        _ => return Err(invalid_deflate("invalid literal/length symbol")),
                    }
                }
                CheckerState::LenExtra(extra) => {
                    self.bitbuf.fill(&mut input);
                    if self.bitbuf.take(extra).is_none() {
                        return Ok(());
                    }
                    self.state = CheckerState::DistSymbol;
                }
                CheckerState::DistSymbol => {
                    self.bitbuf.fill(&mut input);
                    let table = if self.use_fixed {
                        HuffmanTable::fixed_dist()
                    } else {
                        &self.dist
                    };
                    let Some(dsym) = self.bitbuf.decode(table)? else {
                        return Ok(());
                    };
                    if dsym >= 30 {
                        return Err(invalid_deflate("invalid distance symbol"));
                    }
                    let base = DIST_BASE[dsym as usize];
                    let extra = DIST_EXTRA[dsym as usize];
                    if extra == 0 {
                        if base as usize > self.max_distance {
                            return Err(invalid_deflate(
                                "back-reference distance exceeds negotiated window",
                            ));
                        }
                        self.state = CheckerState::Symbol;
                    } else {
                        self.state = CheckerState::DistExtra { base, extra };
                    }
                }
                CheckerState::DistExtra { base, extra } => {
                    self.bitbuf.fill(&mut input);
                    let Some(extra_val) = self.bitbuf.take(extra) else {
                        return Ok(());
                    };
                    let dist = base as usize + extra_val as usize;
                    if dist > self.max_distance {
                        return Err(invalid_deflate(
                            "back-reference distance exceeds negotiated window",
                        ));
                    }
                    self.state = CheckerState::Symbol;
                }
            }
        }
    }
}
