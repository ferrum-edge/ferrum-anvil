//! The vendored tungstenite's RFC 7692 permessage-deflate codec
//! (vendor/README.md), driven through tungstenite's public API over
//! in-memory streams. Received frames use the RFC's own examples (§7.2.3)
//! or are built here with a raw DEFLATE encoder; sent frames are unmasked
//! and inflated here, independently of the codec.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use std::io::{self, Cursor, Read, Write};
use tungstenite::error::{CapacityError, Error, ProtocolError};
use tungstenite::protocol::{DeflateConfig, Message, Role, WebSocket, WebSocketConfig};

struct Mock {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for Mock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Mock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn client(input: Vec<u8>, deflate: Option<DeflateConfig>, max: usize) -> WebSocket<Mock> {
    let cfg = WebSocketConfig::default().max_message_size(Some(max)).max_frame_size(Some(max)).deflate(deflate);
    WebSocket::from_raw_socket(Mock { input: Cursor::new(input), output: Vec::new() }, Role::Client, Some(cfg))
}

fn negotiated() -> Option<DeflateConfig> {
    Some(DeflateConfig::default())
}

/// Concatenated unmasked server frames.
fn frames(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// One unmasked server frame.
fn frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![first];
    match payload.len() {
        n if n < 126 => f.push(n as u8),
        n if n <= u16::MAX as usize => {
            f.push(126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(payload);
    f
}

/// Raw DEFLATE with a sync flush and the RFC 7692 tail removed.
fn deflate_raw(data: &[u8], bits: u8) -> Vec<u8> {
    let mut c = Compress::new_with_window_bits(Compression::best(), false, bits);
    let mut out = Vec::with_capacity(data.len() + 64);
    loop {
        if out.capacity() - out.len() < 64 {
            out.reserve(out.capacity().max(64));
        }
        let consumed = c.total_in() as usize;
        c.compress_vec(&data[consumed..], &mut out, FlushCompress::Sync).unwrap();
        if c.total_in() as usize == data.len() && out.len() < out.capacity() {
            break;
        }
    }
    assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
    out.truncate(out.len() - 4);
    out
}

/// Parsed client frame: (fin, rsv1, opcode, unmasked payload).
fn client_frames(mut wire: &[u8]) -> Vec<(bool, bool, u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !wire.is_empty() {
        let (b0, b1) = (wire[0], wire[1]);
        assert!(b1 & 0x80 != 0, "client frames are masked");
        let (len, mut at) = match b1 & 0x7f {
            126 => (u16::from_be_bytes([wire[2], wire[3]]) as usize, 4),
            127 => (u64::from_be_bytes(wire[2..10].try_into().unwrap()) as usize, 10),
            n => (n as usize, 2),
        };
        let mask = [wire[at], wire[at + 1], wire[at + 2], wire[at + 3]];
        at += 4;
        let payload: Vec<u8> = wire[at..at + len].iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect();
        out.push((b0 & 0x80 != 0, b0 & 0x40 != 0, b0 & 0x0f, payload));
        wire = &wire[at + len..];
    }
    out
}

/// Inflate one permessage-deflate payload (appending the tail) with `d`.
fn inflate(d: &mut Decompress, payload: &[u8]) -> Vec<u8> {
    let mut input = payload.to_vec();
    input.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut out = Vec::with_capacity(1 << 20);
    let start = d.total_in();
    while ((d.total_in() - start) as usize) < input.len() {
        let consumed = (d.total_in() - start) as usize;
        d.decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync).unwrap();
        if out.capacity() == out.len() {
            out.reserve(1 << 20);
        }
    }
    out
}

const HELLO: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

#[test]
fn rfc7692_7_2_3_1_single_block_and_fragments() {
    let mut ws = client(frames(&[&[0xc1, 0x07], HELLO]), negotiated(), 1024);
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    let mut ws = client(frames(&[&[0x41, 0x03, 0xf2, 0x48, 0xcd], &[0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00]]), negotiated(), 1024);
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
}

#[test]
fn rfc7692_7_2_3_2_context_takeover_and_its_absence() {
    // With context takeover the second "Hello" refers back into the first message.
    let takeover = frames(&[&[0xc1, 0x07], HELLO, &[0xc1, 0x05, 0xf2, 0x00, 0x11, 0x00, 0x00]]);
    let mut ws = client(takeover.clone(), negotiated(), 1024);
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    // A peer that promised no context takeover must not do that: the reset
    // decompressor cannot resolve the back-reference.
    let cfg = DeflateConfig { decompress_no_context_takeover: true, ..DeflateConfig::default() };
    let mut ws = client(takeover, Some(cfg), 1024);
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::InvalidCompressedMessage(_)))));
    // Without context takeover each message stands alone.
    let mut ws = client(frames(&[&[0xc1, 0x07], HELLO, &[0xc1, 0x07], HELLO]), Some(cfg), 1024);
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
}

#[test]
fn rfc7692_7_2_3_3_to_6_stored_final_two_blocks_and_empty() {
    let stored = frames(&[&[0xc1, 0x0b, 0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00]]);
    assert_eq!(client(stored, negotiated(), 1024).read().unwrap(), Message::Text("Hello".into()));
    // BFINAL = 1: the stream ends inside the message; the next message starts afresh.
    let bfinal = frames(&[&[0xc1, 0x08, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00], &[0xc1, 0x07], HELLO]);
    let mut ws = client(bfinal, negotiated(), 1024);
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    let two = frames(&[&[0xc1, 0x0d, 0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00]]);
    assert_eq!(client(two, negotiated(), 1024).read().unwrap(), Message::Text("Hello".into()));
    // An empty message: the single 0x00 octet (§7.2.3.6), or no payload at
    // all; neither disturbs the shared window the next message refers to.
    let empty = frames(&[&[0xc1, 0x07], HELLO, &[0xc1, 0x01, 0x00], &[0xc2, 0x00], &[0xc1, 0x05, 0xf2, 0x00, 0x11, 0x00, 0x00]]);
    let mut ws = client(empty, negotiated(), 1024);
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    assert_eq!(ws.read().unwrap(), Message::Text("".into()));
    assert_eq!(ws.read().unwrap(), Message::Binary(Vec::new().into()));
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
}

#[test]
fn uncompressed_messages_and_control_frames_under_deflate() {
    let input = frames(&[&[0x81, 0x05], b"Hello", &[0x89, 0x01, 0x07], &[0x01, 0x02], b"He", &[0x80, 0x03], b"llo"]);
    let mut ws = client(input, negotiated(), 1024);
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    assert_eq!(ws.read().unwrap(), Message::Ping(vec![7].into()));
    assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
}

#[test]
fn rsv1_rules() {
    // A compressed message although nothing was negotiated.
    let mut ws = client(frames(&[&[0xc1, 0x07], HELLO]), None, 1024);
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::CompressedMessageNotNegotiated))));
    // RSV1 on a control frame or on a continuation frame (RFC 7692 §6).
    let mut ws = client(vec![0xc9, 0x00], negotiated(), 1024);
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::NonZeroReservedBits))));
    let mut ws = client(frames(&[&[0x41, 0x03, 0xf2, 0x48, 0xcd], &[0xc0, 0x04, 0xc9, 0xc9, 0x07, 0x00]]), negotiated(), 1024);
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::NonZeroReservedBits))));
    // RSV2 stays undefined.
    let mut ws = client(frames(&[&[0xa1, 0x07], HELLO]), negotiated(), 1024);
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::NonZeroReservedBits))));
}

#[test]
fn undecodable_payload_and_invalid_utf8_after_decompression() {
    let mut ws = client(frame(0xc1, &[0xff, 0xff, 0xff, 0xff]), negotiated(), 1024);
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::InvalidCompressedMessage(_)))));
    let mut ws = client(frame(0xc1, &deflate_raw(&[0xc3, 0x28], 15)), negotiated(), 1024);
    assert!(matches!(ws.read(), Err(Error::Utf8(_))));
}

#[test]
fn the_message_limit_applies_after_decompression() {
    // 8 MiB of zeros deflate to a few KiB: far below the 64 KiB limit on the wire.
    let bomb = deflate_raw(&vec![0u8; 8 << 20], 15);
    assert!(bomb.len() < 16 * 1024, "{}", bomb.len());
    let mut ws = client(frame(0xc2, &bomb), negotiated(), 64 * 1024);
    match ws.read() {
        Err(Error::Capacity(CapacityError::DecompressedMessageTooLong { compressed_size, max_size })) => {
            assert_eq!((compressed_size, max_size), (bomb.len(), 64 * 1024));
        }
        other => panic!("{other:?}"),
    }
    // The same across fragments: the limit counts every fragment's output.
    let (a, b) = bomb.split_at(bomb.len() / 2);
    let mut ws = client(frames(&[&frame(0x42, a), &frame(0x80, b)]), negotiated(), 64 * 1024);
    assert!(matches!(ws.read(), Err(Error::Capacity(CapacityError::DecompressedMessageTooLong { .. }))));
    // Exactly at the limit is fine.
    let exact = deflate_raw(&vec![b'a'; 64 * 1024], 15);
    assert_eq!(client(frame(0xc1, &exact), negotiated(), 64 * 1024).read().unwrap().len(), 64 * 1024);
}

/// Pseudo-random bytes (xorshift32), which DEFLATE cannot shrink.
fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

#[test]
fn any_peer_window_up_to_2_15_decodes() {
    // A 2 KiB block repeated: the repeat refers 2 KiB back.
    let block = noise(2048, 0);
    let data = [block.clone(), block].concat();
    for bits in [9, 12, 15] {
        let payload = deflate_raw(&data, bits);
        assert_eq!(client(frame(0xc2, &payload), negotiated(), 1 << 20).read().unwrap().into_data().as_ref(), &data[..], "{bits}");
    }
}

#[test]
fn outgoing_data_is_compressed_with_the_negotiated_context_and_window() {
    let text: String = noise(4096, 7).iter().map(|b| (b'a' + b % 26) as char).collect();
    // Context takeover: the second copy is a back-reference, so it is tiny.
    let mut ws = client(vec![], negotiated(), 1 << 20);
    ws.send(Message::Text(text.clone().into())).unwrap();
    ws.send(Message::Text(text.clone().into())).unwrap();
    ws.send(Message::Ping(vec![1, 2].into())).unwrap();
    ws.send(Message::Binary(Vec::new().into())).unwrap();
    ws.send(Message::Text(text.clone().into())).unwrap();
    let sent = client_frames(&ws.get_ref().output);
    assert_eq!(sent.len(), 5);
    let mut d = Decompress::new(false);
    for (fin, rsv1, op, payload) in &sent[..2] {
        assert!(*fin && *rsv1 && *op == 1);
        assert_eq!(inflate(&mut d, payload), text.as_bytes());
    }
    assert!(sent[1].3.len() < sent[0].3.len() / 4, "{} vs {}", sent[1].3.len(), sent[0].3.len());
    assert_eq!((sent[2].1, sent[2].2), (false, 9), "control frames are never compressed");
    assert_eq!((sent[3].1, sent[3].2, sent[3].3.as_slice()), (true, 2, &[0x00][..]), "an empty message is the single 0x00 octet");
    assert!(inflate(&mut d, &sent[3].3).is_empty());
    assert_eq!(inflate(&mut d, &sent[4].3), text.as_bytes(), "the shared window survives the empty message");

    // No context takeover: every message inflates with a fresh decompressor.
    let cfg = DeflateConfig { compress_no_context_takeover: true, ..DeflateConfig::default() };
    let mut ws = client(vec![], Some(cfg), 1 << 20);
    ws.send(Message::Text(text.clone().into())).unwrap();
    ws.send(Message::Text(text.clone().into())).unwrap();
    for (_, rsv1, _, payload) in client_frames(&ws.get_ref().output) {
        assert!(rsv1);
        assert_eq!(inflate(&mut Decompress::new(false), &payload), text.as_bytes());
    }

    // A 2^9 window: the 2 KiB repeat cannot be a back-reference, so the
    // message stays incompressible; with 2^15 it shrinks to about half.
    let block = noise(2048, 3);
    let data = [block.clone(), block].concat();
    let size = |bits: u8| {
        let cfg = DeflateConfig { compress_window_bits: bits, ..DeflateConfig::default() };
        let mut ws = client(vec![], Some(cfg), 1 << 20);
        ws.send(Message::Binary(data.clone().into())).unwrap();
        let sent = client_frames(&ws.get_ref().output);
        assert_eq!(inflate(&mut Decompress::new(false), &sent[0].3), data);
        sent[0].3.len()
    };
    let (narrow, wide) = (size(9), size(15));
    assert!(narrow > data.len() * 9 / 10 && wide < data.len() * 6 / 10, "window 9: {narrow} B, window 15: {wide} B");
}

#[test]
fn outgoing_data_stays_uncompressed_when_compression_is_off_or_impossible() {
    for cfg in [
        DeflateConfig { compress: false, ..DeflateConfig::default() },
        DeflateConfig { compress_window_bits: 8, ..DeflateConfig::default() },
    ] {
        let mut ws = client(frames(&[&[0xc1, 0x07], HELLO]), Some(cfg), 1024);
        ws.send(Message::Text("Hello".into())).unwrap();
        let sent = client_frames(&ws.get_ref().output);
        assert_eq!((sent[0].1, sent[0].3.as_slice()), (false, &b"Hello"[..]));
        // Incoming compressed messages are still decoded.
        assert_eq!(ws.read().unwrap(), Message::Text("Hello".into()));
    }
}
