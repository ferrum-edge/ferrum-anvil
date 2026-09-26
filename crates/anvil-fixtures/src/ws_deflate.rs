//! A WebSocket server peer with RFC 7692 `permessage-deflate`, independent of
//! the codec Anvil runs: its own frame reader and writer and raw DEFLATE
//! (flate2), so a mistake shared by Anvil's client and this peer cannot
//! hide. The `/ws` routes of the HTTP fixture (HTTP/1.1 Upgrade, HTTP/2
//! extended CONNECT) and of the HTTP/3 fixture (RFC 9220) hand the session to
//! it when the request offers permessage-deflate or the query names a `pmd`
//! behaviour. It echoes every data message.
//!
//! Query options:
//! * `pmd=accept` (the default) | `decline` (answer no extension) |
//!   `unsolicited` (answer permessage-deflate although nothing was offered) |
//!   `unnegotiated` (answer nothing, but compress every reply anyway)
//! * `pmd_answer=<value>` — answer this `Sec-WebSocket-Extensions` value
//!   verbatim (a malformed or unexpected answer) and run uncompressed
//! * `pmd_server_nct=1`, `pmd_client_nct=1` — add `server_no_context_takeover`
//!   / `client_no_context_takeover` to the answer (both are also echoed when
//!   offered)
//! * `pmd_server_bits=N` — compress with, and announce, a 2^N window
//! * `pmd_client_bits=N` — answer `client_max_window_bits=N`
//! * `pmd_fragment=N` — send compressed replies in N-byte fragments
//! * `pmd_plain_replies=1` — reply uncompressed (RSV1 clear) although negotiated
//! * `pmd_empty=1` — after each echo, send an empty compressed message
//! * `bomb=N` — after the first echo, send one compressed message of N zero bytes
//! * `pmd_corrupt=1` — after the first echo, send an RSV1 message that is not DEFLATE data
//! * `close_after=N` — close with 1000 after N echoes; `max=N` — this peer's
//!   own (decompressed) message limit, answered with 1009
//!
//! Ground truth: the offer received and the answer given
//! ([`GroundTruth::WsExtensions`]), every received data message with its RSV1
//! flag and sizes ([`GroundTruth::WsMessage`], and `MessageReceived` with the
//! decoded size), and what it detects in the client's frames
//! (`FaultApplied`: `ws_client_inflate_failed`, `ws_unnegotiated_rsv1`,
//! `ws_rsv1_on_continuation`, `ws_client_message_too_big`), and the faults
//! it injects itself (`ws_compressed_without_negotiation`,
//! `ws_decompression_bomb`, `ws_corrupt_deflate`).

use crate::log::{GroundTruth, GroundTruthLog};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// How the peer answers and behaves, from the request query.
#[derive(Debug, Clone, Default)]
pub struct Mode {
    pmd: Option<String>,
    answer: Option<String>,
    server_nct: bool,
    client_nct: bool,
    server_bits: Option<u8>,
    client_bits: Option<u8>,
    fragment: Option<usize>,
    plain_replies: bool,
    empty: bool,
    bomb: Option<usize>,
    corrupt: bool,
    close_after: Option<u32>,
    max: Option<usize>,
}

impl Mode {
    /// Parse the (URL-encoded) query string.
    pub fn parse(query: Option<&str>) -> Mode {
        let qs: Vec<(String, String)> = query.map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect()).unwrap_or_default();
        let get = |k: &str| qs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let flag = |k: &str| get(k).as_deref() == Some("1");
        let num = |k: &str| get(k).and_then(|v| v.parse::<usize>().ok());
        Mode {
            pmd: get("pmd"),
            answer: get("pmd_answer"),
            server_nct: flag("pmd_server_nct"),
            client_nct: flag("pmd_client_nct"),
            server_bits: num("pmd_server_bits").map(|b| b as u8),
            client_bits: num("pmd_client_bits").map(|b| b as u8),
            fragment: num("pmd_fragment").filter(|n| *n > 0),
            plain_replies: flag("pmd_plain_replies"),
            empty: flag("pmd_empty"),
            bomb: num("bomb"),
            corrupt: flag("pmd_corrupt"),
            close_after: num("close_after").map(|n| n as u32),
            max: num("max"),
        }
    }

    /// Whether this peer (rather than the plain echo) serves the session.
    pub fn applies(&self, offer: Option<&str>) -> bool {
        self.pmd.is_some()
            || self.answer.is_some()
            || self.bomb.is_some()
            || self.corrupt
            || offer.map(|o| o.to_ascii_lowercase().contains("permessage-deflate")).unwrap_or(false)
    }
}

/// The negotiated session: the answer header and both codec directions.
#[derive(Debug, Clone)]
pub struct Session {
    pub answer: Option<String>,
    deflate: bool,
    /// Compress replies (RSV1) even though nothing was negotiated.
    compress_unnegotiated: bool,
    server_nct: bool,
    client_nct: bool,
    server_bits: u8,
    mode: Mode,
}

/// Offer parameters: `(name, value)` of the first permessage-deflate offer.
fn offer_params(offer: &str) -> Option<Vec<(String, Option<String>)>> {
    offer.split(',').find_map(|ext| {
        let mut parts = ext.split(';');
        if !parts.next()?.trim().eq_ignore_ascii_case("permessage-deflate") {
            return None;
        }
        Some(
            parts
                .map(|p| match p.split_once('=') {
                    Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim().trim_matches('"').to_string())),
                    None => (p.trim().to_ascii_lowercase(), None),
                })
                .collect(),
        )
    })
}

/// Answer the client's offer (`offer` = its `Sec-WebSocket-Extensions`) and
/// record the exchange as ground truth.
pub fn negotiate(offer: Option<&str>, mode: &Mode, log: &GroundTruthLog) -> Session {
    let params = offer.and_then(offer_params);
    let has = |k: &str| params.as_ref().map(|p| p.iter().any(|(n, _)| n == k)).unwrap_or(false);
    let value = |k: &str| params.as_ref().and_then(|p| p.iter().find(|(n, _)| n == k)).and_then(|(_, v)| v.as_ref()?.parse::<u8>().ok());
    let mut s = Session {
        answer: None,
        deflate: false,
        compress_unnegotiated: false,
        server_nct: false,
        client_nct: false,
        server_bits: 15,
        mode: mode.clone(),
    };
    let accept = match mode.pmd.as_deref() {
        _ if mode.answer.is_some() => false,
        Some("decline") => false,
        Some("unnegotiated") => {
            s.compress_unnegotiated = true;
            false
        }
        Some("unsolicited") => true,
        _ => params.is_some(),
    };
    if let Some(raw) = &mode.answer {
        s.answer = Some(raw.clone());
    } else if accept {
        let mut a = String::from("permessage-deflate");
        s.server_nct = has("server_no_context_takeover") || mode.server_nct;
        s.client_nct = has("client_no_context_takeover") || mode.client_nct;
        if s.server_nct {
            a.push_str("; server_no_context_takeover");
        }
        if s.client_nct {
            a.push_str("; client_no_context_takeover");
        }
        let server_bits = match (value("server_max_window_bits"), mode.server_bits) {
            (Some(asked), Some(mine)) => Some(asked.min(mine)),
            (asked, mine) => asked.or(mine),
        };
        if let Some(b) = server_bits {
            a.push_str(&format!("; server_max_window_bits={b}"));
            s.server_bits = b;
        }
        if let Some(b) = mode.client_bits {
            a.push_str(&format!("; client_max_window_bits={b}"));
        }
        s.deflate = true;
        s.answer = Some(a);
    }
    log.push(GroundTruth::WsExtensions { offer: offer.map(str::to_string), answer: s.answer.clone() });
    s
}

struct Frame {
    fin: bool,
    rsv1: bool,
    opcode: u8,
    payload: Vec<u8>,
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<Frame> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).await?;
    let len = match h[1] & 0x7f {
        126 => {
            let mut b = [0u8; 2];
            r.read_exact(&mut b).await?;
            u16::from_be_bytes(b) as u64
        }
        127 => {
            let mut b = [0u8; 8];
            r.read_exact(&mut b).await?;
            u64::from_be_bytes(b)
        }
        n => n as u64,
    };
    if len > max as u64 {
        return Err(std::io::Error::other("frame too large for the fixture"));
    }
    let mut mask = [0u8; 4];
    if h[1] & 0x80 != 0 {
        r.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Ok(Frame { fin: h[0] & 0x80 != 0, rsv1: h[0] & 0x40 != 0, opcode: h[0] & 0x0f, payload })
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, fin: bool, rsv1: bool, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut f = vec![(if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | opcode];
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
    w.write_all(&f).await?;
    w.flush().await
}

/// Raw DEFLATE with a sync flush and the RFC 7692 tail removed (§7.2.1).
fn compress(c: &mut Compress, data: &[u8], reset: bool) -> Vec<u8> {
    let start = c.total_in();
    let mut out = Vec::with_capacity(data.len() + 64);
    loop {
        if out.capacity() - out.len() < 64 {
            out.reserve(out.capacity().max(64));
        }
        let consumed = (c.total_in() - start) as usize;
        if c.compress_vec(&data[consumed..], &mut out, FlushCompress::Sync).is_err() {
            break;
        }
        if (c.total_in() - start) as usize == data.len() && out.len() < out.capacity() {
            break;
        }
    }
    if out.ends_with(&TAIL) {
        out.truncate(out.len() - 4);
    }
    if out.is_empty() {
        out.push(0x00);
    }
    if reset {
        c.reset();
    }
    out
}

/// Inflate one message (§7.2.2), refusing to grow past `limit`.
fn inflate(d: &mut Decompress, payload: &[u8], limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut input = payload.to_vec();
    input.extend_from_slice(&TAIL);
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let mut pos = 0;
    loop {
        let (i0, o0) = (d.total_in(), d.total_out());
        let st = d.decompress(&input[pos..], &mut chunk, FlushDecompress::Sync).map_err(|_| "invalid DEFLATE data")?;
        let read = (d.total_in() - i0) as usize;
        let wrote = (d.total_out() - o0) as usize;
        pos += read;
        out.extend_from_slice(&chunk[..wrote]);
        if out.len() > limit {
            return Err("too big");
        }
        if st == Status::StreamEnd || (pos == input.len() && wrote < chunk.len()) || (read == 0 && wrote == 0) {
            return Ok(out);
        }
    }
}

/// Serve one WebSocket session on an upgraded (or bridged) stream.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(io: S, session: Session, log: GroundTruthLog) {
    let (mut rd, mut wr) = tokio::io::split(io);
    let m = &session.mode;
    let max = m.max.unwrap_or(1 << 20);
    let mut compressor =
        (session.server_bits >= 9).then(|| Compress::new_with_window_bits(Compression::default(), false, session.server_bits));
    let mut decompressor = Decompress::new(false);
    let compress_replies = (session.deflate && !m.plain_replies) || session.compress_unnegotiated;
    // (opcode, compressed, payload, wire bytes) of the message being received.
    let mut current: Option<(u8, bool, Vec<u8>, u64)> = None;
    let mut echoed = 0u32;
    let mut close_sent = false;
    let close = |code: u16, reason: &str| {
        let mut p = code.to_be_bytes().to_vec();
        p.extend_from_slice(reason.as_bytes());
        p
    };
    loop {
        let Ok(f) = read_frame(&mut rd, 64 << 20).await else { return };
        match f.opcode {
            0x8 => {
                // Answer a Close unless this peer started the closing handshake.
                if !close_sent {
                    let code = if f.payload.len() >= 2 { u16::from_be_bytes([f.payload[0], f.payload[1]]) } else { 1000 };
                    let _ = write_frame(&mut wr, true, false, 0x8, &close(code, "")).await;
                }
                let _ = wr.shutdown().await;
                return;
            }
            0x9 => {
                let _ = write_frame(&mut wr, true, false, 0xA, &f.payload).await;
                continue;
            }
            0xA => continue,
            _ => {}
        }
        let fault = |log: &GroundTruthLog, name: &str| log.push(GroundTruth::FaultApplied { fault: name.into() });
        match (f.opcode, current.as_mut()) {
            (1 | 2, None) => {
                if f.rsv1 && !session.deflate {
                    fault(&log, "ws_unnegotiated_rsv1");
                    let _ = write_frame(&mut wr, true, false, 0x8, &close(1002, "unexpected RSV1")).await;
                    return;
                }
                let wire = f.payload.len() as u64;
                current = Some((f.opcode, f.rsv1, f.payload, wire));
            }
            (0, Some(msg)) => {
                if f.rsv1 {
                    fault(&log, "ws_rsv1_on_continuation");
                    let _ = write_frame(&mut wr, true, false, 0x8, &close(1002, "RSV1 on a continuation frame")).await;
                    return;
                }
                msg.3 += f.payload.len() as u64;
                msg.2.extend_from_slice(&f.payload);
            }
            _ => {
                let _ = write_frame(&mut wr, true, false, 0x8, &close(1002, "unexpected frame")).await;
                return;
            }
        }
        if !f.fin {
            continue;
        }
        let (opcode, compressed, payload, wire) = current.take().expect("a message is in progress");
        let data = if compressed {
            match inflate(&mut decompressor, &payload, max) {
                Ok(d) => {
                    if session.client_nct {
                        decompressor.reset(false);
                    }
                    d
                }
                Err("too big") => {
                    fault(&log, "ws_client_message_too_big");
                    let _ = write_frame(&mut wr, true, false, 0x8, &close(1009, "message too big")).await;
                    return;
                }
                Err(_) => {
                    fault(&log, "ws_client_inflate_failed");
                    let _ = write_frame(&mut wr, true, false, 0x8, &close(1002, "invalid compressed data")).await;
                    return;
                }
            }
        } else {
            payload
        };
        if data.len() > max {
            fault(&log, "ws_client_message_too_big");
            let _ = write_frame(&mut wr, true, false, 0x8, &close(1009, "message too big")).await;
            return;
        }
        log.push(GroundTruth::WsMessage { compressed, wire_bytes: wire, bytes: data.len() as u64 });
        log.push(GroundTruth::MessageReceived { bytes: data.len() as u64 });

        // ---- echo (compressed when negotiated), then scripted extras ----
        let mut send = |data: &[u8], compress_it: bool| -> Vec<(bool, bool, u8, Vec<u8>)> {
            let body = match (compress_it, compressor.as_mut()) {
                (true, Some(c)) => Some(compress(c, data, session.server_nct)),
                _ => None,
            };
            let (rsv1, body) = match body {
                Some(b) => (true, b),
                None => (false, data.to_vec()),
            };
            match m.fragment {
                Some(n) if body.len() > n => {
                    let chunks: Vec<&[u8]> = body.chunks(n).collect();
                    let last = chunks.len() - 1;
                    chunks
                        .into_iter()
                        .enumerate()
                        .map(|(i, c)| (i == last, rsv1 && i == 0, if i == 0 { opcode } else { 0 }, c.to_vec()))
                        .collect()
                }
                _ => vec![(true, rsv1, opcode, body)],
            }
        };
        let mut frames = send(&data, compress_replies);
        if session.compress_unnegotiated && echoed == 0 {
            fault(&log, "ws_compressed_without_negotiation");
        }
        if m.empty && session.deflate {
            frames.extend(send(&[], true));
        }
        echoed += 1;
        if echoed == 1 {
            if let Some(n) = m.bomb {
                fault(&log, "ws_decompression_bomb");
                frames.extend(send(&vec![0u8; n], true));
            }
            if m.corrupt {
                fault(&log, "ws_corrupt_deflate");
                frames.push((true, true, 2, vec![0xff, 0xff, 0xff, 0xff]));
            }
        }
        for (fin, rsv1, op, body) in frames {
            if write_frame(&mut wr, fin, rsv1, op, &body).await.is_err() {
                return;
            }
        }
        if m.close_after == Some(echoed) {
            let _ = write_frame(&mut wr, true, false, 0x8, &close(1000, "fixture done")).await;
            close_sent = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_follows_the_offer_and_the_query() {
        let log = GroundTruthLog::default();
        let offer = "permessage-deflate; server_no_context_takeover; server_max_window_bits=10; client_max_window_bits";
        let s = negotiate(Some(offer), &Mode::parse(Some("pmd_server_bits=12&pmd_client_bits=11")), &log);
        assert_eq!(
            s.answer.as_deref(),
            Some("permessage-deflate; server_no_context_takeover; server_max_window_bits=10; client_max_window_bits=11")
        );
        assert!(s.deflate && s.server_nct && s.server_bits == 10);
        let s = negotiate(Some(offer), &Mode::parse(Some("pmd=decline")), &log);
        assert!(s.answer.is_none() && !s.deflate);
        let s = negotiate(None, &Mode::parse(Some("pmd=unsolicited")), &log);
        assert_eq!(s.answer.as_deref(), Some("permessage-deflate"));
        let s = negotiate(Some(offer), &Mode::parse(Some("pmd_answer=permessage-deflate%3B%20mystery")), &log);
        assert_eq!((s.answer.as_deref(), s.deflate), (Some("permessage-deflate; mystery"), false));
        assert_eq!(log.entries().len(), 4);
    }

    #[test]
    fn compress_and_inflate_round_trip_with_the_rfc_example() {
        let mut c = Compress::new_with_window_bits(Compression::default(), false, 15);
        let hello = compress(&mut c, b"Hello", false);
        assert_eq!(inflate(&mut Decompress::new(false), &hello, 100).unwrap(), b"Hello");
        // RFC 7692 §7.2.3.1.
        assert_eq!(inflate(&mut Decompress::new(false), &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], 100).unwrap(), b"Hello");
        assert_eq!(inflate(&mut Decompress::new(false), &compress(&mut c, &[0; 1000], false), 100), Err("too big"));
    }
}
