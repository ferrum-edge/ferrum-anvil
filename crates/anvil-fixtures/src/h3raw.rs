//! A raw HTTP/3 origin for tests of the client's own limits.
//!
//! It writes hand-built frames (RFC 9114 §7) with QPACK static-table field
//! lines (RFC 9204 §4.5) instead of going through h3, so it can send what a
//! conforming server library would not: a HEADERS frame that declares more
//! than the client accepts, a field section over the client's
//! `SETTINGS_MAX_FIELD_SECTION_SIZE`, a body that never ends, or trailers
//! with no end of stream after them.
//!
//! Its SETTINGS enable extended CONNECT (RFC 9220 §3), so a MASQUE client
//! sends its request. It never parses a request and answers as soon as the
//! stream opens: request `n` on a connection gets `answers[n]` (the last one
//! once they run out). It records the `SETTINGS_MAX_FIELD_SECTION_SIZE` each
//! client advertised, how many answers it wrote in full and the code of every
//! `STOP_SENDING` it received.

use crate::tlsserver::{TlsServerOptions, server_config};
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// HTTP/3 frame types (RFC 9114 §7.2).
pub const DATA: u64 = 0x0;
pub const HEADERS: u64 = 0x1;

/// QPACK static-table entries (RFC 9204 Appendix A) used by the answers.
pub const STATUS_200: u8 = 25;
pub const ACCEPT_RANGES_BYTES: u8 = 32;
pub const ETAG: u8 = 7;

/// How an answer ends once its bytes are written.
#[derive(Clone, Copy, Debug)]
pub enum End {
    /// The stream ends (FIN).
    Finish,
    /// The stream stays open until the client stops it.
    Hold,
    /// One more DATA frame of one byte every interval, until the client
    /// stops the stream.
    Drip(Duration),
}

/// What a request stream gets.
#[derive(Clone, Debug)]
pub struct Answer {
    pub bytes: Vec<u8>,
    pub end: End,
}

pub struct RawH3 {
    pub addr: SocketAddr,
    advertised: Arc<Mutex<Vec<u64>>>,
    stops: Arc<Mutex<Vec<u64>>>,
    written: Arc<AtomicUsize>,
    endpoint: quinn::Endpoint,
}

impl RawH3 {
    /// The `SETTINGS_MAX_FIELD_SECTION_SIZE` of each client's SETTINGS frame,
    /// in arrival order (a client that sent none is not listed).
    pub fn advertised(&self) -> Vec<u64> {
        self.advertised.lock().clone()
    }

    /// Wait up to `within` until some client advertised its field-section
    /// limit, and return the first one.
    pub async fn first_advertised(&self, within: Duration) -> Option<u64> {
        let until = Instant::now() + within;
        loop {
            if let Some(v) = self.advertised.lock().first() {
                return Some(*v);
            }
            if Instant::now() >= until {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Wait up to `within` until the bytes of `n` answers were all written
    /// (handed to QUIC, before the stream ends or is held open).
    pub async fn wrote(&self, n: usize, within: Duration) -> bool {
        let until = Instant::now() + within;
        while self.written.load(Ordering::SeqCst) < n {
            if Instant::now() >= until {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    /// Wait up to `within` for the first `STOP_SENDING` a client sent on a
    /// request stream, and return its code.
    pub async fn first_stop(&self, within: Duration) -> Option<u64> {
        let until = Instant::now() + within;
        loop {
            if let Some(v) = self.stops.lock().first() {
                return Some(*v);
            }
            if Instant::now() >= until {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for RawH3 {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"fixture shutdown");
    }
}

/// Serve `answers` over HTTP/3 on a loopback port.
pub async fn serve(mut tls: TlsServerOptions, answers: Vec<Answer>) -> anyhow::Result<RawH3> {
    tls.alpn = vec!["h3".into()];
    tls.tls13_only = true;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config(&tls)?)?;
    let endpoint = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;
    let advertised = Arc::new(Mutex::new(Vec::new()));
    let stops = Arc::new(Mutex::new(Vec::new()));
    let written = Arc::new(AtomicUsize::new(0));
    let answers = Arc::new(answers);
    let (ep, adv, st, wr) = (endpoint.clone(), advertised.clone(), stops.clone(), written.clone());
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let (answers, adv, st, wr) = (answers.clone(), adv.clone(), st.clone(), wr.clone());
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                tokio::spawn(read_client_settings(conn.clone(), adv));
                // The control stream: its type, then SETTINGS with
                // SETTINGS_ENABLE_CONNECT_PROTOCOL = 1. It stays open while the
                // connection is served.
                let Ok(mut control) = conn.open_uni().await else { return };
                let mut first = vec![0x00];
                first.extend(frame(0x04, &[0x08, 0x01]));
                if control.write_all(&first).await.is_err() {
                    return;
                }
                let mut n = 0usize;
                while let Ok((send, recv)) = conn.accept_bi().await {
                    let Some(answer) = answers.get(n.min(answers.len().saturating_sub(1))).cloned() else { return };
                    n += 1;
                    tokio::spawn(answer_stream(send, recv, answer, st.clone(), wr.clone()));
                }
                drop(control);
            });
        }
    });
    Ok(RawH3 { addr, advertised, stops, written, endpoint })
}

async fn answer_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    answer: Answer,
    stops: Arc<Mutex<Vec<u64>>>,
    written: Arc<AtomicUsize>,
) {
    // The request is read and ignored (a CONNECT stream never ends).
    tokio::spawn(async move {
        let _ = recv.read_to_end(64 * 1024).await;
    });
    if send.write_all(&answer.bytes).await.is_err() {
        return record_stop(&send, &stops).await;
    }
    written.fetch_add(1, Ordering::SeqCst);
    match answer.end {
        End::Finish => {
            let _ = send.finish();
            let _ = send.stopped().await;
        }
        End::Hold => record_stop(&send, &stops).await,
        End::Drip(every) => loop {
            tokio::time::sleep(every).await;
            if send.write_all(&frame(DATA, b"x")).await.is_err() {
                return record_stop(&send, &stops).await;
            }
        },
    }
}

async fn record_stop(send: &quinn::SendStream, stops: &Mutex<Vec<u64>>) {
    if let Ok(Some(code)) = send.stopped().await {
        stops.lock().push(code.into_inner());
    }
}

/// Record the `SETTINGS_MAX_FIELD_SECTION_SIZE` (0x06) of the client's
/// control stream.
async fn read_client_settings(conn: quinn::Connection, advertised: Arc<Mutex<Vec<u64>>>) {
    while let Ok(mut recv) = conn.accept_uni().await {
        let advertised = advertised.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            while let Ok(Some(chunk)) = recv.read_chunk(4096, true).await {
                buf.extend_from_slice(&chunk.bytes);
                match control_settings(&buf) {
                    Parsed::Incomplete if buf.len() < 64 * 1024 => {}
                    Parsed::Incomplete | Parsed::NotControl => return,
                    Parsed::Settings(settings) => {
                        if let Some((_, v)) = settings.iter().find(|(id, _)| *id == 0x06) {
                            advertised.lock().push(*v);
                        }
                        return;
                    }
                }
            }
        });
    }
}

enum Parsed {
    Incomplete,
    NotControl,
    Settings(Vec<(u64, u64)>),
}

/// The SETTINGS at the start of a control stream (type 0x00, then a SETTINGS
/// frame, RFC 9114 §6.2.1).
fn control_settings(buf: &[u8]) -> Parsed {
    let Some((ty, a)) = read_varint(buf) else { return Parsed::Incomplete };
    if ty != 0x00 {
        return Parsed::NotControl;
    }
    let Some((frame_type, b)) = read_varint(&buf[a..]) else { return Parsed::Incomplete };
    if frame_type != 0x04 {
        return Parsed::NotControl;
    }
    let Some((len, c)) = read_varint(&buf[a + b..]) else { return Parsed::Incomplete };
    let start = a + b + c;
    let Some(payload) = usize::try_from(len).ok().and_then(|len| buf.get(start..start.checked_add(len)?)) else {
        return Parsed::Incomplete;
    };
    let mut settings = Vec::new();
    let mut p = payload;
    while let Some((id, n)) = read_varint(p) {
        let Some((v, m)) = read_varint(&p[n..]) else { break };
        settings.push((id, v));
        p = &p[n + m..];
    }
    Parsed::Settings(settings)
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let v = bytes[1..].iter().fold(u64::from(first & 0x3f), |v, b| (v << 8) | u64::from(*b));
    Some((v, len))
}

/// Append `v` as an HTTP/3 variable-length integer (RFC 9000 §16).
pub fn varint(out: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// A frame header declaring a payload of `len` bytes.
pub fn frame_header(ty: u64, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(&mut out, ty);
    varint(&mut out, len);
    out
}

/// A whole frame.
pub fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = frame_header(ty, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

/// A QPACK field section of `lines` that uses no dynamic table (Required
/// Insert Count 0, Base 0).
pub fn field_section(lines: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    out.extend_from_slice(lines);
    out
}

/// An indexed field line for static entry `index` (below 64).
pub fn indexed(index: u8) -> u8 {
    0xc0 | index
}

/// A literal field line with the name of static entry `index` (below 15)
/// and `value` sent as it is (no Huffman coding).
pub fn literal(out: &mut Vec<u8>, index: u8, value: &[u8]) {
    out.push(0x50 | index);
    prefix_int(out, 7, value.len());
    out.extend_from_slice(value);
}

/// A QPACK prefixed integer with a `bits`-bit prefix and no flags (RFC 7541 §5.1).
fn prefix_int(out: &mut Vec<u8>, bits: u32, v: usize) {
    let max = (1usize << bits) - 1;
    if v < max {
        out.push(v as u8);
        return;
    }
    out.push(max as u8);
    let mut rest = v - max;
    while rest >= 0x80 {
        out.push((rest & 0x7f) as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}
