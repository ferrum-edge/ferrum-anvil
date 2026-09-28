//! A cleartext HTTP/2 origin (h2c, prior knowledge) written frame by frame,
//! for what an `h2` server cannot be told to do: refuse a request it read
//! whole without processing it (RFC 9113 §8.7). On its first connection it
//! answers the first request `200`, then refuses the second one, which
//! reuses the connection, as [`Refusal`] says. Every other request is
//! answered `200`. Header blocks are not decoded; a response is one HEADERS
//! frame, `:status: 200`, with no body.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// How the second request on the first connection is refused, once the
/// whole of it arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `RST_STREAM` with `REFUSED_STREAM` on its stream.
    RefusedStream,
    /// A graceful `GOAWAY` (`NO_ERROR`) whose last-stream-id is the first
    /// request's stream, so the second one is above it. The connection stays
    /// open until the client closes it.
    GoAway,
}

pub struct RefusingOrigin {
    pub addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    cancel: CancellationToken,
}

impl RefusingOrigin {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    /// Connections accepted.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Requests read whole, the refused one included.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for RefusingOrigin {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const CONTINUATION: u8 = 0x9;
/// `END_STREAM` on DATA and HEADERS, `ACK` on SETTINGS and PING.
const END_STREAM_OR_ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const NO_ERROR: u32 = 0x0;
const REFUSED_STREAM: u32 = 0x7;
/// HPACK: static table entry 8, `:status: 200` (RFC 7541 Appendix A).
const STATUS_200: u8 = 0x88;

/// Start the origin on 127.0.0.1.
pub async fn serve(refusal: Refusal) -> anyhow::Result<RefusingOrigin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let (conns, reqs, c) = (connections.clone(), requests.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (sock, _) = tokio::select! {
                _ = c.cancelled() => return,
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
            };
            let first = conns.fetch_add(1, Ordering::SeqCst) == 0;
            let (reqs, c) = (reqs.clone(), c.clone());
            tokio::spawn(async move {
                tokio::select! {
                    _ = connection(sock, first.then_some(refusal), &reqs) => {}
                    _ = c.cancelled() => {}
                }
            });
        }
    });
    Ok(RefusingOrigin { addr, connections, requests, cancel })
}

/// One frame: its type, flags, stream and payload.
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

async fn read_frame(sock: &mut TcpStream) -> std::io::Result<Frame> {
    let mut head = [0u8; 9];
    sock.read_exact(&mut head).await?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload).await?;
    Ok(Frame { kind: head[3], flags: head[4], stream, payload })
}

async fn write_frame(sock: &mut TcpStream, kind: u8, flags: u8, stream: u32, payload: &[u8]) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(9 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    buf.push(kind);
    buf.push(flags);
    buf.extend_from_slice(&stream.to_be_bytes());
    buf.extend_from_slice(payload);
    sock.write_all(&buf).await
}

/// Serve one connection until the client closes it, refusing its second
/// request when `refusal` is given.
async fn connection(mut sock: TcpStream, refusal: Option<Refusal>, requests: &AtomicUsize) -> std::io::Result<()> {
    let mut preface = [0u8; 24];
    sock.read_exact(&mut preface).await?;
    if preface != PREFACE {
        return Ok(());
    }
    write_frame(&mut sock, SETTINGS, 0, 0, &[]).await?;
    // Requests begun but not yet whole: (header block complete, stream ended).
    let mut partial: HashMap<u32, (bool, bool)> = HashMap::new();
    let mut whole = 0usize;
    let mut first_stream = 0u32;
    loop {
        let f = read_frame(&mut sock).await?;
        match f.kind {
            SETTINGS if f.flags & END_STREAM_OR_ACK == 0 => write_frame(&mut sock, SETTINGS, END_STREAM_OR_ACK, 0, &[]).await?,
            PING if f.flags & END_STREAM_OR_ACK == 0 => write_frame(&mut sock, PING, END_STREAM_OR_ACK, 0, &f.payload).await?,
            HEADERS | CONTINUATION | DATA if f.stream != 0 => {
                let state = partial.entry(f.stream).or_insert((false, false));
                if f.kind != DATA && f.flags & END_HEADERS != 0 {
                    state.0 = true;
                }
                if f.kind != CONTINUATION && f.flags & END_STREAM_OR_ACK != 0 {
                    state.1 = true;
                }
                if *state != (true, true) {
                    continue;
                }
                partial.remove(&f.stream);
                requests.fetch_add(1, Ordering::SeqCst);
                whole += 1;
                if whole == 1 {
                    first_stream = f.stream;
                }
                match refusal {
                    Some(Refusal::RefusedStream) if whole == 2 => {
                        write_frame(&mut sock, RST_STREAM, 0, f.stream, &REFUSED_STREAM.to_be_bytes()).await?;
                    }
                    Some(Refusal::GoAway) if whole == 2 => {
                        let mut goaway = first_stream.to_be_bytes().to_vec();
                        goaway.extend_from_slice(&NO_ERROR.to_be_bytes());
                        write_frame(&mut sock, GOAWAY, 0, 0, &goaway).await?;
                    }
                    Some(Refusal::GoAway) if whole > 2 => {}
                    _ => write_frame(&mut sock, HEADERS, END_HEADERS | END_STREAM_OR_ACK, f.stream, &[STATUS_200]).await?,
                }
            }
            _ => {}
        }
    }
}
