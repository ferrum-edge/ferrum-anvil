//! Minimal LDAPv3 directory fixture (RFC 4511) for the gateway `ldap_auth`
//! plugin's direct-bind flow: simple BindRequest → BindResponse, base-scope
//! SearchRequest on the bound DN → SearchResultEntry + SearchResultDone, and
//! UnbindRequest. Anything else gets a protocol error. BER is decoded with
//! bounded definite lengths only.
//!
//! It is a protocol-faithful stand-in for a directory, not a directory: DNs
//! must look like `uid=<user>,<suffix>`, passwords are compared in memory,
//! and the ground-truth log never contains a password.

use crate::log::{GroundTruth, GroundTruthLog};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub struct LdapFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    /// user → password.
    pub users: Arc<Mutex<HashMap<String, String>>>,
    pub binds_ok: Arc<AtomicU64>,
    pub binds_rejected: Arc<AtomicU64>,
    cancel: CancellationToken,
}

impl Drop for LdapFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

const RC_SUCCESS: u8 = 0;
const RC_PROTOCOL_ERROR: u8 = 2;
const RC_NO_SUCH_OBJECT: u8 = 32;
const RC_INVALID_CREDENTIALS: u8 = 49;

pub async fn serve(bind: &str, users: &[(&str, &str)]) -> anyhow::Result<LdapFixture> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let users = Arc::new(Mutex::new(users.iter().map(|(u, p)| (u.to_string(), p.to_string())).collect::<HashMap<_, _>>()));
    let (ok, rejected) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let cancel = CancellationToken::new();
    let (l2, u2, ok2, rj2, c2) = (log.clone(), users.clone(), ok.clone(), rejected.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
            let (log, users, ok, rj, cancel) = (l2.clone(), u2.clone(), ok2.clone(), rj2.clone(), c2.clone());
            tokio::spawn(async move {
                tokio::select! {
                    _ = session(stream, log, users, ok, rj) => {}
                    _ = cancel.cancelled() => {}
                }
            });
        }
    });
    Ok(LdapFixture { addr, log, users, binds_ok: ok, binds_rejected: rejected, cancel })
}

// ---------------------------------------------------------------- BER ---

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Parse one TLV at the start of `b`; returns it and the bytes consumed.
fn tlv(b: &[u8]) -> Option<(Tlv<'_>, usize)> {
    let tag = *b.first()?;
    let first = *b.get(1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let value = b.get(hdr..end)?;
    Some((Tlv { tag, value }, end))
}

fn children(mut b: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    while let Some((t, n)) = tlv(b) {
        out.push(t);
        b = &b[n..];
        if out.len() > 64 {
            break;
        }
    }
    out
}

fn enc(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn ldap_result(op: u8, rc: u8, diag: &str) -> Vec<u8> {
    let mut c = enc(0x0a, &[rc]);
    c.extend(enc(0x04, b""));
    c.extend(enc(0x04, diag.as_bytes()));
    enc(op, &c)
}

fn message(msg_id: &[u8], op: Vec<u8>) -> Vec<u8> {
    let mut c = enc(0x02, msg_id);
    c.extend(op);
    enc(0x30, &c)
}

/// `uid=alice,ou=people,...` → `alice`.
fn uid_of(dn: &str) -> Option<String> {
    let first = dn.split(',').next()?.trim();
    let (k, v) = first.split_once('=')?;
    k.trim().eq_ignore_ascii_case("uid").then(|| v.trim().to_string())
}

async fn session(
    mut s: TcpStream,
    log: GroundTruthLog,
    users: Arc<Mutex<HashMap<String, String>>>,
    ok: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
) {
    let mut buf: Vec<u8> = Vec::new();
    let mut bound: Option<String> = None;
    let mut chunk = [0u8; 4096];
    loop {
        // Serve every complete message already buffered.
        while let Some((msg, used)) = tlv(&buf) {
            if msg.tag != 0x30 {
                return;
            }
            let parts = children(msg.value);
            let (Some(id), Some(op)) = (parts.first(), parts.get(1)) else { return };
            let id = id.value.to_vec();
            let reply = match op.tag {
                // BindRequest: version, name, simple [0] password.
                0x60 => {
                    let f = children(op.value);
                    let dn = f.get(1).map(|t| String::from_utf8_lossy(t.value).into_owned()).unwrap_or_default();
                    let pw = f.get(2).filter(|t| t.tag == 0x80).map(|t| String::from_utf8_lossy(t.value).into_owned());
                    let user = uid_of(&dn);
                    let good = match (&user, &pw) {
                        (Some(u), Some(p)) if !p.is_empty() => users.lock().get(u).map(|want| want == p).unwrap_or(false),
                        _ => false,
                    };
                    log.push(GroundTruth::RequestReceived {
                        method: "BIND".into(),
                        path: dn.clone(),
                        body_bytes: 0,
                        headers: vec![("result".into(), if good { "success" } else { "invalid_credentials" }.into())],
                    });
                    if good {
                        ok.fetch_add(1, Ordering::SeqCst);
                        bound = user;
                        message(&id, ldap_result(0x61, RC_SUCCESS, ""))
                    } else {
                        rejected.fetch_add(1, Ordering::SeqCst);
                        bound = None;
                        message(&id, ldap_result(0x61, RC_INVALID_CREDENTIALS, "invalid credentials"))
                    }
                }
                // SearchRequest: base, scope, deref, size, time, typesOnly, filter, attributes.
                0x63 => {
                    let f = children(op.value);
                    let base = f.first().map(|t| String::from_utf8_lossy(t.value).into_owned()).unwrap_or_default();
                    let attrs: Vec<String> = f
                        .last()
                        .filter(|t| t.tag == 0x30)
                        .map(|t| children(t.value).iter().map(|a| String::from_utf8_lossy(a.value).into_owned()).collect())
                        .unwrap_or_default();
                    log.push(GroundTruth::RequestReceived {
                        method: "SEARCH".into(),
                        path: base.clone(),
                        body_bytes: 0,
                        headers: attrs.iter().map(|a| ("attribute".to_string(), a.clone())).collect(),
                    });
                    match (uid_of(&base), &bound) {
                        (Some(u), Some(b)) if &u == b => {
                            let attr = attrs.first().cloned().unwrap_or_else(|| "uid".into());
                            let mut vals = enc(0x04, attr.as_bytes());
                            vals.extend(enc(0x31, &enc(0x04, u.as_bytes())));
                            let mut entry = enc(0x04, base.as_bytes());
                            entry.extend(enc(0x30, &enc(0x30, &vals)));
                            let mut out = message(&id, enc(0x64, &entry));
                            out.extend(message(&id, ldap_result(0x65, RC_SUCCESS, "")));
                            out
                        }
                        _ => message(&id, ldap_result(0x65, RC_NO_SUCH_OBJECT, "no such object")),
                    }
                }
                // UnbindRequest: close without a response.
                0x42 => return,
                _ => message(&id, ldap_result(0x61, RC_PROTOCOL_ERROR, "unsupported operation")),
            };
            if s.write_all(&reply).await.is_err() {
                return;
            }
            buf.drain(..used);
        }
        if buf.len() > 64 * 1024 {
            return;
        }
        let n = match tokio::time::timeout(Duration::from_secs(30), s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_round_trip_and_uid() {
        let m = message(&[1], ldap_result(0x61, RC_SUCCESS, ""));
        let (t, used) = tlv(&m).unwrap();
        assert_eq!(used, m.len());
        assert_eq!(t.tag, 0x30);
        let kids = children(t.value);
        assert_eq!(kids[0].value, &[1]);
        assert_eq!(kids[1].tag, 0x61);
        assert_eq!(uid_of("uid=alice,ou=people,dc=anvil,dc=lab").as_deref(), Some("alice"));
        assert_eq!(uid_of("cn=alice,dc=x"), None);
        let long = enc(0x04, &[b'x'; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert!(tlv(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none(), "oversized length forms are refused");
    }
}
