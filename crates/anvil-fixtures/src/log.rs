//! Independent fixture ground truth. Tests compare what the fixture actually
//! saw with what Anvil concluded; this log is never given to the diagnostic
//! engine.

use parking_lot::Mutex;
use serde::Serialize;
use std::sync::Arc;
use std::time::SystemTime;

/// `DatagramRelayed`: a CONNECT-UDP proxy fixture relayed a client HTTP
/// Datagram to its UDP target; `via` is `capsule` or `quic_datagram`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum GroundTruth {
    ConnectionAccepted { peer: String },
    TlsHandshakeCompleted { alpn: Option<String>, client_cert_cn: Option<String> },
    TlsHandshakeFailed { error: String },
    RequestReceived { method: String, path: String, body_bytes: u64, headers: Vec<(String, String)> },
    ResponseStarted { status: u16 },
    FaultApplied { fault: String },
    DatagramReceived { bytes: u64 },
    MessageReceived { bytes: u64 },
    DatagramRelayed { bytes: u64, via: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub at_ms: u128,
    #[serde(flatten)]
    pub event: GroundTruth,
}

#[derive(Default, Clone)]
pub struct GroundTruthLog {
    inner: Arc<Mutex<Vec<Entry>>>,
}

const MAX_ENTRIES: usize = 10_000;

impl GroundTruthLog {
    pub fn push(&self, event: GroundTruth) {
        let at_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let mut g = self.inner.lock();
        if g.len() < MAX_ENTRIES {
            g.push(Entry { at_ms, event });
        }
    }

    pub fn entries(&self) -> Vec<Entry> {
        self.inner.lock().clone()
    }

    pub fn clear(&self) {
        self.inner.lock().clear();
    }

    pub fn requests(&self) -> Vec<(String, String)> {
        self.inner
            .lock()
            .iter()
            .filter_map(|e| match &e.event {
                GroundTruth::RequestReceived { method, path, .. } => Some((method.clone(), path.clone())),
                _ => None,
            })
            .collect()
    }

    pub fn count_requests(&self) -> usize {
        self.requests().len()
    }

    pub fn saw_connection(&self) -> bool {
        self.inner.lock().iter().any(|e| matches!(e.event, GroundTruth::ConnectionAccepted { .. }))
    }

    pub fn last_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.inner.lock().iter().rev().find_map(|e| match &e.event {
            GroundTruth::RequestReceived { headers, .. } => Some(headers.clone()),
            _ => None,
        })
    }
}
