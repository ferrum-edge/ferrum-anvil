//! Shared stream establishment: DNS → TCP → proxy tunnel → TLS, recording
//! each phase. Used by HTTP/1.1, HTTP/2, WebSocket (H1) and raw TCP/TLS.

use crate::dns::{self, DnsConfig};
use crate::net;
use crate::recorder::Recorder;
use crate::stats::{ConnStats, CountingIo};

use crate::tls::{self, PreparedTls};
use anvil_domain::execution::{ConnectionObservation, FailureKind, Phase, PhaseStatus, TransportFailure};
use anvil_domain::settings::Timeouts;
use anvil_domain::tls::ProxyKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

pub type BoxIo = Box<dyn Io>;

static CONN_IDS: AtomicU64 = AtomicU64::new(1);

pub fn next_connection_id() -> u64 {
    CONN_IDS.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone)]
pub struct ProxyPlan {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub credentials: Option<(String, Zeroizing<String>)>,
    /// TLS to the proxy itself (ProxyKind::Https).
    pub tls: Option<Arc<PreparedTls>>,
    /// Display label (no credentials).
    pub label: String,
}

impl std::fmt::Debug for ProxyPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyPlan").field("kind", &self.kind).field("label", &self.label).finish()
    }
}

pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    /// Negotiate TLS with the destination.
    pub tls: Option<&'a PreparedTls>,
    pub alpn: &'a [&'a str],
    /// For plain-HTTP forward proxies the stream stays connected to the proxy
    /// and requests use absolute-form; no tunnel is established.
    pub http_forward_via_proxy: bool,
}

pub struct Established {
    pub io: BoxIo,
    pub stats: Arc<ConnStats>,
    pub observation: ConnectionObservation,
}

fn ms(d: Option<u64>) -> Option<Duration> {
    d.map(Duration::from_millis)
}

pub fn blank_observation(id: u64) -> ConnectionObservation {
    ConnectionObservation {
        id,
        reused: false,
        protocol: None,
        local_address: None,
        remote_address: None,
        resolved_addresses: vec![],
        resolution_source: None,
        connect_attempts: vec![],
        via_proxy: None,
        tls: None,
        prior_requests: 0,
        proxy_header: None,
    }
}

/// A PROXY protocol header to write at the head of the connection, after
/// TCP connect (and any forward-proxy tunnel) and before TLS.
pub struct PreTlsHeader<'a> {
    pub plan: &'a crate::proxy_protocol::HeaderPlan,
    pub redact: crate::proxy_protocol::Redact<'a>,
}

/// Establish a stream to `target`, optionally through `proxy`.
pub async fn establish(
    rec: &mut Recorder,
    target: &Target<'_>,
    dns_cfg: &DnsConfig,
    timeouts: &Timeouts,
    proxy: Option<&ProxyPlan>,
) -> Result<Established, (TransportFailure, ConnectionObservation)> {
    establish_with(rec, target, dns_cfg, timeouts, proxy, None).await
}

/// [`establish`] with an optional PROXY protocol header written before TLS.
pub async fn establish_with(
    rec: &mut Recorder,
    target: &Target<'_>,
    dns_cfg: &DnsConfig,
    timeouts: &Timeouts,
    proxy: Option<&ProxyPlan>,
    header: Option<PreTlsHeader<'_>>,
) -> Result<Established, (TransportFailure, ConnectionObservation)> {
    let mut obs = blank_observation(next_connection_id());
    let stats = ConnStats::new();

    // ---- DNS (of the proxy when proxied: the proxy resolves the target) ----
    let (dns_host, dns_port) = match proxy {
        Some(p) => (p.host.as_str(), p.port),
        None => (target.host, target.port),
    };
    if proxy.is_some() {
        obs.via_proxy = proxy.map(|p| p.label.clone());
    }
    let dns_idx = rec.start(Phase::Dns);
    let resolution = match dns::resolve(dns_host, dns_port, dns_cfg, ms(timeouts.dns_ms)).await {
        Ok(r) => r,
        Err(mut f) => {
            let status = if f.kind == FailureKind::DnsTimeout { PhaseStatus::TimedOut } else { PhaseStatus::Failed };
            if f.phase == Phase::Prepare {
                rec.finish(dns_idx, PhaseStatus::NotApplicable);
            } else {
                rec.finish(dns_idx, status);
                if proxy.is_some() {
                    f.message = format!("resolving the proxy failed: {}", f.message);
                    f.kind = FailureKind::ProxyConnectFailed;
                    f.phase = Phase::Dns;
                }
            }
            return Err((f, obs));
        }
    };
    if resolution.source == "literal" || resolution.source == "override" {
        rec.phases[dns_idx].status = PhaseStatus::NotApplicable;
        rec.phases[dns_idx].start_us = None;
        rec.phases[dns_idx].detail = Some(format!("address from {}", resolution.source));
    } else {
        rec.finish(dns_idx, PhaseStatus::Completed);
    }
    obs.resolved_addresses = resolution.addrs.iter().map(|a| a.to_string()).collect();
    obs.resolution_source = Some(resolution.source.to_string());

    // ---- TCP connect ----
    let conn_idx = rec.start(Phase::Connect);
    let connected = match net::connect_tcp(&resolution.addrs, ms(timeouts.connect_ms)).await {
        Ok(c) => c,
        Err((mut f, attempts)) => {
            obs.connect_attempts = attempts;
            rec.finish(conn_idx, if f.kind == FailureKind::ConnectTimeout { PhaseStatus::TimedOut } else { PhaseStatus::Failed });
            if proxy.is_some() {
                f.message = format!("connecting to the proxy failed: {}", f.message);
                f.kind = FailureKind::ProxyConnectFailed;
            }
            return Err((f, obs));
        }
    };
    rec.finish(conn_idx, PhaseStatus::Completed);
    obs.connect_attempts = connected.attempts;
    obs.remote_address = Some(connected.remote.to_string());
    let local_addr = connected.stream.local_addr().ok();
    obs.local_address = local_addr.map(|a| a.to_string());
    let remote_addr = connected.remote;

    let mut io: BoxIo = Box::new(CountingIo::new(connected.stream, stats.clone()));

    // ---- Proxy tunnel ----
    if let Some(p) = proxy {
        if let (ProxyKind::Https, Some(ptls)) = (p.kind, p.tls.as_ref()) {
            let idx = rec.start(Phase::TlsHandshake);
            match tls::connect(ptls, io, &p.host, &["http/1.1"], ms(timeouts.tls_handshake_ms)).await {
                Ok((s, _o)) => {
                    rec.finish_with(idx, PhaseStatus::Completed, "TLS to proxy");
                    io = Box::new(s);
                }
                Err((mut f, _o)) => {
                    rec.finish_with(idx, PhaseStatus::Failed, "TLS to proxy");
                    f.message = format!("TLS to the proxy failed: {}", f.message);
                    f.kind = FailureKind::ProxyConnectFailed;
                    return Err((f, obs));
                }
            }
        }
        if !target.http_forward_via_proxy {
            let idx = rec.start(Phase::ProxyTunnel);
            let creds = p.credentials.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str()));
            let authority = if target.host.contains(':') && !target.host.starts_with('[') {
                format!("[{}]:{}", target.host, target.port)
            } else {
                format!("{}:{}", target.host, target.port)
            };
            let r = match p.kind {
                ProxyKind::Socks5 => net::socks5_connect(&mut io, target.host, target.port, creds, ms(timeouts.connect_ms)).await,
                _ => net::http_connect_tunnel(&mut io, &authority, creds, ms(timeouts.connect_ms)).await,
            };
            if let Err(f) = r {
                rec.finish(idx, PhaseStatus::Failed);
                return Err((f, obs));
            }
            rec.finish(idx, PhaseStatus::Completed);
        }
    }

    // ---- PROXY protocol header (head of the stream, before any TLS) ----
    if let Some(h) = header {
        use tokio::io::AsyncWriteExt;
        let idx = rec.start(Phase::ProxyProtocolHeader);
        // Behind a forward-proxy tunnel the socket addresses describe the
        // proxy hop, not this stream; only configured addresses apply.
        let (local, remote) = if proxy.is_some() { (None, None) } else { (local_addr, Some(remote_addr)) };
        let built = match h.plan.build(local, remote, h.redact) {
            Ok(b) => b,
            Err(e) => {
                rec.finish(idx, PhaseStatus::Failed);
                let f =
                    TransportFailure::new(Phase::ProxyProtocolHeader, FailureKind::BodySerialization, e).with_field("tcp.proxy_protocol");
                return Err((f, obs));
            }
        };
        let write = async {
            io.write_all(&built.bytes).await?;
            io.flush().await
        };
        let r = match ms(timeouts.request_write_ms) {
            Some(d) => tokio::time::timeout(d, write).await.unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into())),
            None => write.await,
        };
        match r {
            Ok(()) => {
                rec.finish_with(idx, PhaseStatus::Completed, crate::proxy_protocol::header_summary(&built.observation));
                obs.proxy_header = Some(built.observation);
            }
            Err(e) => {
                let timed_out = e.kind() == std::io::ErrorKind::TimedOut;
                rec.finish(idx, if timed_out { PhaseStatus::TimedOut } else { PhaseStatus::Failed });
                let mut f = TransportFailure::new(
                    Phase::ProxyProtocolHeader,
                    if timed_out { FailureKind::RequestWriteTimeout } else { FailureKind::RequestWriteFailed },
                    format!("writing the PROXY protocol header failed: {e}"),
                );
                f.io_error_kind = Some(format!("{:?}", e.kind()));
                f.os_error_code = e.raw_os_error();
                obs.proxy_header = Some(built.observation);
                return Err((f, obs));
            }
        }
    }

    // ---- TLS to destination ----
    match target.tls {
        Some(prepared) => {
            let idx = rec.start(Phase::TlsHandshake);
            match tls::connect(prepared, io, target.host, target.alpn, ms(timeouts.tls_handshake_ms)).await {
                Ok((s, tls_obs)) => {
                    rec.finish(idx, PhaseStatus::Completed);
                    obs.tls = Some(tls_obs);
                    io = Box::new(crate::stats::TlsErrorTap::new(s, stats.clone()));
                }
                Err((f, tls_obs)) => {
                    rec.finish(idx, if f.kind == FailureKind::TlsHandshakeTimeout { PhaseStatus::TimedOut } else { PhaseStatus::Failed });
                    obs.tls = Some(tls_obs);
                    return Err((f, obs));
                }
            }
        }
        None => rec.mark(Phase::TlsHandshake, PhaseStatus::NotApplicable, Some("cleartext")),
    }

    Ok(Established { io, stats, observation: obs })
}
