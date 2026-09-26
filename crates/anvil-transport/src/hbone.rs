//! Mesh HBONE client tunnel: HTTP/2 `CONNECT` over mutual TLS.
//!
//! Anvil connects to the HBONE endpoint (`host:port` of the proxy profile),
//! presents the client SVID of the proxy's TLS profile, verifies the
//! endpoint's server identity (SPIFFE or host name), negotiates HTTP/2 (ALPN
//! `h2`) and sends `CONNECT` with `:authority = <destination host:port>`,
//! plus optional marker / `baggage` headers. A `2xx` opens the tunnel: the
//! stream's body becomes the byte stream the inner connection (HTTP/1.1,
//! HTTP/2, TLS, raw TCP, WebSocket) runs over, exactly like an HTTP CONNECT
//! proxy tunnel.
//!
//! Evidence for the outer leg (DNS, TCP, mTLS identities, HTTP/2 preface,
//! `CONNECT` status and a bounded refusal body) is recorded in a
//! [`TunnelObservation`], separate from the inner phases. A refused or failed
//! tunnel is a typed tunnel-leg failure; the inner destination is never
//! reported as failed because it was never contacted.
//!
//! One fresh HBONE connection is used per inner connection (never pooled):
//! the tunnel's identity and headers belong to one execution.

use crate::connector::{BoxIo, ProxyPlan};
use crate::dns::{self, DnsConfig};
use crate::errors::{HyperStage, classify_hyper};
use crate::net;
use crate::recorder::{EventCtx, Recorder};
use crate::stats::{ConnStats, CountingIo, TlsErrorTap};
use crate::tls;
use anvil_domain::execution::*;
use anvil_domain::settings::Timeouts;
use bytes::{Bytes, BytesMut};
use http::{Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Refusal bodies are evidence, bounded.
const MAX_REFUSAL_BODY: usize = 8 * 1024;

/// The open tunnel stream. Holds the HTTP/2 request handle so the HBONE
/// connection lives exactly as long as the inner connection.
struct TunnelIo {
    io: TokioIo<hyper::upgrade::Upgraded>,
    _sender: http2::SendRequest<Empty<Bytes>>,
}

impl AsyncRead for TunnelIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// `host:port` authority (IPv6 bracketed).
pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

fn ms(d: Option<u64>) -> Option<Duration> {
    d.map(Duration::from_millis)
}

fn blank(p: &ProxyPlan, authority: &str) -> TunnelObservation {
    TunnelObservation {
        kind: TunnelKind::Hbone,
        endpoint: p.label.clone(),
        authority: authority.to_string(),
        resolved_addresses: vec![],
        resolution_source: None,
        connect_attempts: vec![],
        local_address: None,
        remote_address: None,
        phases: vec![],
        tls: None,
        connect_headers: p
            .connect_headers
            .iter()
            .map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() })
            .collect(),
        connect_status: None,
        response_headers: vec![],
        refusal_body: None,
        refusal_body_truncated: false,
        failure: None,
    }
}

fn status_for(f: &TransportFailure) -> PhaseStatus {
    match f.kind {
        FailureKind::DnsTimeout | FailureKind::ConnectTimeout | FailureKind::TlsHandshakeTimeout => PhaseStatus::TimedOut,
        _ if f.deadline_ms.is_some() => PhaseStatus::TimedOut,
        _ => PhaseStatus::Failed,
    }
}

/// The attempt-level failure for a tunnel-leg failure `inner` (kept verbatim
/// in the tunnel observation).
fn outer_failure(kind: FailureKind, inner: &TransportFailure, message: String) -> TransportFailure {
    let mut f = TransportFailure::new(Phase::ProxyTunnel, kind, message);
    f.tls_alert = inner.tls_alert.clone();
    f.h2_error_code = inner.h2_error_code;
    f.status = inner.status;
    f.deadline_ms = inner.deadline_ms;
    f.io_error_kind = inner.io_error_kind.clone();
    f.os_error_code = inner.os_error_code;
    f
}

/// Prefer a typed TLS error seen on the mTLS stream (e.g. the endpoint's
/// `certificate_required` alert after a TLS 1.3 client handshake) over the
/// generic HTTP/2 error it surfaced as.
fn tls_tap(f: &mut TransportFailure, stats: &ConnStats) -> bool {
    if let Some((kind, alert)) = stats.tls_error() {
        f.kind = kind;
        f.tls_alert = alert;
        f.phase = Phase::TlsHandshake;
        return true;
    }
    false
}

/// Open an HBONE tunnel to `target_host:target_port` through `p`. Records the
/// outer phases in the tunnel observation (same clock as `rec`).
pub async fn open(
    rec: &Recorder,
    p: &ProxyPlan,
    target_host: &str,
    target_port: u16,
    dns_cfg: &DnsConfig,
    timeouts: &Timeouts,
) -> Result<(BoxIo, TunnelObservation), (TransportFailure, TunnelObservation)> {
    let authority = authority(target_host.trim_start_matches('[').trim_end_matches(']'), target_port);
    let mut t = blank(p, &authority);
    let mut sub = Recorder { t0: rec.t0, phases: vec![], attempt: rec.attempt, events: EventCtx::none() };
    let endpoint = &p.label;
    macro_rules! bail {
        ($attempt:expr, $inner:expr) => {{
            let attempt: TransportFailure = $attempt;
            let inner: TransportFailure = $inner;
            sub.close_open(status_for(&inner));
            t.phases = std::mem::take(&mut sub.phases);
            t.failure = Some(inner);
            return Err((attempt, t));
        }};
    }

    // ---- HBONE endpoint TLS profile (mTLS is what makes this HBONE) ----
    let Some(ptls) = p.tls.as_ref() else {
        let f = TransportFailure::new(
            Phase::Prepare,
            FailureKind::ProxyConfigInvalid,
            "an HBONE proxy needs a TLS profile (client SVID and the endpoint's trust bundle); nothing was sent",
        )
        .with_field("proxy.tls_profile");
        t.failure = Some(f.clone());
        return Err((f, t));
    };

    // ---- DNS ----
    let dns_idx = sub.start(Phase::Dns);
    let resolution = match dns::resolve(&p.host, p.port, dns_cfg, ms(timeouts.dns_ms)).await {
        Ok(r) => r,
        Err(f) => {
            if f.phase == Phase::Prepare {
                sub.finish(dns_idx, PhaseStatus::NotApplicable);
            }
            let a = outer_failure(
                FailureKind::ProxyConnectFailed,
                &f,
                format!("resolving the HBONE endpoint {endpoint} failed: {}; the destination {authority} was not contacted", f.message),
            );
            bail!(a, f)
        }
    };
    if resolution.source == "literal" || resolution.source == "override" {
        sub.phases[dns_idx].status = PhaseStatus::NotApplicable;
        sub.phases[dns_idx].start_us = None;
        sub.phases[dns_idx].detail = Some(format!("address from {}", resolution.source));
    } else {
        sub.finish(dns_idx, PhaseStatus::Completed);
    }
    t.resolved_addresses = resolution.addrs.iter().map(|a| a.to_string()).collect();
    t.resolution_source = Some(resolution.source.to_string());

    // ---- TCP ----
    let conn_idx = sub.start(Phase::Connect);
    let connected = match net::connect_tcp(&resolution.addrs, ms(timeouts.connect_ms)).await {
        Ok(c) => c,
        Err((f, attempts)) => {
            t.connect_attempts = attempts;
            let a = outer_failure(
                FailureKind::ProxyConnectFailed,
                &f,
                format!("connecting to the HBONE endpoint {endpoint} failed: {}; the destination {authority} was not contacted", f.message),
            );
            bail!(a, f)
        }
    };
    sub.finish(conn_idx, PhaseStatus::Completed);
    t.connect_attempts = connected.attempts;
    t.remote_address = Some(connected.remote.to_string());
    t.local_address = connected.stream.local_addr().ok().map(|a| a.to_string());

    // ---- mutual TLS with the endpoint (client SVID, server identity) ----
    let outer_stats = ConnStats::new();
    let tls_idx = sub.start(Phase::TlsHandshake);
    let io = CountingIo::new(connected.stream, outer_stats.clone());
    let tls_stream = match tls::connect(ptls, io, &p.host, &["h2"], ms(timeouts.tls_handshake_ms)).await {
        Ok((s, o)) => {
            sub.finish_with(tls_idx, PhaseStatus::Completed, "mutual TLS with the HBONE endpoint");
            t.tls = Some(o);
            s
        }
        Err((f, o)) => {
            t.tls = Some(o);
            // No common ALPN: the endpoint does not offer HTTP/2 at all.
            let kind =
                if f.kind == FailureKind::TlsAlpnMismatch { FailureKind::HboneProtocolError } else { FailureKind::HboneEndpointTlsFailed };
            let a = outer_failure(
                kind,
                &f,
                format!(
                    "mutual TLS with the HBONE endpoint {endpoint} failed: {}; the tunnel was not opened and {authority} was not contacted",
                    f.message
                ),
            );
            bail!(a, f)
        }
    };
    let negotiated = t.tls.as_ref().and_then(|o| o.alpn_negotiated.clone());
    if negotiated.as_deref() != Some("h2") {
        let f = TransportFailure::new(
            Phase::TlsHandshake,
            FailureKind::TlsAlpnMismatch,
            format!(
                "HBONE needs HTTP/2 (ALPN 'h2'), but the endpoint negotiated {}",
                negotiated.map(|s| format!("'{s}'")).unwrap_or_else(|| "no ALPN protocol".into())
            ),
        );
        let a = outer_failure(
            FailureKind::HboneProtocolError,
            &f,
            format!("{}; the tunnel was not opened and {authority} was not contacted", f.message),
        );
        bail!(a, f)
    }
    let tls_stream = TlsErrorTap::new(tls_stream, outer_stats.clone());

    // ---- HTTP/2 preface ----
    let h2_idx = sub.start(Phase::ProtocolHandshake);
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder.max_header_list_size(64 * 1024);
    let deadline = ms(timeouts.connect_ms);
    let handshake = builder.handshake::<_, Empty<Bytes>>(TokioIo::new(tls_stream));
    let handshake = match deadline {
        Some(d) => tokio::time::timeout(d, handshake).await.map_err(|_| d),
        None => Ok(handshake.await),
    };
    let (mut sender, conn) = match handshake {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            let mut f = classify_hyper(&e, HyperStage::Handshake);
            let kind = if tls_tap(&mut f, &outer_stats) { FailureKind::HboneEndpointTlsFailed } else { FailureKind::HboneProtocolError };
            let a = outer_failure(kind, &f, format!("the HTTP/2 connection to the HBONE endpoint {endpoint} failed: {}", f.message));
            bail!(a, f)
        }
        Err(d) => {
            let f = TransportFailure::new(
                Phase::ProtocolHandshake,
                FailureKind::HboneProtocolError,
                format!("the HTTP/2 preface with the HBONE endpoint did not complete within {} ms", d.as_millis()),
            )
            .with_deadline(Some(d.as_millis() as u64));
            let a = outer_failure(FailureKind::HboneProtocolError, &f, f.message.clone());
            bail!(a, f)
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sub.finish_with(h2_idx, PhaseStatus::Completed, "HTTP/2 connection preface");

    // ---- CONNECT ----
    let c_idx = sub.start(Phase::ProxyTunnel);
    let mut req = match Request::builder().method(Method::CONNECT).uri(authority.as_str()).body(Empty::<Bytes>::new()) {
        Ok(r) => r,
        Err(e) => {
            let f = TransportFailure::new(
                Phase::Prepare,
                FailureKind::InvalidUrl,
                format!("'{authority}' is not a valid CONNECT authority: {e}"),
            )
            .with_field("url");
            sub.finish(c_idx, PhaseStatus::NotApplicable);
            bail!(f.clone(), f)
        }
    };
    for (n, v) in &p.connect_headers {
        req.headers_mut().append(n.clone(), v.clone());
    }
    let sent = sender.send_request(req);
    let resp = match deadline {
        Some(d) => tokio::time::timeout(d, sent).await.map_err(|_| d),
        None => Ok(sent.await),
    };
    let resp = match resp {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let mut f = classify_hyper(&e, HyperStage::AwaitHeaders);
            f.phase = Phase::ProxyTunnel;
            let kind = if tls_tap(&mut f, &outer_stats) { FailureKind::HboneEndpointTlsFailed } else { FailureKind::HboneProtocolError };
            let a = outer_failure(
                kind,
                &f,
                format!(
                    "the HBONE endpoint {endpoint} did not answer the CONNECT to {authority}: {}; the destination was not contacted",
                    f.message
                ),
            );
            bail!(a, f)
        }
        Err(d) => {
            let f = TransportFailure::new(
                Phase::ProxyTunnel,
                FailureKind::HboneProtocolError,
                format!("the HBONE endpoint did not answer the CONNECT to {authority} within {} ms", d.as_millis()),
            )
            .with_deadline(Some(d.as_millis() as u64));
            let a = outer_failure(FailureKind::HboneProtocolError, &f, f.message.clone());
            bail!(a, f)
        }
    };
    let status = resp.status().as_u16();
    t.connect_status = Some(status);
    t.response_headers = resp
        .headers()
        .iter()
        .map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() })
        .collect();

    if !(200..300).contains(&status) {
        // Keep the refusal (status + bounded body) as evidence.
        let mut body = resp.into_body();
        let mut captured = BytesMut::new();
        let mut truncated = false;
        loop {
            let frame = tokio::time::timeout(Duration::from_millis(timeouts.body_idle_ms.unwrap_or(5_000).min(5_000)), body.frame()).await;
            match frame {
                Ok(Some(Ok(fr))) => {
                    if let Ok(d) = fr.into_data() {
                        let room = MAX_REFUSAL_BODY.saturating_sub(captured.len());
                        if d.len() > room {
                            truncated = true;
                        }
                        captured.extend_from_slice(&d[..d.len().min(room)]);
                        if truncated {
                            break;
                        }
                    }
                }
                Ok(None) => break,
                Ok(Some(Err(_))) | Err(_) => {
                    truncated = true;
                    break;
                }
            }
        }
        if !captured.is_empty() {
            t.refusal_body = Some(String::from_utf8_lossy(&captured).into_owned());
        }
        t.refusal_body_truncated = truncated;
        let mut f = TransportFailure::new(
            Phase::ProxyTunnel,
            FailureKind::HboneConnectRefused,
            format!(
                "the HBONE endpoint {endpoint} refused the CONNECT to {authority} with HTTP {status}; the destination was not contacted"
            ),
        );
        f.status = Some(status);
        sub.finish_with(c_idx, PhaseStatus::Failed, format!("CONNECT {authority} → {status}"));
        t.phases = std::mem::take(&mut sub.phases);
        t.failure = Some(f.clone());
        return Err((f, t));
    }

    let upgraded = match hyper::upgrade::on(resp).await {
        Ok(u) => u,
        Err(e) => {
            let f = TransportFailure::new(
                Phase::ProxyTunnel,
                FailureKind::HboneProtocolError,
                format!("the HBONE CONNECT was accepted ({status}) but the tunnel stream could not be opened: {e}"),
            );
            bail!(f.clone(), f)
        }
    };
    sub.finish_with(c_idx, PhaseStatus::Completed, format!("CONNECT {authority} → {status}"));
    t.phases = std::mem::take(&mut sub.phases);
    let io: BoxIo = Box::new(TunnelIo { io: TokioIo::new(upgraded), _sender: sender });
    Ok((io, t))
}

/// Shared by pooled transports: HBONE tunnels are one per inner connection.
pub fn is_hbone(p: Option<&ProxyPlan>) -> bool {
    p.is_some_and(|p| p.kind == anvil_domain::tls::ProxyKind::Hbone)
}
