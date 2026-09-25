//! HTTP/3 over QUIC (quinn + h3) with measured QUIC phases.
//!
//! There is no TCP phase on this path: DNS then QUIC handshake (which
//! includes TLS 1.3). Forced HTTP/3 never sends over TCP; the engine records
//! any fallback as a separate attempt.

use crate::dns;
use crate::errors::display_chain;
use crate::http::{AttemptOutput, HttpPlan, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::tls;
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::*;
use bytes::{Buf, Bytes, BytesMut};
use chrono::Utc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

type SendReq = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Clone)]
struct H3Conn {
    send: SendReq,
    quic: quinn::Connection,
    template: ConnectionObservation,
    served: Arc<std::sync::atomic::AtomicU32>,
}

pub struct H3Transport {
    endpoints: Mutex<HashMap<bool, quinn::Endpoint>>,
    pool: Mutex<HashMap<String, H3Conn>>,
}

impl Default for H3Transport {
    fn default() -> Self {
        Self::new()
    }
}

fn quic_failure(e: &quinn::ConnectionError, during_handshake: bool, deadline: Option<u64>) -> TransportFailure {
    use quinn::ConnectionError as C;
    let phase = if during_handshake { Phase::QuicHandshake } else { Phase::AwaitResponseHeaders };
    let mut f = TransportFailure::new(phase, FailureKind::QuicOther, display_chain(e));
    match e {
        C::TimedOut => {
            f.kind = if during_handshake { FailureKind::QuicHandshakeTimeout } else { FailureKind::QuicIdleTimeout };
            f.deadline_ms = deadline;
        }
        C::TransportError(te) => {
            let code = u64::from(te.code);
            f.quic_error_code = Some(code);
            // CRYPTO_ERROR range carries the TLS alert (RFC 9001 §4.8).
            if (0x100..=0x1ff).contains(&code) {
                let alert = rustls::AlertDescription::from((code - 0x100) as u8);
                let (k, name) = crate::errors::classify_rustls(&rustls::Error::AlertReceived(alert), !during_handshake);
                f.kind = k;
                f.tls_alert = name;
            } else {
                f.kind = FailureKind::QuicTransportError;
            }
        }
        C::ConnectionClosed(c) => {
            let code = u64::from(c.error_code);
            f.quic_error_code = Some(code);
            if (0x100..=0x1ff).contains(&code) {
                let alert = rustls::AlertDescription::from((code - 0x100) as u8);
                let (k, name) = crate::errors::classify_rustls(&rustls::Error::AlertReceived(alert), !during_handshake);
                f.kind = k;
                f.tls_alert = name;
            } else {
                f.kind = FailureKind::QuicTransportError;
            }
        }
        C::ApplicationClosed(a) => {
            f.kind = FailureKind::QuicApplicationClosed;
            f.quic_error_code = Some(u64::from(a.error_code));
        }
        _ => {}
    }
    f
}

impl H3Transport {
    pub fn new() -> Self {
        H3Transport { endpoints: Mutex::new(HashMap::new()), pool: Mutex::new(HashMap::new()) }
    }

    pub fn clear(&self) {
        self.pool.lock().clear();
    }

    fn endpoint(&self, v6: bool) -> Result<quinn::Endpoint, TransportFailure> {
        let mut eps = self.endpoints.lock();
        if let Some(e) = eps.get(&v6) {
            return Ok(e.clone());
        }
        let bind: SocketAddr = if v6 { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
        let ep = quinn::Endpoint::client(bind).map_err(|e| {
            TransportFailure::new(Phase::Prepare, FailureKind::AddressUnavailable, format!("could not open a UDP socket for QUIC: {e}"))
        })?;
        eps.insert(v6, ep.clone());
        Ok(ep)
    }

    pub async fn execute(
        &self,
        plan: &HttpPlan,
        index: u32,
        reason: AttemptReason,
        events: &EventCtx,
        cancel: &CancellationToken,
    ) -> AttemptOutput {
        let mut rec = Recorder::new(index, events.clone());
        events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: index });
        let mut obs = AttemptObservation {
            index,
            reason,
            method: plan.method.to_string(),
            url: plan.display_url.clone(),
            started_at: Utc::now(),
            connection: None,
            phases: vec![],
            dispatch: DispatchState::NotDispatched,
            bytes: ByteCounts { request_body: plan.body.len() as u64, request_headers_estimated: true, ..Default::default() },
            response_status: None,
            failure: None,
            duration_us: 0,
        };
        let fail = |mut rec: Recorder, mut obs: AttemptObservation, f: TransportFailure, dispatch: DispatchState| {
            let st = match f.kind {
                FailureKind::Canceled => PhaseStatus::Canceled,
                FailureKind::QuicHandshakeTimeout
                | FailureKind::TotalTimeout
                | FailureKind::ResponseHeadersTimeout
                | FailureKind::BodyIdleTimeout
                | FailureKind::DnsTimeout => PhaseStatus::TimedOut,
                _ => PhaseStatus::Failed,
            };
            rec.close_open(st);
            events.emit(ExecutionEvent::AttemptFailed { execution_id: events.execution_id, attempt: obs.index, kind: f.kind });
            obs.duration_us = rec.us();
            obs.phases = std::mem::take(&mut rec.phases);
            obs.dispatch = dispatch;
            obs.failure = Some(f);
            AttemptOutput { observation: obs, response: None, body: Bytes::new() }
        };
        if !plan.https {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::UnsupportedCombination, "HTTP/3 requires an https:// URL")
                .with_field("settings.http_version");
            return fail(rec, obs, f, DispatchState::NotDispatched);
        }
        if plan.proxy.is_some() {
            let f = TransportFailure::new(
                Phase::Prepare,
                FailureKind::UnsupportedCombination,
                "HTTP/3 cannot be sent through the configured HTTP/SOCKS proxy",
            )
            .with_field("settings.proxy");
            return fail(rec, obs, f, DispatchState::NotDispatched);
        }
        let Some(prepared) = plan.tls.clone() else {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "no TLS configuration for HTTP/3");
            return fail(rec, obs, f, DispatchState::NotDispatched);
        };
        let total_deadline = plan.timeouts.total_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let key = format!("{}|h3://{}:{}|{}", plan.isolation, plan.host.to_ascii_lowercase(), plan.port, prepared.fingerprint);

        let pooled = if plan.keepalive {
            let p = self.pool.lock().get(&key).cloned();
            p.filter(|c| c.quic.close_reason().is_none())
        } else {
            None
        };
        let (conn, reused) = match pooled {
            Some(c) => {
                rec.mark(Phase::Dns, PhaseStatus::Reused, Some("pooled QUIC connection"));
                rec.mark(Phase::QuicHandshake, PhaseStatus::Reused, Some("pooled QUIC connection"));
                (c, true)
            }
            None => {
                let mut cobs = crate::connector::blank_observation(crate::connector::next_connection_id());
                rec.mark(Phase::Connect, PhaseStatus::NotApplicable, Some("QUIC has no TCP connect"));
                let dns_idx = rec.start(Phase::Dns);
                let res = dns::resolve(&plan.host, plan.port, &plan.dns, plan.timeouts.dns_ms.map(Duration::from_millis)).await;
                let res = match res {
                    Ok(r) => r,
                    Err(f) => {
                        rec.finish(dns_idx, PhaseStatus::Failed);
                        obs.connection = Some(cobs);
                        return fail(rec, obs, f, DispatchState::NotDispatched);
                    }
                };
                if res.source == "literal" || res.source == "override" {
                    rec.phases[dns_idx].status = PhaseStatus::NotApplicable;
                    rec.phases[dns_idx].start_us = None;
                } else {
                    rec.finish(dns_idx, PhaseStatus::Completed);
                }
                cobs.resolved_addresses = res.addrs.iter().map(|a| a.to_string()).collect();
                cobs.resolution_source = Some(res.source.to_string());
                let addr = res.addrs[0];
                cobs.remote_address = Some(addr.to_string());
                let (cfg, sn, handle) = match tls::client_config_observed(&prepared, &plan.host, &["h3"], true) {
                    Ok(x) => x,
                    Err(f) => return fail(rec, obs, f, DispatchState::NotDispatched),
                };
                let quic_cfg = match quinn::crypto::rustls::QuicClientConfig::try_from(cfg) {
                    Ok(q) => q,
                    Err(e) => {
                        let f = TransportFailure::new(
                            Phase::Prepare,
                            FailureKind::TlsProfileInvalid,
                            format!("TLS profile cannot be used for QUIC: {e}"),
                        );
                        return fail(rec, obs, f, DispatchState::NotDispatched);
                    }
                };
                let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
                let mut transport = quinn::TransportConfig::default();
                transport.keep_alive_interval(Some(Duration::from_secs(10)));
                if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(30)) {
                    transport.max_idle_timeout(Some(idle));
                }
                client_cfg.transport_config(Arc::new(transport));
                let ep = match self.endpoint(addr.is_ipv6()) {
                    Ok(e) => e,
                    Err(f) => return fail(rec, obs, f, DispatchState::NotDispatched),
                };
                let sni = match &sn {
                    rustls_pki_types::ServerName::DnsName(d) => d.as_ref().to_string(),
                    _ => plan.host.clone(),
                };
                let hs_idx = rec.start(Phase::QuicHandshake);
                let connecting = match ep.connect_with(client_cfg, addr, &sni) {
                    Ok(c) => c,
                    Err(e) => {
                        rec.finish(hs_idx, PhaseStatus::Failed);
                        let f = TransportFailure::new(
                            Phase::QuicHandshake,
                            FailureKind::QuicOther,
                            format!("QUIC connect could not start: {e}"),
                        );
                        return fail(rec, obs, f, DispatchState::NotDispatched);
                    }
                };
                let hs_deadline = plan.timeouts.tls_handshake_ms.or(plan.timeouts.connect_ms);
                let result = tokio::select! {
                    r = connecting => r.map_err(|e| quic_failure(&e, true, hs_deadline)),
                    _ = sleep_until_opt(hs_deadline.map(|ms| Instant::now() + Duration::from_millis(ms))) => Err(
                        TransportFailure::new(Phase::QuicHandshake, FailureKind::QuicHandshakeTimeout,
                            format!("no QUIC handshake completed within {} ms (UDP may be blocked, or the server does not serve HTTP/3 here)", hs_deadline.unwrap_or(0)))
                        .with_deadline(hs_deadline)),
                    _ = cancel.cancelled() => Err(TransportFailure::new(Phase::QuicHandshake, FailureKind::Canceled, "canceled during QUIC handshake")),
                };
                let quic = match result {
                    Ok(c) => c,
                    Err(mut f) => {
                        rec.finish(
                            hs_idx,
                            if f.kind == FailureKind::QuicHandshakeTimeout { PhaseStatus::TimedOut } else { PhaseStatus::Failed },
                        );
                        let tls_obs = tls::observe(&handle, &prepared, false);
                        if let TlsVerification::Failed { problem, .. } = &tls_obs.verification {
                            f.kind = *problem;
                        }
                        cobs.tls = Some(tls_obs);
                        obs.connection = Some(cobs);
                        return fail(rec, obs, f, DispatchState::NotDispatched);
                    }
                };
                rec.finish(hs_idx, PhaseStatus::Completed);
                let mut tls_obs = tls::observe(&handle, &prepared, true);
                tls_obs.version = Some("TLSv1_3".into());
                tls_obs.alpn_negotiated = quic
                    .handshake_data()
                    .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|d| d.protocol.map(|p| String::from_utf8_lossy(&p).into_owned()));
                cobs.tls = Some(tls_obs);
                cobs.protocol = Some("h3".into());
                cobs.local_address = ep.local_addr().ok().map(|a| a.to_string());
                let ph = rec.start(Phase::ProtocolHandshake);
                let (mut driver, send) = match h3::client::new(h3_quinn::Connection::new(quic.clone())).await {
                    Ok(x) => x,
                    Err(e) => {
                        rec.finish(ph, PhaseStatus::Failed);
                        obs.connection = Some(cobs);
                        let f = TransportFailure::new(
                            Phase::ProtocolHandshake,
                            FailureKind::QuicOther,
                            format!("HTTP/3 connection setup failed: {e}"),
                        );
                        return fail(rec, obs, f, DispatchState::NotDispatched);
                    }
                };
                rec.finish(ph, PhaseStatus::Completed);
                tokio::spawn(async move {
                    let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
                });
                let c = H3Conn { send, quic, template: cobs, served: Arc::new(std::sync::atomic::AtomicU32::new(0)) };
                if plan.keepalive {
                    self.pool.lock().insert(key.clone(), c.clone());
                }
                (c, false)
            }
        };
        let mut cobs = conn.template.clone();
        cobs.reused = reused;
        cobs.prior_requests = conn.served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        obs.connection = Some(cobs);

        // ---- request ----
        let explicit_host = plan.headers.iter().find(|(n, _)| n == http::header::HOST).map(|(_, v)| v.to_str().unwrap_or("").to_string());
        let uri = format!("https://{}{}", explicit_host.unwrap_or_else(|| plan.authority.clone()), plan.request_target);
        let mut req = http::Request::builder().method(plan.method.clone()).uri(uri);
        for (n, v) in &plan.headers {
            if n == http::header::HOST
                || n == http::header::CONNECTION
                || n == http::header::TRANSFER_ENCODING
                || n == http::header::UPGRADE
                || n.as_str() == "keep-alive"
            {
                continue;
            }
            req = req.header(n, v);
        }
        let req = match req.body(()) {
            Ok(r) => r,
            Err(e) => {
                let f = TransportFailure::new(Phase::Prepare, FailureKind::InvalidHeader, format!("request could not be built: {e}"));
                return fail(rec, obs, f, DispatchState::NotDispatched);
            }
        };
        let w_idx = rec.start(Phase::RequestWrite);
        let mut send = conn.send.clone();
        let sent = async {
            let mut stream = send.send_request(req).await?;
            if !plan.body.is_empty() {
                stream.send_data(plan.body.clone()).await?;
            }
            stream.finish().await?;
            Ok::<_, h3::error::StreamError>(stream)
        };
        let write_deadline = plan.timeouts.request_write_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let mut stream = tokio::select! {
            r = sent => match r {
                Ok(s) => s,
                Err(e) => {
                    rec.finish(w_idx, PhaseStatus::Failed);
                    self.pool.lock().remove(&key);
                    let f = TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteFailed, format!("sending the HTTP/3 request failed: {e}"));
                    return fail(rec, obs, f, DispatchState::MayHaveBeenSent);
                }
            },
            _ = sleep_until_opt(write_deadline) => {
                let f = TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteTimeout, "the HTTP/3 request could not be sent before the write deadline").with_deadline(plan.timeouts.request_write_ms);
                return fail(rec, obs, f, DispatchState::MayHaveBeenSent);
            }
            _ = cancel.cancelled() => {
                let f = TransportFailure::new(Phase::RequestWrite, FailureKind::Canceled, "canceled while sending");
                return fail(rec, obs, f, DispatchState::MayHaveBeenSent);
            }
        };
        rec.finish(w_idx, PhaseStatus::Completed);
        let h_idx = rec.start(Phase::AwaitResponseHeaders);
        let headers_deadline = plan.timeouts.response_headers_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let resp = tokio::select! {
            r = stream.recv_response() => match r {
                Ok(r) => r,
                Err(e) => {
                    rec.finish(h_idx, PhaseStatus::Failed);
                    let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResetBeforeResponse, format!("the HTTP/3 stream ended before a response: {e}"));
                    return fail(rec, obs, f, DispatchState::MayHaveBeenSent);
                }
            },
            _ = sleep_until_opt(headers_deadline) => {
                let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout, "no HTTP/3 response headers before the response-header deadline").with_deadline(plan.timeouts.response_headers_ms);
                return fail(rec, obs, f, DispatchState::MayHaveBeenSent);
            }
            _ = sleep_until_opt(total_deadline) => {
                let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::TotalTimeout, "total deadline elapsed").with_deadline(plan.timeouts.total_ms);
                return fail(rec, obs, f, DispatchState::MayHaveBeenSent);
            }
            _ = cancel.cancelled() => {
                let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled before response headers");
                return fail(rec, obs, f, DispatchState::MayHaveBeenSent);
            }
        };
        rec.finish(h_idx, PhaseStatus::Completed);
        obs.dispatch = DispatchState::Sent;
        let status = resp.status().as_u16();
        obs.response_status = Some(status);
        events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: index, status });
        let headers: Vec<HeaderEntry> = resp
            .headers()
            .iter()
            .map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() })
            .collect();
        obs.bytes.response_headers_logical = Some(headers.iter().map(|h| (h.name.len() + h.value.len() + 4) as u64).sum());
        let content_type = resp.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let content_encoding = resp.headers().get(http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let declared_length =
            resp.headers().get(http::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok());

        let b_idx = rec.start(Phase::ResponseBody);
        let mut captured = BytesMut::new();
        let mut wire = 0u64;
        let mut failure = None;
        let mut completeness = BodyCompleteness::Complete;
        let idle = plan.timeouts.body_idle_ms.map(Duration::from_millis);
        loop {
            let idle_deadline = idle.map(|d| Instant::now() + d);
            tokio::select! {
                r = stream.recv_data() => match r {
                    Ok(Some(mut chunk)) => {
                        let n = chunk.remaining();
                        wire += n as u64;
                        let data = chunk.copy_to_bytes(n);
                        let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                        if room > 0 {
                            captured.extend_from_slice(&data[..data.len().min(room)]);
                        }
                        if wire > plan.limits.max_response_bytes {
                            completeness = BodyCompleteness::StoppedAtLocalLimit;
                            failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::ResponseTooLargeLocal, "stopped reading at the local max_response_bytes limit"));
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        completeness = BodyCompleteness::Incomplete;
                        failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::BodyReset, format!("the HTTP/3 response stream ended abnormally: {e}")));
                        break;
                    }
                },
                _ = sleep_until_opt(idle_deadline) => {
                    completeness = BodyCompleteness::Incomplete;
                    failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::BodyIdleTimeout, "response body stalled").with_deadline(plan.timeouts.body_idle_ms));
                    break;
                }
                _ = cancel.cancelled() => {
                    completeness = BodyCompleteness::Canceled;
                    failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::Canceled, "canceled while reading the body"));
                    break;
                }
            }
        }
        let mut trailers = Vec::new();
        let mut trailers_received = false;
        if failure.is_none()
            && let Ok(Some(t)) = stream.recv_trailers().await
        {
            trailers_received = true;
            trailers = t
                .iter()
                .map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() })
                .collect();
        }
        if (plan.method == http::Method::HEAD || status == 204 || status == 304) && failure.is_none() {
            completeness = BodyCompleteness::NoBody;
        }
        rec.finish(b_idx, if failure.is_none() { PhaseStatus::Completed } else { PhaseStatus::Failed });
        obs.bytes.response_body_wire = Some(wire);
        obs.failure = failure;
        obs.duration_us = rec.us();
        obs.phases = std::mem::take(&mut rec.phases);
        let captured = captured.freeze();
        let response = ResponseRecord {
            status,
            reason: http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason().map(|r| r.to_string())),
            http_version: "HTTP/3".into(),
            headers,
            trailers,
            trailers_received,
            body: BodyCapture {
                completeness,
                wire_bytes: wire,
                declared_length,
                captured_bytes: captured.len() as u64,
                display_truncated: wire > captured.len() as u64,
                content_type,
                content_encoding,
                decoded_bytes: None,
                blob_sha256: if captured.is_empty() { None } else { Some(crate::certs::sha256_hex(&captured)) },
            },
        };
        AttemptOutput { observation: obs, response: Some(response), body: captured }
    }
}
