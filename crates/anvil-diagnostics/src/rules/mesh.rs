//! Mesh client evidence: the HBONE tunnel leg (Anvil ↔ HBONE endpoint) and
//! TLS server-name notes.
//!
//! Attribution discipline:
//! * A tunnel-leg failure is about the hop Anvil configured (scope
//!   `forward_proxy`). The inner destination was never contacted, so no rule
//!   may describe it as failed, and dispatch is `not_dispatched`.
//! * The mTLS failure is split by who decided: Anvil rejecting the
//!   endpoint's server identity (a local verification decision), the
//!   endpoint rejecting or requiring Anvil's client SVID (an alert it sent),
//!   or a handshake that failed otherwise (cause unknown).
//! * A `CONNECT` refusal is attributed to the endpoint (it answered on the
//!   authenticated HTTP/2 connection before any tunnel existed), but the
//!   precise mesh-policy cause is never claimed beyond what the public body
//!   says: several admission reasons share one public response.

use super::Ctx;
use super::tls::{describe_check, identity_evidence};
use crate::{Draft, warn};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{FailureKind as K, TlsObservation, TlsVerification, TunnelKind, TunnelObservation};
use anvil_domain::outcome::{OutcomeWarning, WarningCode};

/// Alerts that concern the client's certificate (the endpoint judged the SVID).
const CLIENT_CERT_ALERTS: &[&str] = &[
    "bad_certificate",
    "unsupported_certificate",
    "certificate_revoked",
    "certificate_expired",
    "certificate_unknown",
    "unknown_ca",
    "access_denied",
];

fn body_error(t: &TunnelObservation) -> String {
    let Some(b) = t.refusal_body.as_deref() else { return "no body".into() };
    let trimmed = b.trim();
    if let Ok(serde_json::Value::Object(o)) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(e) = o.get("error").and_then(|e| e.as_str())
    {
        return format!("\u{201c}{}\u{201d}", e.chars().take(200).collect::<String>());
    }
    if trimmed.is_empty() { "an empty body".into() } else { format!("\u{201c}{}\u{201d}", trimmed.chars().take(200).collect::<String>()) }
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    let Some(a) = ctx.final_attempt() else { return };
    let tunnel = a.connection.as_ref().and_then(|c| c.tunnel.as_ref());

    // ---- server-name notes (inner TLS and the tunnel's mTLS) ----
    let inner = a.connection.as_ref().and_then(|c| c.tls.as_ref());
    if let Some(t) = inner
        && t.server_name_overridden
    {
        out.push(sni_note(t, SourceScope::ClientToPeer, ctx.target_host(), a.index));
    }
    if let Some(t) = tunnel.and_then(|t| t.tls.as_ref())
        && t.server_name_overridden
    {
        out.push(sni_note(t, SourceScope::ForwardProxy, tunnel.map(|x| x.endpoint.clone()).unwrap_or_default(), a.index));
    }

    // The rest is the HBONE leg. A CONNECT-UDP tunnel's facts are judged by
    // the MASQUE rules (`protocol.masque`) from the protocol status.
    let Some(t) = tunnel.filter(|t| t.kind == TunnelKind::Hbone) else { return };
    let endpoint = t.endpoint.clone();

    // ---- verification bypass on the tunnel's mTLS ----
    if let Some(tt) = &t.tls
        && let TlsVerification::Bypassed { would_have_failed } = &tt.verification
    {
        warn(
            warnings,
            WarningCode::InsecureTls,
            "Certificate verification was disabled for the HBONE endpoint; its identity was not authenticated.",
        );
        let mut d = Draft::new(
            "client.tls.verification_bypassed",
            "tls.bypass",
            Confidence::Confirmed,
            SourceScope::ForwardProxy,
            Owner::Caller,
            Severity::Warning,
        )
        .ev_at(E::TlsVerifier, "tunnel.tls.verification", "bypassed", a.index)
        .var("host", format!("the HBONE endpoint {endpoint}"));
        d = match would_have_failed {
            Some(k) => d
                .ev_at(E::TlsVerifier, "tunnel.tls.would_have_failed", format!("{k:?}"), a.index)
                .var("would", super::tls::describe_verification(*k)),
            None => d.var("would", "passed or was not evaluated".to_string()),
        };
        out.push(d);
    }

    let Some(f) = a.failure.as_ref() else { return };
    let inner_f = t.failure.as_ref();
    let base = |code: &str, conf: Confidence, owner: Owner| {
        let mut d = Draft::new(code, "mesh.hbone", conf, SourceScope::ForwardProxy, owner, Severity::Error)
            .ev_at(E::NativeTransport, "failure.kind", format!("{:?}", f.kind), a.index)
            .ev_at(E::NativeTransport, "tunnel.endpoint", endpoint.clone(), a.index)
            .ev_at(E::NativeTransport, "tunnel.authority", t.authority.clone(), a.index)
            .var("endpoint", endpoint.clone())
            .var("authority", t.authority.clone())
            .var("message", f.message.clone());
        if let Some(i) = inner_f {
            d = d
                .ev_at(E::NativeTransport, "tunnel.failure.kind", format!("{:?}", i.kind), a.index)
                .ev_at(E::NativeTransport, "tunnel.failure.phase", format!("{:?}", i.phase), a.index)
                .var("detail", i.message.clone());
        }
        if let Some(tt) = &t.tls {
            d = tunnel_tls_evidence(d, tt, a.index);
        }
        d.ev_at(E::NativeTransport, "dispatch", format!("{:?}", a.dispatch), a.index)
    };

    let d = match f.kind {
        K::ProxyConnectFailed => Some(base("hbone.endpoint_unreachable", Confidence::Confirmed, Owner::NetworkAdministrator)),
        K::HboneEndpointTlsFailed => {
            let ik = inner_f.map(|i| i.kind).unwrap_or(K::TlsOther);
            let alert = f.tls_alert.clone().or_else(|| inner_f.and_then(|i| i.tls_alert.clone())).unwrap_or_default();
            let presented = t.tls.as_ref().map(|x| x.client_certificate_presented.is_some()).unwrap_or(false);
            let d = if ik.is_tls_verification() {
                let problem = match t.tls.as_ref().map(|x| &x.verification) {
                    Some(TlsVerification::Failed { detail, .. }) => detail.clone(),
                    _ => super::tls::describe_verification(ik),
                };
                let expected =
                    t.tls.as_ref().and_then(|x| x.identity_check.as_ref()).map(describe_check).unwrap_or_else(|| "its host name".into());
                base("hbone.endpoint_identity_rejected", Confidence::Confirmed, Owner::Caller)
                    .var("problem", problem)
                    .var("expected", expected)
                    .var(
                        "peer_spiffe_id",
                        t.tls.as_ref().and_then(|x| x.peer_spiffe_id.clone()).unwrap_or_else(|| "no single SPIFFE ID".into()),
                    )
            } else if alert == "certificate_required" && !presented {
                base("hbone.client_svid_required", Confidence::Confirmed, Owner::Caller)
            } else if presented
                && (CLIENT_CERT_ALERTS.contains(&alert.as_str())
                    // TLS 1.3: after Anvil's Finished, the endpoint's only
                    // remaining handshake decision is the client certificate.
                    || (ik == K::TlsAlertAfterHandshake && alert == "handshake_failure"))
            {
                base("hbone.client_svid_rejected", Confidence::Likely, Owner::Caller)
            } else {
                let conf = match ik {
                    K::TlsHandshakeTimeout => Confidence::Confirmed,
                    K::TlsProtocolMismatch => Confidence::Likely,
                    _ => Confidence::Unknown,
                };
                base("hbone.endpoint_tls_failed", conf, Owner::Unknown)
            };
            Some(if alert.is_empty() {
                d
            } else {
                d.ev_at(E::NativeTransport, "tunnel.tls.alert", alert.clone(), a.index).var("alert", alert)
            })
        }
        K::HboneConnectRefused => {
            let status = f.status.or(t.connect_status).unwrap_or(0);
            // The CONNECT answer came over the endpoint's own HTTP/2
            // connection; its origin is certain only when that connection's
            // identity was verified.
            let verified = t.tls.as_ref().map(|x| x.verification == TlsVerification::Verified).unwrap_or(false);
            let conf = if verified { Confidence::Confirmed } else { Confidence::Likely };
            let code = match status >= 500 {
                true => "hbone.tunnel_unavailable",
                false => "hbone.tunnel_refused",
            };
            let mut d = base(code, conf, Owner::Unknown)
                .ev_at(E::HttpStatus, "tunnel.connect_status", status.to_string(), a.index)
                .var("status", status.to_string())
                .var("body_error", body_error(t));
            if let Some(b) = &t.refusal_body {
                d = d.ev_at(E::BodyContent, "tunnel.refusal_body", b.chars().take(300).collect::<String>(), a.index);
            }
            if !t.connect_headers.is_empty() {
                d = d.ev_at(
                    E::Configuration,
                    "tunnel.connect_headers",
                    t.connect_headers.iter().map(|h| h.name.clone()).collect::<Vec<_>>().join(", "),
                    a.index,
                );
            }
            Some(d)
        }
        // TLS 1.3 client-SVID refusal whose alert was lost: the endpoint asked
        // for a client certificate, Anvil finished its side of the handshake,
        // and the fresh HBONE connection then closed or reset before any
        // CONNECT answer without a readable alert (the peer's reset can
        // discard it). Same shape as `client.tls.closed_after_certificate_request`.
        K::HboneProtocolError
            if f.tls_alert.is_none()
                && inner_f.is_some_and(|i| {
                    matches!(i.kind, K::ClosedBeforeResponse | K::ResetBeforeResponse | K::RequestWriteFailed | K::HttpProtocolError)
                        && i.phase == anvil_domain::execution::Phase::ProxyTunnel
                })
                && t.tls
                    .as_ref()
                    .is_some_and(|x| x.client_certificate_requested == Some(true) && x.version.as_deref() == Some("TLSv1_3")) =>
        {
            let presented = t.tls.as_ref().and_then(|x| x.client_certificate_presented.as_ref());
            let conf = if presented.is_some() { Confidence::Unknown } else { Confidence::Likely };
            Some(base("hbone.closed_after_certificate_request", conf, Owner::Caller))
        }
        K::HboneProtocolError => {
            let conf = if f.deadline_ms.is_some() { Confidence::Confirmed } else { Confidence::Unknown };
            let mut d = base("hbone.tunnel_protocol_error", conf, Owner::Unknown);
            if let Some(c) = f.h2_error_code {
                d = d.ev_at(E::NativeTransport, "h2.error_code", super::transport::h2_name(c), a.index);
            }
            Some(d)
        }
        _ => None,
    };
    if let Some(d) = d {
        out.push(d);
    }
}

fn tunnel_tls_evidence(mut d: Draft, t: &TlsObservation, attempt: u32) -> Draft {
    if let Some(c) = &t.client_certificate_presented {
        d = d
            .ev_at(E::NativeTransport, "tunnel.tls.client_svid", c.subject_alt_names.join(", "), attempt)
            .var("client_svid", c.subject_alt_names.iter().find(|s| s.starts_with("URI:")).cloned().unwrap_or_else(|| c.subject.clone()));
    } else {
        d = d.ev_at(E::NativeTransport, "tunnel.tls.client_svid", "none", attempt).var("client_svid", "none");
    }
    if let Some(r) = t.client_certificate_requested {
        d = d.ev_at(E::NativeTransport, "tunnel.tls.client_cert_requested", r.to_string(), attempt);
    }
    d = d.ev_at(E::TlsVerifier, "tunnel.tls.verification", verification_label(&t.verification), attempt);
    identity_evidence(d, t, attempt)
}

fn verification_label(v: &TlsVerification) -> String {
    match v {
        TlsVerification::Verified => "verified".into(),
        TlsVerification::Failed { problem, .. } => format!("failed: {problem:?}"),
        TlsVerification::Bypassed { .. } => "bypassed".into(),
        TlsVerification::NotReached => "not reached".into(),
    }
}

fn sni_note(t: &TlsObservation, scope: SourceScope, host: String, attempt: u32) -> Draft {
    let check = t.identity_check.as_ref().map(describe_check).unwrap_or_else(|| format!("host name {}", t.server_name));
    let d = Draft::new("client.tls.sni_override", "tls.server_name", Confidence::Confirmed, scope, Owner::Caller, Severity::Info)
        .ev_at(E::Configuration, "tls.server_name_override", t.server_name.clone(), attempt)
        .ev_at(E::NativeTransport, "tls.sni", t.sni.clone().unwrap_or_else(|| "none".into()), attempt)
        .ev_at(E::TlsVerifier, "tls.identity_check", check.clone(), attempt)
        .var("host", host)
        .var("server_name", t.server_name.clone())
        .var("identity_check", check);
    if t.sni.is_some() {
        d.var("sni_sent", format!("sent SNI {}", t.server_name))
    } else {
        d.var("sni_sent", format!("sent no SNI ({} is an IP address, which TLS does not carry as SNI)", t.server_name))
    }
}
