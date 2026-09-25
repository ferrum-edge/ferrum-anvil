//! Ferrum-specific rules. Current public markers are coarse and, per the
//! v0.9.5 audit, can be influenced by the backend (the gateway stamps
//! `backend_error` onto a backend's own 5xx and passes a backend-authored
//! `X-Gateway-Upstream-Status` through). Rules therefore:
//! * treat markers from untrusted destinations as "Ferrum-like" only;
//! * never map a coarse token to a single precise cause;
//! * report conflicting / unknown / missing markers explicitly;
//! * use catalog signature matches as "consistent with", listing every
//!   outcome that shares the same public signal.

use super::Ctx;
use crate::facts::FerrumTrust;
use crate::ferrum::{self, MatchStrength, Signal};
use crate::{Draft, warn};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Remediation, Severity, SourceScope};
use anvil_domain::outcome::{OutcomeWarning, WarningCode};

const MARKER: &str = "x-gateway-error";
const UPSTREAM_STATUS: &str = "x-gateway-upstream-status";

fn scope_for_family(f: &str) -> SourceScope {
    match f {
        "upstream_network" => SourceScope::GatewayToUpstream,
        "streaming" => SourceScope::ResponseDelivery,
        "frontend_tls" | "frontend_parse" | "l4" => SourceScope::ClientToPeer,
        "protocol" => SourceScope::GatewayAdmission,
        _ => SourceScope::GatewayAdmission,
    }
}

fn owner_from(s: &str) -> Owner {
    match s {
        "caller" => Owner::Caller,
        "gateway_operator" => Owner::GatewayOperator,
        "api_owner" => Owner::ApiOwner,
        _ => Owner::Unknown,
    }
}

fn token_scope(t: &str) -> SourceScope {
    match t {
        "connection_failure" | "backend_timeout" | "backend_error" => SourceScope::GatewayToUpstream,
        _ => SourceScope::GatewayAdmission,
    }
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    let Some(r) = ctx.input.response else { return };
    let idx = ctx.attempt_index();
    let cat = ferrum::catalog();

    // Collect marker values (repeated headers and comma-joined values).
    let mut tokens: Vec<String> = Vec::new();
    for v in r.header_values(MARKER).into_iter().chain(r.trailer_values(MARKER)) {
        for part in v.split(',') {
            let p = part.trim().to_ascii_lowercase();
            if !p.is_empty() && !tokens.contains(&p) {
                tokens.push(p);
            }
        }
    }
    let degraded = r.header_values(UPSTREAM_STATUS).iter().any(|v| v.trim().eq_ignore_ascii_case("degraded"));

    let (trusted, channel_auth, profile) = match ctx.input.trust {
        FerrumTrust::Trusted { channel_authenticated, profile_name, .. } => (true, *channel_authenticated, profile_name.clone()),
        FerrumTrust::NotConfigured => (false, false, String::new()),
    };

    if !trusted {
        if !tokens.is_empty() || degraded {
            warn(
                warnings,
                WarningCode::UnverifiedFerrumMarker,
                "A Ferrum-like diagnostic header was observed from a destination that is not a trusted Ferrum profile.",
            );
            let mut d = Draft::new(
                "ferrum.marker.unverified",
                "ferrum.marker",
                Confidence::Confirmed,
                SourceScope::Unknown,
                Owner::Caller,
                Severity::Info,
            )
            .var("values", if tokens.is_empty() { "X-Gateway-Upstream-Status: degraded".into() } else { tokens.join(", ") });
            for t in &tokens {
                d = d.ev_at(E::FerrumMarkerUnverified, "header.x-gateway-error", t.clone(), idx);
            }
            out.push(d);
        }
        return;
    }

    // Provenance ceiling: markers are only as trustworthy as the channel and
    // the gateway's ownership of the header.
    let ceiling = if channel_auth && cat.marker_spoofable == Some(false) { Confidence::Confirmed } else { Confidence::Likely };
    let src = E::FerrumMarkerTrusted;

    if degraded {
        warn(warnings, WarningCode::DegradedRouting, "The gateway reported degraded upstream selection for this request.");
        out.push(
            Draft::new(
                "ferrum.degraded_routing",
                "ferrum.marker",
                Confidence::Likely.min(ceiling),
                SourceScope::GatewayToUpstream,
                Owner::GatewayOperator,
                Severity::Info,
            )
            .ev_at(src, "header.x-gateway-upstream-status", "degraded", idx)
            .var("status", r.status.to_string())
            .var("profile", profile.clone()),
        );
    }

    let token = match tokens.len() {
        0 => None,
        1 => Some(tokens[0].clone()),
        _ => {
            let mut d = Draft::new(
                "ferrum.marker.conflicting",
                "ferrum.marker",
                Confidence::ConflictingEvidence,
                SourceScope::Unknown,
                Owner::GatewayOperator,
                Severity::Warning,
            )
            .var("values", tokens.join(", "));
            for t in &tokens {
                d = d.ev_at(src, "header.x-gateway-error", t.clone(), idx);
            }
            out.push(d);
            return;
        }
    };

    if let Some(t) = &token
        && !cat.is_known_token(t)
    {
        out.push(
            Draft::new(
                "ferrum.marker.unknown_token",
                "ferrum.marker",
                Confidence::Unknown,
                SourceScope::Unknown,
                Owner::GatewayOperator,
                Severity::Warning,
            )
            .ev_at(src, "header.x-gateway-error", t.clone(), idx)
            .var("token", t.clone())
            .var("compat", cat.compatibility_id.clone()),
        );
        return;
    }

    if let Some(t) = &token {
        let code = format!("ferrum.token.{t}");
        let conf = Confidence::Confirmed.min(ceiling);
        let mut d = Draft::new(code, "ferrum.marker", conf, token_scope(t), Owner::GatewayOperator, Severity::Error)
            .ev_at(src, "header.x-gateway-error", t.clone(), idx)
            .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
            .var("status", r.status.to_string())
            .var("token", t.clone())
            .var("profile", profile.clone());
        if !channel_auth {
            d = d.not_proven(
                "That this marker was authored by the gateway: the connection to the gateway was not authenticated with verified TLS.",
            );
        }
        out.push(d);
    } else if r.status >= 500 && !matches!(ctx.input.protocol, anvil_domain::request::Protocol::Grpc) {
        out.push(
            Draft::new(
                "ferrum.marker.absent",
                "ferrum.marker",
                Confidence::Unknown,
                SourceScope::Unknown,
                Owner::Unknown,
                Severity::Warning,
            )
            .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
            .var("status", r.status.to_string())
            .var("profile", profile.clone()),
        );
    }

    // ---- catalog signature match ----
    let body_text = String::from_utf8_lossy(ctx.input.body);
    let grpc_status = match ctx.input.protocol_status {
        anvil_domain::outcome::ProtocolStatus::Grpc { grpc_status, .. } => *grpc_status,
        _ => None,
    };
    let matches =
        cat.match_signal(&Signal { status: r.status, token: token.as_deref(), body_text: &body_text, body: ctx.body, grpc_status });
    let exact: Vec<_> = matches.iter().filter(|(_, s)| *s == MatchStrength::Exact).map(|(o, _)| *o).collect();
    let passthrough: Vec<_> = matches.iter().filter(|(_, s)| *s == MatchStrength::PassThrough).map(|(o, _)| *o).collect();

    // Body text is weak evidence: a backend can return identical bytes.
    let body_ceiling = Confidence::Likely.min(ceiling);
    if exact.len() == 1 && exact[0].shared_signal_with.is_empty() {
        let o = exact[0];
        let mut d = Draft::new(
            "ferrum.outcome",
            "ferrum.catalog",
            body_ceiling,
            scope_for_family(&o.family),
            owner_from(&o.owner),
            Severity::Error,
        )
        .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
        .ev_at(E::BodyContent, "body.signature", body_text.chars().take(160).collect::<String>(), idx)
        .ev(E::Configuration, "catalog.outcome", o.id.clone())
        .var("outcome", o.id.clone());
        d.catalog_text = Some((catalog_title(&o.id), o.minimum_truthful_diagnosis.clone()));
        d.extra_does_not_prove.extend(o.must_not_claim.iter().cloned());
        d.extra_does_not_prove.push("That the gateway (rather than a backend returning identical bytes) authored this body.".into());
        d.extra_remediation.extend(o.remediation.iter().map(|t| Remediation { text: t.clone(), owner: owner_from(&o.owner) }));
        out.push(d);
    } else if !exact.is_empty() {
        let mut ids: Vec<String> = exact.iter().map(|o| o.id.clone()).collect();
        for o in &exact {
            for s in &o.shared_signal_with {
                if !ids.contains(s) {
                    ids.push(s.clone());
                }
            }
        }
        let mut d = Draft::new(
            "ferrum.outcome_ambiguous",
            "ferrum.catalog",
            Confidence::Unknown,
            SourceScope::Unknown,
            Owner::GatewayOperator,
            Severity::Error,
        )
        .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
        .ev_at(E::BodyContent, "body.signature", body_text.chars().take(160).collect::<String>(), idx)
        .ev(E::Configuration, "catalog.candidates", ids.join(", "))
        .var("count", ids.len().to_string());
        for id in &ids {
            if let Some(o) = cat.outcome(id) {
                d.extra_alternatives.push(format!("{} ({})", o.minimum_truthful_diagnosis, o.id));
            }
        }
        // The common, always-true statement for the group.
        if let Some(first) = exact.first() {
            d = d.var("common", first.minimum_truthful_diagnosis.clone());
        }
        out.push(d);
    } else if let Some(o) = passthrough.first() {
        let mut d = Draft::new(
            "ferrum.backend_passthrough",
            "ferrum.catalog",
            body_ceiling,
            SourceScope::UpstreamApplication,
            Owner::ApiOwner,
            Severity::Error,
        )
        .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
        .ev(E::Configuration, "catalog.outcome", o.id.clone())
        .var("status", r.status.to_string());
        if let Some(t) = &token {
            d = d.var("token", t.clone());
        } else {
            d = d.var("token", "none".to_string());
        }
        out.push(d);
    }
}

fn catalog_title(id: &str) -> String {
    let family = id.split('.').next().unwrap_or("");
    let label = match family {
        "upstream" => "Gateway could not complete the upstream exchange",
        "gateway" => "Gateway rejected or could not serve the request",
        "size" => "Gateway size limit",
        "frontend_parse" => "Gateway rejected the request framing",
        "frontend_tls" => "Gateway TLS listener rejected the connection",
        "protocol" => "Gateway protocol-specific rejection",
        "streaming" => "Response stream failed after headers",
        "auth" => "Gateway authentication outcome",
        "plugin" => "Gateway plugin outcome",
        _ => "Ferrum Edge outcome",
    };
    label.to_string()
}
