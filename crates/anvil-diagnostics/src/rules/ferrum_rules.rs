//! Ferrum-specific rules. Current public markers are coarse and, per the
//! v0.9.5 and v0.9.7 audits, can be influenced by the backend (the gateway
//! stamps `backend_error` onto a backend's own 5xx and passes a
//! backend-authored `X-Gateway-Upstream-Status` through). Rules therefore:
//! * treat markers from untrusted destinations as "Ferrum-like" only;
//! * never map a coarse token to a single precise cause;
//! * report conflicting / unknown / missing markers explicitly;
//! * use the catalog of the trusted profile's own compatibility id — never
//!   another release's — and report a missing catalog instead of matching;
//! * use catalog signature matches as "consistent with", listing every
//!   outcome that shares the same public signal.

use super::Ctx;
use crate::facts::FerrumTrust;
use crate::ferrum::{self, FerrumCatalog, MatchStrength, Signal};
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
        "connection_failure" | "backend_timeout" => SourceScope::GatewayToUpstream,
        // On 0.9.5 and 0.9.7 `backend_error` is stamped on the application's own 5xx
        // (upstream application), on failed upstream exchanges (gateway to
        // upstream) and on gateway-local refusals such as retained-buffer
        // capacity or response-phase policy rejections (live: UP-015,
        // GW-020 content guard). The token alone does not identify the leg.
        "backend_error" => SourceScope::Unknown,
        _ => SourceScope::GatewayAdmission,
    }
}

fn token_owner(t: &str) -> Owner {
    match t {
        // Application 5xx belongs to the API owner, gateway-local refusals to
        // the operator; the token cannot tell them apart.
        "backend_error" => Owner::Unknown,
        _ => Owner::GatewayOperator,
    }
}

/// What the rules know about the trusted profile's gateway release.
enum Basis {
    /// The embedded, source-audited catalog of the profile's compatibility id.
    Catalog(&'static FerrumCatalog),
    /// No catalog for this compatibility id: only the vocabulary and coarse
    /// token meaning shared by every audited release apply.
    Uncatalogued { compat: String },
}

impl Basis {
    fn is_known_token(&self, t: &str) -> bool {
        match self {
            Basis::Catalog(c) => c.is_known_token(t),
            Basis::Uncatalogued { .. } => ferrum::shared_tokens().iter().any(|k| k == t),
        }
    }

    fn marker_spoofable(&self) -> Option<bool> {
        match self {
            Basis::Catalog(c) => c.marker_spoofable,
            Basis::Uncatalogued { .. } => None,
        }
    }

    /// Wording for the `{basis}` placeholder.
    fn describe(&self) -> String {
        match self {
            Basis::Catalog(c) => format!("compatibility catalog {}", c.compatibility_id),
            Basis::Uncatalogued { compat } => {
                format!("no catalog for {compat}; the vocabulary shared by {}", audited_releases())
            }
        }
    }
}

fn audited_releases() -> String {
    ferrum::compatibility_ids().collect::<Vec<_>>().join(", ")
}

fn has_error_signal(ctx: &Ctx<'_>, status: u16) -> bool {
    status >= 400
        || matches!(ctx.input.protocol_status, anvil_domain::outcome::ProtocolStatus::Grpc { grpc_status: Some(g), .. } if *g != 0)
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    let Some(r) = ctx.input.response else { return };
    let idx = ctx.attempt_index();

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

    let (trusted, channel_auth, profile, compat) = match ctx.input.trust {
        FerrumTrust::Trusted { channel_authenticated, profile_name, compatibility_id } => {
            (true, *channel_authenticated, profile_name.clone(), compatibility_id.trim().to_string())
        }
        FerrumTrust::NotConfigured => (false, false, String::new(), String::new()),
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

    let basis = match ferrum::catalog_for(&compat) {
        Some(c) => Basis::Catalog(c),
        None if compat.is_empty() => Basis::Uncatalogued { compat: "(no compatibility id)".into() },
        None => Basis::Uncatalogued { compat: compat.clone() },
    };
    if let Basis::Uncatalogued { compat } = &basis
        && (!tokens.is_empty() || degraded || has_error_signal(ctx, r.status))
    {
        out.push(
            Draft::new(
                "ferrum.catalog.unavailable",
                "ferrum.catalog",
                Confidence::Unknown,
                SourceScope::Unknown,
                Owner::Caller,
                Severity::Warning,
            )
            .ev(E::Configuration, "integration.compatibility_id", compat.clone())
            .ev(E::Configuration, "catalog.available", audited_releases())
            .var("compat", compat.clone())
            .var("profile", profile.clone())
            .var("available", audited_releases()),
        );
    }

    // Provenance ceiling: markers are only as trustworthy as the channel and
    // the gateway's ownership of the header. Without a catalog the header's
    // ownership is not established, so the ceiling stays at likely.
    let ceiling = if channel_auth && basis.marker_spoofable() == Some(false) { Confidence::Confirmed } else { Confidence::Likely };
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
        && !basis.is_known_token(t)
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
            .var("basis", basis.describe()),
        );
        return;
    }

    // Status/marker consistency. The gateway core writes the seven tokens only
    // on 5xx HTTP responses (gRPC carries them on HTTP 200 trailers-only
    // responses); `src/retry.rs` is identical in every audited release, so this
    // holds for all of them. A known token on a 1xx-4xx HTTP response therefore did not
    // come from the gateway's error classification: a response-header plugin
    // on a rejection path, or an intermediary, added it (live: GW-019
    // reject-path decoration). Report the conflict instead of the token's
    // meaning, and do not match catalog outcomes against it.
    let grpc_shaped = matches!(ctx.input.protocol, anvil_domain::request::Protocol::Grpc)
        || r.body.content_type.as_deref().is_some_and(|ct| ct.trim().to_ascii_lowercase().starts_with("application/grpc"));
    if let Some(t) = &token
        && r.status < 500
        && !grpc_shaped
    {
        out.push(
            Draft::new(
                "ferrum.marker.inconsistent",
                "ferrum.marker",
                Confidence::ConflictingEvidence,
                SourceScope::Unknown,
                Owner::GatewayOperator,
                Severity::Warning,
            )
            .ev_at(src, "header.x-gateway-error", t.clone(), idx)
            .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
            .var("token", t.clone())
            .var("status", r.status.to_string())
            .var("basis", basis.describe()),
        );
        return;
    }

    if let Some(t) = &token {
        let code = format!("ferrum.token.{t}");
        let conf = Confidence::Confirmed.min(ceiling);
        let mut d = Draft::new(code, "ferrum.marker", conf, token_scope(t), token_owner(t), Severity::Error)
            .ev_at(src, "header.x-gateway-error", t.clone(), idx)
            .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
            .var("status", r.status.to_string())
            .var("token", t.clone())
            .var("profile", profile.clone());
        if let Basis::Catalog(c) = &basis
            && let Some(n) = c.token_notes.get(t)
        {
            d = with_release_notes(d, n);
        }
        if !channel_auth {
            d = d.not_proven(
                "That this marker was authored by the gateway: the connection to the gateway was not authenticated with verified TLS.",
            );
        }
        out.push(d);
    } else if r.status >= 500 && !matches!(ctx.input.protocol, anvil_domain::request::Protocol::Grpc) {
        let mut d = Draft::new(
            "ferrum.marker.absent",
            "ferrum.marker",
            Confidence::Unknown,
            SourceScope::Unknown,
            Owner::Unknown,
            Severity::Warning,
        )
        .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
        .var("status", r.status.to_string())
        .var("profile", profile.clone());
        if let Basis::Catalog(c) = &basis {
            d = with_release_notes(d, &c.absent_notes);
        }
        out.push(d);
    }

    // ---- catalog signature match ----
    // Only against the profile's own release: without a catalog there is no
    // audited outcome inventory to compare with (reported above).
    let Basis::Catalog(cat) = basis else { return };
    let release = cat.release_label();
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

    // The gateway's own Via hop is written only by its backend-response
    // builder; 0.9.5 and 0.9.7 never add it to pre-dispatch authentication or
    // authorization rejections (lab-verified on both). A body that matches such a
    // rejection but arrived with that hop was relayed from behind the
    // gateway, so the gateway-rejection candidates are contradicted.
    let exact = match gateway_via_hop(r) {
        Some(via) => {
            let (contradicted, rest): (Vec<_>, Vec<_>) = exact.into_iter().partition(|o| pre_dispatch_reject(o));
            if !contradicted.is_empty() && rest.is_empty() {
                let ids: Vec<String> = contradicted.iter().map(|o| o.id.clone()).collect();
                out.push(
                    Draft::new(
                        "ferrum.relayed_backend_response",
                        "ferrum.catalog",
                        body_ceiling,
                        SourceScope::UpstreamApplication,
                        Owner::ApiOwner,
                        Severity::Error,
                    )
                    .ev_at(E::HttpHeader, "header.via", via.clone(), idx)
                    .ev_at(E::HttpStatus, "status", r.status.to_string(), idx)
                    .ev_at(E::BodyContent, "body.signature", body_text.chars().take(160).collect::<String>(), idx)
                    .ev(E::Configuration, "catalog.contradicted", ids.join(", "))
                    .ev(E::Configuration, "catalog.compatibility_id", cat.compatibility_id.clone())
                    .var("status", r.status.to_string())
                    .var("via", via)
                    .var("release", release.clone())
                    .var("outcome", ids.join(", ")),
                );
                return;
            }
            rest
        }
        None => exact,
    };
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
        .ev(E::Configuration, "catalog.compatibility_id", cat.compatibility_id.clone())
        .var("outcome", o.id.clone())
        .var("release", release.clone());
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
        .ev(E::Configuration, "catalog.compatibility_id", cat.compatibility_id.clone())
        .var("count", ids.len().to_string())
        .var("release", release.clone());
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
        .ev(E::Configuration, "catalog.compatibility_id", cat.compatibility_id.clone())
        .var("status", r.status.to_string())
        .var("release", release);
        if let Some(t) = &token {
            d = d.var("token", t.clone());
        } else {
            d = d.var("token", "none".to_string());
        }
        out.push(d);
    }
}

/// Append a catalog's release-specific sentences to a marker finding. The
/// wording catalog keeps these findings release-neutral (`{release_detail}`
/// is empty when no catalog applies).
fn with_release_notes(mut d: Draft, n: &ferrum::ReleaseNotes) -> Draft {
    if !n.explanation.trim().is_empty() {
        d = d.var("release_detail", n.explanation.clone());
    }
    d.extra_alternatives.extend(n.alternatives.iter().cloned());
    d.extra_does_not_prove.extend(n.does_not_prove.iter().cloned());
    d
}

/// The Via hop Ferrum Edge adds on its backend-response path (default
/// pseudonym `ferrum-edge`), if present. A renamed or disabled pseudonym
/// yields `None`, which keeps the ordinary catalog matching.
fn gateway_via_hop(r: &anvil_domain::execution::ResponseRecord) -> Option<String> {
    r.header_values("via")
        .into_iter()
        .flat_map(|v| v.split(','))
        .map(|hop| hop.trim())
        .find(|hop| hop.split_whitespace().nth(1).map(|name| name.eq_ignore_ascii_case("ferrum-edge")).unwrap_or(false))
        .map(|hop| hop.to_string())
}

/// Outcomes rendered by the gateway's pre-dispatch reject builder (no Via):
/// authentication / authorization 4xx rejections. Credential-lifetime expiry
/// is excluded because it can replace a response after dispatch, and 5xx
/// plugin outcomes because some are raised at the final request body, where
/// the audit could not rule out the backend-response builder.
fn pre_dispatch_reject(o: &ferrum::Outcome) -> bool {
    matches!(o.family.as_str(), "auth" | "authorization")
        && !o.id.contains("lifetime")
        && !o.id.starts_with("protocol.")
        && !o.statuses.is_empty()
        && o.statuses.iter().all(|s| *s < 500)
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

#[cfg(test)]
mod tests {
    use crate::facts::{DiagnosticInput, FerrumTrust};
    use anvil_domain::diagnostics::{Confidence, DiagnosticFinding};
    use anvil_domain::execution::{BodyCapture, BodyCompleteness, HeaderEntry, ResponseRecord};
    use anvil_domain::outcome::ProtocolStatus;
    use anvil_domain::request::Protocol;

    fn response(status: u16, content_type: &str, headers: &[(&str, &str)]) -> ResponseRecord {
        ResponseRecord {
            status,
            reason: None,
            http_version: "HTTP/1.1".into(),
            headers: headers.iter().map(|(n, v)| HeaderEntry { name: n.to_string(), value: v.to_string() }).collect(),
            trailers: vec![],
            trailers_received: false,
            body: BodyCapture {
                completeness: BodyCompleteness::Complete,
                wire_bytes: 0,
                declared_length: None,
                captured_bytes: 0,
                display_truncated: false,
                content_type: Some(content_type.into()),
                content_encoding: None,
                decoded_bytes: None,
                blob_sha256: None,
            },
        }
    }

    fn diagnose(protocol: Protocol, r: &ResponseRecord, body: &[u8]) -> Vec<DiagnosticFinding> {
        diagnose_as(protocol, r, body, "ferrum-edge-0.9.5")
    }

    fn diagnose_as(protocol: Protocol, r: &ResponseRecord, body: &[u8], compat: &str) -> Vec<DiagnosticFinding> {
        let trust = FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: compat.into(), channel_authenticated: false };
        let ps = ProtocolStatus::Http { status: r.status, reason: None };
        crate::diagnose(&DiagnosticInput {
            protocol,
            method: "GET",
            preparation_failure: None,
            attempts: &[],
            response: Some(r),
            body,
            stream: None,
            protocol_status: &ps,
            trust: &trust,
            tls_verification_enabled: true,
            credentials_stripped_on_redirect: false,
            protocol_fallback_from: None,
        })
        .findings
    }

    fn find<'a>(f: &'a [DiagnosticFinding], code: &str) -> Option<&'a DiagnosticFinding> {
        f.iter().find(|x| x.code == code)
    }

    /// Live GW-019 (policy lab): a response_transformer on an ip_restriction
    /// rejection added `X-Gateway-Error: overload` to the 403. The gateway core
    /// never writes a token on a 4xx, so this must not become an overload claim.
    #[test]
    fn known_token_on_a_4xx_is_inconsistent_not_attributed() {
        let body = br#"{"error":"IP address denied"}"#;
        let r = response(403, "application/json", &[("x-gateway-error", "overload")]);
        let f = diagnose(Protocol::Http, &r, body);
        assert!(!f.iter().any(|x| x.code.starts_with("ferrum.token.")), "{:?}", f.iter().map(|x| &x.code).collect::<Vec<_>>());
        assert!(find(&f, "ferrum.outcome").is_none(), "no catalog attribution against a conflicting marker");
        let inc = find(&f, "ferrum.marker.inconsistent").expect("inconsistent marker finding");
        assert_eq!(inc.confidence, Confidence::ConflictingEvidence);
        assert!(inc.explanation.contains("overload") && inc.explanation.contains("403"), "{}", inc.explanation);
        assert!(!inc.remediation.iter().any(|r| r.text.to_lowercase().contains("disable")), "no bypass advice");
        assert!(find(&f, "http.forbidden").is_some(), "the generic 403 meaning is still reported");
    }

    #[test]
    fn known_token_on_a_5xx_keeps_its_capped_meaning() {
        let body = br#"{"error":"Service overloaded"}"#;
        let r = response(503, "application/json", &[("x-gateway-error", "overload")]);
        let f = diagnose(Protocol::Http, &r, body);
        let t = find(&f, "ferrum.token.overload").expect("token finding");
        assert_eq!(t.confidence, Confidence::Likely, "plain-HTTP trust caps at likely");
        assert!(find(&f, "ferrum.marker.inconsistent").is_none());
    }

    #[test]
    fn grpc_trailers_only_token_on_http_200_is_not_inconsistent() {
        let r = response(200, "application/grpc", &[("x-gateway-error", "circuit_breaker_open"), ("grpc-status", "14")]);
        let f = diagnose(Protocol::Http, &r, b"");
        assert!(find(&f, "ferrum.marker.inconsistent").is_none(), "{:?}", f.iter().map(|x| &x.code).collect::<Vec<_>>());
    }

    /// Live GW-013 (policy lab): OPA fail-closed 503 carries no marker. The
    /// "absent marker" finding must name the plugin-rejection possibility
    /// rather than only pointing at the application.
    #[test]
    fn absent_marker_names_plugin_rejections() {
        let body = br#"{"error":"authorization service unavailable"}"#;
        let r = response(503, "application/json", &[]);
        let f = diagnose(Protocol::Http, &r, body);
        let a = find(&f, "ferrum.marker.absent").expect("absent marker finding");
        assert_eq!(a.confidence, Confidence::Unknown);
        assert!(a.alternatives.iter().any(|x| x.contains("plugin")), "{:?}", a.alternatives);
    }

    /// Live UP-015 / GW-020 (admission and policy labs): the gateway stamps
    /// `backend_error` on its own retained-buffer refusal and on an AI
    /// response-guard rejection of a provider 200. The token must not pin the
    /// failure on the gateway-to-upstream leg or on one owner.
    #[test]
    fn backend_error_token_does_not_claim_a_leg_or_owner() {
        let body = br#"{"error":"Response buffering capacity exceeded"}"#;
        let r = response(503, "application/json", &[("x-gateway-error", "backend_error")]);
        let f = diagnose(Protocol::Http, &r, body);
        let t = find(&f, "ferrum.token.backend_error").expect("token finding");
        assert_eq!(t.scope, anvil_domain::diagnostics::SourceScope::Unknown);
        assert_eq!(t.owner, anvil_domain::diagnostics::Owner::Unknown);
        assert_eq!(t.confidence, Confidence::Likely);
        assert!(t.alternatives.iter().any(|a| a.contains("response policy")), "{:?}", t.alternatives);
        assert!(
            !f.iter().any(|x| x.confidence >= Confidence::Likely && x.scope == anvil_domain::diagnostics::SourceScope::UpstreamApplication)
        );
    }

    fn candidates(f: &[DiagnosticFinding]) -> Vec<String> {
        f.iter()
            .filter(|x| x.code.starts_with("ferrum.outcome"))
            .flat_map(|x| x.evidence.iter().filter(|e| e.key == "catalog.candidates" || e.key == "catalog.outcome"))
            .flat_map(|e| e.value.split(", ").map(String::from).collect::<Vec<_>>())
            .collect()
    }

    /// A profile whose compatibility id has no embedded catalog never borrows
    /// another release's: no outcome matching, an explicit unknown-confidence
    /// finding, and only the release-neutral token meaning (capped at likely).
    #[test]
    fn unknown_release_gets_no_catalog_and_only_shared_token_semantics() {
        let body = br#"{"error":"Backend timeout"}"#;
        let r = response(504, "application/json", &[("x-gateway-error", "backend_timeout")]);
        let f = diagnose_as(Protocol::Http, &r, body, "ferrum-edge-0.9.9");
        let u = find(&f, "ferrum.catalog.unavailable").expect("catalog-unavailable finding");
        assert_eq!(u.confidence, Confidence::Unknown);
        assert!(u.explanation.contains("ferrum-edge-0.9.9") && u.explanation.contains("ferrum-edge-0.9.7"), "{}", u.explanation);
        assert!(!f.iter().any(|x| x.code.starts_with("ferrum.outcome") || x.code == "ferrum.backend_passthrough"), "{:?}", codes(&f));
        let t = find(&f, "ferrum.token.backend_timeout").expect("shared token meaning still applies");
        assert_eq!(t.confidence, Confidence::Likely);
        let text = format!("{} {:?}", t.explanation, t.does_not_prove);
        assert!(!text.contains("0.9.5") && !text.contains("0.9.7"), "no release-specific claim for an unaudited release: {text}");
        // A token outside the shared vocabulary stays unknown.
        let r = response(502, "application/json", &[("x-gateway-error", "upstream_reset")]);
        let f = diagnose_as(Protocol::Http, &r, br#"{"error":"x"}"#, "ferrum-edge-0.9.9");
        assert!(find(&f, "ferrum.marker.unknown_token").is_some_and(|x| x.explanation.contains("no catalog for ferrum-edge-0.9.9")));
        // A plain success with no marker needs no catalog at all.
        let r = response(200, "application/json", &[]);
        assert!(find(&diagnose_as(Protocol::Http, &r, b"{}", "ferrum-edge-0.9.9"), "ferrum.catalog.unavailable").is_none());
    }

    /// The route-timeout 504 body exists only in the 0.9.7 audit; the same
    /// bytes against a 0.9.5 profile must not be attributed to it.
    #[test]
    fn route_timeout_504_is_matched_only_against_the_0_9_7_catalog() {
        let body = br#"{"error":"Request timeout"}"#;
        let r = response(504, "application/json", &[("x-gateway-error", "backend_timeout")]);
        let new = diagnose_as(Protocol::Http, &r, body, "ferrum-edge-0.9.7");
        let ids = candidates(&new);
        assert!(ids.iter().any(|i| i == "upstream.route_request_timeout.not_dispatched"), "{ids:?}");
        let amb = find(&new, "ferrum.outcome_ambiguous").expect("dispatched / not dispatched stay ambiguous");
        assert_eq!(amb.confidence, Confidence::Unknown);
        assert!(find(&new, "ferrum.outcome").is_none());
        let old = diagnose_as(Protocol::Http, &r, body, "ferrum-edge-0.9.5");
        assert!(!candidates(&old).iter().any(|i| i.starts_with("upstream.route_request_timeout")), "{:?}", candidates(&old));
    }

    /// Release notes on a token finding come from the profile's own catalog.
    #[test]
    fn token_release_notes_follow_the_profile_release() {
        let body = br#"{"error":"Backend timeout"}"#;
        let r = response(504, "application/json", &[("x-gateway-error", "backend_timeout")]);
        let t95 = diagnose_as(Protocol::Http, &r, body, "ferrum-edge-0.9.5");
        let t95 = find(&t95, "ferrum.token.backend_timeout").unwrap();
        assert!(t95.explanation.contains("Ferrum Edge 0.9.5") && t95.explanation.contains("pooled HTTP/1.1"), "{}", t95.explanation);
        let t97 = diagnose_as(Protocol::Http, &r, body, "ferrum-edge-0.9.7");
        let t97 = find(&t97, "ferrum.token.backend_timeout").unwrap();
        assert!(t97.explanation.contains("Ferrum Edge 0.9.7") && !t97.explanation.contains("pooled"), "{}", t97.explanation);
        assert!(t97.explanation.contains("before any backend received it"), "{}", t97.explanation);
        for f in [t95, t97] {
            assert_eq!(f.confidence, Confidence::Likely);
            assert!(f.does_not_prove.iter().any(|d| d == "That the backend received the request."), "{:?}", f.does_not_prove);
        }
    }

    #[test]
    fn records_name_the_catalog_actually_used() {
        let v = crate::render::catalog().version.clone();
        let t = |id: &str| FerrumTrust::Trusted { profile_name: "p".into(), compatibility_id: id.into(), channel_authenticated: true };
        assert_eq!(crate::catalog_version_for(&t("ferrum-edge-0.9.7")), format!("findings:{v} ferrum:ferrum-edge-0.9.7"));
        assert_eq!(crate::catalog_version_for(&t("ferrum-edge-0.9.5")), format!("findings:{v} ferrum:ferrum-edge-0.9.5"));
        assert_eq!(crate::catalog_version_for(&t("ferrum-edge-2.0")), format!("findings:{v} ferrum:ferrum-edge-2.0(no-catalog)"));
        assert_eq!(crate::catalog_version_for(&FerrumTrust::NotConfigured), format!("findings:{v} ferrum:none"));
        assert_eq!(crate::catalog_version(), format!("findings:{v} ferrum:ferrum-edge-0.9.5,ferrum-edge-0.9.7"));
    }

    fn codes(f: &[DiagnosticFinding]) -> Vec<&str> {
        f.iter().map(|x| x.code.as_str()).collect()
    }

    /// Live GW-010 (policy lab): a WAF 403 and an application 403 with the
    /// same bytes both reach the ambiguous finding; it must say so.
    #[test]
    fn ambiguous_outcome_names_backend_identical_bytes() {
        let r = response(403, "application/json", &[]);
        let f = diagnose(Protocol::Http, &r, br#"{"error":"Forbidden"}"#);
        let a = find(&f, "ferrum.outcome_ambiguous").expect("ambiguous finding");
        assert_eq!(a.confidence, Confidence::Unknown);
        assert!(a.alternatives.iter().any(|x| x.contains("backend returned a response with identical")), "{:?}", a.alternatives);
        assert!(!a.title.to_lowercase().contains("waf"));
    }
}
