//! Ferrum Edge diagnostic reference lookups (G01; Ferrum Edge v0.9.9 and
//! later): `GET <admin base URL>/diagnostics/v1/refs/<ref>` with the trusted
//! gateway profile's lookup credential, through the engine transport (the
//! request's DNS settings and trust roots, never a separate client).
//!
//! A lookup runs only for a destination the user declared as a Ferrum gateway
//! with a lookup configured, and only for a well-formed reference on its
//! final response. It is refused before anything is sent unless the admin
//! listener is reached over verified TLS (`https`, whatever the request's own
//! TLS profile bypasses or overrides), or over plain HTTP straight to a
//! loopback address literal. It is bounded on its own: connect within
//! [`CONNECT_MS`], everything within [`TOTAL_MS`] (or the request's shorter
//! timeouts).
//!
//! The credential is a sensitive value (a vault secret or a template)
//! resolved for the lookup alone: it is sent only to the configured admin
//! listener, added to the execution's redactor, and never logged or recorded.
//! The record is checked and bound to the response before the rules see it
//! ([`anvil_diagnostics::gateway_detail`]).

use crate::context::{ExecutionContext, resolve_sensitive};
use crate::prepare::{self, Target};
use crate::redact::Redactor;
use crate::vars::Resolver;
use crate::{Engine, SensitiveEpoch};
use anvil_diagnostics::gateway_detail::{self as gd, Binding, GatewayDetail, LookupOutcome, ResponseRef};
use anvil_domain::execution::{AttemptObservation, AttemptReason, ResponseRecord, TlsVerification};
use anvil_domain::integration::DiagnosticDetailAccess;
use anvil_domain::settings::{EffectiveSettings, HttpVersionPolicy, Limits, Timeouts};
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::HttpPlan;
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{PreparedTls, TlsSettings};
use bytes::Bytes;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Connect bound of a lookup (or the request's connect timeout, if shorter).
pub const CONNECT_MS: u64 = 2_000;
/// Bound of a whole lookup, a retry included (or the request's timeouts, if shorter).
pub const TOTAL_MS: u64 = 5_000;
/// Wait before asking once more for a record whose detail is not recorded yet.
pub const DETAIL_RETRY_MS: u64 = 250;

/// One execution's lookup context.
pub(crate) struct Lookup<'a> {
    pub engine: &'a Engine,
    pub epoch: SensitiveEpoch,
    pub ctx: &'a ExecutionContext,
    pub settings: &'a EffectiveSettings,
    pub resolver: &'a Resolver,
}

/// One lookup request: where it goes, with which credential, for which response.
struct AdminRequest<'a> {
    target: &'a Target,
    endpoint: &'a str,
    authorization: &'a http::HeaderValue,
    binding: &'a Binding,
}

/// Whether the admin listener may be asked at all: over `https` (always
/// verified), or over plain HTTP straight to a loopback address literal
/// (127.0.0.0/8 or ::1). Decided from the URL alone, before anything is sent.
fn admin_channel_allowed(t: &Target) -> Result<(), String> {
    if t.scheme == "https" || t.host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return Ok(());
    }
    Err(format!(
        "refused before sending: a plain-HTTP admin URL is allowed only to a loopback address (127.0.0.0/8 or ::1), not {}; use https",
        t.host
    ))
}

/// The request's timeouts, each bounded for a lookup: connect by
/// [`CONNECT_MS`], every other phase and the whole attempt by `total_ms`. A
/// timeout the request leaves off is the bound itself.
fn bounded(t: Timeouts, total_ms: u64) -> Timeouts {
    let cap = |v: Option<u64>, max: u64| Some(v.filter(|v| *v > 0).map_or(max, |v| v.min(max)));
    Timeouts {
        dns_ms: cap(t.dns_ms, total_ms),
        connect_ms: cap(t.connect_ms, CONNECT_MS.min(total_ms)),
        tls_handshake_ms: cap(t.tls_handshake_ms, total_ms),
        request_write_ms: cap(t.request_write_ms, total_ms),
        response_headers_ms: cap(t.response_headers_ms, total_ms),
        body_idle_ms: cap(t.body_idle_ms, total_ms),
        total_ms: cap(t.total_ms, total_ms),
    }
}

impl Lookup<'_> {
    /// Look up the reference `response` carries. `attempt` is the recorded
    /// attempt that produced it (its start and end bound the record's
    /// creation time); `redactor` learns the credential.
    pub(crate) async fn run(
        &self,
        access: &DiagnosticDetailAccess,
        response: &ResponseRecord,
        attempt: &AttemptObservation,
        redactor: &mut Redactor,
        cancel: &CancellationToken,
    ) -> GatewayDetail {
        let reference = match gd::response_ref(response) {
            ResponseRef::Absent => return GatewayDetail::NoReference,
            ResponseRef::Invalid(value) => return GatewayDetail::InvalidReference { value: redactor.text(&value) },
            ResponseRef::Present(r) => r,
        };
        let took = chrono::Duration::microseconds(i64::try_from(attempt.duration_us).unwrap_or(i64::MAX));
        let completed = attempt.started_at.checked_add_signed(took).unwrap_or(attempt.started_at);
        let binding = Binding::new(response, reference.clone(), access.namespace.as_deref(), attempt.started_at, completed);
        let (endpoint, channel_authenticated, outcome) = self.ask(access, &binding, redactor, cancel).await;
        GatewayDetail::Looked { reference: reference.value, endpoint, channel_authenticated, outcome }
    }

    /// The lookup credential, without a `Bearer ` prefix the user may have pasted.
    fn credential(&self, access: &DiagnosticDetailAccess) -> Result<Zeroizing<String>, String> {
        let fail = |e: String| format!("the lookup credential could not be resolved: {e}");
        let (raw, _) = resolve_sensitive(&access.credential, self.ctx.secrets.as_ref()).map_err(fail)?;
        let resolved = Zeroizing::new(self.resolver.resolve(&raw, "integration.detail.credential").map_err(|e| fail(e.message))?);
        let token = resolved.trim();
        let token = token.strip_prefix("Bearer ").or_else(|| token.strip_prefix("bearer ")).unwrap_or(token).trim();
        if token.is_empty() {
            return Err("the profile's lookup has no credential".into());
        }
        Ok(Zeroizing::new(token.to_string()))
    }

    /// Ask the admin listener: (endpoint origin, channel authenticated, outcome).
    async fn ask(
        &self,
        access: &DiagnosticDetailAccess,
        binding: &Binding,
        redactor: &mut Redactor,
        cancel: &CancellationToken,
    ) -> (String, bool, LookupOutcome) {
        let failed = |reason: String| LookupOutcome::Failed { reason };
        let mut inferred = vec![];
        let base = match prepare::parse_target(&access.base_url, &["https", "http"], &mut inferred) {
            Ok(t) => t,
            Err(e) => return ("the profile's admin URL".into(), false, failed(format!("the admin URL is not valid: {}", e.message))),
        };
        let endpoint = format!("{}://{}", base.scheme, base.authority);
        if !base.query.is_empty() {
            return (endpoint, false, failed("the admin URL must not have a query".into()));
        }
        if let Err(reason) = admin_channel_allowed(&base) {
            return (endpoint, false, failed(reason));
        }
        let token = match self.credential(access) {
            Ok(t) => t,
            Err(reason) => return (endpoint, false, failed(reason)),
        };
        redactor.add_secret(&token);
        let bearer = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let Ok(mut authorization) = http::HeaderValue::from_str(&bearer) else {
            return (endpoint, false, failed("the lookup credential is not a valid header value".into()));
        };
        authorization.set_sensitive(true);
        let path = format!("{}{}{}", base.path.trim_end_matches('/'), gd::LOOKUP_PATH, binding.reference.value);
        let target = Target { path, query: String::new(), ..base };
        let request = AdminRequest { target: &target, endpoint: &endpoint, authorization: &authorization, binding };
        let started = Instant::now();
        let first = self.once(&request, TOTAL_MS, redactor, cancel).await;
        // Ferrum Edge records the detail when the request's transaction ends
        // (a streamed response when its body ends): a record without it is
        // asked for once more, shortly, within the same overall bound.
        let pending = matches!(&first.1, LookupOutcome::Resolved(view) if view.detail.is_none());
        let spent = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX).saturating_add(DETAIL_RETRY_MS);
        let budget = TOTAL_MS.saturating_sub(spent);
        if !pending || budget == 0 || cancel.is_cancelled() {
            return (endpoint, first.0, first.1);
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(DETAIL_RETRY_MS)) => {}
            _ = cancel.cancelled() => return (endpoint, first.0, first.1),
        }
        let again = self.once(&request, budget, redactor, cancel).await;
        // Only a bound record replaces the first one.
        let (channel_authenticated, outcome) = if matches!(again.1, LookupOutcome::Resolved(_)) { again } else { first };
        (endpoint, channel_authenticated, outcome)
    }

    /// One lookup request within `budget_ms`: (channel authenticated, outcome).
    async fn once(
        &self,
        request: &AdminRequest<'_>,
        budget_ms: u64,
        redactor: &Redactor,
        cancel: &CancellationToken,
    ) -> (bool, LookupOutcome) {
        let failed = |reason: String| LookupOutcome::Failed { reason };
        let plan = match self.plan(request, budget_ms) {
            Ok(p) => p,
            Err(reason) => return (false, failed(reason)),
        };
        let mut outs = self.engine.http.execute(&plan, 0, AttemptReason::Initial, &EventCtx::none(), cancel).await;
        let Some(out) = outs.pop() else { return (false, failed("the lookup made no attempt".into())) };
        // Only verified TLS, or a direct loopback connection, authenticates
        // who answered the lookup.
        let channel_authenticated =
            out.observation.connection.as_ref().is_some_and(|c| {
                c.tls.as_ref().is_some_and(|t| matches!(t.verification, TlsVerification::Verified)) || gd::direct_loopback(c)
            });
        let outcome = match (out.response, out.observation.failure) {
            (_, Some(f)) => failed(format!("the lookup failed ({:?}): {}", f.kind, redactor.text(&f.message))),
            (None, None) => failed("the lookup returned no response".into()),
            (Some(r), None) => match r.status {
                200 => match gd::parse_view(&out.body) {
                    Ok(view) => match gd::check_binding(&view, request.binding) {
                        Ok(()) => LookupOutcome::Resolved(Box::new(view)),
                        Err(m) => LookupOutcome::Mismatch(m),
                    },
                    Err(e) => failed(format!("the gateway answered a record Anvil does not accept: {e}")),
                },
                401 | 403 => LookupOutcome::Refused { status: r.status },
                404 => {
                    let owner = r.header_values(gd::OWNER_REPLICA_HEADER).first().copied().and_then(gd::parse_replica);
                    LookupOutcome::NotFound { owner_replica: owner }
                }
                429 => LookupOutcome::RateLimited,
                // Redirects are never followed: the credential goes to the configured listener only.
                s => failed(format!("the lookup answered HTTP {s}")),
            },
        };
        (channel_authenticated, outcome)
    }

    /// TLS for the admin listener: always verified, with the trust roots of the
    /// request's TLS profile (if it selects one), but never its verification
    /// bypass, SNI override, SPIFFE expectation or client identity.
    fn admin_tls(&self) -> Result<Arc<PreparedTls>, String> {
        let profile = self.settings.tls_profile_id.and_then(|id| self.ctx.tls_profiles.iter().find(|p| p.id == id));
        let (key, s) = match profile {
            Some(p) => (
                format!("diagnostics|{}|{}", p.id, p.updated_at.timestamp_millis()),
                TlsSettings {
                    verify: true,
                    use_system_roots: p.use_system_roots,
                    extra_roots_pem: p.extra_roots_pem.clone(),
                    min_version: p.min_version,
                    ..Default::default()
                },
            ),
            None => ("default-strict".to_string(), TlsSettings::strict_system()),
        };
        self.engine
            .prepared_tls(self.epoch, &self.ctx.isolation, &key, &s)
            .map_err(|e| format!("TLS for the lookup could not be prepared: {}", e.message))
    }

    fn plan(&self, request: &AdminRequest<'_>, budget_ms: u64) -> Result<HttpPlan, String> {
        let target = request.target;
        let https = target.scheme == "https";
        let tls = if https { Some(self.admin_tls()?) } else { None };
        // An https lookup may cross the request's forward proxy: its TLS is
        // verified end to end. Plain HTTP goes straight to loopback, never
        // through a proxy.
        let proxy = if https {
            let mut inferred = vec![];
            crate::http_exec::proxy_for(self.engine, self.epoch, self.ctx, self.settings, target, &mut inferred)
                .map_err(|e| format!("the proxy for the lookup could not be prepared: {}", e.message))?
        } else {
            None
        };
        let bound = gd::MAX_LOOKUP_BODY_BYTES as u64;
        let accept = http::HeaderValue::from_static("application/json");
        Ok(HttpPlan {
            method: http::Method::GET,
            https,
            host: target.host.clone(),
            port: target.port,
            authority: target.authority.clone(),
            request_target: target.request_target(),
            headers: vec![(http::header::AUTHORIZATION, request.authorization.clone()), (http::header::ACCEPT, accept)],
            body: Bytes::new(),
            version: HttpVersionPolicy::Auto,
            timeouts: bounded(self.settings.timeouts, budget_ms),
            limits: Limits { max_response_bytes: bound, capture_bytes: bound, ..self.settings.limits },
            // A fresh connection per lookup: a resend on a reused connection
            // found closed would get a fresh deadline past the lookup's bound.
            keepalive: false,
            dns: DnsConfig {
                resolver: self.settings.resolver.clone(),
                overrides: self.settings.dns_overrides.clone(),
                ip_preference: self.settings.ip_preference,
            },
            proxy,
            tls,
            isolation: format!("{}|diagnostics", self.ctx.isolation),
            display_url: format!("{}{}", request.endpoint, gd::LOOKUP_PATH),
            // The admin listener is another listener: never the request's PROXY header.
            proxy_header: None,
            proxy_header_withheld: None,
            early_data: anvil_transport::http::EarlyDataIntent::Off,
            fence: Some(self.epoch.transport()),
        })
    }
}

/// Look up the reference of a recorded response again, exactly as an
/// execution's own lookup does (for example after the gateway's retention
/// ended). `attempt` is the recorded attempt that produced `response`.
pub async fn lookup_recorded(
    engine: &Engine,
    ctx: &ExecutionContext,
    access: &DiagnosticDetailAccess,
    response: &ResponseRecord,
    attempt: &AttemptObservation,
    cancel: &CancellationToken,
) -> GatewayDetail {
    let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
    let settings = crate::settings::resolve(&ctx.settings_layers);
    let mut redactor = Redactor::for_execution(&resolver, &ctx.redaction_names);
    let lookup = Lookup { engine, epoch: engine.epoch_for(ctx), ctx, settings: &settings, resolver: &resolver };
    lookup.run(access, response, attempt, &mut redactor, cancel).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str) -> Target {
        prepare::parse_target(url, &["https", "http"], &mut vec![]).unwrap()
    }

    #[test]
    fn plain_http_is_allowed_only_to_a_loopback_literal() {
        let allowed =
            ["https://gateway.example:9443", "https://192.0.2.10", "http://127.0.0.1:18090", "http://127.8.9.10", "http://[::1]:9000"];
        for ok in allowed {
            assert!(admin_channel_allowed(&target(ok)).is_ok(), "{ok}");
        }
        for refused in ["http://localhost:18090", "http://192.0.2.10:9000", "http://gateway.example", "http://[::ffff:127.0.0.1]:9000"] {
            let e = admin_channel_allowed(&target(refused)).unwrap_err();
            assert!(e.contains("refused before sending"), "{refused}: {e}");
        }
    }

    /// A plain-HTTP lookup goes straight to loopback even when the request
    /// selects a forward proxy; only an https lookup, verified end to end,
    /// may cross it. Each lookup uses a fresh connection.
    #[tokio::test]
    async fn a_plain_http_lookup_never_takes_the_requests_proxy() {
        use anvil_domain::settings::{ProxySelection, SettingsOverrides};
        use anvil_domain::tls::{ProxyKind, ProxyProfile};
        let engine = Engine::new();
        let proxy = ProxyProfile {
            id: anvil_domain::Id::new(),
            workspace_id: anvil_domain::Id::new(),
            name: "corporate proxy".into(),
            kind: ProxyKind::Http,
            address: "192.0.2.1:3128".into(),
            username: None,
            password: None,
            no_proxy: String::new(),
            tls_profile_id: None,
            hbone: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let selection = SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id: proxy.id }), ..Default::default() };
        let mut ctx = ExecutionContext::standalone(anvil_domain::request::RequestSpec::http("GET", "http://gateway.example/"));
        ctx.proxy_profiles.push(proxy);
        ctx.settings_layers.push(("run".into(), selection));
        let settings = crate::settings::resolve(&ctx.settings_layers);
        let resolver = Resolver::new(vec![], None);
        let lookup = Lookup { engine: &engine, epoch: engine.sensitive_epoch(), ctx: &ctx, settings: &settings, resolver: &resolver };
        let now = chrono::Utc::now();
        let binding = Binding {
            reference: gd::parse_ref("fd1_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f").unwrap(),
            status: 502,
            gateway_error: None,
            protocol: Some("http1"),
            namespace: None,
            not_before: now,
            not_after: now,
        };
        let authorization = http::HeaderValue::from_static("Bearer lab");
        let plan = |url: &str| {
            let target = target(url);
            let request = AdminRequest { target: &target, endpoint: "", authorization: &authorization, binding: &binding };
            lookup.plan(&request, TOTAL_MS).unwrap()
        };
        let loopback = plan("http://127.0.0.1:18090/diagnostics/v1/refs/x");
        assert!(loopback.proxy.is_none(), "a plain-HTTP lookup never takes the request's proxy");
        assert!(!loopback.keepalive && loopback.tls.is_none());
        let verified = plan("https://admin.example:9443/diagnostics/v1/refs/x");
        assert!(verified.proxy.is_some(), "an https lookup may cross the proxy");
        assert!(verified.tls.is_some() && !verified.keepalive);
    }

    #[test]
    fn lookups_are_bounded_whatever_the_request_allows() {
        let off = Timeouts {
            dns_ms: None,
            connect_ms: None,
            tls_handshake_ms: None,
            request_write_ms: None,
            response_headers_ms: None,
            body_idle_ms: None,
            total_ms: None,
        };
        let b = bounded(off, TOTAL_MS);
        assert_eq!((b.connect_ms, b.total_ms, b.response_headers_ms), (Some(CONNECT_MS), Some(TOTAL_MS), Some(TOTAL_MS)));
        let b = bounded(Timeouts::default(), TOTAL_MS);
        assert_eq!((b.connect_ms, b.total_ms, b.dns_ms), (Some(CONNECT_MS), Some(TOTAL_MS), Some(TOTAL_MS)));
        let short = Timeouts { connect_ms: Some(500), total_ms: Some(1_000), ..Timeouts::default() };
        let b = bounded(short, TOTAL_MS);
        assert_eq!((b.connect_ms, b.total_ms), (Some(500), Some(1_000)), "the request's shorter timeouts apply");
        // A retry gets only what is left of the overall bound.
        assert_eq!(bounded(Timeouts::default(), 1_200).connect_ms, Some(1_200));
    }
}
