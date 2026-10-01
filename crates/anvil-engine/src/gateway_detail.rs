//! Ferrum Edge diagnostic reference lookups (G01; Ferrum Edge v0.9.9 and
//! later): `GET <admin base URL>/diagnostics/v1/refs/<ref>` with the trusted
//! gateway profile's lookup credential, through the engine transport (the
//! request's TLS profile, proxy, DNS and timeouts, never a separate client).
//!
//! A lookup runs only for a destination the user declared as a Ferrum gateway
//! with a lookup configured, and only for a well-formed reference on its
//! final response. The credential is a sensitive value (a vault secret or a
//! template) resolved for the lookup alone: it is sent only to the configured
//! admin listener, added to the execution's redactor, and never logged or
//! recorded. The record is checked and bound to the response before the rules
//! see it ([`anvil_diagnostics::gateway_detail`]).

use crate::context::{ExecutionContext, resolve_sensitive};
use crate::prepare::{self, Target};
use crate::redact::Redactor;
use crate::vars::Resolver;
use crate::{Engine, SensitiveEpoch};
use anvil_diagnostics::gateway_detail::{self as gd, Binding, GatewayDetail, LookupOutcome, ResponseRef};
use anvil_domain::execution::{AttemptReason, ResponseRecord, TlsVerification};
use anvil_domain::integration::DiagnosticDetailAccess;
use anvil_domain::settings::{EffectiveSettings, HttpVersionPolicy, Limits};
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::HttpPlan;
use anvil_transport::recorder::EventCtx;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// One execution's lookup context.
pub(crate) struct Lookup<'a> {
    pub engine: &'a Engine,
    pub epoch: SensitiveEpoch,
    pub ctx: &'a ExecutionContext,
    pub settings: &'a EffectiveSettings,
    pub resolver: &'a Resolver,
}

impl Lookup<'_> {
    /// Look up the reference `response` carries. `sent_at` is when the request
    /// that produced it was sent; `redactor` learns the credential.
    pub(crate) async fn run(
        &self,
        access: &DiagnosticDetailAccess,
        response: &ResponseRecord,
        sent_at: DateTime<Utc>,
        redactor: &mut Redactor,
        cancel: &CancellationToken,
    ) -> GatewayDetail {
        let reference = match gd::response_ref(response) {
            ResponseRef::Absent => return GatewayDetail::NoReference,
            ResponseRef::Invalid(value) => return GatewayDetail::InvalidReference { value: redactor.text(&value) },
            ResponseRef::Present(r) => r,
        };
        let binding = Binding::new(response, reference.clone(), access.namespace.as_deref(), sent_at, Utc::now());
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
        let plan = match self.plan(&target, &endpoint, authorization) {
            Ok(p) => p,
            Err(reason) => return (endpoint, false, failed(reason)),
        };
        let mut outs = self.engine.http.execute(&plan, 0, AttemptReason::Initial, &EventCtx::none(), cancel).await;
        let Some(out) = outs.pop() else { return (endpoint, false, failed("the lookup made no attempt".into())) };
        // Only verified TLS, or a direct loopback connection, authenticates
        // who answered the lookup.
        let channel_authenticated = out.observation.connection.as_ref().is_some_and(|c| {
            c.tls.as_ref().is_some_and(|t| matches!(t.verification, TlsVerification::Verified)) || gd::direct_loopback(c)
        });
        let outcome = match (out.response, out.observation.failure) {
            (_, Some(f)) => failed(format!("the lookup failed ({:?}): {}", f.kind, redactor.text(&f.message))),
            (None, None) => failed("the lookup returned no response".into()),
            (Some(r), None) => match r.status {
                200 => match gd::parse_view(&out.body) {
                    Ok(view) => match gd::check_binding(&view, binding) {
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
                s => failed(format!("the lookup answered HTTP {s}")),
            },
        };
        (endpoint, channel_authenticated, outcome)
    }

    fn plan(&self, target: &Target, endpoint: &str, authorization: http::HeaderValue) -> Result<HttpPlan, String> {
        let mut inferred = vec![];
        let tls = if target.scheme == "https" {
            let choice = crate::http_exec::tls_for(self.engine, self.epoch, self.ctx, self.settings, target, &mut inferred);
            Some(choice.map_err(|e| format!("TLS for the lookup could not be prepared: {}", e.message))?.0)
        } else {
            None
        };
        // The admin listener is reached like the request's own origin: through
        // the request's proxy profile (and its NO_PROXY list).
        let proxy = crate::http_exec::proxy_for(self.engine, self.epoch, self.ctx, self.settings, target, &mut inferred)
            .map_err(|e| format!("the proxy for the lookup could not be prepared: {}", e.message))?;
        let bound = gd::MAX_LOOKUP_BODY_BYTES as u64;
        let accept = http::HeaderValue::from_static("application/json");
        Ok(HttpPlan {
            method: http::Method::GET,
            https: target.scheme == "https",
            host: target.host.clone(),
            port: target.port,
            authority: target.authority.clone(),
            request_target: target.request_target(),
            headers: vec![(http::header::AUTHORIZATION, authorization), (http::header::ACCEPT, accept)],
            body: Bytes::new(),
            version: HttpVersionPolicy::Auto,
            timeouts: self.settings.timeouts,
            limits: Limits { max_response_bytes: bound, capture_bytes: bound, ..self.settings.limits },
            keepalive: true,
            dns: DnsConfig {
                resolver: self.settings.resolver.clone(),
                overrides: self.settings.dns_overrides.clone(),
                ip_preference: self.settings.ip_preference,
            },
            proxy,
            tls,
            isolation: format!("{}|diagnostics", self.ctx.isolation),
            display_url: format!("{endpoint}{}", gd::LOOKUP_PATH),
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
/// ended). `sent_at` is when the request that produced `response` was sent.
pub async fn lookup_recorded(
    engine: &Engine,
    ctx: &ExecutionContext,
    access: &DiagnosticDetailAccess,
    response: &ResponseRecord,
    sent_at: DateTime<Utc>,
    cancel: &CancellationToken,
) -> GatewayDetail {
    let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
    let settings = crate::settings::resolve(&ctx.settings_layers);
    let mut redactor = Redactor::for_execution(&resolver, &ctx.redaction_names);
    let lookup = Lookup { engine, epoch: engine.epoch_for(ctx), ctx, settings: &settings, resolver: &resolver };
    lookup.run(access, response, sent_at, &mut redactor, cancel).await
}
