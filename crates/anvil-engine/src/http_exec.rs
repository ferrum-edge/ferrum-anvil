//! HTTP-family execution: one logical request = one or more attempts
//! (redirects, safe retries, DPoP nonce challenge), each with freshly applied
//! auth, followed by diagnosis and record assembly.

use crate::Engine;
use crate::assertions::{self, Observed};
use crate::context::{ExecutionContext, resolve_sensitive};
use crate::prepare::{self, PreparedHttp, Target};
use crate::record::{self, Assembly};
use crate::redact::Redactor;
use crate::vars::Resolver;
use anvil_auth::{ResolvedAuth, SignableRequest};
use anvil_diagnostics::FerrumTrust;
use anvil_domain::auth::AuthConfig;
use anvil_domain::execution::*;
use anvil_domain::integration::IntegrationKind;
use anvil_domain::settings::EffectiveSettings;
use anvil_transport::connector::ProxyPlan;
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::{AttemptOutput, HttpPlan};
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{ClientIdentityMaterial, PreparedTls, TlsSettings};
use bytes::Bytes;
use chrono::Utc;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub struct Prepared {
    pub http: PreparedHttp,
    pub auth: ResolvedAuth,
    pub auth_label: String,
    pub auth_secrets: Vec<String>,
    pub settings: EffectiveSettings,
    pub tls: Option<Arc<PreparedTls>>,
    pub tls_profile_name: Option<String>,
    pub tls_profile_bindings: Vec<anvil_domain::tls::HostBinding>,
    pub proxy: Option<ProxyPlan>,
    pub trust: FerrumTrust,
    pub require_verified_tls: bool,
    pub oauth_key: Option<(String, anvil_auth::oauth::OAuthResolved)>,
    pub inferred: Vec<String>,
    /// The request's PROXY header (HTTP-family requests), for connections to
    /// the request's own `host:port`.
    pub proxy_header: Option<anvil_transport::proxy_protocol::HeaderPlan>,
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let h = host.to_ascii_lowercase();
    match p.strip_prefix("*.") {
        Some(suffix) => h.ends_with(&format!(".{suffix}")),
        None => p == h,
    }
}

pub(crate) fn binding_matches(b: &[anvil_domain::tls::HostBinding], t: &Target) -> bool {
    b.is_empty() || b.iter().any(|x| host_matches(&x.host, &t.host) && x.port.map(|p| p == t.port).unwrap_or(true))
}

/// Resolve auth configuration secrets into a [`ResolvedAuth`].
pub(crate) fn resolve_auth(
    engine: &Engine,
    auth: &AuthConfig,
    ctx: &ExecutionContext,
    r: &Resolver,
    oauth_key: &mut Option<(String, anvil_auth::oauth::OAuthResolved)>,
) -> Result<ResolvedAuth, TransportFailure> {
    let fail = |m: String| TransportFailure::new(Phase::Prepare, FailureKind::AuthPreparationFailed, m).with_field("auth");
    let sens = |v: &anvil_domain::secret::SensitiveValue, field: &str| -> Result<Zeroizing<String>, TransportFailure> {
        let (raw, _) = resolve_sensitive(v, ctx.secrets.as_ref()).map_err(|e| fail(format!("{field}: {e}")))?;
        let resolved = r.resolve(&raw, field)?;
        Ok(Zeroizing::new(resolved))
    };
    Ok(match auth {
        AuthConfig::Inherit | AuthConfig::None => ResolvedAuth::None,
        AuthConfig::ApiKey { name, value, location } => {
            ResolvedAuth::ApiKey { name: r.resolve(name, "auth.name")?, value: sens(value, "auth.value")?, location: *location }
        }
        AuthConfig::Basic { username, password } => {
            ResolvedAuth::Basic { username: r.resolve(username, "auth.username")?, password: sens(password, "auth.password")? }
        }
        AuthConfig::Bearer { token, prefix } => ResolvedAuth::Bearer { token: sens(token, "auth.token")?, prefix: prefix.clone() },
        AuthConfig::Jwt { algorithm, signing_key, claims, kid, header_name, prefix } => {
            let extra = if claims.extra_json.trim().is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&r.resolve(&claims.extra_json, "auth.claims.extra_json")?)
                    .map_err(|e| fail(format!("additional JWT claims are not valid JSON: {e}")))?
            };
            let mut c = claims.clone();
            c.iss = c.iss.map(|v| r.resolve(&v, "auth.claims.iss")).transpose()?;
            c.sub = c.sub.map(|v| r.resolve(&v, "auth.claims.sub")).transpose()?;
            c.aud = c.aud.map(|v| r.resolve(&v, "auth.claims.aud")).transpose()?;
            ResolvedAuth::Jwt {
                algorithm: *algorithm,
                signing_key: sens(signing_key, "auth.signing_key")?,
                claims: c,
                extra_claims: extra,
                kid: kid.clone(),
                header_name: header_name.clone(),
                prefix: prefix.clone(),
            }
        }
        AuthConfig::OAuth2 { config } => {
            let resolved = crate::oauth_http::resolve_oauth(config, ctx, r)?;
            let key = crate::oauth_http::cache_key(ctx, &resolved);
            let cached = engine.tokens.get(&key);
            *oauth_key = Some((key, resolved));
            match cached {
                Some(t) => ResolvedAuth::OAuth2 { access_token: t.access_token.clone(), token_type: t.token_type.clone() },
                None => ResolvedAuth::OAuth2 { access_token: Zeroizing::new(String::new()), token_type: "Bearer".into() },
            }
        }
        AuthConfig::Hmac { config } => ResolvedAuth::Hmac(anvil_auth::HmacParams {
            profile: config.profile,
            username: r.resolve(&config.username, "auth.username")?,
            secret: sens(&config.secret, "auth.secret")?,
            algorithm: config.algorithm,
            digest_header: config.digest_header,
            namespace: r.resolve(&config.namespace, "auth.namespace")?,
            allow_unsafe_legacy: config.allow_unsafe_legacy,
        }),
        AuthConfig::Dpop { config } => ResolvedAuth::Dpop {
            access_token: sens(&config.access_token, "auth.access_token")?,
            private_key_pem: sens(&config.private_key_pem, "auth.private_key_pem")?,
            dpop_scheme: config.dpop_scheme,
            nonce: None,
        },
        AuthConfig::Wsse { config } => ResolvedAuth::Wsse {
            username: r.resolve(&config.username, "auth.username")?,
            password: sens(&config.password, "auth.password")?,
            password_type: config.password_type,
            timestamp_ttl_secs: config.timestamp_ttl_secs,
            saml_assertion: config.saml_assertion.as_ref().map(|s| sens(s, "auth.saml_assertion")).transpose()?,
        },
        AuthConfig::Multi { profiles } => {
            let mut v = Vec::new();
            for p in profiles {
                v.push(resolve_auth(engine, p, ctx, r, oauth_key)?);
            }
            ResolvedAuth::Multi(v)
        }
    })
}

/// Prepared TLS material, the selected profile's name and its host bindings.
pub(crate) type TlsChoice = (Arc<PreparedTls>, Option<String>, Vec<anvil_domain::tls::HostBinding>);

/// Build the TLS settings for a target (profile scoping + host binding).
pub(crate) fn tls_for(
    engine: &Engine,
    ctx: &ExecutionContext,
    settings: &EffectiveSettings,
    target: &Target,
    inferred: &mut Vec<String>,
) -> Result<TlsChoice, TransportFailure> {
    let profile = settings.tls_profile_id.and_then(|id| ctx.tls_profiles.iter().find(|p| p.id == id));
    let Some(p) = profile else {
        if settings.tls_profile_id.is_some() {
            return Err(TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "the selected TLS profile no longer exists")
                .with_field("settings.tls_profile"));
        }
        return Ok((engine.prepared_tls("default-strict", &TlsSettings::strict_system())?, None, vec![]));
    };
    let prepared = prepared_from_profile(engine, ctx, p, &target.host, target.port, inferred)?;
    Ok((prepared, Some(p.name.clone()), p.bindings.clone()))
}

/// Prepared TLS material for one profile, presenting its client identity only
/// to `host:port` when the profile's bindings allow it.
pub(crate) fn prepared_from_profile(
    engine: &Engine,
    ctx: &ExecutionContext,
    p: &anvil_domain::tls::TlsProfile,
    host: &str,
    port: u16,
    inferred: &mut Vec<String>,
) -> Result<Arc<PreparedTls>, TransportFailure> {
    let mut s = TlsSettings {
        verify: p.verify,
        use_system_roots: p.use_system_roots,
        extra_roots_pem: p.extra_roots_pem.clone(),
        client_identity: None,
        min_version: p.min_version,
        server_name_override: p.server_name_override.clone().filter(|n| !n.trim().is_empty()),
        server_spiffe: p.server_spiffe.clone(),
    };
    let bind =
        Target { scheme: "https".into(), host: host.to_string(), port, authority: String::new(), path: "/".into(), query: String::new() };
    if let Some(id) = &p.client_identity {
        if binding_matches(&p.bindings, &bind) {
            s.client_identity = Some(match id {
                anvil_domain::tls::ClientIdentity::Pem { cert_chain_pem, private_key_pem } => {
                    let (key, _) = resolve_sensitive(private_key_pem, ctx.secrets.as_ref()).map_err(|e| {
                        TransportFailure::new(Phase::Prepare, FailureKind::ClientIdentityInvalid, e)
                            .with_field("tls.client_identity.private_key")
                    })?;
                    ClientIdentityMaterial { cert_chain_pem: cert_chain_pem.clone(), private_key_pem: key }
                }
                anvil_domain::tls::ClientIdentity::Pkcs12 { bundle_b64, password } => {
                    let (b, _) = resolve_sensitive(bundle_b64, ctx.secrets.as_ref())
                        .map_err(|e| TransportFailure::new(Phase::Prepare, FailureKind::ClientIdentityInvalid, e))?;
                    let (pw, _) = resolve_sensitive(password, ctx.secrets.as_ref())
                        .map_err(|e| TransportFailure::new(Phase::Prepare, FailureKind::ClientIdentityInvalid, e))?;
                    crate::pkcs12::to_pem(&b, &pw)?
                }
            });
        } else {
            inferred.push(format!("client certificate from TLS profile '{}' not presented: {} is not in its host bindings", p.name, host));
        }
    }
    let key = format!("{}|{}|{}", p.id, p.updated_at.timestamp_millis(), s.client_identity.is_some());
    engine.prepared_tls(&key, &s)
}

fn proxy_invalid(msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, FailureKind::ProxyConfigInvalid, msg).with_field(field)
}

/// Headers that are connection-specific in HTTP/2 and never sent on a CONNECT.
const CONNECTION_SPECIFIC: &[&str] = &["host", "connection", "upgrade", "transfer-encoding", "keep-alive", "proxy-connection", "te"];

/// Protocol marker headers on an HBONE `CONNECT`.
const HBONE_MARKERS: &[&str] = &["x-ferrum-mesh-protocol", "x-istio-protocol"];

/// Validated extra headers for an HBONE `CONNECT` (marker, baggage, extras).
/// A `datagram` tunnel (UDP) always carries the marker with the value `udp`,
/// which is what makes the endpoint relay datagrams; the byte-stream marker
/// value is `hbone`, and it is optional.
fn hbone_connect_headers(
    h: &anvil_domain::tls::HboneOptions,
    datagram: bool,
) -> Result<Vec<(http::HeaderName, http::HeaderValue)>, TransportFailure> {
    use anvil_domain::tls::HboneMarker;
    let mut out = Vec::new();
    let mut push = |name: &str, value: &str, field: &str| -> Result<(), TransportFailure> {
        let n = http::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| proxy_invalid(format!("'{name}' is not a valid HBONE CONNECT header name"), field))?;
        if CONNECTION_SPECIFIC.contains(&n.as_str()) {
            return Err(proxy_invalid(format!("'{name}' is a connection-specific header and cannot be sent on an HTTP/2 CONNECT"), field));
        }
        if datagram && field != "proxy.hbone.marker" && HBONE_MARKERS.contains(&n.as_str()) {
            return Err(proxy_invalid(
                format!(
                    "'{name}' is set by Anvil on a UDP tunnel (the marker value udp selects the datagram relay); remove it from the HBONE proxy's extra headers"
                ),
                field,
            ));
        }
        let v = http::HeaderValue::from_str(value)
            .map_err(|_| proxy_invalid(format!("the value of HBONE CONNECT header '{name}' is not a valid header value"), field))?;
        out.push((n, v));
        Ok(())
    };
    let value = if datagram { "udp" } else { "hbone" };
    match (h.marker, datagram) {
        (HboneMarker::None, false) => {}
        (HboneMarker::IstioProtocol, _) => push("x-istio-protocol", value, "proxy.hbone.marker")?,
        (HboneMarker::None | HboneMarker::FerrumMeshProtocol, _) => push("x-ferrum-mesh-protocol", value, "proxy.hbone.marker")?,
    }
    if let Some(b) = h.baggage.as_deref().map(str::trim).filter(|b| !b.is_empty()) {
        push("baggage", b, "proxy.hbone.baggage")?;
    }
    for (i, kv) in h.extra_headers.iter().enumerate().filter(|(_, kv)| kv.enabled) {
        push(&kv.name, &kv.value, &format!("proxy.hbone.extra_headers[{i}]"))?;
    }
    Ok(out)
}

/// The `CONNECT` headers of the selected HBONE proxy profile for a UDP
/// datagram tunnel (the `udp` marker, then the profile's baggage and extras).
pub(crate) fn hbone_datagram_connect_headers(
    ctx: &ExecutionContext,
    settings: &EffectiveSettings,
) -> Result<Vec<(http::HeaderName, http::HeaderValue)>, TransportFailure> {
    let opts = settings
        .proxy_profile_id
        .and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id))
        .and_then(|p| p.hbone.clone())
        .unwrap_or_default();
    hbone_connect_headers(&opts, true)
}

pub(crate) fn proxy_for(
    engine: &Engine,
    ctx: &ExecutionContext,
    settings: &EffectiveSettings,
    target: &Target,
    inferred: &mut Vec<String>,
) -> Result<Option<ProxyPlan>, TransportFailure> {
    use anvil_domain::tls::ProxyKind;
    let Some(pid) = settings.proxy_profile_id else { return Ok(None) };
    let p = ctx
        .proxy_profiles
        .iter()
        .find(|p| p.id == pid)
        .ok_or_else(|| proxy_invalid("the selected proxy profile no longer exists", "settings.proxy"))?;
    if anvil_transport::net::no_proxy_matches(&p.no_proxy, &target.host, target.port) {
        inferred.push(format!("proxy '{}' bypassed for {} (NO_PROXY)", p.name, target.host));
        return Ok(None);
    }
    let (host, port) = match p.address.rsplit_once(':') {
        Some((h, pt)) => match pt.parse::<u16>() {
            Ok(n) => (h.trim_start_matches('[').trim_end_matches(']').to_string(), n),
            Err(_) => return Err(proxy_invalid(format!("proxy address '{}' has an invalid port", p.address), "proxy.address")),
        },
        None => return Err(proxy_invalid(format!("proxy address '{}' must be host:port", p.address), "proxy.address")),
    };
    let credentials = match (&p.username, &p.password) {
        (Some(u), Some(pw)) => {
            let (v, _) = resolve_sensitive(pw, ctx.secrets.as_ref()).map_err(|e| proxy_invalid(e, "proxy.password"))?;
            Some((u.clone(), v))
        }
        (Some(u), None) => Some((u.clone(), Zeroizing::new(String::new()))),
        _ => None,
    };
    if p.kind == ProxyKind::Hbone && credentials.is_some() {
        return Err(proxy_invalid(
            "an HBONE endpoint authenticates the client by its SVID (mutual TLS); remove the proxy username/password",
            "proxy.username",
        ));
    }
    let profile_tls = match p.tls_profile_id {
        Some(id) => {
            let tp = ctx.tls_profiles.iter().find(|t| t.id == id).ok_or_else(|| {
                proxy_invalid(format!("the TLS profile selected for proxy '{}' no longer exists", p.name), "proxy.tls_profile")
            })?;
            Some(prepared_from_profile(engine, ctx, tp, &host, port, inferred)?)
        }
        None => None,
    };
    let tls = match p.kind {
        ProxyKind::Https => Some(match profile_tls {
            Some(t) => t,
            None => Arc::new(anvil_transport::tls::prepare(&TlsSettings::strict_system())?),
        }),
        ProxyKind::Hbone => Some(profile_tls.ok_or_else(|| {
            proxy_invalid(
                format!(
                    "HBONE proxy '{}' has no TLS profile: HBONE is HTTP/2 CONNECT over mutual TLS, so it needs the client SVID and the endpoint's trust bundle; nothing was sent",
                    p.name
                ),
                "proxy.tls_profile",
            )
        })?),
        _ => None,
    };
    let connect_headers = match (&p.kind, &p.hbone) {
        (ProxyKind::Hbone, Some(h)) => hbone_connect_headers(h, false)?,
        _ => vec![],
    };
    Ok(Some(ProxyPlan { kind: p.kind, host, port, credentials, tls, label: format!("{} ({})", p.name, p.address), connect_headers }))
}

pub(crate) fn trust_for(ctx: &ExecutionContext, target: &Target) -> (FerrumTrust, bool) {
    for i in &ctx.integrations {
        let IntegrationKind::FerrumGateway { hosts, compatibility_id, require_verified_tls, .. } = &i.kind;
        if hosts.iter().any(|h| host_matches(&h.host, &target.host) && h.port.map(|p| p == target.port).unwrap_or(true)) {
            return (
                FerrumTrust::Trusted {
                    profile_name: i.name.clone(),
                    compatibility_id: compatibility_id.clone(),
                    channel_authenticated: false,
                },
                *require_verified_tls,
            );
        }
    }
    (FerrumTrust::NotConfigured, false)
}

pub(crate) fn prepare_all(engine: &Engine, ctx: &ExecutionContext, r: &Resolver, allowed: &[&str]) -> Result<Prepared, TransportFailure> {
    let settings = crate::settings::resolve(&ctx.settings_layers);
    let http = prepare::prepare_http(&ctx.spec, r, ctx.attachments.as_ref(), &settings, ctx.send_anyway, allowed)?;
    let mut inferred = http.inferred.clone();
    let (auth_scope, auth_cfg) = ctx.effective_auth();
    let mut oauth_key = None;
    let auth = resolve_auth(engine, &auth_cfg, ctx, r, &mut oauth_key)?;
    let auth_label = if matches!(auth, ResolvedAuth::None) { "none".into() } else { format!("{} (from {auth_scope})", auth.label()) };
    let tls_scheme = matches!(http.target.scheme.as_str(), "https" | "wss" | "grpcs");
    let (tls, tls_name, bindings) = if tls_scheme {
        tls_for(engine, ctx, &settings, &http.target, &mut inferred).map(|(a, b, c)| (Some(a), b, c))?
    } else {
        (None, None, vec![])
    };
    let proxy = proxy_for(engine, ctx, &settings, &http.target, &mut inferred)?;
    let proxy_header = crate::proxy_protocol::request_header(&ctx.spec, r, &settings, proxy.as_ref())?;
    if let (Some(spec), Some(_)) = (&ctx.spec.proxy_protocol, &proxy_header) {
        inferred.push(crate::proxy_protocol::request_header_note(spec, &http.target.authority));
    }
    let (trust, require_verified_tls) = trust_for(ctx, &http.target);
    Ok(Prepared {
        http,
        auth,
        auth_label,
        auth_secrets: vec![],
        settings,
        tls,
        tls_profile_name: tls_name,
        tls_profile_bindings: bindings,
        proxy,
        trust,
        require_verified_tls,
        oauth_key,
        inferred,
        proxy_header,
    })
}

/// Whether two targets are the same TCP listener (`host:port`): a PROXY
/// header is configured for the request's own listener only.
fn same_listener(a: &Target, b: &Target) -> bool {
    a.host.eq_ignore_ascii_case(&b.host) && a.port == b.port
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

struct AttemptTarget {
    method: String,
    target: Target,
    headers: Vec<(String, String)>,
    body: Bytes,
    with_credentials: bool,
    tls: Option<Arc<PreparedTls>>,
}

#[allow(clippy::collapsible_if)] // the redirect branch reads clearer nested
pub async fn execute(engine: &Engine, ctx: &ExecutionContext, events: EventCtx, cancel: CancellationToken) -> crate::ExecutionOutput {
    let started_at = Utc::now();
    let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
    let prepared = prepare_all(engine, ctx, &resolver, &["https", "http"]);
    let mut prep = match prepared {
        Ok(p) => p,
        Err(f) => return record::local_failure(ctx, &resolver, started_at, f),
    };
    let mut redactor = Redactor::new(resolver.used_secrets.lock().clone(), ctx.redaction_names.clone());
    let mut extra_findings: Vec<anvil_diagnostics::Draft> = Vec::new();

    // OAuth: acquire/refresh through the same transport before sending.
    // Interactive grants without a usable token fail here, typed, before the
    // API request exists on the wire.
    if let Some((key, cfg)) = &prep.oauth_key {
        let http = crate::oauth_http::EngineTokenHttp { engine, ctx, settings: &prep.settings };
        match engine.tokens.get_or_acquire(key, cfg, &http, Utc::now()).await {
            Ok(t) => {
                replace_oauth(&mut prep.auth, &t);
            }
            Err(e) => {
                let f = crate::oauth_http::acquisition_failure(cfg, e, "The API request was not sent.");
                return record::local_failure(ctx, &resolver, started_at, f);
            }
        }
    }
    crate::local_checks::bearer_expiry(&prep.auth, &mut extra_findings);

    let mut attempts: Vec<AttemptObservation> = Vec::new();
    let mut last: Option<AttemptOutput> = None;
    let mut current = AttemptTarget {
        method: prep.http.method.clone(),
        target: prep.http.target.clone(),
        headers: prep.http.headers.clone(),
        body: prep.http.body.clone(),
        with_credentials: true,
        tls: prep.tls.clone(),
    };
    let original_origin = current.target.origin();
    let mut redirects = 0u8;
    let mut retries = 0u8;
    let mut dpop_challenge_used = false;
    let mut reason = AttemptReason::Initial;
    let mut credentials_stripped = false;
    let mut final_auth_facts: Vec<(String, String)> = vec![];

    loop {
        // ---- per-attempt auth (fresh nonces / proofs / time claims) ----
        let signable = SignableRequest {
            method: current.method.clone(),
            scheme: current.target.scheme.clone(),
            authority: current
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| current.target.authority.clone()),
            raw_path: current.target.path.clone(),
            raw_query: current.target.query.clone(),
            headers: current.headers.clone(),
            body: current.body.to_vec(),
        };
        let mut headers = current.headers.clone();
        let mut query = current.target.query.clone();
        let mut body = current.body.clone();
        if current.with_credentials {
            match anvil_auth::apply(&prep.auth, &signable, Utc::now()) {
                Ok(applied) => {
                    for s in &applied.secrets {
                        redactor.add_secret(s);
                    }
                    for (n, v) in applied.set_headers {
                        headers.retain(|(h, _)| !h.eq_ignore_ascii_case(&n));
                        headers.push((n, v));
                    }
                    for (k, v) in applied.append_query {
                        let pair = format!("{}={}", prepare::encode_component(&k), prepare::encode_component(&v));
                        query = if query.is_empty() { pair } else { format!("{query}&{pair}") };
                    }
                    if let Some(b) = applied.body {
                        body = Bytes::from(b);
                    }
                    final_auth_facts = applied.facts;
                }
                Err(e) => {
                    let f = TransportFailure::new(Phase::Prepare, FailureKind::AuthPreparationFailed, e.to_string()).with_field("auth");
                    if attempts.is_empty() {
                        return record::local_failure(ctx, &resolver, started_at, f);
                    }
                    break;
                }
            }
        }
        // Cookies from the workspace jar (never across workspaces).
        if prep.settings.cookies {
            let jar_cookie = engine.cookie_header(&ctx.isolation, &current.target);
            if let Some(c) = jar_cookie {
                match headers.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case("cookie")) {
                    Some((_, v)) => *v = format!("{v}; {c}"),
                    None => headers.push(("Cookie".into(), c)),
                }
            }
        }
        let mut header_pairs = Vec::with_capacity(headers.len());
        for (n, v) in &headers {
            if let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(n.as_bytes()), http::HeaderValue::from_str(v)) {
                header_pairs.push((n, v));
            }
        }
        let target_for_plan = Target { query: query.clone(), ..current.target.clone() };
        let display_url = redactor.url(&target_for_plan.url());
        // The PROXY header is configured for the request's own listener: a
        // redirect elsewhere is followed without it, and the attempt says so.
        let (proxy_header, proxy_header_withheld) = match &prep.proxy_header {
            Some(h) if same_listener(&current.target, &prep.http.target) => {
                let r = redactor.clone();
                let redact: anvil_transport::proxy_protocol::SharedRedact = Arc::new(move |s: &str| r.text(s));
                (Some(anvil_transport::proxy_protocol::ConnectionHeader { plan: h.clone(), redact: Some(redact) }), None)
            }
            Some(_) => {
                let why = format!(
                    "not sent: the PROXY header is configured for {} only, and this attempt goes to {}",
                    prep.http.target.authority, current.target.authority
                );
                if !prep.inferred.iter().any(|i| i.starts_with("PROXY header withheld")) {
                    prep.inferred.push(format!("PROXY header withheld on the redirect to {}: {why}", current.target.authority));
                }
                (None, Some(why))
            }
            None => (None, None),
        };
        let plan = HttpPlan {
            method: http::Method::from_bytes(current.method.as_bytes()).unwrap_or(http::Method::GET),
            https: current.target.scheme == "https",
            host: current.target.host.clone(),
            port: current.target.port,
            authority: current.target.authority.clone(),
            request_target: target_for_plan.request_target(),
            headers: header_pairs,
            body: body.clone(),
            version: prep.settings.http_version,
            timeouts: prep.settings.timeouts,
            limits: prep.settings.limits,
            keepalive: prep.settings.keepalive,
            dns: DnsConfig {
                resolver: prep.settings.resolver.clone(),
                overrides: prep.settings.dns_overrides.clone(),
                ip_preference: prep.settings.ip_preference,
            },
            proxy: prep.proxy.clone(),
            tls: current.tls.clone(),
            isolation: ctx.isolation.clone(),
            display_url,
            proxy_header,
            proxy_header_withheld,
        };
        let index = attempts.len() as u32;
        let outs = match prep.settings.http_version {
            anvil_domain::settings::HttpVersionPolicy::Http3Only | anvil_domain::settings::HttpVersionPolicy::Http3WithFallback => {
                crate::h3_exec::execute(engine, &plan, prep.settings.http_version, index, reason.clone(), &events, &cancel).await
            }
            _ => engine.http.execute(&plan, index, reason.clone(), &events, &cancel).await,
        };
        let mut out_iter = outs.into_iter().peekable();
        let mut out = None;
        while let Some(o) = out_iter.next() {
            if out_iter.peek().is_some() {
                attempts.push(o.observation);
            } else {
                out = Some(o);
            }
        }
        let out = out.expect("transport returns at least one attempt");
        attempts.push(out.observation.clone());

        // Store cookies from the response.
        if prep.settings.cookies
            && let Some(r) = &out.response
        {
            engine.store_cookies(&ctx.isolation, &current.target, r);
        }

        // ---- redirects ----
        if let Some(resp) = &out.response
            && is_redirect(resp.status)
            && prep.settings.redirects.follow
        {
            if let Some(loc) = resp.header_values("location").first().map(|s| s.to_string()) {
                if redirects >= prep.settings.redirects.max {
                    last = Some(out);
                    break;
                }
                let base = url::Url::parse(&current.target.url()).ok();
                let next = base.and_then(|b| b.join(&loc).ok()).map(|u| u.to_string()).unwrap_or(loc.clone());
                let mut inf = vec![];
                match prepare::parse_target(&next, &["https", "http"], &mut inf) {
                    Ok(t) => {
                        redirects += 1;
                        let status = resp.status;
                        let (method, body) = match status {
                            303 if current.method != "HEAD" => ("GET".to_string(), Bytes::new()),
                            301 | 302 if current.method == "POST" => ("GET".to_string(), Bytes::new()),
                            _ => (current.method.clone(), current.body.clone()),
                        };
                        let cross_origin = t.origin() != original_origin;
                        let mut headers = current.headers.clone();
                        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("host"));
                        if body.is_empty() {
                            headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-type") && !n.eq_ignore_ascii_case("content-length"));
                        }
                        let mut with_credentials = current.with_credentials;
                        let tls;
                        if cross_origin && !prep.settings.redirects.forward_credentials_cross_origin {
                            headers.retain(|(n, _)| {
                                !matches!(n.to_ascii_lowercase().as_str(), "authorization" | "cookie" | "proxy-authorization")
                            });
                            with_credentials = false;
                            credentials_stripped = true;
                        }
                        if t.scheme == "https" {
                            let mut inf2 = vec![];
                            // The redirect target gets its own TLS policy; the
                            // client identity is presented only where bound.
                            let cross_bound = binding_matches(&prep.tls_profile_bindings, &t) && !prep.tls_profile_bindings.is_empty();
                            if cross_origin && !cross_bound {
                                let mut strict_ctx = ctx.clone();
                                strict_ctx.tls_profiles.iter_mut().for_each(|p| {
                                    if !binding_matches(&p.bindings, &t) || p.bindings.is_empty() {
                                        p.client_identity = None;
                                    }
                                });
                                tls = tls_for(engine, &strict_ctx, &prep.settings, &t, &mut inf2).ok().map(|x| x.0);
                            } else {
                                tls = tls_for(engine, ctx, &prep.settings, &t, &mut inf2).ok().map(|x| x.0);
                            }
                        } else {
                            tls = None;
                        }
                        current = AttemptTarget { method, target: t, headers, body, with_credentials, tls };
                        reason = AttemptReason::Redirect { status };
                        last = Some(out);
                        continue;
                    }
                    Err(_) => {
                        last = Some(out);
                        break;
                    }
                }
            }
        }

        // ---- DPoP nonce challenge (RFC 9449 §8): one fresh proof ----
        if let Some(resp) = &out.response
            && !dpop_challenge_used
            && matches!(prep.auth, ResolvedAuth::Dpop { .. })
            && (resp.status == 401 || resp.status == 400)
            && let Some(nonce) = resp.header_values("dpop-nonce").first().map(|s| s.to_string())
        {
            dpop_challenge_used = true;
            if let ResolvedAuth::Dpop { nonce: n, .. } = &mut prep.auth {
                *n = Some(nonce);
            }
            reason = AttemptReason::AuthChallenge { scheme: "DPoP".into() };
            last = Some(out);
            continue;
        }

        // ---- safe automatic retries (off by default) ----
        if let Some(f) = &out.observation.failure
            && out.response.is_none()
            && retries < prep.settings.retries.max_retries
            && f.kind != FailureKind::Canceled
            && !f.kind.is_local_preparation()
        {
            // Never replay a possibly processed non-idempotent request:
            // retry only when the request provably never left, or when the
            // method is idempotent (repeating it is safe by definition).
            let idempotent = anvil_diagnostics::facts::is_idempotent(&current.method);
            let safe = out.observation.dispatch == DispatchState::NotDispatched || idempotent;
            if safe {
                retries += 1;
                let backoff = prep.settings.retries.backoff_ms.saturating_mul(1u64 << (retries - 1).min(6));
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(backoff)) => {}
                    _ = cancel.cancelled() => { last = Some(out); break; }
                }
                reason = AttemptReason::Retry { after: f.kind };
                last = Some(out);
                continue;
            }
        }
        last = Some(out);
        break;
    }

    let last = last.expect("at least one attempt");
    // Channel authentication for Ferrum trust: verified TLS on the final connection.
    let mut trust = prep.trust.clone();
    if let FerrumTrust::Trusted { channel_authenticated, .. } = &mut trust {
        let verified = last
            .observation
            .connection
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .map(|t| matches!(t.verification, TlsVerification::Verified))
            .unwrap_or(false);
        *channel_authenticated = verified;
        if prep.require_verified_tls && !verified {
            // Profile requires verified TLS but the channel was not verified:
            // markers are treated as unverified.
            trust = FerrumTrust::NotConfigured;
        }
    }
    let used_secrets = resolver.used_secrets.lock().clone();
    for s in &used_secrets {
        redactor.add_secret(s);
    }
    // An automatic HTTP/3 → TCP fallback is reported, never hidden.
    let fallback_from = attempts.iter().find_map(|a| match &a.reason {
        AttemptReason::ProtocolFallback { from } => Some(from.clone()),
        _ => None,
    });
    let assembly = Assembly {
        ctx,
        started_at,
        prepared_method: prep.http.method.clone(),
        prepared_url: prep.http.target.url(),
        prepared_headers: prep.http.headers.clone(),
        prepared_body: prep.http.body.clone(),
        content_type: prep.http.content_type.clone(),
        auth_label: prep.auth_label.clone(),
        auth_facts: final_auth_facts,
        settings: prep.settings.clone(),
        tls_profile: prep.tls_profile_name.clone(),
        proxy: prep.proxy.as_ref().map(|p| p.label.clone()),
        tls_verification_enabled: prep.tls.as_ref().map(|t| t.verify).unwrap_or(true),
        inferred: prep.inferred.clone(),
        lint_bypassed: prep.http.lint_bypassed.clone(),
        attempts,
        last,
        trust,
        credentials_stripped,
        protocol_fallback_from: fallback_from,
        redactor: &redactor,
        extra_findings,
        stream: None,
        protocol_status_override: None,
    };
    let output = record::assemble(assembly);
    let _ = assertions::evaluate;
    let _: Option<Observed> = None;
    output
}

fn replace_oauth(a: &mut ResolvedAuth, t: &anvil_auth::oauth::CachedToken) {
    match a {
        ResolvedAuth::OAuth2 { access_token, token_type } => {
            *access_token = t.access_token.clone();
            *token_type = t.token_type.clone();
        }
        ResolvedAuth::Multi(v) => v.iter_mut().for_each(|x| replace_oauth(x, t)),
        _ => {}
    }
}
