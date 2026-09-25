//! Session protocols — WebSocket, gRPC, SSE, raw TCP/TLS and UDP/DTLS.
//!
//! Automation ([`execute`]) and interactive sessions ([`Engine::open_session`])
//! share one preparation path with HTTP: variables, settings layers, auth
//! (applied as headers for WebSocket / gRPC / SSE), TLS profiles and trust,
//! proxies and redaction behave identically. Unsupported combinations
//! (e.g. a proxy with UDP, WebSocket over HTTP/3) fail before any traffic.
//! Every run ends in a full [`ExecutionOutput`] assembled by
//! [`record::assemble`] with the session transcript and the typed protocol
//! status, so diagnostics and assertions (`MessageCount`, `GrpcStatus`, ...)
//! work exactly as for HTTP.

use crate::context::{ExecutionContext, resolve_sensitive};
use crate::http_exec::{self, Prepared};
use crate::prepare::{self, Target};
use crate::record::{self, Assembly};
use crate::redact::Redactor;
use crate::vars::Resolver;
use crate::{Engine, ExecutionOutput};
use anvil_auth::{ResolvedAuth, SignableRequest};
use anvil_diagnostics::{Draft, FerrumTrust};
use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, EvidenceSource, Owner, Remediation, Severity, SourceScope};
use anvil_domain::events::SessionCommand;
use anvil_domain::execution::*;
use anvil_domain::request::*;
use anvil_domain::settings::{EffectiveSettings, HttpVersionPolicy};
use anvil_transport::dns::DnsConfig;
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::{CommandRx, RedactFn, SessionFacts, SessionOutput, TranscriptLimits};
use anvil_transport::tls::{ClientIdentityMaterial, PreparedTls};
use anvil_transport::{dtls, grpc, rawtcp, sse, udp, ws};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{HeaderName, HeaderValue};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Bound of the interactive command queue (the UI never blocks a session).
const COMMAND_QUEUE: usize = 256;
/// Reconnections allowed for an SSE stream with `reconnect` enabled.
const SSE_MAX_RECONNECTS: u32 = 5;
/// Per-message receive ceiling for gRPC (local policy; lowered by limits).
const GRPC_MAX_MESSAGE: u64 = 64 * 1024 * 1024;

enum Plan {
    Ws(ws::WsPlan),
    Grpc(grpc::GrpcPlan),
    Sse(sse::SsePlan),
    Tcp(rawtcp::TcpPlan),
    Udp(udp::UdpPlan),
    Dtls(dtls::DtlsPlan),
}

/// Everything a session run needs, frozen before any traffic.
struct SessionPrep {
    plan: Plan,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Bytes,
    content_type: Option<String>,
    auth_label: String,
    auth_facts: Vec<(String, String)>,
    settings: EffectiveSettings,
    tls_profile: Option<String>,
    proxy: Option<String>,
    tls_verification_enabled: bool,
    inferred: Vec<String>,
    lint_bypassed: Option<String>,
    trust: FerrumTrust,
    require_verified_tls: bool,
    redactor: Redactor,
    extra_findings: Vec<Draft>,
}

fn local(kind: FailureKind, msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, kind, msg).with_field(field)
}

fn unsupported(msg: impl Into<String>, field: &str) -> TransportFailure {
    local(FailureKind::UnsupportedCombination, msg, field)
}

fn header_pairs(headers: &[(String, String)]) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .filter_map(|(n, v)| match (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_str(v)) {
            (Ok(n), Ok(v)) => Some((n, v)),
            _ => None,
        })
        .collect()
}

fn dns_config(s: &EffectiveSettings) -> DnsConfig {
    DnsConfig { resolver: s.resolver.clone(), overrides: s.dns_overrides.clone(), ip_preference: s.ip_preference }
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

fn has_explicit_header(spec: &RequestSpec, name: &str) -> bool {
    spec.headers.iter().any(|h| h.enabled && h.name.trim().eq_ignore_ascii_case(name))
}

/// OAuth acquisition (same transport and trust as HTTP) and per-send auth.
/// Returns the final headers and query, auth facts, and scrubs every secret
/// used through the redactor.
#[allow(clippy::too_many_arguments)]
async fn apply_auth(
    engine: &Engine,
    ctx: &ExecutionContext,
    prep: &mut Prepared,
    redactor: &mut Redactor,
    method: &str,
    target: &Target,
    headers: Vec<(String, String)>,
    body: &[u8],
) -> Result<(Vec<(String, String)>, String, Vec<(String, String)>), TransportFailure> {
    if let Some((key, cfg)) = &prep.oauth_key {
        let http = crate::oauth_http::EngineTokenHttp { engine, ctx, settings: &prep.settings };
        match engine.tokens.get_or_acquire(key, cfg, &http, Utc::now()).await {
            Ok(t) => replace_oauth(&mut prep.auth, &t),
            Err(e) => return Err(crate::oauth_http::acquisition_failure(cfg, e, "Nothing was sent.")),
        }
    }
    if matches!(prep.auth, ResolvedAuth::None) {
        return Ok((headers, target.query.clone(), vec![]));
    }
    let signable = SignableRequest {
        method: method.to_string(),
        scheme: target.scheme.clone(),
        authority: headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| target.authority.clone()),
        raw_path: target.path.clone(),
        raw_query: target.query.clone(),
        headers: headers.clone(),
        body: body.to_vec(),
    };
    let applied = anvil_auth::apply(&prep.auth, &signable, Utc::now())
        .map_err(|e| local(FailureKind::AuthPreparationFailed, e.to_string(), "auth"))?;
    if applied.body.is_some() {
        return Err(unsupported(
            format!("the auth profile '{}' rewrites the message body, which this protocol cannot carry", applied.label),
            "auth",
        ));
    }
    for s in &applied.secrets {
        redactor.add_secret(s);
    }
    let mut out = headers;
    for (n, v) in applied.set_headers {
        out.retain(|(h, _)| !h.eq_ignore_ascii_case(&n));
        out.push((n, v));
    }
    let mut query = target.query.clone();
    for (k, v) in applied.append_query {
        let pair = format!("{}={}", prepare::encode_component(&k), prepare::encode_component(&v));
        query = if query.is_empty() { pair } else { format!("{query}&{pair}") };
    }
    Ok((out, query, applied.facts))
}

/// Client identity material (PEM) for DTLS, following the TLS profile's
/// host bindings exactly as TLS does.
fn identity_material(
    ctx: &ExecutionContext,
    settings: &EffectiveSettings,
    target: &Target,
) -> Result<Option<ClientIdentityMaterial>, TransportFailure> {
    let Some(p) = settings.tls_profile_id.and_then(|id| ctx.tls_profiles.iter().find(|p| p.id == id)) else { return Ok(None) };
    let Some(id) = &p.client_identity else { return Ok(None) };
    if !http_exec::binding_matches(&p.bindings, target) {
        return Ok(None);
    }
    Ok(Some(match id {
        anvil_domain::tls::ClientIdentity::Pem { cert_chain_pem, private_key_pem } => {
            let (key, _) = resolve_sensitive(private_key_pem, ctx.secrets.as_ref())
                .map_err(|e| local(FailureKind::ClientIdentityInvalid, e, "tls.client_identity.private_key"))?;
            ClientIdentityMaterial { cert_chain_pem: cert_chain_pem.clone(), private_key_pem: key }
        }
        anvil_domain::tls::ClientIdentity::Pkcs12 { bundle_b64, password } => {
            let (b, _) = resolve_sensitive(bundle_b64, ctx.secrets.as_ref())
                .map_err(|e| local(FailureKind::ClientIdentityInvalid, e, "tls.client_identity"))?;
            let (pw, _) = resolve_sensitive(password, ctx.secrets.as_ref())
                .map_err(|e| local(FailureKind::ClientIdentityInvalid, e, "tls.client_identity"))?;
            crate::pkcs12::to_pem(&b, &pw)?
        }
    }))
}

fn decode_payloads(r: &Resolver, payloads: &[StreamPayload], field: &str) -> Result<Vec<Bytes>, TransportFailure> {
    payloads
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let data = r.resolve(&p.data, &format!("{field}[{i}].data"))?;
            anvil_transport::session::decode_payload(&StreamPayload { data, encoding: p.encoding })
                .map_err(|e| local(FailureKind::BodySerialization, e, &format!("{field}[{i}]")))
        })
        .collect()
}

fn concat(parts: &[Bytes]) -> Bytes {
    let mut v = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        v.extend_from_slice(p);
    }
    Bytes::from(v)
}

struct Base {
    prep: Prepared,
    redactor: Redactor,
    inferred: Vec<String>,
}

fn base(engine: &Engine, ctx: &ExecutionContext, r: &Resolver, schemes: &[&str]) -> Result<Base, TransportFailure> {
    let prep = http_exec::prepare_all(engine, ctx, r, schemes)?;
    let redactor = Redactor::new(r.used_secrets.lock().clone(), ctx.redaction_names.clone());
    let inferred = prep.inferred.clone();
    Ok(Base { prep, redactor, inferred })
}

fn finish_prep(
    b: Base,
    plan: Plan,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Bytes,
    auth_facts: Vec<(String, String)>,
) -> SessionPrep {
    let Base { prep, redactor, inferred } = b;
    SessionPrep {
        plan,
        method,
        url,
        headers,
        body,
        content_type: prep.http.content_type.clone(),
        auth_label: prep.auth_label.clone(),
        auth_facts,
        tls_profile: prep.tls_profile_name.clone(),
        proxy: prep.proxy.as_ref().map(|p| p.label.clone()),
        tls_verification_enabled: prep.tls.as_ref().map(|t| t.verify).unwrap_or(true),
        lint_bypassed: prep.http.lint_bypassed.clone(),
        trust: prep.trust.clone(),
        require_verified_tls: prep.require_verified_tls,
        settings: prep.settings,
        inferred,
        redactor,
        extra_findings: vec![],
    }
}

fn redact_fn(r: &Redactor) -> RedactFn {
    let r = r.clone();
    Arc::new(move |s: &str| r.text(s))
}

async fn prepare_session(
    engine: &Engine,
    ctx: &ExecutionContext,
    r: &Resolver,
    interactive: bool,
) -> Result<SessionPrep, TransportFailure> {
    match ctx.spec.protocol {
        Protocol::WebSocket => prepare_ws(engine, ctx, r).await,
        Protocol::Grpc => prepare_grpc(engine, ctx, r, interactive).await,
        Protocol::Sse => prepare_sse(engine, ctx, r).await,
        Protocol::Tcp => prepare_tcp(engine, ctx, r),
        Protocol::Udp => prepare_udp(engine, ctx, r),
        Protocol::Http => Err(unsupported("HTTP is request/response; use execute() rather than a session", "protocol")),
    }
}

async fn prepare_ws(engine: &Engine, ctx: &ExecutionContext, r: &Resolver) -> Result<SessionPrep, TransportFailure> {
    let spec = ctx.spec.websocket.clone().unwrap_or(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![],
        expect_messages: 0,
        max_message_bytes: 16 * 1024 * 1024,
        idle_close_ms: 5_000,
    });
    let mut b = base(engine, ctx, r, &["wss", "ws"])?;
    let target = b.prep.http.target.clone();
    let mut headers = b.prep.http.headers.clone();
    if !has_explicit_header(&ctx.spec, "accept-encoding") {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept-encoding"));
        b.inferred.retain(|i| !i.starts_with("Accept-Encoding"));
    }
    let mut script = Vec::with_capacity(spec.messages.len());
    for (i, m) in spec.messages.iter().enumerate() {
        let field = format!("websocket.messages[{i}]");
        script.push(match m {
            WsMessage::Text { text } => WsMessage::Text { text: r.resolve(text, &field)? },
            WsMessage::Binary { hex } => {
                let hex = r.resolve(hex, &field)?;
                anvil_transport::session::decode_hex(&hex).map_err(|e| local(FailureKind::BodySerialization, e, &field))?;
                WsMessage::Binary { hex }
            }
            WsMessage::Ping { hex } => {
                let hex = r.resolve(hex, &field)?;
                anvil_transport::session::decode_hex(&hex).map_err(|e| local(FailureKind::BodySerialization, e, &field))?;
                WsMessage::Ping { hex }
            }
            WsMessage::Close { code, reason } => WsMessage::Close { code: *code, reason: r.resolve(reason, &field)? },
        });
    }
    let subprotocols = spec
        .subprotocols
        .iter()
        .enumerate()
        .map(|(i, s)| r.resolve(s, &format!("websocket.subprotocols[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;
    let method = if spec.bootstrap == WsBootstrap::Http2ExtendedConnect { "CONNECT" } else { "GET" };
    let (headers, query, facts) = apply_auth(engine, ctx, &mut b.prep, &mut b.redactor, "GET", &target, headers, &[]).await?;
    for (k, v) in &facts {
        b.inferred.push(format!("auth {k}: {v}"));
    }
    let t = Target { query, ..target.clone() };
    let plan = ws::WsPlan {
        bootstrap: spec.bootstrap,
        secure: t.scheme == "wss",
        host: t.host.clone(),
        port: t.port,
        authority: t.authority.clone(),
        request_target: t.request_target(),
        headers: header_pairs(&headers),
        subprotocols,
        script,
        expect_messages: spec.expect_messages,
        idle_close_ms: spec.idle_close_ms,
        max_message_bytes: spec.max_message_bytes,
        timeouts: b.prep.settings.timeouts,
        limits: b.prep.settings.limits,
        dns: dns_config(&b.prep.settings),
        proxy: b.prep.proxy.clone(),
        tls: b.prep.tls.clone(),
        display_url: b.redactor.url(&t.url()),
        transcript: TranscriptLimits::default(),
        redact: Some(redact_fn(&b.redactor)),
    };
    let url = t.url();
    Ok(finish_prep(b, Plan::Ws(plan), method.into(), url, headers, Bytes::new(), vec![]))
}

async fn prepare_sse(engine: &Engine, ctx: &ExecutionContext, r: &Resolver) -> Result<SessionPrep, TransportFailure> {
    let spec = ctx.spec.sse.clone().unwrap_or(SseSpec { max_events: 0, idle_timeout_ms: 30_000, last_event_id: None, reconnect: false });
    let mut b = base(engine, ctx, r, &["https", "http"])?;
    if let Some(f) = sse::version_unsupported(b.prep.settings.http_version) {
        return Err(f);
    }
    let target = b.prep.http.target.clone();
    let mut headers = b.prep.http.headers.clone();
    if !has_explicit_header(&ctx.spec, "accept") {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept"));
    }
    if !has_explicit_header(&ctx.spec, "accept-encoding") {
        // Events are parsed incrementally; ask for an unencoded stream.
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept-encoding"));
        headers.push(("Accept-Encoding".into(), "identity".into()));
        b.inferred.retain(|i| !i.starts_with("Accept-Encoding"));
        b.inferred.push("Accept-Encoding: identity (events are parsed as they arrive)".into());
    }
    let last_event_id = spec.last_event_id.as_ref().map(|v| r.resolve(v, "sse.last_event_id")).transpose()?;
    let body = b.prep.http.body.clone();
    let method = b.prep.http.method.clone();
    let (headers, query, facts) = apply_auth(engine, ctx, &mut b.prep, &mut b.redactor, &method, &target, headers, &body).await?;
    let t = Target { query, ..target.clone() };
    let plan = sse::SsePlan {
        method: http::Method::from_bytes(method.as_bytes()).unwrap_or(http::Method::GET),
        https: t.scheme == "https",
        host: t.host.clone(),
        port: t.port,
        authority: t.authority.clone(),
        request_target: t.request_target(),
        headers: header_pairs(&headers),
        body: body.clone(),
        version: b.prep.settings.http_version,
        timeouts: b.prep.settings.timeouts,
        limits: b.prep.settings.limits,
        dns: dns_config(&b.prep.settings),
        proxy: b.prep.proxy.clone(),
        tls: b.prep.tls.clone(),
        display_url: b.redactor.url(&t.url()),
        max_events: spec.max_events,
        idle_timeout_ms: spec.idle_timeout_ms,
        last_event_id,
        reconnect: spec.reconnect,
        max_reconnects: if spec.reconnect { SSE_MAX_RECONNECTS } else { 0 },
        transcript: TranscriptLimits::default(),
        redact: Some(redact_fn(&b.redactor)),
    };
    let url = t.url();
    Ok(finish_prep(b, Plan::Sse(plan), method, url, headers, body, facts))
}

async fn load_schema(ctx: &ExecutionContext, spec: &GrpcSpec) -> Result<grpc::Schema, TransportFailure> {
    match &spec.schema {
        GrpcSchemaSource::Reflection => Ok(grpc::Schema::Reflection),
        GrpcSchemaSource::DescriptorSet { attachment } => {
            let bytes = ctx.attachments.load(attachment).map_err(|e| local(FailureKind::MissingAttachment, e, "grpc.schema.attachment"))?;
            grpc::pool_from_descriptor_set(&bytes)
                .map(grpc::Schema::Pool)
                .map_err(|e| local(FailureKind::BodySerialization, e, "grpc.schema"))
        }
        GrpcSchemaSource::ProtoFiles { files } => {
            let mut sources = Vec::with_capacity(files.len());
            for (i, a) in files.iter().enumerate() {
                let field = format!("grpc.schema.files[{i}]");
                let bytes = ctx.attachments.load(a).map_err(|e| local(FailureKind::MissingAttachment, e, &field))?;
                let name = match a {
                    AttachmentRef::Stored { file_name, .. } => file_name.clone(),
                    AttachmentRef::LinkedFile { path } => {
                        std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| path.clone())
                    }
                };
                let src = String::from_utf8(bytes.to_vec())
                    .map_err(|_| local(FailureKind::BodySerialization, "the .proto file is not UTF-8", &field))?;
                sources.push((name, src));
            }
            grpc::pool_from_proto_sources(&sources)
                .map(grpc::Schema::Pool)
                .map_err(|e| local(FailureKind::BodySerialization, format!("the .proto files could not be compiled: {e}"), "grpc.schema"))
        }
    }
}

async fn prepare_grpc(engine: &Engine, ctx: &ExecutionContext, r: &Resolver, interactive: bool) -> Result<SessionPrep, TransportFailure> {
    let Some(spec) = ctx.spec.grpc.clone() else {
        return Err(local(FailureKind::BodySerialization, "a gRPC request needs a service, method and schema", "grpc"));
    };
    let mut b = base(engine, ctx, r, &["grpcs", "grpc", "https", "http"])?;
    match b.prep.settings.http_version {
        HttpVersionPolicy::Http1Only => {
            return Err(unsupported("gRPC requires HTTP/2; HTTP/1.1-only was selected", "settings.http_version"));
        }
        HttpVersionPolicy::Http3Only | HttpVersionPolicy::Http3WithFallback => {
            return Err(unsupported("gRPC over HTTP/3 is not implemented; choose HTTP/2 (TLS) or h2c", "settings.http_version"));
        }
        _ => {}
    }
    if interactive && !matches!(spec.mode, GrpcMode::ClientStreaming | GrpcMode::Bidirectional) {
        return Err(unsupported(
            format!("interactive sessions need a client-streaming or bidirectional method; run this {:?} call with execute()", spec.mode),
            "grpc.mode",
        ));
    }
    let target = b.prep.http.target.clone();
    let tls_url = matches!(target.scheme.as_str(), "grpcs" | "https");
    if spec.plaintext && tls_url {
        return Err(unsupported("plaintext (h2c) was selected for a TLS URL; use grpc:// or http:// for h2c", "grpc.plaintext"));
    }
    if !tls_url {
        b.inferred.push("cleartext gRPC uses HTTP/2 with prior knowledge (h2c)".into());
    }
    let service = r.resolve(&spec.service, "grpc.service")?;
    let method_name = r.resolve(&spec.method, "grpc.method")?;
    let messages =
        spec.messages.iter().enumerate().map(|(i, m)| r.resolve(m, &format!("grpc.messages[{i}]"))).collect::<Result<Vec<_>, _>>()?;
    let schema = load_schema(ctx, &spec).await?;
    // Local schema: the method, call mode and every message are validated before traffic.
    let mut unary_body = Bytes::new();
    if let grpc::Schema::Pool(pool) = &schema {
        let m = grpc::resolve_method(pool, &service, &method_name, spec.mode)?;
        for (i, j) in messages.iter().enumerate() {
            let enc =
                grpc::encode_json(&m.input(), j).map_err(|e| local(FailureKind::BodySerialization, e, &format!("grpc.messages[{i}]")))?;
            if matches!(spec.mode, GrpcMode::Unary | GrpcMode::ServerStreaming) {
                unary_body = grpc::frame(&enc);
            }
        }
        if matches!(spec.mode, GrpcMode::Unary | GrpcMode::ServerStreaming) && messages.len() > 1 {
            return Err(local(
                FailureKind::BodySerialization,
                format!("a {:?} call sends exactly one request message", spec.mode),
                "grpc.messages",
            ));
        }
    }
    // Metadata: request headers + gRPC metadata entries; HTTP content negotiation headers do not apply.
    let mut headers: Vec<(String, String)> = b
        .prep
        .http
        .headers
        .iter()
        .filter(|(n, _)| !matches!(n.to_ascii_lowercase().as_str(), "accept" | "accept-encoding" | "content-type" | "user-agent"))
        .cloned()
        .collect();
    if has_explicit_header(&ctx.spec, "user-agent")
        && let Some(ua) = b.prep.http.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("user-agent"))
    {
        headers.push(ua.clone());
    }
    b.inferred.retain(|i| !i.starts_with("Accept-Encoding") && !i.starts_with("User-Agent") && !i.starts_with("Content-Type"));
    for (i, kv) in spec.metadata.iter().enumerate().filter(|(_, kv)| kv.enabled) {
        let n = r.resolve(kv.name.trim(), &format!("grpc.metadata[{i}].name"))?.to_ascii_lowercase();
        let v = r.resolve(&kv.value, &format!("grpc.metadata[{i}].value"))?;
        if HeaderName::from_bytes(n.as_bytes()).is_err() || n.starts_with(':') || n.starts_with("grpc-") {
            return Err(local(
                FailureKind::InvalidHeader,
                format!("'{n}' is not a valid custom gRPC metadata key"),
                &format!("grpc.metadata[{i}].name"),
            ));
        }
        if HeaderValue::from_str(&v).is_err() {
            return Err(local(
                FailureKind::InvalidHeader,
                format!("the value of '{n}' is not a valid metadata value"),
                &format!("grpc.metadata[{i}].value"),
            ));
        }
        headers.push((n, v));
    }
    let prefix = target.path.trim_end_matches('/').to_string();
    let path = format!("{prefix}/{service}/{method_name}");
    let call_target = Target { path: path.clone(), ..target.clone() };
    let (headers, query, facts) = apply_auth(engine, ctx, &mut b.prep, &mut b.redactor, "POST", &call_target, headers, &unary_body).await?;
    if !query.is_empty() && query != target.query {
        return Err(unsupported("an auth profile that adds query parameters cannot be used with gRPC (the path is fixed)", "auth"));
    }
    let display = format!("{}://{}{}", target.scheme, target.authority, path);
    let plan = grpc::GrpcPlan {
        tls: if tls_url { b.prep.tls.clone() } else { None },
        host: target.host.clone(),
        port: target.port,
        authority: target.authority.clone(),
        path_prefix: prefix,
        service,
        method: method_name,
        mode: spec.mode,
        schema,
        messages,
        headers: header_pairs(&headers),
        deadline_ms: spec.deadline_ms,
        timeouts: b.prep.settings.timeouts,
        limits: b.prep.settings.limits,
        dns: dns_config(&b.prep.settings),
        proxy: b.prep.proxy.clone(),
        display_url: b.redactor.url(&display),
        max_message_bytes: b.prep.settings.limits.max_response_bytes.min(GRPC_MAX_MESSAGE) as usize,
        transcript: TranscriptLimits::default(),
        redact: Some(redact_fn(&b.redactor)),
    };
    let mut p = finish_prep(b, Plan::Grpc(plan), "POST".into(), display, headers, unary_body, facts);
    p.content_type = Some("application/grpc".into());
    Ok(p)
}

fn no_auth(prep: &Prepared, protocol: &str) -> Result<(), TransportFailure> {
    if matches!(prep.auth, ResolvedAuth::None) {
        Ok(())
    } else {
        Err(unsupported(
            format!(
                "auth '{}' cannot be applied to raw {protocol}: payloads are sent verbatim. Set the request's auth to none (client certificates come from the TLS profile)",
                prep.auth_label
            ),
            "auth",
        ))
    }
}

fn prepare_tcp(engine: &Engine, ctx: &ExecutionContext, r: &Resolver) -> Result<SessionPrep, TransportFailure> {
    let spec = ctx.spec.tcp.clone().unwrap_or(TcpSpec {
        tls: false,
        framing: TcpFraming::None,
        payloads: vec![],
        half_close_after_send: false,
        read_idle_ms: 2_000,
        max_read_bytes: 1024 * 1024,
        expect_frames: 0,
    });
    let mut b = base(engine, ctx, r, &["tcp", "tls"])?;
    no_auth(&b.prep, "TCP")?;
    let target = b.prep.http.target.clone();
    let use_tls = target.scheme == "tls" || spec.tls;
    let mut tls: Option<Arc<PreparedTls>> = None;
    if use_tls {
        let (t, name, _) = http_exec::tls_for(engine, ctx, &b.prep.settings, &target, &mut b.inferred)?;
        tls = Some(t);
        b.prep.tls_profile_name = name;
        b.prep.tls = tls.clone();
    }
    let payloads = decode_payloads(r, &spec.payloads, "tcp.payloads")?;
    for (i, p) in payloads.iter().enumerate() {
        rawtcp::encode_frame(spec.framing, p).map_err(|e| local(FailureKind::BodySerialization, e, &format!("tcp.payloads[{i}]")))?;
    }
    b.inferred.retain(|i| i.starts_with("no scheme given") || i.contains("TLS profile") || i.contains("NO_PROXY"));
    let scheme = if use_tls { "tls" } else { "tcp" };
    let url = format!("{scheme}://{}", target.authority);
    let plan = rawtcp::TcpPlan {
        host: target.host.clone(),
        port: target.port,
        tls,
        alpn: vec![],
        proxy: b.prep.proxy.clone(),
        dns: dns_config(&b.prep.settings),
        timeouts: b.prep.settings.timeouts,
        framing: spec.framing,
        payloads: payloads.clone(),
        half_close_after_send: spec.half_close_after_send,
        read_idle_ms: spec.read_idle_ms,
        max_read_bytes: spec.max_read_bytes,
        expect_frames: spec.expect_frames,
        display_url: b.redactor.url(&url),
        transcript: TranscriptLimits::default(),
        redact: Some(redact_fn(&b.redactor)),
    };
    let body = concat(&payloads);
    let mut p = finish_prep(b, Plan::Tcp(plan), scheme.to_ascii_uppercase(), url, vec![], body, vec![]);
    p.content_type = None;
    Ok(p)
}

fn prepare_udp(engine: &Engine, ctx: &ExecutionContext, r: &Resolver) -> Result<SessionPrep, TransportFailure> {
    let spec = ctx.spec.udp.clone().unwrap_or(UdpSpec { dtls: false, datagrams: vec![], response_window_ms: 1_000, max_datagrams: 1_000 });
    let mut b = base(engine, ctx, r, &["udp", "dtls"])?;
    no_auth(&b.prep, "UDP")?;
    if let Some(p) = &b.prep.proxy {
        return Err(unsupported(
            format!("UDP/DTLS cannot be sent through the proxy '{}' (HTTP CONNECT and SOCKS5 CONNECT carry TCP only)", p.label),
            "settings.proxy",
        ));
    }
    let target = b.prep.http.target.clone();
    let use_dtls = target.scheme == "dtls" || spec.dtls;
    let datagrams = decode_payloads(r, &spec.datagrams, "udp.datagrams")?;
    b.inferred.retain(|i| i.starts_with("no scheme given") || i.contains("TLS profile") || i.contains("NO_PROXY"));
    let scheme = if use_dtls { "dtls" } else { "udp" };
    let url = format!("{scheme}://{}", target.authority);
    let display_url = b.redactor.url(&url);
    let settings = b.prep.settings.clone();
    let plan = if use_dtls {
        let (t, name, _) = http_exec::tls_for(engine, ctx, &settings, &target, &mut b.inferred)?;
        b.prep.tls_profile_name = name;
        b.prep.tls = Some(t.clone());
        let identity = match identity_material(ctx, &settings, &target)? {
            Some(m) => Some(dtls::identity_from_pem(&m.cert_chain_pem, &m.private_key_pem)?),
            None => None,
        };
        Plan::Dtls(dtls::DtlsPlan {
            host: target.host.clone(),
            port: target.port,
            dns: dns_config(&settings),
            timeouts: settings.timeouts,
            tls: t,
            identity,
            datagrams: datagrams.clone(),
            response_window_ms: spec.response_window_ms,
            max_datagrams: spec.max_datagrams,
            display_url,
            transcript: TranscriptLimits::default(),
            redact: Some(redact_fn(&b.redactor)),
        })
    } else {
        Plan::Udp(udp::UdpPlan {
            host: target.host.clone(),
            port: target.port,
            dns: dns_config(&settings),
            timeouts: settings.timeouts,
            datagrams: datagrams.clone(),
            response_window_ms: spec.response_window_ms,
            max_datagrams: spec.max_datagrams,
            display_url,
            transcript: TranscriptLimits::default(),
            redact: Some(redact_fn(&b.redactor)),
        })
    };
    let body = concat(&datagrams);
    let mut p = finish_prep(b, plan, scheme.to_ascii_uppercase(), url, vec![], body, vec![]);
    p.content_type = None;
    Ok(p)
}

/// Findings the engine derives from session facts (wording supplied here;
/// these are adapter observations, not generic rules).
fn fact_findings(facts: &SessionFacts, protocol: Protocol) -> Vec<Draft> {
    let mut out = Vec::new();
    if let Some(r) = &facts.grpc_reflection
        && !r.succeeded
    {
        let mut d = Draft::new(
            "grpc.reflection_unavailable",
            "protocol.grpc",
            Confidence::Confirmed,
            SourceScope::ClientToPeer,
            Owner::Caller,
            Severity::Error,
        )
        .ev(EvidenceSource::GrpcStatus, "reflection.service", r.service.clone())
        .ev(EvidenceSource::GrpcStatus, "reflection.grpc_status", r.grpc_status.map(|s| s.to_string()).unwrap_or_else(|| "missing".into()))
        .not_proven("That the service or method itself is unavailable — only schema discovery by reflection failed.");
        d.catalog_text = Some((
            "Server reflection did not provide a schema".into(),
            format!(
                "{} The method was not called. This concerns schema discovery only; the service may work normally with a local schema.",
                r.problem.clone().unwrap_or_else(|| "Server reflection failed.".into())
            ),
        ));
        d.extra_remediation.push(Remediation {
            text: "Import the service's .proto files or a descriptor set and call it without reflection, or ask the operator to allow reflection for this caller.".into(),
            owner: Owner::Caller,
        });
        out.push(d);
    }
    if facts.icmp_port_unreachable && protocol == Protocol::Udp {
        let mut d = Draft::new(
            "udp.icmp_port_unreachable",
            "protocol.streams",
            Confidence::Likely,
            SourceScope::ClientToPeer,
            Owner::Unknown,
            Severity::Warning,
        )
        .ev(EvidenceSource::NativeTransport, "icmp", "port unreachable reported to the socket")
        .alt("A firewall or gateway generated the ICMP message on behalf of the destination.")
        .not_proven("That the destination host is down.");
        d.catalog_text = Some((
            "The destination reported the UDP port unreachable".into(),
            "The operating system received an ICMP port-unreachable for this destination, which usually means nothing is listening on that UDP port."
                .into(),
        ));
        out.push(d);
    }
    if facts.repeated_datagrams > 0 {
        let mut d = Draft::new(
            "udp.repeated_payloads",
            "protocol.streams",
            Confidence::Confirmed,
            SourceScope::Unknown,
            Owner::Unknown,
            Severity::Info,
        )
        .ev(EvidenceSource::NativeTransport, "udp.repeated_payloads", facts.repeated_datagrams.to_string())
        .alt("The network duplicated datagrams.")
        .alt("The peer sent identical replies on purpose.")
        .not_proven("Which datagrams were duplicated — UDP has no sequence numbers unless the application protocol adds them.");
        d.catalog_text = Some((
            "Some received datagrams repeated earlier payloads".into(),
            format!(
                "{} received datagram(s) were byte-identical to an earlier received datagram. Anvil counts this as an observation, not as proof of duplicate delivery.",
                facts.repeated_datagrams
            ),
        ));
        out.push(d);
    }
    out
}

async fn run_plan(plan: &Plan, events: &EventCtx, cancel: &CancellationToken, commands: Option<CommandRx>) -> SessionOutput {
    match plan {
        Plan::Ws(p) => ws::run(p, events, cancel, commands).await,
        Plan::Grpc(p) => grpc::run(p, events, cancel, commands).await,
        Plan::Sse(p) => sse::run(p, events, cancel, commands).await,
        Plan::Tcp(p) => rawtcp::run(p, events, cancel, commands).await,
        Plan::Udp(p) => udp::run(p, events, cancel, commands).await,
        Plan::Dtls(p) => dtls::run(p, events, cancel, commands).await,
    }
}

async fn run_prepared(
    prep: SessionPrep,
    ctx: &ExecutionContext,
    resolver: &Resolver,
    started_at: DateTime<Utc>,
    events: EventCtx,
    cancel: CancellationToken,
    commands: Option<CommandRx>,
) -> ExecutionOutput {
    let out = run_plan(&prep.plan, &events, &cancel, commands).await;
    let SessionPrep { method, url, headers, body, content_type, auth_label, auth_facts, settings, tls_profile, proxy, .. } = prep;
    let mut redactor = prep.redactor;
    for s in resolver.used_secrets.lock().iter() {
        redactor.add_secret(s);
    }
    let mut attempts = out.attempts;
    let Some(last) = attempts.pop() else {
        let f = TransportFailure::new(Phase::Session, FailureKind::Internal, "the session adapter returned no attempt");
        return record::local_failure(ctx, resolver, started_at, f);
    };
    let mut observations: Vec<AttemptObservation> = attempts.into_iter().map(|a| a.observation).collect();
    observations.push(last.observation.clone());
    let mut trust = prep.trust;
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
            trust = FerrumTrust::NotConfigured;
        }
    }
    let mut inferred = prep.inferred;
    inferred.extend(out.facts.notes.iter().cloned());
    if let Some(d) = &out.facts.grpc_status_details {
        inferred.push(format!("grpc-status-details-bin: {d}"));
    }
    let mut extra = prep.extra_findings;
    extra.extend(fact_findings(&out.facts, ctx.spec.protocol));
    let assembly = Assembly {
        ctx,
        started_at,
        prepared_method: method,
        prepared_url: url,
        prepared_headers: headers,
        prepared_body: body,
        content_type,
        auth_label,
        auth_facts,
        settings,
        tls_profile,
        proxy,
        tls_verification_enabled: prep.tls_verification_enabled,
        inferred,
        lint_bypassed: prep.lint_bypassed,
        attempts: observations,
        last,
        trust,
        credentials_stripped: false,
        protocol_fallback_from: None,
        redactor: &redactor,
        extra_findings: extra,
        stream: out.transcript,
        protocol_status_override: Some(out.status),
    };
    record::assemble(assembly)
}

/// Automation execution for WebSocket, gRPC, SSE, TCP/TLS and UDP/DTLS.
pub(crate) async fn execute(engine: &Engine, ctx: &ExecutionContext, events: EventCtx, cancel: CancellationToken) -> ExecutionOutput {
    let started_at = Utc::now();
    let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
    match prepare_session(engine, ctx, &resolver, false).await {
        Ok(prep) => run_prepared(prep, ctx, &resolver, started_at, events, cancel, None).await,
        Err(f) => record::local_failure(ctx, &resolver, started_at, f),
    }
}

// ------------------------------------------------------------ interactive ---

/// Why a command was not accepted by an interactive session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("the session has ended")]
    Closed,
    #[error("{0}")]
    Unsupported(String),
}

/// Handle to a live interactive session. Live messages arrive through the
/// [`EventCtx`] given to [`Engine::open_session`]; the authoritative record
/// is returned by [`SessionHandle::finish`].
pub struct SessionHandle {
    pub execution_id: Id,
    pub protocol: Protocol,
    commands: Option<mpsc::Sender<SessionCommand>>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<ExecutionOutput>,
    fallback: Box<ExecutionContext>,
}

fn command_unsupported(protocol: Protocol, cmd: &SessionCommand) -> Option<String> {
    use SessionCommand as C;
    match (protocol, cmd) {
        (Protocol::WebSocket, C::HalfClose) => Some("WebSocket has no half-close; send Close instead".into()),
        (Protocol::Tcp, C::Ping) => Some("raw TCP has no ping; send a payload".into()),
        (Protocol::Udp, C::Ping | C::HalfClose) => Some("UDP/DTLS has no ping or half-close".into()),
        (Protocol::Grpc, C::Ping) => Some("gRPC calls have no ping command".into()),
        (Protocol::Sse, C::Close { .. }) => None,
        (Protocol::Sse, _) => Some("an event stream is receive-only; only Close/cancel apply".into()),
        _ => None,
    }
}

impl SessionHandle {
    /// Queue a command. Commands a protocol cannot express are rejected here
    /// rather than silently ignored.
    pub async fn send(&self, cmd: SessionCommand) -> Result<(), SessionError> {
        if let Some(why) = command_unsupported(self.protocol, &cmd) {
            return Err(SessionError::Unsupported(why));
        }
        match &self.commands {
            Some(tx) => tx.send(cmd).await.map_err(|_| SessionError::Closed),
            None => Err(SessionError::Closed),
        }
    }

    /// Graceful close: WebSocket Close 1000, gRPC half-close, TCP/UDP/SSE end.
    pub async fn close(&self) -> Result<(), SessionError> {
        self.send(SessionCommand::Close { code: 1000, reason: String::new() }).await
    }

    /// Abort the session now (no graceful close handshake is awaited).
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Wait for the session to end (peer close, [`close`](Self::close),
    /// [`cancel`](Self::cancel) or a stop condition) and return its record.
    pub async fn finish(self) -> ExecutionOutput {
        let SessionHandle { commands, task, fallback, .. } = self;
        let out = task.await;
        drop(commands);
        match out {
            Ok(o) => o,
            Err(e) => {
                let r = Resolver::new(vec![], None);
                let f = TransportFailure::new(Phase::Session, FailureKind::Internal, format!("the session task ended unexpectedly: {e}"));
                record::local_failure(&fallback, &r, Utc::now(), f)
            }
        }
    }
}

impl Engine {
    /// Open an interactive session (WebSocket, TCP/TLS, UDP/DTLS,
    /// client-streaming/bidirectional gRPC, or a receive-only SSE stream).
    /// Preparation happens now; a preparation failure yields a handle whose
    /// [`SessionHandle::finish`] returns the local-failure record at once.
    /// Scripted messages in the spec are sent first; the total deadline and
    /// idle auto-close do not apply to interactive sessions.
    pub async fn open_session(&self, ctx: ExecutionContext, events: EventCtx) -> SessionHandle {
        let started_at = Utc::now();
        let protocol = ctx.spec.protocol;
        let execution_id = events.execution_id;
        let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
        let cancel = CancellationToken::new();
        let fallback = Box::new(ctx.clone());
        match prepare_session(self, &ctx, &resolver, true).await {
            Ok(prep) => {
                let (tx, rx) = mpsc::channel(COMMAND_QUEUE);
                let c2 = cancel.clone();
                let task = tokio::spawn(async move { run_prepared(prep, &ctx, &resolver, started_at, events, c2, Some(rx)).await });
                SessionHandle { execution_id, protocol, commands: Some(tx), cancel, task, fallback }
            }
            Err(f) => {
                let out = record::local_failure(&ctx, &resolver, started_at, f);
                let task = tokio::spawn(async move { out });
                SessionHandle { execution_id, protocol, commands: None, cancel, task, fallback }
            }
        }
    }
}
