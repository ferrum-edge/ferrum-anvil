//! The request the effective-request preview shows for each protocol: the
//! method, target, headers and body that are sent, before auth is applied.
//! For a session protocol (WebSocket, SSE, gRPC) it is built from the
//! prepared request the way [`crate::sessions`] builds the protocol's plan,
//! with the headers the session transport adds. Nothing is sent and no token
//! is acquired. Raw TCP and UDP send no HTTP request, so there is none to
//! preview.

use crate::context::ExecutionContext;
use crate::http_exec::Prepared;
use crate::prepare::Target;
use crate::sessions;
use crate::vars::Resolver;
use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_domain::request::*;
use anvil_domain::settings::HttpVersionPolicy;
use anvil_transport::{grpc, sse};
use bytes::Bytes;
use futures::FutureExt;
use http::{HeaderName, HeaderValue};

/// Stands in for the `Sec-WebSocket-Key` generated for each handshake.
pub(crate) const WS_KEY_PER_HANDSHAKE: &str = "<generated per handshake>";

/// Connection-specific fields an HTTP/2 or HTTP/3 request does not carry
/// (the `Host` is sent as `:authority`), and the WebSocket key, which only
/// the HTTP/1.1 upgrade has (RFC 8441 §4).
const WS_NOT_ON_EXTENDED_CONNECT: &[&str] = &["host", "connection", "upgrade", "transfer-encoding", "keep-alive", "sec-websocket-key"];

/// The fields a gRPC call does not take from the request's headers (the
/// transport frames the body and sets the authority itself).
const GRPC_NOT_SENT: &[&str] = &["host", "connection", "transfer-encoding", "upgrade", "content-length", "keep-alive"];

/// The connection-specific fields an event stream over HTTP/2 or HTTP/3
/// does not send (the `Host` is sent as `:authority`).
const SSE_NOT_SENT_OVER_H2_H3: &[&str] = &["host", "connection", "transfer-encoding", "upgrade", "keep-alive"];

/// A request as it is sent, before auth is applied.
pub(crate) struct Shape {
    pub method: String,
    /// Where the request is sent. Auth signs for its HTTP counterpart
    /// (`wss` as `https`, `grpc` as `http`), as the session transports do.
    pub target: Target,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub content_type: Option<String>,
    /// Whether the request-target sent carries the query (a gRPC call's path
    /// has none).
    sends_query: bool,
    /// Whether an auth profile may rewrite the body (HTTP only: a session
    /// handshake or call cannot carry the rewritten body).
    body_rewritable: bool,
    /// Whether an auth profile may add query parameters (not to a gRPC
    /// call's fixed path).
    query_extendable: bool,
    /// Headers the transport sets after auth: `(name, value, replace)`. One
    /// that does not replace is added only when the request has none.
    transport: Vec<(String, String, bool)>,
    /// Lowercase names of the headers the transport leaves out.
    not_sent: &'static [&'static str],
    /// Whether the transport sends the authority as `Host` (HTTP/1.1).
    host_from_authority: bool,
}

fn local(kind: FailureKind, msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, kind, msg).with_field(field)
}

fn unsupported(msg: impl Into<String>, field: &str) -> TransportFailure {
    local(FailureKind::UnsupportedCombination, msg, field)
}

/// The URL schemes a request of `protocol` is sent with (the first is used
/// for a URL without one), as the send path and the sessions accept them.
/// Raw TCP and UDP send no HTTP request: the preview says it does not
/// support them rather than show a request that is never sent.
pub(crate) fn schemes(protocol: Protocol) -> Result<&'static [&'static str], TransportFailure> {
    match protocol {
        Protocol::Http | Protocol::Sse => Ok(&["https", "http"]),
        Protocol::WebSocket => Ok(&["wss", "ws"]),
        Protocol::Grpc => Ok(&["grpcs", "grpc", "https", "http"]),
        Protocol::Tcp => Err(unsupported(
            "preview not supported for raw TCP: the payloads are sent verbatim, with no HTTP request to preview",
            "protocol",
        )),
        Protocol::Udp => Err(unsupported(
            "preview not supported for UDP: the datagrams are sent verbatim, with no HTTP request to preview",
            "protocol",
        )),
    }
}

impl Shape {
    /// An HTTP request: sent as prepared.
    pub(crate) fn http(prep: &Prepared) -> Shape {
        Shape {
            method: prep.http.method.clone(),
            target: prep.http.target.clone(),
            headers: prep.http.headers.clone(),
            body: prep.http.body.clone(),
            content_type: prep.http.content_type.clone(),
            sends_query: true,
            body_rewritable: true,
            query_extendable: true,
            transport: vec![],
            not_sent: &[],
            host_from_authority: false,
        }
    }

    /// The handshake (WebSocket, SSE) or call (gRPC) of a session protocol,
    /// refused before traffic exactly where the session is.
    pub(crate) fn session(
        ctx: &ExecutionContext,
        r: &Resolver,
        prep: &Prepared,
        inferred: &mut Vec<String>,
    ) -> Result<Shape, TransportFailure> {
        if prep.settings.early_data.enabled {
            // The opt-in covers HTTP requests only; say so instead of ignoring it.
            inferred.push("0-RTT early data is not used for sessions: the early-data setting applies to HTTP requests only".into());
        }
        match ctx.spec.protocol {
            Protocol::WebSocket => websocket(ctx, r, prep, inferred),
            Protocol::Sse => event_stream(ctx, r, prep, inferred),
            Protocol::Grpc => grpc_call(ctx, r, prep, inferred),
            p => Err(schemes(p).err().unwrap_or_else(|| unsupported("HTTP is not a session protocol", "protocol"))),
        }
    }

    /// Why the session refuses what an auth profile applied, as it does
    /// before sending anything.
    pub(crate) fn auth_refusal(&self, applied: &anvil_auth::Applied) -> Option<String> {
        if applied.body.is_some() && !self.body_rewritable {
            return Some(format!("the auth profile '{}' rewrites the message body, which this protocol cannot carry", applied.label));
        }
        if !applied.append_query.is_empty() && !self.query_extendable {
            return Some("an auth profile that adds query parameters cannot be used with gRPC (the path is fixed)".into());
        }
        None
    }

    /// Apply what the transport does to the headers after auth: the fields
    /// it adds or replaces, and those it leaves out. `authority` is the one
    /// the request is sent with (and signed for).
    pub(crate) fn transport_headers(&self, headers: &mut Vec<(String, String)>, authority: &str) {
        headers.retain(|(n, _)| !self.not_sent.contains(&n.to_ascii_lowercase().as_str()));
        if self.host_from_authority {
            headers.push(("Host".into(), authority.to_string()));
        }
        for (name, value, replace) in &self.transport {
            let present = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
            if *replace {
                headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
            } else if present {
                continue;
            }
            headers.push((name.clone(), value.clone()));
        }
    }

    /// The URL the request is sent to, for `target` (with any query an auth
    /// profile added).
    pub(crate) fn url(&self, target: &Target) -> String {
        if self.sends_query { target.url() } else { format!("{}://{}{}", target.scheme, target.authority, target.path) }
    }
}

/// The WebSocket handshake: `GET` with an HTTP/1.1 upgrade, `CONNECT` with
/// `:protocol = websocket` over HTTP/2 and HTTP/3 (RFC 8441, RFC 9220).
fn websocket(ctx: &ExecutionContext, r: &Resolver, prep: &Prepared, inferred: &mut Vec<String>) -> Result<Shape, TransportFailure> {
    let spec = ctx.spec.websocket.as_ref();
    let bootstrap = spec.map(|s| s.bootstrap).unwrap_or(WsBootstrap::Http1Upgrade);
    let deflate = match spec {
        Some(s) => sessions::ws_deflate_offer(&ctx.spec, &s.permessage_deflate)?,
        None => None,
    };
    let mut headers = prep.http.headers.clone();
    if !sessions::has_explicit_header(&ctx.spec, "accept-encoding") {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept-encoding"));
        inferred.retain(|i| !i.starts_with("Accept-Encoding"));
    }
    for (i, m) in spec.map(|s| s.messages.as_slice()).unwrap_or_default().iter().enumerate() {
        let field = format!("websocket.messages[{i}]");
        match m {
            WsMessage::Text { text } => {
                r.resolve(text, &field)?;
            }
            WsMessage::Binary { hex } | WsMessage::Ping { hex } => {
                let hex = r.resolve(hex, &field)?;
                anvil_transport::session::decode_hex(&hex).map_err(|e| local(FailureKind::BodySerialization, e, &field))?;
            }
            WsMessage::Close { reason, .. } => {
                r.resolve(reason, &field)?;
            }
        }
    }
    let subprotocols = spec
        .map(|s| s.subprotocols.as_slice())
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(i, s)| r.resolve(s, &format!("websocket.subprotocols[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut transport = vec![("Sec-WebSocket-Version".to_string(), "13".to_string(), false)];
    if !subprotocols.is_empty() {
        transport.push(("Sec-WebSocket-Protocol".into(), subprotocols.join(", "), false));
    }
    if let Some(d) = &deflate {
        transport.push(("Sec-WebSocket-Extensions".into(), d.header_value(), false));
        inferred.push(format!("Sec-WebSocket-Extensions: {} (permessage-deflate offered, RFC 7692)", d.header_value()));
    }
    // Extended CONNECT (RFC 8441, RFC 9220) is sent, and so signed, as CONNECT.
    let (method, not_sent): (&str, &[&str]) = match bootstrap {
        WsBootstrap::Http1Upgrade => {
            transport.push(("Connection".into(), "Upgrade".into(), false));
            transport.push(("Upgrade".into(), "websocket".into(), false));
            transport.push(("Sec-WebSocket-Key".into(), WS_KEY_PER_HANDSHAKE.into(), false));
            ("GET", &[])
        }
        WsBootstrap::Http2ExtendedConnect | WsBootstrap::Http3ExtendedConnect => {
            transport.push(("User-Agent".into(), concat!("Ferrum-Anvil/", env!("CARGO_PKG_VERSION")).into(), false));
            let (version, rfc) = if bootstrap == WsBootstrap::Http2ExtendedConnect { ("HTTP/2", 8441) } else { ("HTTP/3", 9220) };
            inferred.push(format!("extended CONNECT over {version} with :protocol websocket (RFC {rfc}); the Host is sent as :authority"));
            ("CONNECT", WS_NOT_ON_EXTENDED_CONNECT)
        }
    };
    Ok(Shape {
        method: method.into(),
        target: prep.http.target.clone(),
        headers,
        body: Bytes::new(),
        content_type: None,
        sends_query: true,
        body_rewritable: false,
        query_extendable: true,
        transport,
        not_sent,
        host_from_authority: false,
    })
}

/// The request that opens an event stream: the request's method and body,
/// asking for `text/event-stream` without content coding.
fn event_stream(ctx: &ExecutionContext, r: &Resolver, prep: &Prepared, inferred: &mut Vec<String>) -> Result<Shape, TransportFailure> {
    if let Some(f) = sse::version_unsupported(prep.settings.http_version, prep.http.target.scheme == "https", prep.proxy.is_some()) {
        return Err(f);
    }
    let mut headers = prep.http.headers.clone();
    if !sessions::has_explicit_header(&ctx.spec, "accept") {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept"));
    }
    if !sessions::has_explicit_header(&ctx.spec, "accept-encoding") {
        // Events are parsed incrementally; ask for an unencoded stream.
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept-encoding"));
        headers.push(("Accept-Encoding".into(), "identity".into()));
        inferred.retain(|i| !i.starts_with("Accept-Encoding"));
        inferred.push("Accept-Encoding: identity (events are parsed as they arrive)".into());
    }
    let sse_spec = ctx.spec.sse.as_ref();
    let last_event_id = sse_spec.and_then(|s| s.last_event_id.as_ref()).map(|v| r.resolve(v, "sse.last_event_id")).transpose()?;
    if last_event_id.as_deref().is_some_and(|id| HeaderValue::from_str(id).is_err()) {
        return Err(local(
            FailureKind::InvalidHeader,
            "sse.last_event_id resolves to a value that is not a valid Last-Event-ID header value (it holds a line break or control character); the request was not sent",
            "sse.last_event_id",
        ));
    }
    let mut transport =
        vec![("Accept".to_string(), "text/event-stream".to_string(), true), ("Cache-Control".to_string(), "no-cache".to_string(), false)];
    if let Some(id) = last_event_id {
        transport.push(("Last-Event-ID".into(), id, true));
    }
    // Where the version policy leaves no choice of HTTP/2 or HTTP/3.
    let h2_or_h3 =
        matches!(prep.settings.http_version, HttpVersionPolicy::H2c | HttpVersionPolicy::Http2Only | HttpVersionPolicy::Http3Only);
    Ok(Shape {
        method: prep.http.method.clone(),
        target: prep.http.target.clone(),
        headers,
        body: prep.http.body.clone(),
        content_type: prep.http.content_type.clone(),
        sends_query: true,
        body_rewritable: false,
        query_extendable: true,
        transport,
        not_sent: if h2_or_h3 { SSE_NOT_SENT_OVER_H2_H3 } else { &[] },
        host_from_authority: false,
    })
}

/// A gRPC or gRPC-Web call: `POST` to the method's path under the URL's
/// path, with the framed request message of a unary or server-streaming
/// call as its body.
fn grpc_call(ctx: &ExecutionContext, r: &Resolver, prep: &Prepared, inferred: &mut Vec<String>) -> Result<Shape, TransportFailure> {
    let Some(spec) = ctx.spec.grpc.clone() else {
        return Err(local(FailureKind::BodySerialization, "a gRPC request needs a service, method and schema", "grpc"));
    };
    let version = prep.settings.http_version;
    let target = &prep.http.target;
    let tls_url = matches!(target.scheme.as_str(), "grpcs" | "https");
    let reflection = matches!(spec.schema, GrpcSchemaSource::Reflection);
    if let Some((msg, field)) = grpc::unsupported_combination(spec.wire, spec.mode, reflection, version, tls_url, prep.proxy.is_some()) {
        return Err(unsupported(msg, field));
    }
    if spec.plaintext && tls_url {
        return Err(unsupported("plaintext (h2c) was selected for a TLS URL; use grpc:// or http:// for h2c", "grpc.plaintext"));
    }
    // Whether the call is known to go over HTTP/1.1 (gRPC-Web only), which
    // sends the authority as `Host`.
    let mut http1 = false;
    if spec.wire.is_web() {
        inferred.push(format!(
            "gRPC-Web ({}): unary and server streaming only; the status is read from the trailer frame at the end of the response body",
            if spec.wire == GrpcWire::GrpcWebText { "text, base64 in both directions" } else { "binary" }
        ));
        let h2_or_h3 = matches!(version, HttpVersionPolicy::H2c | HttpVersionPolicy::Http3Only | HttpVersionPolicy::Http3WithFallback);
        http1 = version == HttpVersionPolicy::Http1Only || (!tls_url && !h2_or_h3);
        inferred.push(
            match (version, tls_url) {
                (HttpVersionPolicy::Http1Only, _) => "gRPC-Web over HTTP/1.1",
                (HttpVersionPolicy::Http2Only, _) => "gRPC-Web over HTTP/2 (ALPN h2 only)",
                (HttpVersionPolicy::H2c, _) => "gRPC-Web over cleartext HTTP/2 with prior knowledge (h2c)",
                (HttpVersionPolicy::Http3Only | HttpVersionPolicy::Http3WithFallback, _) => "gRPC-Web over HTTP/3",
                (_, true) => "gRPC-Web over TLS: ALPN offers h2 and http/1.1; the negotiated protocol is used",
                (_, false) => "cleartext gRPC-Web uses HTTP/1.1",
            }
            .into(),
        );
    } else if !tls_url {
        inferred.push("cleartext gRPC uses HTTP/2 with prior knowledge (h2c)".into());
    }
    let service = r.resolve(&spec.service, "grpc.service")?;
    let method_name = r.resolve(&spec.method, "grpc.method")?;
    let messages =
        spec.messages.iter().enumerate().map(|(i, m)| r.resolve(m, &format!("grpc.messages[{i}]"))).collect::<Result<Vec<_>, _>>()?;
    let single = matches!(spec.mode, GrpcMode::Unary | GrpcMode::ServerStreaming);
    // Loading a local schema reads attachments only; it never waits.
    let mut body = Bytes::new();
    match sessions::load_schema(ctx, &spec).now_or_never().transpose()? {
        Some(grpc::Schema::Pool(pool)) => {
            let m = grpc::resolve_method(&pool, &service, &method_name, spec.mode)?;
            for (i, j) in messages.iter().enumerate() {
                let enc =
                    grpc::encode_json(&m.input(), j).map_err(|e| local(FailureKind::BodySerialization, e, &format!("grpc.messages[{i}]")))?;
                if single {
                    // The exact bytes sent (and signed).
                    body = match spec.wire {
                        GrpcWire::GrpcWebText => anvil_transport::grpc_web::encode_text(&grpc::frame(&enc)),
                        _ => grpc::frame(&enc),
                    };
                }
            }
            if single && messages.len() > 1 {
                return Err(local(
                    FailureKind::BodySerialization,
                    format!("a {:?} call sends exactly one request message", spec.mode),
                    "grpc.messages",
                ));
            }
            if !single {
                inferred.push("the request messages are streamed once the call is open; the body shown is empty".into());
            }
        }
        Some(grpc::Schema::Reflection) => {
            inferred.push("server reflection: the request message is encoded when the call is sent; the body shown is empty".into())
        }
        None => inferred.push("the gRPC schema is loaded when the call is sent; the body shown is empty".into()),
    }
    // Metadata: request headers + gRPC metadata entries; HTTP content negotiation headers do not apply.
    let mut headers: Vec<(String, String)> = prep
        .http
        .headers
        .iter()
        .filter(|(n, _)| !matches!(n.to_ascii_lowercase().as_str(), "accept" | "accept-encoding" | "content-type" | "user-agent"))
        .cloned()
        .collect();
    if sessions::has_explicit_header(&ctx.spec, "user-agent")
        && let Some(ua) = prep.http.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("user-agent"))
    {
        headers.push(ua.clone());
    }
    inferred.retain(|i| !i.starts_with("Accept-Encoding") && !i.starts_with("User-Agent") && !i.starts_with("Content-Type"));
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
    let content_type = match spec.wire {
        GrpcWire::Grpc => "application/grpc",
        GrpcWire::GrpcWeb => anvil_transport::grpc_web::CT_BINARY,
        GrpcWire::GrpcWebText => anvil_transport::grpc_web::CT_TEXT,
    };
    let mut transport = vec![("content-type".to_string(), content_type.to_string(), true)];
    if spec.wire.is_web() {
        // PROTOCOL-WEB: the response mode follows Accept; ask for the request's own.
        transport.push(("accept".into(), content_type.into(), true));
        transport.push(("x-grpc-web".into(), "1".into(), true));
    } else {
        transport.push(("te".into(), "trailers".into(), true));
    }
    transport.push(("user-agent".into(), concat!("grpc-anvil/", env!("CARGO_PKG_VERSION")).into(), false));
    if let Some(ms) = spec.deadline_ms {
        transport.push(("grpc-timeout".into(), grpc::grpc_timeout(ms), true));
    }
    let prefix = target.path.trim_end_matches('/');
    Ok(Shape {
        method: "POST".into(),
        target: Target { path: format!("{prefix}/{service}/{method_name}"), ..target.clone() },
        headers,
        body,
        content_type: Some(content_type.into()),
        sends_query: false,
        body_rewritable: false,
        query_extendable: false,
        transport,
        not_sent: GRPC_NOT_SENT,
        host_from_authority: http1,
    })
}
