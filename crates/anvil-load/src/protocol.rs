//! Per-protocol load units (LOAD-013).
//!
//! Every plan step is one `Engine::execute` call — the same preparation,
//! auth, TLS, proxy and DNS path as a manual Send — and produces one *unit*
//! of the plan's [`LoadUnitKind`]: an HTTP request, a unary,
//! server-streaming, client-streaming or bidirectional gRPC call, an SSE
//! stream, a WebSocket session, a TCP exchange or a UDP/DTLS exchange. A plan has exactly one unit kind, so
//! every count and latency in its report has a single denominator.
//!
//! Client-streaming and bidirectional gRPC calls are units of their own: a
//! load run uses the automation path, which sends the request's scripted
//! messages, half-closes and reads until the terminal status, so the call
//! has one defined completion. UDP and DTLS exchanges through a MASQUE or
//! HBONE proxy open one tunnel per exchange, counted in the datagram block's
//! tunnel denominators.
//!
//! Combinations without a defined unit are refused with a typed
//! [`Refusal`] before any traffic — never emulated:
//! * mixed unit kinds in one chain or mix;
//! * datagram exchanges that mix direct sends and tunnels, or two kinds of
//!   tunnel (the tunnel denominators would cover only part of the units);
//! * gRPC with server reflection as the schema source (every call would
//!   first run a reflection RPC, so a unit would not be one call);
//! * a gRPC call the engine refuses on every send (gRPC-Web with client or
//!   bidirectional streaming, or a wire/HTTP version/TLS/proxy combination
//!   that cannot be sent), found by the engine's own check;
//! * UDP or DTLS through a MASQUE proxy while a proxy profile routes the
//!   request (the proxy's QUIC connection cannot go through it, so the
//!   engine refuses every exchange);
//! * SSE with automatic reconnection (one unit would become several
//!   connections with server-chosen delays);
//! * a mesh HBONE proxy with persistent connections for HTTP and gRPC
//!   (tunnels are never pooled, so the mode could not be honoured).

use anvil_domain::Id;
use anvil_domain::execution::TunnelKind;
use anvil_domain::load::{ConnectionMode, LoadUnitKind, UnitSemantics};
use anvil_domain::request::{Body, GrpcMode, GrpcSchemaSource, Protocol, TcpFraming};
use anvil_domain::tls::{ProxyKind, ProxyProfile};
use anvil_engine::ExecutionContext;
use anvil_engine::prepare::Target;
use serde::{Deserialize, Serialize};

/// Why a plan cannot be load tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    /// The chain or mix produces more than one unit kind.
    MixedUnitKinds,
    /// Datagram exchanges that mix direct sends with tunnels, or a MASQUE
    /// tunnel with an HBONE tunnel.
    MixedTunnels,
    /// gRPC with server reflection as the schema source.
    GrpcReflection,
    /// A gRPC call the engine refuses before every send: gRPC-Web with
    /// client or bidirectional streaming, or a wire, HTTP version, TLS and
    /// proxy combination that cannot be sent.
    GrpcUnsupportedCombination,
    /// UDP or DTLS through a MASQUE proxy while a proxy profile routes the
    /// request: the MASQUE proxy's QUIC connection cannot go through it.
    MasqueThroughProxy,
    /// SSE with automatic reconnection enabled.
    SseReconnect,
    /// A mesh HBONE proxy with the persistent connection mode (HTTP, gRPC).
    HbonePersistent,
    /// The request enables 0-RTT early data.
    EarlyData,
    /// The request lacks what its protocol needs (e.g. a gRPC method).
    IncompleteRequest,
    /// An MCP request: its load unit (one session's handshake and call) is
    /// not defined yet.
    McpUnsupported,
}

/// A typed refusal, raised before any traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub code: RefusalCode,
    /// The request that caused it, when one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Id>,
    pub message: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = serde_json::to_value(self.code).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        write!(f, "{} (LOAD-013 {code})", self.message)
    }
}

/// What one plan step produces, with the request settings the load metrics
/// need to classify its units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepUnit {
    pub kind: LoadUnitKind,
    /// TCP: the request's `expect_frames`, when it has a framing preset.
    pub tcp_expect_frames: Option<u32>,
    /// WebSocket: `expect_messages` (> 0 defines round-trip pairing).
    pub ws_expect_messages: u32,
    /// HTTP: the request is SOAP or GraphQL, whose application outcome is
    /// read from the response body (a fault or error arrives with a 2xx).
    pub application_from_body: bool,
    /// UDP/DTLS: the tunnel every exchange opens (MASQUE CONNECT-UDP or
    /// mesh HBONE); `None` for direct datagrams and other protocols.
    pub tunnel: Option<TunnelKind>,
}

impl StepUnit {
    fn of(kind: LoadUnitKind) -> Self {
        StepUnit { kind, tcp_expect_frames: None, ws_expect_messages: 0, application_from_body: false, tunnel: None }
    }
}

/// Short plural label, e.g. `WebSocket sessions`.
pub fn label(kind: LoadUnitKind) -> &'static str {
    match kind {
        LoadUnitKind::HttpRequest => "HTTP requests",
        LoadUnitKind::GrpcCall => "unary gRPC calls",
        LoadUnitKind::GrpcStream => "server-streaming gRPC streams",
        LoadUnitKind::GrpcClientStream => "client-streaming gRPC calls",
        LoadUnitKind::GrpcBidiStream => "bidirectional gRPC streams",
        LoadUnitKind::SseStream => "SSE streams",
        LoadUnitKind::WebsocketSession => "WebSocket sessions",
        LoadUnitKind::TcpExchange => "TCP/TLS exchanges",
        LoadUnitKind::UdpExchange => "UDP exchanges",
        LoadUnitKind::DtlsExchange => "DTLS exchanges",
    }
}

/// Whether the engine sends the request through a mesh HBONE proxy: the
/// selected profile is HBONE and its `NO_PROXY` list does not bypass the
/// target. A URL that does not resolve is never tunneled; every send then
/// fails on the URL itself.
fn is_hbone(id: Option<Id>, ctx: &ExecutionContext, protocol: Protocol) -> Result<bool, Refusal> {
    // Without a selected HBONE profile the answer does not depend on the URL.
    let selected = anvil_engine::settings::resolve(&ctx.settings_layers).proxy_profile_id;
    if !ctx.proxy_profiles.iter().any(|p| Some(p.id) == selected && p.kind == ProxyKind::Hbone) {
        return Ok(false);
    }
    Ok(send_route(id, ctx, protocol)?.and_then(|(_, p)| p).is_some_and(|p| p.kind == ProxyKind::Hbone))
}

fn uses_dtls(id: Option<Id>, ctx: &ExecutionContext) -> Result<bool, Refusal> {
    if ctx.spec.udp.as_ref().is_some_and(|u| u.dtls) {
        return Ok(true);
    }
    // The scheme may come from a variable; resolve with the context's own layers.
    let url = send_url(id, ctx)?.unwrap_or_else(|| ctx.spec.url.clone());
    Ok(url.trim().to_ascii_lowercase().starts_with("dtls://"))
}

const DEFERRED_URL: &str = "the request URL uses a vault variable that resolves only when the request is sent (after its OAuth token endpoint is validated), so this plan cannot be classified before traffic; use a non-vault variable for the URL";

/// The request URL from a throwaway resolver; `None` when it does not
/// resolve. A vault variable whose credential resolves only after its OAuth
/// token endpoint is validated has no value here: a classification that
/// depends on it is refused rather than judged from a stand-in.
fn send_url(id: Option<Id>, ctx: &ExecutionContext) -> Result<Option<String>, Refusal> {
    match anvil_engine::vars::Resolver::new(ctx.var_layers.clone(), None).resolve(&ctx.spec.url, "url") {
        Ok(url) => Ok(Some(url)),
        Err(failure) if anvil_engine::vars::is_deferred_secret(&failure) => {
            Err(Refusal { code: RefusalCode::IncompleteRequest, request_id: id, message: DEFERRED_URL.into() })
        }
        Err(_) => Ok(None),
    }
}

/// The request's resolved target and the proxy profile the engine's
/// preparation routes it through (`NO_PROXY` applied), from a throwaway
/// resolver. `None` when the URL does not resolve or parse: every send then
/// fails on the URL itself.
fn send_route(id: Option<Id>, ctx: &ExecutionContext, protocol: Protocol) -> Result<Option<(Target, Option<&ProxyProfile>)>, Refusal> {
    Ok(send_url(id, ctx)?.and_then(|url| route(ctx, &url, protocol)))
}

/// The URL schemes the engine sends a request of `protocol` with (the first
/// is used for a URL without one).
pub fn send_schemes(protocol: Protocol) -> &'static [&'static str] {
    match protocol {
        Protocol::Http | Protocol::Sse | Protocol::Mcp => &["https", "http"],
        Protocol::WebSocket => &["wss", "ws"],
        Protocol::Grpc => &["grpcs", "grpc", "https", "http"],
        Protocol::Tcp => &["tcp", "tls"],
        Protocol::Udp => &["udp", "dtls"],
    }
}

/// The target of an already resolved `url` for a request of `protocol`,
/// and the proxy profile the engine's preparation routes it through: the
/// selected profile, unless its `NO_PROXY` list bypasses the target's host
/// and port. `None` when the URL does not parse: every send then fails on
/// the URL itself.
pub fn route<'a>(ctx: &'a ExecutionContext, url: &str, protocol: Protocol) -> Option<(Target, Option<&'a ProxyProfile>)> {
    let target = anvil_engine::prepare::parse_target(url, send_schemes(protocol), &mut Vec::new()).ok()?;
    let proxy = anvil_engine::settings::resolve(&ctx.settings_layers)
        .proxy_profile_id
        .and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id))
        .filter(|p| !anvil_transport::net::no_proxy_matches(&p.no_proxy, &target.host, target.port));
    Some((target, proxy))
}

/// Classify one request, or refuse it.
pub fn classify(id: Option<Id>, ctx: &ExecutionContext, mode: ConnectionMode) -> Result<StepUnit, Refusal> {
    let refuse = |code: RefusalCode, message: String| Err(Refusal { code, request_id: id, message });
    if anvil_engine::settings::resolve(&ctx.settings_layers).early_data.enabled {
        // Early-data handshakes of one session-ticket context are serialized
        // (their evidence is per connection), which would distort a load
        // measurement; the report has no early-data denominators either.
        return refuse(
            RefusalCode::EarlyData,
            "the request enables 0-RTT early data, which load runs do not support (handshakes that share session tickets are serialized and the report does not count early data); turn early data off for the requests of this plan".into(),
        );
    }
    let hbone_persistent =
        |protocol: Protocol| -> Result<bool, Refusal> { Ok(mode == ConnectionMode::Persistent && is_hbone(id, ctx, protocol)?) };
    let hbone_msg = |what: &str| {
        format!(
            "{what} through a mesh HBONE proxy cannot use the persistent connection mode: an HBONE tunnel carries one execution's identity and headers and is never pooled, so every unit would open its own tunnel. Choose the fresh connection mode, which is what would happen"
        )
    };
    match ctx.spec.protocol {
        Protocol::Http => {
            if hbone_persistent(Protocol::Http)? {
                return refuse(RefusalCode::HbonePersistent, hbone_msg("HTTP requests"));
            }
            let application_from_body = matches!(ctx.spec.body, Body::Soap { .. } | Body::GraphQl { .. });
            Ok(StepUnit { application_from_body, ..StepUnit::of(LoadUnitKind::HttpRequest) })
        }
        Protocol::Grpc => {
            let Some(g) = &ctx.spec.grpc else {
                // The engine refuses this per send; a load run has no unit for it.
                return refuse(RefusalCode::IncompleteRequest, "the gRPC request has no service, method or schema".into());
            };
            // Client and bidirectional streams run the automation path: the
            // scripted messages, a half-close, then reading until the
            // terminal status, so every mode has one defined completion.
            let kind = grpc_unit(g.mode);
            if matches!(g.schema, GrpcSchemaSource::Reflection) {
                return refuse(
                    RefusalCode::GrpcReflection,
                    "gRPC load needs a local schema: with server reflection every call would first run a reflection RPC, so one unit would not be one call. Import the .proto files or a descriptor set".into(),
                );
            }
            // The engine's own pre-traffic check, with the inputs its
            // preparation uses: a call it refuses fails every unit.
            if let Some((target, proxy)) = send_route(id, ctx, Protocol::Grpc)? {
                let version = anvil_engine::settings::resolve(&ctx.settings_layers).http_version;
                let tls = matches!(target.scheme.as_str(), "grpcs" | "https");
                let refused = anvil_transport::grpc::unsupported_combination(g.wire, g.mode, false, version, tls, proxy.is_some());
                if let Some((why, _)) = refused {
                    return refuse(
                        RefusalCode::GrpcUnsupportedCombination,
                        format!("this gRPC call cannot be load tested because the engine refuses it before every send: {why}"),
                    );
                }
            }
            if hbone_persistent(Protocol::Grpc)? {
                return refuse(RefusalCode::HbonePersistent, hbone_msg("gRPC calls"));
            }
            Ok(StepUnit::of(kind))
        }
        Protocol::Sse => {
            if ctx.spec.sse.as_ref().is_some_and(|s| s.reconnect) {
                return refuse(
                    RefusalCode::SseReconnect,
                    "SSE with automatic reconnection cannot be load tested: one stream would become several connections with server-chosen delays. Turn reconnection off; each stream is then one unit".into(),
                );
            }
            Ok(StepUnit::of(LoadUnitKind::SseStream))
        }
        Protocol::Mcp => refuse(
            RefusalCode::McpUnsupported,
            "MCP requests cannot be load tested yet: one execution is a session (initialize, the call, the close), and there is no MCP load unit to count it as. Load test the endpoint's HTTP requests instead".into(),
        ),
        Protocol::WebSocket => Ok(StepUnit {
            ws_expect_messages: ctx.spec.websocket.as_ref().map(|w| w.expect_messages).unwrap_or(0),
            ..StepUnit::of(LoadUnitKind::WebsocketSession)
        }),
        Protocol::Tcp => {
            let tcp = ctx.spec.tcp.as_ref();
            let expect = tcp.filter(|t| t.framing != TcpFraming::None && t.expect_frames > 0).map(|t| t.expect_frames);
            Ok(StepUnit { tcp_expect_frames: expect, ..StepUnit::of(LoadUnitKind::TcpExchange) })
        }
        Protocol::Udp => {
            // A MASQUE tunnel is part of the request; an HBONE one comes from
            // the selected proxy profile. Either way every exchange opens its
            // own tunnel, counted in the tunnel denominators.
            let masque = ctx.spec.udp.as_ref().is_some_and(|u| u.masque.is_some());
            if masque && let Some((_, Some(p))) = send_route(id, ctx, Protocol::Udp)? {
                return refuse(
                    RefusalCode::MasqueThroughProxy,
                    format!(
                        "UDP through a MASQUE proxy cannot also go through the proxy profile '{}': the MASQUE proxy is reached over QUIC, which HTTP CONNECT, SOCKS5 and HBONE tunnels do not carry, so the engine would refuse every exchange. Clear the proxy selection for this request or add its target to the profile's NO_PROXY list",
                        p.name
                    ),
                );
            }
            let tunnel = if masque {
                Some(TunnelKind::ConnectUdp)
            } else if is_hbone(id, ctx, Protocol::Udp)? {
                Some(TunnelKind::Hbone)
            } else {
                None
            };
            let kind = if uses_dtls(id, ctx)? { LoadUnitKind::DtlsExchange } else { LoadUnitKind::UdpExchange };
            Ok(StepUnit { tunnel, ..StepUnit::of(kind) })
        }
    }
}

/// Classify every step of a plan (in plan order) and require one unit kind.
pub fn classify_plan<'a>(
    steps: impl IntoIterator<Item = (Id, &'a ExecutionContext)>,
    mode: ConnectionMode,
) -> Result<(LoadUnitKind, Vec<StepUnit>), Refusal> {
    let mut units: Vec<StepUnit> = Vec::new();
    let mut ids: Vec<Id> = Vec::new();
    for (id, ctx) in steps {
        units.push(classify(Some(id), ctx, mode)?);
        ids.push(id);
    }
    let Some(first) = units.first().map(|u| u.kind) else {
        return Ok((LoadUnitKind::HttpRequest, units));
    };
    if let Some(other) = units.iter().find(|u| u.kind != first) {
        return Err(Refusal {
            code: RefusalCode::MixedUnitKinds,
            request_id: None,
            message: format!(
                "a load plan measures one kind of unit, and this one mixes {} with {}: their counts and latencies have different denominators. Split the plan per protocol",
                label(first),
                label(other.kind)
            ),
        });
    }
    let tunnel = units[0].tunnel;
    if let Some((i, other)) = units.iter().enumerate().find(|(_, u)| u.tunnel != tunnel) {
        return Err(Refusal {
            code: RefusalCode::MixedTunnels,
            request_id: ids.get(i).copied(),
            message: format!(
                "a load plan's datagram exchanges must all take the same path, and this one mixes {} with {}: the tunnel counts would cover only part of the exchanges, and a tunnel's setup changes what an exchange costs. Split the plan per path",
                path_label(tunnel),
                path_label(other.tunnel)
            ),
        });
    }
    Ok((first, units))
}

fn grpc_unit(mode: GrpcMode) -> LoadUnitKind {
    match mode {
        GrpcMode::Unary => LoadUnitKind::GrpcCall,
        GrpcMode::ServerStreaming => LoadUnitKind::GrpcStream,
        GrpcMode::ClientStreaming => LoadUnitKind::GrpcClientStream,
        GrpcMode::Bidirectional => LoadUnitKind::GrpcBidiStream,
    }
}

fn path_label(t: Option<TunnelKind>) -> &'static str {
    match t {
        None => "direct datagrams",
        Some(TunnelKind::ConnectUdp) => "a MASQUE (CONNECT-UDP) tunnel",
        Some(TunnelKind::Hbone) => "an HBONE datagram tunnel",
    }
}

/// The definitions reported with every run of this unit kind.
pub fn semantics(kind: LoadUnitKind, mode: ConnectionMode) -> UnitSemantics {
    let persistent = mode == ConnectionMode::Persistent;
    let own_connection = |what: &str| format!("Each {what} opens its own connection; the plan's connection mode does not apply to it.");
    let s = |a: &str, b: &str, c: &str, d: &str, e: &str, f: String| UnitSemantics {
        unit_singular: a.into(),
        unit_plural: b.into(),
        completed_means: c.into(),
        success_means: d.into(),
        latency_means: e.into(),
        connection_mode_means: f,
    };
    let grpc_conn = if persistent {
        "Persistent: each virtual user reuses one pooled channel per destination — a multiplexed HTTP/2 or HTTP/3 connection (HTTP/1.1 for gRPC-Web over HTTP/1.1, one call at a time). A channel the peer closed is replaced by a new connection.".to_string()
    } else {
        "Fresh: every call opens its own connection (and TLS or QUIC handshake).".to_string()
    };
    match kind {
        LoadUnitKind::HttpRequest => s(
            "request",
            "requests",
            "A complete HTTP response was received (any status). Redirects, retries and an HTTP/3 → TCP fallback are attempts inside the request, not extra requests.",
            "Completed with an application success (status below 400; for SOAP and GraphQL, no fault or error in the complete response body) and every assertion passing.",
            "Sum of the request's attempt durations (connect … last body byte), fallback attempts included.",
            if persistent {
                "Persistent: each virtual user keeps pooled connections (HTTP/1.1 keep-alive, one multiplexed HTTP/2 or HTTP/3 connection per origin).".into()
            } else {
                "Fresh: every request opens a new connection (and TLS or QUIC handshake).".into()
            },
        ),
        LoadUnitKind::GrpcCall => s(
            "call",
            "calls",
            "A terminal grpc-status arrived with complete framing (any code). A call that got a response but no status is incomplete, never completed.",
            "Completed with grpc-status 0 (OK) and every assertion passing. HTTP 200 alone is never a success.",
            "Sum of the call's attempt durations (connection or channel checkout … terminal status).",
            grpc_conn,
        ),
        LoadUnitKind::GrpcStream => s(
            "stream",
            "streams",
            "The server ended the stream with a terminal grpc-status and complete framing (any code).",
            "Completed with grpc-status 0 (OK) and every assertion passing.",
            "Stream duration: call start … terminal status, connection setup included. Time to first message is reported separately.",
            grpc_conn,
        ),
        LoadUnitKind::GrpcClientStream => s(
            "call",
            "calls",
            "The request's scripted messages were sent, the client stream was half-closed, and the server answered with a terminal grpc-status and complete framing (any code).",
            "Completed with grpc-status 0 (OK) and every assertion passing.",
            "Call duration: call start … terminal status, connection setup and sending the scripted messages included. Time to the response message is reported separately.",
            grpc_conn,
        ),
        LoadUnitKind::GrpcBidiStream => s(
            "stream",
            "streams",
            "The request's scripted messages were sent and the client stream was half-closed, and the server ended the stream with a terminal grpc-status and complete framing (any code).",
            "Completed with grpc-status 0 (OK) and every assertion passing.",
            "Stream duration: call start … terminal status, connection setup included. Time to first message is reported separately; no round trip is claimed, because a server message is not paired with a sent one.",
            grpc_conn,
        ),
        LoadUnitKind::SseStream => s(
            "stream",
            "streams",
            "The response arrived and the stream ended without a failure: the server ended it, or a stop condition of the request was reached (max_events, idle timeout). An error status completes as an application failure.",
            "Completed as a 2xx event stream with every assertion passing.",
            "Stream duration: request start … end of the stream, connection setup included. Time to first event is reported separately.",
            own_connection("stream"),
        ),
        LoadUnitKind::WebsocketSession => s(
            "session",
            "sessions",
            "The handshake was answered and the session ended without a failure: a close handshake by either side, the request's expect_messages, or its idle close. A rejected handshake completes as an application failure.",
            "Completed with an accepted handshake, a normal close (1000, 1001 or none) and every assertion passing.",
            "Session duration: connect … close. Round-trip times are reported separately, and only when the request defines expect_messages.",
            own_connection("session"),
        ),
        LoadUnitKind::TcpExchange => s(
            "exchange",
            "exchanges",
            "The connection was set up, the request's frames were sent and reading stopped on a stop condition (expected frames, max bytes, read-idle or the peer's close) without a failure.",
            "Completed, the expected frames arrived (when the request sets expect_frames with a framing preset) and every assertion passed. Fewer frames count as an application failure.",
            "Exchange duration: connect … end of reading. It includes the read-idle wait when the exchange ends on idle.",
            own_connection("exchange"),
        ),
        LoadUnitKind::UdpExchange | LoadUnitKind::DtlsExchange => s(
            "exchange",
            "exchanges",
            if kind == LoadUnitKind::DtlsExchange {
                "The DTLS handshake completed, the request's datagrams were sent and the response window elapsed (or max_datagrams arrived) without a local failure. Completion says nothing about delivery."
            } else {
                "The request's datagrams were sent and the response window elapsed (or max_datagrams arrived) without a local failure. Completion says nothing about delivery."
            },
            "Completed with at least one datagram received and every assertion passing. A completed exchange with nothing received is 'no response observed': neither a success nor a failure.",
            "Time to first response: first datagram sent → first datagram received in the same exchange. It is not attributed to a specific datagram; exchanges without a response have none.",
            if kind == LoadUnitKind::DtlsExchange {
                "Each exchange uses its own socket and DTLS handshake; the plan's connection mode does not apply to it.".into()
            } else {
                "Each exchange uses its own socket; the plan's connection mode does not apply to it.".into()
            },
        ),
    }
}

/// [`semantics`] for a classified plan: datagram exchanges through a tunnel
/// say that each exchange opens its own tunnel.
pub fn plan_semantics(kind: LoadUnitKind, mode: ConnectionMode, steps: &[StepUnit]) -> UnitSemantics {
    let mut s = semantics(kind, mode);
    if let Some(t) = steps.first().and_then(|u| u.tunnel) {
        let (what, how) = match t {
            TunnelKind::ConnectUdp => ("MASQUE (CONNECT-UDP) tunnel", "a QUIC connection to the proxy and an extended CONNECT"),
            TunnelKind::Hbone => ("HBONE datagram tunnel", "an mTLS connection to the mesh endpoint and an HTTP/2 CONNECT"),
        };
        s.connection_mode_means = format!(
            "Each exchange opens its own {what} ({how}){}, never pooled; the plan's connection mode does not apply to it. Tunnel setup is counted separately and is not part of the time to first response.",
            if kind == LoadUnitKind::DtlsExchange { " and runs its DTLS handshake inside it" } else { "" }
        );
        s.completed_means.push_str(
            " A tunnel that does not open (refused by the proxy, or failed) leaves the exchange incomplete: a transport failure, never an exchange with no response observed.",
        );
    }
    s
}

/// Best-effort unit kind of a request spec, without refusals (for labels, e.g.
/// a crash report whose worker never announced its run).
pub fn unit_of_spec(spec: &anvil_domain::request::RequestSpec) -> LoadUnitKind {
    match spec.protocol {
        // An MCP request is refused for load; its exchanges are HTTP requests.
        Protocol::Http | Protocol::Mcp => LoadUnitKind::HttpRequest,
        Protocol::Grpc => grpc_unit(spec.grpc.as_ref().map(|g| g.mode).unwrap_or_default()),
        Protocol::Sse => LoadUnitKind::SseStream,
        Protocol::WebSocket => LoadUnitKind::WebsocketSession,
        Protocol::Tcp => LoadUnitKind::TcpExchange,
        Protocol::Udp if spec.udp.as_ref().is_some_and(|u| u.dtls) || spec.url.trim().to_ascii_lowercase().starts_with("dtls://") => {
            LoadUnitKind::DtlsExchange
        }
        Protocol::Udp => LoadUnitKind::UdpExchange,
    }
}

/// Whether the plan's connection mode changes how units connect.
pub fn connection_mode_applies(kind: LoadUnitKind) -> bool {
    matches!(
        kind,
        LoadUnitKind::HttpRequest
            | LoadUnitKind::GrpcCall
            | LoadUnitKind::GrpcStream
            | LoadUnitKind::GrpcClientStream
            | LoadUnitKind::GrpcBidiStream
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MCP load units are a follow-up: a plan with an MCP request is refused
    /// before any traffic, with its own code.
    #[test]
    fn an_mcp_request_is_refused_for_load() {
        let mut spec = anvil_domain::request::RequestSpec::http("POST", "http://127.0.0.1:9/mcp");
        spec.protocol = Protocol::Mcp;
        let ctx = ExecutionContext::standalone(spec);
        let r = classify(None, &ctx, ConnectionMode::Persistent).unwrap_err();
        assert_eq!(r.code, RefusalCode::McpUnsupported);
        assert!(r.to_string().contains("(LOAD-013 mcp_unsupported)"), "{r}");
        assert_eq!(send_schemes(Protocol::Mcp), ["https", "http"]);
    }

    /// A vault variable deferred until an OAuth token endpoint is validated
    /// has no value here: a unit that depends on the URL is refused rather
    /// than judged from a stand-in, and one that does not is unaffected.
    #[test]
    fn a_deferred_vault_url_is_refused_only_where_the_unit_depends_on_it() {
        use anvil_engine::vars::{DEFERRED_SECRET_VALUE, VarEntry, VarLayer};
        let target = VarEntry { name: "target".into(), value: DEFERRED_SECRET_VALUE.into(), secret: true };
        let mut spec = anvil_domain::request::RequestSpec::http("GET", "{{target}}");
        spec.protocol = Protocol::Udp;
        let mut ctx = ExecutionContext::standalone(spec);
        ctx.var_layers.push(VarLayer { label: "workspace".into(), vars: vec![target] });
        let r = classify(None, &ctx, ConnectionMode::Fresh).unwrap_err();
        assert_eq!(r.code, RefusalCode::IncompleteRequest);
        assert!(r.message.contains("vault variable"), "{r}");
        ctx.spec.protocol = Protocol::Http;
        assert_eq!(classify(None, &ctx, ConnectionMode::Persistent).unwrap().kind, LoadUnitKind::HttpRequest);
    }
}
