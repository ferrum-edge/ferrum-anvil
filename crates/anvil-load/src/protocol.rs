//! Per-protocol load units (LOAD-013).
//!
//! Every plan step is one `Engine::execute` call — the same preparation,
//! auth, TLS, proxy and DNS path as a manual Send — and produces one *unit*
//! of the plan's [`LoadUnitKind`]: an HTTP request, a unary gRPC call, a
//! server-streaming gRPC call, an SSE stream, a WebSocket session, a TCP
//! exchange or a UDP/DTLS exchange. A plan has exactly one unit kind, so
//! every count and latency in its report has a single denominator.
//!
//! Combinations without a defined unit are refused with a typed
//! [`Refusal`] before any traffic — never emulated:
//! * mixed unit kinds in one chain or mix;
//! * client-streaming and bidirectional gRPC (long-lived two-way streams
//!   have no single completion or message denominator yet);
//! * gRPC with server reflection as the schema source (every call would
//!   first run a reflection RPC, so a unit would not be one call);
//! * SSE with automatic reconnection (one unit would become several
//!   connections with server-chosen delays);
//! * UDP through a MASQUE proxy (a QUIC connection and CONNECT-UDP tunnel
//!   per exchange, with no tunnel reuse or tunnel denominators);
//! * a mesh HBONE proxy with persistent connections for HTTP and gRPC
//!   (tunnels are never pooled, so the mode could not be honoured).

use anvil_domain::Id;
use anvil_domain::load::{ConnectionMode, LoadUnitKind, UnitSemantics};
use anvil_domain::request::{GrpcMode, GrpcSchemaSource, Protocol, TcpFraming};
use anvil_domain::tls::ProxyKind;
use anvil_engine::ExecutionContext;
use serde::{Deserialize, Serialize};

/// Why a plan cannot be load tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    /// The chain or mix produces more than one unit kind.
    MixedUnitKinds,
    GrpcClientStreaming,
    GrpcBidirectional,
    /// gRPC with server reflection as the schema source.
    GrpcReflection,
    /// SSE with automatic reconnection enabled.
    SseReconnect,
    /// UDP through a MASQUE (CONNECT-UDP) proxy.
    UdpMasque,
    /// UDP through a mesh HBONE datagram tunnel.
    UdpHbone,
    /// A mesh HBONE proxy with the persistent connection mode (HTTP, gRPC).
    HbonePersistent,
    /// The request enables 0-RTT early data.
    EarlyData,
    /// The request lacks what its protocol needs (e.g. a gRPC method).
    IncompleteRequest,
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
}

impl StepUnit {
    fn of(kind: LoadUnitKind) -> Self {
        StepUnit { kind, tcp_expect_frames: None, ws_expect_messages: 0 }
    }
}

/// Short plural label, e.g. `WebSocket sessions`.
pub fn label(kind: LoadUnitKind) -> &'static str {
    match kind {
        LoadUnitKind::HttpRequest => "HTTP requests",
        LoadUnitKind::GrpcCall => "unary gRPC calls",
        LoadUnitKind::GrpcStream => "server-streaming gRPC streams",
        LoadUnitKind::SseStream => "SSE streams",
        LoadUnitKind::WebsocketSession => "WebSocket sessions",
        LoadUnitKind::TcpExchange => "TCP/TLS exchanges",
        LoadUnitKind::UdpExchange => "UDP exchanges",
        LoadUnitKind::DtlsExchange => "DTLS exchanges",
    }
}

fn is_hbone(ctx: &ExecutionContext) -> bool {
    let eff = anvil_engine::settings::resolve(&ctx.settings_layers);
    eff.proxy_profile_id.and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id)).is_some_and(|p| p.kind == ProxyKind::Hbone)
}

fn uses_dtls(ctx: &ExecutionContext) -> bool {
    if ctx.spec.udp.as_ref().is_some_and(|u| u.dtls) {
        return true;
    }
    // The scheme may come from a variable; resolve with the context's own layers.
    let url = anvil_engine::vars::Resolver::new(ctx.var_layers.clone(), None)
        .resolve(&ctx.spec.url, "url")
        .unwrap_or_else(|_| ctx.spec.url.clone());
    url.trim().to_ascii_lowercase().starts_with("dtls://")
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
    let hbone_persistent = mode == ConnectionMode::Persistent && is_hbone(ctx);
    let hbone_msg = |what: &str| {
        format!(
            "{what} through a mesh HBONE proxy cannot use the persistent connection mode: an HBONE tunnel carries one execution's identity and headers and is never pooled, so every unit would open its own tunnel. Choose the fresh connection mode, which is what would happen"
        )
    };
    match ctx.spec.protocol {
        Protocol::Http => {
            if hbone_persistent {
                return refuse(RefusalCode::HbonePersistent, hbone_msg("HTTP requests"));
            }
            Ok(StepUnit::of(LoadUnitKind::HttpRequest))
        }
        Protocol::Grpc => {
            let Some(g) = &ctx.spec.grpc else {
                // The engine refuses this per send; a load run has no unit for it.
                return refuse(RefusalCode::IncompleteRequest, "the gRPC request has no service, method or schema".into());
            };
            let kind = match g.mode {
                GrpcMode::Unary => LoadUnitKind::GrpcCall,
                GrpcMode::ServerStreaming => LoadUnitKind::GrpcStream,
                GrpcMode::ClientStreaming => {
                    return refuse(
                        RefusalCode::GrpcClientStreaming,
                        "client-streaming gRPC cannot be load tested yet: a long-lived client stream has no defined completion or per-message denominator, so it is refused rather than counted as calls".into(),
                    );
                }
                GrpcMode::Bidirectional => {
                    return refuse(
                        RefusalCode::GrpcBidirectional,
                        "bidirectional gRPC cannot be load tested yet: a long-lived two-way stream has no defined completion or per-message denominator, so it is refused rather than counted as calls".into(),
                    );
                }
            };
            if matches!(g.schema, GrpcSchemaSource::Reflection) {
                return refuse(
                    RefusalCode::GrpcReflection,
                    "gRPC load needs a local schema: with server reflection every call would first run a reflection RPC, so one unit would not be one call. Import the .proto files or a descriptor set".into(),
                );
            }
            if hbone_persistent {
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
        Protocol::WebSocket => Ok(StepUnit {
            kind: LoadUnitKind::WebsocketSession,
            tcp_expect_frames: None,
            ws_expect_messages: ctx.spec.websocket.as_ref().map(|w| w.expect_messages).unwrap_or(0),
        }),
        Protocol::Tcp => {
            let tcp = ctx.spec.tcp.as_ref();
            let expect = tcp.filter(|t| t.framing != TcpFraming::None && t.expect_frames > 0).map(|t| t.expect_frames);
            Ok(StepUnit { kind: LoadUnitKind::TcpExchange, tcp_expect_frames: expect, ws_expect_messages: 0 })
        }
        Protocol::Udp => {
            if ctx.spec.udp.as_ref().is_some_and(|u| u.masque.is_some()) {
                return refuse(
                    RefusalCode::UdpMasque,
                    "UDP through a MASQUE (CONNECT-UDP) proxy cannot be load tested yet: every exchange would open its own QUIC connection and tunnel, and there are no tunnel denominators. Send to the UDP target directly".into(),
                );
            }
            if is_hbone(ctx) {
                return refuse(
                    RefusalCode::UdpHbone,
                    "UDP through an HBONE tunnel cannot be load tested yet: every exchange would open its own mTLS connection and datagram tunnel, and there are no tunnel denominators. Send to the UDP target directly".into(),
                );
            }
            Ok(StepUnit::of(if uses_dtls(ctx) { LoadUnitKind::DtlsExchange } else { LoadUnitKind::UdpExchange }))
        }
    }
}

/// Classify every step of a plan (in plan order) and require one unit kind.
pub fn classify_plan<'a>(
    steps: impl IntoIterator<Item = (Id, &'a ExecutionContext)>,
    mode: ConnectionMode,
) -> Result<(LoadUnitKind, Vec<StepUnit>), Refusal> {
    let mut units: Vec<StepUnit> = Vec::new();
    for (id, ctx) in steps {
        units.push(classify(Some(id), ctx, mode)?);
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
    Ok((first, units))
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
            "Completed with an application success (status below 400, no SOAP fault or GraphQL error) and every assertion passing.",
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

/// Best-effort unit kind of a request spec, without refusals (for labels, e.g.
/// a crash report whose worker never announced its run).
pub fn unit_of_spec(spec: &anvil_domain::request::RequestSpec) -> LoadUnitKind {
    match spec.protocol {
        Protocol::Http => LoadUnitKind::HttpRequest,
        Protocol::Grpc if spec.grpc.as_ref().is_some_and(|g| g.mode == GrpcMode::ServerStreaming) => LoadUnitKind::GrpcStream,
        Protocol::Grpc => LoadUnitKind::GrpcCall,
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
    matches!(kind, LoadUnitKind::HttpRequest | LoadUnitKind::GrpcCall | LoadUnitKind::GrpcStream)
}
