//! The request the effective-request preview shows for each protocol: the
//! method, target, headers and body that are sent, before auth is applied.
//! For a session protocol (WebSocket, SSE, gRPC) it is the handshake or call
//! [`crate::sessions`] builds for the session itself, with the headers the
//! session transport adds. Nothing is sent and no token is acquired. Raw TCP
//! and UDP send no HTTP request, so there is none to preview.

use crate::context::ExecutionContext;
use crate::http_exec::Prepared;
use crate::prepare::Target;
use crate::sessions::{self, SessionRequest};
use crate::vars::Resolver;
use anvil_auth::ResolvedAuth;
use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_domain::request::*;
use anvil_domain::settings::HttpVersionPolicy;
use anvil_transport::grpc;

/// A request as it is sent, before auth is applied.
pub(crate) struct Shape {
    pub req: SessionRequest,
    /// Whether it opens a session, which refuses auth it cannot carry.
    session: bool,
    /// The request message (JSON) of a unary or server-streaming gRPC call,
    /// shown in place of the framed bytes sent: a secret in those bytes
    /// (or in their base64 text) would not be recognised to be redacted.
    /// With server reflection the message is encoded, and the call signed
    /// over it, only when the call is sent.
    pub message: Option<String>,
}

fn unsupported(msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, FailureKind::UnsupportedCombination, msg).with_field(field)
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
        Protocol::Udp => {
            Err(unsupported("preview not supported for UDP: the datagrams are sent verbatim, with no HTTP request to preview", "protocol"))
        }
    }
}

impl Shape {
    /// An HTTP request: sent as prepared.
    pub(crate) fn http(prep: &Prepared) -> Shape {
        let req = SessionRequest {
            method: prep.http.method.clone(),
            target: prep.http.target.clone(),
            headers: prep.http.headers.clone(),
            body: prep.http.body.clone(),
            content_type: prep.http.content_type.clone(),
            transport: vec![],
            not_sent: &[],
            host_from_authority: false,
            path_only: false,
        };
        Shape { req, session: false, message: None }
    }

    /// The handshake (WebSocket, SSE) or call (gRPC) of a session protocol,
    /// built and refused before traffic exactly as the session builds it.
    pub(crate) fn session(
        ctx: &ExecutionContext,
        r: &Resolver,
        prep: &Prepared,
        inferred: &mut Vec<String>,
    ) -> Result<Shape, TransportFailure> {
        if prep.settings.early_data.enabled {
            inferred.push(sessions::EARLY_DATA_NOTE.into());
        }
        let (req, message) = match ctx.spec.protocol {
            Protocol::WebSocket => (websocket(ctx, r, prep, inferred)?, None),
            Protocol::Sse => (event_stream(ctx, r, prep, inferred)?, None),
            Protocol::Grpc => grpc_call(ctx, r, prep, inferred)?,
            p => return Err(schemes(p).err().unwrap_or_else(|| unsupported("HTTP is not a session protocol", "protocol"))),
        };
        Ok(Shape { req, session: true, message })
    }

    /// Why the session refuses what an auth profile applied, as it does
    /// before sending anything.
    pub(crate) fn auth_refusal(&self, applied: &anvil_auth::Applied) -> Option<String> {
        if self.session { sessions::auth_refusal(applied, self.req.path_only) } else { None }
    }

    /// Apply what the transport does to the headers after auth: the fields
    /// it adds or replaces, and those it leaves out. `authority` is the one
    /// the request is sent with (and signed for).
    pub(crate) fn transport_headers(&self, headers: &mut Vec<(String, String)>, authority: &str) {
        headers.retain(|(n, _)| !self.req.not_sent.contains(&n.to_ascii_lowercase().as_str()));
        if self.req.host_from_authority {
            headers.push(("Host".into(), authority.to_string()));
        }
        for (name, value, replace) in &self.req.transport {
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
        if self.req.path_only { format!("{}://{}{}", target.scheme, target.authority, target.path) } else { target.url() }
    }
}

fn websocket(
    ctx: &ExecutionContext,
    r: &Resolver,
    prep: &Prepared,
    inferred: &mut Vec<String>,
) -> Result<SessionRequest, TransportFailure> {
    let hs = sessions::ws_offer(ctx)?.handshake(ctx, r, prep, inferred)?;
    if let Some(d) = &hs.deflate {
        inferred.push(sessions::deflate_note(d));
    }
    let over = match hs.spec.bootstrap {
        WsBootstrap::Http1Upgrade => None,
        WsBootstrap::Http2ExtendedConnect => Some(("HTTP/2", 8441)),
        WsBootstrap::Http3ExtendedConnect => Some(("HTTP/3", 9220)),
    };
    if let Some((version, rfc)) = over {
        inferred.push(format!("extended CONNECT over {version} with :protocol websocket (RFC {rfc}); the Host is sent as :authority"));
    }
    Ok(hs.request)
}

fn event_stream(
    ctx: &ExecutionContext,
    r: &Resolver,
    prep: &Prepared,
    inferred: &mut Vec<String>,
) -> Result<SessionRequest, TransportFailure> {
    let s = sessions::sse_request(ctx, r, prep, inferred)?;
    // The session signs each send afresh, which the preview (sending
    // nothing) cannot do.
    if !matches!(prep.auth, ResolvedAuth::None) {
        inferred.push(
            "each send (initial, TCP fallback, each reconnection) is signed again when it is sent, not with the signature shown".into(),
        );
    }
    // Over TLS the version is negotiated when the stream is opened, and with
    // it whether the `Host` is sent as `Host` or as `:authority`.
    let https = prep.http.target.scheme == "https";
    let over = match prep.settings.http_version {
        HttpVersionPolicy::Auto if https => "HTTP/2 or HTTP/1.1, as ALPN negotiates",
        HttpVersionPolicy::Http3WithFallback if https => "HTTP/3, or after a fallback to TCP HTTP/2 or HTTP/1.1 as ALPN negotiates",
        _ => return Ok(s.request),
    };
    inferred.push(format!("the stream is opened over {over}: the Host is sent as :authority over HTTP/2 and HTTP/3, Host over HTTP/1.1"));
    Ok(s.request)
}

/// The call, and the request message shown in place of its framed body.
fn grpc_call(
    ctx: &ExecutionContext,
    r: &Resolver,
    prep: &Prepared,
    inferred: &mut Vec<String>,
) -> Result<(SessionRequest, Option<String>), TransportFailure> {
    let call = sessions::grpc_call(ctx, r, prep, inferred, sessions::grpc_spec(ctx)?, false)?;
    let single = matches!(call.spec.mode, GrpcMode::Unary | GrpcMode::ServerStreaming);
    if single && call.spec.messages.is_empty() {
        // With server reflection the frame is signed only when the call is
        // sent: what the preview shows is signed over an empty body.
        let signed = match (&prep.auth, &call.schema) {
            (ResolvedAuth::None, _) => "",
            (_, grpc::Schema::Reflection) => ", and auth signs that frame when the call is sent",
            _ => ", and auth signs that frame",
        };
        inferred.push(format!("no request message is set: the call sends the empty message ({{}}), framed{signed}"));
    }
    let mut message = None;
    match &call.schema {
        grpc::Schema::Pool(_) if single => {
            if let Some(m) = call.messages.first() {
                let n = call.request.body.len();
                let text = if call.spec.wire == GrpcWire::GrpcWebText { ", base64-encoded (gRPC-Web text)" } else { "" };
                inferred.push(format!("the request message is shown as JSON; it is sent as {n} framed bytes{text}"));
                message = Some(m.clone());
            }
        }
        grpc::Schema::Pool(_) => inferred.push("the request messages are streamed once the call is open; the body shown is empty".into()),
        // The session signs the framed message once reflection has resolved
        // the schema, which the preview (sending nothing) cannot do.
        grpc::Schema::Reflection if single => {
            message = call.messages.first().cloned();
            let signed = if matches!(prep.auth, ResolvedAuth::None) {
                ""
            } else {
                ", and auth signs the call then, over the framed message sent: a Content-Digest or signature shown here is computed over an empty body, not over the message"
            };
            inferred.push(format!(
                "server reflection: the request message is shown as JSON; it is encoded, and its size known, once the schema is resolved when the call is sent{signed}"
            ));
        }
        grpc::Schema::Reflection => {
            inferred.push("server reflection: the request messages are streamed once the call is open; the body shown is empty".into())
        }
    }
    if matches!(call.schema, grpc::Schema::Reflection) && !matches!(prep.auth, ResolvedAuth::None) {
        inferred.push(
            "each server reflection request is signed for its own path and message when it is sent, not with the signature shown".into(),
        );
    }
    Ok((call.request, message))
}
