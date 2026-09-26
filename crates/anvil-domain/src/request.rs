use crate::Id;
use crate::assertions::{Assertion, Extraction};
use crate::auth::AuthConfig;
use crate::settings::SettingsOverrides;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Wire protocol family of a saved request. SOAP and GraphQL are HTTP body
/// kinds, not separate transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Http,
    WebSocket,
    Grpc,
    Sse,
    Tcp,
    Udp,
}

/// Enabled/disabled name-value entry. Repeated names are legal and preserved
/// in order (headers and query parameters may repeat).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KeyValue {
    pub name: String,
    pub value: String,
    #[serde(default = "crate::request::default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Marks the value as sensitive for masking/redaction/export.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
}

impl KeyValue {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        KeyValue { name: name.into(), value: value.into(), enabled: true, description: String::new(), sensitive: false }
    }
}

pub(crate) fn default_true() -> bool {
    true
}

/// Reference to a content-addressed attachment (binary body, multipart file,
/// proto file, dataset). The bytes live in encrypted attachment storage or,
/// for linked files, at a path the user selected on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AttachmentRef {
    /// Stored inside Anvil (portable; included in exports).
    Stored {
        sha256: String,
        size: u64,
        file_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
    },
    /// Linked local file (device-specific; exports report it as a rebinding
    /// requirement rather than copying an absolute machine path silently).
    LinkedFile { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MultipartPart {
    pub name: String,
    #[serde(default = "crate::request::default_true")]
    pub enabled: bool,
    #[serde(flatten)]
    pub content: MultipartContent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "part_kind", rename_all = "snake_case")]
pub enum MultipartContent {
    Text {
        value: String,
    },
    File {
        attachment: AttachmentRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file_name: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum SoapVersion {
    #[default]
    Soap11,
    Soap12,
}

/// Request body model. Serialization (and content-type inference) happens in
/// the engine before any body-dependent signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Body {
    #[default]
    None,
    Raw {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_type: Option<String>,
    },
    Json {
        text: String,
    },
    Xml {
        text: String,
    },
    FormUrlEncoded {
        fields: Vec<KeyValue>,
    },
    Multipart {
        parts: Vec<MultipartPart>,
    },
    Binary {
        attachment: AttachmentRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_type: Option<String>,
    },
    #[serde(rename = "graphql")]
    GraphQl {
        query: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        variables: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_name: Option<String>,
    },
    Soap {
        version: SoapVersion,
        envelope: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
    },
}

/// Policy for sending a body whose syntax lint failed. Anvil is a testing
/// client, so invalid JSON/XML is sendable by explicit choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LintSendPolicy {
    /// Refuse to send until the user chooses "send anyway" for this send.
    #[default]
    Block,
    /// Warn in the outcome but send.
    Warn,
    /// Do not lint (e.g. deliberate malformed-payload tests).
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcMode {
    #[default]
    Unary,
    ClientStreaming,
    ServerStreaming,
    Bidirectional,
}

/// Where gRPC message schemas come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrpcSchemaSource {
    /// `.proto` sources (compiled in-process; imports resolved only among the
    /// provided files).
    ProtoFiles { files: Vec<AttachmentRef> },
    /// Serialized `FileDescriptorSet`.
    DescriptorSet { attachment: AttachmentRef },
    /// Server reflection (grpc.reflection.v1, falling back to v1alpha).
    Reflection,
}

/// How gRPC calls are carried on the wire. The HTTP version comes from the
/// request's HTTP version policy (see `docs/protocols.md` §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcWire {
    /// Native gRPC (`application/grpc`) over HTTP/2 or HTTP/3; the status
    /// arrives in HTTP trailers (or the headers of a trailers-only answer).
    #[default]
    Grpc,
    /// gRPC-Web, binary (`application/grpc-web+proto`), over HTTP/1.1, HTTP/2
    /// or HTTP/3. Unary and server streaming only; the status arrives in a
    /// trailer frame (flag `0x80`) at the end of the response body.
    GrpcWeb,
    /// gRPC-Web, text (`application/grpc-web-text`): the same frames,
    /// base64-encoded in both directions.
    GrpcWebText,
}

impl GrpcWire {
    pub fn is_web(self) -> bool {
        !matches!(self, GrpcWire::Grpc)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrpcSpec {
    /// Fully qualified `package.Service`.
    pub service: String,
    pub method: String,
    #[serde(default)]
    pub mode: GrpcMode,
    pub schema: GrpcSchemaSource,
    /// JSON messages to send in order (one for unary / server streaming).
    pub messages: Vec<String>,
    #[serde(default)]
    pub metadata: Vec<KeyValue>,
    /// `grpc-timeout` sent to the server, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// Use h2c (cleartext prior knowledge) for `http://` targets (native gRPC).
    #[serde(default)]
    pub plaintext: bool,
    /// Wire format: native gRPC (default; records saved before this field
    /// existed load as native), gRPC-Web binary or gRPC-Web text.
    #[serde(default)]
    pub wire: GrpcWire,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum WsBootstrap {
    /// RFC 6455 HTTP/1.1 Upgrade.
    #[default]
    Http1Upgrade,
    /// RFC 8441 Extended CONNECT over HTTP/2.
    Http2ExtendedConnect,
    /// RFC 9220 Extended CONNECT over HTTP/3.
    Http3ExtendedConnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WsMessage {
    Text {
        text: String,
    },
    /// Hex-encoded bytes.
    Binary {
        hex: String,
    },
    Ping {
        hex: String,
    },
    Close {
        code: u16,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsSpec {
    #[serde(default)]
    pub bootstrap: WsBootstrap,
    #[serde(default)]
    pub subprotocols: Vec<String>,
    /// Messages sent after open (automation / scripted session).
    #[serde(default)]
    pub messages: Vec<WsMessage>,
    /// Automation: wait for this many inbound messages before closing.
    #[serde(default)]
    pub expect_messages: u32,
    #[serde(default = "default_ws_max_message")]
    pub max_message_bytes: u64,
    /// Close the session after this idle period (automation only).
    #[serde(default = "default_ws_idle")]
    pub idle_close_ms: u64,
}

fn default_ws_max_message() -> u64 {
    16 * 1024 * 1024
}
fn default_ws_idle() -> u64 {
    5_000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SseSpec {
    /// Stop after this many events (0 = until cancel/idle/max duration).
    #[serde(default)]
    pub max_events: u32,
    #[serde(default = "default_sse_idle")]
    pub idle_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
    /// Automatic reconnect is off by default; reconnect only when explicitly enabled.
    #[serde(default)]
    pub reconnect: bool,
}

fn default_sse_idle() -> u64 {
    30_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    #[default]
    Text,
    Hex,
    Base64,
}

/// Framing presets for raw TCP exchanges. Arbitrary bytes are never assumed to
/// be a known application protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum TcpFraming {
    #[default]
    None,
    NewlineDelimited,
    LengthPrefixedU16,
    LengthPrefixedU32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StreamPayload {
    pub data: String,
    #[serde(default)]
    pub encoding: PayloadEncoding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TcpSpec {
    /// Use TLS (the `tls_profile` settings apply).
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub framing: TcpFraming,
    pub payloads: Vec<StreamPayload>,
    /// Half-close (shutdown write) after sending, then keep reading.
    #[serde(default)]
    pub half_close_after_send: bool,
    #[serde(default = "default_stream_idle")]
    pub read_idle_ms: u64,
    #[serde(default = "default_stream_max")]
    pub max_read_bytes: u64,
    /// Stop reading after this many frames (0 = until idle/close/max bytes).
    #[serde(default)]
    pub expect_frames: u32,
    /// PROXY protocol header written after TCP connect, before any TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<crate::proxy_protocol::ProxyHeaderSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UdpSpec {
    /// Use DTLS (the `tls_profile` settings apply).
    #[serde(default)]
    pub dtls: bool,
    pub datagrams: Vec<StreamPayload>,
    /// How long to wait for responses after the last datagram is sent.
    #[serde(default = "default_udp_window")]
    pub response_window_ms: u64,
    #[serde(default = "default_udp_max")]
    pub max_datagrams: u32,
    /// PROXY v2 `DGRAM` envelope prepended to every datagram (DTLS: outside
    /// the DTLS records, handshake included).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<crate::proxy_protocol::DatagramEnvelopeSpec>,
    /// Send the datagrams through an HTTP/3 MASQUE proxy (RFC 9298
    /// CONNECT-UDP) instead of directly. The request URL stays the UDP
    /// target (`udp://host:port`); the proxy only relays. `None` = direct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masque: Option<MasqueSpec>,
}

/// RFC 9298 UDP proxying over HTTP/3 ("MASQUE" CONNECT-UDP). Belongs to
/// the UDP request rather than to a proxy profile: the proxy is addressed by
/// a URI Template (not `host:port`), carries only UDP, and its datagram
/// encoding is part of the exchange's evidence (docs/protocols.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MasqueSpec {
    /// The proxy's `https://host:port` origin (variables allowed). HTTP/3
    /// needs TLS, so any other scheme is refused before traffic; the TLS
    /// profile setting applies to the QUIC handshake with the proxy.
    pub proxy_url: String,
    /// RFC 9298 §2 URI Template path (and optional query) on the proxy.
    /// `{target_host}` and `{target_port}` are expanded from the request URL.
    #[serde(default = "default_masque_template")]
    pub uri_template: String,
    #[serde(default)]
    pub datagrams: MasqueDatagramMode,
}

/// How HTTP Datagrams (RFC 9297) are carried through the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum MasqueDatagramMode {
    /// QUIC DATAGRAM frames when the proxy's SETTINGS enable HTTP/3
    /// datagrams (`SETTINGS_H3_DATAGRAM`) and QUIC negotiated DATAGRAM
    /// frames; otherwise DATAGRAM capsules on the CONNECT stream (RFC 9297
    /// §3.5). The encoding used is recorded.
    #[default]
    Auto,
    /// Require QUIC DATAGRAM frames; fail before traffic when the proxy does
    /// not offer HTTP/3 datagrams.
    QuicDatagrams,
    /// Always DATAGRAM capsules on the CONNECT stream.
    Capsules,
}

/// RFC 9298 §2 default URI Template path.
pub const MASQUE_DEFAULT_TEMPLATE: &str = "/.well-known/masque/udp/{target_host}/{target_port}/";

fn default_masque_template() -> String {
    MASQUE_DEFAULT_TEMPLATE.to_string()
}

fn default_stream_idle() -> u64 {
    2_000
}
fn default_stream_max() -> u64 {
    1024 * 1024
}
fn default_udp_window() -> u64 {
    1_000
}
fn default_udp_max() -> u32 {
    1_000
}

/// The editable, serializable definition of a request. Execution never
/// mutates it; a run snapshots it as an immutable [`crate::workspace::RequestRevision`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestSpec {
    #[serde(default)]
    pub protocol: Protocol,
    /// HTTP method (ignored for non-HTTP protocols).
    #[serde(default = "default_method")]
    pub method: String,
    /// URL template (may contain `{{variables}}`). For TCP/UDP: `tcp://host:port`,
    /// `tls://host:port`, `udp://host:port`, `dtls://host:port`.
    pub url: String,
    #[serde(default)]
    pub params: Vec<KeyValue>,
    #[serde(default)]
    pub headers: Vec<KeyValue>,
    #[serde(default)]
    pub body: Body,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub settings: SettingsOverrides,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    #[serde(default)]
    pub extractions: Vec<Extraction>,
    #[serde(default)]
    pub lint_policy: LintSendPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<GrpcSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket: Option<WsSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse: Option<SseSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<UdpSpec>,
    /// Reference to the imported spec operation this request came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ImportSource>,
}

fn default_method() -> String {
    "GET".into()
}

impl RequestSpec {
    pub fn http(method: &str, url: &str) -> Self {
        RequestSpec {
            protocol: Protocol::Http,
            method: method.to_string(),
            url: url.to_string(),
            params: vec![],
            headers: vec![],
            body: Body::None,
            auth: AuthConfig::Inherit,
            settings: SettingsOverrides::default(),
            assertions: vec![],
            extractions: vec![],
            lint_policy: LintSendPolicy::default(),
            grpc: None,
            websocket: None,
            sse: None,
            tcp: None,
            udp: None,
            source: None,
        }
    }
}

/// Link from a request to the spec/collection it was imported from, used for
/// reimport diffs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ImportSource {
    pub import_id: Id,
    /// Stable key: operationId when present, else `METHOD path`.
    pub operation_key: String,
    /// Hash of the generated request spec at import time (detects user edits).
    pub generated_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_specs_saved_before_the_wire_field_load_as_native_grpc() {
        let old = r#"{"service":"a.v1.S","method":"M","mode":"unary","schema":{"kind":"reflection"},"messages":["{}"],"plaintext":true}"#;
        let s: GrpcSpec = serde_json::from_str(old).unwrap();
        assert_eq!(s.wire, GrpcWire::Grpc);
        assert!(s.plaintext);
        let web: GrpcSpec = serde_json::from_str(&old.replace("\"plaintext\":true", "\"wire\":\"grpc_web_text\"")).unwrap();
        assert_eq!(web.wire, GrpcWire::GrpcWebText);
        assert!(web.wire.is_web() && !GrpcWire::Grpc.is_web());
        assert!(serde_json::to_string(&web).unwrap().contains(r#""wire":"grpc_web_text""#));
    }
}
