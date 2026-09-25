/* Generated from contracts/schemas by scripts/gen-contracts.mjs — do not edit. */

/**
 * Protocol negotiation policy for HTTP-family requests.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "HttpVersionPolicy".
 */
export type HttpVersionPolicy = "http1_only" | "auto" | "http2_only" | "h2c" | "http3_only" | "http3_with_fallback";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "IpPreference".
 */
export type IpPreference = "system" | "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ResolverMode".
 */
export type ResolverMode =
  | {
      mode: "system";
    }
  | {
      nameservers: string[];
      mode: "custom";
    };
/**
 * Explicit proxy choice: a profile, or explicitly none (overrides inherited).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ProxySelection".
 */
export type ProxySelection =
  | {
      kind: "none";
    }
  | {
      id: Id;
      kind: "profile";
    };
/**
 * Stable object identifier. UUIDv7 so ids sort roughly by creation time.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Id".
 */
export type Id = string;
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Theme".
 */
export type Theme = "system" | "light" | "dark";
/**
 * What happens to active runs when the vault locks.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "LockRunPolicy".
 */
export type LockRunPolicy = "stop_runs";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "DatasetFormat".
 */
export type DatasetFormat = "csv" | "json";
/**
 * Reference to a content-addressed attachment (binary body, multipart file,
 * proto file, dataset). The bytes live in encrypted attachment storage or,
 * for linked files, at a path the user selected on this machine.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "AttachmentRef".
 */
export type AttachmentRef =
  | {
      sha256: string;
      size: number;
      file_name: string;
      media_type?: string | null;
      kind: "stored";
    }
  | {
      path: string;
      kind: "linked_file";
    };
/**
 * Which leg / owner of the path a claim is about.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "SourceScope".
 */
export type SourceScope =
  | ("forward_proxy" | "upstream_application" | "unknown")
  | "local_client"
  | "client_to_peer"
  | "gateway_admission"
  | "gateway_to_upstream"
  | "response_delivery";
/**
 * Qualitative confidence. Anvil never invents probability percentages.
 * `Unknown` is a correct answer when evidence is insufficient.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Confidence".
 */
export type Confidence = "conflicting_evidence" | "unknown" | "likely" | "confirmed";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "warning" | "error";
/**
 * Where a piece of evidence came from. Rules weight native measurements and
 * trusted gateway fields above generic status meanings and body heuristics.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "EvidenceSource".
 */
export type EvidenceSource =
  | (
      | "local_validation"
      | "native_transport"
      | "tls_verifier"
      | "http_status"
      | "http_header"
      | "http_trailer"
      | "grpc_status"
      | "web_socket_close"
      | "body_completion"
      | "configuration"
      | "assertion"
    )
  | "body_content"
  | "ferrum_marker_trusted"
  | "ferrum_marker_unverified"
  | "gateway_detail";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Owner".
 */
export type Owner =
  ("gateway_operator" | "api_owner" | "network_administrator" | "identity_provider" | "unknown") | "caller";
/**
 * A field that may carry sensitive material (password, token, key).
 *
 * * `Template` — text that may contain `{{variable}}` references. A literal
 *   (non-variable) template in a sensitive field is itself treated as
 *   sensitive: it is masked in the UI, redacted in history, and replaced by a
 *   placeholder in safe-share exports.
 * * `Secret` — a vault reference.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "SensitiveValue".
 */
export type SensitiveValue =
  | {
      value: string;
      kind: "template";
    }
  | {
      secret: SecretRef;
      kind: "secret";
    };
/**
 * Structured, bounded progress events emitted while an execution runs. The
 * UI and CLI render these live; the final [`crate::execution::ExecutionRecord`]
 * is authoritative.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ExecutionEvent".
 */
export type ExecutionEvent =
  | {
      execution_id: Id;
      method: string;
      url: string;
      event: "started";
    }
  | {
      execution_id: Id;
      attempt: number;
      event: "attempt_started";
    }
  | {
      execution_id: Id;
      attempt: number;
      phase: Phase;
      status: PhaseStatus;
      offset_us: number;
      event: "phase";
    }
  | {
      execution_id: Id;
      attempt: number;
      status: number;
      event: "response_head";
    }
  | {
      execution_id: Id;
      bytes: number;
      event: "body_progress";
    }
  | {
      execution_id: Id;
      message: StreamMessage;
      event: "message";
    }
  | {
      execution_id: Id;
      attempt: number;
      kind: FailureKind;
      event: "attempt_failed";
    }
  | {
      execution_id: Id;
      event: "finished";
    };
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Phase".
 */
export type Phase =
  | (
      | "dns"
      | "tls_handshake"
      | "quic_handshake"
      | "dtls_handshake"
      | "request_write"
      | "await_response_headers"
      | "response_body"
    )
  | "prepare"
  | "queue"
  | "connect"
  | "proxy_tunnel"
  | "protocol_handshake"
  | "session";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "PhaseStatus".
 */
export type PhaseStatus = ("completed" | "failed" | "timed_out" | "canceled") | "reused" | "not_applicable" | "unknown";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Direction".
 */
export type Direction = "sent" | "received";
/**
 * Typed failure kinds. Rules match on these, never on message text.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "FailureKind".
 */
export type FailureKind =
  | (
      | "invalid_url"
      | "unsupported_scheme"
      | "unresolved_variable"
      | "variable_cycle"
      | "missing_attachment"
      | "client_identity_invalid"
      | "client_identity_key_mismatch"
      | "tls_profile_invalid"
      | "proxy_config_invalid"
      | "invalid_header"
      | "body_serialization"
      | "lint_blocked"
      | "request_too_large_local"
      | "auth_preparation_failed"
      | "unsupported_combination"
      | "vault_locked"
      | "dns_no_such_host"
      | "dns_no_records"
      | "dns_timeout"
      | "dns_server_failure"
      | "dns_other"
      | "connect_refused"
      | "connect_timeout"
      | "connect_reset"
      | "network_unreachable"
      | "host_unreachable"
      | "address_unavailable"
      | "connect_other"
      | "proxy_connect_failed"
      | "proxy_tunnel_rejected"
      | "proxy_auth_required"
      | "proxy_protocol_error"
      | "tls_untrusted_issuer"
      | "tls_expired"
      | "tls_not_yet_valid"
      | "tls_name_mismatch"
      | "tls_revoked"
      | "tls_bad_certificate"
      | "tls_alert_received"
      | "tls_handshake_timeout"
      | "tls_peer_closed"
      | "tls_reset"
      | "tls_protocol_mismatch"
      | "tls_alpn_mismatch"
      | "tls_other"
      | "quic_handshake_timeout"
      | "quic_idle_timeout"
      | "quic_transport_error"
      | "quic_application_closed"
      | "quic_other"
      | "dtls_handshake_timeout"
      | "dtls_handshake_failed"
      | "request_write_timeout"
      | "request_write_failed"
      | "response_headers_timeout"
      | "closed_before_response"
      | "reset_before_response"
      | "http_protocol_error"
      | "h2_stream_reset"
      | "h2_refused_stream"
      | "h2_go_away"
      | "response_headers_too_large"
      | "body_idle_timeout"
      | "body_incomplete"
      | "body_reset"
      | "response_too_large_local"
      | "decompression_failed"
      | "ws_handshake_rejected"
      | "ws_protocol_error"
      | "ws_message_too_large"
      | "total_timeout"
      | "canceled"
      | "internal"
    )
  | "tls_alert_after_handshake";
/**
 * Wire protocol family of a saved request. SOAP and GraphQL are HTTP body
 * kinds, not separate transports.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Protocol".
 */
export type Protocol = "http" | "web_socket" | "grpc" | "sse" | "tcp" | "udp";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "AttemptReason".
 */
export type AttemptReason =
  | {
      reason: "initial";
    }
  | {
      status: number;
      reason: "redirect";
    }
  | {
      after: FailureKind;
      reason: "retry";
    }
  | {
      from: string;
      reason: "protocol_fallback";
    }
  | {
      scheme: string;
      reason: "auth_challenge";
    };
/**
 * Result of peer-certificate verification.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TlsVerification".
 */
export type TlsVerification =
  | {
      result: "verified";
    }
  | {
      problem: FailureKind;
      detail: string;
      result: "failed";
    }
  | {
      would_have_failed?: FailureKind | null;
      result: "bypassed";
    }
  | {
      result: "not_reached";
    };
/**
 * Whether request bytes of an attempt may have reached the peer.
 *
 * Derived from typed transport state (bytes written to the socket, response
 * received, HTTP/2 `REFUSED_STREAM`, ...), never from error message text.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "DispatchState".
 */
export type DispatchState = "unknown" | "not_dispatched" | "sent" | "may_have_been_sent";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "BodyCompleteness".
 */
export type BodyCompleteness = "complete" | "incomplete" | "canceled" | "stopped_at_local_limit" | "no_body";
/**
 * Transport completion, independent of HTTP/RPC status.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TransportState".
 */
export type TransportState = ("canceled" | "unknown") | "completed" | "failed" | "incomplete";
/**
 * Application-level result: HTTP status class, gRPC status, SOAP fault,
 * GraphQL errors. Evaluated only when a response exists.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ApplicationState".
 */
export type ApplicationState = "success" | "failure" | "not_evaluated";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "AssertionState".
 */
export type AssertionState = "pass" | "fail" | "not_run";
/**
 * Typed protocol-level result.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ProtocolStatus".
 */
export type ProtocolStatus =
  | {
      protocol: "none";
    }
  | {
      status: number;
      reason?: string | null;
      protocol: "http";
    }
  | {
      http_status?: number | null;
      grpc_status?: number | null;
      grpc_message?: string | null;
      source: GrpcStatusSource;
      protocol: "grpc";
    }
  | {
      handshake_status?: number | null;
      close_code?: number | null;
      close_reason?: string;
      closed_by: ClosedBy;
      protocol: "websocket";
    }
  | {
      http_status: number;
      events: number;
      closed_by: ClosedBy;
      protocol: "sse";
    }
  | {
      bytes_sent: number;
      bytes_received: number;
      half_closed: boolean;
      closed_by: ClosedBy;
      protocol: "tcp";
    }
  | {
      datagrams_sent: number;
      datagrams_received: number;
      window_ms: number;
      protocol: "udp";
    };
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "GrpcStatusSource".
 */
export type GrpcStatusSource = "trailers" | "trailers_only" | "missing";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ClosedBy".
 */
export type ClosedBy = ("peer" | "client" | "timeout" | "not_closed") | "abnormal";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "WarningCode".
 */
export type WarningCode =
  | "degraded_routing"
  | "insecure_tls"
  | "partial_visibility"
  | "display_truncated"
  | "lint_bypassed"
  | "unverified_ferrum_marker"
  | "credentials_stripped_on_redirect"
  | "protocol_fallback"
  | "reused_connection"
  | "clock_skew_suspected"
  | "response_is_untrusted_content";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "JwtAlgorithm".
 */
export type JwtAlgorithm = "HS256" | "HS384" | "HS512" | "RS256" | "ES256";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "OAuthGrant".
 */
export type OAuthGrant = ("client_credentials" | "refresh_token") | "authorization_code_pkce";
/**
 * Auth configuration. Applied after interpolation, content-type inference
 * and serialization so body-dependent signatures cover the final bytes.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "AuthConfig".
 */
export type AuthConfig =
  | {
      type: "inherit";
    }
  | {
      type: "none";
    }
  | {
      name: string;
      value: SensitiveValue;
      /**
       * Where an API key is presented.
       */
      location?: "header" | "query" | "cookie";
      type: "api_key";
    }
  | {
      username: string;
      password: SensitiveValue;
      type: "basic";
    }
  | {
      token: SensitiveValue;
      prefix?: string;
      type: "bearer";
    }
  | {
      algorithm: JwtAlgorithm;
      /**
       * A field that may carry sensitive material (password, token, key).
       *
       * * `Template` — text that may contain `{{variable}}` references. A literal
       *   (non-variable) template in a sensitive field is itself treated as
       *   sensitive: it is masked in the UI, redacted in history, and replaced by a
       *   placeholder in safe-share exports.
       * * `Secret` — a vault reference.
       */
      signing_key:
        | {
            value: string;
            kind: "template";
          }
        | {
            secret: SecretRef;
            kind: "secret";
          };
      claims: JwtClaims;
      kid?: string | null;
      /**
       * Header carrying the token (default `Authorization: Bearer`).
       */
      header_name?: string;
      prefix?: string;
      type: "jwt";
    }
  | {
      config: OAuth2Config;
      type: "oauth2";
    }
  | {
      config: HmacConfig;
      type: "hmac";
    }
  | {
      config: DpopConfig;
      type: "dpop";
    }
  | {
      config: WsseConfig;
      type: "wsse";
    }
  | {
      profiles: AuthConfig[];
      type: "multi";
    };
/**
 * Explicit user decision that a destination is a Ferrum Edge gateway.
 *
 * Without such a profile a `X-Gateway-Error` header is only a "Ferrum-like
 * marker" from an unverified peer: any server can emit that header.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "IntegrationProfile".
 */
export type IntegrationProfile = IntegrationProfile1 & IntegrationProfile2;
export type IntegrationProfile1 = {
  /**
   * Hosts (and optional ports) that are this gateway's frontends.
   */
  hosts: HostBinding[];
  /**
   * Compatibility catalog id, e.g. `ferrum-edge-0.9.5`.
   */
  compatibility_id: string;
  /**
   * Only treat markers as gateway-authored when the TLS peer was
   * verified. Plain-HTTP trust is allowed only for explicitly marked
   * local/lab destinations and caps confidence at `likely`.
   */
  require_verified_tls?: boolean;
  /**
   * Optional authorized diagnostic detail endpoint (proposed gateway
   * contract; unavailable on current releases).
   */
  detail?: DiagnosticDetailAccess | null;
  /**
   * Link to Foundry/Nexus for read-only context (never auto-edited).
   */
  console_url?: string | null;
  kind: "ferrum_gateway";
};
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Workload".
 */
export type Workload =
  | {
      stages: Stage[];
      think_time_ms?: number;
      model: "closed_virtual_users";
    }
  | {
      stages: Stage[];
      max_in_flight: number;
      model: "open_arrival_rate";
    }
  | {
      iterations: number;
      concurrency: number;
      model: "iterations";
    };
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "RunCompletion".
 */
export type RunCompletion = "completed" | "canceled_by_user" | "aborted_by_rule" | "worker_crashed" | "stopped_by_lock";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ProxyKind".
 */
export type ProxyKind = "socks5" | "http" | "https";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "MultipartPart".
 */
export type MultipartPart = {
  name: string;
  enabled?: boolean;
  content_type?: string | null;
} & MultipartPart1;
export type MultipartPart1 =
  | {
      value: string;
      part_kind: "text";
    }
  | {
      attachment: AttachmentRef;
      file_name?: string | null;
      part_kind: "file";
    };
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "SoapVersion".
 */
export type SoapVersion = "soap11" | "soap12";
/**
 * Declarative, no-code assertion. Assertion failures are reported separately
 * from transport and application failures.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Assertion".
 */
export type Assertion = {
  enabled?: boolean;
  label?: string;
} & Assertion1;
export type Assertion1 =
  | {
      comparison: Comparison;
      value: string;
      type: "status";
    }
  | {
      values: number[];
      type: "status_in";
    }
  | {
      name: string;
      comparison: Comparison;
      value?: string;
      type: "header";
    }
  | {
      name: string;
      comparison: Comparison;
      value?: string;
      type: "trailer";
    }
  | {
      path: string;
      comparison: Comparison;
      value?: string;
      type: "json_path";
    }
  | {
      path: string;
      comparison: Comparison;
      value?: string;
      type: "x_path";
    }
  | {
      schema: string;
      type: "json_schema";
    }
  | {
      comparison: Comparison;
      value?: string;
      type: "body";
    }
  | {
      max: number;
      type: "latency_ms";
    }
  | {
      code: number;
      type: "grpc_status";
    }
  | {
      comparison: Comparison;
      value: number;
      type: "message_count";
    }
  | {
      code: string;
      present: boolean;
      type: "diagnostic";
    }
  | {
      state: string;
      type: "transport";
    };
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Comparison".
 */
export type Comparison =
  | "equals"
  | "not_equals"
  | "contains"
  | "not_contains"
  | "matches"
  | "exists"
  | "not_exists"
  | "less_than"
  | "greater_than";
/**
 * Extract a response value into an iteration-local variable for chaining.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Extraction".
 */
export type Extraction = {
  variable: string;
  /**
   * Treat the extracted value as sensitive (masked, redacted from reports).
   */
  sensitive?: boolean;
} & Extraction1;
export type Extraction1 =
  | {
      path: string;
      from: "json_path";
    }
  | {
      path: string;
      from: "x_path";
    }
  | {
      name: string;
      from: "header";
    }
  | {
      pattern: string;
      group?: number;
      from: "regex";
    }
  | {
      from: "status";
    };
/**
 * Where gRPC message schemas come from.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "GrpcSchemaSource".
 */
export type GrpcSchemaSource =
  | {
      files: AttachmentRef[];
      kind: "proto_files";
    }
  | {
      attachment: AttachmentRef;
      kind: "descriptor_set";
    }
  | {
      kind: "reflection";
    };
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "WsMessage".
 */
export type WsMessage =
  | {
      text: string;
      kind: "text";
    }
  | {
      hex: string;
      kind: "binary";
    }
  | {
      hex: string;
      kind: "ping";
    }
  | {
      code: number;
      reason: string;
      kind: "close";
    };
/**
 * Commands for an interactive session (WebSocket / TCP / UDP / bidi gRPC).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "SessionCommand".
 */
export type SessionCommand =
  | {
      text: string;
      command: "send_text";
    }
  | {
      hex: string;
      command: "send_binary_hex";
    }
  | {
      command: "ping";
    }
  | {
      code: number;
      reason: string;
      command: "close";
    }
  | {
      command: "half_close";
    };
/**
 * Client identity presented to a peer (identity #2 in the plan's three
 * identities). Never the gateway's own backend identity.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ClientIdentity".
 */
export type ClientIdentity =
  | {
      /**
       * Certificate chain PEM (not secret).
       */
      cert_chain_pem: string;
      /**
       * A field that may carry sensitive material (password, token, key).
       *
       * * `Template` — text that may contain `{{variable}}` references. A literal
       *   (non-variable) template in a sensitive field is itself treated as
       *   sensitive: it is masked in the UI, redacted in history, and replaced by a
       *   placeholder in safe-share exports.
       * * `Secret` — a vault reference.
       */
      private_key_pem:
        | {
            value: string;
            kind: "template";
          }
        | {
            secret: SecretRef;
            kind: "secret";
          };
      format: "pem";
    }
  | {
      /**
       * A field that may carry sensitive material (password, token, key).
       *
       * * `Template` — text that may contain `{{variable}}` references. A literal
       *   (non-variable) template in a sensitive field is itself treated as
       *   sensitive: it is masked in the UI, redacted in history, and replaced by a
       *   placeholder in safe-share exports.
       * * `Secret` — a vault reference.
       */
      bundle_b64:
        | {
            value: string;
            kind: "template";
          }
        | {
            secret: SecretRef;
            kind: "secret";
          };
      password: SensitiveValue;
      format: "pkcs12";
    };
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ProtectionMode".
 */
export type ProtectionMode = "os_keychain" | "passphrase";
/**
 * Where an API key is presented.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "KeyLocation".
 */
export type KeyLocation = "header" | "query" | "cookie";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "OAuthClientAuth".
 */
export type OAuthClientAuth = "basic_header" | "request_body";
/**
 * HMAC request signing profile. `FerrumV2` is the gateway's current
 * single-use profile; `FerrumV1Legacy` is disabled unless the user explicitly
 * enables the unsafe compatibility option.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "HmacProfile".
 */
export type HmacProfile = "ferrum_v2" | "ferrum_v1_legacy";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "HmacAlgorithm".
 */
export type HmacAlgorithm = "hmac_sha256" | "hmac_sha384" | "hmac_sha512";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "BodyDigestHeader".
 */
export type BodyDigestHeader = "content_digest" | "legacy_digest";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "WssePasswordType".
 */
export type WssePasswordType = "password_text" | "password_digest";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ConnectionMode".
 */
export type ConnectionMode = "persistent" | "fresh";
/**
 * Request body model. Serialization (and content-type inference) happens in
 * the engine before any body-dependent signing.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Body".
 */
export type Body =
  | {
      type: "none";
    }
  | {
      text: string;
      content_type?: string | null;
      type: "raw";
    }
  | {
      text: string;
      type: "json";
    }
  | {
      text: string;
      type: "xml";
    }
  | {
      fields: KeyValue[];
      type: "form_url_encoded";
    }
  | {
      parts: MultipartPart[];
      type: "multipart";
    }
  | {
      attachment: AttachmentRef;
      content_type?: string | null;
      type: "binary";
    }
  | {
      query: string;
      variables?: string;
      operation_name?: string | null;
      type: "graphql";
    }
  | {
      version: SoapVersion;
      envelope: string;
      action?: string | null;
      type: "soap";
    };
/**
 * Policy for sending a body whose syntax lint failed. Anvil is a testing
 * client, so invalid JSON/XML is sendable by explicit choice.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "LintSendPolicy".
 */
export type LintSendPolicy = "block" | "warn" | "off";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "GrpcMode".
 */
export type GrpcMode = "unary" | "client_streaming" | "server_streaming" | "bidirectional";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "WsBootstrap".
 */
export type WsBootstrap = "http1_upgrade" | "http2_extended_connect" | "http3_extended_connect";
/**
 * Framing presets for raw TCP exchanges. Arbitrary bytes are never assumed to
 * be a known application protocol.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TcpFraming".
 */
export type TcpFraming = "none" | "newline_delimited" | "length_prefixed_u16" | "length_prefixed_u32";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "PayloadEncoding".
 */
export type PayloadEncoding = "text" | "hex" | "base64";
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TlsMinVersion".
 */
export type TlsMinVersion = "tls12" | "tls13";

export interface AnvilContracts {
  AppSettings?: AppSettings;
  Dataset?: Dataset;
  DiagnosticFinding?: DiagnosticFinding;
  EffectiveSettings?: EffectiveSettings;
  Environment?: Environment;
  ExecutionEvent?: ExecutionEvent;
  ExecutionRecord?: ExecutionRecord;
  Folder?: Folder;
  IntegrationProfile?: IntegrationProfile;
  LoadPlan?: LoadPlan;
  LoadReport?: LoadReport;
  ProxyProfile?: ProxyProfile;
  RequestDefinition?: RequestDefinition;
  RequestRevision?: RequestRevision;
  RequestSpec?: RequestSpec;
  Scenario?: Scenario;
  SessionCommand?: SessionCommand;
  TlsProfile?: TlsProfile;
  UserProfile?: UserProfile;
  Workspace?: Workspace;
}
/**
 * Portable application settings (included in whole-app backups).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "AppSettings".
 */
export interface AppSettings {
  schema_version: number;
  defaults: SettingsOverrides;
  theme: Theme;
  history: HistoryPolicy;
  lock: LockPolicy;
  autosave: boolean;
  /**
   * Extra header/query/cookie/body-field names always treated as secrets
   * by the redactor (in addition to built-in patterns).
   */
  redaction_names: string[];
  check_for_updates: boolean;
}
/**
 * Non-secret request settings resolved deterministically:
 * app defaults → workspace → ancestor folders → request → run override.
 * Every field is optional at each layer; `None` inherits.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "SettingsOverrides".
 */
export interface SettingsOverrides {
  http_version?: HttpVersionPolicy | null;
  timeouts?: TimeoutOverrides | null;
  redirects?: RedirectPolicy | null;
  retries?: RetryPolicy | null;
  ip_preference?: IpPreference | null;
  resolver?: ResolverMode | null;
  dns_overrides?: DnsOverride[];
  proxy_profile_id?: ProxySelection | null;
  tls_profile_id?: Id | null;
  limits?: Limits | null;
  decompress?: boolean | null;
  cookies?: boolean | null;
  keepalive?: boolean | null;
  infer_content_type?: boolean | null;
  integration_profile_id?: Id | null;
}
/**
 * Partial timeout overrides (each class independently inheritable).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TimeoutOverrides".
 */
export interface TimeoutOverrides {
  dns_ms?: number | null;
  connect_ms?: number | null;
  tls_handshake_ms?: number | null;
  request_write_ms?: number | null;
  response_headers_ms?: number | null;
  body_idle_ms?: number | null;
  total_ms?: number | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "RedirectPolicy".
 */
export interface RedirectPolicy {
  follow: boolean;
  max: number;
  /**
   * Forward `Authorization`/cookies/client identity to a different origin.
   * Off by default; the target's own configuration applies otherwise.
   */
  forward_credentials_cross_origin: boolean;
}
/**
 * Automatic retry policy. Off by default. Possibly-processed non-idempotent
 * operations are never retried automatically regardless of this setting.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "RetryPolicy".
 */
export interface RetryPolicy {
  max_retries: number;
  backoff_ms: number;
  /**
   * Retry only failures proven `not_dispatched`, or idempotent methods.
   */
  only_safe: boolean;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "DnsOverride".
 */
export interface DnsOverride {
  /**
   * Host name to override (exact, case-insensitive).
   */
  host: string;
  /**
   * Addresses to connect to instead of resolving.
   */
  addresses: string[];
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Limits".
 */
export interface Limits {
  /**
   * Hard ceiling on response body bytes read from the wire; exceeded bodies
   * end with a local `response_too_large` outcome (never a peer fault).
   */
  max_response_bytes: number;
  /**
   * Bytes retained for display/history; beyond this the body is still read
   * and counted but marked display-truncated.
   */
  capture_bytes: number;
  /**
   * Ceiling on decompressed size.
   */
  max_decoded_bytes: number;
  max_response_header_bytes: number;
  max_request_body_bytes: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "HistoryPolicy".
 */
export interface HistoryPolicy {
  enabled: boolean;
  keep_response_bodies: boolean;
  max_age_days: number;
  max_total_bytes: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "LockPolicy".
 */
export interface LockPolicy {
  /**
   * Lock after this many minutes of inactivity (0 = never).
   */
  idle_minutes: number;
  lock_on_os_lock: boolean;
  run_policy: LockRunPolicy;
  clear_clipboard_on_lock: boolean;
}
/**
 * Iteration data (CSV rows / JSON array of objects).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Dataset".
 */
export interface Dataset {
  id: Id;
  schema_version: number;
  created_at: string;
  updated_at: string;
  workspace_id: Id;
  name: string;
  format: DatasetFormat;
  attachment: AttachmentRef;
  /**
   * Columns that hold secrets (masked and redacted in reports).
   */
  sensitive_columns?: string[];
}
/**
 * A single diagnostic claim with its evidence and confidence.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "DiagnosticFinding".
 */
export interface DiagnosticFinding {
  /**
   * Stable finding code, e.g. `client.tls.untrusted_issuer`.
   */
  code: string;
  rule_id: string;
  rule_version: number;
  title: string;
  explanation: string;
  scope: SourceScope;
  confidence: Confidence;
  severity: Severity;
  evidence: Evidence[];
  /**
   * Other explanations consistent with the same evidence.
   */
  alternatives: string[];
  /**
   * Statements this evidence does NOT establish (shown explicitly).
   */
  does_not_prove: string[];
  remediation: Remediation[];
  owner: Owner;
  /**
   * What additional evidence would confirm or refute the claim.
   */
  confirm_with: string[];
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Evidence".
 */
export interface Evidence {
  source: EvidenceSource;
  /**
   * Machine key, e.g. `failure.kind`, `header.x-gateway-error`, `tls.alert`.
   */
  key: string;
  /**
   * Redacted value as observed.
   */
  value: string;
  attempt?: number | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Remediation".
 */
export interface Remediation {
  text: string;
  owner: Owner;
}
/**
 * Fully-resolved settings used for one execution, with the layer each value
 * came from (for the Effective Request inspector).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "EffectiveSettings".
 */
export interface EffectiveSettings {
  http_version: HttpVersionPolicy;
  timeouts: Timeouts;
  redirects: RedirectPolicy;
  retries: RetryPolicy;
  ip_preference: IpPreference;
  resolver: ResolverMode;
  dns_overrides: DnsOverride[];
  proxy_profile_id?: Id | null;
  tls_profile_id?: Id | null;
  limits: Limits;
  decompress: boolean;
  cookies: boolean;
  keepalive: boolean;
  infer_content_type: boolean;
  integration_profile_id?: Id | null;
  /**
   * Field path → layer label ("app", "workspace", "folder:<name>", "request", "run").
   */
  sources: SettingSource[];
}
/**
 * Separate timeout classes. `None` means "no deadline for this phase" (the
 * total deadline still applies). Values are milliseconds.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Timeouts".
 */
export interface Timeouts {
  dns_ms?: number | null;
  connect_ms?: number | null;
  tls_handshake_ms?: number | null;
  /**
   * Deadline for handing the complete request (headers + body) to the connection.
   */
  request_write_ms?: number | null;
  /**
   * Deadline from request sent to response headers.
   */
  response_headers_ms?: number | null;
  /**
   * Maximum idle gap between response body chunks.
   */
  body_idle_ms?: number | null;
  /**
   * Whole-attempt deadline.
   */
  total_ms?: number | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "SettingSource".
 */
export interface SettingSource {
  field: string;
  layer: string;
}
/**
 * Common persistent metadata.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Environment".
 */
export interface Environment {
  id: Id;
  schema_version: number;
  created_at: string;
  updated_at: string;
  workspace_id: Id;
  name: string;
  variables?: Variable[];
}
/**
 * Variable in a workspace base set, an environment, a folder or a request.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Variable".
 */
export interface Variable {
  name: string;
  value: SensitiveValue;
  /**
   * Secret variables are masked, redacted from history/reports and replaced
   * by placeholders in safe-share exports.
   */
  secret?: boolean;
  enabled?: boolean;
  description?: string;
}
/**
 * Reference to a value held in the encrypted vault. The value itself never
 * appears in ordinary object graphs, logs or safe-share exports.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "SecretRef".
 */
export interface SecretRef {
  id: Id;
  /**
   * Human label shown in the UI and in export previews ("prod API key").
   */
  label: string;
}
/**
 * One message/event/datagram in a session transcript (bounded preview).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "StreamMessage".
 */
export interface StreamMessage {
  direction: Direction;
  offset_us: number;
  /**
   * `text`, `binary`, `ping`, `pong`, `close`, `event`, `grpc_message`, `datagram`, `bytes`.
   */
  kind: string;
  size: number;
  /**
   * UTF-8 preview or hex (bounded).
   */
  preview: string;
  preview_is_hex: boolean;
  preview_truncated: boolean;
  event_id?: string | null;
  event_type?: string | null;
}
/**
 * Complete record of one execution (possibly several attempts).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ExecutionRecord".
 */
export interface ExecutionRecord {
  id: Id;
  schema_version: number;
  adapter_version: string;
  catalog_version: string;
  compatibility_id?: string | null;
  workspace_id?: Id | null;
  request_id?: Id | null;
  revision_id?: Id | null;
  environment_id?: Id | null;
  started_at: string;
  finished_at: string;
  prepared: PreparedSummary;
  attempts: AttemptObservation[];
  response?: ResponseRecord | null;
  stream?: StreamTranscript | null;
  outcome: ExecutionOutcome;
  assertion_results: AssertionResult[];
  /**
   * Extracted variable names (values are run-local and not persisted here).
   */
  extracted: string[];
  findings: DiagnosticFinding[];
}
/**
 * Summary of the prepared request as it was actually sent (redacted).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "PreparedSummary".
 */
export interface PreparedSummary {
  protocol: Protocol;
  method: string;
  url: string;
  headers: HeaderEntry[];
  body_bytes: number;
  body_sha256?: string | null;
  content_type?: string | null;
  /**
   * `api_key(header X-API-Key)`, `mtls(CN=...)`, etc. Never the secret.
   */
  auth_label: string;
  tls_profile?: string | null;
  proxy?: string | null;
  tls_verification_enabled: boolean;
  settings: EffectiveSettings;
  /**
   * Headers Anvil added or inferred, and why.
   */
  inferred: string[];
  /**
   * Secrets omitted from this summary (labels only).
   */
  omitted_secrets: string[];
}
/**
 * Header entry (order and duplicates preserved).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "HeaderEntry".
 */
export interface HeaderEntry {
  name: string;
  value: string;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "AttemptObservation".
 */
export interface AttemptObservation {
  index: number;
  reason: AttemptReason;
  method: string;
  /**
   * Redacted URL.
   */
  url: string;
  started_at: string;
  connection?: ConnectionObservation | null;
  phases: PhaseTiming[];
  dispatch: DispatchState;
  bytes: ByteCounts;
  response_status?: number | null;
  failure?: TransportFailure | null;
  duration_us: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ConnectionObservation".
 */
export interface ConnectionObservation {
  /**
   * Engine-local connection id (stable within one app session).
   */
  id: number;
  reused: boolean;
  /**
   * Negotiated application protocol: `http/1.1`, `h2`, `h3`, `ws`, `tcp`, `udp`.
   */
  protocol?: string | null;
  local_address?: string | null;
  remote_address?: string | null;
  resolved_addresses: string[];
  /**
   * Source of the addresses: `system`, `custom_resolver`, `override`, `literal`, `proxy`.
   */
  resolution_source?: string | null;
  connect_attempts: ConnectAttempt[];
  via_proxy?: string | null;
  tls?: TlsObservation | null;
  /**
   * Requests previously served on this connection (0 = fresh).
   */
  prior_requests: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ConnectAttempt".
 */
export interface ConnectAttempt {
  address: string;
  failure?: FailureKind | null;
  duration_us?: number | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TlsObservation".
 */
export interface TlsObservation {
  /**
   * SNI/verification name used.
   */
  server_name: string;
  version?: string | null;
  cipher_suite?: string | null;
  /**
   * ALPN protocols offered by the client.
   */
  alpn_offered: string[];
  alpn_negotiated?: string | null;
  verification: TlsVerification;
  /**
   * Peer chain as presented (leaf first), when received.
   */
  peer_certificates: CertificateSummary[];
  /**
   * Whether the peer sent a CertificateRequest. `None` = not observed
   * (handshake did not get that far, or resumed session).
   */
  client_certificate_requested?: boolean | null;
  /**
   * The client certificate actually presented (public data only).
   */
  client_certificate_presented?: CertificateSummary | null;
  alert_received?: string | null;
  resumed?: boolean | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "CertificateSummary".
 */
export interface CertificateSummary {
  subject: string;
  issuer: string;
  subject_alt_names: string[];
  not_before: string;
  not_after: string;
  serial_hex: string;
  sha256_fingerprint: string;
  is_ca: boolean;
  key_algorithm: string;
}
/**
 * A measured phase. Offsets are microseconds from attempt start on a
 * monotonic clock. Concurrent phases may overlap; do not sum them blindly.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "PhaseTiming".
 */
export interface PhaseTiming {
  phase: Phase;
  status: PhaseStatus;
  start_us?: number | null;
  end_us?: number | null;
  detail?: string | null;
}
/**
 * Byte accounting for one attempt. Logical header sizes on HTTP/2/3 are
 * estimates (HPACK/QPACK compress headers); `connection_*` counters are
 * connection-scoped TLS/transport bytes and include other multiplexed streams.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ByteCounts".
 */
export interface ByteCounts {
  request_headers_logical: number;
  request_headers_estimated: boolean;
  request_body: number;
  response_headers_logical?: number | null;
  response_body_wire?: number | null;
  response_body_decoded?: number | null;
  connection_bytes_written?: number | null;
  connection_bytes_read?: number | null;
}
/**
 * A typed transport failure with library detail for display. `message` is
 * sanitized display text only; diagnostic rules must use the typed fields.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TransportFailure".
 */
export interface TransportFailure {
  phase: Phase;
  kind: FailureKind;
  message: string;
  io_error_kind?: string | null;
  os_error_code?: number | null;
  /**
   * TLS alert description (e.g. `certificate_required`) when one was received.
   */
  tls_alert?: string | null;
  /**
   * HTTP/2 error code (RST_STREAM / GOAWAY) when applicable.
   */
  h2_error_code?: number | null;
  /**
   * QUIC transport/application error code when applicable.
   */
  quic_error_code?: number | null;
  /**
   * HTTP status of a rejected proxy CONNECT / WebSocket handshake.
   */
  status?: number | null;
  /**
   * Field path for local validation failures (e.g. `headers[2].value`).
   */
  field?: string | null;
  /**
   * The configured deadline that elapsed, for timeouts.
   */
  deadline_ms?: number | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ResponseRecord".
 */
export interface ResponseRecord {
  status: number;
  reason?: string | null;
  http_version: string;
  headers: HeaderEntry[];
  trailers: HeaderEntry[];
  trailers_received: boolean;
  body: BodyCapture;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "BodyCapture".
 */
export interface BodyCapture {
  completeness: BodyCompleteness;
  /**
   * Body bytes received from the wire (after transfer decoding, before content decoding).
   */
  wire_bytes: number;
  declared_length?: number | null;
  /**
   * Bytes retained for display/history.
   */
  captured_bytes: number;
  /**
   * True when more bytes were received than retained (display cap only —
   * NOT a wire failure).
   */
  display_truncated: boolean;
  content_type?: string | null;
  content_encoding?: string | null;
  decoded_bytes?: number | null;
  /**
   * Content-addressed id of the stored raw (captured) bytes.
   */
  blob_sha256?: string | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "StreamTranscript".
 */
export interface StreamTranscript {
  messages: StreamMessage[];
  /**
   * Messages dropped from the transcript because of the retention bound.
   */
  dropped_messages: number;
  sent_count: number;
  received_count: number;
  sent_bytes: number;
  received_bytes: number;
}
/**
 * The composite outcome. Transport completion, application status and
 * assertion results are deliberately separate dimensions.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ExecutionOutcome".
 */
export interface ExecutionOutcome {
  transport: TransportState;
  application: ApplicationState;
  assertions: AssertionState;
  completeness?: BodyCompleteness | null;
  protocol_status: ProtocolStatus;
  /**
   * Whether request bytes of an attempt may have reached the peer.
   *
   * Derived from typed transport state (bytes written to the socket, response
   * received, HTTP/2 `REFUSED_STREAM`, ...), never from error message text.
   */
  dispatch: "unknown" | "not_dispatched" | "sent" | "may_have_been_sent";
  warnings: OutcomeWarning[];
  /**
   * One-line human summary (derived; not authoritative).
   */
  summary: string;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "OutcomeWarning".
 */
export interface OutcomeWarning {
  code: WarningCode;
  message: string;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "AssertionResult".
 */
export interface AssertionResult {
  label: string;
  passed: boolean;
  /**
   * Redacted observed value.
   */
  actual?: string | null;
  message: string;
}
/**
 * Common persistent metadata.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Folder".
 */
export interface Folder {
  id: Id;
  schema_version: number;
  created_at: string;
  updated_at: string;
  workspace_id: Id;
  /**
   * `None` = top level of the workspace.
   */
  parent_id?: Id | null;
  name: string;
  description?: string;
  /**
   * Fractional ordering key among siblings.
   */
  sort_key: number;
  settings?: SettingsOverrides1;
  variables?: Variable[];
  /**
   * Auth configuration. Applied after interpolation, content-type inference
   * and serialization so body-dependent signatures cover the final bytes.
   */
  auth?:
    | {
        type: "inherit";
      }
    | {
        type: "none";
      }
    | {
        name: string;
        value: SensitiveValue;
        /**
         * Where an API key is presented.
         */
        location?: "header" | "query" | "cookie";
        type: "api_key";
      }
    | {
        username: string;
        password: SensitiveValue;
        type: "basic";
      }
    | {
        token: SensitiveValue;
        prefix?: string;
        type: "bearer";
      }
    | {
        algorithm: JwtAlgorithm;
        /**
         * A field that may carry sensitive material (password, token, key).
         *
         * * `Template` — text that may contain `{{variable}}` references. A literal
         *   (non-variable) template in a sensitive field is itself treated as
         *   sensitive: it is masked in the UI, redacted in history, and replaced by a
         *   placeholder in safe-share exports.
         * * `Secret` — a vault reference.
         */
        signing_key:
          | {
              value: string;
              kind: "template";
            }
          | {
              secret: SecretRef;
              kind: "secret";
            };
        claims: JwtClaims;
        kid?: string | null;
        /**
         * Header carrying the token (default `Authorization: Bearer`).
         */
        header_name?: string;
        prefix?: string;
        type: "jwt";
      }
    | {
        config: OAuth2Config;
        type: "oauth2";
      }
    | {
        config: HmacConfig;
        type: "hmac";
      }
    | {
        config: DpopConfig;
        type: "dpop";
      }
    | {
        config: WsseConfig;
        type: "wsse";
      }
    | {
        profiles: AuthConfig[];
        type: "multi";
      };
  tags?: string[];
}
/**
 * Non-secret request settings resolved deterministically:
 * app defaults → workspace → ancestor folders → request → run override.
 * Every field is optional at each layer; `None` inherits.
 */
export interface SettingsOverrides1 {
  http_version?: HttpVersionPolicy | null;
  timeouts?: TimeoutOverrides | null;
  redirects?: RedirectPolicy | null;
  retries?: RetryPolicy | null;
  ip_preference?: IpPreference | null;
  resolver?: ResolverMode | null;
  dns_overrides?: DnsOverride[];
  proxy_profile_id?: ProxySelection | null;
  tls_profile_id?: Id | null;
  limits?: Limits | null;
  decompress?: boolean | null;
  cookies?: boolean | null;
  keepalive?: boolean | null;
  infer_content_type?: boolean | null;
  integration_profile_id?: Id | null;
}
/**
 * Claims editor for the JWT helper. Anvil signs only with key material the
 * user supplies; it never invents an issuer or a gateway token endpoint.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "JwtClaims".
 */
export interface JwtClaims {
  iss?: string | null;
  sub?: string | null;
  aud?: string | null;
  /**
   * Lifetime in seconds from signing time; `exp` is computed per send.
   */
  expires_in_secs?: number | null;
  /**
   * `nbf` offset (seconds, may be negative) relative to signing time.
   */
  not_before_offset_secs?: number | null;
  /**
   * Additional claims as a JSON object text (may contain `{{vars}}`).
   */
  extra_json?: string;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "OAuth2Config".
 */
export interface OAuth2Config {
  grant: OAuthGrant;
  token_url: string;
  authorization_url?: string;
  client_id: string;
  /**
   * A field that may carry sensitive material (password, token, key).
   *
   * * `Template` — text that may contain `{{variable}}` references. A literal
   *   (non-variable) template in a sensitive field is itself treated as
   *   sensitive: it is masked in the UI, redacted in history, and replaced by a
   *   placeholder in safe-share exports.
   * * `Secret` — a vault reference.
   */
  client_secret?:
    | {
        value: string;
        kind: "template";
      }
    | {
        secret: SecretRef;
        kind: "secret";
      };
  scope?: string;
  audience?: string;
  /**
   * How client credentials are sent to the token endpoint.
   */
  client_auth?: "basic_header" | "request_body";
  /**
   * Where the acquired access token is cached (vault) — id of the token
   * cache entry, managed by the engine.
   */
  token_cache_id?: Id | null;
  /**
   * Refresh this many seconds before expiry.
   */
  refresh_skew_secs?: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "HmacConfig".
 */
export interface HmacConfig {
  /**
   * HMAC request signing profile. `FerrumV2` is the gateway's current
   * single-use profile; `FerrumV1Legacy` is disabled unless the user explicitly
   * enables the unsafe compatibility option.
   */
  profile?: "ferrum_v2" | "ferrum_v1_legacy";
  username: string;
  secret: SensitiveValue;
  algorithm?: "hmac_sha256" | "hmac_sha384" | "hmac_sha512";
  digest_header?: "content_digest" | "legacy_digest";
  /**
   * Optional namespace bound into the signature when the gateway profile uses one.
   */
  namespace?: string;
  /**
   * Explicit opt-in required to use the replayable legacy profile.
   */
  allow_unsafe_legacy?: boolean;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "DpopConfig".
 */
export interface DpopConfig {
  /**
   * A field that may carry sensitive material (password, token, key).
   *
   * * `Template` — text that may contain `{{variable}}` references. A literal
   *   (non-variable) template in a sensitive field is itself treated as
   *   sensitive: it is masked in the UI, redacted in history, and replaced by a
   *   placeholder in safe-share exports.
   * * `Secret` — a vault reference.
   */
  access_token:
    | {
        value: string;
        kind: "template";
      }
    | {
        secret: SecretRef;
        kind: "secret";
      };
  /**
   * A field that may carry sensitive material (password, token, key).
   *
   * * `Template` — text that may contain `{{variable}}` references. A literal
   *   (non-variable) template in a sensitive field is itself treated as
   *   sensitive: it is masked in the UI, redacted in history, and replaced by a
   *   placeholder in safe-share exports.
   * * `Secret` — a vault reference.
   */
  private_key_pem:
    | {
        value: string;
        kind: "template";
      }
    | {
        secret: SecretRef;
        kind: "secret";
      };
  /**
   * Present the token as `DPoP <token>` (RFC 9449) or legacy `Bearer`.
   */
  dpop_scheme?: boolean;
  /**
   * Automatically answer a single `use_dpop_nonce` challenge with a fresh proof.
   */
  handle_nonce_challenge?: boolean;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "WsseConfig".
 */
export interface WsseConfig {
  username: string;
  password: SensitiveValue;
  password_type?: "password_text" | "password_digest";
  /**
   * Add a `wsu:Timestamp` with this lifetime.
   */
  timestamp_ttl_secs?: number | null;
  /**
   * User-provided signed SAML assertion XML to embed verbatim (Anvil never
   * mints assertions).
   */
  saml_assertion?: SensitiveValue | null;
}
/**
 * Host/port pattern a TLS profile or client identity is bound to. Wildcards
 * are allowed only as a leading `*.` label and produce a UI warning.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "HostBinding".
 */
export interface HostBinding {
  host: string;
  port?: number | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "DiagnosticDetailAccess".
 */
export interface DiagnosticDetailAccess {
  base_url: string;
  /**
   * A field that may carry sensitive material (password, token, key).
   *
   * * `Template` — text that may contain `{{variable}}` references. A literal
   *   (non-variable) template in a sensitive field is itself treated as
   *   sensitive: it is masked in the UI, redacted in history, and replaced by a
   *   placeholder in safe-share exports.
   * * `Secret` — a vault reference.
   */
  credential:
    | {
        value: string;
        kind: "template";
      }
    | {
        secret: SecretRef;
        kind: "secret";
      };
  namespace?: string | null;
}
export interface IntegrationProfile2 {
  id: Id;
  workspace_id: Id;
  name: string;
  created_at: string;
  updated_at: string;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "LoadPlan".
 */
export interface LoadPlan {
  id: Id;
  workspace_id: Id;
  name: string;
  workload: Workload;
  /**
   * A sequential chain executed per iteration (with extraction), or a
   * weighted mix (one request per iteration) when `mix` is non-empty.
   */
  chain?: Id[];
  mix?: WeightedStep[];
  dataset_id?: Id | null;
  environment_id?: Id | null;
  connection_mode?: "persistent" | "fresh";
  warmup_secs?: number;
  abort?: AbortRule | null;
  /**
   * Seed for weighted selection / generated data.
   */
  seed?: number;
  /**
   * Imported plans are never auto-started; the user must acknowledge the
   * destination and ownership reminder for each run.
   */
  trusted?: boolean;
  created_at: string;
  updated_at: string;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Stage".
 */
export interface Stage {
  duration_secs: number;
  /**
   * Target at the end of the stage (arrivals/s for open workloads, VUs for
   * closed); linear ramp from the previous stage's target.
   */
  target: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "WeightedStep".
 */
export interface WeightedStep {
  request_id: Id;
  weight?: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "AbortRule".
 */
export interface AbortRule {
  /**
   * Abort when the failure ratio over the last window exceeds this (0–1, as permille).
   */
  max_failure_permille: number;
  window_secs: number;
}
/**
 * Saved, self-describing load report. Viewable offline.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "LoadReport".
 */
export interface LoadReport {
  run_id: Id;
  schema_version: number;
  engine: string;
  engine_version: string;
  plan: LoadPlan;
  /**
   * Revision ids of the requests executed.
   */
  request_revisions: Id[];
  dataset_sha256?: string | null;
  started_at: string;
  finished_at: string;
  completion: RunCompletion;
  /**
   * True if the report is partial (cancel, crash, abort, lock).
   */
  partial: boolean;
  warmup_included_in_metrics: boolean;
  destination_summary: string[];
  counts: LoadCounts;
  /**
   * Iterations started per second over the measured window.
   */
  achieved_rate_per_sec: number;
  latency_success: LatencySummary;
  latency_failure: LatencySummary1;
  /**
   * Mergeable serialized HDR histogram (V2 + DEFLATE, base64) of success latency.
   */
  histogram_success_b64: string;
  status_distribution: [unknown, unknown][];
  failure_categories: FailureSample[];
  timeline: TimeBucket[];
  bytes_sent: number;
  bytes_received: number;
  generator: GeneratorHealth;
  notes: string[];
  requests?: RequestCounts;
  /**
   * Human label of the workload semantics (closed/open/iterations).
   */
  workload_label?: string;
  /**
   * Scheduled arrivals per second over the measured window (open workloads only).
   */
  offered_rate_per_sec?: number | null;
  /**
   * Length of the measured window (after warmup, until scheduling stopped).
   */
  measured_duration_secs?: number;
  timeouts_censored?: CensoredTimeouts;
  latency_setup?: LatencySummary3;
  /**
   * Mergeable serialized HDR histogram (V2 + DEFLATE, base64) of failure latency.
   */
  histogram_failure_b64?: string;
  /**
   * Negotiated application protocols observed (e.g. `http/1.1`, `h2`) → sends.
   */
  protocols?: [unknown, unknown][];
  warmup_iterations_excluded?: number;
  warmup_sends_excluded?: number;
  /**
   * SHA-256 of the canonical JSON of this report with this field unset;
   * verified when a saved report is reopened.
   */
  integrity_sha256?: string | null;
}
/**
 * Iteration ledger of the measured window. One *iteration* is one arrival
 * (open workload) or one pass of a virtual user / concurrency lane: a single
 * request for a weighted mix, or the whole sequential chain.
 *
 * The counts always balance:
 * * `scheduled = started + dropped` (only open workloads drop; closed and
 *   iteration workloads schedule exactly what they start);
 * * `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`
 *   — the five terminal classes are disjoint.
 *
 * `application_failures` and `assertion_failures` are *subsets* of
 * `completed` (a complete response that failed at the application level or
 * an assertion) and may overlap each other.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "LoadCounts".
 */
export interface LoadCounts {
  scheduled: number;
  started: number;
  /**
   * Open-workload arrivals not started because `max_in_flight` was reached.
   */
  dropped: number;
  /**
   * Every step of the iteration received a complete response (any status).
   */
  completed: number;
  /**
   * Ended by a transport failure other than a deadline (no complete response).
   */
  transport_failures: number;
  /**
   * Completed iterations with at least one application failure (4xx/5xx, gRPC non-OK).
   */
  application_failures: number;
  /**
   * Completed iterations with at least one failed assertion.
   */
  assertion_failures: number;
  /**
   * Ended by a deadline (censored latency; see [`CensoredTimeouts`]).
   */
  timeouts: number;
  /**
   * Ended by run cancellation (user cancel, abort rule, graceful-stop limit).
   */
  canceled: number;
  /**
   * Started but with no known outcome when the report was produced (worker
   * crash, or a send that ignored cancellation past the drain limit).
   */
  in_flight_at_end: number;
}
/**
 * Network-exchange latency (sum of attempt durations) of successful sends:
 * complete response, application success, assertions passed or not run.
 */
export interface LatencySummary {
  count: number;
  min_us: number;
  max_us: number;
  mean_us: number;
  p50_us: number;
  p90_us: number;
  p95_us: number;
  p99_us: number;
}
/**
 * Latency of failed sends to their failure point: transport failures,
 * application failures and assertion failures. Timeouts (censored) and
 * cancellations are excluded.
 */
export interface LatencySummary1 {
  count: number;
  min_us: number;
  max_us: number;
  mean_us: number;
  p50_us: number;
  p90_us: number;
  p95_us: number;
  p99_us: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "FailureSample".
 */
export interface FailureSample {
  category: string;
  count: number;
  /**
   * Up to a bounded number of representative redacted examples.
   */
  examples: string[];
}
/**
 * One timeline bucket (send level, except `dropped`, which counts arrivals).
 * Includes warmup seconds, flagged, which are excluded from summary metrics.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TimeBucket".
 */
export interface TimeBucket {
  /**
   * Bucket start, seconds from run start.
   */
  second: number;
  /**
   * Sends started in the bucket.
   */
  started: number;
  /**
   * Sends that received a complete response in the bucket (any status).
   */
  completed: number;
  /**
   * Sends that failed in the bucket (transport, timeout, application or assertion).
   */
  failures: number;
  /**
   * Arrivals dropped in the bucket (open workloads).
   */
  dropped: number;
  /**
   * Successful-send latency percentiles of sends completing in the bucket.
   */
  p50_us: number;
  p99_us: number;
  /**
   * Peak sends in flight during the bucket.
   */
  in_flight: number;
  warmup?: boolean;
  /**
   * p99 start lag (scheduled arrival → actual start) of arrivals in the bucket.
   */
  p99_schedule_lag_us?: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "GeneratorHealth".
 */
export interface GeneratorHealth {
  /**
   * Peak process CPU (user + system time over wall time; 100 = one core).
   * `None` when the platform measurement is unavailable.
   */
  peak_cpu_percent?: number | null;
  peak_rss_bytes?: number | null;
  /**
   * Peak open file descriptors (sockets included), when measurable.
   */
  peak_open_fds?: number | null;
  /**
   * Maximum observed lag between a scheduled arrival and its start.
   */
  max_schedule_lag_us: number;
  p99_schedule_lag_us: number;
  /**
   * True when the generator could not sustain the planned target.
   */
  target_not_achieved: boolean;
  notes: string[];
}
/**
 * Send ledger (see [`RequestCounts`]); equals `counts` for single-request iterations.
 */
export interface RequestCounts {
  started: number;
  completed: number;
  transport_failures: number;
  timeouts: number;
  canceled: number;
  in_flight_at_end: number;
  /**
   * Subset of `completed`.
   */
  application_failures: number;
  /**
   * Subset of `completed`.
   */
  assertion_failures: number;
  /**
   * Attempts that opened a new connection (engine evidence).
   */
  connections_opened: number;
  /**
   * Attempts served on a reused pooled connection.
   */
  connections_reused: number;
}
/**
 * Sends abandoned at a deadline. Their elapsed time is a *lower bound* on the
 * latency the target would have produced, so they are excluded from both
 * latency distributions and summarised separately.
 */
export interface CensoredTimeouts {
  count: number;
  /**
   * Smallest / largest configured deadline that elapsed, when recorded.
   */
  deadline_ms_min?: number | null;
  deadline_ms_max?: number | null;
  elapsed_at_timeout: LatencySummary2;
  label: string;
}
/**
 * Elapsed time when each send was abandoned (censored values, not latencies).
 */
export interface LatencySummary2 {
  count: number;
  min_us: number;
  max_us: number;
  mean_us: number;
  p50_us: number;
  p90_us: number;
  p95_us: number;
  p99_us: number;
}
/**
 * Local time around the network exchange: preparation, token
 * acquisition/refresh, retry backoff and record assembly.
 */
export interface LatencySummary3 {
  count: number;
  min_us: number;
  max_us: number;
  mean_us: number;
  p50_us: number;
  p90_us: number;
  p95_us: number;
  p99_us: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ProxyProfile".
 */
export interface ProxyProfile {
  id: Id;
  workspace_id: Id;
  name: string;
  kind: ProxyKind;
  /**
   * `host:port` of the proxy.
   */
  address: string;
  username?: string | null;
  password?: SensitiveValue | null;
  /**
   * `NO_PROXY` semantics: comma-separated hosts/suffixes/CIDRs, `*` for all.
   */
  no_proxy?: string;
  created_at: string;
  updated_at: string;
}
/**
 * Common persistent metadata.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "RequestDefinition".
 */
export interface RequestDefinition {
  id: Id;
  schema_version: number;
  created_at: string;
  updated_at: string;
  workspace_id: Id;
  folder_id?: Id | null;
  name: string;
  description?: string;
  tags?: string[];
  favorite?: boolean;
  sort_key: number;
  spec: RequestSpec;
  /**
   * Latest immutable revision id (updated on explicit save).
   */
  revision_id?: Id | null;
}
/**
 * The editable, serializable definition of a request. Execution never
 * mutates it; a run snapshots it as an immutable [`crate::workspace::RequestRevision`].
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "RequestSpec".
 */
export interface RequestSpec {
  /**
   * Wire protocol family of a saved request. SOAP and GraphQL are HTTP body
   * kinds, not separate transports.
   */
  protocol?: "http" | "web_socket" | "grpc" | "sse" | "tcp" | "udp";
  /**
   * HTTP method (ignored for non-HTTP protocols).
   */
  method?: string;
  /**
   * URL template (may contain `{{variables}}`). For TCP/UDP: `tcp://host:port`,
   * `tls://host:port`, `udp://host:port`, `dtls://host:port`.
   */
  url: string;
  params?: KeyValue[];
  headers?: KeyValue[];
  /**
   * Request body model. Serialization (and content-type inference) happens in
   * the engine before any body-dependent signing.
   */
  body?:
    | {
        type: "none";
      }
    | {
        text: string;
        content_type?: string | null;
        type: "raw";
      }
    | {
        text: string;
        type: "json";
      }
    | {
        text: string;
        type: "xml";
      }
    | {
        fields: KeyValue[];
        type: "form_url_encoded";
      }
    | {
        parts: MultipartPart[];
        type: "multipart";
      }
    | {
        attachment: AttachmentRef;
        content_type?: string | null;
        type: "binary";
      }
    | {
        query: string;
        variables?: string;
        operation_name?: string | null;
        type: "graphql";
      }
    | {
        version: SoapVersion;
        envelope: string;
        action?: string | null;
        type: "soap";
      };
  /**
   * Auth configuration. Applied after interpolation, content-type inference
   * and serialization so body-dependent signatures cover the final bytes.
   */
  auth?:
    | {
        type: "inherit";
      }
    | {
        type: "none";
      }
    | {
        name: string;
        value: SensitiveValue;
        /**
         * Where an API key is presented.
         */
        location?: "header" | "query" | "cookie";
        type: "api_key";
      }
    | {
        username: string;
        password: SensitiveValue;
        type: "basic";
      }
    | {
        token: SensitiveValue;
        prefix?: string;
        type: "bearer";
      }
    | {
        algorithm: JwtAlgorithm;
        /**
         * A field that may carry sensitive material (password, token, key).
         *
         * * `Template` — text that may contain `{{variable}}` references. A literal
         *   (non-variable) template in a sensitive field is itself treated as
         *   sensitive: it is masked in the UI, redacted in history, and replaced by a
         *   placeholder in safe-share exports.
         * * `Secret` — a vault reference.
         */
        signing_key:
          | {
              value: string;
              kind: "template";
            }
          | {
              secret: SecretRef;
              kind: "secret";
            };
        claims: JwtClaims;
        kid?: string | null;
        /**
         * Header carrying the token (default `Authorization: Bearer`).
         */
        header_name?: string;
        prefix?: string;
        type: "jwt";
      }
    | {
        config: OAuth2Config;
        type: "oauth2";
      }
    | {
        config: HmacConfig;
        type: "hmac";
      }
    | {
        config: DpopConfig;
        type: "dpop";
      }
    | {
        config: WsseConfig;
        type: "wsse";
      }
    | {
        profiles: AuthConfig[];
        type: "multi";
      };
  settings?: SettingsOverrides2;
  assertions?: Assertion[];
  extractions?: Extraction[];
  /**
   * Policy for sending a body whose syntax lint failed. Anvil is a testing
   * client, so invalid JSON/XML is sendable by explicit choice.
   */
  lint_policy?: "block" | "warn" | "off";
  grpc?: GrpcSpec | null;
  websocket?: WsSpec | null;
  sse?: SseSpec | null;
  tcp?: TcpSpec | null;
  udp?: UdpSpec | null;
  /**
   * Reference to the imported spec operation this request came from.
   */
  source?: ImportSource | null;
}
/**
 * Enabled/disabled name-value entry. Repeated names are legal and preserved
 * in order (headers and query parameters may repeat).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "KeyValue".
 */
export interface KeyValue {
  name: string;
  value: string;
  enabled?: boolean;
  description?: string;
  /**
   * Marks the value as sensitive for masking/redaction/export.
   */
  sensitive?: boolean;
}
/**
 * Non-secret request settings resolved deterministically:
 * app defaults → workspace → ancestor folders → request → run override.
 * Every field is optional at each layer; `None` inherits.
 */
export interface SettingsOverrides2 {
  http_version?: HttpVersionPolicy | null;
  timeouts?: TimeoutOverrides | null;
  redirects?: RedirectPolicy | null;
  retries?: RetryPolicy | null;
  ip_preference?: IpPreference | null;
  resolver?: ResolverMode | null;
  dns_overrides?: DnsOverride[];
  proxy_profile_id?: ProxySelection | null;
  tls_profile_id?: Id | null;
  limits?: Limits | null;
  decompress?: boolean | null;
  cookies?: boolean | null;
  keepalive?: boolean | null;
  infer_content_type?: boolean | null;
  integration_profile_id?: Id | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "GrpcSpec".
 */
export interface GrpcSpec {
  /**
   * Fully qualified `package.Service`.
   */
  service: string;
  method: string;
  mode?: "unary" | "client_streaming" | "server_streaming" | "bidirectional";
  schema: GrpcSchemaSource;
  /**
   * JSON messages to send in order (one for unary / server streaming).
   */
  messages: string[];
  metadata?: KeyValue[];
  /**
   * `grpc-timeout` sent to the server, if any.
   */
  deadline_ms?: number | null;
  /**
   * Use h2c (cleartext prior knowledge) for `http://` targets.
   */
  plaintext?: boolean;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "WsSpec".
 */
export interface WsSpec {
  bootstrap?: "http1_upgrade" | "http2_extended_connect" | "http3_extended_connect";
  subprotocols?: string[];
  /**
   * Messages sent after open (automation / scripted session).
   */
  messages?: WsMessage[];
  /**
   * Automation: wait for this many inbound messages before closing.
   */
  expect_messages?: number;
  max_message_bytes?: number;
  /**
   * Close the session after this idle period (automation only).
   */
  idle_close_ms?: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "SseSpec".
 */
export interface SseSpec {
  /**
   * Stop after this many events (0 = until cancel/idle/max duration).
   */
  max_events?: number;
  idle_timeout_ms?: number;
  last_event_id?: string | null;
  /**
   * Automatic reconnect is off by default; reconnect only when explicitly enabled.
   */
  reconnect?: boolean;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TcpSpec".
 */
export interface TcpSpec {
  /**
   * Use TLS (the `tls_profile` settings apply).
   */
  tls?: boolean;
  /**
   * Framing presets for raw TCP exchanges. Arbitrary bytes are never assumed to
   * be a known application protocol.
   */
  framing?: "none" | "newline_delimited" | "length_prefixed_u16" | "length_prefixed_u32";
  payloads: StreamPayload[];
  /**
   * Half-close (shutdown write) after sending, then keep reading.
   */
  half_close_after_send?: boolean;
  read_idle_ms?: number;
  max_read_bytes?: number;
  /**
   * Stop reading after this many frames (0 = until idle/close/max bytes).
   */
  expect_frames?: number;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "StreamPayload".
 */
export interface StreamPayload {
  data: string;
  encoding?: "text" | "hex" | "base64";
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "UdpSpec".
 */
export interface UdpSpec {
  /**
   * Use DTLS (the `tls_profile` settings apply).
   */
  dtls?: boolean;
  datagrams: StreamPayload[];
  /**
   * How long to wait for responses after the last datagram is sent.
   */
  response_window_ms?: number;
  max_datagrams?: number;
}
/**
 * Link from a request to the spec/collection it was imported from, used for
 * reimport diffs.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ImportSource".
 */
export interface ImportSource {
  import_id: Id;
  /**
   * Stable key: operationId when present, else `METHOD path`.
   */
  operation_key: string;
  /**
   * Hash of the generated request spec at import time (detects user edits).
   */
  generated_hash: string;
}
/**
 * Immutable snapshot of a request spec. History and run reports reference
 * revisions, so editing a request never rewrites past outcomes.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "RequestRevision".
 */
export interface RequestRevision {
  id: Id;
  request_id: Id;
  created_at: string;
  /**
   * SHA-256 of the canonical JSON of `spec`.
   */
  spec_sha256: string;
  spec: RequestSpec;
}
/**
 * Ordered chain of saved requests executed by the collection runner.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Scenario".
 */
export interface Scenario {
  id: Id;
  schema_version: number;
  created_at: string;
  updated_at: string;
  workspace_id: Id;
  name: string;
  description?: string;
  steps: ScenarioStep[];
  dataset_id?: Id | null;
  iterations?: number;
  /**
   * Stop the iteration at the first failed step.
   */
  stop_on_failure?: boolean;
  /**
   * Imported scenarios are not runnable until the user explicitly trusts them.
   */
  trusted?: boolean;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "ScenarioStep".
 */
export interface ScenarioStep {
  request_id: Id;
  enabled?: boolean;
  /**
   * Delay before this step (think time).
   */
  delay_ms?: number;
}
/**
 * Trust + identity settings for TLS/DTLS connections.
 *
 * `verify = false` means encryption stays on but the peer is not
 * authenticated. That is distinct from choosing plaintext (`http://`). A
 * bypass is scoped to the requests that select this profile, shows a
 * persistent warning, and is never activated by import.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "TlsProfile".
 */
export interface TlsProfile {
  id: Id;
  workspace_id: Id;
  name: string;
  verify?: boolean;
  use_system_roots?: boolean;
  /**
   * Additional trusted CA certificates (PEM). Scoped to this profile only;
   * never installed into the OS store.
   */
  extra_roots_pem?: string[];
  client_identity?: ClientIdentity | null;
  /**
   * Destinations where this profile's client identity may be presented.
   * Empty = any destination that selects the profile (UI warns).
   */
  bindings?: HostBinding[];
  min_version?: "tls12" | "tls13";
  /**
   * Override the SNI / verification name (advanced). The HTTP authority is unchanged.
   */
  server_name_override?: string | null;
  created_at: string;
  updated_at: string;
}
/**
 * Local profile (a selector, not an OS security boundary).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "UserProfile".
 */
export interface UserProfile {
  id: Id;
  schema_version: number;
  created_at: string;
  updated_at: string;
  display_name: string;
  protection: ProtectionMode;
  /**
   * Provider identity bound to this profile (identity only — never a key).
   */
  linked_identity?: LinkedIdentity | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "LinkedIdentity".
 */
export interface LinkedIdentity {
  /**
   * `google`, `github`, `facebook`, or `mock` (CI only).
   */
  provider: string;
  /**
   * Provider subject identifier.
   */
  subject: string;
  email?: string | null;
  linked_at: string;
  /**
   * Require a fresh provider authentication before local unlock
   * (online-only policy; offline unlock then needs the recovery path).
   */
  require_fresh_login?: boolean;
}
/**
 * Common persistent metadata.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "Workspace".
 */
export interface Workspace {
  id: Id;
  schema_version: number;
  created_at: string;
  updated_at: string;
  name: string;
  description?: string;
  settings?: SettingsOverrides3;
  variables?: Variable[];
  /**
   * Auth configuration. Applied after interpolation, content-type inference
   * and serialization so body-dependent signatures cover the final bytes.
   */
  auth?:
    | {
        type: "inherit";
      }
    | {
        type: "none";
      }
    | {
        name: string;
        value: SensitiveValue;
        /**
         * Where an API key is presented.
         */
        location?: "header" | "query" | "cookie";
        type: "api_key";
      }
    | {
        username: string;
        password: SensitiveValue;
        type: "basic";
      }
    | {
        token: SensitiveValue;
        prefix?: string;
        type: "bearer";
      }
    | {
        algorithm: JwtAlgorithm;
        /**
         * A field that may carry sensitive material (password, token, key).
         *
         * * `Template` — text that may contain `{{variable}}` references. A literal
         *   (non-variable) template in a sensitive field is itself treated as
         *   sensitive: it is masked in the UI, redacted in history, and replaced by a
         *   placeholder in safe-share exports.
         * * `Secret` — a vault reference.
         */
        signing_key:
          | {
              value: string;
              kind: "template";
            }
          | {
              secret: SecretRef;
              kind: "secret";
            };
        claims: JwtClaims;
        kid?: string | null;
        /**
         * Header carrying the token (default `Authorization: Bearer`).
         */
        header_name?: string;
        prefix?: string;
        type: "jwt";
      }
    | {
        config: OAuth2Config;
        type: "oauth2";
      }
    | {
        config: HmacConfig;
        type: "hmac";
      }
    | {
        config: DpopConfig;
        type: "dpop";
      }
    | {
        config: WsseConfig;
        type: "wsse";
      }
    | {
        profiles: AuthConfig[];
        type: "multi";
      };
  active_environment_id?: Id | null;
}
/**
 * Non-secret request settings resolved deterministically:
 * app defaults → workspace → ancestor folders → request → run override.
 * Every field is optional at each layer; `None` inherits.
 */
export interface SettingsOverrides3 {
  http_version?: HttpVersionPolicy | null;
  timeouts?: TimeoutOverrides | null;
  redirects?: RedirectPolicy | null;
  retries?: RetryPolicy | null;
  ip_preference?: IpPreference | null;
  resolver?: ResolverMode | null;
  dns_overrides?: DnsOverride[];
  proxy_profile_id?: ProxySelection | null;
  tls_profile_id?: Id | null;
  limits?: Limits | null;
  decompress?: boolean | null;
  cookies?: boolean | null;
  keepalive?: boolean | null;
  infer_content_type?: boolean | null;
  integration_profile_id?: Id | null;
}
/**
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "LatencySummary".
 */
export interface LatencySummary4 {
  count: number;
  min_us: number;
  max_us: number;
  mean_us: number;
  p50_us: number;
  p90_us: number;
  p95_us: number;
  p99_us: number;
}
/**
 * Send ledger of the measured window: one entry per `Engine::execute` call.
 * Balances like [`LoadCounts`]:
 * `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`.
 *
 * `completed` means a complete response was received for a request/response
 * protocol. Datagram and stream denominators (UDP datagrams sent/received,
 * WebSocket messages, gRPC stream messages) are not modelled here: the load
 * engine refuses non-HTTP requests rather than implying delivery (LOAD-013).
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "RequestCounts".
 */
export interface RequestCounts1 {
  started: number;
  completed: number;
  transport_failures: number;
  timeouts: number;
  canceled: number;
  in_flight_at_end: number;
  /**
   * Subset of `completed`.
   */
  application_failures: number;
  /**
   * Subset of `completed`.
   */
  assertion_failures: number;
  /**
   * Attempts that opened a new connection (engine evidence).
   */
  connections_opened: number;
  /**
   * Attempts served on a reused pooled connection.
   */
  connections_reused: number;
}
/**
 * Sends abandoned at a deadline. Their elapsed time is a *lower bound* on the
 * latency the target would have produced, so they are excluded from both
 * latency distributions and summarised separately.
 *
 * This interface was referenced by `AnvilContracts`'s JSON-Schema
 * via the `definition` "CensoredTimeouts".
 */
export interface CensoredTimeouts1 {
  count: number;
  /**
   * Smallest / largest configured deadline that elapsed, when recorded.
   */
  deadline_ms_min?: number | null;
  deadline_ms_max?: number | null;
  elapsed_at_timeout: LatencySummary2;
  label: string;
}
