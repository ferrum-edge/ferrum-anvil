// Request editor. Edits a draft RequestDefinition; nothing here performs I/O
// except explicit lint/preview calls to the Rust backend.
import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type EffectiveRequest, type LintResult } from "./api";
import type {
  Assertion,
  AuthConfig,
  Body,
  Comparison,
  Extraction,
  HttpVersionPolicy,
  IntegrationProfile,
  KeyValue,
  MultipartPart,
  ProxyProfile,
  RequestDefinition,
  RequestSpec,
  SettingsOverrides,
  TlsProfile,
} from "./generated/contracts";
import { AuthEditor } from "./AuthEditor";
import { KeyValueEditor, Tabs, fmtBytes, humanize, useDebounced } from "./ui";

export interface Profiles {
  tls: TlsProfile[];
  proxy: ProxyProfile[];
  integrations: IntegrationProfile[];
}

type Sub = "params" | "headers" | "body" | "auth" | "tests" | "protocol" | "settings" | "effective";
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"];
const PROTOCOLS: { id: NonNullable<RequestSpec["protocol"]>; label: string }[] = [
  { id: "http", label: "HTTP" },
  { id: "web_socket", label: "WebSocket" },
  { id: "grpc", label: "gRPC" },
  { id: "sse", label: "SSE" },
  { id: "tcp", label: "TCP" },
  { id: "udp", label: "UDP" },
];

export function RequestEditor(props: {
  req: RequestDefinition;
  onChange: (r: RequestDefinition) => void;
  onSend: (sendAnyway: boolean) => void;
  onConnect: () => void;
  connected: boolean;
  onSave: () => void;
  onCancel: () => void;
  running: boolean;
  dirty: boolean;
  workspaceId: string;
  environmentId: string | null;
  profiles: Profiles;
}) {
  const { req } = props;
  const spec = req.spec;
  const protocol = spec.protocol ?? "http";
  const [sub, setSub] = useState<Sub>("params");
  const set = (patch: Partial<RequestSpec>) => props.onChange({ ...req, spec: { ...spec, ...patch } });
  const bodyKind = spec.body?.type ?? "none";
  const tabs: { id: Sub; label: string; count?: number }[] = [
    { id: "params", label: "Params", count: spec.params?.filter((p) => p.enabled !== false && p.name).length },
    { id: "headers", label: "Headers", count: spec.headers?.filter((p) => p.enabled !== false && p.name).length },
    ...(protocol === "http" ? [{ id: "body" as Sub, label: bodyKind === "none" ? "Body" : `Body · ${humanize(bodyKind)}` }] : [{ id: "protocol" as Sub, label: PROTOCOLS.find((p) => p.id === protocol)!.label }]),
    { id: "auth", label: "Auth" },
    { id: "tests", label: "Tests", count: (spec.assertions?.length ?? 0) + (spec.extractions?.length ?? 0) || undefined },
    { id: "settings", label: "Settings" },
    { id: "effective", label: "Effective request" },
  ];
  const activeSub = tabs.some((t) => t.id === sub) ? sub : "params";

  return (
    <>
      <form
        className="urlbar"
        onSubmit={(e) => {
          e.preventDefault();
          props.running ? props.onCancel() : props.onSend(false);
        }}
      >
        <select className="field" aria-label="Protocol" value={protocol} style={{ width: 110 }} onChange={(e) => set({ protocol: e.target.value as RequestSpec["protocol"] })}>
          {PROTOCOLS.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
        </select>
        {(protocol === "http" || protocol === "sse") && (
          <select className={`field method-select m-${spec.method ?? "GET"}`} aria-label="Method" value={spec.method ?? "GET"} onChange={(e) => set({ method: e.target.value })}>
            {METHODS.map((m) => (
              <option key={m}>{m}</option>
            ))}
          </select>
        )}
        <input
          className="field url"
          aria-label="URL"
          spellCheck={false}
          value={spec.url}
          placeholder={placeholderFor(protocol)}
          onChange={(e) => {
            const url = e.target.value;
            // A non-HTTP scheme typed into an HTTP request selects the matching protocol.
            const inferred = protocol === "http" ? protocolForScheme(url) : null;
            set(inferred ? { url, protocol: inferred } : { url });
          }}
        />
        {interactive(spec) && !props.running && (
          <button type="button" className="btn" disabled={props.connected} title="Open an interactive session: send and receive messages live" onClick={props.onConnect}>
            {props.connected ? "Connected" : "Connect"}
          </button>
        )}
        {props.running ? (
          <button type="submit" className="btn">
            Cancel
          </button>
        ) : (
          <button type="submit" className="btn primary" disabled={props.connected} title={protocol === "http" ? "Send (⌘/Ctrl+Enter)" : "Run the scripted exchange and stop (⌘/Ctrl+Enter)"}>
            {protocol === "http" ? "Send" : "Run"}
          </button>
        )}
        <button type="button" className="btn" onClick={props.onSave} disabled={!props.dirty} title="Save (⌘/Ctrl+S)">
          Save
        </button>
      </form>
      <Tabs tabs={tabs} value={activeSub} onChange={setSub} />
      <div className="pane">
        {activeSub === "params" && <KeyValueEditor rows={spec.params ?? []} onChange={(params) => set({ params })} nameLabel="Query parameter" />}
        {activeSub === "headers" && (
          <div className="col">
            <KeyValueEditor rows={spec.headers ?? []} onChange={(headers) => set({ headers })} nameLabel="Header" />
            <p className="hint">Content-Type, Content-Length and auth headers are added at send time; the Effective request tab shows exactly what will be sent and why.</p>
          </div>
        )}
        {activeSub === "body" && <BodyEditor spec={spec} set={set} />}
        {activeSub === "protocol" && <ProtocolEditor spec={spec} set={set} />}
        {activeSub === "auth" && <AuthEditor value={(spec.auth as AuthConfig) ?? { type: "inherit" }} onChange={(auth) => set({ auth })} workspaceId={props.workspaceId} />}
        {activeSub === "tests" && <TestsEditor spec={spec} set={set} />}
        {activeSub === "settings" && <SettingsEditor spec={spec} set={set} profiles={props.profiles} />}
        {activeSub === "effective" && <EffectivePanel req={req} workspaceId={props.workspaceId} environmentId={props.environmentId} />}
      </div>
    </>
  );
}

function protocolForScheme(url: string): RequestSpec["protocol"] | null {
  const m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(url.trim());
  switch (m?.[1].toLowerCase()) {
    case "ws":
    case "wss":
      return "web_socket";
    case "tcp":
    case "tls":
      return "tcp";
    case "udp":
    case "dtls":
      return "udp";
    default:
      return null;
  }
}

/** Protocols with an interactive session mode. */
function interactive(spec: RequestSpec): boolean {
  const p = spec.protocol ?? "http";
  if (p === "web_socket" || p === "tcp" || p === "udp" || p === "sse") return true;
  return p === "grpc" && (spec.grpc?.mode === "client_streaming" || spec.grpc?.mode === "bidirectional");
}

function placeholderFor(p: string): string {
  switch (p) {
    case "web_socket":
      return "wss://host/path";
    case "grpc":
      return "https://host:443  (service and method in the gRPC tab)";
    case "tcp":
      return "tcp://host:port or tls://host:port";
    case "udp":
      return "udp://host:port or dtls://host:port";
    default:
      return "https://api.example.com/v1/resource?q={{var}}";
  }
}

// ------------------------------------------------------------------ body

const BODY_KINDS: { id: Body["type"]; label: string }[] = [
  { id: "none", label: "None" },
  { id: "json", label: "JSON" },
  { id: "xml", label: "XML" },
  { id: "raw", label: "Raw text" },
  { id: "form_url_encoded", label: "Form (urlencoded)" },
  { id: "multipart", label: "Multipart form" },
  { id: "binary", label: "Binary file" },
  { id: "graphql", label: "GraphQL" },
  { id: "soap", label: "SOAP" },
];

function bodyDefault(t: Body["type"], prev?: Body): Body | undefined {
  const text = prev && "text" in prev ? prev.text : "";
  switch (t) {
    case "none":
      return { type: "none" };
    case "json":
      return { type: "json", text: text || "{\n  \n}" };
    case "xml":
      return { type: "xml", text: text || '<?xml version="1.0" encoding="UTF-8"?>\n' };
    case "raw":
      return { type: "raw", text, content_type: "text/plain" };
    case "form_url_encoded":
      return { type: "form_url_encoded", fields: [] };
    case "multipart":
      return { type: "multipart", parts: [] };
    case "graphql":
      return { type: "graphql", query: "query {\n  \n}", variables: "{}" };
    case "soap":
      return {
        type: "soap",
        version: "soap11",
        envelope: '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">\n  <soapenv:Header/>\n  <soapenv:Body>\n  </soapenv:Body>\n</soapenv:Envelope>',
        action: "",
      };
    case "binary":
      return undefined;
  }
}

function BodyEditor({ spec, set }: { spec: RequestSpec; set: (p: Partial<RequestSpec>) => void }) {
  const b = (spec.body ?? { type: "none" }) as Body;
  const setBody = (body: Body) => set({ body });
  const pickBinary = async () => {
    const path = await open({ multiple: false, directory: false });
    if (typeof path !== "string") return;
    const attachment = await api.attachmentAdd(path, null);
    setBody({ type: "binary", attachment, content_type: "application/octet-stream" });
  };
  return (
    <div className="col" style={{ height: "100%" }}>
      <div className="row">
        <select
          className="field"
          aria-label="Body type"
          value={b.type}
          onChange={(e) => {
            const t = e.target.value as Body["type"];
            if (t === "binary") void pickBinary();
            else setBody(bodyDefault(t, b)!);
          }}
        >
          {BODY_KINDS.map((k) => (
            <option key={k.id} value={k.id}>
              {k.label}
            </option>
          ))}
        </select>
        {(b.type === "json" || b.type === "xml" || b.type === "soap") && (
          <label className="lbl" style={{ flexDirection: "row", alignItems: "center" }}>
            If invalid:
            <select className="field" value={spec.lint_policy ?? "warn"} onChange={(e) => set({ lint_policy: e.target.value as RequestSpec["lint_policy"] })}>
              <option value="warn">Warn and send</option>
              <option value="block">Block send</option>
              <option value="off">Don't check</option>
            </select>
          </label>
        )}
      </div>
      {b.type === "none" && <p className="hint">No body is sent.</p>}
      {(b.type === "json" || b.type === "xml") && <LintedText kind={b.type} text={b.text} onChange={(text) => setBody({ ...b, text })} />}
      {b.type === "raw" && (
        <>
          <label className="lbl" style={{ maxWidth: 320 }}>
            Content-Type
            <input className="field mono" value={b.content_type ?? ""} onChange={(e) => setBody({ ...b, content_type: e.target.value || null })} />
          </label>
          <textarea className="field grow" style={{ minHeight: 160 }} spellCheck={false} value={b.text} onChange={(e) => setBody({ ...b, text: e.target.value })} />
        </>
      )}
      {b.type === "form_url_encoded" && <KeyValueEditor rows={b.fields} onChange={(fields) => setBody({ ...b, fields })} nameLabel="Field" />}
      {b.type === "multipart" && <MultipartEditor parts={b.parts} onChange={(parts) => setBody({ ...b, parts })} />}
      {b.type === "binary" && (
        <div className="row">
          <span className="badge">{b.attachment.kind === "stored" ? `${b.attachment.file_name} · ${fmtBytes(b.attachment.size)}` : b.attachment.path}</span>
          <button className="btn small" onClick={pickBinary}>
            Choose another file…
          </button>
          <label className="lbl" style={{ flexDirection: "row", alignItems: "center" }}>
            Content-Type
            <input className="field mono" value={b.content_type ?? ""} onChange={(e) => setBody({ ...b, content_type: e.target.value || null })} />
          </label>
        </div>
      )}
      {b.type === "graphql" && (
        <>
          <label className="lbl">
            Query
            <textarea className="field" rows={8} spellCheck={false} value={b.query} onChange={(e) => setBody({ ...b, query: e.target.value })} />
          </label>
          <label className="lbl">
            Variables (JSON)
            <LintedText kind="json" text={b.variables ?? "{}"} onChange={(variables) => setBody({ ...b, variables })} rows={4} />
          </label>
          <label className="lbl" style={{ maxWidth: 320 }}>
            Operation name
            <input className="field mono" value={b.operation_name ?? ""} onChange={(e) => setBody({ ...b, operation_name: e.target.value || null })} />
          </label>
        </>
      )}
      {b.type === "soap" && (
        <>
          <div className="row">
            <label className="lbl">
              SOAP version
              <select className="field" value={b.version} onChange={(e) => setBody({ ...b, version: e.target.value as "soap11" })}>
                <option value="soap11">1.1 (text/xml + SOAPAction)</option>
                <option value="soap12">1.2 (application/soap+xml; action=)</option>
              </select>
            </label>
            <label className="lbl grow">
              Action
              <input className="field mono" value={b.action ?? ""} onChange={(e) => setBody({ ...b, action: e.target.value || null })} />
            </label>
          </div>
          <LintedText kind="xml" text={b.envelope} onChange={(envelope) => setBody({ ...b, envelope })} />
        </>
      )}
    </div>
  );
}

function LintedText(props: { kind: "json" | "xml"; text: string; onChange: (t: string) => void; rows?: number }) {
  const debounced = useDebounced(props.text, 250);
  const [lint, setLint] = useState<LintResult | null>(null);
  useEffect(() => {
    let alive = true;
    api
      .lint(props.kind, debounced)
      .then((r) => alive && setLint(r))
      .catch(() => alive && setLint(null));
    return () => {
      alive = false;
    };
  }, [debounced, props.kind]);
  const invalid = lint?.status === "invalid";
  return (
    <div className="col grow" style={{ minHeight: 0 }}>
      <textarea
        className="field grow"
        style={{ minHeight: props.rows ? undefined : 180, borderColor: invalid ? "var(--bad)" : undefined }}
        rows={props.rows}
        spellCheck={false}
        aria-invalid={invalid}
        aria-label={`${props.kind.toUpperCase()} body`}
        value={props.text}
        onChange={(e) => props.onChange(e.target.value)}
      />
      <div className="row" aria-live="polite" style={{ fontSize: 12 }}>
        {lint?.status === "valid" && <span style={{ color: "var(--ok)" }}>✓ Valid {props.kind.toUpperCase()}</span>}
        {lint?.status === "invalid" &&
          lint.issues.slice(0, 3).map((i, n) => (
            <span key={n} style={{ color: "var(--bad)" }}>
              Line {i.line}, column {i.column}: {i.message}
            </span>
          ))}
        {lint?.status === "skipped" && <span className="faint">{lint.reason}</span>}
        {props.kind === "json" && lint?.status === "valid" && (
          <button
            className="btn ghost small"
            onClick={() => {
              try {
                props.onChange(JSON.stringify(JSON.parse(props.text), null, 2));
              } catch {
                /* template variables — leave untouched */
              }
            }}
          >
            Format
          </button>
        )}
      </div>
    </div>
  );
}

function MultipartEditor({ parts, onChange }: { parts: MultipartPart[]; onChange: (p: MultipartPart[]) => void }) {
  const set = (i: number, p: MultipartPart) => onChange(parts.map((x, j) => (j === i ? p : x)));
  return (
    <div className="col">
      {parts.map((p, i) => (
        <div className="row" key={i}>
          <input type="checkbox" aria-label="Enabled" checked={p.enabled !== false} onChange={(e) => set(i, { ...p, enabled: e.target.checked })} />
          <input className="field mono" style={{ width: 180 }} placeholder="name" value={p.name} onChange={(e) => set(i, { ...p, name: e.target.value })} />
          {p.part_kind === "text" ? (
            <input className="field mono grow" placeholder="value" value={p.value} onChange={(e) => set(i, { ...p, value: e.target.value })} />
          ) : (
            <span className="badge grow">📎 {p.attachment.kind === "stored" ? `${p.attachment.file_name} · ${fmtBytes(p.attachment.size)}` : p.attachment.path}</span>
          )}
          <input className="field mono" style={{ width: 170 }} placeholder="content-type (auto)" value={p.content_type ?? ""} onChange={(e) => set(i, { ...p, content_type: e.target.value || null })} />
          <button className="btn ghost icon-btn" aria-label="Remove" onClick={() => onChange(parts.filter((_, j) => j !== i))}>
            ✕
          </button>
        </div>
      ))}
      <div className="row">
        <button className="btn small" onClick={() => onChange([...parts, { name: "", part_kind: "text", value: "", enabled: true }])}>
          + Text field
        </button>
        <button
          className="btn small"
          onClick={async () => {
            const path = await open({ multiple: false, directory: false });
            if (typeof path !== "string") return;
            const attachment = await api.attachmentAdd(path, null);
            const name = attachment.kind === "stored" ? attachment.file_name : "file";
            onChange([...parts, { name: "file", part_kind: "file", attachment, file_name: name, enabled: true }]);
          }}
        >
          + File…
        </button>
      </div>
      <p className="hint">Files are copied into the encrypted workspace so exports stay portable.</p>
    </div>
  );
}

// -------------------------------------------------------------- protocols

function ProtocolEditor({ spec, set }: { spec: RequestSpec; set: (p: Partial<RequestSpec>) => void }) {
  const p = spec.protocol ?? "http";
  if (p === "web_socket") {
    const ws = spec.websocket ?? {};
    return (
      <div className="col" style={{ maxWidth: 760 }}>
        <label className="lbl">
          Bootstrap
          <select className="field" value={ws.bootstrap ?? "http1_upgrade"} onChange={(e) => set({ websocket: { ...ws, bootstrap: e.target.value as "http1_upgrade" } })}>
            <option value="http1_upgrade">HTTP/1.1 Upgrade</option>
            <option value="http2_extended_connect">HTTP/2 extended CONNECT (RFC 8441)</option>
            <option value="http3_extended_connect">HTTP/3 extended CONNECT (RFC 9220)</option>
          </select>
        </label>
        <label className="lbl">
          Subprotocols (comma-separated)
          <input className="field mono" value={(ws.subprotocols ?? []).join(", ")} onChange={(e) => set({ websocket: { ...ws, subprotocols: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) } })} />
        </label>
        <label className="lbl">
          Messages to send after open (one text message per line)
          <textarea
            className="field"
            rows={5}
            value={(ws.messages ?? []).map((m) => (m.kind === "text" ? m.text : "")).join("\n")}
            onChange={(e) => set({ websocket: { ...ws, messages: e.target.value.split("\n").filter((l) => l.length > 0).map((text) => ({ kind: "text" as const, text })) } })}
          />
        </label>
        <div className="row">
          <NumField label="Wait for inbound messages" value={ws.expect_messages} onChange={(v) => set({ websocket: { ...ws, expect_messages: v ?? undefined } })} />
          <NumField label="Close after idle (ms)" value={ws.idle_close_ms} onChange={(v) => set({ websocket: { ...ws, idle_close_ms: v ?? undefined } })} />
        </div>
      </div>
    );
  }
  if (p === "sse") {
    const s = spec.sse ?? {};
    return (
      <div className="col" style={{ maxWidth: 760 }}>
        <div className="row">
          <NumField label="Stop after events (0 = until idle)" value={s.max_events} onChange={(v) => set({ sse: { ...s, max_events: v ?? undefined } })} />
          <NumField label="Idle timeout (ms)" value={s.idle_timeout_ms} onChange={(v) => set({ sse: { ...s, idle_timeout_ms: v ?? undefined } })} />
        </div>
        <label className="lbl">
          Last-Event-ID
          <input className="field mono" value={s.last_event_id ?? ""} onChange={(e) => set({ sse: { ...s, last_event_id: e.target.value || null } })} />
        </label>
        <label className="check">
          <input type="checkbox" checked={!!s.reconnect} onChange={(e) => set({ sse: { ...s, reconnect: e.target.checked } })} />
          Reconnect automatically (off by default)
        </label>
      </div>
    );
  }
  if (p === "grpc") {
    const g = spec.grpc ?? { service: "", method: "", schema: { kind: "reflection" as const }, messages: ["{}"] };
    return (
      <div className="col" style={{ maxWidth: 760 }}>
        <div className="row">
          <label className="lbl grow">
            Service (package.Service)
            <input className="field mono" value={g.service} onChange={(e) => set({ grpc: { ...g, service: e.target.value } })} />
          </label>
          <label className="lbl grow">
            Method
            <input className="field mono" value={g.method} onChange={(e) => set({ grpc: { ...g, method: e.target.value } })} />
          </label>
          <label className="lbl">
            Mode
            <select className="field" value={g.mode ?? "unary"} onChange={(e) => set({ grpc: { ...g, mode: e.target.value as "unary" } })}>
              <option value="unary">Unary</option>
              <option value="server_streaming">Server streaming</option>
              <option value="client_streaming">Client streaming</option>
              <option value="bidirectional">Bidirectional</option>
            </select>
          </label>
        </div>
        <label className="lbl">
          Schema source
          <select
            className="field"
            value={g.schema.kind}
            onChange={async (e) => {
              if (e.target.value === "reflection") set({ grpc: { ...g, schema: { kind: "reflection" } } });
              else {
                const path = await open({ multiple: e.target.value === "proto_files", directory: false });
                const paths = typeof path === "string" ? [path] : Array.isArray(path) ? path : [];
                if (paths.length === 0) return;
                const refs = await Promise.all(paths.map((x) => api.attachmentAdd(x, null)));
                set({ grpc: { ...g, schema: e.target.value === "proto_files" ? { kind: "proto_files", files: refs } : { kind: "descriptor_set", attachment: refs[0] } } });
              }
            }}
          >
            <option value="reflection">Server reflection</option>
            <option value="proto_files">.proto files…</option>
            <option value="descriptor_set">Descriptor set (.pb)…</option>
          </select>
        </label>
        <label className="lbl">
          Messages (JSON, one per line; unary/server streaming send the first)
          <textarea className="field" rows={5} value={g.messages.join("\n")} onChange={(e) => set({ grpc: { ...g, messages: e.target.value.split("\n").filter((l) => l.trim()) } })} />
        </label>
        <div className="row">
          <NumField label="Deadline (grpc-timeout, ms)" value={g.deadline_ms} onChange={(v) => set({ grpc: { ...g, deadline_ms: v } })} />
          <label className="check">
            <input type="checkbox" checked={!!g.plaintext} onChange={(e) => set({ grpc: { ...g, plaintext: e.target.checked } })} />
            h2c (cleartext) for http:// targets
          </label>
        </div>
        <p className="hint">gRPC status comes from trailers. An HTTP 200 with missing trailers is reported as incomplete, not success.</p>
      </div>
    );
  }
  if (p === "tcp") {
    const t = spec.tcp ?? { payloads: [] };
    return (
      <div className="col" style={{ maxWidth: 760 }}>
        <div className="row">
          <label className="lbl">
            Framing
            <select className="field" value={t.framing ?? "none"} onChange={(e) => set({ tcp: { ...t, framing: e.target.value as "none" } })}>
              <option value="none">None (raw bytes)</option>
              <option value="newline_delimited">Newline-delimited</option>
              <option value="length_prefixed_u16">Length-prefixed (u16)</option>
              <option value="length_prefixed_u32">Length-prefixed (u32)</option>
            </select>
          </label>
          <NumField label="Read idle (ms)" value={t.read_idle_ms} onChange={(v) => set({ tcp: { ...t, read_idle_ms: v ?? undefined } })} />
          <NumField label="Expect frames" value={t.expect_frames} onChange={(v) => set({ tcp: { ...t, expect_frames: v ?? undefined } })} />
        </div>
        <PayloadsEditor payloads={t.payloads} onChange={(payloads) => set({ tcp: { ...t, payloads } })} />
        <label className="check">
          <input type="checkbox" checked={!!t.half_close_after_send} onChange={(e) => set({ tcp: { ...t, half_close_after_send: e.target.checked } })} />
          Half-close (shutdown write) after sending
        </label>
      </div>
    );
  }
  if (p === "udp") {
    const u = spec.udp ?? { datagrams: [] };
    return (
      <div className="col" style={{ maxWidth: 760 }}>
        <PayloadsEditor payloads={u.datagrams} onChange={(datagrams) => set({ udp: { ...u, datagrams } })} />
        <div className="row">
          <NumField label="Response window (ms)" value={u.response_window_ms} onChange={(v) => set({ udp: { ...u, response_window_ms: v ?? undefined } })} />
          <NumField label="Max datagrams" value={u.max_datagrams} onChange={(v) => set({ udp: { ...u, max_datagrams: v ?? undefined } })} />
        </div>
        <p className="hint">UDP has no delivery signal: silence means no reply arrived within the window, not that the datagram was lost or dropped by a specific hop.</p>
      </div>
    );
  }
  return null;
}

function PayloadsEditor({ payloads, onChange }: { payloads: { data: string; encoding?: "text" | "hex" | "base64" }[]; onChange: (p: { data: string; encoding?: "text" | "hex" | "base64" }[]) => void }) {
  return (
    <div className="col">
      {payloads.map((p, i) => (
        <div className="row" key={i}>
          <select className="field" value={p.encoding ?? "text"} onChange={(e) => onChange(payloads.map((x, j) => (j === i ? { ...x, encoding: e.target.value as "text" } : x)))}>
            <option value="text">Text</option>
            <option value="hex">Hex</option>
            <option value="base64">Base64</option>
          </select>
          <input className="field mono grow" value={p.data} onChange={(e) => onChange(payloads.map((x, j) => (j === i ? { ...x, data: e.target.value } : x)))} />
          <button className="btn ghost icon-btn" aria-label="Remove" onClick={() => onChange(payloads.filter((_, j) => j !== i))}>
            ✕
          </button>
        </div>
      ))}
      <button className="btn small" style={{ alignSelf: "start" }} onClick={() => onChange([...payloads, { data: "", encoding: "text" }])}>
        + Payload
      </button>
    </div>
  );
}

// ------------------------------------------------------------------ tests

const ASSERTION_TYPES: { id: Assertion["type"]; label: string }[] = [
  { id: "status", label: "Status" },
  { id: "status_in", label: "Status is one of" },
  { id: "header", label: "Header" },
  { id: "trailer", label: "Trailer" },
  { id: "json_path", label: "JSONPath" },
  { id: "x_path", label: "XPath" },
  { id: "json_schema", label: "JSON Schema" },
  { id: "body", label: "Body" },
  { id: "latency_ms", label: "Latency under (ms)" },
  { id: "grpc_status", label: "gRPC status" },
  { id: "message_count", label: "Message count" },
  { id: "diagnostic", label: "Diagnostic finding" },
  { id: "transport", label: "Transport state" },
];
const COMPARISONS: Comparison[] = ["equals", "not_equals", "contains", "not_contains", "matches", "exists", "not_exists", "less_than", "greater_than"];

function assertionDefault(t: Assertion["type"]): Assertion {
  switch (t) {
    case "status":
      return { type: "status", comparison: "equals", value: "200" };
    case "status_in":
      return { type: "status_in", values: [200, 201, 204] };
    case "header":
    case "trailer":
      return { type: t, name: "", comparison: "exists" };
    case "json_path":
    case "x_path":
      return { type: t, path: t === "json_path" ? "$.id" : "//id", comparison: "exists" };
    case "json_schema":
      return { type: "json_schema", schema: '{\n  "type": "object"\n}' };
    case "body":
      return { type: "body", comparison: "contains", value: "" };
    case "latency_ms":
      return { type: "latency_ms", max: 500 };
    case "grpc_status":
      return { type: "grpc_status", code: 0 };
    case "message_count":
      return { type: "message_count", comparison: "greater_than", value: 0 };
    case "diagnostic":
      return { type: "diagnostic", code: "", present: false };
    case "transport":
      return { type: "transport", state: "completed" };
  }
}

function TestsEditor({ spec, set }: { spec: RequestSpec; set: (p: Partial<RequestSpec>) => void }) {
  const as = spec.assertions ?? [];
  const ex = spec.extractions ?? [];
  const setA = (i: number, a: Assertion) => set({ assertions: as.map((x, j) => (j === i ? a : x)) });
  const setE = (i: number, e: Extraction) => set({ extractions: ex.map((x, j) => (j === i ? e : x)) });
  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="col">
        <h4 className="faint" style={{ margin: 0 }}>Assertions</h4>
        {as.map((a, i) => (
          <div className="row" key={i} style={{ flexWrap: "wrap" }}>
            <input type="checkbox" aria-label="Enabled" checked={a.enabled !== false} onChange={(e) => setA(i, { ...a, enabled: e.target.checked })} />
            <select className="field" value={a.type} onChange={(e) => setA(i, { ...assertionDefault(e.target.value as Assertion["type"]), enabled: a.enabled, label: a.label })}>
              {ASSERTION_TYPES.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
            <AssertionFields a={a} onChange={(n) => setA(i, n)} />
            <button className="btn ghost icon-btn" aria-label="Remove assertion" onClick={() => set({ assertions: as.filter((_, j) => j !== i) })}>
              ✕
            </button>
          </div>
        ))}
        <button className="btn small" style={{ alignSelf: "start" }} onClick={() => set({ assertions: [...as, assertionDefault("status")] })}>
          + Assertion
        </button>
        <p className="hint">Assertion results are reported separately from transport and HTTP status — a failed assertion never changes what the network did.</p>
      </div>
      <div className="col">
        <h4 className="faint" style={{ margin: 0 }}>Extract into variables (for chained requests)</h4>
        {ex.map((x, i) => (
          <div className="row" key={i}>
            <input className="field mono" style={{ width: 160 }} placeholder="variable" value={x.variable} onChange={(e) => setE(i, { ...x, variable: e.target.value })} />
            <select
              className="field"
              value={x.from}
              onChange={(e) => {
                const f = e.target.value as Extraction["from"];
                const base = { variable: x.variable, sensitive: x.sensitive };
                setE(i, f === "status" ? { ...base, from: "status" } : f === "header" ? { ...base, from: "header", name: "" } : f === "regex" ? { ...base, from: "regex", pattern: "", group: 1 } : { ...base, from: f, path: "" });
              }}
            >
              <option value="json_path">JSONPath</option>
              <option value="x_path">XPath</option>
              <option value="header">Header</option>
              <option value="regex">Regex</option>
              <option value="status">Status</option>
            </select>
            {(x.from === "json_path" || x.from === "x_path") && <input className="field mono grow" value={x.path} onChange={(e) => setE(i, { ...x, path: e.target.value })} />}
            {x.from === "header" && <input className="field mono grow" value={x.name} onChange={(e) => setE(i, { ...x, name: e.target.value })} />}
            {x.from === "regex" && <input className="field mono grow" value={x.pattern} onChange={(e) => setE(i, { ...x, pattern: e.target.value })} />}
            <label className="check">
              <input type="checkbox" checked={!!x.sensitive} onChange={(e) => setE(i, { ...x, sensitive: e.target.checked })} />
              secret
            </label>
            <button className="btn ghost icon-btn" aria-label="Remove extraction" onClick={() => set({ extractions: ex.filter((_, j) => j !== i) })}>
              ✕
            </button>
          </div>
        ))}
        <button className="btn small" style={{ alignSelf: "start" }} onClick={() => set({ extractions: [...ex, { variable: "", from: "json_path", path: "$." }] })}>
          + Extraction
        </button>
      </div>
    </div>
  );
}

function AssertionFields({ a, onChange }: { a: Assertion; onChange: (a: Assertion) => void }) {
  const cmp = (c: Comparison, cb: (c: Comparison) => void) => (
    <select className="field" value={c} onChange={(e) => cb(e.target.value as Comparison)}>
      {COMPARISONS.map((x) => (
        <option key={x} value={x}>
          {humanize(x)}
        </option>
      ))}
    </select>
  );
  const val = (v: string | undefined, cb: (v: string) => void, ph = "value") => <input className="field mono grow" placeholder={ph} value={v ?? ""} onChange={(e) => cb(e.target.value)} />;
  switch (a.type) {
    case "status":
      return (
        <>
          {cmp(a.comparison, (comparison) => onChange({ ...a, comparison }))}
          {val(a.value, (value) => onChange({ ...a, value }))}
        </>
      );
    case "status_in":
      return <input className="field mono grow" value={a.values.join(", ")} onChange={(e) => onChange({ ...a, values: e.target.value.split(/[,\s]+/).filter(Boolean).map(Number).filter((n) => !Number.isNaN(n)) })} />;
    case "header":
    case "trailer":
      return (
        <>
          {val(a.name, (name) => onChange({ ...a, name }), "name")}
          {cmp(a.comparison, (comparison) => onChange({ ...a, comparison }))}
          {val(a.value, (value) => onChange({ ...a, value }))}
        </>
      );
    case "json_path":
    case "x_path":
      return (
        <>
          {val(a.path, (path) => onChange({ ...a, path }), "path")}
          {cmp(a.comparison, (comparison) => onChange({ ...a, comparison }))}
          {val(a.value, (value) => onChange({ ...a, value }))}
        </>
      );
    case "json_schema":
      return <textarea className="field grow" rows={3} value={a.schema} onChange={(e) => onChange({ ...a, schema: e.target.value })} />;
    case "body":
      return (
        <>
          {cmp(a.comparison, (comparison) => onChange({ ...a, comparison }))}
          {val(a.value, (value) => onChange({ ...a, value }))}
        </>
      );
    case "latency_ms":
      return <input className="field mono" style={{ width: 120 }} value={a.max} onChange={(e) => onChange({ ...a, max: Number(e.target.value) || 0 })} />;
    case "grpc_status":
      return <input className="field mono" style={{ width: 120 }} value={a.code} onChange={(e) => onChange({ ...a, code: Number(e.target.value) || 0 })} />;
    case "message_count":
      return (
        <>
          {cmp(a.comparison, (comparison) => onChange({ ...a, comparison }))}
          <input className="field mono" style={{ width: 120 }} value={a.value} onChange={(e) => onChange({ ...a, value: Number(e.target.value) || 0 })} />
        </>
      );
    case "diagnostic":
      return (
        <>
          {val(a.code, (code) => onChange({ ...a, code }), "finding code, e.g. ferrum.marker.connection_failure")}
          <select className="field" value={a.present ? "present" : "absent"} onChange={(e) => onChange({ ...a, present: e.target.value === "present" })}>
            <option value="absent">is absent</option>
            <option value="present">is present</option>
          </select>
        </>
      );
    case "transport":
      return (
        <select className="field" value={a.state} onChange={(e) => onChange({ ...a, state: e.target.value })}>
          {["completed", "failed", "incomplete", "canceled"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      );
  }
}

// --------------------------------------------------------------- settings

function tri(v: boolean | null | undefined): string {
  return v == null ? "inherit" : v ? "on" : "off";
}
function fromTri(s: string): boolean | null {
  return s === "inherit" ? null : s === "on";
}

function SettingsEditor({ spec, set, profiles }: { spec: RequestSpec; set: (p: Partial<RequestSpec>) => void; profiles: Profiles }) {
  const s: SettingsOverrides = spec.settings ?? {};
  const upd = (patch: Partial<SettingsOverrides>) => set({ settings: { ...s, ...patch } });
  const t = s.timeouts ?? {};
  const selectedTls = profiles.tls.find((p) => p.id === s.tls_profile_id);
  return (
    <div className="col" style={{ gap: 14, maxWidth: 860 }}>
      <p className="hint">Blank or “inherit” uses the folder, workspace or app default. The Effective request tab shows the resolved value and which layer it came from.</p>
      <div className="row" style={{ flexWrap: "wrap", alignItems: "flex-end" }}>
        <label className="lbl">
          HTTP version
          <select className="field" value={s.http_version ?? ""} onChange={(e) => upd({ http_version: (e.target.value || null) as HttpVersionPolicy | null })}>
            <option value="">inherit</option>
            <option value="auto">Auto (ALPN)</option>
            <option value="http1_only">HTTP/1.1 only</option>
            <option value="http2_only">HTTP/2 only</option>
            <option value="h2c">h2c (cleartext HTTP/2)</option>
            <option value="http3_only">HTTP/3 only</option>
            <option value="http3_with_fallback">HTTP/3, fall back to TCP (safe requests only)</option>
          </select>
        </label>
        <label className="lbl">
          IP family
          <select className="field" value={s.ip_preference ?? ""} onChange={(e) => upd({ ip_preference: (e.target.value || null) as SettingsOverrides["ip_preference"] })}>
            <option value="">inherit</option>
            <option value="system">System</option>
            <option value="prefer_ipv4">Prefer IPv4</option>
            <option value="prefer_ipv6">Prefer IPv6</option>
            <option value="ipv4_only">IPv4 only</option>
            <option value="ipv6_only">IPv6 only</option>
          </select>
        </label>
        {(["decompress", "cookies", "keepalive"] as const).map((k) => (
          <label className="lbl" key={k}>
            {k === "keepalive" ? "Reuse connections" : humanize(k)}
            <select className="field" value={tri(s[k])} onChange={(e) => upd({ [k]: fromTri(e.target.value) })}>
              <option value="inherit">inherit</option>
              <option value="on">on</option>
              <option value="off">off</option>
            </select>
          </label>
        ))}
      </div>
      <fieldset style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10 }}>
        <legend className="faint">Timeouts (ms)</legend>
        <div className="row" style={{ flexWrap: "wrap" }}>
          {(
            [
              ["dns_ms", "DNS"],
              ["connect_ms", "Connect"],
              ["tls_handshake_ms", "TLS handshake"],
              ["request_write_ms", "Request write"],
              ["response_headers_ms", "Response headers"],
              ["body_idle_ms", "Body idle"],
              ["total_ms", "Total"],
            ] as const
          ).map(([k, label]) => (
            <NumField key={k} label={label} value={t[k]} onChange={(v) => upd({ timeouts: { ...t, [k]: v } })} />
          ))}
        </div>
      </fieldset>
      <div className="row" style={{ flexWrap: "wrap", alignItems: "flex-end" }}>
        <label className="lbl">
          Redirects
          <select
            className="field"
            value={s.redirects == null ? "inherit" : s.redirects.follow ? "follow" : "no"}
            onChange={(e) => upd({ redirects: e.target.value === "inherit" ? null : { follow: e.target.value === "follow", max: s.redirects?.max ?? 10, forward_credentials_cross_origin: s.redirects?.forward_credentials_cross_origin ?? false } })}
          >
            <option value="inherit">inherit</option>
            <option value="follow">Follow</option>
            <option value="no">Don't follow</option>
          </select>
        </label>
        {s.redirects && (
          <>
            <NumField label="Max redirects" value={s.redirects.max} onChange={(v) => upd({ redirects: { ...s.redirects!, max: v ?? 10 } })} />
            <label className="check">
              <input type="checkbox" checked={s.redirects.forward_credentials_cross_origin} onChange={(e) => upd({ redirects: { ...s.redirects!, forward_credentials_cross_origin: e.target.checked } })} />
              Forward credentials to other origins
            </label>
          </>
        )}
        <label className="lbl">
          Automatic retries
          <select
            className="field"
            value={s.retries == null ? "inherit" : String(s.retries.max_retries)}
            onChange={(e) => upd({ retries: e.target.value === "inherit" ? null : { max_retries: Number(e.target.value), backoff_ms: s.retries?.backoff_ms ?? 200, only_safe: true } })}
          >
            <option value="inherit">inherit</option>
            {[0, 1, 2, 3, 5].map((n) => (
              <option key={n} value={n}>
                {n === 0 ? "Off" : `${n}`}
              </option>
            ))}
          </select>
        </label>
      </div>
      {s.redirects?.forward_credentials_cross_origin && <div className="warn-box">Credentials will be sent to whatever origin a redirect points at. Only enable this for origins you control.</div>}
      {(s.retries?.max_retries ?? 0) > 0 && <p className="hint">Retries only happen when the request provably never left this machine, or the method is idempotent. A possibly-processed POST/PATCH is never replayed automatically.</p>}
      <div className="row" style={{ flexWrap: "wrap", alignItems: "flex-end" }}>
        <label className="lbl">
          TLS profile
          <select className="field" value={s.tls_profile_id ?? ""} onChange={(e) => upd({ tls_profile_id: e.target.value || null })}>
            <option value="">inherit (system trust, verification on)</option>
            {profiles.tls.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.verify === false ? " — verification OFF" : ""}
              </option>
            ))}
          </select>
        </label>
        <label className="lbl">
          Proxy
          <select
            className="field"
            value={s.proxy_profile_id == null ? "" : s.proxy_profile_id.kind === "none" ? "none" : s.proxy_profile_id.id}
            onChange={(e) => upd({ proxy_profile_id: e.target.value === "" ? null : e.target.value === "none" ? { kind: "none" } : { kind: "profile", id: e.target.value } })}
          >
            <option value="">inherit</option>
            <option value="none">No proxy</option>
            {profiles.proxy.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.kind} {p.address})
              </option>
            ))}
          </select>
        </label>
        <label className="lbl">
          Ferrum gateway profile
          <select className="field" value={s.integration_profile_id ?? ""} onChange={(e) => upd({ integration_profile_id: e.target.value || null })}>
            <option value="">inherit</option>
            {profiles.integrations.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.compatibility_id})
              </option>
            ))}
          </select>
        </label>
      </div>
      {selectedTls?.verify === false && (
        <div className="warn-box">
          <b>Certificate verification is off for requests using “{selectedTls.name}”.</b> Traffic is still encrypted, but the server is not authenticated. This applies only to requests that select this profile.
        </div>
      )}
    </div>
  );
}

function NumField(props: { label: string; value?: number | null; onChange: (v: number | null) => void }) {
  return (
    <label className="lbl">
      {props.label}
      <input
        className="field mono"
        style={{ width: 120 }}
        inputMode="numeric"
        value={props.value ?? ""}
        onChange={(e) => {
          const v = e.target.value.trim();
          props.onChange(v === "" ? null : Number.isNaN(Number(v)) ? null : Number(v));
        }}
      />
    </label>
  );
}

// ------------------------------------------------------ effective request

function EffectivePanel({ req, workspaceId, environmentId }: { req: RequestDefinition; workspaceId: string; environmentId: string | null }) {
  const debounced = useDebounced(req, 300);
  const [eff, setEff] = useState<EffectiveRequest | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    api
      .effective({ workspace_id: workspaceId, request_id: debounced.id, spec: debounced.spec, environment_id: environmentId, send_anyway: false })
      .then((r) => {
        if (!alive) return;
        setEff(r);
        setErr(null);
      })
      .catch((e) => alive && setErr(String((e as Error).message)));
    return () => {
      alive = false;
    };
  }, [debounced, workspaceId, environmentId]);
  if (err) return <div className="bad-box">This request cannot be prepared yet: {err}</div>;
  if (!eff) return <div className="faint">Resolving…</div>;
  return (
    <div className="col">
      <p className="hint">Exactly what Send will put on the wire, after variables, inheritance and auth. Secret values are redacted here; per-send values (signatures, nonces, JWT timestamps) change on every send.</p>
      <pre className="code">
        {eff.method} {eff.url}
      </pre>
      <table className="grid">
        <tbody>
          <tr><td className="k">Destination</td><td className="v">{eff.destination}</td></tr>
          <tr><td className="k">Auth</td><td className="v">{eff.auth}{eff.auth_varies_per_send ? " (computed per send)" : ""}</td></tr>
          <tr>
            <td className="k">TLS</td>
            <td className="v">
              {eff.tls_profile ?? "system trust"} · {eff.tls_verification ? "verification on" : <b style={{ color: "var(--warn)" }}>verification OFF</b>}
            </td>
          </tr>
          <tr><td className="k">Proxy</td><td className="v">{eff.proxy ?? "none"}</td></tr>
          <tr><td className="k">Ferrum trust</td><td className="v">{eff.ferrum_trust ?? "not a declared Ferrum gateway (markers are unverified)"}</td></tr>
          <tr><td className="k">HTTP version</td><td className="v">{humanize(eff.settings.http_version)}</td></tr>
          <tr><td className="k">Body</td><td className="v">{fmtBytes(eff.body_bytes)} {eff.content_type ? `· ${eff.content_type}` : ""}</td></tr>
        </tbody>
      </table>
      {eff.lint_warning && <div className="warn-box">{eff.lint_warning}</div>}
      <h4 className="faint" style={{ margin: "6px 0 0" }}>Headers</h4>
      <table className="grid">
        <tbody>
          {eff.headers.map((h, i) => (
            <tr key={i}>
              <td className="k">{h.name}</td>
              <td className="v">{h.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {eff.inferred.length > 0 && (
        <>
          <h4 className="faint" style={{ margin: "6px 0 0" }}>Added by Anvil</h4>
          <ul style={{ margin: 0 }}>
            {eff.inferred.map((x, i) => (
              <li key={i} className="muted">
                {x}
              </li>
            ))}
          </ul>
        </>
      )}
      {eff.variables_used.length > 0 && (
        <>
          <h4 className="faint" style={{ margin: "6px 0 0" }}>Variables</h4>
          <table className="grid">
            <tbody>
              {eff.variables_used.map(([k, src], i) => (
                <tr key={i}>
                  <td className="k">{`{{${k}}}`}</td>
                  <td className="v">{src}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {eff.body_preview && (
        <>
          <h4 className="faint" style={{ margin: "6px 0 0" }}>Body preview</h4>
          <pre className="code">{eff.body_preview}</pre>
        </>
      )}
      <details>
        <summary className="muted">Settings sources</summary>
        <table className="grid">
          <tbody>
            {eff.settings.sources.map((s, i) => (
              <tr key={i}>
                <td className="k">{s.field}</td>
                <td className="v">{s.layer}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}

export function newSpec(): RequestSpec {
  return { protocol: "http", method: "GET", url: "", params: [], headers: [], body: { type: "none" }, auth: { type: "inherit" }, assertions: [], extractions: [] };
}

export type { KeyValue };
