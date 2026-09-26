// PROXY protocol settings for TCP/TLS (connection header) and UDP/DTLS
// (per-datagram v2 DGRAM envelope) sessions. Pure editors: nothing here
// performs I/O except storing a secret in the vault through SecretField.
import type { DatagramAuthSpec, DatagramEnvelopeSpec, ProxyHeaderObservation, ProxyHeaderSpec } from "./generated/contracts";
import { SecretField } from "./ui";

function Num(props: { label: string; value?: number | null; onChange: (v: number | null) => void; placeholder?: string }) {
  return (
    <label className="lbl">
      {props.label}
      <input
        className="field mono"
        style={{ width: 150 }}
        inputMode="numeric"
        placeholder={props.placeholder}
        value={props.value ?? ""}
        onChange={(e) => {
          const v = e.target.value.trim();
          props.onChange(v === "" || Number.isNaN(Number(v)) ? null : Number(v));
        }}
      />
    </label>
  );
}

function Addr(props: { label: string; value?: string | null; onChange: (v: string | null) => void; placeholder: string }) {
  return (
    <label className="lbl grow">
      {props.label}
      <input className="field mono" value={props.value ?? ""} placeholder={props.placeholder} onChange={(e) => props.onChange(e.target.value.trim() === "" ? null : e.target.value)} />
    </label>
  );
}

type HeaderMode = "off" | "v1" | "v2" | "raw";

/** PROXY v1/v2 header written after connect and before TLS. */
export function ProxyHeaderEditor(props: { value: ProxyHeaderSpec | null | undefined; onChange: (v: ProxyHeaderSpec | null) => void }) {
  const h = props.value;
  const mode: HeaderMode = h ? (h.version ?? "v2") : "off";
  const set = (patch: Partial<ProxyHeaderSpec>) => props.onChange({ ...(h ?? {}), ...patch });
  return (
    <fieldset className="col" aria-label="PROXY protocol">
      <legend>PROXY protocol header</legend>
      <div className="row">
        <label className="lbl">
          Header
          <select
            className="field"
            aria-label="PROXY protocol header"
            value={mode}
            onChange={(e) => {
              const m = e.target.value as HeaderMode;
              props.onChange(m === "off" ? null : { ...(h ?? {}), version: m });
            }}
          >
            <option value="off">Off</option>
            <option value="v1">v1 (text)</option>
            <option value="v2">v2 (binary)</option>
            <option value="raw">Custom bytes (hex)</option>
          </select>
        </label>
        {mode === "v2" && (
          <label className="lbl">
            Command
            <select className="field" value={h?.command ?? "proxy"} onChange={(e) => set({ command: e.target.value as "proxy" })}>
              <option value="proxy">PROXY (relayed client)</option>
              <option value="local">LOCAL (health check, no addresses)</option>
            </select>
          </label>
        )}
        {(mode === "v1" || (mode === "v2" && (h?.command ?? "proxy") === "proxy")) && (
          <label className="lbl">
            Addresses
            <select className="field" value={h?.family ?? "auto"} onChange={(e) => set({ family: e.target.value as "auto" })}>
              <option value="auto">Source → destination</option>
              <option value="unspec">{mode === "v1" ? "UNKNOWN (none)" : "AF_UNSPEC (none)"}</option>
            </select>
          </label>
        )}
      </div>
      {mode !== "off" && mode !== "raw" && (h?.family ?? "auto") === "auto" && (h?.command ?? "proxy") === "proxy" && (
        <div className="row">
          <Addr label="Source (client) ip:port" value={h?.source} onChange={(source) => set({ source })} placeholder="this connection's local address" />
          <Addr label="Destination ip:port" value={h?.destination} onChange={(destination) => set({ destination })} placeholder="this connection's remote address" />
        </div>
      )}
      {mode === "v2" && (
        <label className="lbl">
          Authority TLV (0x02, e.g. the SNI name)
          <input className="field mono" value={h?.authority ?? ""} onChange={(e) => set({ authority: e.target.value === "" ? null : e.target.value })} />
        </label>
      )}
      {mode === "raw" && (
        <label className="lbl">
          Header bytes (hex) — sent verbatim; Anvil records whether they are well-formed
          <input className="field mono" value={h?.raw_hex ?? ""} placeholder="50524f585920..." onChange={(e) => set({ raw_hex: e.target.value })} />
        </label>
      )}
      {mode !== "off" && (
        <p className="hint">
          Written at the head of the connection, before any TLS. A listener that requires PROXY protocol closes a connection whose header is missing, malformed or from an untrusted peer without saying why; Anvil reports such a close as a possible cause, never as a
          confirmed one.
        </p>
      )}
    </fieldset>
  );
}

/** PROXY v2 DGRAM envelope on every UDP/DTLS datagram, optionally authenticated. */
export function DatagramEnvelopeEditor(props: {
  value: DatagramEnvelopeSpec | null | undefined;
  onChange: (v: DatagramEnvelopeSpec | null) => void;
  workspaceId: string | null;
  dtls: boolean;
}) {
  const e = props.value;
  const set = (patch: Partial<DatagramEnvelopeSpec>) => props.onChange({ ...(e ?? {}), ...patch });
  const a = e?.authentication ?? null;
  const setAuth = (patch: Partial<DatagramAuthSpec>) =>
    set({ authentication: { secret: { kind: "template", value: "" }, listener_bind_address: "0.0.0.0", ...(a ?? {}), ...patch } as DatagramAuthSpec });
  return (
    <fieldset className="col" aria-label="PROXY protocol envelope">
      <legend>PROXY v2 datagram envelope</legend>
      <div className="row">
        <label className="lbl">
          Envelope
          <select
            className="field"
            aria-label="PROXY v2 datagram envelope"
            value={e ? (e.command ?? "proxy") : "off"}
            onChange={(ev) => {
              const v = ev.target.value;
              props.onChange(v === "off" ? null : { ...(e ?? {}), command: v as "proxy" | "local" });
            }}
          >
            <option value="off">Off</option>
            <option value="proxy">PROXY (relayed client)</option>
            <option value="local">LOCAL (health probe, no addresses)</option>
          </select>
        </label>
        {e && (e.command ?? "proxy") === "proxy" && (
          <label className="lbl">
            Addresses
            <select className="field" value={e.family ?? "auto"} onChange={(ev) => set({ family: ev.target.value as "auto" })}>
              <option value="auto">Source → destination</option>
              <option value="unspec">AF_UNSPEC (none)</option>
            </select>
          </label>
        )}
      </div>
      {e && (e.command ?? "proxy") === "proxy" && (e.family ?? "auto") === "auto" && (
        <div className="row">
          <Addr label="Source (client) ip:port" value={e.source} onChange={(source) => set({ source })} placeholder="this socket's local address" />
          <Addr label="Destination ip:port" value={e.destination} onChange={(destination) => set({ destination })} placeholder="this socket's remote address" />
        </div>
      )}
      {e && (
        <label className="check">
          <input
            type="checkbox"
            checked={!!a}
            onChange={(ev) => set({ authentication: ev.target.checked ? ({ secret: { kind: "template", value: "" }, listener_bind_address: "0.0.0.0", sender_id: 1 } as DatagramAuthSpec) : null })}
          />
          Authenticate (HMAC-SHA-256 tag + freshness record)
        </label>
      )}
      {e && a && (
        <div className="col">
          <SecretField label="Shared secret (at least 32 bytes, used verbatim)" value={a.secret} onChange={(secret) => setAuth({ secret })} workspaceId={props.workspaceId} />
          <div className="row">
            <label className="lbl">
              Listener receive boundary
              <select className="field" value={a.listener_protocol ?? (props.dtls ? "dtls" : "udp")} onChange={(ev) => setAuth({ listener_protocol: ev.target.value as "udp" | "dtls" })}>
                <option value="udp">UDP (plain, or DTLS passthrough)</option>
                <option value="dtls">DTLS terminated by the listener</option>
              </select>
            </label>
            <label className="lbl">
              Listener bind address
              <input className="field mono" style={{ width: 160 }} value={a.listener_bind_address ?? "0.0.0.0"} onChange={(ev) => setAuth({ listener_bind_address: ev.target.value })} />
            </label>
            <Num label="Listener port" value={a.listener_port} placeholder="destination port" onChange={(v) => setAuth({ listener_port: v })} />
          </div>
          <div className="row">
            <Num label="Sender id" value={a.sender_id} onChange={(v) => setAuth({ sender_id: v ?? 0 })} />
            <Num label="Epoch" value={a.epoch} placeholder="now (ms)" onChange={(v) => setAuth({ epoch: v })} />
            <Num label="First sequence" value={a.first_sequence} onChange={(v) => setAuth({ first_sequence: v ?? 0 })} />
            <Num label="Timestamp offset (ms)" value={a.timestamp_offset_ms} onChange={(v) => setAuth({ timestamp_offset_ms: v ?? 0 })} />
          </div>
          <p className="hint">
            The tag is bound to the listener identity (receive boundary, bind address, port) exactly as the gateway bound it: a wildcard bind (0.0.0.0 or ::) and a specific address are different identities. The secret is never recorded.
          </p>
        </div>
      )}
      {e && (
        <p className="hint">
          Every datagram carries the envelope{props.dtls ? ", including DTLS handshake records (outside the DTLS layer)" : ""}. A listener drops a failing envelope silently, so a missing reply stays "no response observed".
        </p>
      )}
    </fieldset>
  );
}

const FORMATS: Record<ProxyHeaderObservation["format"], string> = {
  v1: "PROXY v1",
  v2: "PROXY v2",
  raw: "Custom (raw) header",
  v2_datagram: "PROXY v2 DGRAM envelope",
};

/** What Anvil actually sent (connection evidence). Tag bytes are never present. */
export function ProxyHeaderEvidence({ h }: { h: ProxyHeaderObservation }) {
  return (
    <div className="col">
      <h4 className="faint" style={{ margin: "6px 0 0" }}>PROXY protocol</h4>
      <table className="grid">
        <tbody>
          <tr>
            <td className="k">Sent</td>
            <td className="v">
              {FORMATS[h.format]}
              {h.command ? ` — ${h.command.toUpperCase()}` : ""} {h.family} ({h.length} bytes{h.format === "v2_datagram" ? " per datagram" : ""})
            </td>
          </tr>
          {(h.source || h.destination) && (
            <tr>
              <td className="k">Source → destination</td>
              <td className="v">
                {h.source ?? "—"}
                {h.source_origin ? ` (${h.source_origin})` : ""} → {h.destination ?? "—"}
                {h.destination_origin ? ` (${h.destination_origin})` : ""}
              </td>
            </tr>
          )}
          {h.text && (
            <tr>
              <td className="k">Line</td>
              <td className="v mono">{h.text}</td>
            </tr>
          )}
          <tr>
            <td className="k">Bytes (hex)</td>
            <td className="v mono" style={{ wordBreak: "break-all" }}>
              {h.hex}
            </td>
          </tr>
          {(h.tlvs ?? []).map((t, i) => (
            <tr key={i}>
              <td className="k">TLV</td>
              <td className="v mono">{t}</td>
            </tr>
          ))}
          <tr>
            <td className="k">Well-formed</td>
            <td className="v">
              {h.well_formed ? "yes" : <span className="badge warn">no</span>}
              {h.problem ? ` — ${h.problem}` : ""}
            </td>
          </tr>
          {h.authenticated && (
            <tr>
              <td className="k">Authenticated for</td>
              <td className="v">
                {h.listener_binding} (sender {h.sender_id}, epoch {h.epoch})
              </td>
            </tr>
          )}
          {h.first_sequence != null && (
            <tr>
              <td className="k">Sequences</td>
              <td className="v">
                {h.first_sequence} → {h.last_sequence ?? "—"}
              </td>
            </tr>
          )}
          {!!h.datagrams && (
            <tr>
              <td className="k">Datagrams wrapped</td>
              <td className="v">{h.datagrams}</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
