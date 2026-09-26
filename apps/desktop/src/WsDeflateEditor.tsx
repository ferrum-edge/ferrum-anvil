// WebSocket permessage-deflate (RFC 7692): the offer in the request editor
// and the negotiation/compression evidence in the response. Pure views: the
// engine builds the offer, validates the server's answer and runs the codec.
import type { WsDeflateOffer, WsDirectionTotals, WsExtensions } from "./generated/contracts";
import { fmtBytes } from "./ui";

const BITS = [8, 9, 10, 11, 12, 13, 14, 15];

/** The permessage-deflate offer of a WebSocket request (off by default). */
export function WsDeflateEditor(props: { value?: WsDeflateOffer | null; onChange: (v: WsDeflateOffer) => void }) {
  const v = props.value ?? {};
  const set = (patch: Partial<WsDeflateOffer>) => props.onChange({ ...v, ...patch });
  const bits = (value: number | null | undefined, none: string, label: string, onChange: (b: number | null) => void) => (
    <label className="lbl">
      {label}
      <select className="field" aria-label={label} value={value ?? ""} onChange={(e) => onChange(e.target.value === "" ? null : Number(e.target.value))}>
        <option value="">{none}</option>
        {BITS.map((b) => (
          <option key={b} value={b}>
            {b} ({fmtBytes(2 ** b)} window)
          </option>
        ))}
      </select>
    </label>
  );
  return (
    <fieldset className="col" aria-label="Compression">
      <legend>Compression</legend>
      <label className="check">
        <input type="checkbox" checked={!!v.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
        Offer permessage-deflate (RFC 7692)
      </label>
      {v.enabled && (
        <>
          <div className="row">
            <label className="check">
              <input type="checkbox" checked={!!v.server_no_context_takeover} onChange={(e) => set({ server_no_context_takeover: e.target.checked })} />
              Ask the server to compress each message on its own (server_no_context_takeover)
            </label>
            <label className="check">
              <input type="checkbox" checked={!!v.client_no_context_takeover} onChange={(e) => set({ client_no_context_takeover: e.target.checked })} />
              Compress each of Anvil's messages on its own (client_no_context_takeover)
            </label>
          </div>
          <div className="row">
            {bits(v.server_max_window_bits, "Not requested", "server_max_window_bits", (b) => set({ server_max_window_bits: b }))}
            {bits(v.client_max_window_bits, "Offered without a value", "client_max_window_bits", (b) => set({ client_max_window_bits: b }))}
          </div>
        </>
      )}
      <p className="hint" data-testid="ws-deflate-help">
        Off by default, so saved requests keep an uncompressed wire. When offered, the result shows whether the server accepted it; a server,
        proxy or gateway may decline or strip the offer, which is not an error. An answer that does not fit the offer fails the handshake.
        Previews show decompressed messages, and the message limit applies after decompression. With a 2^8 window Anvil sends its own messages
        uncompressed (RFC 7692 allows this) because its DEFLATE cannot compress that small.
      </p>
    </fieldset>
  );
}

const NEGOTIATION: Record<WsExtensions["negotiation"], string> = {
  not_offered: "Not offered",
  not_negotiated: "Offered, not negotiated (uncompressed)",
  negotiated: "Negotiated",
  rejected: "Answer refused (handshake failed)",
};

function totals(t: WsDirectionTotals): string {
  const ratio = t.payload_bytes > 0 && t.compressed_messages > 0 ? ` (${Math.round((100 * t.wire_bytes) / t.payload_bytes)}% on the wire)` : "";
  return `${t.messages} message(s), ${t.compressed_messages} compressed · ${fmtBytes(t.payload_bytes)} payload, ${fmtBytes(t.wire_bytes)} on the wire${ratio}`;
}

/** Extension negotiation and compression evidence of a WebSocket session. */
export function WsExtensionsEvidence({ e }: { e: WsExtensions }) {
  const d = e.deflate;
  return (
    <div className="col" data-testid="ws-extensions">
      <h4 className="faint" style={{ margin: "6px 0 0" }}>WebSocket extensions</h4>
      <table className="grid">
        <tbody>
          <tr>
            <td className="k">permessage-deflate</td>
            <td className="v">
              {e.negotiation === "rejected" || e.violation ? <span className="badge warn">{NEGOTIATION[e.negotiation]}</span> : NEGOTIATION[e.negotiation]}
              {e.problem ? ` — ${e.problem}` : ""}
            </td>
          </tr>
          <tr>
            <td className="k">Offered</td>
            <td className="v mono">{e.offered ?? "—"}</td>
          </tr>
          <tr>
            <td className="k">Answered</td>
            <td className="v mono">{e.answered ?? "no extension"}</td>
          </tr>
          {d && (
            <tr>
              <td className="k">Agreed</td>
              <td className="v">
                server window 2^{d.server_max_window_bits ?? 15}
                {d.server_no_context_takeover ? " without" : " with"} context takeover · Anvil window 2^{d.client_max_window_bits ?? 15}
                {d.client_no_context_takeover ? " without" : " with"} context takeover
                {d.client_compresses ? "" : " · Anvil sends uncompressed (2^8 window)"}
              </td>
            </tr>
          )}
          {e.traffic && (
            <>
              <tr>
                <td className="k">Sent</td>
                <td className="v">{totals(e.traffic.sent)}</td>
              </tr>
              <tr>
                <td className="k">Received</td>
                <td className="v">{totals(e.traffic.received)}</td>
              </tr>
            </>
          )}
          {e.violation && (
            <tr>
              <td className="k">Ended by</td>
              <td className="v">
                <span className="badge warn">
                  {e.violation.kind === "compressed_without_negotiation"
                    ? "a compressed message that was never negotiated (peer)"
                    : e.violation.kind === "undecodable"
                      ? "an undecodable compressed message (peer)"
                      : "Anvil's message limit, reached while decompressing"}
                </span>
                {e.violation.limit_bytes != null ? ` · limit ${fmtBytes(e.violation.limit_bytes)}` : ""}
                {e.violation.compressed_bytes != null ? ` after ${fmtBytes(e.violation.compressed_bytes)} compressed` : ""}
                {e.violation.detail ? ` · ${e.violation.detail}` : ""}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
