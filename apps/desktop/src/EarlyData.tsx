// TLS 1.3 / QUIC 0-RTT early data: the settings editor (any layer) and the
// evidence views. Pure components: nothing here performs I/O. The engine
// refuses a non-idempotent method in the policy before any traffic, and
// sends every other ineligible method after the handshake with the reason.
import type { EarlyDataNotUsed, EarlyDataObservation, EarlyDataPolicy } from "./generated/contracts";

/** Idempotent methods a user may add explicitly (GET, HEAD, OPTIONS are always eligible). */
export const EXTRA_EARLY_METHODS = ["PUT", "DELETE", "TRACE"] as const;

const NOT_USED: Record<EarlyDataNotUsed, string> = {
  no_ticket: "no session ticket from an earlier connection to this server yet (full handshake)",
  ticket_without_early_data: "the server's session ticket does not allow early data (resumption only)",
  method_not_eligible: "the method is not eligible — sent after the handshake",
  connection_reused: "an established connection carried the request (no handshake)",
  retry_after_too_early: "retry after 425 Too Early — retries are never early data",
  alpn_not_fixed: "the HTTP version offers two protocols over TCP; choose HTTP/1.1-only or HTTP/2-only",
  through_proxy: "a proxy or tunnel carries the connection",
  handshake_completed_first: "the handshake completed before the request was written, so it went out as ordinary data",
};

export function notUsedText(r: EarlyDataNotUsed): string {
  return NOT_USED[r];
}

/** One line for the attempts table. */
export function earlyDataSummary(e: EarlyDataObservation): string {
  if (e.offered) {
    if (e.accepted === true) return "0-RTT accepted";
    if (e.accepted === false) return e.resent_after_handshake ? "0-RTT rejected, re-sent after handshake" : "0-RTT rejected";
    return "0-RTT offered";
  }
  return e.not_used ? `no 0-RTT (${e.not_used.replace(/_/g, " ")})` : "no 0-RTT";
}

/** Early-data policy for a settings layer: inherit, off, or on with extra methods. */
export function EarlyDataSettings(props: { value: EarlyDataPolicy | null | undefined; onChange: (v: EarlyDataPolicy | null) => void }) {
  const v = props.value;
  const mode = v == null ? "inherit" : v.enabled ? "on" : "off";
  const extra = v?.extra_methods ?? [];
  return (
    <fieldset aria-label="0-RTT early data">
      <legend>0-RTT early data (TLS 1.3 / QUIC)</legend>
      <div className="fields">
        <label className="lbl">
          Early data
          <select
            className="field"
            aria-label="Early data"
            value={mode}
            onChange={(e) => props.onChange(e.target.value === "inherit" ? null : { enabled: e.target.value === "on", extra_methods: extra })}
          >
            <option value="inherit">inherit</option>
            <option value="off">off</option>
            <option value="on">on (replay-safe requests)</option>
          </select>
        </label>
        {v?.enabled && (
          <div className="col tight">
            <span className="faint small-text">Always eligible: GET, HEAD, OPTIONS. Also allow:</span>
            <div className="row methods-row">
              {EXTRA_EARLY_METHODS.map((m) => (
                <label className="check" key={m}>
                  <input
                    type="checkbox"
                    checked={extra.includes(m)}
                    onChange={(e) =>
                      props.onChange({ enabled: true, extra_methods: e.target.checked ? [...extra.filter((x) => x !== m), m] : extra.filter((x) => x !== m) })
                    }
                  />
                  {m}
                </label>
              ))}
            </div>
          </div>
        )}
      </div>
      {v?.enabled && (
        <div className="warn-box" role="note">
          Early data is sent before the handshake completes and can be <b>replayed</b> by anyone who captured it. Only eligible methods use it, on a new
          connection that resumes an earlier session with this server (same workspace, TLS profile, client identity, server name and port); other methods go
          out after the handshake and the record says why. Connection reuse keeps using the established connection instead. A 425 Too Early answer is retried
          once, after the handshake.
        </div>
      )}
      {extra.some((m) => !EXTRA_EARLY_METHODS.includes(m as (typeof EXTRA_EARLY_METHODS)[number])) && (
        <div className="bad-box" role="alert">
          The policy lists a method that is not idempotent ({extra.filter((m) => !EXTRA_EARLY_METHODS.includes(m as (typeof EXTRA_EARLY_METHODS)[number])).join(", ")}). Such requests are
          refused before sending.
        </div>
      )}
    </fieldset>
  );
}

/** Connection-tab evidence of one attempt's early data. */
export function EarlyDataEvidence({ e }: { e: EarlyDataObservation }) {
  return (
    <div className="col" aria-label="Early data evidence">
      <h4 className="section-title">
        0-RTT early data ({e.transport === "quic" ? "QUIC" : "TLS 1.3 over TCP"})
      </h4>
      <table className="grid">
        <tbody>
          <tr>
            <td className="k">Method eligible</td>
            <td className="v">{e.method_eligible ? "yes" : "no"}</td>
          </tr>
          <tr>
            <td className="k">Session resumption</td>
            <td className="v">
              {e.resumption_attempted ? (e.resumption_accepted === true ? "ticket offered, resumed" : e.resumption_accepted === false ? "ticket offered, declined (full handshake)" : "ticket offered") : "no ticket offered"}
            </td>
          </tr>
          <tr>
            <td className="k">Early data</td>
            <td className="v">
              {e.offered ? (
                <>
                  offered —{" "}
                  {e.accepted === true ? (
                    <span className="badge warn">accepted</span>
                  ) : e.accepted === false ? (
                    <span className="badge">rejected by the server</span>
                  ) : (
                    "outcome unknown (handshake did not complete)"
                  )}
                </>
              ) : (
                "not used"
              )}
            </td>
          </tr>
          {e.not_used && (
            <tr>
              <td className="k">Why not</td>
              <td className="v">{notUsedText(e.not_used)}</td>
            </tr>
          )}
          {e.offered && (
            <tr>
              <td className="k">Sent as early data</td>
              <td className="v">
                {e.bytes} bytes{e.bytes_estimated ? " (HTTP/3 request, header size estimated)" : " (TLS plaintext)"}
              </td>
            </tr>
          )}
          {e.resent_after_handshake && (
            <tr>
              <td className="k">Re-sent after the handshake</td>
              <td className="v">yes — the server discarded the rejected early data unread; this is the protocol delivering it, not an application retry</td>
            </tr>
          )}
          <tr>
            <td className="k">Session tickets received</td>
            <td className="v">
              {e.tickets_received}
              {e.ticket_max_early_data != null ? (e.ticket_max_early_data > 0 ? " (allow early data)" : " (no early data)") : ""}
            </td>
          </tr>
        </tbody>
      </table>
      {e.accepted === true && <p className="hint">Accepted early data can be replayed by anyone who captured it; only replay-safe methods are sent this way.</p>}
    </div>
  );
}
