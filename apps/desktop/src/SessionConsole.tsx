// Live console for an interactive session. Received content is shown as
// inert text (or hex) only.
import { useEffect, useRef, useState } from "react";
import type { SessionCommand, StreamMessage } from "./api";
import { fmtBytes, fmtUs } from "./ui";

export function SessionConsole(props: {
  protocol: string;
  messages: StreamMessage[];
  onSend: (c: SessionCommand) => Promise<void>;
  onCancel: () => void;
}) {
  const [text, setText] = useState("");
  const [hex, setHex] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [code, setCode] = useState(1000);
  const listRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight });
  }, [props.messages.length]);
  const receiveOnly = props.protocol === "sse";
  const run = async (c: SessionCommand) => {
    setErr(null);
    try {
      await props.onSend(c);
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };
  const send = async () => {
    if (!text) return;
    await run(hex ? { command: "send_binary_hex", hex: text.replace(/\s+/g, "") } : { command: "send_text", text });
    setText("");
  };
  return (
    <div className="resp" style={{ gridTemplateRows: "auto 1fr auto" }}>
      <div className="resp-head">
        <span className="badge ok">● connected</span>
        <span className="muted">{props.protocol.replace("_", " ")} session · {props.messages.length} messages</span>
        <span className="spacer" />
        {props.protocol === "web_socket" && (
          <button className="btn small" onClick={() => void run({ command: "ping" })}>
            Ping
          </button>
        )}
        {(props.protocol === "tcp" || props.protocol === "grpc") && (
          <button className="btn small" title="Stop sending but keep reading" onClick={() => void run({ command: "half_close" })}>
            Half-close
          </button>
        )}
        {props.protocol === "web_socket" && (
          <input className="field mono" style={{ width: 70 }} aria-label="Close code" value={code} onChange={(e) => setCode(Number(e.target.value) || 1000)} />
        )}
        <button className="btn small" onClick={() => void run({ command: "close", code, reason: "" })}>
          Close
        </button>
        <button className="btn small danger" title="Abort without a close handshake" onClick={props.onCancel}>
          Abort
        </button>
      </div>
      <div className="pane" ref={listRef}>
        {props.messages.length === 0 && <div className="faint">Waiting for messages…</div>}
        {props.messages.map((m, i) => (
          <div key={i} className="row" style={{ alignItems: "flex-start", fontSize: 12, padding: "3px 0", borderBottom: "1px solid var(--border)" }}>
            <span className="mono faint" style={{ width: 70, flex: "none" }}>
              {fmtUs(m.offset_us)}
            </span>
            <span style={{ color: m.direction === "sent" ? "var(--info)" : "var(--ok)", width: 14, flex: "none" }}>{m.direction === "sent" ? "→" : "←"}</span>
            <span className="mono faint" style={{ width: 110, flex: "none" }}>
              {m.kind}
              {m.event_type ? `·${m.event_type}` : ""} {fmtBytes(m.size)}
            </span>
            <span className="mono grow" style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
              {m.preview}
              {m.preview_truncated ? " …" : ""}
            </span>
          </div>
        ))}
      </div>
      {!receiveOnly && (
        <form
          className="row"
          style={{ padding: "8px 12px", borderTop: "1px solid var(--border)" }}
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
        >
          <input className="field mono grow" aria-label="Message" placeholder={hex ? "hex bytes, e.g. 48 65 6c 6c 6f" : "message text"} value={text} onChange={(e) => setText(e.target.value)} />
          <label className="check">
            <input type="checkbox" checked={hex} onChange={(e) => setHex(e.target.checked)} />
            hex
          </label>
          <button className="btn primary" type="submit" disabled={!text}>
            Send
          </button>
        </form>
      )}
      {err && <div className="bad-box" style={{ margin: 8 }}>{err}</div>}
    </div>
  );
}
