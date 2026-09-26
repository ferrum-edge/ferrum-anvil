// Live console for an interactive session. Received content is shown as
// inert text (or hex) only.
import { useEffect, useRef, useState } from "react";
import type { SessionCommand, StreamMessage } from "./api";
import { Icon } from "./icons";
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
    <div className="resp session">
      <div className="resp-head">
        <span className="badge ok">
          <span className="live-dot" />
          connected
        </span>
        <span className="muted small-text">
          {props.protocol.replace("_", " ")} session · {props.messages.length} messages
        </span>
        <span className="spacer" />
        <div className="row">
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
            <input className="field mono tiny small-field" aria-label="Close code" title="Close code" value={code} onChange={(e) => setCode(Number(e.target.value) || 1000)} />
          )}
          <button className="btn small" onClick={() => void run({ command: "close", code, reason: "" })}>
            Close
          </button>
          <button className="btn small danger" title="Abort without a close handshake" onClick={props.onCancel}>
            <Icon name="x" size={13} />
            Abort
          </button>
        </div>
      </div>
      <div className="pane console-list" ref={listRef}>
        {props.messages.length === 0 && <div className="faint">Waiting for messages…</div>}
        {props.messages.map((m, i) => (
          <div key={i} className="console-row">
            <span className="faint">{fmtUs(m.offset_us)}</span>
            <span className={`dir ${m.direction}`} title={m.direction}>
              {m.direction === "sent" ? "→" : "←"}
            </span>
            <span className="faint">
              {m.kind}
              {m.event_type ? `·${m.event_type}` : ""} {fmtBytes(m.size)}
            </span>
            <span className="payload">
              {m.preview}
              {m.preview_truncated ? " …" : ""}
            </span>
          </div>
        ))}
      </div>
      {!receiveOnly && (
        <form
          className="console-send"
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
            <Icon name="send" size={14} />
            Send
          </button>
        </form>
      )}
      {err && <div className="bad-box console-err">{err}</div>}
    </div>
  );
}
