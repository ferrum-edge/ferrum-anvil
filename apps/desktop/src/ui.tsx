// Shared UI primitives.
import { useEffect, useRef, useState, type ReactNode } from "react";
import type { KeyValue, SensitiveValue } from "./generated/contracts";
import { api } from "./api";

export function uid(): string {
  return crypto.randomUUID();
}

export function fmtBytes(n?: number | null): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function fmtUs(us?: number | null): string {
  if (us == null) return "—";
  if (us < 1000) return `${us} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)} ms`;
  return `${(us / 1_000_000).toFixed(2)} s`;
}

export function humanize(s: string): string {
  return s.replace(/_/g, " ");
}

export function Modal(props: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    window.addEventListener("keydown", onKey);
    // Focus the first field in the body (not the header close button).
    const root = ref.current;
    const field =
      root?.querySelector<HTMLElement>("[data-autofocus]") ??
      root?.querySelector<HTMLElement>(".content input:not([type=password]), .content select, .content textarea") ??
      root?.querySelector<HTMLElement>(".content button, footer button");
    field?.focus();
    if (field instanceof HTMLInputElement && field.type === "text") field.select();
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={props.title} ref={ref} style={props.wide ? { width: "min(980px, 96vw)" } : undefined}>
        <header>
          <h2>{props.title}</h2>
          <button className="btn ghost icon-btn" aria-label="Close" onClick={props.onClose}>
            ✕
          </button>
        </header>
        <div className="content">{props.children}</div>
        {props.footer && <footer>{props.footer}</footer>}
      </div>
    </div>
  );
}

export function Tabs<T extends string>(props: { tabs: { id: T; label: string; count?: number }[]; value: T; onChange: (t: T) => void; className?: string }) {
  return (
    <div className={props.className ?? "subtabs"} role="tablist">
      {props.tabs.map((t) => (
        <button key={t.id} role="tab" className="subtab" aria-selected={props.value === t.id} onClick={() => props.onChange(t.id)}>
          {t.label}
          {t.count ? <span className="count">{t.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

const SENSITIVE = /(authorization|cookie|token|secret|password|api[-_]?key|session|signature)/i;

export function KeyValueEditor(props: { rows: KeyValue[]; onChange: (rows: KeyValue[]) => void; nameLabel?: string; valueLabel?: string }) {
  const rows = props.rows;
  const set = (i: number, patch: Partial<KeyValue>) => props.onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <div className="kv">
      <span />
      <span className="hdr">{props.nameLabel ?? "Name"}</span>
      <span className="hdr">{props.valueLabel ?? "Value"}</span>
      <span />
      {rows.map((r, i) => (
        <KvRow key={i} r={r} onSet={(p) => set(i, p)} onRemove={() => props.onChange(rows.filter((_, j) => j !== i))} />
      ))}
      <span />
      <button className="btn small ghost" style={{ justifySelf: "start" }} onClick={() => props.onChange([...rows, { name: "", value: "", enabled: true }])}>
        + Add
      </button>
    </div>
  );
}

function KvRow({ r, onSet, onRemove }: { r: KeyValue; onSet: (p: Partial<KeyValue>) => void; onRemove: () => void }) {
  const sensitive = r.sensitive || SENSITIVE.test(r.name);
  const [reveal, setReveal] = useState(false);
  return (
    <>
      <input type="checkbox" aria-label="Enabled" checked={r.enabled !== false} onChange={(e) => onSet({ enabled: e.target.checked })} />
      <input className="field mono" value={r.name} placeholder="name" onChange={(e) => onSet({ name: e.target.value })} />
      <div className="row">
        <input
          className="field mono grow"
          type={sensitive && !reveal && !/^\s*\{\{.*\}\}\s*$/.test(r.value) ? "password" : "text"}
          value={r.value}
          placeholder="value or {{variable}}"
          onChange={(e) => onSet({ value: e.target.value })}
        />
        {sensitive && (
          <button className="btn ghost icon-btn" aria-label={reveal ? "Hide value" : "Reveal value"} onClick={() => setReveal(!reveal)}>
            {reveal ? "◉" : "◎"}
          </button>
        )}
      </div>
      <button className="btn ghost icon-btn" aria-label="Remove" onClick={onRemove}>
        ✕
      </button>
    </>
  );
}

/** Sensitive value editor: a literal/`{{variable}}` template, or a vault secret reference. */
export function SecretField(props: { label: string; value: SensitiveValue | undefined; onChange: (v: SensitiveValue) => void; workspaceId: string | null; multiline?: boolean }) {
  const v = props.value ?? { kind: "template", value: "" };
  const [reveal, setReveal] = useState(false);
  const [storing, setStoring] = useState(false);
  if (v.kind === "secret") {
    return (
      <label className="lbl">
        {props.label}
        <div className="row">
          <span className="badge accent">🔒 vault: {v.secret.label}</span>
          <button className="btn small" onClick={() => props.onChange({ kind: "template", value: "" })}>
            Replace
          </button>
        </div>
      </label>
    );
  }
  const Tag = props.multiline ? "textarea" : "input";
  return (
    <label className="lbl">
      {props.label}
      <div className="row">
        <Tag
          className="field mono grow"
          type={!props.multiline && !reveal && !/^\s*\{\{.*\}\}\s*$/.test(v.value) ? "password" : "text"}
          rows={props.multiline ? 5 : undefined}
          value={v.value}
          placeholder="{{variable}} or a value to keep in the vault"
          onChange={(e: { target: { value: string } }) => props.onChange({ kind: "template", value: e.target.value })}
        />
        {!props.multiline && (
          <button className="btn ghost icon-btn" aria-label={reveal ? "Hide" : "Reveal"} onClick={() => setReveal(!reveal)}>
            {reveal ? "◉" : "◎"}
          </button>
        )}
        <button
          className="btn small"
          disabled={!v.value || /^\s*\{\{.*\}\}\s*$/.test(v.value) || storing}
          title="Move this value into the encrypted vault and keep only a reference"
          onClick={async () => {
            setStoring(true);
            try {
              const ref = await api.createSecret(props.workspaceId, props.label, v.value);
              props.onChange({ kind: "secret", secret: ref });
            } finally {
              setStoring(false);
            }
          }}
        >
          Store in vault
        </button>
      </div>
    </label>
  );
}

export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function Toast(props: { message: string | null; onClose: () => void }) {
  useEffect(() => {
    if (!props.message) return;
    const t = setTimeout(props.onClose, 6000);
    return () => clearTimeout(t);
  }, [props.message]);
  if (!props.message) return null;
  return (
    <div className="toast" role="status">
      {props.message}
    </div>
  );
}
