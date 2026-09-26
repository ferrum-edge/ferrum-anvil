// Shared UI primitives.
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import type { KeyValue, SensitiveValue } from "./generated/contracts";
import { api } from "./api";
import { Icon } from "./icons";

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

/** "just now", "5 min ago", "3 h ago", "2 d ago", then the local date. */
export function fmtAgo(ms: number, now = Date.now()): string {
  const s = Math.round((now - ms) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  if (s < 7 * 86_400) return `${Math.round(s / 86_400)} d ago`;
  return new Date(ms).toLocaleDateString();
}

export function humanize(s: string): string {
  return s.replace(/_/g, " ");
}

/** The platform's shortcut modifier, as its keycap shows it. */
export const IS_MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
export const MOD = IS_MAC ? "⌘" : "Ctrl";
/** A shortcut for titles and hints, e.g. `shortcut("S")` → "⌘S" or "Ctrl+S". */
export function shortcut(key: string): string {
  const k = key === "Enter" ? (IS_MAC ? "↵" : "Enter") : key;
  return IS_MAC ? `${MOD}${k}` : `${MOD}+${k}`;
}

/** Keycaps for a shortcut: `<Keys k="Enter" />` → ⌘ ↵. */
export function Keys(props: { k: string }) {
  return (
    <>
      <kbd>{MOD}</kbd>
      <kbd>{props.k === "Enter" ? (IS_MAC ? "↵" : "Enter") : props.k}</kbd>
    </>
  );
}

/** Track a pointer drag on one axis; `onMove` gets the delta since the last event. */
export function drag(e: React.MouseEvent, axis: "x" | "y", onMove: (delta: number, ev: MouseEvent) => void) {
  e.preventDefault();
  const handle = e.currentTarget as HTMLElement;
  let last = axis === "x" ? e.clientX : e.clientY;
  handle.classList.add("dragging");
  document.body.classList.add(`dragging-${axis}`);
  const move = (ev: MouseEvent) => {
    const cur = axis === "x" ? ev.clientX : ev.clientY;
    onMove(cur - last, ev);
    last = cur;
  };
  const up = () => {
    handle.classList.remove("dragging");
    document.body.classList.remove(`dragging-${axis}`);
    window.removeEventListener("mousemove", move);
    window.removeEventListener("mouseup", up);
  };
  window.addEventListener("mousemove", move);
  window.addEventListener("mouseup", up);
}

/** Lets every view's sidebar share one width (set by the workbench). */
export const SidebarContext = createContext<{ resize?: (delta: number) => void }>({});

export function SidebarResizer() {
  const { resize } = useContext(SidebarContext);
  if (!resize) return <div className="resizer static" aria-hidden="true" />;
  return (
    <div
      className="resizer"
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize sidebar"
      onMouseDown={(e) => drag(e, "x", (d) => resize(d))}
    />
  );
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
      <div className={`modal${props.wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-label={props.title} ref={ref}>
        <header>
          <h2 title={props.title}>{props.title}</h2>
          <button className="btn ghost icon-btn" aria-label="Close" title="Close (Esc)" onClick={props.onClose}>
            <Icon name="x" />
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
const TEMPLATE_ONLY = /^\s*\{\{.*\}\}\s*$/;

export function KeyValueEditor(props: { rows: KeyValue[]; onChange: (rows: KeyValue[]) => void; nameLabel?: string; valueLabel?: string; emptyText?: string }) {
  const rows = props.rows;
  const set = (i: number, patch: Partial<KeyValue>) => props.onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <div className="kv">
      <span className="kv-head c0" />
      <span className="kv-head">{props.nameLabel ?? "Name"}</span>
      <span className="kv-head">{props.valueLabel ?? "Value"}</span>
      <span className="kv-head" />
      {rows.length === 0 && <div className="kv-empty">{props.emptyText ?? "Nothing here yet."}</div>}
      {rows.map((r, i) => (
        <KvRow key={i} r={r} onSet={(p) => set(i, p)} onRemove={() => props.onChange(rows.filter((_, j) => j !== i))} />
      ))}
      <div className="kv-foot">
        <button className="btn small ghost" onClick={() => props.onChange([...rows, { name: "", value: "", enabled: true }])}>
          <Icon name="plus" size={14} />
          Add
        </button>
      </div>
    </div>
  );
}

function KvRow({ r, onSet, onRemove }: { r: KeyValue; onSet: (p: Partial<KeyValue>) => void; onRemove: () => void }) {
  const sensitive = r.sensitive || SENSITIVE.test(r.name);
  const [reveal, setReveal] = useState(false);
  const off = r.enabled === false ? " off" : "";
  // Row layout: [enabled] [name] [value (+reveal)] [remove]; the name input is itself a cell.
  return (
    <>
      <div className="kv-cell c0 center">
        <input type="checkbox" aria-label="Enabled" checked={r.enabled !== false} onChange={(e) => onSet({ enabled: e.target.checked })} />
      </div>
      <input className={`field mono kv-name${off}`} value={r.name} placeholder="name" aria-label="Name" onChange={(e) => onSet({ name: e.target.value })} />
      <div className={`kv-cell${off}`}>
        <div className="row nowrap">
          <input
            className="field mono grow"
            type={sensitive && !reveal && !TEMPLATE_ONLY.test(r.value) ? "password" : "text"}
            value={r.value}
            placeholder="value or {{variable}}"
            aria-label="Value"
            onChange={(e) => onSet({ value: e.target.value })}
          />
          {sensitive && (
            <button className="btn ghost small icon-btn" aria-label={reveal ? "Hide value" : "Reveal value"} title={reveal ? "Hide value" : "Reveal value"} onClick={() => setReveal(!reveal)}>
              <Icon name={reveal ? "eyeOff" : "eye"} size={14} />
            </button>
          )}
        </div>
      </div>
      <div className="kv-cell center">
        <button className="btn ghost small icon-btn" aria-label="Remove" title="Remove" onClick={onRemove}>
          <Icon name="x" size={14} />
        </button>
      </div>
    </>
  );
}

/** Sensitive value editor: a literal/`{{variable}}` template, or a vault secret reference.
 * `label` also names the vault entry; `hideLabel` keeps it for screen readers only (table cells). */
export function SecretField(props: {
  label: string;
  value: SensitiveValue | undefined;
  onChange: (v: SensitiveValue) => void;
  workspaceId: string | null;
  multiline?: boolean;
  hideLabel?: boolean;
}) {
  const v = props.value ?? { kind: "template", value: "" };
  const [reveal, setReveal] = useState(false);
  const [storing, setStoring] = useState(false);
  const label = props.hideLabel ? <span className="sr-only">{props.label}</span> : props.label;
  if (v.kind === "secret") {
    return (
      <label className="lbl">
        {label}
        <div className="row nowrap">
          <span className="badge accent">
            <Icon name="key" size={12} />
            vault: {v.secret.label}
          </span>
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
      {label}
      <div className={`row nowrap${props.multiline ? " top" : ""}`}>
        <Tag
          className="field mono grow"
          type={!props.multiline && !reveal && !TEMPLATE_ONLY.test(v.value) ? "password" : "text"}
          rows={props.multiline ? 5 : undefined}
          value={v.value}
          placeholder="{{variable}} or a value to keep in the vault"
          onChange={(e: { target: { value: string } }) => props.onChange({ kind: "template", value: e.target.value })}
        />
        {!props.multiline && (
          <button className="btn ghost icon-btn" aria-label={reveal ? "Hide" : "Reveal"} title={reveal ? "Hide" : "Reveal"} onClick={() => setReveal(!reveal)}>
            <Icon name={reveal ? "eyeOff" : "eye"} />
          </button>
        )}
        <button
          className="btn"
          disabled={!props.workspaceId || !v.value || TEMPLATE_ONLY.test(v.value) || storing}
          title={props.workspaceId ? "Move this value into the encrypted vault and keep only a reference" : "Open a workspace to keep values in its vault"}
          onClick={async () => {
            const workspaceId = props.workspaceId;
            if (!workspaceId) return;
            setStoring(true);
            try {
              const ref = await api.createSecret(workspaceId, props.label, v.value);
              props.onChange({ kind: "secret", secret: ref });
            } finally {
              setStoring(false);
            }
          }}
        >
          <Icon name="key" size={14} />
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
      <Icon name="info" />
      <span>{props.message}</span>
      <button className="btn ghost small icon-btn" aria-label="Dismiss" onClick={props.onClose}>
        <Icon name="x" size={14} />
      </button>
    </div>
  );
}
