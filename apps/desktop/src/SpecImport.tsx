// OpenAPI / WSDL / Postman / Insomnia / cURL / HAR import: pick or paste,
// preview what will be created and what was not representable, then import.
// Nothing imported is sent or run.
import { useState } from "react";
import { api, DEFAULT_IMPORT_OPTIONS, type ImportOptions, type SpecImported, type SpecInput, type SpecPreview } from "./api";
import { humanize } from "./ui";
import { Icon } from "./icons";

export function SpecImport(props: { workspaceId: string | null; workspaceName: string | null; onImported: (r: SpecImported) => void }) {
  const [input, setInput] = useState<SpecInput | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [paste, setPaste] = useState("");
  const [opts, setOpts] = useState<ImportOptions>(DEFAULT_IMPORT_OPTIONS);
  const [target, setTarget] = useState<"new" | "current">("new");
  const [preview, setPreview] = useState<SpecPreview | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const effectiveInput = (): SpecInput | null => (paste.trim() ? { kind: "text", text: paste, name: "pasted.txt" } : input);

  const doPreview = async () => {
    const i = effectiveInput();
    if (!i) return;
    setBusy(true);
    setErr(null);
    try {
      setPreview(await api.specPreview(i, opts));
    } catch (e) {
      setPreview(null);
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  const doImport = async () => {
    const i = effectiveInput();
    if (!i) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await api.specImport(i, opts, target === "current" && props.workspaceId ? { kind: "workspace", workspace_id: props.workspaceId } : { kind: "new_workspace" });
      props.onImported(r);
    } catch (e) {
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  const setOpt = (patch: Partial<ImportOptions>) => {
    setOpts({ ...opts, ...patch });
    setPreview(null);
  };

  return (
    <div className="col spec-import">
      <div className="row nowrap">
        <button
          className="btn"
          data-autofocus
          onClick={async () => {
            setErr(null);
            try {
              const f = await api.chooseFile("spec_source", {
                filters: [{ name: "API specs and collections", extensions: ["json", "yaml", "yml", "wsdl", "xml", "har", "txt", "sh"] }],
              });
              if (f) {
                setInput({ kind: "file", grant: f.token });
                setFileName(f.file_name);
                setPaste("");
                setPreview(null);
              }
            } catch (e) {
              setErr(String((e as Error).message));
            }
          }}
        >
          <Icon name="file" size={14} />
          Choose file…
        </button>
        <span className={`path-chip grow${input?.kind === "file" ? "" : " none"}`} title={input?.kind === "file" ? (fileName ?? undefined) : undefined}>
          {input?.kind === "file" ? fileName : "OpenAPI 2.0–3.2, WSDL 1.1, Postman v2.x, Insomnia v4, HAR"}
        </span>
      </div>
      <label className="lbl">
        …or paste a cURL command (or any of the formats above)
        <textarea
          className="field"
          rows={3}
          value={paste}
          placeholder="curl -X POST https://api.example.com/v1/orders -H 'Content-Type: application/json' -d '{…}'"
          onChange={(e) => {
            setPaste(e.target.value);
            setPreview(null);
          }}
        />
      </label>
      <div className="fields">
        <label className="lbl">
          Request bodies
          <select className="field" value={opts.mode} onChange={(e) => setOpt({ mode: e.target.value as "sample" })}>
            <option value="sample">Sample values (examples, defaults, generated)</option>
            <option value="blank">Blank skeletons</option>
          </select>
        </label>
        <label className="lbl">
          Folders by
          <select className="field" value={opts.group_by} onChange={(e) => setOpt({ group_by: e.target.value as "tags" })}>
            <option value="tags">Tags</option>
            <option value="paths">First path segment</option>
          </select>
        </label>
        <label className="lbl">
          Server (OpenAPI)
          <input className="field mono tiny" value={opts.server_index} onChange={(e) => setOpt({ server_index: Number(e.target.value) || 0 })} />
        </label>
        <label className="check field-check">
          <input type="checkbox" checked={opts.include_optional} onChange={(e) => setOpt({ include_optional: e.target.checked })} />
          Include optional fields
        </label>
      </div>
      <label className="check">
        <input type="checkbox" checked={opts.include_credentials} onChange={(e) => setOpt({ include_credentials: e.target.checked })} />
        Keep literal credentials found in HAR/cURL/Postman/Insomnia (off: they become placeholders)
      </label>
      {opts.include_credentials && <div className="warn-box">Literal credentials will be stored in requests. Prefer moving them into the vault after import.</div>}
      <div className="row import-actions">
        <label className="check">
          <input type="radio" name="spec-target" checked={target === "new"} onChange={() => setTarget("new")} />
          New workspace
        </label>
        <label className="check">
          <input type="radio" name="spec-target" disabled={!props.workspaceId} checked={target === "current"} onChange={() => setTarget("current")} />
          Into “{props.workspaceName ?? "current workspace"}” (new folder)
        </label>
        <span className="spacer" />
        <button className="btn" disabled={busy || !effectiveInput()} onClick={doPreview}>
          Preview
        </button>
        <button className="btn primary" disabled={busy || !preview} onClick={doImport}>
          <Icon name="download" size={14} />
          Import
        </button>
      </div>
      {err && <div className="bad-box">{err}</div>}
      {preview && <PreviewView p={preview} />}
      <p className="hint">Imports never send requests or run scripts. Scripts in Postman/Insomnia collections are kept only as notes in the report. External $refs are listed, never fetched.</p>
    </div>
  );
}

function PreviewView({ p }: { p: SpecPreview }) {
  const r = p.report;
  return (
    <div className="col">
      <div className="row">
        <span className="badge accent">{humanize(p.detected.kind)}</span>
        <span className="badge">{humanize(p.detected.dialect)}</span>
        {p.detected.declared_version && <span className="badge">v{p.detected.declared_version}</span>}
        {p.title && <b>{p.title}</b>}
      </div>
      <table className="grid">
        <tbody>
          <tr>
            <td className="k">Requests / folders / environments</td>
            <td className="v">
              {p.requests} / {p.folders} / {p.environments}
            </td>
          </tr>
          <tr>
            <td className="k">Operations found / skipped</td>
            <td className="v">
              {r.counts.operations_found} / {r.counts.skipped_operations}
            </td>
          </tr>
        </tbody>
      </table>
      {r.required_variables.length > 0 && (
        <div className="warn-box">
          Fill in after import: {r.required_variables.slice(0, 12).map((v) => `{{${v.name}}}${v.secret ? " (secret)" : ""}`).join(", ")}
          {r.required_variables.length > 12 ? ` and ${r.required_variables.length - 12} more` : ""}
        </div>
      )}
      <Section title="Redacted credentials" items={r.redactions.map((x) => `${x.field} → ${x.placeholder} (${x.pointer})`)} />
      <Section title="Not imported / not representable" items={r.unsupported.map((x) => `${x.message} (${x.pointer})`)} />
      <Section title="Warnings" items={r.warnings.map((x) => `${x.message} (${x.pointer})`)} />
      <Section title="External references (not fetched)" items={r.external_refs.map((x) => `${x.reference} — ${humanize(x.kind)}`)} />
      <Section title="Scripts kept as notes (never run)" items={r.scripts.map((x) => `${x.owner} ${x.event} (${x.language})`)} />
      <Section title="Settings imported inactive" items={r.inactive_settings.map((x) => `${x.setting}: ${x.reason}`)} />
      <details>
        <summary>First requests</summary>
        <pre className="code">{p.sample.join("\n")}</pre>
      </details>
    </div>
  );
}

function Section(props: { title: string; items: string[] }) {
  if (props.items.length === 0) return null;
  return (
    <details>
      <summary>
        {props.title} ({props.items.length})
      </summary>
      <ul className="plain-list">
        {props.items.slice(0, 200).map((x, i) => (
          <li key={i} className="mono">
            {x}
          </li>
        ))}
      </ul>
    </details>
  );
}
