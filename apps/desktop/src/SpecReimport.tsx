// Reimport a changed spec or collection file into the workspace it was
// imported into: pick the import and the new version of its source (a file
// chosen in the native dialog, or pasted text), review what would change, choose
// what happens to your own edits and to what the source no longer has, then
// apply exactly what was reviewed. Nothing is sent or run.
import { useEffect, useRef, useState } from "react";
import { api, type ReimportChange, type ReimportDecisions, type ReimportPlan, type ReviewedReimport, type SpecInput, type SpecSourceRecord } from "./api";
import { Modal, fmtAgo, humanize } from "./ui";
import { Icon } from "./icons";

/** Rows shown per list before the rest is summarized. */
const LIST_LIMIT = 200;

const sourceName = (s: SpecSourceRecord) => s.source.title || s.file_name;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

type Decision = keyof ReimportDecisions;
const NO_DECISIONS: ReimportDecisions = { overwrite: [], delete: [], overwrite_scope: [], delete_scope: [] };

/**
 * The current id of the import `id` names: a reimport gives the import a new
 * id and keeps the earlier ones in `previous_import_ids`. Null when none has it.
 */
export function currentImportId(list: SpecSourceRecord[], id: string): string | null {
  const found = list.find((s) => s.source.import_id === id) ?? list.find((s) => (s.previous_import_ids ?? []).includes(id));
  return found ? found.source.import_id : null;
}

/** Whether applying the plan writes anything at all. */
export function planChanges(p: ReimportPlan): boolean {
  return (
    p.added.length + p.updated.length + p.conflicts.length + p.removed.length + p.scope_updated.length + p.scope_conflicts.length + p.scope_removed.length > 0
  );
}

export function SpecReimportDialog(props: {
  workspaceId: string;
  workspaceName: string;
  /** The stored name of a request of the workspace, when known. */
  requestName: (id: string) => string | undefined;
  onClose: () => void;
  /** Applied: `requests` is how many requests the import has now. */
  onReimported: (r: { requests: number; fileName: string }) => void;
}) {
  const [sources, setSources] = useState<SpecSourceRecord[] | null>(null);
  const [importId, setImportId] = useState<string>("");
  const [input, setInput] = useState<SpecInput | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [paste, setPaste] = useState("");
  const [reviewed, setReviewed] = useState<ReviewedReimport | null>(null);
  const [decisions, setDecisions] = useState<ReimportDecisions>(NO_DECISIONS);
  const [confirming, setConfirming] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"review" | "apply" | null>(null);
  // A review that finishes after its source or import was changed is dropped.
  const revision = useRef(0);
  const invalidate = () => {
    revision.current += 1;
    setReviewed(null);
    setDecisions(NO_DECISIONS);
    setConfirming(false);
  };

  // Reads read since the dialog closed, or from an earlier read, are dropped.
  const sourceReads = useRef(0);
  const loadSources = async (refresh: boolean) => {
    const n = ++sourceReads.current;
    try {
      const list = await api.specSources(props.workspaceId);
      if (n !== sourceReads.current) return;
      setSources(list);
      // A reimport made elsewhere (the CLI on the same profile) gives the
      // selected import a new id: follow it. On the first read, an unknown
      // id selects the first import; on a refresh it stays, and is refused.
      setImportId((id) => currentImportId(list, id) ?? (refresh && id ? id : (list[0]?.source.import_id ?? "")));
    } catch (e) {
      if (n === sourceReads.current) setErr(String((e as Error).message));
    }
  };
  useEffect(() => {
    void loadSources(false);
    return () => {
      sourceReads.current += 1;
    };
  }, [props.workspaceId]);

  const selected = sources?.find((s) => s.source.import_id === importId) ?? null;
  const effectiveInput = (): SpecInput | null => (paste.trim() ? { kind: "text", text: paste, name: "pasted.txt" } : input);
  const newName = () => (paste.trim() ? "pasted text" : (fileName ?? ""));

  const choose = async () => {
    setErr(null);
    try {
      const f = await api.chooseFile("spec_source", {
        filters: [{ name: "API specs and collections", extensions: ["json", "yaml", "yml", "wsdl", "xml", "har", "txt", "sh"] }],
      });
      if (f) {
        setInput({ kind: "file", grant: f.token });
        setFileName(f.file_name);
        setPaste("");
        invalidate();
      }
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };

  const review = async () => {
    const i = effectiveInput();
    if (!i || !importId) return;
    const seen = revision.current;
    setBusy("review");
    setErr(null);
    try {
      const r = await api.specReimportPlan(importId, i);
      if (revision.current === seen) {
        setReviewed(r);
        setDecisions(NO_DECISIONS);
        setConfirming(false);
      }
    } catch (e) {
      if (revision.current === seen) setReviewed(null);
      setErr(String((e as Error).message));
      // The import may have been reimported meanwhile under a new id.
      void loadSources(true);
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    const i = effectiveInput();
    if (!i || !reviewed) return;
    setBusy("apply");
    setErr(null);
    try {
      // Exactly the reviewed plan: the backend refuses it, writing nothing, if
      // the source or the stored import changed since.
      const n = await api.specReimportApply(importId, i, decisions, reviewed.approval);
      props.onReimported({ requests: n, fileName: newName() || (selected?.file_name ?? "") });
    } catch (e) {
      // A refused apply wrote nothing; its approval is spent either way.
      invalidate();
      setErr(`${String((e as Error).message)} Review the changes again before applying.`);
      // A refusal can mean the import was reimported meanwhile: read the
      // imports again so the next review names its current id.
      void loadSources(true);
    } finally {
      setBusy(null);
    }
  };

  const toggle = (kind: Decision, id: string, on: boolean) => {
    setConfirming(false);
    setDecisions((d) => ({ ...d, [kind]: on ? [...d[kind].filter((x) => x !== id), id] : d[kind].filter((x) => x !== id) }));
  };

  const overwrites = decisions.overwrite.length + decisions.overwrite_scope.length;
  const deletes = decisions.delete.length + decisions.delete_scope.length;
  const destructive = overwrites + deletes > 0;
  const ready = !!effectiveInput() && !!importId;

  const footer = (
    <>
      {confirming ? (
        <button className="btn" disabled={busy !== null} onClick={() => setConfirming(false)}>
          Back
        </button>
      ) : (
        <button className="btn" onClick={props.onClose}>
          Cancel
        </button>
      )}
      <button className={reviewed ? "btn" : "btn primary"} disabled={busy !== null || !ready} onClick={() => void review()}>
        {busy === "review" ? "Reviewing…" : reviewed ? "Review again" : "Review changes"}
      </button>
      {reviewed && (
        <button
          className={`btn ${confirming ? "danger" : "primary"}`}
          disabled={busy !== null}
          onClick={() => (destructive && !confirming ? setConfirming(true) : void apply())}
        >
          <Icon name="download" size={14} />
          {busy === "apply" ? "Applying…" : confirming ? "Confirm and apply" : destructive ? "Apply…" : "Apply"}
        </button>
      )}
    </>
  );

  return (
    <Modal title="Reimport a changed spec" wide onClose={props.onClose} footer={sources && sources.length > 0 ? footer : undefined}>
      <div className="col spec-import">
        {sources === null && !err && <div className="faint">Loading the imports of “{props.workspaceName}”…</div>}
        {sources !== null && sources.length === 0 && (
          <div className="empty-note">
            “{props.workspaceName}” has no imported spec or collection. Import one first (Import → API spec or collection), then reimport it here when its file changes.
          </div>
        )}
        {sources !== null && sources.length > 0 && (
          <>
            <p className="hint">
              Requests keep their ids, folders and history. What changed in the source and not here is updated; your own edits and what the source no longer has are kept unless you
              choose otherwise below. Nothing is sent or run.
            </p>
            <label className="lbl">
              Import to update
              <select
                className="field"
                value={importId}
                disabled={busy === "apply"}
                onChange={(e) => {
                  setImportId(e.target.value);
                  invalidate();
                }}
              >
                {sources.map((s) => (
                  <option key={s.source.import_id} value={s.source.import_id}>
                    {`${sourceName(s)} — ${s.file_name} (${humanize(s.source.kind)}, imported ${fmtAgo(Date.parse(s.source.imported_at))})`}
                  </option>
                ))}
              </select>
            </label>
            <div className="row nowrap">
              <button className="btn" data-autofocus disabled={busy === "apply"} onClick={() => void choose()}>
                <Icon name="file" size={14} />
                Choose the new version…
              </button>
              <span className={`path-chip grow${input?.kind === "file" ? "" : " none"}`} title={input?.kind === "file" ? (fileName ?? undefined) : undefined}>
                {input?.kind === "file" ? fileName : `Last imported from ${selected?.file_name ?? "a file"}`}
              </span>
            </div>
            <label className="lbl">
              …or paste the new version
              <textarea
                className="field"
                rows={3}
                value={paste}
                disabled={busy === "apply"}
                onChange={(e) => {
                  setPaste(e.target.value);
                  invalidate();
                }}
              />
            </label>
          </>
        )}
        {err && (
          <div className="bad-box" role="alert">
            {err}
          </div>
        )}
        {reviewed && (
          <PlanView
            plan={reviewed.plan}
            decisions={decisions}
            requestName={props.requestName}
            disabled={busy !== null}
            onToggle={toggle}
          />
        )}
        {reviewed && confirming && (
          <div className="warn-box" role="alert">
            {overwrites > 0 && <div>Your edits to {plural(overwrites, "item")} will be replaced with the source's version.</div>}
            {deletes > 0 && <div>{plural(deletes, "item")} the source no longer has will be deleted from “{props.workspaceName}”.</div>}
            <div>Choose Back to change this, or Confirm and apply to go ahead.</div>
          </div>
        )}
      </div>
    </Modal>
  );
}

function PlanView(props: {
  plan: ReimportPlan;
  decisions: ReimportDecisions;
  requestName: (id: string) => string | undefined;
  disabled: boolean;
  onToggle: (kind: Decision, id: string, on: boolean) => void;
}) {
  const p = props.plan;
  const name = (c: { existing_id: string; operation_key: string; fresh?: ReimportChange["fresh"] }) =>
    props.requestName(c.existing_id) ?? c.fresh?.name ?? c.operation_key;
  const kept = p.preserved_edits.length + p.scope_preserved_edits.length;
  return (
    <section className="col" aria-label="Reimport plan">
      <table className="grid">
        <tbody>
          <tr>
            <td className="k">New requests</td>
            <td className="v">{p.added.length}</td>
          </tr>
          <tr>
            <td className="k">Updated (not edited here)</td>
            <td className="v">{p.updated.length}</td>
          </tr>
          <tr>
            <td className="k">Edited here and in the source</td>
            <td className="v">{p.conflicts.length}</td>
          </tr>
          <tr>
            <td className="k">No longer in the source</td>
            <td className="v">{p.removed.length}</td>
          </tr>
          <tr>
            <td className="k">Configuration updated / edited in both / gone</td>
            <td className="v">
              {p.scope_updated.length} / {p.scope_conflicts.length} / {p.scope_removed.length}
            </td>
          </tr>
          <tr>
            <td className="k">Unchanged / your edits kept / not from the import</td>
            <td className="v">
              {p.unchanged.length} / {kept} / {p.unlinked.length}
            </td>
          </tr>
        </tbody>
      </table>
      {!planChanges(p) && <div className="ok-box">The new version changes nothing here. Applying it only records it as the import's source.</div>}
      {p.added.length > 0 && (
        <details open>
          <summary>New requests ({p.added.length})</summary>
          <ul className="plain-list">
            {p.added.slice(0, LIST_LIMIT).map((q) => (
              <li key={q.id} className="mono">
                {q.spec.method} {q.name}
              </li>
            ))}
            {p.added.length > LIST_LIMIT && <li>…and {p.added.length - LIST_LIMIT} more</li>}
          </ul>
        </details>
      )}
      {p.updated.length > 0 && (
        <details>
          <summary>Updated ({p.updated.length})</summary>
          <ul className="plain-list">
            {p.updated.slice(0, LIST_LIMIT).map((c) => (
              <li key={c.existing_id}>
                {name(c)} <span className="faint">— {fields(c.upstream_fields?.length ? c.upstream_fields : c.changed_fields)}</span>
              </li>
            ))}
            {p.updated.length > LIST_LIMIT && <li>…and {p.updated.length - LIST_LIMIT} more</li>}
          </ul>
        </details>
      )}
      {(p.conflicts.length > 0 || p.scope_conflicts.length > 0) && (
        <fieldset>
          <legend>Edited here and changed in the source</legend>
          <p className="hint">Kept as you left them unless you tick them: a ticked one takes the source's version. What changed only in the source is updated either way.</p>
          {p.conflicts.map((c) => (
            <label className="check top" key={c.existing_id}>
              <input
                type="checkbox"
                aria-label={`Overwrite your edits to ${name(c)}`}
                checked={props.decisions.overwrite.includes(c.existing_id)}
                disabled={props.disabled}
                onChange={(e) => props.onToggle("overwrite", c.existing_id, e.target.checked)}
              />
              <span className="grow">
                {name(c)}{" "}
                <span className="faint">
                  {c.credential_review && !c.user_edited
                    ? "— its credentials or the request they belong to may have changed: check before taking the source's version"
                    : `— both changed ${fields(c.conflicting_fields?.length ? c.conflicting_fields : c.changed_fields)}`}
                </span>
              </span>
            </label>
          ))}
          {p.scope_conflicts.map((c) => (
            <label className="check top" key={c.key}>
              <input
                type="checkbox"
                aria-label={`Overwrite your edits to ${c.label}`}
                checked={props.decisions.overwrite_scope.includes(c.key)}
                disabled={props.disabled}
                onChange={(e) => props.onToggle("overwrite_scope", c.key, e.target.checked)}
              />
              <span className="grow">
                {c.label}
                {c.credential_review && !c.user_edited && (
                  <span className="faint"> — it holds or feeds credentials that may now belong elsewhere: check before taking it</span>
                )}
              </span>
            </label>
          ))}
        </fieldset>
      )}
      {(p.removed.length > 0 || p.scope_removed.length > 0) && (
        <fieldset>
          <legend>No longer in the source</legend>
          <p className="hint">Kept unless you tick them: a ticked one is deleted.</p>
          {p.removed.map((r) => (
            <label className="check top" key={r.existing_id}>
              <input
                type="checkbox"
                aria-label={`Delete ${name(r)}`}
                checked={props.decisions.delete.includes(r.existing_id)}
                disabled={props.disabled}
                onChange={(e) => props.onToggle("delete", r.existing_id, e.target.checked)}
              />
              <span className="grow">
                {name(r)} {r.user_edited && <span className="badge warn">edited here</span>}
              </span>
            </label>
          ))}
          {p.scope_removed.map((c) => (
            <label className="check top" key={c.key}>
              <input
                type="checkbox"
                aria-label={`Delete ${c.label}`}
                checked={props.decisions.delete_scope.includes(c.key)}
                disabled={props.disabled}
                onChange={(e) => props.onToggle("delete_scope", c.key, e.target.checked)}
              />
              <span className="grow">
                {c.label} {c.user_edited && <span className="badge warn">edited here</span>}
              </span>
            </label>
          ))}
        </fieldset>
      )}
      {p.scope_updated.length > 0 && (
        <details>
          <summary>Configuration updated ({p.scope_updated.length})</summary>
          <ul className="plain-list">
            {p.scope_updated.slice(0, LIST_LIMIT).map((c) => (
              <li key={c.key}>{c.label}</li>
            ))}
            {p.scope_updated.length > LIST_LIMIT && <li>…and {p.scope_updated.length - LIST_LIMIT} more</li>}
          </ul>
        </details>
      )}
    </section>
  );
}

/** Field names of a change, for reading (`spec` is the request itself). */
function fields(list: string[]): string {
  return list.map((f) => (f === "spec" ? "request" : humanize(f))).join(", ") || "details";
}
