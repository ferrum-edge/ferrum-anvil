// Contract drift: what the API was seen doing in this collection's sends,
// compared with its OpenAPI description, and revisions to adopt. Also the
// per-send "Contract" tab of the response panel.
import { useEffect, useMemo, useState } from "react";
import { api, type DriftPlan, type DriftReport, type ExecutionDrift } from "./api";
import type { DriftFinding, LintSeverity, Suggestion } from "./generated/contracts";
import { Modal } from "./ui";
import { Icon, type IconName } from "./icons";

const SEV_CLASS: Record<LintSeverity, string> = { error: "error", warn: "warning", info: "info", hint: "info" };
const SEV_BADGE: Record<LintSeverity, string> = { error: "bad", warn: "warn", info: "info", hint: "neutral" };
const SEV_LABEL: Record<LintSeverity, string> = { error: "Error", warn: "Warning", info: "Info", hint: "Hint" };
const SEV_ICON: Record<LintSeverity, IconName> = { error: "alertCircle", warn: "alertTriangle", info: "info", hint: "info" };

const fmtMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`);

/** Inline `code` in generated text (names from the description or the traffic), inert. */
function withCode(text: string) {
  return text.split(/(`[^`]+`)/).map((part, i) => (part.length > 2 && part.startsWith("`") && part.endsWith("`") ? <code key={i}>{part.slice(1, -1)}</code> : part));
}

export function DriftFindingCard(props: { f: DriftFinding; suggestions: Suggestion[] }) {
  const f = props.f;
  const fixes = f.suggestions.map((id) => props.suggestions.find((s) => s.id === id)).filter((s): s is Suggestion => !!s);
  return (
    <article className={`finding sev-${SEV_CLASS[f.severity]}`} aria-label={f.message}>
      <div className="finding-head">
        <span className="sev-icon">
          <Icon name={SEV_ICON[f.severity]} size={16} />
        </span>
        <div className="grow">
          <div className="finding-title">{withCode(f.message)}</div>
          <div className="finding-meta">
            <span className={`badge ${SEV_BADGE[f.severity]}`}>{SEV_LABEL[f.severity]}</span>
            {f.count > 1 && <span className="badge">×{f.count}</span>}
            {f.line != null && <span className="badge">Line {f.line}</span>}
            {f.operation && <span className="owner">{f.operation}</span>}
            <span className="faint mono code-id">{f.kind}</span>
          </div>
        </div>
      </div>
      {fixes.length > 0 && (
        <div className="finding-body">
          <div>
            <h4>Suggested revision</h4>
            <ul>
              {fixes.map((s) => (
                <li key={s.id}>
                  {withCode(s.title)}
                  {s.kind === "relaxation" && <span className="owner"> — relaxes the contract; the API may be what needs fixing</span>}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </article>
  );
}

function SuggestionRow(props: { s: Suggestion; checked: boolean; onToggle: (on: boolean) => void }) {
  const s = props.s;
  return (
    <div className="suggestion">
      <label className="check">
        <input type="checkbox" aria-label={s.title} checked={props.checked} onChange={(e) => props.onToggle(e.target.checked)} />
        <span className="grow">{withCode(s.title)}</span>
        <span className={`badge ${s.kind === "addition" ? "ok" : "warn"}`}>{s.kind === "addition" ? "addition" : "relaxation"}</span>
        {s.line != null && <span className="badge">Line {s.line}</span>}
      </label>
      <div className="suggestion-detail">{withCode(s.detail)}</div>
      <details>
        <summary>Change</summary>
        <pre className="code">{s.snippet}</pre>
      </details>
    </div>
  );
}

/** The import's collection history against its description. */
export function DriftPage(props: { importId: string; fileName: string; notify: (m: string) => void; onReimported: () => void }) {
  const [report, setReport] = useState<DriftReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [plan, setPlan] = useState<DriftPlan | null>(null);
  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.driftReport(props.importId);
      setReport(r);
      setChosen(new Set(r.suggestions.filter((s) => s.recommended).map((s) => s.id)));
    } catch (e) {
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void run();
  }, [props.importId]);
  const ids = useMemo(() => (report ? report.suggestions.filter((s) => chosen.has(s.id)).map((s) => s.id) : []), [report, chosen]);
  const save = async (format: "spec" | "patch") => {
    try {
      const base = props.fileName.replace(/\.[^.]+$/, "") || "openapi";
      const ext = format === "patch" ? "patch.json" : (props.fileName.match(/\.[^.]+$/)?.[0] ?? ".yaml").slice(1);
      const file = await api.chooseFile("spec_revision_export", { file_name: `${base}.revised.${ext}` });
      if (!file) return;
      await api.driftExport(props.importId, ids, format, file.token);
      props.notify(`Saved to ${file.file_name}`);
    } catch (e) {
      props.notify(String((e as Error).message));
    }
  };
  const preview = async () => {
    try {
      setPlan(await api.driftReimportPlan(props.importId, ids));
    } catch (e) {
      props.notify(String((e as Error).message));
    }
  };
  const apply = async () => {
    if (!plan) return;
    // Exactly the previewed revision: the backend refuses it if the analysis changed since.
    const digest = plan.revision.digest;
    setPlan(null);
    try {
      const n = await api.driftReimportApply(props.importId, ids, digest);
      props.notify(`Updated the import (${n} request${n === 1 ? "" : "s"} changed)`);
      props.onReimported();
      await run();
    } catch (e) {
      props.notify(String((e as Error).message));
    }
  };

  if (!report) {
    return (
      <div className="page narrow">
        {busy && <div className="faint">Comparing sends with {props.fileName}…</div>}
        {err && <div className="bad-box">{err}</div>}
      </div>
    );
  }
  const called = report.operations.filter((o) => o.calls > 0).length;
  const errors = report.findings.filter((f) => f.severity === "error").length;
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>Live traffic</h2>
            <span className={`badge ${report.findings.length === 0 ? "ok" : errors > 0 ? "bad" : "warn"}`}>
              {report.findings.length === 0 ? "matches the description" : `${report.findings.length} difference${report.findings.length === 1 ? "" : "s"}`}
            </span>
          </div>
          <div className="page-meta">
            {report.observations} send{report.observations === 1 ? "" : "s"} from history · {report.matched} matched an operation
            {report.from && report.to ? ` · ${new Date(report.from).toLocaleString()} – ${new Date(report.to).toLocaleString()}` : ""}
          </div>
        </div>
        <div className="page-actions">
          <button className="btn small" disabled={busy} onClick={() => void run()}>
            {busy ? "Checking…" : "Check again"}
          </button>
        </div>
      </div>
      {err && <div className="bad-box">{err}</div>}
      <div className="cards">
        <div className="card">
          <div className="card-label">Sends checked</div>
          <div className="card-value">{report.observations}</div>
        </div>
        <div className={`card${errors > 0 ? " bad" : ""}`}>
          <div className="card-label">Differences</div>
          <div className="card-value">{report.findings.length}</div>
        </div>
        <div className="card">
          <div className="card-label">Operations exercised</div>
          <div className="card-value">
            {called}/{report.operations.length}
          </div>
        </div>
        <div className={`card${report.undeclared.length > 0 ? " bad" : ""}`}>
          <div className="card-label">Not in the description</div>
          <div className="card-value">{report.undeclared.length}</div>
        </div>
      </div>
      {report.notes.map((n) => (
        <p className="hint" key={n}>
          {n}
        </p>
      ))}
      {report.findings.length === 0 && report.observations > 0 && <div className="ok-box">Every send matched the description.</div>}
      {report.findings.map((f, i) => (
        <DriftFindingCard key={`${f.kind}|${f.message}|${i}`} f={f} suggestions={report.suggestions} />
      ))}
      {report.suggestions.length > 0 && (
        <fieldset>
          <legend>Suggested revisions</legend>
          <p className="hint">
            Additions document what the API does; relaxations loosen the contract and are not selected by default. Inferred schemas keep the shape of what was seen, never its values.
          </p>
          <div className="row">
            <button className="btn small ghost" onClick={() => setChosen(new Set(report.suggestions.filter((s) => s.recommended).map((s) => s.id)))}>
              Select additions
            </button>
            <button className="btn small ghost" onClick={() => setChosen(new Set(report.suggestions.map((s) => s.id)))}>
              Select all
            </button>
            <button className="btn small ghost" onClick={() => setChosen(new Set())}>
              Select none
            </button>
          </div>
          {report.suggestions.map((s) => (
            <SuggestionRow
              key={s.id}
              s={s}
              checked={chosen.has(s.id)}
              onToggle={(on) =>
                setChosen((c) => {
                  const n = new Set(c);
                  if (on) n.add(s.id);
                  else n.delete(s.id);
                  return n;
                })
              }
            />
          ))}
          <div className="row">
            <button className="btn primary" disabled={ids.length === 0} onClick={() => void preview()}>
              Update the import…
            </button>
            <button className="btn" disabled={ids.length === 0} onClick={() => void save("spec")}>
              <Icon name="upload" size={13} />
              Save revised spec…
            </button>
            <button className="btn" disabled={ids.length === 0} onClick={() => void save("patch")}>
              Save JSON Patch…
            </button>
          </div>
        </fieldset>
      )}
      <fieldset>
        <legend>Coverage</legend>
        <table className="grid coverage">
          <thead>
            <tr>
              <th>Operation</th>
              <th>Calls</th>
              <th>Statuses seen</th>
              <th>p95</th>
              <th>Budget</th>
            </tr>
          </thead>
          <tbody>
            {report.operations.map((o) => (
              <tr key={o.pointer} className={o.calls === 0 ? "faint" : undefined}>
                <td className="mono">{o.operation}</td>
                <td className="k">{o.calls}</td>
                <td className="k">
                  {Object.entries(o.statuses)
                    .map(([k, v]) => `${k}×${v}`)
                    .join(" ") || "—"}
                </td>
                <td className="k">{o.latency_ms ? fmtMs(o.latency_ms.p95) : "—"}</td>
                <td className="k">{o.budget.max_latency_ms != null ? fmtMs(o.budget.max_latency_ms) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {report.undeclared.length > 0 && (
          <>
            <h4 className="subhead">Called, but not in the description</h4>
            <table className="grid coverage">
              <tbody>
                {report.undeclared.map((u) => (
                  <tr key={`${u.method} ${u.path}`}>
                    <td className="mono">
                      {u.method} {u.path}
                    </td>
                    <td className="k">{u.calls}</td>
                    <td className="k">
                      {Object.entries(u.statuses)
                        .map(([k, v]) => `${k}×${v}`)
                        .join(" ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </fieldset>
      {plan && (
        <Modal
          title="Update the import?"
          onClose={() => setPlan(null)}
          footer={
            <>
              <button className="btn" onClick={() => setPlan(null)}>
                Cancel
              </button>
              <button className="btn primary" onClick={() => void apply()}>
                Update import
              </button>
            </>
          }
        >
          <p>
            {plan.revision.applied.length} revision{plan.revision.applied.length === 1 ? "" : "s"} become the import's new version of {props.fileName}. Its requests are updated as in any reimport:
          </p>
          <ul className="plain-list">
            {plan.added.length > 0 && <li>New requests: {plan.added.join(", ")}</li>}
            <li>{plan.updated} updated where you did not edit them</li>
            {plan.conflicts > 0 && <li>{plan.conflicts} you edited are kept as they are</li>}
            {plan.removed > 0 && <li>{plan.removed} no longer in the description are kept</li>}
          </ul>
          {plan.revision.skipped.length > 0 && <div className="warn-box">{plan.revision.skipped.length} chosen revision(s) no longer apply and are left out.</div>}
          <p className="hint">YAML is written anew: comments and formatting of the original are not kept. Save the revised spec instead to merge it into your source by hand.</p>
        </Modal>
      )}
    </div>
  );
}

/** The response panel's check of one send against its import's description. */
export function ContractTab(props: { drift: ExecutionDrift }) {
  const d = props.drift;
  const r = d.report;
  const op = r.operations.find((o) => o.calls > 0);
  return (
    <div className="findings">
      <div className="summary-line">
        Checked against {d.title ? <b>{d.title}</b> : null} ({d.file_name}):{" "}
        {op ? (
          <>
            operation <span className="mono">{op.operation}</span>
          </>
        ) : r.undeclared.length > 0 ? (
          "the description has no such operation"
        ) : (
          "no operation matched"
        )}
        .
      </div>
      {r.findings.length === 0 && <div className="ok-box">This send matches the description.</div>}
      {r.findings.map((f, i) => (
        <DriftFindingCard key={`${f.kind}|${i}`} f={f} suggestions={r.suggestions} />
      ))}
      {r.suggestions.length > 0 && (
        <p className="hint">Apply revisions from the Contract view (the import's Live traffic tab), where every send of the collection is taken into account.</p>
      )}
      {r.notes.map((n) => (
        <p className="hint" key={n}>
          {n}
        </p>
      ))}
    </div>
  );
}
