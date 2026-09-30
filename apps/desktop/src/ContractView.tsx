// API contract: check OpenAPI descriptions (imported ones, or a file) against
// the API standards kept in the profile, and manage those rulesets.
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type LintReport, type LintTarget, type SpecSourceRecord, type StandardsView, type StoredRuleset } from "./api";
import type { LintFinding, LintSeverity } from "./generated/contracts";
import { SidebarResizer, fmtAgo, humanize } from "./ui";
import { Icon, type IconName } from "./icons";

type Sel = { kind: "import"; id: string } | { kind: "file"; grant: string; name: string } | { kind: "rules" } | { kind: "ruleset"; id: string } | null;

const SEV_LABEL: Record<LintSeverity, string> = { error: "Error", warn: "Warning", info: "Info", hint: "Hint" };
const SEV_CLASS: Record<LintSeverity, string> = { error: "error", warn: "warning", info: "info", hint: "info" };
const SEV_BADGE: Record<LintSeverity, string> = { error: "bad", warn: "warn", info: "info", hint: "neutral" };
const SEV_ICON: Record<LintSeverity, IconName> = { error: "alertCircle", warn: "alertTriangle", info: "info", hint: "info" };
const SEV_PLURAL: Record<LintSeverity, string> = { error: "Errors", warn: "Warnings", info: "Info", hint: "Hints" };
const DIALECT: Record<string, string> = { swagger20: "Swagger 2.0", open_api30: "OpenAPI 3.0", open_api31: "OpenAPI 3.1", open_api32: "OpenAPI 3.2" };
/** Findings rendered before "Show more". */
const PAGE = 200;

const isOpenApi = (s: SpecSourceRecord) => s.source.kind === "open_api";
const specName = (s: SpecSourceRecord) => s.source.title || s.file_name;

export function ContractView(props: { workspaceId: string; notify: (m: string) => void; hidden?: boolean }) {
  const [sources, setSources] = useState<SpecSourceRecord[]>([]);
  const [standards, setStandards] = useState<StandardsView | null>(null);
  const [sel, setSel] = useState<Sel>(null);
  const [shownWs, setShownWs] = useState(props.workspaceId);
  if (shownWs !== props.workspaceId) {
    setShownWs(props.workspaceId);
    setSources([]);
    setSel((s) => (s?.kind === "import" ? null : s));
  }
  const wsRef = useRef(props.workspaceId);
  wsRef.current = props.workspaceId;

  const loadSources = async () => {
    const w = props.workspaceId;
    try {
      const list = await api.specSources(w);
      if (w === wsRef.current) setSources(list.filter(isOpenApi));
    } catch (e) {
      props.notify(String((e as Error).message));
    }
  };
  const loadStandards = async () => {
    try {
      setStandards(await api.standards());
    } catch (e) {
      props.notify(String((e as Error).message));
    }
  };
  useEffect(() => {
    void loadSources();
  }, [props.workspaceId]);
  useEffect(() => {
    // Imports made while this view was hidden show up when it is shown again.
    if (!props.hidden) void loadSources();
  }, [props.hidden]);
  useEffect(() => {
    void loadStandards();
  }, []);

  const change = async (op: () => Promise<unknown>) => {
    try {
      await op();
    } catch (e) {
      props.notify(String((e as Error).message));
    }
    await loadStandards();
  };
  const chooseRuleset = async () => {
    const f = await api.chooseFile("ruleset", { filters: [{ name: "Rulesets", extensions: ["yaml", "yml", "json"] }] });
    return f;
  };
  const addRuleset = async () => {
    try {
      const f = await chooseRuleset();
      if (!f) return;
      const r = await api.standardsAdd(f.token);
      props.notify(`Added ruleset “${r.name}”`);
      setSel({ kind: "ruleset", id: r.id });
    } catch (e) {
      props.notify(String((e as Error).message));
    }
    await loadStandards();
  };
  const chooseSpec = async () => {
    try {
      const f = await api.chooseFile("spec_source", { filters: [{ name: "OpenAPI and Swagger", extensions: ["json", "yaml", "yml"] }] });
      if (f) setSel({ kind: "file", grant: f.token, name: f.file_name });
    } catch (e) {
      props.notify(String((e as Error).message));
    }
  };

  const rulesets = standards?.standards.rulesets ?? [];
  const selRuleset = sel?.kind === "ruleset" ? rulesets.find((r) => r.id === sel.id) : undefined;
  const selImport = sel?.kind === "import" ? sources.find((s) => s.source.import_id === sel.id) : undefined;
  const target: LintTarget | null =
    sel?.kind === "import" ? { kind: "import", import_id: sel.id } : sel?.kind === "file" ? { kind: "spec", input: { kind: "file", grant: sel.grant } } : null;
  const targetName = selImport ? selImport.file_name : sel?.kind === "file" ? sel.name : "";
  // A new standards set re-runs the shown check.
  const rulesKey = standards ? JSON.stringify(standards.standards) : "";

  return (
    <div className="main" style={props.hidden ? { display: "none" } : undefined}>
      <aside className="sidebar" aria-label="Specs and rulesets">
        <div className="side-body">
          <div className="side-section-head">
            <span>Imported specs</span>
          </div>
          {sources.length === 0 && <div className="side-empty">Import an OpenAPI or Swagger description (Import → API spec) to check it here.</div>}
          {sources.map((s) => (
            <div
              key={s.source.import_id}
              className={`hist-row${sel?.kind === "import" && sel.id === s.source.import_id ? " selected" : ""}`}
              role="button"
              tabIndex={0}
              title={`${s.file_name} — imported ${new Date(s.source.imported_at).toLocaleString()}`}
              onClick={() => setSel({ kind: "import", id: s.source.import_id })}
              onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "import", id: s.source.import_id })}
            >
              <div className="hist-line">
                <span className="hist-title">{specName(s)}</span>
                <span className="badge neutral">{DIALECT[s.source.dialect] ?? s.source.dialect}</span>
              </div>
              <div className="hist-line">
                <span className="hist-meta">{s.file_name}</span>
                <span className="hist-when">{fmtAgo(Date.parse(s.source.imported_at))}</span>
              </div>
            </div>
          ))}
          <div className="side-card">
            <button className="btn" onClick={() => void chooseSpec()}>
              <Icon name="file" size={14} />
              Check a spec file…
            </button>
          </div>
          <div className="side-section-head">
            <span>API standards</span>
            <button className="btn ghost small" aria-label="Add a ruleset file" title="Add a ruleset file" onClick={() => void addRuleset()}>
              <Icon name="plus" size={14} />
              Add
            </button>
          </div>
          {standards?.error && <div className="bad-box small-text">The rulesets do not load: {standards.error}. Disable or remove the one at fault.</div>}
          <label className="tree-row check" title="Anvil's built-in rules, applied before your rulesets">
            <input
              type="checkbox"
              aria-label="Include Anvil recommended rules"
              checked={standards?.standards.include_recommended ?? true}
              disabled={!standards}
              onChange={(e) => void change(() => api.standardsSetRecommended(e.target.checked))}
            />
            <span className="name">Anvil recommended</span>
            <span className="badge neutral">built-in</span>
          </label>
          {rulesets.map((r) => (
            <div key={r.id} className={`tree-row${sel?.kind === "ruleset" && sel.id === r.id ? " selected" : ""}`}>
              <input
                type="checkbox"
                aria-label={`Use ${r.name}`}
                checked={r.enabled}
                onChange={(e) => void change(() => api.standardsSetEnabled(r.id, e.target.checked))}
              />
              <span className="name" role="button" tabIndex={0} onClick={() => setSel({ kind: "ruleset", id: r.id })} onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "ruleset", id: r.id })}>
                {r.name}
              </span>
              {r.version && <span className="badge neutral">{r.version}</span>}
            </div>
          ))}
          <div
            className={`tree-row${sel?.kind === "rules" ? " selected" : ""}`}
            role="button"
            tabIndex={0}
            onClick={() => setSel({ kind: "rules" })}
            onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "rules" })}
          >
            <Icon name="listChecks" size={14} className="row-icon" />
            <span className="name">Rules in effect</span>
            {standards && <span className="badge neutral">{standards.rules.length}</span>}
          </div>
        </div>
      </aside>
      <SidebarResizer />
      <section className="work single">
        <div className="pane">
          {target && <LintPage key={`${JSON.stringify(target)}|${rulesKey}`} target={target} fileName={targetName} notify={props.notify} />}
          {sel?.kind === "rules" && standards && <RulesPage view={standards} />}
          {selRuleset && (
            <RulesetPage
              key={selRuleset.id}
              ruleset={selRuleset}
              view={standards}
              onReplace={async () => {
                const f = await chooseRuleset().catch((e) => props.notify(String((e as Error).message)));
                if (f) await change(() => api.standardsReplace(selRuleset.id, f.token));
              }}
              onRemove={async () => {
                await change(() => api.standardsRemove(selRuleset.id));
                setSel(null);
              }}
            />
          )}
          {(!sel || (sel.kind === "import" && !selImport) || (sel.kind === "ruleset" && !selRuleset)) && (
            <div className="empty">
              <div>
                <span className="empty-icon">
                  <Icon name="fileCheck" size={22} />
                </span>
                <div className="big">Check OpenAPI descriptions against your API standards.</div>
                <div className="sub">
                  Add your team's ruleset (YAML or JSON) and pick a spec: every finding names the rule, the line to edit and how to fix it. Works for Swagger 2.0 and OpenAPI 3.0, 3.1 and 3.2.
                </div>
                <div className="row">
                  <button className="btn primary" onClick={() => void chooseSpec()}>
                    <Icon name="file" size={15} />
                    Check a spec file…
                  </button>
                  <button className="btn" onClick={() => void addRuleset()}>
                    <Icon name="plus" size={15} />
                    Add ruleset…
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function LintPage(props: { target: LintTarget; fileName: string; notify: (m: string) => void }) {
  const [report, setReport] = useState<LintReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState<LintSeverity | "all">("all");
  const [shown, setShown] = useState(PAGE);
  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      setReport(await api.lintSpec(props.target));
    } catch (e) {
      setReport(null);
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void run();
  }, []);
  const findings = useMemo(() => (report ? report.findings.filter((f) => filter === "all" || f.severity === filter) : []), [report, filter]);
  const exportAs = async (format: "json" | "sarif") => {
    try {
      const base = props.fileName.replace(/\.[^.]+$/, "") || "spec";
      const file = await api.chooseFile("lint_report_export", { file_name: `${base}.standards.${format === "sarif" ? "sarif" : "json"}` });
      if (!file) return;
      await api.exportLintReport(props.target, format, props.fileName, file.token);
      props.notify(`Exported to ${file.file_name}`);
    } catch (e) {
      props.notify(String((e as Error).message));
    }
  };
  if (!report) {
    return (
      <div className="page narrow">
        {busy && <div className="faint">Checking {props.fileName}…</div>}
        {err && (
          <>
            <div className="bad-box">{err}</div>
            <div className="row">
              <button className="btn" onClick={() => void run()}>
                Check again
              </button>
            </div>
          </>
        )}
      </div>
    );
  }
  const c = report.counts;
  const passed = c.error === 0;
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>{report.spec.title || props.fileName}</h2>
            <span className="badge neutral">{DIALECT[report.spec.dialect] ?? report.spec.dialect}</span>
            <span className={`badge ${passed ? "ok" : "bad"}`}>{passed ? "meets the standards" : "does not meet the standards"}</span>
          </div>
          <div className="page-meta">
            {props.fileName}
            {report.spec.version ? ` · version ${report.spec.version}` : ""} · {report.spec.operations} operation{report.spec.operations === 1 ? "" : "s"} · {report.rules_run} rules from{" "}
            {report.rulesets.map((r) => r.name).join(", ") || "no ruleset"}
          </div>
        </div>
        <div className="page-actions">
          <button className="btn small" disabled={busy} onClick={() => void run()} title="Read the spec again and re-check it">
            {busy ? "Checking…" : "Check again"}
          </button>
          <div className="btn-group" role="group" aria-label="Export report">
            <button className="btn small" title="Export as SARIF (code scanning)" onClick={() => void exportAs("sarif")}>
              <Icon name="upload" size={13} />
              SARIF
            </button>
            <button className="btn small" title="Export as JSON" onClick={() => void exportAs("json")}>
              JSON
            </button>
          </div>
        </div>
      </div>
      {err && <div className="bad-box">{err}</div>}
      <div className="cards">
        {(["error", "warn", "info", "hint"] as LintSeverity[]).map((s) => (
          <button
            key={s}
            className={`card${s === "error" && c.error > 0 ? " bad" : ""}${filter === s ? " selected" : ""}`}
            aria-pressed={filter === s}
            title={`Show only ${SEV_PLURAL[s].toLowerCase()}`}
            onClick={() => {
              setFilter(filter === s ? "all" : s);
              setShown(PAGE);
            }}
          >
            <div className="card-label">{SEV_PLURAL[s]}</div>
            <div className="card-value">{c[s]}</div>
          </button>
        ))}
      </div>
      {report.findings.length === 0 && <div className="ok-box">No findings: the description meets every rule in effect.</div>}
      {findings.slice(0, shown).map((f, i) => (
        <LintFindingCard key={`${f.rule}|${f.pointer}|${i}`} f={f} />
      ))}
      {findings.length > shown && (
        <div className="row">
          <button className="btn" onClick={() => setShown(shown + PAGE)}>
            Show {Math.min(PAGE, findings.length - shown)} more of {findings.length - shown}
          </button>
        </div>
      )}
      {(report.unresolved_ref_count ?? 0) > 0 && (
        <div className="warn-box">
          {report.unresolved_ref_count} <code>$ref</code>
          {report.unresolved_ref_count === 1 ? " was" : "s were"} not followed (external, missing or cyclic), so what they point to was not checked:{" "}
          <span className="mono">{(report.unresolved_refs ?? []).slice(0, 5).join(", ")}</span>
          {(report.unresolved_ref_count ?? 0) > 5 ? ", …" : ""}
        </div>
      )}
      {report.dropped > 0 && <p className="hint">{report.dropped} more findings are counted above but not listed. Fix the most severe first, or export the report.</p>}
    </div>
  );
}

function LintFindingCard({ f }: { f: LintFinding }) {
  return (
    <article className={`finding sev-${SEV_CLASS[f.severity]}`} aria-label={f.message}>
      <div className="finding-head">
        <span className="sev-icon">
          <Icon name={SEV_ICON[f.severity]} size={16} />
        </span>
        <div className="grow">
          <div className="finding-title">{f.message}</div>
          <div className="finding-meta">
            <span className={`badge ${SEV_BADGE[f.severity]}`}>{SEV_LABEL[f.severity]}</span>
            {f.line != null && <span className="badge">Line {f.line}{f.column != null ? `:${f.column}` : ""}</span>}
            <span className="owner">{f.label}</span>
            <span className="faint mono code-id">{f.rule}</span>
          </div>
        </div>
      </div>
      <div className="finding-body">
        {f.how_to_fix ? <div>{withCode(f.how_to_fix)}</div> : <div className="faint">No fix is suggested for this rule.</div>}
        <div>
          <h4>Where</h4>
          <div className="mono small-text wrap-anywhere">{f.pointer || "/"}</div>
        </div>
        <div>
          <h4>Rule</h4>
          <div>
            {f.rule} · {f.ruleset}
          </div>
          {f.docs_url && <div className="mono small-text wrap-anywhere">{f.docs_url}</div>}
        </div>
      </div>
    </article>
  );
}

/** Ruleset text with `backticks` shown as code (the text itself stays inert). */
function withCode(text: string) {
  return text.split(/(`[^`]+`)/).map((part, i) => (part.length > 2 && part.startsWith("`") && part.endsWith("`") ? <code key={i}>{part.slice(1, -1)}</code> : part));
}

function RulesPage(props: { view: StandardsView }) {
  const v = props.view;
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>Rules in effect</h2>
            <span className="badge neutral">{v.rules.length}</span>
          </div>
          <div className="page-meta">Layered in order: {v.sources.map((s) => `${s.name}${s.version ? ` ${s.version}` : ""}`).join(" → ") || "no ruleset"}</div>
        </div>
      </div>
      <table className="grid rules">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule</th>
            <th>Applies to</th>
            <th>From</th>
          </tr>
        </thead>
        <tbody>
          {v.rules.map((r) => (
            <tr key={r.id}>
              <td className="k">
                <span className={`badge ${SEV_BADGE[r.severity]}`}>{SEV_LABEL[r.severity]}</span>
              </td>
              <td>
                <div className="mono">{r.id}</div>
                {r.description && <div className="step-note">{withCode(r.description)}</div>}
              </td>
              <td className="k">
                {humanize(r.given)}
                {r.formats.length > 0 && <div className="step-note">{r.formats.join(", ")}</div>}
              </td>
              <td className="k">{r.ruleset}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {v.disabled.length > 0 && <p className="hint">Turned off by a ruleset: {v.disabled.join(", ")}.</p>}
    </div>
  );
}

function RulesetPage(props: { ruleset: StoredRuleset; view: StandardsView | null; onReplace: () => void; onRemove: () => void }) {
  const r = props.ruleset;
  const own = props.view?.rules.filter((x) => x.ruleset === r.name) ?? [];
  return (
    <div className="page narrow">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>{r.name}</h2>
            {r.version && <span className="badge neutral">{r.version}</span>}
            {!r.enabled && <span className="badge warn">not used</span>}
          </div>
          <div className="page-meta">
            {r.file_name} · added {new Date(r.added_at).toLocaleString()} · sha256 {r.sha256.slice(0, 12)}…
          </div>
        </div>
        <div className="page-actions">
          <button className="btn small" title="Replace with a newer version of the file" onClick={props.onReplace}>
            <Icon name="download" size={13} />
            Replace…
          </button>
          <button className="btn small ghost danger" onClick={props.onRemove}>
            <Icon name="trash" size={13} />
            Remove
          </button>
        </div>
      </div>
      <fieldset>
        <legend>Rules it defines</legend>
        {own.length === 0 && <div className="empty-note">It only changes the severity of inherited rules, or it is not used.</div>}
        {own.map((x) => (
          <div className="step-row" key={x.id}>
            <span className={`badge ${SEV_BADGE[x.severity]}`}>{SEV_LABEL[x.severity]}</span>
            <span className="step-name">
              <span className="mono">{x.id}</span>
              {x.description ? <> — {withCode(x.description)}</> : ""}
            </span>
          </div>
        ))}
      </fieldset>
      <details>
        <summary>Ruleset text</summary>
        <pre className="code">{r.text}</pre>
      </details>
    </div>
  );
}
