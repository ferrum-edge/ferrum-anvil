// Collection runner: scenarios (ordered saved requests with chaining) and
// folder runs, live progress, and saved reports with per-step outcomes.
import { useEffect, useMemo, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, onRunEvent, onRunFinished, type RunEvent, type RunReport, type Scenario, type TreeNode } from "./api";
import type { Environment } from "./generated/contracts";
import { Modal, SidebarResizer, fmtAgo, fmtUs, humanize } from "./ui";
import { Icon } from "./icons";

type Sel = { kind: "scenario"; id: string } | { kind: "report"; id: string } | { kind: "new" } | null;

function flatRequests(nodes: TreeNode[], path: string[] = []): { id: string; label: string; method: string }[] {
  return nodes.flatMap((n) =>
    n.kind === "folder" ? flatRequests(n.children, [...path, n.name]) : [{ id: n.id, label: [...path, n.name].join(" / "), method: n.method ?? "GET" }],
  );
}
function flatFolders(nodes: TreeNode[], path: string[] = []): { id: string; label: string }[] {
  return nodes.flatMap((n) => (n.kind === "folder" ? [{ id: n.id, label: [...path, n.name].join(" / ") }, ...flatFolders(n.children, [...path, n.name])] : []));
}

export function RunnerView(props: { workspaceId: string; tree: TreeNode[]; environments: Environment[]; activeEnvironment: string | null; notify: (m: string) => void }) {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [reports, setReports] = useState<RunReport[]>([]);
  const [sel, setSel] = useState<Sel>(null);
  const [live, setLive] = useState<{ runId: string; name: string; events: RunEvent[] } | null>(null);
  const [folderPick, setFolderPick] = useState("");
  const [confirmUntrusted, setConfirmUntrusted] = useState<Scenario | null>(null);
  const requests = useMemo(() => flatRequests(props.tree), [props.tree]);
  const folders = useMemo(() => flatFolders(props.tree), [props.tree]);

  const reload = async () => {
    const [s, r] = await Promise.all([api.scenarios(props.workspaceId), api.runReports(props.workspaceId)]);
    setScenarios(s);
    setReports(r);
  };
  useEffect(() => {
    void reload();
  }, [props.workspaceId]);
  useEffect(() => {
    const a = onRunEvent((ev) => setLive((l) => (l && l.runId === ev.run_id ? { ...l, events: [...l.events, ev].slice(-500) } : l)));
    const b = onRunFinished((f) => {
      setLive((l) => (l && l.runId === f.run_id ? null : l));
      if (f.error) props.notify(`Run did not complete: ${f.error}`);
      void reload().then(() => setSel({ kind: "report", id: f.run_id }));
    });
    return () => {
      void a.then((f) => f());
      void b.then((f) => f());
    };
  }, []);

  const start = async (target: Parameters<typeof api.runStart>[0], name: string, allowUntrusted = false) => {
    try {
      const runId = await api.runStart(target, { environment_id: props.activeEnvironment, allow_untrusted: allowUntrusted });
      setLive({ runId, name, events: [] });
    } catch (e) {
      props.notify(String((e as Error).message));
    }
  };

  const runScenario = (s: Scenario) => (s.trusted === false ? setConfirmUntrusted(s) : void start({ kind: "scenario", scenario_id: s.id }, s.name));

  return (
    <div className="main">
      <aside className="sidebar" aria-label="Scenarios and run reports">
        <div className="side-body">
          <div className="side-section-head">
            <span>Scenarios</span>
            <button className="btn ghost small" title="New scenario" onClick={() => setSel({ kind: "new" })}>
              <Icon name="plus" size={14} />
              New
            </button>
          </div>
          {scenarios.length === 0 && <div className="side-empty">No scenarios yet.</div>}
          {scenarios.map((s) => (
            <div
              key={s.id}
              className={`tree-row${sel?.kind === "scenario" && sel.id === s.id ? " selected" : ""}`}
              role="button"
              tabIndex={0}
              onClick={() => setSel({ kind: "scenario", id: s.id })}
              onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "scenario", id: s.id })}
            >
              <Icon name="listChecks" size={14} className="row-icon" />
              <span className="name">{s.name}</span>
              {s.trusted === false && <span className="badge warn">imported</span>}
            </div>
          ))}
          <div className="side-section-head">
            <span>Run a folder</span>
          </div>
          <div className="side-card">
            <select className="field" aria-label="Folder to run" value={folderPick} onChange={(e) => setFolderPick(e.target.value)}>
              <option value="">Whole workspace</option>
              {folders.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
            </select>
            <button
              className="btn"
              disabled={!!live}
              onClick={() => void start({ kind: "folder", workspace_id: props.workspaceId, folder_id: folderPick || null }, folders.find((f) => f.id === folderPick)?.label ?? "Whole workspace")}
            >
              <Icon name="play" size={11} />
              Run folder
            </button>
          </div>
          <div className="side-section-head">
            <span>Reports</span>
          </div>
          {reports.length === 0 && <div className="side-empty">No runs yet.</div>}
          {reports.map((r) => (
            <div
              key={r.run_id}
              className={`hist-row${sel?.kind === "report" && sel.id === r.run_id ? " selected" : ""}`}
              role="button"
              tabIndex={0}
              title={`${r.name} — ${new Date(r.started_at).toLocaleString()}`}
              onClick={() => setSel({ kind: "report", id: r.run_id })}
              onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "report", id: r.run_id })}
            >
              <div className="hist-line">
                <span className="hist-title">{r.name}</span>
                <span className={`badge ${r.totals.steps_failed + r.totals.steps_errored === 0 && r.completion === "completed" ? "ok" : "bad"}`}>
                  {r.totals.steps_passed}/{r.totals.steps_executed}
                </span>
              </div>
              <div className="hist-line">
                <span className="hist-meta">{humanize(r.completion)}</span>
                <span className="hist-when">{fmtAgo(Date.parse(r.started_at))}</span>
              </div>
            </div>
          ))}
        </div>
      </aside>
      <SidebarResizer />
      <section className="work single">
        <div className="pane">
          {live && <LiveRun live={live} onCancel={() => void api.runCancel(live.runId)} />}
          {!live && sel?.kind === "new" && (
            <ScenarioEditor
              requests={requests}
              onCreate={async (name, ids) => {
                const s = await api.createScenario(props.workspaceId, name, ids);
                await reload();
                setSel({ kind: "scenario", id: s.id });
              }}
            />
          )}
          {!live && sel?.kind === "scenario" && (
            <ScenarioDetail
              key={sel.id}
              scenario={scenarios.find((s) => s.id === sel.id)!}
              requests={requests}
              onRun={runScenario}
              onSaved={reload}
              onDeleted={async () => {
                await reload();
                setSel(null);
              }}
            />
          )}
          {!live && sel?.kind === "report" && <ReportView key={sel.id} runId={sel.id} notify={props.notify} onDeleted={async () => { await reload(); setSel(null); }} />}
          {!live && !sel && (
            <div className="empty">
              <div>
                <span className="empty-icon">
                  <Icon name="listChecks" size={22} />
                </span>
                <div className="big">Run saved requests as repeatable tests.</div>
                <div className="sub">Each step is a normal Send: same preparation, auth and diagnostics. Values extracted by earlier steps feed later ones.</div>
                <button className="btn primary" onClick={() => setSel({ kind: "new" })}>
                  <Icon name="plus" size={15} />
                  New scenario
                </button>
              </div>
            </div>
          )}
        </div>
      </section>
      {confirmUntrusted && (
        <Modal
          title="Run an imported scenario?"
          onClose={() => setConfirmUntrusted(null)}
          footer={
            <>
              <button className="btn" onClick={() => setConfirmUntrusted(null)}>
                Cancel
              </button>
              <button
                className="btn"
                onClick={async () => {
                  const s = confirmUntrusted;
                  setConfirmUntrusted(null);
                  await api.trustScenario(s.id);
                  await reload();
                  void start({ kind: "scenario", scenario_id: s.id }, s.name);
                }}
              >
                Trust and run
              </button>
              <button
                className="btn primary"
                onClick={() => {
                  const s = confirmUntrusted;
                  setConfirmUntrusted(null);
                  void start({ kind: "scenario", scenario_id: s.id }, s.name, true);
                }}
              >
                <Icon name="play" size={11} />
                Run once
              </button>
            </>
          }
        >
          <div className="warn-box">“{confirmUntrusted.name}” came from an import. Review its steps and destinations before running it: it sends real requests.</div>
        </Modal>
      )}
    </div>
  );
}

function ScenarioEditor(props: { requests: { id: string; label: string; method: string }[]; onCreate: (name: string, ids: string[]) => Promise<void> }) {
  const [name, setName] = useState("New scenario");
  const [ids, setIds] = useState<string[]>([]);
  const [pick, setPick] = useState("");
  return (
    <div className="page narrow">
      <input className="field title-input" aria-label="Scenario name" value={name} onChange={(e) => setName(e.target.value)} />
      <fieldset>
        <legend>Steps</legend>
        {ids.length === 0 && <div className="empty-note">Add saved requests in the order they should run.</div>}
        {ids.length > 0 && (
          <div className="step-list">
            {ids.map((id, i) => (
              <div className="step-row" key={`${id}-${i}`}>
                <span className="step-n">{i + 1}</span>
                <span className="step-name">{props.requests.find((r) => r.id === id)?.label}</span>
                <button className="btn ghost small icon-btn" aria-label="Remove step" title="Remove step" onClick={() => setIds(ids.filter((_, j) => j !== i))}>
                  <Icon name="x" size={14} />
                </button>
              </div>
            ))}
          </div>
        )}
        <div className="row nowrap">
          <select className="field grow" aria-label="Add step" value={pick} onChange={(e) => setPick(e.target.value)}>
            <option value="">Add a saved request…</option>
            {props.requests.map((r) => (
              <option key={r.id} value={r.id}>
                {r.method} {r.label}
              </option>
            ))}
          </select>
          <button
            className="btn"
            disabled={!pick}
            onClick={() => {
              setIds([...ids, pick]);
              setPick("");
            }}
          >
            <Icon name="plus" size={14} />
            Add step
          </button>
        </div>
      </fieldset>
      <button className="btn primary start" disabled={!name.trim() || ids.length === 0} onClick={() => void props.onCreate(name.trim(), ids)}>
        Create scenario
      </button>
      <p className="hint">Set extractions on a request (Tests tab) to pass values such as tokens or ids to later steps.</p>
    </div>
  );
}

function ScenarioDetail(props: { scenario: Scenario; requests: { id: string; label: string }[]; onRun: (s: Scenario) => void; onSaved: () => void; onDeleted: () => void }) {
  const [s, setS] = useState(props.scenario);
  if (!s) return null;
  return (
    <div className="page narrow">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>{s.name}</h2>
            {s.trusted === false && <span className="badge warn">imported</span>}
          </div>
          <div className="page-meta">
            {s.steps.length} step{s.steps.length === 1 ? "" : "s"} · {s.iterations ?? 1} iteration{(s.iterations ?? 1) === 1 ? "" : "s"}
          </div>
        </div>
        <div className="page-actions">
          <button className="btn primary" onClick={() => props.onRun(s)}>
            <Icon name="play" size={11} />
            Run
          </button>
          <button
            className="btn ghost danger icon-btn"
            aria-label="Delete scenario"
            title="Delete scenario"
            onClick={async () => {
              await api.deleteScenario(s.id);
              props.onDeleted();
            }}
          >
            <Icon name="trash" />
          </button>
        </div>
      </div>
      {s.trusted === false && <div className="warn-box">Imported scenario: review the steps before running it.</div>}
      <fieldset>
        <legend>Steps</legend>
        <div className="step-list">
          {s.steps.map((st, i) => (
            <div className="step-row" key={i}>
              <span className="step-n">{i + 1}</span>
              <span className="step-name">{props.requests.find((r) => r.id === st.request_id)?.label ?? "(missing request)"}</span>
              {st.delay_ms ? <span className="faint small-text">{st.delay_ms} ms think time</span> : null}
            </div>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend>Run options</legend>
        <div className="fields">
          <label className="lbl">
            Iterations
            <input className="field mono tiny" value={s.iterations ?? 1} onChange={(e) => setS({ ...s, iterations: Number(e.target.value) || 1 })} />
          </label>
          <label className="check field-check">
            <input type="checkbox" checked={!!s.stop_on_failure} onChange={(e) => setS({ ...s, stop_on_failure: e.target.checked })} />
            Stop an iteration at its first failed step
          </label>
          <span className="spacer" />
          <button
            className="btn"
            onClick={async () => {
              setS(await api.saveScenario(s));
              props.onSaved();
            }}
          >
            Save
          </button>
        </div>
      </fieldset>
    </div>
  );
}

function LiveRun(props: { live: { runId: string; name: string; events: RunEvent[] }; onCancel: () => void }) {
  const last = [...props.live.events].reverse().find((e) => "progress" in e) as Extract<RunEvent, { progress: unknown }> | undefined;
  const p = last?.progress;
  const steps = props.live.events.filter((e): e is Extract<RunEvent, { event: "step_finished" }> => e.event === "step_finished");
  return (
    <div className="page narrow">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>{props.live.name}</h2>
            <span className="badge accent">
              <span className="live-dot" />
              running
            </span>
          </div>
          <div className="page-meta">
            {p ? `${p.steps_done}/${p.steps_total} steps · ${p.steps_failed} failed · iteration ${p.iterations_done}/${p.iterations_total}` : "Starting…"}
          </div>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={props.onCancel}>
            <Icon name="stop" size={12} />
            Stop run
          </button>
        </div>
      </div>
      <div className="progress" />
      <table className="grid live-steps">
        <thead>
          <tr>
            <th>Step</th>
            <th>Status</th>
            <th>Result</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {steps.slice(-200).map((e, i) => (
            <tr key={i}>
              <td className="k">
                {e.iteration + 1}.{e.step + 1}
              </td>
              <td className="k status-cell">
                <span className={`badge ${e.status === "passed" ? "ok" : "bad"}`}>{e.status}</span>
              </td>
              <td className="v">{e.http_status ?? ""}</td>
              <td className="k">{e.duration_ms != null ? `${e.duration_ms} ms` : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReportView(props: { runId: string; notify: (m: string) => void; onDeleted: () => void }) {
  const [r, setR] = useState<RunReport | null>(null);
  useEffect(() => {
    api.runReport(props.runId).then(setR);
  }, [props.runId]);
  if (!r) return <div className="faint">Loading report…</div>;
  const t = r.totals;
  const exportAs = async (format: "json" | "junit" | "html") => {
    const ext = format === "junit" ? "xml" : format;
    const path = await save({ defaultPath: `anvil-run-${r.name.replace(/[^\w.-]+/g, "_")}-${r.started_at.slice(0, 10)}.${ext}` });
    if (!path) return;
    await api.exportRunReport(r.run_id, format, path);
    props.notify(`Exported to ${path}`);
  };
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>{r.name}</h2>
            <span className={`badge ${r.completion === "completed" && t.steps_failed + t.steps_errored === 0 ? "ok" : "bad"}`}>{humanize(r.completion)}</span>
            {r.partial && <span className="badge warn">partial</span>}
          </div>
          <div className="page-meta">
            {new Date(r.started_at).toLocaleString()} · {(r.duration_ms / 1000).toFixed(1)} s{r.environment_name ? ` · ${r.environment_name}` : ""}
          </div>
        </div>
        <div className="page-actions">
          <div className="btn-group" role="group" aria-label="Export report">
            <button className="btn small" title="Export as JUnit XML" onClick={() => void exportAs("junit")}>
              <Icon name="upload" size={13} />
              JUnit
            </button>
            <button className="btn small" title="Export as HTML" onClick={() => void exportAs("html")}>
              HTML
            </button>
            <button className="btn small" title="Export as JSON" onClick={() => void exportAs("json")}>
              JSON
            </button>
          </div>
          <button
            className="btn small ghost danger"
            onClick={async () => {
              await api.deleteRunReport(r.run_id);
              props.onDeleted();
            }}
          >
            <Icon name="trash" size={13} />
            Delete
          </button>
        </div>
      </div>
      <div className="cards">
        {(
          [
            ["Steps passed", t.steps_passed, false],
            ["Steps failed", t.steps_failed, t.steps_failed > 0],
            ["Errors (not sent)", t.steps_errored, t.steps_errored > 0],
            ["Skipped", t.steps_skipped, false],
            ["Transport failures", t.transport_failures, t.transport_failures > 0],
            ["Application failures", t.application_failures, t.application_failures > 0],
          ] as [string, number, boolean][]
        ).map(([label, v, bad]) => (
          <div className={`card${bad ? " bad" : ""}`} key={label}>
            <div className="card-label">{label}</div>
            <div className="card-value">{v}</div>
          </div>
        ))}
      </div>
      {r.iterations.map((it) => (
        <details key={it.index} open={it.status !== "passed"} className="iteration">
          <summary>
            Iteration {it.index + 1}
            {it.dataset_row != null ? ` (dataset row ${it.dataset_row + 1})` : ""}
            <span className={`badge ${it.status === "passed" ? "ok" : "bad"}`}>{it.status}</span>
            <span className="faint">{it.duration_ms} ms</span>
          </summary>
          <table className="grid steps">
            <thead>
              <tr>
                <th>#</th>
                <th>Step</th>
                <th>Status</th>
                <th>Result</th>
                <th>Why</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {it.steps.map((s) => (
                <tr key={s.index}>
                  <td className="k">{s.index + 1}</td>
                  <td>
                    <div className="step-title">{s.name}</div>
                    <div className="step-url">
                      {s.method} {s.url}
                    </div>
                  </td>
                  <td className="k status-cell">
                    <span className={`badge ${s.status === "passed" ? "ok" : s.status === "skipped" ? "neutral" : "bad"}`}>{s.status}</span>
                  </td>
                  <td className="v">
                    {s.http_status ?? s.grpc_status ?? ""} {s.failed_dimensions?.length ? `(${s.failed_dimensions.join(", ")})` : ""}
                  </td>
                  <td>
                    {s.message ?? s.summary}
                    {s.findings?.slice(0, 2).map((f) => (
                      <div key={f.code} className="step-note">
                        {f.title} ({f.confidence})
                      </div>
                    ))}
                    {s.assertion_results
                      ?.filter((a) => !a.passed)
                      .map((a, i) => (
                        <div key={i} className="step-note s5">
                          ✗ {a.label}: {a.message}
                        </div>
                      ))}
                  </td>
                  <td className="k">{s.exchange_ms != null ? fmtUs(s.exchange_ms * 1000) : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      ))}
    </div>
  );
}
