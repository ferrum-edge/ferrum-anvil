// Collection runner: scenarios (ordered saved requests with chaining) and
// folder runs, live progress, and saved reports with per-step outcomes.
import { useEffect, useMemo, useRef, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, onRunEvent, onRunFinished, type RunEvent, type RunReport, type Scenario, type TreeNode } from "./api";
import type { Environment } from "./generated/contracts";
import { Modal, fmtUs, humanize } from "./ui";

type Sel = { kind: "scenario"; id: string } | { kind: "report"; id: string } | { kind: "new" } | null;

function flatRequests(nodes: TreeNode[], path: string[] = []): { id: string; label: string; method: string }[] {
  return nodes.flatMap((n) =>
    n.kind === "folder" ? flatRequests(n.children, [...path, n.name]) : [{ id: n.id, label: [...path, n.name].join(" / "), method: n.method ?? "GET" }],
  );
}
function flatFolders(nodes: TreeNode[], path: string[] = []): { id: string; label: string }[] {
  return nodes.flatMap((n) => (n.kind === "folder" ? [{ id: n.id, label: [...path, n.name].join(" / ") }, ...flatFolders(n.children, [...path, n.name])] : []));
}

/**
 * Stays mounted (only hidden) while another view is shown: a run continues in
 * the backend, and this view holds its only live progress and Stop control.
 */
export function RunnerView(props: {
  workspaceId: string;
  tree: TreeNode[];
  environments: Environment[];
  activeEnvironment: string | null;
  notify: (m: string) => void;
  hidden?: boolean;
  onLiveChange?: (live: boolean) => void;
}) {
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
  // The run listeners outlive renders: read the current workspace and callbacks.
  const current = useRef({ reload, notify: props.notify });
  current.current = { reload, notify: props.notify };
  useEffect(() => {
    void reload();
  }, [props.workspaceId]);
  useEffect(() => {
    props.onLiveChange?.(!!live);
  }, [!!live]);
  useEffect(() => {
    const a = onRunEvent((ev) => setLive((l) => (l && l.runId === ev.run_id ? { ...l, events: [...l.events, ev].slice(-500) } : l)));
    const b = onRunFinished((f) => {
      setLive((l) => (l && l.runId === f.run_id ? null : l));
      if (f.error) current.current.notify(`Run did not complete: ${f.error}`);
      void current.current.reload().then(() => setSel({ kind: "report", id: f.run_id }));
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
    <div className="main" style={{ ["--sidebar-w" as string]: "290px", display: props.hidden ? "none" : undefined }}>
      <aside className="sidebar" aria-label="Scenarios and run reports">
        <div className="side-body">
          <div className="row" style={{ marginBottom: 6 }}>
            <b className="grow">Scenarios</b>
            <button className="btn small" onClick={() => setSel({ kind: "new" })}>
              + Scenario
            </button>
          </div>
          {scenarios.length === 0 && <div className="faint" style={{ padding: 6 }}>No scenarios yet.</div>}
          {scenarios.map((s) => (
            <div key={s.id} className={`tree-row ${sel?.kind === "scenario" && sel.id === s.id ? "selected" : ""}`} role="button" tabIndex={0} onClick={() => setSel({ kind: "scenario", id: s.id })}>
              <span className="name grow">{s.name}</span>
              {s.trusted === false && <span className="badge warn">imported</span>}
            </div>
          ))}
          <div className="col" style={{ margin: "14px 0" }}>
            <b>Run a folder</b>
            <select className="field" aria-label="Folder to run" value={folderPick} onChange={(e) => setFolderPick(e.target.value)}>
              <option value="">Whole workspace</option>
              {folders.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
            </select>
            <button
              className="btn small"
              disabled={!!live}
              onClick={() => void start({ kind: "folder", workspace_id: props.workspaceId, folder_id: folderPick || null }, folders.find((f) => f.id === folderPick)?.label ?? "Whole workspace")}
            >
              Run folder
            </button>
          </div>
          <b>Reports</b>
          {reports.length === 0 && <div className="faint" style={{ padding: 6 }}>No runs yet.</div>}
          {reports.map((r) => (
            <div key={r.run_id} className={`hist-row ${sel?.kind === "report" && sel.id === r.run_id ? "selected" : ""}`} role="button" tabIndex={0} onClick={() => setSel({ kind: "report", id: r.run_id })}>
              <span className={`badge ${r.totals.steps_failed + r.totals.steps_errored === 0 && r.completion === "completed" ? "ok" : "bad"}`} style={{ justifySelf: "start" }}>
                {r.totals.steps_passed}/{r.totals.steps_executed}
              </span>
              <span className="mono" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {r.name}
              </span>
              <span />
              <span className="faint" style={{ fontSize: 11 }}>
                {new Date(r.started_at).toLocaleString()} · {humanize(r.completion)}
              </span>
            </div>
          ))}
        </div>
      </aside>
      <div className="resizer" />
      <section className="work" style={{ gridTemplateRows: "1fr" }}>
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
                <div className="big">Run saved requests as repeatable tests.</div>
                <div>Each step is a normal Send: same preparation, auth and diagnostics. Values extracted by earlier steps feed later ones.</div>
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
                Run once
              </button>
            </>
          }
        >
          <p>“{confirmUntrusted.name}” came from an import. Review its steps and destinations before running it: it sends real requests.</p>
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
    <div className="col" style={{ maxWidth: 820, gap: 12 }}>
      <input className="field" aria-label="Scenario name" value={name} onChange={(e) => setName(e.target.value)} style={{ fontSize: 15, fontWeight: 600 }} />
      {ids.map((id, i) => (
        <div className="row" key={`${id}-${i}`}>
          <span className="faint mono">{i + 1}.</span>
          <span className="grow">{props.requests.find((r) => r.id === id)?.label}</span>
          <button className="btn ghost icon-btn" aria-label="Remove step" onClick={() => setIds(ids.filter((_, j) => j !== i))}>
            ✕
          </button>
        </div>
      ))}
      <div className="row">
        <select className="field grow" aria-label="Add step" value={pick} onChange={(e) => setPick(e.target.value)}>
          <option value="">Add a saved request…</option>
          {props.requests.map((r) => (
            <option key={r.id} value={r.id}>
              {r.method} {r.label}
            </option>
          ))}
        </select>
        <button
          className="btn small"
          disabled={!pick}
          onClick={() => {
            setIds([...ids, pick]);
            setPick("");
          }}
        >
          Add step
        </button>
      </div>
      <button className="btn primary" style={{ alignSelf: "start" }} disabled={!name.trim() || ids.length === 0} onClick={() => void props.onCreate(name.trim(), ids)}>
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
    <div className="col" style={{ maxWidth: 820, gap: 12 }}>
      <div className="row">
        <b className="grow" style={{ fontSize: 15 }}>
          {s.name}
        </b>
        <button className="btn primary" onClick={() => props.onRun(s)}>
          Run
        </button>
        <button
          className="btn danger"
          onClick={async () => {
            await api.deleteScenario(s.id);
            props.onDeleted();
          }}
        >
          Delete
        </button>
      </div>
      {s.trusted === false && <div className="warn-box">Imported scenario: review the steps before running it.</div>}
      <table className="grid">
        <tbody>
          {s.steps.map((st, i) => (
            <tr key={i}>
              <td className="k">{i + 1}</td>
              <td>{props.requests.find((r) => r.id === st.request_id)?.label ?? "(missing request)"}</td>
              <td className="k">{st.delay_ms ? `${st.delay_ms} ms think time` : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row">
        <label className="lbl">
          Iterations
          <input className="field mono" style={{ width: 90 }} value={s.iterations ?? 1} onChange={(e) => setS({ ...s, iterations: Number(e.target.value) || 1 })} />
        </label>
        <label className="check">
          <input type="checkbox" checked={!!s.stop_on_failure} onChange={(e) => setS({ ...s, stop_on_failure: e.target.checked })} />
          Stop an iteration at its first failed step
        </label>
        <button
          className="btn small"
          onClick={async () => {
            setS(await api.saveScenario(s));
            props.onSaved();
          }}
        >
          Save
        </button>
      </div>
    </div>
  );
}

function LiveRun(props: { live: { runId: string; name: string; events: RunEvent[] }; onCancel: () => void }) {
  const last = [...props.live.events].reverse().find((e) => "progress" in e) as Extract<RunEvent, { progress: unknown }> | undefined;
  const p = last?.progress;
  const steps = props.live.events.filter((e): e is Extract<RunEvent, { event: "step_finished" }> => e.event === "step_finished");
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row">
        <b style={{ fontSize: 15 }}>{props.live.name}</b>
        <span className="badge accent">running</span>
        {p && (
          <span className="faint">
            {p.steps_done}/{p.steps_total} steps · {p.steps_failed} failed · iteration {p.iterations_done}/{p.iterations_total}
          </span>
        )}
        <span className="spacer" />
        <button className="btn" onClick={props.onCancel}>
          Stop run
        </button>
      </div>
      <div className="progress" />
      <table className="grid">
        <tbody>
          {steps.slice(-200).map((e, i) => (
            <tr key={i}>
              <td className="k">
                {e.iteration + 1}.{e.step + 1}
              </td>
              <td className={`k ${e.status === "passed" ? "conf-confirmed" : "s5"}`}>{e.status}</td>
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
    <div className="col" style={{ gap: 12 }}>
      <div className="row" style={{ flexWrap: "wrap" }}>
        <b style={{ fontSize: 15 }}>{r.name}</b>
        <span className={`badge ${r.completion === "completed" && t.steps_failed + t.steps_errored === 0 ? "ok" : "bad"}`}>{humanize(r.completion)}</span>
        {r.partial && <span className="badge warn">partial</span>}
        <span className="faint">
          {new Date(r.started_at).toLocaleString()} · {(r.duration_ms / 1000).toFixed(1)} s{r.environment_name ? ` · ${r.environment_name}` : ""}
        </span>
        <span className="spacer" />
        <button className="btn small" onClick={() => void exportAs("junit")}>
          JUnit
        </button>
        <button className="btn small" onClick={() => void exportAs("html")}>
          HTML
        </button>
        <button className="btn small" onClick={() => void exportAs("json")}>
          JSON
        </button>
        <button
          className="btn small danger"
          onClick={async () => {
            await api.deleteRunReport(r.run_id);
            props.onDeleted();
          }}
        >
          Delete
        </button>
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
          <div className="card" key={label}>
            <div className="card-label">{label}</div>
            <div className="card-value" style={bad ? { color: "var(--bad)" } : undefined}>
              {v}
            </div>
          </div>
        ))}
      </div>
      {r.iterations.map((it) => (
        <details key={it.index} open={it.status !== "passed"}>
          <summary>
            Iteration {it.index + 1}
            {it.dataset_row != null ? ` (dataset row ${it.dataset_row + 1})` : ""} — {it.status} · {it.duration_ms} ms
          </summary>
          <table className="grid">
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
                    {s.name}
                    <div className="faint mono" style={{ fontSize: 11 }}>
                      {s.method} {s.url}
                    </div>
                  </td>
                  <td className={`k ${s.status === "passed" ? "conf-confirmed" : s.status === "skipped" ? "faint" : "s5"}`}>{s.status}</td>
                  <td className="v">
                    {s.http_status ?? s.grpc_status ?? ""} {s.failed_dimensions?.length ? `(${s.failed_dimensions.join(", ")})` : ""}
                  </td>
                  <td>
                    {s.message ?? s.summary}
                    {s.findings?.slice(0, 2).map((f) => (
                      <div key={f.code} className="faint" style={{ fontSize: 11 }}>
                        {f.title} ({f.confidence})
                      </div>
                    ))}
                    {s.assertion_results
                      ?.filter((a) => !a.passed)
                      .map((a, i) => (
                        <div key={i} className="s5" style={{ fontSize: 11 }}>
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
