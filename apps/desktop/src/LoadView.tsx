// Load testing: plan editor, explicit preflight confirmation, live progress
// from the worker process, saved reports and run comparison. Every plan
// measures one load unit (HTTP requests, gRPC calls or streams, SSE streams,
// WebSocket sessions, TCP or UDP/DTLS exchanges); the editor shows which one,
// or the typed refusal, before anything can run (LOAD-013).
import { useEffect, useMemo, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  api,
  onLoadFinished,
  onLoadProgress,
  type Dataset,
  type LoadComparison,
  type LoadPlan,
  type LoadPlanCheck,
  type LoadPreflight,
  type LoadProgress,
  type LoadReport,
  type LoadReportSummary,
  type TreeNode,
} from "./api";
import type {
  ClosedCount,
  Environment,
  LatencySummary,
  LoadUnitKind,
  Protocol,
  ProtocolLoadMetrics,
  RequestCounts,
  Stage,
  TimeBucket,
  WeightedStep,
  Workload,
} from "./generated/contracts";

/// Plan with its optional list fields normalized for editing.
type EditPlan = LoadPlan & { chain: string[]; mix: WeightedStep[] };
import { Modal, SidebarResizer, fmtAgo, fmtBytes, fmtUs, humanize, uid } from "./ui";
import { Icon } from "./icons";

const UNIT_WORDS: Record<LoadUnitKind, [string, string]> = {
  http_request: ["request", "requests"],
  grpc_call: ["call", "calls"],
  grpc_stream: ["stream", "streams"],
  sse_stream: ["stream", "streams"],
  websocket_session: ["session", "sessions"],
  tcp_exchange: ["exchange", "exchanges"],
  udp_exchange: ["exchange", "exchanges"],
  dtls_exchange: ["exchange", "exchanges"],
};

const PROTOCOL_LABEL: Record<Protocol, string> = { http: "HTTP", web_socket: "WebSocket", grpc: "gRPC", sse: "SSE", tcp: "TCP", udp: "UDP" };

const GRPC_CODES = [
  "OK",
  "CANCELLED",
  "UNKNOWN",
  "INVALID_ARGUMENT",
  "DEADLINE_EXCEEDED",
  "NOT_FOUND",
  "ALREADY_EXISTS",
  "PERMISSION_DENIED",
  "RESOURCE_EXHAUSTED",
  "FAILED_PRECONDITION",
  "ABORTED",
  "OUT_OF_RANGE",
  "UNIMPLEMENTED",
  "INTERNAL",
  "UNAVAILABLE",
  "DATA_LOSS",
  "UNAUTHENTICATED",
];

/** Singular and plural unit nouns ("request"/"requests" for reports without protocol metrics). */
export function unitWords(p?: ProtocolLoadMetrics | null): [string, string] {
  return p ? [p.semantics.unit_singular, p.semantics.unit_plural] : ["request", "requests"];
}

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

const NO_UNITS: RequestCounts = {
  started: 0,
  completed: 0,
  transport_failures: 0,
  timeouts: 0,
  canceled: 0,
  in_flight_at_end: 0,
  application_failures: 0,
  assertion_failures: 0,
  connections_opened: 0,
  connections_reused: 0,
};

/** A percentile only exists when there were samples: never "0 µs". */
function pct(l: LatencySummary | undefined, v: number | undefined): string {
  return !l || l.count === 0 ? "—" : fmtUs(v);
}

function closedText(c: ClosedCount["closed_by"]): string {
  switch (c) {
    case "peer":
      return "peer";
    case "client":
      return "client (stop condition or close)";
    case "abnormal":
      return "abnormal (no close handshake)";
    case "timeout":
      return "timeout (idle or deadline)";
    default:
      return "not closed";
  }
}

function flatten(nodes: TreeNode[], path: string[] = []): { id: string; label: string; method: string }[] {
  return nodes.flatMap((n) =>
    n.kind === "folder" ? flatten(n.children, [...path, n.name]) : [{ id: n.id, label: [...path, n.name].join(" / "), method: n.method ?? "GET" }],
  );
}

function newPlan(workspaceId: string): LoadPlan {
  const now = new Date().toISOString();
  return {
    id: uid(),
    workspace_id: workspaceId,
    name: "New load plan",
    workload: { model: "closed_virtual_users", stages: [{ duration_secs: 30, target: 10 }], think_time_ms: 0 },
    chain: [],
    mix: [],
    connection_mode: "persistent",
    warmup_secs: 0,
    seed: 1,
    trusted: true,
    created_at: now,
    updated_at: now,
  };
}

type Sel = { kind: "plan"; id: string } | { kind: "report"; id: string } | null;

export function LoadView(props: { workspaceId: string; tree: TreeNode[]; environments: Environment[]; notify: (m: string) => void }) {
  const [plans, setPlans] = useState<LoadPlan[]>([]);
  const [reports, setReports] = useState<LoadReportSummary[]>([]);
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [sel, setSel] = useState<Sel>(null);
  const [draft, setDraft] = useState<LoadPlan | null>(null);
  const [live, setLive] = useState<{ runKey: string; planName: string; progress: LoadProgress | null; timeline: TimeBucket[] } | null>(null);
  const requests = useMemo(() => flatten(props.tree), [props.tree]);

  const reload = async () => {
    const [p, r, d] = await Promise.all([api.loadPlans(props.workspaceId), api.loadReports(props.workspaceId), api.datasets(props.workspaceId)]);
    setPlans(p);
    setReports(r);
    setDatasets(d);
  };
  useEffect(() => {
    void reload();
  }, [props.workspaceId]);

  useEffect(() => {
    const a = onLoadProgress((e) =>
      setLive((l) => {
        if (!l || l.runKey !== e.run_key) return l;
        const tl = [...l.timeline];
        e.progress.timeline_delta.forEach((b, i) => (tl[e.progress.timeline_from + i] = b));
        return { ...l, progress: e.progress, timeline: tl };
      }),
    );
    const b = onLoadFinished((e) => {
      setLive((l) => (l && l.runKey === e.run_key ? null : l));
      if (e.error) props.notify(`Load run ended without a saved report: ${e.error}`);
      void reload().then(() => e.run_id && setSel({ kind: "report", id: e.run_id }));
    });
    return () => {
      void a.then((f) => f());
      void b.then((f) => f());
    };
  }, []);

  useEffect(() => {
    // Keep an unsaved new plan; otherwise edit the saved copy.
    if (sel?.kind === "plan") setDraft((d) => plans.find((p) => p.id === sel.id) ?? (d?.id === sel.id ? d : null));
  }, [sel, plans]);

  return (
    <div className="main">
      <aside className="sidebar" aria-label="Load plans and reports">
        <div className="side-body">
          <div className="side-section-head">
            <span>Load plans</span>
            <button
              className="btn ghost small"
              title="New load plan"
              onClick={() => {
                const p = newPlan(props.workspaceId);
                setDraft(p);
                setSel({ kind: "plan", id: p.id });
              }}
            >
              <Icon name="plus" size={14} />
              New
            </button>
          </div>
          {plans.length === 0 && <div className="side-empty">No plans yet.</div>}
          {plans.map((p) => (
            <div
              key={p.id}
              className={`tree-row${sel?.kind === "plan" && sel.id === p.id ? " selected" : ""}`}
              role="button"
              tabIndex={0}
              onClick={() => setSel({ kind: "plan", id: p.id })}
              onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "plan", id: p.id })}
            >
              <Icon name="zap" size={14} className="row-icon" />
              <span className="name">{p.name}</span>
              {!p.trusted && <span className="badge warn">imported</span>}
            </div>
          ))}
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
              title={`${r.plan_name} — ${new Date(r.started_at).toLocaleString()}`}
              onClick={() => setSel({ kind: "report", id: r.run_id })}
              onKeyDown={(e) => e.key === "Enter" && setSel({ kind: "report", id: r.run_id })}
            >
              <div className="hist-line">
                <span className="hist-title">{r.plan_name}</span>
                <span className={`badge ${r.completion === "completed" && !r.partial ? "ok" : "warn"}`}>{r.partial ? "partial" : "done"}</span>
              </div>
              <div className="hist-line">
                <span className="hist-meta">
                  {r.achieved_rate_per_sec.toFixed(1)} {UNIT_WORDS[r.unit]?.[1] ?? "requests"}/s · p95 {r.p95_us === null ? "— (no successes)" : fmtUs(r.p95_us)} · {r.failures} failed
                </span>
                <span className="hist-when">{fmtAgo(Date.parse(r.started_at))}</span>
              </div>
            </div>
          ))}
        </div>
      </aside>
      <SidebarResizer />
      <section className="work single">
        <div className="pane">
          {live && <LivePanel live={live} onCancel={() => void api.loadRunCancel(live.runKey)} />}
          {!live && sel?.kind === "plan" && draft && (
            <PlanEditor
              key={draft.id}
              plan={draft}
              requests={requests}
              environments={props.environments}
              datasets={datasets}
              onDatasetsChanged={reload}
              onSaved={async (p) => {
                await reload();
                setSel({ kind: "plan", id: p.id });
                props.notify("Plan saved.");
              }}
              onDeleted={async () => {
                await reload();
                setSel(null);
              }}
              onStarted={(runKey, name) => setLive({ runKey, planName: name, progress: null, timeline: [] })}
            />
          )}
          {!live && sel?.kind === "report" && <ReportView key={sel.id} runId={sel.id} reports={reports} notify={props.notify} onDeleted={async () => { await reload(); setSel(null); }} />}
          {!live && !sel && (
            <div className="empty">
              <div>
                <span className="empty-icon">
                  <Icon name="zap" size={22} />
                </span>
                <div className="big">Test under load with the same requests you send by hand.</div>
                <div className="sub">Every iteration uses the same preparation, auth signing and TLS rules as Send. Runs execute in a separate worker process.</div>
                <button
                  className="btn primary"
                  onClick={() => {
                    const p = newPlan(props.workspaceId);
                    setDraft(p);
                    setSel({ kind: "plan", id: p.id });
                  }}
                >
                  <Icon name="plus" size={15} />
                  New load plan
                </button>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

// ------------------------------------------------------------ plan editor

export function PlanEditor(props: {
  plan: LoadPlan;
  requests: { id: string; label: string; method: string }[];
  environments: Environment[];
  datasets: Dataset[];
  onDatasetsChanged: () => void;
  onSaved: (p: LoadPlan) => void;
  onDeleted: () => void;
  onStarted: (runKey: string, name: string) => void;
}) {
  const [p, setP] = useState<EditPlan>({ ...props.plan, chain: props.plan.chain ?? [], mix: props.plan.mix ?? [] });
  const [err, setErr] = useState<string | null>(null);
  const [pick, setPick] = useState("");
  const [preflight, setPreflight] = useState<LoadPreflight | null>(null);
  const [ack, setAck] = useState(false);
  const [datasetDlg, setDatasetDlg] = useState(false);
  const [check, setCheck] = useState<LoadPlanCheck | null>(null);
  const useMix = p.mix.length > 0;
  const requestKey = JSON.stringify([p.chain, p.mix.map((m) => m.request_id), p.connection_mode]);
  // What the plan measures (or why it is refused), re-checked as requests change. Nothing is sent.
  useEffect(() => {
    if (p.chain.length === 0 && p.mix.length === 0) {
      setCheck(null);
      return;
    }
    let stale = false;
    const t = setTimeout(() => {
      api
        .loadPlanCheck(p)
        .then((c) => !stale && setCheck(c))
        .catch(() => !stale && setCheck(null));
    }, 150);
    return () => {
      stale = true;
      clearTimeout(t);
    };
  }, [requestKey]);
  const protocolOf = (id: string) => check?.protocols.find(([rid]) => rid === id)?.[1];
  const refused = !!check?.refusal;
  const w = p.workload;
  const setW = (workload: Workload) => setP({ ...p, workload });
  const label = (id: string) => props.requests.find((r) => r.id === id)?.label ?? "(missing request)";

  const saveIt = async (): Promise<LoadPlan | null> => {
    setErr(null);
    try {
      const saved = await api.saveLoadPlan(p);
      setP({ ...saved, chain: saved.chain ?? [], mix: saved.mix ?? [] });
      props.onSaved(saved);
      return saved;
    } catch (e) {
      setErr(String((e as Error).message));
      return null;
    }
  };

  return (
    <div className="page narrow">
      <div className="page-head">
        <input className="field title-input grow" aria-label="Plan name" value={p.name} onChange={(e) => setP({ ...p, name: e.target.value })} />
        <div className="page-actions">
          <button className="btn" onClick={() => void saveIt()}>
            Save
          </button>
          <button
            className="btn primary"
            disabled={refused}
            title={refused ? "This plan cannot be load tested; see the refusal below." : undefined}
            onClick={async () => {
              const saved = await saveIt();
              if (!saved) return;
              try {
                setAck(false);
                setPreflight(await api.loadPreflight(saved.id));
              } catch (e) {
                setErr(String((e as Error).message));
              }
            }}
          >
            <Icon name="play" size={12} />
            Run…
          </button>
          <button
            className="btn ghost danger icon-btn"
            aria-label="Delete plan"
            title="Delete plan"
            onClick={async () => {
              await api.deleteLoadPlan(p.id).catch(() => undefined);
              props.onDeleted();
            }}
          >
            <Icon name="trash" />
          </button>
        </div>
      </div>
      {!p.trusted && <div className="warn-box">This plan was imported. Review it and save it before it can run.</div>}
      {err && <div className="bad-box">{err}</div>}

      <fieldset className="box">
        <legend>Requests</legend>
        <label className="check">
          <input
            type="checkbox"
            checked={useMix}
            onChange={(e) =>
              setP(e.target.checked ? { ...p, mix: p.chain.map((request_id) => ({ request_id, weight: 1 })), chain: [] } : { ...p, chain: p.mix.map((m) => m.request_id), mix: [] })
            }
          />
          Weighted mix (one request per iteration) instead of a sequential chain
        </label>
        {(useMix ? p.mix.length : p.chain.length) > 0 && (
          <div className="step-list">
            {!useMix &&
              p.chain.map((id, i) => (
                <div className="step-row" key={`${id}-${i}`}>
                  <span className="step-n">{i + 1}</span>
                  <ProtocolBadge protocol={protocolOf(id)} />
                  <span className="step-name">{label(id)}</span>
                  <button className="btn ghost small icon-btn" aria-label="Move up" title="Move up" disabled={i === 0} onClick={() => setP({ ...p, chain: swap(p.chain, i, i - 1) })}>
                    <Icon name="arrowUp" size={14} />
                  </button>
                  <button className="btn ghost small icon-btn" aria-label="Move down" title="Move down" disabled={i === p.chain.length - 1} onClick={() => setP({ ...p, chain: swap(p.chain, i, i + 1) })}>
                    <Icon name="arrowDown" size={14} />
                  </button>
                  <button className="btn ghost small icon-btn" aria-label="Remove" title="Remove" onClick={() => setP({ ...p, chain: p.chain.filter((_, j) => j !== i) })}>
                    <Icon name="x" size={14} />
                  </button>
                </div>
              ))}
            {useMix &&
              p.mix.map((m, i) => (
                <div className="step-row" key={`${m.request_id}-${i}`}>
                  <ProtocolBadge protocol={protocolOf(m.request_id)} />
                  <span className="step-name">{label(m.request_id)}</span>
                  <label className="lbl inline">
                    Weight
                    <input className="field mono tiny" value={m.weight ?? 1} onChange={(e) => setP({ ...p, mix: p.mix.map((x, j) => (j === i ? { ...x, weight: Number(e.target.value) || 0 } : x)) })} />
                  </label>
                  <button className="btn ghost small icon-btn" aria-label="Remove" title="Remove" onClick={() => setP({ ...p, mix: p.mix.filter((_, j) => j !== i) })}>
                    <Icon name="x" size={14} />
                  </button>
                </div>
              ))}
          </div>
        )}
        <div className="row nowrap">
          <select className="field grow" aria-label="Add request" value={pick} onChange={(e) => setPick(e.target.value)}>
            <option value="">Choose a saved request…</option>
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
              setP(useMix ? { ...p, mix: [...p.mix, { request_id: pick, weight: 1 }] } : { ...p, chain: [...p.chain, pick] });
              setPick("");
            }}
          >
            <Icon name="plus" size={14} />
            Add
          </button>
        </div>
        <p className="hint">Values extracted by earlier steps are available to later steps of the same iteration. Auth signatures, nonces and JWTs are generated fresh for every send.</p>
        <UnitBox check={check} />
      </fieldset>

      <fieldset className="box">
        <legend>Workload</legend>
        <div className="fields">
          <label className="lbl">
            Model
            <select
              className="field"
              value={w.model}
              onChange={(e) => {
                const m = e.target.value as Workload["model"];
                setW(
                  m === "closed_virtual_users"
                    ? { model: m, stages: [{ duration_secs: 30, target: 10 }], think_time_ms: 0 }
                    : m === "open_arrival_rate"
                      ? { model: m, stages: [{ duration_secs: 30, target: 50 }], max_in_flight: 200 }
                      : { model: m, iterations: 100, concurrency: 10 },
                );
              }}
            >
              <option value="closed_virtual_users">Closed — fixed virtual users</option>
              <option value="open_arrival_rate">Open — target arrival rate</option>
              <option value="iterations">Fixed number of iterations</option>
            </select>
          </label>
          {w.model === "closed_virtual_users" && <Num label="Think time (ms)" value={w.think_time_ms ?? 0} onChange={(v) => setW({ ...w, think_time_ms: v })} />}
          {w.model === "open_arrival_rate" && <Num label="Max in flight" value={w.max_in_flight} onChange={(v) => setW({ ...w, max_in_flight: v })} />}
          {w.model === "iterations" && (
            <>
              <Num label="Iterations" value={w.iterations} onChange={(v) => setW({ ...w, iterations: v })} />
              <Num label="Concurrency" value={w.concurrency} onChange={(v) => setW({ ...w, concurrency: v })} />
            </>
          )}
          <Num label="Warmup (s, excluded)" value={p.warmup_secs ?? 0} onChange={(v) => setP({ ...p, warmup_secs: v })} />
          <label className="lbl">
            Connections
            <select className="field" value={p.connection_mode ?? "persistent"} onChange={(e) => setP({ ...p, connection_mode: e.target.value as "persistent" })}>
              <option value="persistent">Reuse per virtual user</option>
              <option value="fresh">New connection per iteration</option>
            </select>
          </label>
        </div>
        {w.model !== "iterations" && (
          <StagesEditor stages={w.stages} unit={w.model === "open_arrival_rate" ? "arrivals/s" : "virtual users"} onChange={(stages) => setW({ ...w, stages })} />
        )}
        <p className="hint">
          {w.model === "closed_virtual_users"
            ? "Closed workloads slow down when responses slow down, so they understate overload. Use an open workload to hold a rate."
            : w.model === "open_arrival_rate"
              ? "Arrivals are scheduled independently of responses. Arrivals beyond the in-flight cap are dropped and counted, never queued."
              : "Runs a fixed number of iterations as fast as the concurrency allows."}
        </p>
      </fieldset>

      <fieldset className="box">
        <legend>Data and limits</legend>
        <div className="fields">
          <label className="lbl">
            Environment
            <select className="field" value={p.environment_id ?? ""} onChange={(e) => setP({ ...p, environment_id: e.target.value || null })}>
              <option value="">None</option>
              {props.environments.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name}
                </option>
              ))}
            </select>
          </label>
          <label className="lbl">
            Dataset (one row per iteration)
            <select className="field" value={p.dataset_id ?? ""} onChange={(e) => setP({ ...p, dataset_id: e.target.value || null })}>
              <option value="">None</option>
              {props.datasets.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name} ({d.format})
                </option>
              ))}
            </select>
          </label>
          <button className="btn" onClick={() => setDatasetDlg(true)}>
            <Icon name="file" size={14} />
            Add dataset…
          </button>
        </div>
        <label className="check">
          <input
            type="checkbox"
            checked={!!p.abort}
            onChange={(e) => setP({ ...p, abort: e.target.checked ? { max_failure_permille: 200, window_secs: 10 } : null })}
          />
          Abort when failures exceed a rate
        </label>
        {p.abort && (
          <div className="fields">
            <Num label="Max failures (%)" value={p.abort.max_failure_permille / 10} onChange={(v) => setP({ ...p, abort: { ...p.abort!, max_failure_permille: Math.round(v * 10) } })} />
            <Num label="Window (s)" value={p.abort.window_secs} onChange={(v) => setP({ ...p, abort: { ...p.abort!, window_secs: v } })} />
          </div>
        )}
      </fieldset>

      {datasetDlg && (
        <DatasetDialog
          workspaceId={p.workspace_id}
          onClose={() => setDatasetDlg(false)}
          onAdded={(d) => {
            setDatasetDlg(false);
            props.onDatasetsChanged();
            setP({ ...p, dataset_id: d.id });
          }}
        />
      )}

      {preflight && (
        <Modal
          title="Confirm load run"
          onClose={() => setPreflight(null)}
          footer={
            <>
              <button className="btn" onClick={() => setPreflight(null)}>
                Cancel
              </button>
              <button
                className="btn primary"
                disabled={!ack}
                onClick={async () => {
                  try {
                    const key = await api.loadRunStart(p.id, true);
                    setPreflight(null);
                    props.onStarted(key, p.name);
                  } catch (e) {
                    setErr(String((e as Error).message));
                    setPreflight(null);
                  }
                }}
              >
                <Icon name="play" size={12} />
                Start load
              </button>
            </>
          }
        >
          <table className="grid">
            <tbody>
              <tr>
                <td className="k">Destinations</td>
                <td className="v">
                  {preflight.destinations.map((d) => (
                    <div key={d}>{d}</div>
                  ))}
                </td>
              </tr>
              <tr>
                <td className="k">Load unit</td>
                <td className="v">
                  <div>{preflight.unit_label}</div>
                  <div className="faint">{preflight.semantics.completed_means}</div>
                </td>
              </tr>
              <tr>
                <td className="k">Workload</td>
                <td className="v">{preflight.workload}</td>
              </tr>
              <tr>
                <td className="k">Planned duration</td>
                <td className="v">{preflight.max_duration_secs ? `${preflight.max_duration_secs} s` : "until the iterations finish"}</td>
              </tr>
              {preflight.dataset_rows != null && (
                <tr>
                  <td className="k">Dataset rows</td>
                  <td className="v">{preflight.dataset_rows}</td>
                </tr>
              )}
            </tbody>
          </table>
          {preflight.warnings.map((w) => (
            <div className="warn-box" key={w}>
              {w}
            </div>
          ))}
          <label className="check top ack">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            <span>I own these destinations or am authorized to load-test them, and I accept that this run sends real traffic.</span>
          </label>
        </Modal>
      )}
    </div>
  );
}

function ProtocolBadge({ protocol }: { protocol?: Protocol }) {
  return protocol ? <span className="badge">{PROTOCOL_LABEL[protocol]}</span> : null;
}

/** The plan's load unit and its definitions, or the typed refusal (LOAD-013). */
export function UnitBox({ check }: { check: LoadPlanCheck | null }) {
  if (!check) return null;
  if (check.refusal) {
    return (
      <div className="bad-box" role="alert" data-testid="load-refusal">
        <b>Not supported for load</b> <span className="mono">({check.refusal.code})</span>: {check.refusal.message}
      </div>
    );
  }
  if (!check.unit || !check.semantics) return null;
  const s = check.semantics;
  return (
    <div className="ok-box" data-testid="load-unit">
      <b>Load unit: {check.unit_label}</b> — every count, rate and latency is per {s.unit_singular}.
      <ul>
        <li>Completed: {s.completed_means}</li>
        <li>Success: {s.success_means}</li>
        <li>Latency: {s.latency_means}</li>
        <li>Connections: {s.connection_mode_means}</li>
      </ul>
    </div>
  );
}

function swap<T>(a: T[], i: number, j: number): T[] {
  const b = [...a];
  [b[i], b[j]] = [b[j], b[i]];
  return b;
}

function StagesEditor(props: { stages: Stage[]; unit: string; onChange: (s: Stage[]) => void }) {
  return (
    <div className="col">
      {props.stages.map((s, i) => (
        <div className="stage-row" key={i}>
          <span className="stage-n">Stage {i + 1}</span>
          <Num label="Duration (s)" value={s.duration_secs} onChange={(v) => props.onChange(props.stages.map((x, j) => (j === i ? { ...x, duration_secs: v } : x)))} />
          <Num label={`Ramp to (${props.unit})`} value={s.target} onChange={(v) => props.onChange(props.stages.map((x, j) => (j === i ? { ...x, target: v } : x)))} />
          <button className="btn ghost icon-btn end" aria-label="Remove stage" title="Remove stage" disabled={props.stages.length === 1} onClick={() => props.onChange(props.stages.filter((_, j) => j !== i))}>
            <Icon name="x" />
          </button>
        </div>
      ))}
      <button className="btn small start" onClick={() => props.onChange([...props.stages, { ...props.stages[props.stages.length - 1] }])}>
        <Icon name="plus" size={14} />
        Stage (ramp, step or spike)
      </button>
    </div>
  );
}

function Num(props: { label: string; value: number; onChange: (v: number) => void }) {
  return (
    <label className="lbl">
      {props.label}
      <input className="field mono num" inputMode="numeric" value={props.value} onChange={(e) => props.onChange(Number(e.target.value) || 0)} />
    </label>
  );
}

function DatasetDialog(props: { workspaceId: string; onClose: () => void; onAdded: (d: Dataset) => void }) {
  const [path, setPath] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [sensitive, setSensitive] = useState("");
  const [err, setErr] = useState<string | null>(null);
  return (
    <Modal
      title="Add dataset"
      onClose={props.onClose}
      footer={
        <button
          className="btn primary"
          disabled={!path || !name.trim()}
          onClick={async () => {
            try {
              props.onAdded(await api.addDataset(props.workspaceId, path!, name.trim(), sensitive.split(",").map((s) => s.trim()).filter(Boolean)));
            } catch (e) {
              setErr(String((e as Error).message));
            }
          }}
        >
          Add
        </button>
      }
    >
      <div className="row nowrap">
        <button
          className="btn"
          data-autofocus
          onClick={async () => {
            const p = await open({ multiple: false, filters: [{ name: "CSV or JSON", extensions: ["csv", "json"] }] });
            if (typeof p === "string") {
              setPath(p);
              if (!name) setName(p.split(/[\\/]/).pop() ?? "dataset");
            }
          }}
        >
          <Icon name="file" size={14} />
          Choose CSV/JSON…
        </button>
        <span className={`path-chip grow${path ? "" : " none"}`} title={path ?? undefined}>
          {path ?? "No file selected"}
        </span>
      </div>
      <label className="lbl">
        Name
        <input className="field" value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label className="lbl">
        Sensitive columns (comma-separated; masked and redacted from reports)
        <input className="field mono" value={sensitive} onChange={(e) => setSensitive(e.target.value)} />
      </label>
      <p className="hint">The file is copied into encrypted storage. Columns become variables named after the header, e.g. {"{{user_id}}"}.</p>
      {err && <div className="bad-box">{err}</div>}
    </Modal>
  );
}

// ------------------------------------------------------------- live run

function LivePanel(props: { live: { runKey: string; planName: string; progress: LoadProgress | null; timeline: TimeBucket[] }; onCancel: () => void }) {
  const p = props.live.progress;
  const c = p?.snapshot.counts;
  const u = p?.snapshot.requests;
  const [, many] = unitWords(p?.snapshot.protocol);
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>{props.live.planName}</h2>
            <span className="badge accent">
              <span className="live-dot" />
              {p ? humanize(p.phase) : "starting worker…"}
            </span>
          </div>
          <div className="page-meta">{p ? `${p.elapsed_secs.toFixed(0)} s elapsed` : "Waiting for the worker process…"}</div>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={props.onCancel}>
            <Icon name="stop" size={12} />
            Stop run
          </button>
        </div>
      </div>
      <div className="progress" />
      {p && c && (
        <>
          <div className="cards">
            <Card label="Achieved rate" value={`${p.snapshot.achieved_rate_per_sec.toFixed(1)}/s`} sub={p.snapshot.offered_rate_per_sec != null ? `offered ${p.snapshot.offered_rate_per_sec.toFixed(1)}/s` : undefined} />
            <Card label="In flight" value={String(p.in_flight)} />
            <Card label="Iterations started" value={String(c.started)} sub={c.dropped ? `${c.dropped} dropped` : undefined} />
            {u && <Card label={`${cap(many)} completed`} value={String(u.completed)} sub={`${u.started} started`} />}
            {u && (
              <Card label={`Failed ${many}`} value={String(u.transport_failures + u.timeouts + u.application_failures)} bad={u.transport_failures + u.timeouts + u.application_failures > 0} />
            )}
            {p.snapshot.latency_success.count === 0 ? (
              <Card label="p95 (success)" value="—" sub={`no successful ${many} yet`} />
            ) : (
              <Card label="p95 (success)" value={fmtUs(p.snapshot.latency_success.p95_us)} sub={`p99 ${fmtUs(p.snapshot.latency_success.p99_us)}`} />
            )}
          </div>
          {p.snapshot.protocol && <ProtocolCards p={p.snapshot.protocol} />}
          <Timeline buckets={props.live.timeline.filter(Boolean)} />
        </>
      )}
      <p className="hint">Traffic runs in a separate worker process. Stopping lets in-flight requests drain briefly, then produces a partial report.</p>
    </div>
  );
}

function Card(props: { label: string; value: string; sub?: string; bad?: boolean }) {
  return (
    <div className={`card${props.bad ? " bad" : ""}`}>
      <div className="card-label" title={props.label}>
        {props.label}
      </div>
      <div className="card-value">{props.value}</div>
      {props.sub && (
        <div className="card-sub" title={props.sub}>
          {props.sub}
        </div>
      )}
    </div>
  );
}

function Timeline({ buckets }: { buckets: TimeBucket[] }) {
  if (buckets.length < 2) return <div className="empty-note">The timeline appears after the first seconds of measurement.</div>;
  const W = 760;
  const H = 150;
  const top = 8;
  const bottom = H - 18;
  const maxRate = Math.max(1, ...buckets.map((b) => b.started));
  const maxP99 = Math.max(1, ...buckets.map((b) => b.p99_us));
  const x = (i: number) => (i / (buckets.length - 1)) * (W - 16) + 8;
  const y = (v: number, max: number) => bottom - (v / max) * (bottom - top);
  const line = (f: (b: TimeBucket) => number, max: number) => buckets.map((b, i) => `${x(i)},${y(f(b), max)}`).join(" ");
  const failed = buckets.some((b) => b.failures > 0);
  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Started per second and p99 latency over time">
        {[0.25, 0.5, 0.75, 1].map((f) => (
          <line key={f} x1="8" x2={W - 8} y1={y(f, 1)} y2={y(f, 1)} stroke="var(--border)" strokeWidth="1" />
        ))}
        <line x1="8" x2={W - 8} y1={bottom} y2={bottom} stroke="var(--border-strong)" strokeWidth="1" />
        <polyline fill="none" stroke="var(--blue)" strokeWidth="2" strokeLinejoin="round" points={line((b) => b.started, maxRate)} />
        <polyline fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeDasharray="4 3" strokeLinejoin="round" points={line((b) => b.p99_us, maxP99)} />
        {buckets.map((b, i) => (b.failures > 0 ? <circle key={i} cx={x(i)} cy={H - 8} r="3" fill="var(--bad)" /> : null))}
      </svg>
      <figcaption className="chart-legend">
        <span>
          <i className="sw-rate" />
          Started per second (max {maxRate})
        </span>
        <span>
          <i className="dashed sw-p99" />
          p99 latency (max {fmtUs(maxP99)})
        </span>
        {failed && (
          <span>
            <i className="dot sw-fail" />
            Seconds with failures
          </span>
        )}
      </figcaption>
    </figure>
  );
}

// --------------------------------------------------------------- report

export function ReportView(props: { runId: string; reports: LoadReportSummary[]; notify: (m: string) => void; onDeleted: () => void }) {
  const [r, setR] = useState<LoadReport | null>(null);
  const [cmpWith, setCmpWith] = useState("");
  const [cmp, setCmp] = useState<LoadComparison | null>(null);
  useEffect(() => {
    api.loadReport(props.runId).then(setR);
  }, [props.runId]);
  if (!r) return <div className="faint">Loading report…</div>;
  const c = r.counts;
  const u = r.requests ?? NO_UNITS;
  const [, many] = unitWords(r.protocol_metrics);
  const exportAs = async (format: "json" | "csv" | "timeline_csv" | "html") => {
    const ext = format === "html" ? "html" : format === "json" ? "json" : "csv";
    const path = await save({ defaultPath: `anvil-load-${r.plan.name.replace(/[^\w.-]+/g, "_")}-${r.started_at.slice(0, 10)}.${format === "timeline_csv" ? "timeline.csv" : ext}` });
    if (!path) return;
    const n = await api.exportLoadReport(r.run_id, format, path);
    props.notify(`Exported ${fmtBytes(n)} to ${path}`);
  };
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-titles">
          <div className="page-title">
            <h2>{r.plan.name}</h2>
            <span className={`badge ${r.completion === "completed" && !r.partial ? "ok" : "warn"}`}>{humanize(r.completion)}</span>
            {r.partial && <span className="badge warn">partial report</span>}
          </div>
          <div className="page-meta">
            {new Date(r.started_at).toLocaleString()} → {new Date(r.finished_at).toLocaleTimeString()}
            {r.workload_label ? ` · ${r.workload_label}` : ""}
          </div>
          <div className="page-meta">
            <Icon name="globe" size={12} /> {r.destination_summary.join(", ")}
          </div>
        </div>
        <div className="page-actions">
          <div className="btn-group" role="group" aria-label="Export report">
            <button className="btn small" title="Export as HTML" onClick={() => void exportAs("html")}>
              <Icon name="upload" size={13} />
              HTML
            </button>
            <button className="btn small" title="Export as JSON" onClick={() => void exportAs("json")}>
              JSON
            </button>
            <button className="btn small" title="Export as CSV" onClick={() => void exportAs("csv")}>
              CSV
            </button>
            <button className="btn small" title="Export the per-second timeline as CSV" onClick={() => void exportAs("timeline_csv")}>
              Timeline CSV
            </button>
          </div>
          <button
            className="btn small ghost danger"
            onClick={async () => {
              await api.deleteLoadReport(r.run_id);
              props.onDeleted();
            }}
          >
            <Icon name="trash" size={13} />
            Delete
          </button>
        </div>
      </div>
      <div className="cards">
        <Card label="Achieved rate" value={`${r.achieved_rate_per_sec.toFixed(1)}/s`} sub={r.offered_rate_per_sec != null ? `offered ${r.offered_rate_per_sec.toFixed(1)}/s` : undefined} />
        <Card label="Iterations started" value={String(c.started)} sub={c.dropped ? `${c.dropped} dropped (in-flight cap)` : undefined} />
        <Card label={`${cap(many)} started`} value={String(u.started)} />
        <Card label={`${cap(many)} completed`} value={String(u.completed)} />
        <Card label="Transport failures" value={String(u.transport_failures)} bad={u.transport_failures > 0} />
        <Card label="Timeouts" value={String(u.timeouts)} bad={u.timeouts > 0} />
        <Card label="Application failures" value={String(u.application_failures)} bad={u.application_failures > 0} />
        <Card label="Assertion failures" value={String(u.assertion_failures)} bad={u.assertion_failures > 0} />
      </div>
      {r.protocol_metrics && <ProtocolPanel p={r.protocol_metrics} requests={u} />}
      <h4 className="section-title">Latency</h4>
      <table className="grid metrics">
        <thead>
          <tr>
            <th>Distribution</th>
            <th>count</th>
            <th>p50</th>
            <th>p90</th>
            <th>p95</th>
            <th>p99</th>
            <th>max</th>
          </tr>
        </thead>
        <tbody>
          {[
            [`Successful ${many}`, r.latency_success],
            [`Failed ${many} (to failure point)`, r.latency_failure],
          ].map(([name, l]) => {
            const L = l as LoadReport["latency_success"];
            return (
              <tr key={name as string}>
                <td>{name as string}</td>
                <td className="v">{L.count}</td>
                {L.count === 0 ? (
                  <td className="v faint" colSpan={5}>
                    — (no samples)
                  </td>
                ) : (
                  <>
                    <td className="v">{fmtUs(L.p50_us)}</td>
                    <td className="v">{fmtUs(L.p90_us)}</td>
                    <td className="v">{fmtUs(L.p95_us)}</td>
                    <td className="v">{fmtUs(L.p99_us)}</td>
                    <td className="v">{fmtUs(L.max_us)}</td>
                  </>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="hint">
        {r.protocol_metrics ? `${r.protocol_metrics.semantics.latency_means} ` : ""}Timeouts are censored (their true latency is unknown) and excluded from both distributions; they are counted above. Percentiles cover
        successful {many} only and come from merged HDR histograms, never averaged.
      </p>
      <h4 className="section-title">Timeline</h4>
      <Timeline buckets={r.timeline} />
      <div className="split-2">
        <div className="col">
          <h4 className="section-title">Status codes</h4>
          {r.status_distribution.length === 0 && <div className="faint small-text">No responses.</div>}
          <table className="grid metrics compact">
            <tbody>
              {r.status_distribution.map(([code, n]) => (
                <tr key={String(code)}>
                  <td>
                    <span className={`status-pill s${String(code)[0]}`}>{String(code)}</span>
                  </td>
                  <td className="v">{String(n)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="col">
          <h4 className="section-title">Failure categories (redacted samples)</h4>
          {r.failure_categories.length === 0 && <div className="faint small-text">None.</div>}
          {r.failure_categories.map((f) => (
            <details key={f.category} className="failure-cat">
              <summary>
                {humanize(f.category)} <span className="badge bad">{f.count}</span>
              </summary>
              <ul className="plain-list">
                {f.examples.map((x, i) => (
                  <li key={i} className="mono">
                    {x}
                  </li>
                ))}
              </ul>
            </details>
          ))}
        </div>
      </div>
      <details>
        <summary>Load generator health</summary>
        <table className="grid">
          <tbody>
            <tr>
              <td className="k">Peak CPU</td>
              <td className="v">{r.generator.peak_cpu_percent != null ? `${r.generator.peak_cpu_percent.toFixed(0)}%` : "not measured"}</td>
            </tr>
            <tr>
              <td className="k">Peak memory</td>
              <td className="v">{fmtBytes(r.generator.peak_rss_bytes)}</td>
            </tr>
            <tr>
              <td className="k">Schedule lag p99 / max</td>
              <td className="v">
                {fmtUs(r.generator.p99_schedule_lag_us)} / {fmtUs(r.generator.max_schedule_lag_us)}
              </td>
            </tr>
            <tr>
              <td className="k">Bytes sent / received</td>
              <td className="v">
                {fmtBytes(r.bytes_sent)} / {fmtBytes(r.bytes_received)}
              </td>
            </tr>
          </tbody>
        </table>
      </details>
      {r.notes.length > 0 && (
        <div className="col">
          {r.notes.map((n, i) => (
            <div className="warn-box" key={i}>
              {n}
            </div>
          ))}
        </div>
      )}
      <div className="row nowrap compare-row">
        <select className="field grow" aria-label="Compare with" value={cmpWith} onChange={(e) => setCmpWith(e.target.value)}>
          <option value="">Compare with another run…</option>
          {props.reports
            .filter((x) => x.run_id !== r.run_id)
            .map((x) => (
              <option key={x.run_id} value={x.run_id}>
                {x.plan_name} · {new Date(x.started_at).toLocaleString()}
              </option>
            ))}
        </select>
        <button className="btn" disabled={!cmpWith} onClick={async () => setCmp(await api.compareLoadReports(r.run_id, cmpWith))}>
          Compare
        </button>
      </div>
      {cmp && (
        <div className={cmp.compatible ? "ok-box" : "warn-box"}>
          <div>{cmp.summary}</div>
          {cmp.differences.length > 0 && (
            <ul>
              {cmp.differences.map((d, i) => (
                <li key={i}>
                  <b>{d.aspect}</b>: {d.a} → {d.b} — {d.explanation}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------ protocol

function Rows(props: { rows: [string, string][]; testid?: string }) {
  return (
    <table className="grid" data-testid={props.testid}>
      <tbody>
        {props.rows.map(([k, v]) => (
          <tr key={k}>
            <td className="k">{k}</td>
            <td className="v">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LatencyRows(props: { rows: [string, LatencySummary][] }) {
  return (
    <table className="grid metrics">
      <thead>
        <tr>
          <th>Distribution</th>
          <th>count</th>
          <th>p50</th>
          <th>p90</th>
          <th>p99</th>
          <th>max</th>
        </tr>
      </thead>
      <tbody>
        {props.rows.map(([name, l]) => (
          <tr key={name}>
            <td>{name}</td>
            <td className="v">{l.count}</td>
            <td className="v">{pct(l, l.p50_us)}</td>
            <td className="v">{pct(l, l.p90_us)}</td>
            <td className="v">{pct(l, l.p99_us)}</td>
            <td className="v">{pct(l, l.max_us)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const ratio = (n: number, d: number) => (d === 0 ? "—" : (n / d).toFixed(3));

/** Compact live cards for the protocol denominators. */
export function ProtocolCards({ p }: { p: ProtocolLoadMetrics }) {
  return (
    <div className="cards" data-testid="protocol-cards">
      {p.http && p.http.protocol_fallback_attempts > 0 && <Card label="HTTP/3 fallback attempts" value={String(p.http.protocol_fallback_attempts)} />}
      {p.grpc && (
        <>
          <Card label="gRPC OK" value={String(p.grpc.ok)} />
          <Card label="gRPC non-OK" value={String(p.grpc.non_ok)} bad={p.grpc.non_ok > 0} />
          <Card label="No terminal status" value={String(p.grpc.missing_status)} bad={p.grpc.missing_status > 0} />
        </>
      )}
      {p.stream && <Card label={p.unit === "sse_stream" ? "Events received" : "Messages received"} value={String(p.stream.messages_received)} sub={`${p.stream.opened} streams opened`} />}
      {p.websocket && (
        <>
          <Card label="Sessions opened" value={String(p.websocket.opened)} sub={p.websocket.handshake_rejected ? `${p.websocket.handshake_rejected} rejected` : undefined} />
          <Card label="Messages sent / received" value={`${p.websocket.messages_sent} / ${p.websocket.messages_received}`} />
        </>
      )}
      {p.tcp && <Card label="Frames sent / received" value={`${p.tcp.frames_sent} / ${p.tcp.frames_received}`} sub={`${p.tcp.connected} connections`} />}
      {p.datagram && (
        <>
          <Card label="Datagrams sent" value={String(p.datagram.datagrams_sent)} />
          <Card label="Datagrams received" value={String(p.datagram.datagrams_received)} sub="a separate count, not deliveries" />
          <Card label="No response observed" value={String(p.datagram.exchanges_silent)} sub="exchanges; not failures" />
        </>
      )}
    </div>
  );
}

/** The unit's definitions and its protocol denominators (mirrors the HTML report). */
export function ProtocolPanel({ p, requests }: { p: ProtocolLoadMetrics; requests: RequestCounts }) {
  const s = p.semantics;
  return (
    <section className="col" data-testid="protocol-panel" aria-label="Protocol metrics">
      <h4 className="section-title">
        Load unit: {s.unit_plural} ({humanize(p.unit)})
      </h4>
      <Rows
        rows={[
          ["Completed", s.completed_means],
          ["Success", s.success_means],
          ["Latency", s.latency_means],
          ["Connections", s.connection_mode_means],
        ]}
      />
      {p.http && (
        <Rows
          rows={[
            ["HTTP/3 → TCP fallback attempts (extra attempts, not requests)", String(p.http.protocol_fallback_attempts)],
            ["Requests that needed a fallback", String(p.http.units_with_fallback)],
            ["Requests completed over HTTP/3", String(p.http.units_over_h3)],
          ]}
        />
      )}
      {p.grpc && (
        <>
          <Rows
            testid="grpc-summary"
            rows={[
              ["Status OK", String(p.grpc.ok)],
              ["Status non-OK", String(p.grpc.non_ok)],
              ["Response without a terminal status (incomplete, never success)", String(p.grpc.missing_status)],
              ["Timed out before any status (status unknown, not DEADLINE_EXCEEDED)", String(requests.timeouts)],
              ["HTTP/3 → TCP fallback attempts", String(p.grpc.protocol_fallback_attempts)],
            ]}
          />
          {p.grpc.status_codes.length > 0 && (
            <Rows
              testid="grpc-codes"
              rows={p.grpc.status_codes.map(([code, n]) => [`${String(code)} ${GRPC_CODES[Number(code)] ?? "non-standard code"}`, String(n)] as [string, string])}
            />
          )}
        </>
      )}
      {p.stream && (
        <>
          <Rows
            rows={[
              ["Streams opened", String(p.stream.opened)],
              [p.unit === "sse_stream" ? "Events received" : "Messages received", String(p.stream.messages_received)],
              ["Opened streams with at least one", String(p.stream.with_messages)],
              ["Mean per opened stream", ratio(p.stream.messages_received, p.stream.opened)],
              ...(p.stream.ended_by ?? []).map((c) => [`Ended by ${closedText(c.closed_by)}`, String(c.count)] as [string, string]),
            ]}
          />
          <LatencyRows rows={[["Time to first message/event", p.stream.time_to_first_message]]} />
        </>
      )}
      {p.websocket && (
        <>
          <Rows
            testid="ws-summary"
            rows={[
              ["Sessions opened (handshake accepted)", String(p.websocket.opened)],
              ["Handshake rejected (server answered another status)", String(p.websocket.handshake_rejected)],
              ["Not opened (connect, TLS, invalid handshake, timeout, cancel)", String(p.websocket.not_opened)],
              ["Opened and closed cleanly", String(p.websocket.closed_cleanly)],
              ["Messages sent / received", `${p.websocket.messages_sent} / ${p.websocket.messages_received}`],
              ...p.websocket.close_codes.map((c) => [`Closed by ${closedText(c.closed_by)}${c.code != null ? `, code ${c.code}` : ""}`, String(c.count)] as [string, string]),
            ]}
          />
          {p.websocket.rtt_defined ? (
            <LatencyRows rows={[[`Round trip (i-th sent → i-th received; ${p.websocket.rtt_pairs} pairs)`, p.websocket.rtt]]} />
          ) : (
            <p className="hint" data-testid="ws-no-rtt">
              Round-trip time: not defined — the request does not set expect_messages, so messages are not paired.
            </p>
          )}
        </>
      )}
      {p.tcp && (
        <Rows
          rows={[
            ["Connections set up", String(p.tcp.connected)],
            ["Frames sent / received", `${p.tcp.frames_sent} / ${p.tcp.frames_received}`],
            ["Payload bytes sent / received", `${fmtBytes(p.tcp.payload_bytes_sent)} / ${fmtBytes(p.tcp.payload_bytes_received)}`],
            ["Exchanges ending with a partial frame", String(p.tcp.partial_frames)],
            ["Exchanges the peer closed", String(p.tcp.peer_closes)],
            ["Expected frames per exchange", p.tcp.expected_frames != null ? String(p.tcp.expected_frames) : "not defined"],
            ["Expected frames received / short", `${p.tcp.expectation_met} / ${p.tcp.expectation_short}`],
          ]}
        />
      )}
      {p.datagram && (
        <>
          <Rows
            testid="datagram-summary"
            rows={[
              ["Datagrams sent", String(p.datagram.datagrams_sent)],
              ["Datagrams received", String(p.datagram.datagrams_received)],
              ["Received per sent (observed ratio, not a delivery rate)", ratio(p.datagram.datagrams_received, p.datagram.datagrams_sent)],
              ["Exchanges with a response", String(p.datagram.exchanges_with_response)],
              ["Exchanges with no response observed", String(p.datagram.exchanges_silent)],
              ["Repeated payloads", String(p.datagram.repeated_payloads)],
              ["Echoed / other payloads", `${p.datagram.echoed_payloads} / ${Math.max(0, p.datagram.datagrams_received - p.datagram.echoed_payloads)}`],
              ["Exchanges with ICMP port unreachable", String(p.datagram.icmp_unreachable_exchanges)],
              ...(p.datagram.dtls_handshakes
                ? ([
                    ["DTLS handshakes attempted", String(p.datagram.dtls_handshakes.attempted)],
                    [
                      "Completed / failed / timed out",
                      `${p.datagram.dtls_handshakes.completed} / ${p.datagram.dtls_handshakes.failed} / ${p.datagram.dtls_handshakes.timed_out}`,
                    ],
                  ] as [string, string][])
                : []),
            ]}
          />
          <LatencyRows
            rows={[
              ["Time to first response", p.datagram.time_to_first_datagram],
              ...(p.datagram.dtls_handshakes ? ([["DTLS handshake (completed)", p.datagram.dtls_handshakes.duration]] as [string, LatencySummary][]) : []),
            ]}
          />
          <p className="hint">
            Sent and received are separate counts. UDP has no acknowledgement: nothing here claims delivery or loss, and received datagrams are not attributed to
            sent ones. Silence means only that no response was observed.
          </p>
        </>
      )}
    </section>
  );
}
