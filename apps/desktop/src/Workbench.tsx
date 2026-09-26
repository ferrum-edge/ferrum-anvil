// Main workspace window: collection tree + history, open request tabs, and
// the request/response split.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ask } from "@tauri-apps/plugin-dialog";
import { api, onExecutionEvent, onSessionEnded, type ExecutionView, type HistoryItem, type StreamMessage, type TreeNode } from "./api";
import { SessionConsole } from "./SessionConsole";
import { ScopeSettingsDialog } from "./ScopeSettings";
import mark from "./assets/ferrum-anvil-mark.png";
import type { Environment, RequestDefinition, Workspace } from "./generated/contracts";
import { EnvironmentsDialog, ExportDialog, ImportDialog, ProfilesDialog, SettingsDialog } from "./Dialogs";
import { RequestEditor, newSpec, type Profiles } from "./RequestEditor";
import { ResponsePanel } from "./ResponsePanel";
import { LoadView } from "./LoadView";
import { RunnerView } from "./RunnerView";
import { Modal, Toast, uid } from "./ui";

// Open tabs live for the whole unlocked session, across workspaces: switching
// workspaces hides a workspace's tabs (with their drafts, in-flight sends and
// sessions) and switching back restores them.
interface OpenTab {
  wsId: string;
  req: RequestDefinition;
  saved: string; // JSON of the last saved spec+name, for dirty tracking
  view: ExecutionView | null;
  running: boolean;
  execId: string | null;
  progress: number | null;
  session?: { execId: string; messages: StreamMessage[] } | null;
}

type Dialog =
  | null
  | "env"
  | "profiles"
  | "export"
  | "import"
  | "settings"
  | "workspace"
  | { kind: "rename"; id: string; isFolder: boolean; name: string }
  | { kind: "history"; view: ExecutionView }
  | { kind: "folder"; id: string };

const snap = (r: RequestDefinition) => JSON.stringify({ n: r.name, s: r.spec });
const isDirty = (t: OpenTab) => snap(t.req) !== t.saved;
/** What is still running for a tab in the backend, if anything. */
const liveWork = (t: OpenTab): "session" | "request" | null => (t.session ? "session" : t.running ? "request" : null);

type View = "requests" | "runner" | "load";

export function Workbench(props: { onLock: () => void; profileName: string }) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [ws, setWs] = useState<Workspace | null>(null);
  const [envs, setEnvs] = useState<Environment[]>([]);
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [tabs, setTabs] = useState<OpenTab[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [side, setSide] = useState<"tree" | "history">("tree");
  const [view, setView] = useState<View>("requests");
  // Runner and Load tests stay mounted once opened, so a run that continues in
  // the backend keeps its live progress and Stop control while another view is shown.
  const [mounted, setMounted] = useState(new Set<View>(["requests"]));
  const [liveRuns, setLiveRuns] = useState({ runner: false, load: false });
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [profiles, setProfiles] = useState<Profiles>({ tls: [], proxy: [], integrations: [] });
  const [dialog, setDialog] = useState<Dialog>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [catalog, setCatalog] = useState("");
  const [reqHeight, setReqHeight] = useState(42);
  const [sideW, setSideW] = useState(290);
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const activeRef = useRef(active);
  activeRef.current = active;
  const activeByWs = useRef<Record<string, string | null>>({});
  const prevWs = useRef<string | null>(null);

  const notify = (m: string) => setToast(m);
  const fail = (e: unknown) => setToast(String((e as Error).message ?? e));

  // ---------------------------------------------------------------- loading
  const loadWorkspaces = useCallback(async (selectId?: string) => {
    let list = await api.workspaces();
    if (list.length === 0) list = [await api.createWorkspace("My workspace")];
    setWorkspaces(list);
    setWs((cur) => list.find((w) => w.id === (selectId ?? cur?.id)) ?? list[0]);
  }, []);
  const loadTree = useCallback(async () => ws && setTree(await api.tree(ws.id)), [ws]);
  const loadHistory = useCallback(async () => ws && setHistory(await api.history(ws.id, null, 200)), [ws]);
  const loadHistoryRef = useRef(loadHistory);
  loadHistoryRef.current = loadHistory;
  const loadProfiles = useCallback(async () => {
    if (!ws) return;
    const [tls, proxy, integrations] = await Promise.all([api.tlsProfiles(ws.id), api.proxyProfiles(ws.id), api.integrations(ws.id)]);
    setProfiles({ tls, proxy, integrations });
  }, [ws]);
  const loadEnvs = useCallback(async () => ws && setEnvs(await api.environments(ws.id)), [ws]);

  useEffect(() => {
    void loadWorkspaces().catch(fail);
    api.systemInfo().then((i) => setCatalog(i.catalog));
    api.settings().then((s) => document.documentElement.setAttribute("data-theme", s.theme));
  }, []);
  useEffect(() => {
    if (!ws) return;
    // Keep every workspace's tabs; remember which one was active here.
    if (prevWs.current) activeByWs.current[prevWs.current] = activeRef.current;
    prevWs.current = ws.id;
    setActive(activeByWs.current[ws.id] ?? null);
    void Promise.all([loadTree(), loadHistory(), loadProfiles(), loadEnvs()]).catch(fail);
  }, [ws?.id]);

  // Live progress and session messages.
  useEffect(() => {
    const un = onExecutionEvent((ev) => {
      if (ev.event === "body_progress") {
        setTabs((ts) => ts.map((t) => (t.execId === ev.execution_id ? { ...t, progress: ev.bytes } : t)));
      } else if (ev.event === "message") {
        setTabs((ts) =>
          ts.map((t) =>
            t.session?.execId === ev.execution_id ? { ...t, session: { ...t.session, messages: [...t.session.messages, ev.message].slice(-5000) } } : t,
          ),
        );
      }
    });
    const ended = onSessionEnded((e) => {
      setTabs((ts) => ts.map((t) => (t.session?.execId === e.execution_id ? { ...t, session: null, view: e.view ?? t.view } : t)));
      if (e.error) setToast(`Session ended: ${e.error}`);
      void loadHistoryRef.current?.();
    });
    return () => {
      void un.then((f) => f());
      void ended.then((f) => f());
    };
  }, []);

  const wsTabs = tabs.filter((t) => t.wsId === ws?.id);
  const tab = wsTabs.find((t) => t.req.id === active) ?? null;
  const updateTab = (id: string, patch: Partial<OpenTab>) => setTabs((ts) => ts.map((t) => (t.req.id === id ? { ...t, ...patch } : t)));

  // ---------------------------------------------------------------- actions
  const openRequest = async (id: string) => {
    if (!tabsRef.current.some((t) => t.req.id === id)) {
      const req = await api.getRequest(id);
      setTabs((ts) => [...ts, { wsId: req.workspace_id, req, saved: snap(req), view: null, running: false, execId: null, progress: null }]);
    }
    setActive(id);
  };

  const newRequest = async (folderId: string | null) => {
    if (!ws) return;
    const req = await api.createRequest(ws.id, folderId, "New request", newSpec());
    await loadTree();
    if (folderId) setExpanded((s) => new Set(s).add(folderId));
    setTabs((ts) => [...ts, { wsId: ws.id, req, saved: snap(req), view: null, running: false, execId: null, progress: null }]);
    setActive(req.id);
  };

  const newFolder = async (parentId: string | null) => {
    if (!ws) return;
    const f = await api.createFolder(ws.id, parentId, "New folder");
    await loadTree();
    setExpanded((s) => new Set(s).add(f.id));
    setDialog({ kind: "rename", id: f.id, isFolder: true, name: f.name });
  };

  const saveTab = async (t: OpenTab | null = tab) => {
    if (!t) return;
    try {
      const saved = await api.saveRequest(t.req);
      updateTab(t.req.id, { req: saved, saved: snap(saved) });
      await loadTree();
    } catch (e) {
      fail(e);
    }
  };

  // The tab's own workspace: a send can outlive a workspace switch.
  const envOf = (wsId: string) => (wsId === ws?.id ? ws : workspaces.find((w) => w.id === wsId))?.active_environment_id ?? null;

  const send = async (sendAnyway = false, id: string | null = active) => {
    const t = tabsRef.current.find((x) => x.req.id === id);
    if (!t || !ws || t.running) return;
    const execId = uid();
    const rid = t.req.id;
    updateTab(rid, { running: true, execId, progress: null });
    try {
      const view = await api.send({ workspace_id: t.wsId, request_id: rid, spec: t.req.spec, environment_id: envOf(t.wsId), send_anyway: sendAnyway }, execId);
      updateTab(rid, { view, running: false, execId: null });
      void loadHistory();
      if (!sendAnyway && view.record.findings.some((f) => f.code === "local.lint_blocked")) {
        const go = await ask("The body failed syntax validation and this request blocks invalid bodies. Send it anyway?", {
          title: "Invalid body",
          kind: "warning",
          okLabel: "Send anyway",
          cancelLabel: "Keep editing",
        });
        if (go) await send(true, rid);
      }
    } catch (e) {
      updateTab(rid, { running: false, execId: null });
      fail(e);
    }
  };

  const connect = async () => {
    const t = tabsRef.current.find((x) => x.req.id === active);
    if (!t || !ws || t.running || t.session) return;
    const execId = uid();
    updateTab(t.req.id, { session: { execId, messages: [] }, view: null });
    try {
      await api.sessionOpen({ workspace_id: t.wsId, request_id: t.req.id, spec: t.req.spec, environment_id: envOf(t.wsId), send_anyway: false }, execId);
    } catch (e) {
      updateTab(t.req.id, { session: null });
      fail(e);
    }
  };

  const show = (v: View) => {
    setView(v);
    setMounted((m) => (m.has(v) ? m : new Set(m).add(v)));
    if (v !== "requests") void loadTree();
  };

  const cancel = async () => {
    if (tab?.execId) await api.cancel(tab.execId);
  };

  // Stop what a tab still runs in the backend: the tab is its only control.
  const stopWork = async (t: OpenTab) => {
    try {
      if (t.session) await api.sessionCancel(t.session.execId);
      if (t.running && t.execId) await api.cancel(t.execId);
    } catch (e) {
      fail(e);
    }
  };

  const closeTab = async (id: string) => {
    const t = tabsRef.current.find((x) => x.req.id === id);
    if (!t) return;
    const live = liveWork(t);
    const dirty = isDirty(t);
    if (live) {
      const what = live === "session" ? "an open session that will be disconnected" : "a request in flight that will be canceled";
      const ok = await ask(`“${t.req.name}” has ${what}${dirty ? " and unsaved changes that will be discarded" : ""}. Close it?`, {
        title: live === "session" ? "Open session" : "Request in flight",
        kind: "warning",
        okLabel: live === "session" ? "Disconnect and close" : "Cancel and close",
        cancelLabel: "Keep open",
      });
      if (!ok) return;
    } else if (dirty) {
      const discard = await ask(`“${t.req.name}” has unsaved changes. Close without saving?`, { title: "Unsaved changes", kind: "warning", okLabel: "Discard", cancelLabel: "Keep open" });
      if (!discard) return;
    }
    const cur = tabsRef.current.find((x) => x.req.id === id);
    if (cur) await stopWork(cur);
    setTabs((ts) => ts.filter((x) => x.req.id !== id));
    setActive((a) => (a === id ? (tabsRef.current.find((x) => x.req.id !== id && x.wsId === t.wsId)?.req.id ?? null) : a));
  };

  const removeNode = async (n: TreeNode) => {
    // The unfiltered node: a filtered folder may hide some of its requests.
    const ids = new Set(requestIds([findNode(tree, n.id) ?? n]));
    const live = tabsRef.current.some((t) => ids.has(t.req.id) && liveWork(t));
    const stop = live ? " Its open session or request in flight will be stopped." : "";
    const ok = await ask(n.kind === "folder" ? `Delete folder “${n.name}” and everything in it?${stop}` : `Delete “${n.name}”?${stop}`, { title: "Delete", kind: "warning", okLabel: "Delete" });
    if (!ok) return;
    try {
      if (n.kind === "folder") await api.deleteFolder(n.id);
      else await api.deleteRequest(n.id);
      const gone = tabsRef.current.filter((t) => ids.has(t.req.id));
      await Promise.all(gone.map(stopWork));
      setTabs((ts) => ts.filter((t) => !ids.has(t.req.id)));
      setActive((a) => (a && ids.has(a) ? null : a));
      await loadTree();
    } catch (e) {
      fail(e);
    }
  };

  const moveInto = async (dragId: string, dragKind: string, folderId: string | null) => {
    try {
      const key = Date.now();
      if (dragKind === "request") await api.moveRequest(dragId, folderId, key);
      else if (dragId !== folderId) await api.moveFolder(dragId, folderId, key);
      await loadTree();
    } catch (e) {
      fail(e);
    }
  };

  // ------------------------------------------------------------- shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key === "Enter") {
        e.preventDefault();
        void send();
      } else if (mod && e.key.toLowerCase() === "s") {
        e.preventDefault();
        void saveTab();
      } else if (mod && e.key.toLowerCase() === "l") {
        e.preventDefault();
        props.onLock();
      } else if (mod && e.key.toLowerCase() === "n") {
        e.preventDefault();
        void newRequest(null);
      } else if (e.key === "Escape" && tab?.running) {
        void cancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  // Tell the backend the user is active (idle auto-lock).
  useEffect(() => {
    let last = 0;
    const ping = () => {
      const n = Date.now();
      if (n - last > 15000) {
        last = n;
        void api.touch();
      }
    };
    window.addEventListener("pointerdown", ping);
    window.addEventListener("keydown", ping);
    return () => {
      window.removeEventListener("pointerdown", ping);
      window.removeEventListener("keydown", ping);
    };
  }, []);

  const filtered = useMemo(() => filterTree(tree, filter.trim().toLowerCase()), [tree, filter]);
  const activeEnv = envs.find((e) => e.id === ws?.active_environment_id) ?? null;

  // ------------------------------------------------------------------ render
  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <img className="brand-mark" src={mark} alt="" />
          Anvil
        </div>
        <select
          className="field"
          aria-label="Workspace"
          value={ws?.id ?? ""}
          onChange={async (e) => {
            if (e.target.value === "__new") {
              const w = await api.createWorkspace("New workspace");
              await loadWorkspaces(w.id);
              setDialog({ kind: "rename", id: w.id, isFolder: false, name: w.name });
            } else setWs(workspaces.find((w) => w.id === e.target.value) ?? null);
          }}
        >
          {workspaces.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name + wsNote(tabs.filter((t) => t.wsId === w.id))}
            </option>
          ))}
          <option value="__new">+ New workspace…</option>
        </select>
        <button className="btn ghost icon-btn" aria-label="Workspace settings" title="Workspace auth, variables and settings" onClick={() => setDialog("workspace")}>
          ⚙
        </button>
        <select
          className="field"
          aria-label="Environment"
          value={ws?.active_environment_id ?? ""}
          onChange={async (e) => {
            if (!ws) return;
            if (e.target.value === "__manage") return setDialog("env");
            const w = await api.saveWorkspace({ ...ws, active_environment_id: e.target.value || null });
            setWs(w);
            setWorkspaces((l) => l.map((x) => (x.id === w.id ? w : x)));
          }}
        >
          <option value="">No environment</option>
          {envs.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
          <option value="__manage">Manage environments…</option>
        </select>
        <div className="viewswitch" role="group" aria-label="View">
          <button aria-pressed={view === "requests"} onClick={() => show("requests")}>
            Requests
          </button>
          <button aria-pressed={view === "runner"} title={liveRuns.runner ? "A run is in progress" : undefined} onClick={() => show("runner")}>
            Runner
            {liveRuns.runner && <span className="live-dot" data-testid="runner-live" />}
          </button>
          <button aria-pressed={view === "load"} title={liveRuns.load ? "A load run is in progress" : undefined} onClick={() => show("load")}>
            Load tests
            {liveRuns.load && <span className="live-dot" data-testid="load-live" />}
          </button>
        </div>
        <span className="spacer" />
        <button className="btn ghost" onClick={() => setDialog("profiles")}>
          Profiles
        </button>
        <button className="btn ghost" onClick={() => setDialog("import")}>
          Import
        </button>
        <button className="btn ghost" onClick={() => setDialog("export")}>
          Export
        </button>
        <button className="btn ghost icon-btn" aria-label="Settings" onClick={() => setDialog("settings")}>
          ⚙
        </button>
        <button className="btn" onClick={props.onLock} title="Lock (⌘/Ctrl+L)">
          🔒 Lock
        </button>
      </header>

      {mounted.has("load") && ws && (
        <LoadView
          workspaceId={ws.id}
          tree={tree}
          environments={envs}
          notify={notify}
          hidden={view !== "load"}
          onLiveChange={(load) => setLiveRuns((l) => ({ ...l, load }))}
        />
      )}
      {mounted.has("runner") && ws && (
        <RunnerView
          workspaceId={ws.id}
          tree={tree}
          environments={envs}
          activeEnvironment={ws.active_environment_id ?? null}
          notify={notify}
          hidden={view !== "runner"}
          onLiveChange={(runner) => setLiveRuns((l) => ({ ...l, runner }))}
        />
      )}
      <div className="main" style={{ ["--sidebar-w" as string]: `${sideW}px`, display: view === "requests" ? undefined : "none" }}>
        <aside className="sidebar" aria-label="Collections and history">
          <div className="side-tabs" role="tablist">
            <button className="side-tab" role="tab" aria-selected={side === "tree"} onClick={() => setSide("tree")}>
              Collections
            </button>
            <button
              className="side-tab"
              role="tab"
              aria-selected={side === "history"}
              onClick={() => {
                setSide("history");
                void loadHistory();
              }}
            >
              History
            </button>
          </div>
          {side === "tree" && (
            <div className="side-body" onDragOver={(e) => e.preventDefault()} onDrop={(e) => onDropTo(e, null, moveInto)}>
              <div className="row" style={{ marginBottom: 6 }}>
                <input className="field grow" placeholder="Filter" aria-label="Filter requests" value={filter} onChange={(e) => setFilter(e.target.value)} />
                <button className="btn small" title="New request (⌘/Ctrl+N)" onClick={() => newRequest(null)}>
                  + Request
                </button>
                <button className="btn small ghost" title="New folder" onClick={() => newFolder(null)}>
                  + Folder
                </button>
              </div>
              {filtered.length === 0 && <div className="faint" style={{ padding: 8 }}>{filter ? "No matches." : "No requests yet. Create one, or import a bundle."}</div>}
              <Tree
                nodes={filtered}
                depth={0}
                expanded={filter ? new Set(allIds(filtered)) : expanded}
                activeId={active}
                onToggle={(id) => setExpanded((s) => (s.has(id) ? new Set([...s].filter((x) => x !== id)) : new Set(s).add(id)))}
                onOpen={openRequest}
                onNewRequest={newRequest}
                onNewFolder={newFolder}
                onRename={(n) => setDialog({ kind: "rename", id: n.id, isFolder: n.kind === "folder", name: n.name })}
                onFolderSettings={(id) => setDialog({ kind: "folder", id })}
                onDuplicate={async (n) => {
                  await api.duplicateRequest(n.id);
                  await loadTree();
                }}
                onDelete={removeNode}
                onMove={moveInto}
              />
            </div>
          )}
          {side === "history" && (
            <div className="side-body">
              {history.length === 0 && <div className="faint" style={{ padding: 8 }}>No history yet.</div>}
              {history.map((h) => (
                <div
                  key={h.id}
                  className="hist-row"
                  role="button"
                  tabIndex={0}
                  onClick={async () => setDialog({ kind: "history", view: await api.historyGet(h.id) })}
                  onKeyDown={async (e) => e.key === "Enter" && setDialog({ kind: "history", view: await api.historyGet(h.id) })}
                >
                  <span className={`method m-${h.method}`}>{h.method}</span>
                  <span className="mono" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {h.url}
                  </span>
                  <span className={`mono s${String(h.status ?? 5)[0]}`}>{h.status ?? "—"}</span>
                  <span className="faint" style={{ fontSize: 11 }}>
                    {new Date(h.started_at * 1000).toLocaleString()} · {h.summary}
                  </span>
                </div>
              ))}
            </div>
          )}
        </aside>
        <div className="resizer" onMouseDown={(e) => drag(e, "x", (d) => setSideW((w) => Math.min(520, Math.max(200, w + d))))} role="separator" aria-orientation="vertical" />
        <section className="work">
          <nav className="tabbar" role="tablist" aria-label="Open requests">
            {wsTabs.map((t) => (
              <div key={t.req.id} className="tab" role="tab" aria-selected={t.req.id === active} onClick={() => setActive(t.req.id)} onAuxClick={(e) => e.button === 1 && closeTab(t.req.id)}>
                <span className={`method m-${t.req.spec.method ?? "GET"}`}>{(t.req.spec.protocol ?? "http") === "http" ? t.req.spec.method ?? "GET" : protoShort(t.req.spec.protocol!)}</span>
                <span className="name">{t.req.name}</span>
                {isDirty(t) && <span className="dirty" aria-label="unsaved" />}
                {t.session && <span className="badge accent">live</span>}
                <button
                  className="btn ghost icon-btn"
                  style={{ width: 18, height: 18, fontSize: 10 }}
                  aria-label={`Close ${t.req.name}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    void closeTab(t.req.id);
                  }}
                >
                  ✕
                </button>
              </div>
            ))}
          </nav>
          {tab && ws ? (
            <div className="editor" style={{ ["--req-h" as string]: `${reqHeight}%` }}>
              <div style={{ display: "contents" }}>
                <RequestEditor
                  key={tab.req.id}
                  req={tab.req}
                  onChange={(req) => updateTab(tab.req.id, { req })}
                  onSend={(anyway) => void send(anyway)}
                  onConnect={() => void connect()}
                  connected={!!tab.session}
                  onSave={() => void saveTab()}
                  onCancel={() => void cancel()}
                  running={tab.running}
                  dirty={snap(tab.req) !== tab.saved}
                  workspaceId={ws.id}
                  environmentId={ws.active_environment_id ?? null}
                  profiles={profiles}
                />
              </div>
              <div
                className="hsplit"
                role="separator"
                aria-orientation="horizontal"
                onMouseDown={(e) => {
                  const host = (e.currentTarget.parentElement as HTMLElement).getBoundingClientRect();
                  drag(e, "y", (_d, ev) => setReqHeight(Math.min(75, Math.max(15, ((ev.clientY - host.top - 90) / host.height) * 100))));
                }}
              />
              {tab.session ? (
                <SessionConsole
                  protocol={tab.req.spec.protocol ?? "http"}
                  messages={tab.session.messages}
                  onSend={(c) => api.sessionSend(tab.session!.execId, c)}
                  onCancel={() => void api.sessionCancel(tab.session!.execId)}
                />
              ) : (
                <ResponsePanel view={tab.view} running={tab.running} progressBytes={tab.progress} onCancel={() => void cancel()} />
              )}
            </div>
          ) : (
            <div className="empty">
              <div>
                <img className="empty-mark" src={mark} alt="" />
                <div className="big">Put your APIs to the test.</div>
                <div>Open a request from the sidebar, or create one with ⌘/Ctrl+N.</div>
                <button className="btn primary" style={{ marginTop: 14 }} onClick={() => newRequest(null)}>
                  New request
                </button>
              </div>
            </div>
          )}
        </section>
      </div>

      <footer className="statusbar">
        <span>Profile: {props.profileName}</span>
        <span>Environment: {activeEnv?.name ?? "none"}</span>
        <span className="spacer" />
        <span>Local-only · no account</span>
        <span>Diagnostics catalog {catalog}</span>
      </footer>

      {dialog === "env" && ws && (
        <EnvironmentsDialog
          workspace={ws}
          onClose={() => setDialog(null)}
          onChanged={async () => {
            await loadEnvs();
            await loadWorkspaces(ws.id);
          }}
        />
      )}
      {dialog === "workspace" && ws && (
        <ScopeSettingsDialog
          target={{ kind: "workspace", workspace: ws }}
          workspaceId={ws.id}
          profiles={profiles}
          onClose={() => setDialog(null)}
          onSaved={(w) => {
            if (w) {
              setWs(w);
              setWorkspaces((l) => l.map((x) => (x.id === w.id ? w : x)));
            }
          }}
        />
      )}
      {typeof dialog === "object" && dialog?.kind === "folder" && ws && (
        <ScopeSettingsDialog target={{ kind: "folder", id: dialog.id }} workspaceId={ws.id} profiles={profiles} onClose={() => setDialog(null)} onSaved={() => void loadTree()} />
      )}
      {dialog === "profiles" && ws && <ProfilesDialog workspaceId={ws.id} onClose={() => setDialog(null)} onChanged={loadProfiles} />}
      {dialog === "export" && <ExportDialog workspace={ws} onClose={() => setDialog(null)} notify={notify} />}
      {dialog === "import" && (
        <ImportDialog
          workspaceId={ws?.id ?? null}
          workspaceName={ws?.name ?? null}
          onSpecImported={async (r) => {
            setDialog(null);
            const missing = r.report.required_variables.length;
            notify(`Imported ${r.requests} request(s). Nothing was sent.${missing ? ` Fill in ${missing} variable(s) before sending.` : ""}`);
            await loadWorkspaces(r.workspace_id);
            await loadTree();
          }}
          onClose={() => setDialog(null)}
          onImported={async (ids) => {
            notify(`Imported ${ids.length} workspace(s). Nothing was run.`);
            await loadWorkspaces(ids[0]);
            await loadTree();
          }}
        />
      )}
      {dialog === "settings" && <SettingsDialog onClose={() => setDialog(null)} onSaved={(s) => document.documentElement.setAttribute("data-theme", s.theme)} />}
      {typeof dialog === "object" && dialog?.kind === "rename" && (
        <RenameDialog
          name={dialog.name}
          onClose={() => setDialog(null)}
          onSave={async (name) => {
            try {
              if (dialog.isFolder) {
                const f = await api.getFolder(dialog.id);
                await api.saveFolder({ ...f, name });
              } else if (workspaces.some((w) => w.id === dialog.id)) {
                const w = workspaces.find((x) => x.id === dialog.id)!;
                const saved = await api.saveWorkspace({ ...w, name });
                setWorkspaces((l) => l.map((x) => (x.id === saved.id ? saved : x)));
                setWs(saved);
              } else {
                const open = tabsRef.current.find((t) => t.req.id === dialog.id);
                const r = open ? open.req : await api.getRequest(dialog.id);
                const saved = await api.saveRequest({ ...r, name });
                if (open) updateTab(saved.id, { req: { ...open.req, name }, saved: snap({ ...open.req, name }) === open.saved ? open.saved : snap(saved) });
              }
              await loadTree();
            } catch (e) {
              fail(e);
            }
            setDialog(null);
          }}
        />
      )}
      {typeof dialog === "object" && dialog?.kind === "history" && (
        <Modal title={`${dialog.view.record.prepared.method} ${dialog.view.record.prepared.url}`} wide onClose={() => setDialog(null)}>
          <div style={{ height: "70vh", display: "grid" }}>
            <ResponsePanel view={dialog.view} running={false} progressBytes={null} onCancel={() => {}} />
          </div>
          {dialog.view.record.request_id && (
            <button
              className="btn"
              onClick={() => {
                const rid = dialog.view.record.request_id!;
                setDialog(null);
                void openRequest(rid).catch(() => notify("That saved request no longer exists."));
              }}
            >
              Open the saved request
            </button>
          )}
        </Modal>
      )}
      <Toast message={toast} onClose={() => setToast(null)} />
    </div>
  );
}

/** Shown in the workspace switcher: what that workspace's open tabs still hold. */
function wsNote(ts: OpenTab[]): string {
  const unsaved = ts.filter(isDirty).length;
  const live = ts.filter((t) => liveWork(t)).length;
  const parts = [unsaved ? `${unsaved} unsaved` : "", live ? `${live} live` : ""].filter(Boolean);
  return parts.length ? ` (${parts.join(", ")})` : "";
}

function findNode(nodes: TreeNode[], id: string): TreeNode | null {
  for (const n of nodes) {
    if (n.id === id) return n;
    const hit = findNode(n.children, id);
    if (hit) return hit;
  }
  return null;
}
function requestIds(nodes: TreeNode[]): string[] {
  return nodes.flatMap((n) => (n.kind === "request" ? [n.id] : requestIds(n.children)));
}

function protoShort(p: string) {
  return { web_socket: "WS", grpc: "gRPC", sse: "SSE", tcp: "TCP", udp: "UDP" }[p] ?? p.toUpperCase();
}

function RenameDialog(props: { name: string; onClose: () => void; onSave: (n: string) => void }) {
  const [n, setN] = useState(props.name);
  return (
    <Modal
      title="Rename"
      onClose={props.onClose}
      footer={
        <button className="btn primary" disabled={!n.trim()} onClick={() => props.onSave(n.trim())}>
          Save
        </button>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (n.trim()) props.onSave(n.trim());
        }}
      >
        <input className="field" style={{ width: "100%" }} value={n} onChange={(e) => setN(e.target.value)} onFocus={(e) => e.target.select()} />
      </form>
    </Modal>
  );
}

function drag(e: React.MouseEvent, axis: "x" | "y", onMove: (delta: number, ev: MouseEvent) => void) {
  e.preventDefault();
  let last = axis === "x" ? e.clientX : e.clientY;
  const move = (ev: MouseEvent) => {
    const cur = axis === "x" ? ev.clientX : ev.clientY;
    onMove(cur - last, ev);
    last = cur;
  };
  const up = () => {
    window.removeEventListener("mousemove", move);
    window.removeEventListener("mouseup", up);
  };
  window.addEventListener("mousemove", move);
  window.addEventListener("mouseup", up);
}

function filterTree(nodes: TreeNode[], q: string): TreeNode[] {
  if (!q) return nodes;
  const out: TreeNode[] = [];
  for (const n of nodes) {
    const kids = filterTree(n.children, q);
    const hit = n.name.toLowerCase().includes(q) || (n.url ?? "").toLowerCase().includes(q);
    if (hit || kids.length) out.push({ ...n, children: hit && n.kind === "folder" ? n.children : kids });
  }
  return out;
}
function allIds(nodes: TreeNode[]): string[] {
  return nodes.flatMap((n) => [n.id, ...allIds(n.children)]);
}

function onDropTo(e: React.DragEvent, folderId: string | null, move: (id: string, kind: string, folder: string | null) => void) {
  e.preventDefault();
  e.stopPropagation();
  const data = e.dataTransfer.getData("application/x-anvil-node");
  if (!data) return;
  const { id, kind } = JSON.parse(data) as { id: string; kind: string };
  move(id, kind, folderId);
}

function Tree(props: {
  nodes: TreeNode[];
  depth: number;
  expanded: Set<string>;
  activeId: string | null;
  onToggle: (id: string) => void;
  onOpen: (id: string) => void;
  onNewRequest: (folder: string) => void;
  onNewFolder: (parent: string) => void;
  onRename: (n: TreeNode) => void;
  onFolderSettings: (id: string) => void;
  onDuplicate: (n: TreeNode) => void;
  onDelete: (n: TreeNode) => void;
  onMove: (id: string, kind: string, folder: string | null) => void;
}) {
  const [over, setOver] = useState<string | null>(null);
  return (
    <div role={props.depth === 0 ? "tree" : "group"}>
      {props.nodes.map((n) => {
        const isOpen = props.expanded.has(n.id);
        return (
          <div key={n.id}>
            <div
              className={`tree-row ${props.activeId === n.id ? "selected" : ""} ${over === n.id ? "drop-target" : ""}`}
              role="treeitem"
              aria-expanded={n.kind === "folder" ? isOpen : undefined}
              aria-selected={props.activeId === n.id}
              tabIndex={0}
              style={{ paddingLeft: 6 + props.depth * 14 }}
              draggable
              onDragStart={(e) => e.dataTransfer.setData("application/x-anvil-node", JSON.stringify({ id: n.id, kind: n.kind }))}
              onDragOver={(e) => {
                if (n.kind === "folder") {
                  e.preventDefault();
                  setOver(n.id);
                }
              }}
              onDragLeave={() => setOver(null)}
              onDrop={(e) => {
                setOver(null);
                if (n.kind === "folder") onDropTo(e, n.id, props.onMove);
              }}
              onClick={() => (n.kind === "folder" ? props.onToggle(n.id) : props.onOpen(n.id))}
              onKeyDown={(e) => {
                if (e.key === "Enter") n.kind === "folder" ? props.onToggle(n.id) : props.onOpen(n.id);
                if (e.key === "F2") props.onRename(n);
                if (e.key === "Delete" || e.key === "Backspace") props.onDelete(n);
              }}
            >
              {n.kind === "folder" ? <span className="caret">{isOpen ? "▾" : "▸"}</span> : <span className={`method m-${n.method ?? "GET"}`}>{n.method ?? "GET"}</span>}
              <span className="name grow">{n.kind === "folder" ? `📁 ${n.name}` : n.name}</span>
              <span className="actions" onClick={(e) => e.stopPropagation()}>
                {n.kind === "folder" && (
                  <>
                    <button className="btn ghost icon-btn" style={{ width: 22, height: 22 }} title="New request here" aria-label="New request in folder" onClick={() => props.onNewRequest(n.id)}>
                      +
                    </button>
                    <button className="btn ghost icon-btn" style={{ width: 22, height: 22 }} title="New subfolder" aria-label="New subfolder" onClick={() => props.onNewFolder(n.id)}>
                      ⊞
                    </button>
                    <button className="btn ghost icon-btn" style={{ width: 22, height: 22 }} title="Folder auth, variables and settings" aria-label="Folder settings" onClick={() => props.onFolderSettings(n.id)}>
                      ⚙
                    </button>
                  </>
                )}
                {n.kind === "request" && (
                  <button className="btn ghost icon-btn" style={{ width: 22, height: 22 }} title="Duplicate" aria-label="Duplicate" onClick={() => props.onDuplicate(n)}>
                    ⧉
                  </button>
                )}
                <button className="btn ghost icon-btn" style={{ width: 22, height: 22 }} title="Rename (F2)" aria-label="Rename" onClick={() => props.onRename(n)}>
                  ✎
                </button>
                <button className="btn ghost icon-btn" style={{ width: 22, height: 22 }} title="Delete" aria-label="Delete" onClick={() => props.onDelete(n)}>
                  🗑
                </button>
              </span>
            </div>
            {n.kind === "folder" && isOpen && <Tree {...props} nodes={n.children} depth={props.depth + 1} />}
          </div>
        );
      })}
    </div>
  );
}
