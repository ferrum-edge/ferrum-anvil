// Main workspace window: collection tree + history, open request tabs, and
// the request/response split.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ask } from "@tauri-apps/plugin-dialog";
import { api, onExecutionEvent, onSessionEnded, type ExecutionView, type HistoryItem, type StreamMessage, type TreeNode } from "./api";
import { SessionConsole } from "./SessionConsole";
import { ScopeSettingsDialog } from "./ScopeSettings";
import mark from "./assets/ferrum-anvil-mark.png";
import type { Environment, Protocol, RequestDefinition, Workspace } from "./generated/contracts";
import { EnvironmentsDialog, ExportDialog, ImportDialog, ProfilesDialog, SettingsDialog } from "./Dialogs";
import { RequestEditor, newSpec, type Profiles } from "./RequestEditor";
import { ResponsePanel } from "./ResponsePanel";
import { LoadView } from "./LoadView";
import { RunnerView } from "./RunnerView";
import { Icon } from "./icons";
import { Keys, Modal, SidebarContext, SidebarResizer, Toast, drag, fmtAgo, shortcut, uid } from "./ui";

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
type Layout = "stack" | "side";

const clamp = (lo: number, hi: number, v: number) => Math.min(hi, Math.max(lo, v));
/** Below this viewport width the sidebar folds away (the toggle brings it back). */
const NARROW = "(max-width: 860px)";
/** The side-by-side layout needs this much editor width; narrower editors stack. */
const SIDE_MIN_WIDTH = 980;
const LAYOUT_KEY = "anvil.editor.layout";

function storedLayout(): Layout {
  try {
    return localStorage.getItem(LAYOUT_KEY) === "side" ? "side" : "stack";
  } catch {
    return "stack";
  }
}

export function Workbench(props: { onLock: () => void; profileName: string }) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [ws, setWs] = useState<Workspace | null>(null);
  const [envs, setEnvs] = useState<Environment[]>([]);
  const [tree, setTree] = useState<TreeNode[]>([]);
  // The workspace whose tree is shown: until the selected one's arrives, it is loading.
  const [treeWs, setTreeWs] = useState<string | null>(null);
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
  const [reqWidth, setReqWidth] = useState(46);
  const [sideW, setSideW] = useState(280);
  const [sideCollapsed, setSideCollapsed] = useState(false);
  const [layout, setLayout] = useState<Layout>(storedLayout);
  const [editorWide, setEditorWide] = useState(false);
  const editorRef = useRef<HTMLDivElement | null>(null);
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const activeRef = useRef(active);
  activeRef.current = active;
  const activeByWs = useRef<Record<string, string | null>>({});
  const prevWs = useRef<string | null>(null);
  // Read after awaits (a resend, a session open): the workspaces as they are now.
  const wsRef = useRef(ws);
  wsRef.current = ws;
  const workspacesRef = useRef(workspaces);
  workspacesRef.current = workspaces;
  // The last selected workspace: Runner and Load tests stay mounted through a
  // brief `ws === null` (a reload), keeping a live run's progress and Stop control.
  const lastWs = useRef(ws);
  if (ws) lastWs.current = ws;
  const viewWs = ws ?? lastWs.current;
  // Sessions this window canceled: their failed open is not an error to report.
  const stopped = useRef(new Set<string>());
  // Opens whose `session_open` call has not returned yet.
  const opening = useRef(new Set<string>());
  // Opens aborted before the backend registered them: canceled again once they open.
  const earlyAborts = useRef(new Set<string>());

  const notify = (m: string) => setToast(m);
  const fail = (e: unknown) => setToast(String((e as Error).message ?? e));

  // ---------------------------------------------------------------- loading
  const loadWorkspaces = useCallback(async (selectId?: string) => {
    let list = await api.workspaces();
    if (list.length === 0) list = [await api.createWorkspace("My workspace")];
    setWorkspaces(list);
    setWs((cur) => list.find((w) => w.id === (selectId ?? cur?.id)) ?? list[0]);
  }, []);
  // A workspace's lists (tree, history, profiles, environments) are shown only
  // from their latest read, and only while that workspace is still selected:
  // an earlier read that finishes late, or one from a workspace since left, is
  // dropped with its result or error.
  const reads = useRef(new Map<string, number>());
  const readLatest = async <T,>(list: string, wsId: string, read: () => Promise<T>, show: (v: T) => void) => {
    const key = `${list}:${wsId}`;
    const n = (reads.current.get(key) ?? 0) + 1;
    reads.current.set(key, n);
    const current = () => reads.current.get(key) === n && wsRef.current?.id === wsId;
    try {
      const v = await read();
      if (current()) show(v);
    } catch (e) {
      if (current()) throw e;
    }
  };
  const loadTree = useCallback(async () => {
    if (!ws) return;
    await readLatest("tree", ws.id, () => api.tree(ws.id), (t) => {
      setTree(t);
      setTreeWs(ws.id);
    });
  }, [ws]);
  const loadHistory = useCallback(async () => {
    if (ws) await readLatest("history", ws.id, () => api.history(ws.id, null, 200), setHistory);
  }, [ws]);
  const loadHistoryRef = useRef(loadHistory);
  loadHistoryRef.current = loadHistory;
  const loadProfiles = useCallback(async () => {
    if (!ws) return;
    const read = async () => {
      const [tls, proxy, integrations] = await Promise.all([api.tlsProfiles(ws.id), api.proxyProfiles(ws.id), api.integrations(ws.id)]);
      return { tls, proxy, integrations };
    };
    await readLatest("profiles", ws.id, read, setProfiles);
  }, [ws]);
  const loadEnvs = useCallback(async () => {
    if (ws) await readLatest("envs", ws.id, () => api.environments(ws.id), setEnvs);
  }, [ws]);

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
    // Nothing of the workspace left is shown while this one loads.
    setTree([]);
    setHistory([]);
    setProfiles({ tls: [], proxy: [], integrations: [] });
    setEnvs([]);
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
      stopped.current.delete(e.execution_id);
      setTabs((ts) => ts.map((t) => (t.session?.execId === e.execution_id ? { ...t, session: null, view: e.view ?? t.view } : t)));
      if (e.error) setToast(`Session ended: ${e.error}`);
      void loadHistoryRef.current?.();
    });
    return () => {
      void un.then((f) => f());
      void ended.then((f) => f());
    };
  }, []);

  // Narrow windows fold the sidebar away; widening brings it back.
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(NARROW);
    const apply = () => setSideCollapsed(mq.matches);
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, []);

  const wsTabs = tabs.filter((t) => t.wsId === ws?.id);
  const tab = wsTabs.find((t) => t.req.id === active) ?? null;
  const updateTab = (id: string, patch: Partial<OpenTab>) => setTabs((ts) => ts.map((t) => (t.req.id === id ? { ...t, ...patch } : t)));

  // The side-by-side layout applies only while the editor is wide enough.
  const hasEditor = !!tab && !!ws;
  useEffect(() => {
    const el = editorRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([e]) => setEditorWide(e.contentRect.width >= SIDE_MIN_WIDTH));
    ro.observe(el);
    return () => ro.disconnect();
  }, [hasEditor, view]);
  const sideBySide = layout === "side" && editorWide;
  const toggleLayout = () => {
    const next: Layout = layout === "side" ? "stack" : "side";
    setLayout(next);
    try {
      localStorage.setItem(LAYOUT_KEY, next);
    } catch {
      /* storage unavailable: keep the choice for this session */
    }
  };

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

  // The editor stays usable while a save is pending. Saves of one request run
  // one at a time, in the order asked, so the last to finish wrote last; each
  // moves the saved baseline to what it wrote and keeps edits made meanwhile,
  // which stay unsaved.
  const saving = useRef(new Map<string, Promise<RequestDefinition>>());
  const saveTab = async (t: OpenTab | null = tab) => {
    if (!t) return;
    const submitted = t.req;
    const id = submitted.id;
    const run = (saving.current.get(id) ?? Promise.resolve()).catch(() => {}).then(() => api.saveRequest(submitted));
    saving.current.set(id, run);
    try {
      const saved = await run;
      setTabs((ts) =>
        ts.map((x) => (x.req.id !== id ? x : { ...x, req: x.req === submitted ? saved : { ...saved, name: x.req.name, spec: x.req.spec }, saved: snap(saved) })),
      );
      await loadTree();
    } catch (e) {
      fail(e);
    } finally {
      if (saving.current.get(id) === run) saving.current.delete(id);
    }
  };

  // The tab's own workspace, as it is now: a send can outlive a workspace switch
  // or an environment change (a resend runs after a prompt).
  const envOf = (wsId: string) => {
    const cur = wsRef.current;
    return (cur?.id === wsId ? cur : workspacesRef.current.find((w) => w.id === wsId))?.active_environment_id ?? null;
  };

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
    opening.current.add(execId);
    try {
      await api.sessionOpen({ workspace_id: t.wsId, request_id: t.req.id, spec: t.req.spec, environment_id: envOf(t.wsId), send_anyway: false }, execId);
    } catch (e) {
      opening.current.delete(execId);
      earlyAborts.current.delete(execId);
      // Only this open's session: the tab may hold a newer one by now.
      setTabs((ts) => ts.map((x) => (x.session?.execId === execId ? { ...x, session: null } : x)));
      if (!stopped.current.delete(execId)) fail(e);
      return;
    }
    opening.current.delete(execId);
    if (earlyAborts.current.delete(execId)) await cancelSession(execId);
  };

  const show = (v: View) => {
    setView(v);
    setMounted((m) => (m.has(v) ? m : new Set(m).add(v)));
    if (v !== "requests") void loadTree();
  };

  const cancel = async () => {
    if (tab?.execId) await api.cancel(tab.execId);
  };

  // Abort a session, or an open still connecting; an open it abandons is not an
  // error to report. The backend finds nothing to stop both for a session that
  // is already over (its end event is on the way) and for an open it has not
  // registered yet. The latter is canceled again once it opens (`connect`), or
  // right away if it opened while this cancel was on its way.
  const abortSession = async (sid: string, retry = true): Promise<void> => {
    const wasOpening = opening.current.has(sid);
    stopped.current.add(sid);
    try {
      await api.sessionCancel(sid);
    } catch (e) {
      if (String((e as Error).message ?? e) !== "the session is no longer open") {
        stopped.current.delete(sid);
        throw e;
      }
      if (!wasOpening) stopped.current.delete(sid);
      else if (opening.current.has(sid)) earlyAborts.current.add(sid);
      else if (retry) await abortSession(sid, false);
    }
  };

  // The session console's Cancel.
  const cancelSession = async (sid: string) => {
    try {
      await abortSession(sid);
    } catch (e) {
      fail(e);
    }
  };

  // Stop what a tab still runs in the backend: the tab is its only control, so
  // it must stay open when this fails. Returns whether nothing is left running.
  const stopWork = async (t: OpenTab, outcome = "so its tab stays open"): Promise<boolean> => {
    const sid = t.session?.execId;
    try {
      if (sid) await abortSession(sid);
      if (t.running && t.execId) await api.cancel(t.execId);
      return true;
    } catch (e) {
      notify(`Could not stop “${t.req.name}”, ${outcome}: ${String((e as Error).message ?? e)}`);
      return false;
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
    if (cur && !(await stopWork(cur))) return;
    setTabs((ts) => ts.filter((x) => x.req.id !== id));
    setActive((a) => (a === id ? (tabsRef.current.find((x) => x.req.id !== id && x.wsId === t.wsId)?.req.id ?? null) : a));
  };

  const removeNode = async (n: TreeNode) => {
    // The unfiltered node: a filtered folder may hide some of its requests.
    const ids = new Set(requestIds([findNode(tree, n.id) ?? n]));
    const affected = tabsRef.current.filter((t) => ids.has(t.req.id));
    const stop = affected.some((t) => liveWork(t)) ? " Its open session or request in flight will be stopped." : "";
    const dirty = affected.filter(isDirty).length;
    const edits = !dirty ? "" : n.kind === "request" ? " Its unsaved changes will be lost." : ` Unsaved changes in ${dirty} open tab(s) will be lost.`;
    const ok = await ask(n.kind === "folder" ? `Delete folder “${n.name}” and everything in it?${stop}${edits}` : `Delete “${n.name}”?${stop}${edits}`, { title: "Delete", kind: "warning", okLabel: "Delete" });
    if (!ok) return;
    try {
      // Stop first: a tab whose work could not be stopped stays, and so does its request.
      const gone = tabsRef.current.filter((t) => ids.has(t.req.id));
      const results = await Promise.all(gone.map((t) => stopWork(t, "so the delete was abandoned and its tab stays open")));
      if (results.includes(false)) return;
      if (n.kind === "folder") await api.deleteFolder(n.id);
      else await api.deleteRequest(n.id);
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
      } else if (mod && e.key.toLowerCase() === "b") {
        e.preventDefault();
        setSideCollapsed((c) => !c);
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
  const sidebar = useMemo(() => ({ resize: (d: number) => setSideW((w) => clamp(200, 520, w + d)) }), []);

  // ------------------------------------------------------------------ render
  return (
    <SidebarContext.Provider value={sidebar}>
      <div className={`shell${sideCollapsed ? " side-collapsed" : ""}`} style={{ ["--sidebar-w" as string]: `${sideW}px` }}>
        <header className="topbar">
          <button
            className="btn ghost icon-btn"
            aria-label={sideCollapsed ? "Show sidebar" : "Hide sidebar"}
            title={`${sideCollapsed ? "Show" : "Hide"} sidebar (${shortcut("B")})`}
            onClick={() => setSideCollapsed((c) => !c)}
          >
            <Icon name="sidebar" />
          </button>
          <div className="brand">
            <img className="brand-mark" src={mark} alt="" />
            <span className="brand-name">Anvil</span>
          </div>
          <span className="divider" />
          <div className="topbar-group">
            <div className="picker" title={ws ? `Workspace: ${ws.name}` : "Workspace"}>
              <Icon name="layers" size={15} />
              <select
                className="field"
                aria-label="Workspace"
                value={ws?.id ?? ""}
                onChange={async (e) => {
                  if (e.target.value === "__new") {
                    const w = await api.createWorkspace("New workspace");
                    await loadWorkspaces(w.id);
                    setDialog({ kind: "rename", id: w.id, isFolder: false, name: w.name });
                  } else {
                    const w = workspaces.find((x) => x.id === e.target.value);
                    if (w) setWs(w);
                  }
                }}
              >
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name + wsNote(tabs.filter((t) => t.wsId === w.id))}
                  </option>
                ))}
                <option value="__new">+ New workspace…</option>
              </select>
            </div>
            <button className="btn ghost icon-btn" aria-label="Workspace settings" title="Workspace auth, variables and settings" onClick={() => setDialog("workspace")}>
              <Icon name="sliders" />
            </button>
            <div className="picker" title={`Environment: ${activeEnv?.name ?? "none"}`}>
              <span className={`env-dot${activeEnv ? " on" : ""}`} />
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
            </div>
          </div>
          <span className="divider" />
          <div className="viewswitch" role="group" aria-label="View">
            <button aria-pressed={view === "requests"} aria-label="Requests" title="Requests" onClick={() => show("requests")}>
              <Icon name="send" size={14} />
              <span className="vs-label">Requests</span>
            </button>
            <button aria-pressed={view === "runner"} aria-label="Runner" title={liveRuns.runner ? "A run is in progress" : "Collection runner"} onClick={() => show("runner")}>
              <Icon name="listChecks" size={14} />
              <span className="vs-label">Runner</span>
              {liveRuns.runner && <span className="live-dot" data-testid="runner-live" />}
            </button>
            <button aria-pressed={view === "load"} aria-label="Load tests" title={liveRuns.load ? "A load run is in progress" : "Load tests"} onClick={() => show("load")}>
              <Icon name="zap" size={14} />
              <span className="vs-label">Load tests</span>
              {liveRuns.load && <span className="live-dot" data-testid="load-live" />}
            </button>
          </div>
          <span className="spacer" />
          <div className="topbar-group">
            <button className="btn ghost collapsible" title="Connection profiles: TLS, proxies and Ferrum gateways" aria-label="Profiles" onClick={() => setDialog("profiles")}>
              <Icon name="shield" />
              <span className="collapsible-label">Profiles</span>
            </button>
            <button className="btn ghost collapsible" title="Import a spec, collection or Anvil bundle" aria-label="Import" onClick={() => setDialog("import")}>
              <Icon name="download" />
              <span className="collapsible-label">Import</span>
            </button>
            <button className="btn ghost collapsible" title="Export a workspace or a full backup" aria-label="Export" onClick={() => setDialog("export")}>
              <Icon name="upload" />
              <span className="collapsible-label">Export</span>
            </button>
            <button className="btn ghost icon-btn" aria-label="Settings" title="Settings" onClick={() => setDialog("settings")}>
              <Icon name="gear" />
            </button>
          </div>
          <span className="divider" />
          <button className="btn" onClick={props.onLock} title={`Lock (${shortcut("L")})`}>
            <Icon name="lock" size={14} />
            Lock
          </button>
        </header>

        {mounted.has("load") && viewWs && (
          <LoadView
            workspaceId={viewWs.id}
            tree={tree}
            environments={envs}
            notify={notify}
            hidden={view !== "load"}
            onLiveChange={(load) => setLiveRuns((l) => ({ ...l, load }))}
          />
        )}
        {mounted.has("runner") && viewWs && (
          <RunnerView
            workspaceId={viewWs.id}
            tree={tree}
            environments={envs}
            activeEnvironment={viewWs.active_environment_id ?? null}
            notify={notify}
            hidden={view !== "runner"}
            onLiveChange={(runner) => setLiveRuns((l) => ({ ...l, runner }))}
          />
        )}
        <div className="main" style={{ display: view === "requests" ? undefined : "none" }}>
          <aside className="sidebar" aria-label="Collections and history">
            <div className="side-tabs" role="tablist">
              <button className="side-tab" role="tab" aria-selected={side === "tree"} onClick={() => setSide("tree")}>
                <Icon name="layers" size={14} />
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
                <Icon name="history" size={14} />
                History
              </button>
            </div>
            {side === "tree" && (
              <>
                <div className="side-toolbar">
                  <div className="search">
                    <Icon name="search" size={14} />
                    <input className="field" placeholder="Filter requests" aria-label="Filter requests" value={filter} onChange={(e) => setFilter(e.target.value)} />
                  </div>
                  <button className="btn ghost icon-btn" title={`New request (${shortcut("N")})`} aria-label="New request" onClick={() => newRequest(null)}>
                    <Icon name="plus" />
                  </button>
                  <button className="btn ghost icon-btn" title="New folder" aria-label="New folder" onClick={() => newFolder(null)}>
                    <Icon name="folderPlus" />
                  </button>
                </div>
                <div className="side-body" onDragOver={(e) => e.preventDefault()} onDrop={(e) => onDropTo(e, null, moveInto)}>
                  {treeWs !== ws?.id ? (
                    <div className="side-empty">Loading…</div>
                  ) : (
                    filtered.length === 0 && <div className="side-empty">{filter ? "No requests match this filter." : "No requests yet. Create one, or import a spec or bundle."}</div>
                  )}
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
              </>
            )}
            {side === "history" && (
              <div className="side-body">
                {history.length === 0 && <div className="side-empty">No history yet. Every send is recorded here, encrypted.</div>}
                {history.map((h) => (
                  <div
                    key={h.id}
                    className="hist-row"
                    role="button"
                    tabIndex={0}
                    title={`${h.method} ${h.url}\n${h.summary}`}
                    onClick={async () => setDialog({ kind: "history", view: await api.historyGet(h.id) })}
                    onKeyDown={async (e) => e.key === "Enter" && setDialog({ kind: "history", view: await api.historyGet(h.id) })}
                  >
                    <div className="hist-line">
                      <span className={`method m-${h.method}`}>{h.method}</span>
                      <span className="hist-url">{h.url}</span>
                    </div>
                    <div className="hist-line">
                      <span className={`status-pill s${String(h.status ?? 5)[0]}`}>{h.status ?? "—"}</span>
                      <span className="hist-meta">{h.summary}</span>
                      <span className="hist-when" title={new Date(h.started_at).toLocaleString()}>
                        {fmtAgo(h.started_at)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </aside>
          <SidebarResizer />
          <section className="work">
            <nav className="tabbar" aria-label="Open requests">
              <div className="tabs-scroll" role="tablist" aria-label="Open requests">
                {wsTabs.map((t) => {
                  const dirty = isDirty(t);
                  return (
                    <div
                      key={t.req.id}
                      className="tab"
                      role="tab"
                      aria-selected={t.req.id === active}
                      title={t.req.spec.url ? `${t.req.name}\n${t.req.spec.url}` : t.req.name}
                      onClick={() => setActive(t.req.id)}
                      onAuxClick={(e) => e.button === 1 && closeTab(t.req.id)}
                    >
                      <RequestTag protocol={t.req.spec.protocol} method={t.req.spec.method} />
                      <span className="name">{t.req.name}</span>
                      {t.session && <span className="live-dot tab-live" role="img" aria-label="live session" title="Live session" />}
                      <span className={`tab-end${dirty ? " is-dirty" : ""}`}>
                        {dirty && <span className="dirty" aria-label="unsaved" />}
                        <button
                          className="btn ghost xs icon-btn"
                          aria-label={`Close ${t.req.name}`}
                          title="Close"
                          onClick={(e) => {
                            e.stopPropagation();
                            void closeTab(t.req.id);
                          }}
                        >
                          <Icon name="x" size={12} strokeWidth={2.2} />
                        </button>
                      </span>
                    </div>
                  );
                })}
              </div>
              <div className="tabbar-actions">
                <button className="btn ghost small icon-btn" title="New request" aria-label="New request tab" onClick={() => newRequest(null)}>
                  <Icon name="plus" size={15} />
                </button>
                <button
                  className={`btn ghost small icon-btn${layout === "side" ? " active" : ""}`}
                  aria-pressed={layout === "side"}
                  aria-label="Side-by-side layout"
                  title={
                    layout === "side"
                      ? "Stack the request above the response"
                      : `Show the request and response side by side${editorWide ? "" : " (when the window is wide enough)"}`
                  }
                  onClick={toggleLayout}
                >
                  <Icon name="splitColumns" size={15} />
                </button>
              </div>
            </nav>
            {tab && ws ? (
              <div
                ref={editorRef}
                className={`editor${sideBySide ? " side" : ""}`}
                style={{ ["--req-h" as string]: `${reqHeight}%`, ["--req-w" as string]: `${reqWidth}%` }}
              >
                <div className="req-parts">
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
                    dirty={isDirty(tab)}
                    workspaceId={ws.id}
                    environmentId={ws.active_environment_id ?? null}
                    profiles={profiles}
                  />
                </div>
                <div
                  className="hsplit"
                  role="separator"
                  aria-orientation={sideBySide ? "vertical" : "horizontal"}
                  aria-label="Resize request and response"
                  onMouseDown={(e) => {
                    const host = (e.currentTarget.parentElement as HTMLElement).getBoundingClientRect();
                    if (sideBySide) {
                      drag(e, "x", (_d, ev) => setReqWidth(clamp(25, 75, ((ev.clientX - host.left) / host.width) * 100)));
                    } else {
                      const pane = (e.currentTarget.parentElement as HTMLElement).querySelector(":scope > .req-parts > .pane");
                      const top = pane?.getBoundingClientRect().top ?? host.top + 96;
                      drag(e, "y", (_d, ev) => setReqHeight(clamp(10, 80, ((ev.clientY - top) / host.height) * 100)));
                    }
                  }}
                />
                {tab.session ? (
                  <SessionConsole
                    protocol={tab.req.spec.protocol ?? "http"}
                    messages={tab.session.messages}
                    onSend={(c) => api.sessionSend(tab.session!.execId, c)}
                    onCancel={() => void cancelSession(tab.session!.execId)}
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
                  <div className="sub">Open a request from the sidebar, or start a new one.</div>
                  <button className="btn primary" onClick={() => newRequest(null)}>
                    <Icon name="plus" size={15} />
                    New request
                  </button>
                  <div className="keys">
                    <span>
                      <Keys k="N" /> new
                    </span>
                    <span>
                      <Keys k="Enter" /> send
                    </span>
                    <span>
                      <Keys k="S" /> save
                    </span>
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>

        <footer className="statusbar">
          <span title="Local profile">
            <Icon name="lock" size={12} />
            Profile: {props.profileName}
          </span>
          <span>
            <span className={`dot${activeEnv ? " on" : ""}`} />
            Environment: {activeEnv?.name ?? "none"}
          </span>
          <span className="spacer" />
          <span className="local">
            <Icon name="shield" size={12} />
            Local-only · no account
          </span>
          <span className="catalog-wrap" title={`Diagnostics catalog ${catalog}`}>
            <span className="catalog">Diagnostics catalog {catalog}</span>
          </span>
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
                  if (!open) {
                    await api.saveRequest({ ...(await api.getRequest(dialog.id)), name });
                  } else {
                    const baseline = JSON.parse(open.saved) as {
                      n: string;
                      s: RequestDefinition["spec"];
                    };
                    const prior = saving.current.get(open.req.id);
                    const run = (prior ?? Promise.resolve(undefined))
                      .catch(() => undefined)
                      .then((lastSaved) => {
                        const current = tabsRef.current.find((t) => t.req.id === open.req.id);
                        const source = lastSaved ?? current?.req ?? open.req;
                        return api.saveRequest({
                          ...source,
                          name,
                          spec: lastSaved?.spec ?? baseline.s,
                        });
                      });
                    saving.current.set(open.req.id, run);
                    try {
                      const saved = await run;
                      setTabs((ts) =>
                        ts.map((t) =>
                          t.req.id === saved.id
                            ? { ...t, req: { ...saved, spec: t.req.spec }, saved: snap(saved) }
                            : t,
                        ),
                      );
                    } finally {
                      if (saving.current.get(open.req.id) === run) saving.current.delete(open.req.id);
                    }
                  }
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
          <Modal
            title={`${dialog.view.record.prepared.method} ${dialog.view.record.prepared.url}`}
            wide
            onClose={() => setDialog(null)}
            footer={
              dialog.view.record.request_id ? (
                <button
                  className="btn"
                  onClick={() => {
                    const rid = dialog.view.record.request_id!;
                    setDialog(null);
                    void openRequest(rid).catch(() => notify("That saved request no longer exists."));
                  }}
                >
                  <Icon name="file" size={14} />
                  Open the saved request
                </button>
              ) : undefined
            }
          >
            <div className="history-view">
              <ResponsePanel view={dialog.view} running={false} progressBytes={null} onCancel={() => {}} />
            </div>
          </Modal>
        )}
        <Toast message={toast} onClose={() => setToast(null)} />
      </div>
    </SidebarContext.Provider>
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

const PROTOCOL_TAGS: Partial<Record<Protocol, string>> = { web_socket: "WS", grpc: "gRPC", sse: "SSE", tcp: "TCP", udp: "UDP" };

function protoShort(p: string) {
  return PROTOCOL_TAGS[p as Protocol] ?? p.toUpperCase();
}

/** The method of an HTTP request, or the short name of any other protocol. */
function RequestTag(props: { protocol?: Protocol | null; method?: string | null }) {
  const label = (props.protocol ?? "http") === "http" ? (props.method ?? "GET") : protoShort(props.protocol!);
  return <span className={`method m-${label}`}>{label}</span>;
}

function RenameDialog(props: { name: string; onClose: () => void; onSave: (n: string) => void }) {
  const [n, setN] = useState(props.name);
  return (
    <Modal
      title="Rename"
      onClose={props.onClose}
      footer={
        <>
          <button className="btn" onClick={props.onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!n.trim()} onClick={() => props.onSave(n.trim())}>
            Save
          </button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (n.trim()) props.onSave(n.trim());
        }}
      >
        <input className="field full" aria-label="Name" value={n} onChange={(e) => setN(e.target.value)} onFocus={(e) => e.target.select()} />
      </form>
    </Modal>
  );
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
  const nested = props.depth > 0;
  return (
    <div role={nested ? "group" : "tree"} className={nested ? "tree-group" : undefined} style={nested ? { ["--depth" as string]: props.depth } : undefined}>
      {props.nodes.map((n) => {
        const isOpen = props.expanded.has(n.id);
        const folder = n.kind === "folder";
        return (
          <div key={n.id}>
            <div
              className={`tree-row${folder ? " folder" : ""}${props.activeId === n.id ? " selected" : ""}${over === n.id ? " drop-target" : ""}`}
              role="treeitem"
              aria-expanded={folder ? isOpen : undefined}
              aria-selected={props.activeId === n.id}
              tabIndex={0}
              title={folder ? n.name : n.url ? `${n.name}\n${n.url}` : n.name}
              style={{ paddingLeft: 6 + props.depth * 14 }}
              draggable
              onDragStart={(e) => e.dataTransfer.setData("application/x-anvil-node", JSON.stringify({ id: n.id, kind: n.kind }))}
              onDragOver={(e) => {
                if (folder) {
                  e.preventDefault();
                  setOver(n.id);
                }
              }}
              onDragLeave={() => setOver(null)}
              onDrop={(e) => {
                setOver(null);
                if (folder) onDropTo(e, n.id, props.onMove);
              }}
              onClick={() => (folder ? props.onToggle(n.id) : props.onOpen(n.id))}
              onKeyDown={(e) => {
                if (e.key === "Enter") folder ? props.onToggle(n.id) : props.onOpen(n.id);
                if (e.key === "F2") props.onRename(n);
                if (e.key === "Delete" || e.key === "Backspace") props.onDelete(n);
              }}
            >
              {folder ? (
                <>
                  <span className="caret">
                    <Icon name="chevronRight" size={12} strokeWidth={2.2} />
                  </span>
                  <Icon name={isOpen ? "folderOpen" : "folder"} size={15} className="folder-icon" />
                </>
              ) : (
                <RequestTag protocol={n.protocol} method={n.method} />
              )}
              <span className="name">{n.name}</span>
              <span className="actions" onClick={(e) => e.stopPropagation()}>
                {folder && (
                  <>
                    <button className="btn ghost xs icon-btn" title="New request here" aria-label="New request in folder" onClick={() => props.onNewRequest(n.id)}>
                      <Icon name="plus" size={14} />
                    </button>
                    <button className="btn ghost xs icon-btn" title="New subfolder" aria-label="New subfolder" onClick={() => props.onNewFolder(n.id)}>
                      <Icon name="folderPlus" size={14} />
                    </button>
                    <button className="btn ghost xs icon-btn" title="Folder auth, variables and settings" aria-label="Folder settings" onClick={() => props.onFolderSettings(n.id)}>
                      <Icon name="sliders" size={14} />
                    </button>
                  </>
                )}
                {!folder && (
                  <button className="btn ghost xs icon-btn" title="Duplicate" aria-label="Duplicate" onClick={() => props.onDuplicate(n)}>
                    <Icon name="copy" size={14} />
                  </button>
                )}
                <button className="btn ghost xs icon-btn" title="Rename (F2)" aria-label="Rename" onClick={() => props.onRename(n)}>
                  <Icon name="pencil" size={14} />
                </button>
                <button className="btn ghost xs icon-btn danger" title="Delete" aria-label="Delete" onClick={() => props.onDelete(n)}>
                  <Icon name="trash" size={14} />
                </button>
              </span>
            </div>
            {folder && isOpen && <Tree {...props} nodes={n.children} depth={props.depth + 1} />}
          </div>
        );
      })}
    </div>
  );
}
