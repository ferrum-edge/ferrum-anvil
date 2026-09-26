// Renderer tests for Workbench state that must survive navigation (jsdom; the
// Tauri backend is a scripted fake). Switching workspaces keeps unsaved drafts
// and live sessions; Runner and Load tests keep a backend run's Stop control
// while another view is shown; closing or deleting a tab stops (after
// confirmation) what only that tab controlled, and a tab whose work could not
// be stopped stays open.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { vi } from "vitest";

const { invoke, ask, handlers } = vi.hoisted(() => ({
  invoke: vi.fn(),
  ask: vi.fn(),
  handlers: new Map<string, Set<(ev: { payload: unknown }) => void>>(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: async (name: string, cb: (ev: { payload: unknown }) => void) => {
    const set = handlers.get(name) ?? new Set();
    handlers.set(name, set);
    set.add(cb);
    return () => set.delete(cb);
  },
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: (...a: unknown[]) => ask(...a), open: vi.fn(), save: vi.fn() }));

import type { TreeNode } from "./api";
import type { LoadPlan, RequestDefinition, RequestSpec, Workspace } from "./generated/contracts";
import { newSpec } from "./RequestEditor";
import { Workbench } from "./Workbench";

// SessionConsole scrolls its message list; jsdom has no element scrolling.
Element.prototype.scrollTo = () => {};

const now = "2026-01-01T00:00:00Z";
const workspace = (id: string, name: string) => ({ id, name, schema_version: 1, created_at: now, updated_at: now }) as Workspace;
const request = (id: string, wsId: string, name: string, spec: Partial<RequestSpec> = {}): RequestDefinition =>
  ({ id, workspace_id: wsId, name, schema_version: 1, created_at: now, updated_at: now, sort_key: 0, spec: { ...newSpec(), url: `https://${id}.test/`, ...spec } }) as RequestDefinition;
const node = (r: RequestDefinition): TreeNode => ({ id: r.id, kind: "request", name: r.name, method: "GET", url: r.spec.url, favorite: false, children: [] });

const plan: LoadPlan = {
  id: "plan-1",
  workspace_id: "A",
  name: "Plan A",
  workload: { model: "closed_virtual_users", stages: [{ duration_secs: 30, target: 10 }], think_time_ms: 0 },
  chain: [],
  mix: [],
  connection_mode: "persistent",
  warmup_secs: 0,
  seed: 1,
  trusted: true,
  created_at: now,
  updated_at: now,
} as LoadPlan;

let requests: Record<string, RequestDefinition>;
// The fake's sessions, as the backend tracks them: an open still connecting
// (its `session_open` call pending) and sessions that finished opening.
let connecting: Map<string, (err: string) => void>;
let openSessions: Set<string>;

function backend(overrides: Record<string, (args: Record<string, unknown>) => unknown> = {}) {
  requests = {
    r1: request("r1", "A", "Alpha"),
    r2: request("r2", "A", "Beta"),
    r3: request("r3", "B", "Gamma"),
    s1: request("s1", "A", "Socket", { protocol: "web_socket", url: "wss://s1.test/" }),
  };
  connecting = new Map();
  openSessions = new Set();
  invoke.mockImplementation(async (cmd: string, args: Record<string, unknown> = {}) => {
    if (overrides[cmd]) return overrides[cmd](args);
    switch (cmd) {
      case "workspaces_list":
        return [workspace("A", "One"), workspace("B", "Two")];
      case "system_info":
        return { catalog: "test" };
      case "settings_get":
        return { theme: "dark" };
      case "tree_get":
        return Object.values(requests)
          .filter((r) => r.workspace_id === args.workspaceId)
          .map(node);
      case "request_get":
        return requests[args.requestId as string];
      case "history_list":
      case "tls_profiles_list":
      case "proxy_profiles_list":
      case "integrations_list":
      case "environments_list":
      case "scenarios_list":
      case "run_reports":
      case "load_reports":
      case "datasets_list":
        return [];
      case "load_plans":
        return [plan];
      case "session_open":
        // Stays connecting until the test opens it or it is canceled.
        return new Promise((_resolve, reject) => connecting.set(args.executionId as string, reject));
      case "session_cancel": {
        // Like the backend: canceling an open still connecting fails that open.
        const id = args.executionId as string;
        const pending = connecting.get(id);
        if (pending) {
          connecting.delete(id);
          pending("the session was canceled before it opened");
        } else if (!openSessions.delete(id)) throw "the session is no longer open";
        return null;
      }
      case "cancel_execution":
        return true;
      default:
        // Anything else (effective request, reports, …) stays pending: it is not under test.
        return new Promise(() => {});
    }
  });
}

const calls = (cmd: string) => invoke.mock.calls.filter((c) => c[0] === cmd).map((c) => c[1] as Record<string, unknown>);
const emit = (name: string, payload: unknown) => act(() => handlers.get(name)?.forEach((cb) => cb({ payload })));

async function boot() {
  render(<Workbench onLock={() => {}} profileName="test" />);
  await screen.findByRole("treeitem", { name: /Alpha/ });
}

// The open request tabs (the request editor has sub-tabs of its own, e.g. "WebSocket").
const openTabs = () => within(screen.getByRole("tablist", { name: "Open requests" }));

async function openTab(name: string) {
  fireEvent.click(screen.getByRole("treeitem", { name: new RegExp(name) }));
  await openTabs().findByRole("tab", { name: new RegExp(name) });
}

async function selectWorkspace(id: string, expectItem: string) {
  fireEvent.change(screen.getByLabelText("Workspace"), { target: { value: id } });
  await screen.findByRole("treeitem", { name: new RegExp(expectItem) });
}

const urlField = () => screen.getByLabelText("URL") as HTMLInputElement;

afterEach(() => {
  cleanup();
  invoke.mockReset();
  ask.mockReset();
  handlers.clear();
});

describe("switching workspaces", () => {
  it("keeps every unsaved draft and restores it on return, without saving or prompting", async () => {
    backend();
    await boot();
    await openTab("Alpha");
    fireEvent.change(urlField(), { target: { value: "https://alpha-edited.test/" } });
    await openTab("Beta");
    fireEvent.change(urlField(), { target: { value: "https://beta-edited.test/" } });
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(2);

    await selectWorkspace("B", "Gamma");
    expect(openTabs().queryByRole("tab", { name: /Alpha/ })).toBeNull();
    expect(openTabs().queryByRole("tab", { name: /Beta/ })).toBeNull();
    expect(screen.getByRole("option", { name: /One/ }).textContent).toContain("2 unsaved");
    await openTab("Gamma");

    await selectWorkspace("A", "Alpha");
    expect(openTabs().queryByRole("tab", { name: /Gamma/ })).toBeNull();
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(2);
    // The tab that was active in this workspace is active again.
    expect(urlField().value).toBe("https://beta-edited.test/");
    fireEvent.click(openTabs().getByRole("tab", { name: /Alpha/ }));
    await waitFor(() => expect(urlField().value).toBe("https://alpha-edited.test/"));

    await selectWorkspace("B", "Gamma");
    expect(openTabs().getByRole("tab", { name: /Gamma/ })).toBeTruthy();
    expect(calls("request_save")).toHaveLength(0);
    expect(ask).not.toHaveBeenCalled();
  });

  it("leaves a connected session running and reachable in its workspace", async () => {
    backend();
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    const execId = calls("session_open")[0].executionId;

    await selectWorkspace("B", "Gamma");
    expect(screen.getByRole("option", { name: /One/ }).textContent).toContain("1 live");
    await selectWorkspace("A", "Alpha");
    expect(screen.getByRole("button", { name: "Connected" })).toBeTruthy();
    expect(calls("session_cancel")).toHaveLength(0);

    // The session ending while its workspace is hidden still clears it.
    await selectWorkspace("B", "Gamma");
    emit("session-ended", { execution_id: execId });
    await selectWorkspace("A", "Alpha");
    expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
    expect(screen.getByRole("option", { name: /One/ }).textContent).not.toContain("live");
  });
});

describe("closing a tab with backend work", () => {
  it("asks before disconnecting a session, and Keep open leaves it connected", async () => {
    backend();
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    const execId = calls("session_open")[0].executionId;

    ask.mockResolvedValueOnce(false);
    fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
    await waitFor(() => expect(ask).toHaveBeenCalledTimes(1));
    expect(ask.mock.calls[0][0]).toContain("open session");
    expect(openTabs().getByRole("tab", { name: /Socket/ })).toBeTruthy();
    expect(calls("session_cancel")).toHaveLength(0);

    ask.mockResolvedValueOnce(true);
    fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
    await waitFor(() => expect(calls("session_cancel")).toEqual([{ executionId: execId }]));
    await waitFor(() => expect(openTabs().queryByRole("tab", { name: /Socket/ })).toBeNull());
    // The open was still connecting: canceling it leaves no session behind, and
    // its failed open is not reported as an error.
    expect(connecting.size).toBe(0);
    expect(openSessions.size).toBe(0);
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("disconnects a session that finished opening", async () => {
    backend();
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    const execId = calls("session_open")[0].executionId as string;
    connecting.delete(execId);
    openSessions.add(execId);

    ask.mockResolvedValueOnce(true);
    fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
    await waitFor(() => expect(calls("session_cancel")).toEqual([{ executionId: execId }]));
    await waitFor(() => expect(openTabs().queryByRole("tab", { name: /Socket/ })).toBeNull());
    expect(openSessions.size).toBe(0);
  });

  it("keeps the tab, and the request, when its session cannot be stopped", async () => {
    backend({
      session_cancel: () => {
        throw "backend unavailable";
      },
      request_delete: (a) => void delete requests[a.requestId as string],
    });
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));

    ask.mockResolvedValueOnce(true);
    fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
    expect((await screen.findByRole("status")).textContent).toContain("Could not stop “Socket”");
    expect(openTabs().getByRole("tab", { name: /Socket/ })).toBeTruthy();

    ask.mockResolvedValueOnce(true);
    fireEvent.click(within(screen.getByRole("treeitem", { name: /Socket/ })).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(calls("session_cancel")).toHaveLength(2));
    expect(calls("request_delete")).toHaveLength(0);
    expect(openTabs().getByRole("tab", { name: /Socket/ })).toBeTruthy();
    expect(screen.getByRole("treeitem", { name: /Socket/ })).toBeTruthy();
  });

  it("cancels a request in flight when its tab is closed", async () => {
    backend();
    await boot();
    await openTab("Alpha");
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(calls("send_request")).toHaveLength(1));
    const execId = calls("send_request")[0].executionId;

    ask.mockResolvedValueOnce(true);
    fireEvent.click(screen.getByRole("button", { name: "Close Alpha" }));
    await waitFor(() => expect(calls("cancel_execution")).toEqual([{ executionId: execId }]));
    expect(ask.mock.calls[0][0]).toContain("in flight");
    await waitFor(() => expect(openTabs().queryByRole("tab", { name: /Alpha/ })).toBeNull());
  });

  it("stops a live session when its request is deleted", async () => {
    backend({ request_delete: (a) => void delete requests[a.requestId as string] });
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    const execId = calls("session_open")[0].executionId;

    ask.mockResolvedValueOnce(true);
    fireEvent.click(within(screen.getByRole("treeitem", { name: /Socket/ })).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(calls("session_cancel")).toEqual([{ executionId: execId }]));
    expect(ask.mock.calls[0][0]).toContain("will be stopped");
    await waitFor(() => expect(calls("request_delete")).toEqual([{ requestId: "s1" }]));
    await waitFor(() => expect(openTabs().queryByRole("tab", { name: /Socket/ })).toBeNull());
    expect(connecting.size).toBe(0);
  });

  it("warns about unsaved edits when deleting an open request", async () => {
    backend();
    await boot();
    await openTab("Alpha");
    fireEvent.change(urlField(), { target: { value: "https://alpha-edited.test/" } });

    ask.mockResolvedValueOnce(false);
    fireEvent.click(within(screen.getByRole("treeitem", { name: /Alpha/ })).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(ask).toHaveBeenCalledTimes(1));
    expect(ask.mock.calls[0][0]).toContain("unsaved changes will be lost");
    expect(calls("request_delete")).toHaveLength(0);
  });
});

describe("Runner and Load tests keep their runs across navigation", () => {
  it("restores the runner's Stop control after visiting Requests", async () => {
    backend({ run_start: () => "run-1", run_cancel: () => true });
    await boot();
    fireEvent.click(screen.getByRole("button", { name: "Runner" }));
    fireEvent.click(await screen.findByRole("button", { name: "Run folder" }));
    await screen.findByRole("button", { name: "Stop run" });

    fireEvent.click(screen.getByRole("button", { name: "Requests" }));
    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
    expect(screen.getByTestId("runner-live")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Runner" }));
    expect((screen.getByRole("button", { name: "Run folder" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Stop run" }));
    await waitFor(() => expect(calls("run_cancel")).toEqual([{ runId: "run-1" }]));
  });

  it("notices a run that finishes while the runner is hidden", async () => {
    backend({ run_start: () => "run-1" });
    await boot();
    fireEvent.click(screen.getByRole("button", { name: "Runner" }));
    fireEvent.click(await screen.findByRole("button", { name: "Run folder" }));
    await screen.findByRole("button", { name: "Stop run" });
    fireEvent.click(screen.getByRole("button", { name: "Requests" }));

    emit("run-finished", { run_id: "run-1" });
    await waitFor(() => expect(screen.queryByTestId("runner-live")).toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Runner" }));
    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
    expect((screen.getByRole("button", { name: "Run folder" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("restores a load run's Stop control, and notices it finish while hidden", async () => {
    backend({
      load_plan_save: () => plan,
      load_preflight: () => ({
        destinations: ["https://r1.test/"],
        workload: "10 virtual users",
        max_duration_secs: 30,
        peak_target: 10,
        trusted: true,
        warnings: [],
        unit: "http_request",
        unit_label: "HTTP requests",
        semantics: { unit_singular: "request", unit_plural: "requests", completed_means: "a response arrived", success_means: "", latency_means: "", connection_mode_means: "" },
      }),
      load_run_start: () => "key-1",
      load_run_cancel: () => true,
    });
    await boot();
    fireEvent.click(screen.getByRole("button", { name: "Load tests" }));
    fireEvent.click(await screen.findByText("Plan A"));
    fireEvent.click(await screen.findByRole("button", { name: "Run…" }));
    fireEvent.click(await screen.findByLabelText(/I own these destinations/));
    fireEvent.click(screen.getByRole("button", { name: "Start load" }));
    await screen.findByRole("button", { name: "Stop run" });

    fireEvent.click(screen.getByRole("button", { name: "Requests" }));
    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
    expect(screen.getByTestId("load-live")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Load tests" }));
    fireEvent.click(screen.getByRole("button", { name: "Stop run" }));
    await waitFor(() => expect(calls("load_run_cancel")).toEqual([{ runKey: "key-1" }]));

    fireEvent.click(screen.getByRole("button", { name: "Requests" }));
    emit("load-finished", { run_key: "key-1", run_id: null });
    await waitFor(() => expect(screen.queryByTestId("load-live")).toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Load tests" }));
    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
  });
});
