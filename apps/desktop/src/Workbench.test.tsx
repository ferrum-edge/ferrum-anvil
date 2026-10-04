// Renderer tests for Workbench state that must survive navigation (jsdom; the
// Tauri backend is a scripted fake). Switching workspaces keeps unsaved drafts
// and live sessions, and a workspace's late reads never replace the lists of the
// one selected since; a save that finishes late keeps the edits made meanwhile; Runner and Load tests keep a backend run's Stop control
// while another view is shown; closing or deleting a tab stops (after
// confirmation) what only that tab controlled, and a tab whose work could not
// be stopped stays open. Relocating a linked file reloads the saved request
// into its tab's draft, once the user confirms discarding unsaved edits.
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

import type { ExecutionView, NativeExecutionEvent, StreamMessage, TreeNode } from "./api";
import type { Environment, LoadPlan, RequestDefinition, RequestSpec, TlsProfile, Workspace } from "./generated/contracts";
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
const cancelArgs = (openIndex = 0) => {
  const { executionId, attemptId } = calls("session_open")[openIndex];
  return { executionId, attemptId };
};

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

// A backend reply the test completes by hand.
function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}
const environment = (id: string, wsId: string, name: string) => ({ id, workspace_id: wsId, name, schema_version: 1, created_at: now, updated_at: now }) as Environment;
const tlsProfile = (id: string, wsId: string, name: string) => ({ id, workspace_id: wsId, name }) as TlsProfile;
const historyItem = (id: string, url: string) => ({ id, started_at: 0, method: "GET", url, summary: "200 OK", status: 200 });

function sessionView(text: string): ExecutionView {
  return {
    record: {
      id: "00000000-0000-7000-8000-000000000001",
      schema_version: 1,
      adapter_version: "test",
      catalog_version: "test",
      started_at: now,
      finished_at: now,
      prepared: {
        protocol: "web_socket",
        method: "GET",
        url: "wss://s1.test/",
        headers: [],
        body_bytes: 0,
        auth_label: "none",
        tls_verification_enabled: true,
        settings: {
          http_version: "auto",
          timeouts: {},
          redirects: { follow: false, max: 0, forward_credentials_cross_origin: false },
          retries: { max_retries: 0, backoff_ms: 0, only_safe: true },
          ip_preference: "system",
          resolver: { mode: "system" },
          dns_overrides: [],
          limits: {
            max_response_bytes: 1_048_576,
            capture_bytes: 1_048_576,
            max_decoded_bytes: 4_194_304,
            max_response_header_bytes: 65_536,
            max_request_body_bytes: 1_048_576,
          },
          decompress: true,
          cookies: true,
          keepalive: true,
          infer_content_type: true,
          early_data: { enabled: false },
          sources: [],
        },
        inferred: [],
        omitted_secrets: [],
      },
      attempts: [],
      response: {
        status: 101,
        http_version: "HTTP/1.1",
        headers: [],
        trailers: [],
        trailers_received: false,
        body: {
          completeness: "complete",
          wire_bytes: text.length,
          captured_bytes: text.length,
          display_truncated: false,
          content_type: "text/plain",
        },
      },
      outcome: {
        transport: "completed",
        application: "success",
        assertions: "not_run",
        protocol_status: { protocol: "none" },
        dispatch: "sent",
        warnings: [],
        summary: "Session completed",
      },
      assertion_results: [],
      extracted: [],
      findings: [],
    },
    body: {
      text,
      pretty: null,
      hex: null,
      is_binary: false,
      decoded: false,
      shown_bytes: text.length,
      captured_bytes: text.length,
    },
  };
}

function sessionMessage(preview: string): StreamMessage {
  return {
    direction: "received",
    offset_us: 1,
    kind: "text",
    size: preview.length,
    preview,
    preview_is_hex: false,
    preview_truncated: false,
  };
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
  ask.mockReset();
  handlers.clear();
  vi.restoreAllMocks();
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
    emit("session-ended", { execution_id: execId, attempt_id: calls("session_open")[0].attemptId });
    await selectWorkspace("A", "Alpha");
    expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
    expect(screen.getByRole("option", { name: /One/ }).textContent).not.toContain("live");
  });
});

describe("session controls", () => {
  it.each(["text", "close", "half-close"])(
    "keeps an old console's %s bound to its attempt after native retirement and ID reuse",
    async (action) => {
      const owners = new Map<string, string>();
      const effects: unknown[] = [];
      backend({
        session_open: ({ executionId, attemptId }) => {
          if (typeof executionId !== "string" || typeof attemptId !== "string") {
            throw new Error("missing session identity");
          }
          if (owners.has(executionId)) throw new Error("duplicate execution ID");
          owners.set(executionId, attemptId);
          return executionId;
        },
        session_send: ({ executionId, attemptId, command }) => {
          if (typeof executionId !== "string" || owners.get(executionId) !== attemptId) {
            throw new Error("the session is no longer open");
          }
          effects.push(command);
          return null;
        },
      });
      requests.s1 = request("s1", "A", "Socket", { protocol: "tcp" });
      requests.s2 = request("s2", "A", "Peer", { protocol: "tcp" });
      await boot();
      await openTab("Socket");
      const executionId = "00000000-0000-7000-8000-000000000060";
      const oldAttempt = "00000000-0000-7000-8000-000000000061";
      const newAttempt = "00000000-0000-7000-8000-000000000062";
      const ids = vi.spyOn(crypto, "randomUUID");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(oldAttempt);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(calls("session_open")).toHaveLength(1));
      await act(async () => {});
      // Native retires A before history finalization/completion. Its actual
      // console remains mounted in the tab; no IPC admission reordering is used.
      owners.delete(executionId);
      await openTab("Peer");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(newAttempt);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(calls("session_open")).toHaveLength(2));
      await act(async () => {});
      fireEvent.click(openTabs().getByRole("tab", { name: /Socket/ }));
      const command =
        action === "text"
          ? { command: "send_text", text: "console payload" }
          : action === "close"
            ? { command: "close", code: 1000, reason: "" }
            : { command: "half_close" };
      const send = () => {
        if (action === "text") {
          fireEvent.change(screen.getByLabelText("Message"), { target: { value: "console payload" } });
          fireEvent.click(screen.getByRole("button", { name: "Send" }));
        } else {
          const name = action === "close" ? "Close" : "Half-close";
          fireEvent.click(screen.getByRole("button", { name }));
        }
      };
      send();
      await screen.findByText("the session is no longer open");
      expect(calls("session_send")).toEqual([{ executionId, attemptId: oldAttempt, command }]);
      expect(effects).toEqual([]);
      expect(owners.get(executionId)).toBe(newAttempt);
      fireEvent.click(openTabs().getByRole("tab", { name: /Peer/ }));
      send();
      await waitFor(() => expect(effects).toEqual([command]));
      expect(calls("session_send")).toEqual([
        { executionId, attemptId: oldAttempt, command },
        { executionId, attemptId: newAttempt, command },
      ]);
    },
  );

  it.each(["full", "scalar"])(
    "keeps the original %s completion owner after a duplicate open is rejected",
    async (completion) => {
      const owners = new Map<string, string>();
      backend({
        session_open: ({ executionId, attemptId }) => {
          if (typeof executionId !== "string" || typeof attemptId !== "string") {
            throw new Error("missing session identity");
          }
          if (owners.has(executionId)) throw `attempt ${executionId} is already running`;
          owners.set(executionId, attemptId);
          return executionId;
        },
        session_send: () => null,
      });
      requests.s2 = request("s2", "A", "Peer", { protocol: "web_socket" });
      await boot();
      await openTab("Socket");
      const executionId = "00000000-0000-7000-8000-000000000020";
      const original = "00000000-0000-7000-8000-000000000021";
      const duplicate = "00000000-0000-7000-8000-000000000022";
      const ids = vi.spyOn(crypto, "randomUUID");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(original);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(calls("session_open")).toHaveLength(1));
      await openTab("Peer");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(duplicate);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      expect((await screen.findByRole("status")).textContent).toContain("is already running");
      expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
      expect(owners.get(executionId)).toBe(original);
      fireEvent.click(openTabs().getByRole("tab", { name: /Socket/ }));
      expect(screen.getByRole("button", { name: "Connected" })).toBeTruthy();
      fireEvent.click(screen.getByRole("button", { name: "Ping" }));
      await waitFor(() =>
        expect(calls("session_send")).toEqual([{ ...cancelArgs(), command: { command: "ping" } }]),
      );
      const historyReads = calls("history_list").length;
      emit("session-ended", {
        execution_id: executionId,
        attempt_id: original,
        view: completion === "full" ? sessionView("original completion body") : null,
        error: completion === "full" ? null : "LOCKED",
      });
      expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
      expect(screen.queryByRole("button", { name: "Abort" })).toBeNull();
      if (completion === "full") {
        expect(await screen.findByText("original completion body")).toBeTruthy();
      } else {
        expect((await screen.findByRole("status")).textContent).toContain("Session ended: LOCKED");
      }
      await waitFor(() => expect(calls("history_list")).toHaveLength(historyReads + 1));
    },
  );

  it.each(["lock/unlock", "profile switch"])(
    "binds a delayed open's abort to its old attempt after %s remounts Workbench",
    async (transition) => {
      const oldOpen = deferred<string>();
      const owners = new Map<string, string>();
      let opens = 0;
      backend({
        session_open: ({ executionId, attemptId }) => {
          if (typeof executionId !== "string" || typeof attemptId !== "string") {
            throw new Error("missing session identity");
          }
          if (++opens === 1) return oldOpen.promise;
          owners.set(executionId, attemptId);
          return executionId;
        },
        session_cancel: ({ executionId, attemptId }) => {
          if (typeof executionId !== "string" || owners.get(executionId) !== attemptId) {
            throw "the session is no longer open";
          }
          owners.delete(executionId);
          return null;
        },
        session_send: () => null,
      });
      await boot();
      await openTab("Socket");
      const executionId = "00000000-0000-7000-8000-000000000030";
      const oldAttempt = "00000000-0000-7000-8000-000000000031";
      const newAttempt = "00000000-0000-7000-8000-000000000032";
      const ids = vi.spyOn(crypto, "randomUUID");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(oldAttempt);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(calls("session_open")).toHaveLength(1));
      fireEvent.click(screen.getByRole("button", { name: "Abort" }));
      await waitFor(() => expect(calls("session_cancel")).toEqual([cancelArgs()]));
      await act(async () => {});
      cleanup();
      render(
        <Workbench onLock={() => {}} profileName={transition === "lock/unlock" ? "test" : "other"} />,
      );
      await screen.findByRole("treeitem", { name: /Alpha/ });
      await openTab("Socket");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(newAttempt);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(calls("session_open")).toHaveLength(2));
      expect(owners.get(executionId)).toBe(newAttempt);
      await act(async () => oldOpen.resolve(executionId));
      await waitFor(() => expect(calls("session_cancel")).toEqual([cancelArgs(), cancelArgs()]));
      expect(calls("session_cancel")[1]).toEqual({ executionId, attemptId: oldAttempt });
      expect(owners.get(executionId)).toBe(newAttempt);
      expect(screen.getByRole("button", { name: "Connected" })).toBeTruthy();
      expect(screen.queryByRole("status")).toBeNull();
      fireEvent.click(screen.getByRole("button", { name: "Ping" }));
      await waitFor(() =>
        expect(calls("session_send")).toEqual([{ ...cancelArgs(1), command: { command: "ping" } }]),
      );
      const historyReads = calls("history_list").length;
      emit("session-ended", {
        execution_id: executionId,
        attempt_id: newAttempt,
        view: sessionView("replacement after remount"),
      });
      expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
      expect(await screen.findByText("replacement after remount")).toBeTruthy();
      await waitFor(() => expect(calls("history_list")).toHaveLength(historyReads + 1));
    },
  );

  it.each(["same epoch", "lock/unlock", "profile switch"])(
    "filters queued messages after execution ID reuse across %s",
    async (transition) => {
      backend({
        session_open: ({ executionId }) => executionId,
        session_cancel: () => null,
      });
      await boot();
      await openTab("Socket");
      const executionId = "00000000-0000-7000-8000-000000000040";
      const oldAttempt = "00000000-0000-7000-8000-000000000041";
      const newAttempt = "00000000-0000-7000-8000-000000000042";
      const ids = vi.spyOn(crypto, "randomUUID");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(oldAttempt);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(calls("session_open")).toHaveLength(1));
      const packet: NativeExecutionEvent = {
        event: "message",
        execution_id: executionId,
        attempt_id: oldAttempt,
        message: sessionMessage("queued old payload"),
      };
      const release = deferred<void>();
      const delivery = release.promise.then(() => emit("execution-event", packet));
      if (transition === "same epoch") {
        ask.mockResolvedValueOnce(true);
        fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
        await waitFor(() => expect(openTabs().queryByRole("tab", { name: /Socket/ })).toBeNull());
      } else {
        cleanup();
        render(
          <Workbench onLock={() => {}} profileName={transition === "lock/unlock" ? "test" : "other"} />,
        );
        await screen.findByRole("treeitem", { name: /Alpha/ });
      }
      await openTab("Socket");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(newAttempt);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(calls("session_open")).toHaveLength(2));
      await act(async () => {
        release.resolve(undefined);
        await delivery;
      });
      emit("execution-event", {
        event: "message",
        execution_id: executionId,
        message: sessionMessage("unattributed legacy payload"),
      } satisfies NativeExecutionEvent);
      expect(screen.queryByText("queued old payload")).toBeNull();
      expect(screen.queryByText("unattributed legacy payload")).toBeNull();
      expect(screen.getByText(/session · 0 messages/)).toBeTruthy();
      emit("execution-event", {
        ...packet,
        attempt_id: newAttempt,
        message: sessionMessage("fresh payload"),
      });
      expect(screen.getByText("fresh payload")).toBeTruthy();
      expect(screen.getByText(/session · 1 messages/)).toBeTruthy();
      expect(screen.getByRole("button", { name: "Abort" })).toBeTruthy();
    },
  );

  it.each([false, true])(
    "drops queued session progress from a reused manual ID (remount=%s)",
    async (remount) => {
      backend({ session_open: ({ executionId }) => executionId, session_cancel: () => null });
      await boot();
      await openTab("Socket");
      const executionId = "00000000-0000-7000-8000-000000000050";
      const attemptId = "00000000-0000-7000-8000-000000000051";
      const ids = vi.spyOn(crypto, "randomUUID");
      ids.mockReturnValueOnce(executionId).mockReturnValueOnce(attemptId);
      fireEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(calls("session_open")).toHaveLength(1));
      const packet: NativeExecutionEvent = {
        event: "body_progress",
        execution_id: executionId,
        attempt_id: attemptId,
        bytes: 999,
      };
      const release = deferred<void>();
      const delivery = release.promise.then(() => emit("execution-event", packet));
      if (remount) {
        cleanup();
        await boot();
      } else {
        ask.mockResolvedValueOnce(true);
        fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
        await waitFor(() => expect(openTabs().queryByRole("tab", { name: /Socket/ })).toBeNull());
      }
      await openTab("Alpha");
      ids.mockReturnValueOnce(executionId);
      fireEvent.click(screen.getByRole("button", { name: "Send" }));
      await waitFor(() => expect(calls("send_request")).toHaveLength(1));
      await act(async () => {
        release.resolve(undefined);
        await delivery;
      });
      expect(screen.queryByText(/received$/)).toBeNull();
      emit("execution-event", {
        event: "body_progress",
        execution_id: executionId,
        bytes: 64,
      } satisfies NativeExecutionEvent);
      expect(screen.getByText("64 B received")).toBeTruthy();
    },
  );

  it("aborts an open still connecting without reporting it as an error", async () => {
    backend();
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));

    fireEvent.click(screen.getByRole("button", { name: "Abort" }));
    await waitFor(() => expect(calls("session_cancel")).toEqual([cancelArgs()]));
    await waitFor(() => expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy());
    expect(connecting.size).toBe(0);
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("stops an open that the backend had not registered yet when Abort reached it", async () => {
    const open = deferred<string>();
    let registered = false;
    backend({
      session_open: () => open.promise,
      session_cancel: (a) => {
        // Before `session_open` registers, the backend has nothing to stop.
        if (!registered) throw "the session is no longer open";
        openSessions.delete(a.executionId as string);
        return null;
      },
    });
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    const execId = calls("session_open")[0].executionId as string;

    fireEvent.click(screen.getByRole("button", { name: "Abort" }));
    await waitFor(() => expect(calls("session_cancel")).toHaveLength(1));
    await act(async () => {});
    expect(screen.queryByRole("status")).toBeNull();
    // The open then registers and succeeds: the pending abort stops the session.
    registered = true;
    openSessions.add(execId);
    await act(async () => open.resolve(execId));
    await waitFor(() => expect(calls("session_cancel")).toEqual([cancelArgs(), cancelArgs()]));
    expect(openSessions.size).toBe(0);
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("stops an open that succeeded while its early Abort's answer was on the way", async () => {
    const open = deferred<string>();
    let cancels = 0;
    let answerFirstCancel!: (err: string) => void;
    backend({
      session_open: () => open.promise,
      session_cancel: (a) => {
        // The first cancel reached the backend before the open registered; its answer arrives late.
        if (++cancels === 1) return new Promise((_resolve, reject) => (answerFirstCancel = reject));
        openSessions.delete(a.executionId as string);
        return null;
      },
    });
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    const execId = calls("session_open")[0].executionId as string;

    fireEvent.click(screen.getByRole("button", { name: "Abort" }));
    await waitFor(() => expect(calls("session_cancel")).toHaveLength(1));
    openSessions.add(execId);
    await act(async () => open.resolve(execId));
    expect(calls("session_cancel")).toHaveLength(1);
    await act(async () => answerFirstCancel("the session is no longer open"));
    await waitFor(() => expect(calls("session_cancel")).toEqual([cancelArgs(), cancelArgs()]));
    expect(openSessions.size).toBe(0);
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("a failed open clears only its own session, not a newer one", async () => {
    backend();
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    const first = calls("session_open")[0].executionId as string;
    // The first session is reported over before its open settles; a second one starts.
    emit("session-ended", { execution_id: first, attempt_id: calls("session_open")[0].attemptId });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(2));

    await act(async () => connecting.get(first)!("connection refused"));
    expect((await screen.findByRole("status")).textContent).toContain("connection refused");
    expect(screen.getByRole("button", { name: "Connected" })).toBeTruthy();
  });

  it.each([
    ["same epoch", "full"],
    ["same epoch", "scalar"],
    ["lock/unlock", "full"],
    ["lock/unlock", "scalar"],
    ["locked profile switch", "full"],
    ["locked profile switch", "scalar"],
  ])("ignores queued %s / %s completion after ID reuse", async (transition, completion) => {
    backend({
      session_open: (args) => {
        openSessions.add(args.executionId as string);
        return args.executionId;
      },
      session_send: () => null,
    });
    await boot();
    await openTab("Socket");
    const executionId = "00000000-0000-7000-8000-000000000010";
    const oldAttempt = "00000000-0000-7000-8000-000000000011";
    const newAttempt = "00000000-0000-7000-8000-000000000012";
    const ids = vi.spyOn(crypto, "randomUUID");
    ids.mockReturnValueOnce(executionId).mockReturnValueOnce(oldAttempt);
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    expect(calls("session_open")[0]).toMatchObject({ executionId, attemptId: oldAttempt });
    await act(async () => {});

    // Hold a packet already accepted by native enqueue until after the new
    // attempt exists. This fake tests renderer delivery, not Tauri transport.
    const release = deferred<void>();
    const delivery = release.promise.then(() =>
      emit("session-ended", {
        execution_id: executionId,
        attempt_id: oldAttempt,
        view: completion === "full" ? sessionView("old completion body") : null,
        error: completion === "full" ? "old recording error" : "LOCKED",
      }),
    );
    if (transition === "same epoch") {
      ask.mockResolvedValueOnce(true);
      fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
      await waitFor(() => expect(openTabs().queryByRole("tab", { name: /Socket/ })).toBeNull());
    } else {
      // The lock screen removes Workbench; unlock/profile publication mounts
      // another one. Native transition fencing is covered by the Rust tests.
      cleanup();
      openSessions.clear();
      render(
        <Workbench
          onLock={() => {}}
          profileName={transition === "lock/unlock" ? "test" : "other"}
        />,
      );
      await screen.findByRole("treeitem", { name: /Alpha/ });
    }
    await openTab("Socket");
    ids.mockReturnValueOnce(executionId).mockReturnValueOnce(newAttempt);
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(2));
    expect(calls("session_open")[1]).toMatchObject({ executionId, attemptId: newAttempt });
    await act(async () => {});
    const historyReads = calls("history_list").length;
    await act(async () => {
      release.resolve(undefined);
      await delivery;
    });
    expect(screen.getByRole("button", { name: "Connected" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Abort" })).toBeTruthy();
    expect(screen.queryByText("old completion body")).toBeNull();
    expect(screen.queryByRole("status")).toBeNull();
    expect(calls("history_list")).toHaveLength(historyReads);
    expect(openSessions.has(executionId)).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Ping" }));
    await waitFor(() =>
      expect(calls("session_send")).toEqual([{ ...cancelArgs(1), command: { command: "ping" } }]),
    );

    // The matching generation still retires normally, for either packet form.
    openSessions.delete(executionId);
    emit("session-ended", {
      execution_id: executionId,
      attempt_id: newAttempt,
      view: completion === "full" ? sessionView("replacement completion body") : null,
      error: completion === "full" ? null : "LOCKED",
    });
    expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Abort" })).toBeNull();
    if (completion === "full") {
      expect(await screen.findByText("replacement completion body")).toBeTruthy();
    } else {
      expect((await screen.findByRole("status")).textContent).toContain("Session ended: LOCKED");
    }
    await waitFor(() => expect(calls("history_list")).toHaveLength(historyReads + 1));
  });

  it("retires a matching completion delivered before its open reply or tab render", async () => {
    const open = deferred<string>();
    backend({
      session_open: (args) => {
        emit("session-ended", {
          execution_id: args.executionId,
          attempt_id: args.attemptId,
          view: null,
          error: "LOCKED",
        });
        return open.promise;
      },
    });
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));
    expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Abort" })).toBeNull();
    expect((await screen.findByRole("status")).textContent).toContain("Session ended: LOCKED");
    await act(async () => open.resolve(calls("session_open")[0].executionId as string));
    expect(screen.getByRole("button", { name: "Connect" })).toBeTruthy();
  });
});

describe("closing a tab with backend work", () => {
  it("asks before disconnecting a session, and Keep open leaves it connected", async () => {
    backend();
    await boot();
    await openTab("Socket");
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(calls("session_open")).toHaveLength(1));

    ask.mockResolvedValueOnce(false);
    fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
    await waitFor(() => expect(ask).toHaveBeenCalledTimes(1));
    expect(ask.mock.calls[0][0]).toContain("open session");
    expect(openTabs().getByRole("tab", { name: /Socket/ })).toBeTruthy();
    expect(calls("session_cancel")).toHaveLength(0);

    ask.mockResolvedValueOnce(true);
    fireEvent.click(screen.getByRole("button", { name: "Close Socket" }));
    await waitFor(() => expect(calls("session_cancel")).toEqual([cancelArgs()]));
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
    await waitFor(() => expect(calls("session_cancel")).toEqual([cancelArgs()]));
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
    // The abandoned delete reports its failed stop; flush once more so a delete
    // that went ahead regardless would have been called by now.
    await waitFor(() => expect(screen.getByRole("status").textContent).toContain("the delete was abandoned"));
    await act(async () => {});
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

    ask.mockResolvedValueOnce(true);
    fireEvent.click(within(screen.getByRole("treeitem", { name: /Socket/ })).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(calls("session_cancel")).toEqual([cancelArgs()]));
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
    expect(await screen.findByRole("button", { name: "Runner (run in progress)" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Requests" }));
    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
    expect(screen.getByTestId("runner-live")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Runner/ }));
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
    expect(await screen.findByRole("button", { name: "Load tests (run in progress)" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Requests" }));
    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
    expect(screen.getByTestId("load-live")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Load tests/ }));
    fireEvent.click(screen.getByRole("button", { name: "Stop run" }));
    await waitFor(() => expect(calls("load_run_cancel")).toEqual([{ runKey: "key-1" }]));

    fireEvent.click(screen.getByRole("button", { name: "Requests" }));
    emit("load-finished", { run_key: "key-1", run_id: null });
    await waitFor(() => expect(screen.queryByTestId("load-live")).toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Load tests" }));
    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
  });
});

describe("workspace lists follow the selected workspace", () => {
  // Every list read of workspace A is held until the test completes it; B's
  // reads, and A's after the first, answer at once.
  function heldFirstReadsOfA() {
    const held = new Map<string, ReturnType<typeof deferred<unknown>>>();
    const hold = (cmd: string, reply: (ws: string) => unknown) => (a: Record<string, unknown>) => {
      if (a.workspaceId !== "A" || held.has(cmd)) return reply(a.workspaceId as string);
      const d = deferred<unknown>();
      held.set(cmd, d);
      return d.promise;
    };
    backend({
      tree_get: hold("tree_get", (ws) => Object.values(requests).filter((r) => r.workspace_id === ws).map(node)),
      history_list: hold("history_list", (ws) => [historyItem(`h-${ws}`, `https://history-${ws}.test/`)]),
      tls_profiles_list: hold("tls_profiles_list", (ws) => [tlsProfile(`t-${ws}`, ws, `TLS ${ws}`)]),
      environments_list: hold("environments_list", (ws) => [environment(`e-${ws}`, ws, `Env ${ws}`)]),
    });
    return held;
  }
  // The stale replies: what A held before anything changed.
  const staleA: Record<string, unknown> = {
    tree_get: [node(request("old", "A", "Stale"))],
    history_list: [historyItem("h-old", "https://history-stale.test/")],
    tls_profiles_list: [tlsProfile("t-old", "A", "TLS stale")],
    environments_list: [environment("e-old", "A", "Env stale")],
  };
  const completeHeld = (held: Map<string, ReturnType<typeof deferred<unknown>>>) =>
    act(async () => {
      for (const [cmd, d] of held) d.resolve(staleA[cmd]);
    });

  async function startInA() {
    render(<Workbench onLock={() => {}} profileName="test" />);
    await screen.findByRole("option", { name: "Two" });
    await waitFor(() => expect(calls("environments_list")).toHaveLength(1));
    // A's lists are still loading: nothing is shown for it yet.
    expect(screen.getByText("Loading…")).toBeTruthy();
  }

  it("ignores A's late reads once B is selected", async () => {
    const held = heldFirstReadsOfA();
    await startInA();
    await selectWorkspace("B", "Gamma");
    await screen.findByRole("option", { name: "Env B" });
    await completeHeld(held);

    expect((screen.getByLabelText("Workspace") as HTMLSelectElement).value).toBe("B");
    expect(screen.getByRole("treeitem", { name: /Gamma/ })).toBeTruthy();
    expect(screen.queryByRole("treeitem", { name: /Stale|Alpha/ })).toBeNull();
    expect(screen.getByRole("option", { name: "Env B" })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "Env stale" })).toBeNull();

    await openTab("Gamma");
    fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    expect(screen.getByRole("option", { name: "TLS B" })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "TLS stale" })).toBeNull();

    fireEvent.click(screen.getByRole("tab", { name: "History" }));
    expect(await screen.findByText("https://history-B.test/")).toBeTruthy();
    expect(screen.queryByText("https://history-stale.test/")).toBeNull();
  });

  it("ignores A's first reads after A to B to A, keeping the newer ones", async () => {
    const held = heldFirstReadsOfA();
    await startInA();
    await selectWorkspace("B", "Gamma");
    await selectWorkspace("A", "Alpha");
    await screen.findByRole("option", { name: "Env A" });
    await completeHeld(held);

    expect(screen.getByRole("treeitem", { name: /Alpha/ })).toBeTruthy();
    expect(screen.queryByRole("treeitem", { name: /Stale/ })).toBeNull();
    expect(screen.getByRole("option", { name: "Env A" })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "Env stale" })).toBeNull();

    await openTab("Alpha");
    fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    expect(screen.getByRole("option", { name: "TLS A" })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "TLS stale" })).toBeNull();
  });

  it("clears the lists of the workspace left while the next one loads", async () => {
    const pendingB = deferred<unknown>();
    backend({
      tree_get: (a) => (a.workspaceId === "B" ? pendingB.promise : Object.values(requests).filter((r) => r.workspace_id === a.workspaceId).map(node)),
    });
    await boot();
    fireEvent.change(screen.getByLabelText("Workspace"), { target: { value: "B" } });
    expect(await screen.findByText("Loading…")).toBeTruthy();
    expect(screen.queryByRole("treeitem", { name: /Alpha/ })).toBeNull();

    await act(async () => pendingB.resolve([node(requests.r3)]));
    expect(await screen.findByRole("treeitem", { name: /Gamma/ })).toBeTruthy();
    expect(screen.queryByText("Loading…")).toBeNull();
  });
});

describe("imports refresh the selected workspace and its open tabs", () => {
  const emptySpecReport = {
    warnings: [],
    unsupported: [],
    external_refs: [],
    scripts: [],
    inactive_settings: [],
    redactions: [],
    required_variables: [],
    counts: {
      operations_found: 0,
      requests: 0,
      folders: 0,
      environments: 0,
      skipped_operations: 0,
      warnings: 0,
    },
  };

  it(
    "reloads environments and replaces a clean tab after importing a spec into the current workspace",
    async () => {
      let imported = false;
      backend({
        environments_list: (a) => [
          environment(
            imported ? "new-env" : "old-env",
            a.workspaceId as string,
            imported ? "Imported env" : "Old env",
          ),
        ],
        spec_preview: () => ({
          binding: { source_sha256: "source", plan_sha256: "plan" },
          approval: {
            binding: { source_sha256: "source", plan_sha256: "plan" },
            scope: "native-scope",
          },
          detected: { kind: "openapi", dialect: "openapi", syntax: "json" },
          report: emptySpecReport,
          folders: 1,
          requests: 1,
          environments: 1,
          sample: [],
        }),
        spec_import: () => {
          imported = true;
          requests.r1 = request("r1", "A", "Alpha", { url: "https://imported.test/" });
          return {
            workspace_id: "A",
            import_id: "import-1",
            requests: 1,
            report: emptySpecReport,
          };
        },
      });
      await boot();
      await openTab("Alpha");
      expect(screen.getByRole("option", { name: "Old env" })).toBeTruthy();
      fireEvent.click(screen.getByRole("button", { name: "Import" }));
      const importDialog = screen.getByRole("dialog", { name: "Import" });
      fireEvent.change(screen.getByPlaceholderText(/curl -X POST/), {
        target: { value: "openapi: 3.0.0" },
      });
      fireEvent.click(screen.getByLabelText(/Into “One”/));
      fireEvent.click(screen.getByRole("button", { name: "Preview" }));
      await screen.findByText("Requests / folders / environments");
      fireEvent.click(within(importDialog).getByRole("button", { name: /^Import$/ }));

      await waitFor(() => expect(urlField().value).toBe("https://imported.test/"));
      expect(await screen.findByRole("option", { name: "Imported env" })).toBeTruthy();
      expect(screen.queryByRole("option", { name: "Old env" })).toBeNull();
      expect(
        calls("tls_profiles_list").filter((c) => c.workspaceId === "A").length,
      ).toBeGreaterThan(1);
      expect(calls("history_list").filter((c) => c.workspaceId === "A").length).toBeGreaterThan(1);
    },
  );

  it(
    "keeps a dirty draft when a spec reimport changes its saved request",
    async () => {
      backend({
        spec_preview: () => ({
          binding: { source_sha256: "source", plan_sha256: "plan" },
          approval: {
            binding: { source_sha256: "source", plan_sha256: "plan" },
            scope: "native-scope",
          },
          detected: { kind: "openapi", dialect: "openapi", syntax: "json" },
          report: emptySpecReport,
          folders: 1,
          requests: 1,
          environments: 0,
          sample: [],
        }),
        spec_import: () => {
          requests.r1 = request("r1", "A", "Alpha", { url: "https://imported.test/" });
          return { workspace_id: "A", import_id: "import-2", requests: 1, report: emptySpecReport };
        },
      });
      await boot();
      await openTab("Alpha");
      fireEvent.change(urlField(), { target: { value: "https://my-draft.test/" } });
      fireEvent.click(screen.getByRole("button", { name: "Import" }));
      const importDialog = screen.getByRole("dialog", { name: "Import" });
      fireEvent.change(screen.getByPlaceholderText(/curl -X POST/), {
        target: { value: "openapi: 3.0.0" },
      });
      fireEvent.click(screen.getByLabelText(/Into “One”/));
      fireEvent.click(screen.getByRole("button", { name: "Preview" }));
      await screen.findByText("Requests / folders / environments");
      fireEvent.click(within(importDialog).getByRole("button", { name: /^Import$/ }));

      await waitFor(() => expect(urlField().value).toBe("https://my-draft.test/"));
      expect(screen.getByLabelText("unsaved")).toBeTruthy();
      expect(
        await screen.findByText(/unsaved tab\(s\) kept; stored requests changed/),
      ).toBeTruthy();
    },
  );

  it(
    "refreshes clean tabs and workspace lists after bundle Replace existing",
    async () => {
      let imported = false;
      backend({
        file_choose: () => [{ token: "bundle-token", file_name: "workspace.anvil" }],
        import_preview: () => ({
          plan: {
            policy: "replace",
            to_create: 0,
            to_replace: 1,
            skipped_existing: 0,
            conflicts: [],
            foreign_secrets: [],
            foreign_objects: [],
            existing_workspaces: [{ id: "A", name: "One" }],
          },
          warnings: [],
          secrets_restored: false,
          missing_secrets: [],
          linked_files: [],
          workspaces: ["One"],
          workspace_ids: ["A"],
          full_backup: false,
          api_standards_count: 0,
          bundle_sha256: "hash",
        }),
        import_apply: () => {
          imported = true;
          requests.r1 = request("r1", "A", "Alpha", { url: "https://bundle.test/" });
          return { workspace_ids: ["A"] };
        },
        environments_list: (a) => [
          environment(
            imported ? "bundle-env" : "old-env",
            a.workspaceId as string,
            imported ? "Bundle env" : "Old env",
          ),
        ],
      });
      await boot();
      await openTab("Alpha");
      fireEvent.click(screen.getByRole("button", { name: "Import" }));
      const importDialog = screen.getByRole("dialog", { name: "Import" });
      fireEvent.click(screen.getByRole("tab", { name: "Anvil bundle / backup" }));
      fireEvent.click(within(importDialog).getByRole("button", { name: "Choose bundle…" }));
      await within(importDialog).findByText("workspace.anvil");
      fireEvent.change(within(importDialog).getByLabelText("If objects already exist"), {
        target: { value: "replace" },
      });
      fireEvent.click(within(importDialog).getByRole("button", { name: "Preview" }));
      await within(importDialog).findByText("To replace");
      fireEvent.click(within(importDialog).getByLabelText(/I trust this bundle/));
      fireEvent.click(within(importDialog).getByRole("button", { name: /^Import$/ }));

      await waitFor(() => expect(urlField().value).toBe("https://bundle.test/"));
      expect(await screen.findByRole("option", { name: "Bundle env" })).toBeTruthy();
      expect(screen.queryByRole("option", { name: "Old env" })).toBeNull();
    },
  );
});

describe("saving a request", () => {
  it("marks the request saved (control)", async () => {
    backend({ request_save: (a) => a.request });
    await boot();
    await openTab("Alpha");
    fireEvent.change(urlField(), { target: { value: "https://submitted.test/" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.queryByLabelText("unsaved")).toBeNull());
    expect(urlField().value).toBe("https://submitted.test/");
    expect(calls("request_save")).toHaveLength(1);
  });

  it("keeps edits made while the save was pending, and they stay unsaved", async () => {
    const saves: ReturnType<typeof deferred<RequestDefinition>>[] = [];
    backend({
      request_save: () => {
        const d = deferred<RequestDefinition>();
        saves.push(d);
        return d.promise;
      },
    });
    await boot();
    await openTab("Alpha");
    fireEvent.change(urlField(), { target: { value: "https://submitted.test/" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saves).toHaveLength(1));
    const submitted = calls("request_save")[0].request as RequestDefinition;
    expect(submitted.spec.url).toBe("https://submitted.test/");

    fireEvent.change(urlField(), { target: { value: "https://newer-draft.test/" } });
    await act(async () => saves[0].resolve({ ...submitted, revision_id: "rev-1" }));

    expect(urlField().value).toBe("https://newer-draft.test/");
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(1);
    // The baseline is what was written: returning to it is clean again.
    fireEvent.change(urlField(), { target: { value: "https://submitted.test/" } });
    expect(screen.queryByLabelText("unsaved")).toBeNull();
  });

  it("runs overlapping saves in order, ending saved as the last one wrote", async () => {
    const saves: ReturnType<typeof deferred<RequestDefinition>>[] = [];
    backend({
      request_save: () => {
        const d = deferred<RequestDefinition>();
        saves.push(d);
        return d.promise;
      },
    });
    await boot();
    await openTab("Alpha");
    fireEvent.change(urlField(), { target: { value: "https://first.test/" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saves).toHaveLength(1));
    fireEvent.change(urlField(), { target: { value: "https://second.test/" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.change(urlField(), { target: { value: "https://third.test/" } });

    // The second save waits for the first to finish.
    await act(async () => {});
    expect(saves).toHaveLength(1);
    const first = calls("request_save")[0].request as RequestDefinition;
    await act(async () => saves[0].resolve(first));
    await waitFor(() => expect(saves).toHaveLength(2));
    const second = calls("request_save")[1].request as RequestDefinition;
    expect(second.spec.url).toBe("https://second.test/");
    expect(urlField().value).toBe("https://third.test/");

    await act(async () => saves[1].resolve(second));
    expect(urlField().value).toBe("https://third.test/");
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(1);
    fireEvent.change(urlField(), { target: { value: "https://second.test/" } });
    expect(screen.queryByLabelText("unsaved")).toBeNull();
  });
});

describe("renaming an open request", () => {
  const startRename = () => {
    fireEvent.click(
      within(screen.getByRole("treeitem", { name: /Alpha/ })).getByRole("button", { name: "Rename" }),
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "Renamed" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
  };

  it("saves only the name and keeps drafts made before and during the rename", async () => {
    const saves: ReturnType<typeof deferred<RequestDefinition>>[] = [];
    backend({
      request_save: () => {
        const d = deferred<RequestDefinition>();
        saves.push(d);
        return d.promise;
      },
    });
    await boot();
    await openTab("Alpha");
    fireEvent.change(urlField(), { target: { value: "https://before-rename.test/" } });
    startRename();
    await waitFor(() => expect(saves).toHaveLength(1));

    const submitted = calls("request_save")[0].request as RequestDefinition;
    expect(submitted.name).toBe("Renamed");
    expect(submitted.spec.url).toBe("https://r1.test/");
    fireEvent.change(urlField(), { target: { value: "https://during-rename.test/" } });
    await act(async () => saves[0].resolve({ ...submitted, revision_id: "rename-rev" }));

    expect(openTabs().getByRole("tab", { name: /Renamed/ })).toBeTruthy();
    expect(urlField().value).toBe("https://during-rename.test/");
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(1);
    fireEvent.change(urlField(), { target: { value: "https://r1.test/" } });
    expect(screen.queryByLabelText("unsaved")).toBeNull();
  });

  it("waits behind an in-flight save and renames its saved revision", async () => {
    const saves: ReturnType<typeof deferred<RequestDefinition>>[] = [];
    backend({
      request_save: () => {
        const d = deferred<RequestDefinition>();
        saves.push(d);
        return d.promise;
      },
    });
    await boot();
    await openTab("Alpha");
    fireEvent.change(urlField(), { target: { value: "https://first-save.test/" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saves).toHaveLength(1));
    const first = calls("request_save")[0].request as RequestDefinition;

    startRename();
    await act(async () => {});
    expect(saves).toHaveLength(1);
    await act(async () => saves[0].resolve({ ...first, revision_id: "first-rev" }));
    await waitFor(() => expect(saves).toHaveLength(2));
    const renamed = calls("request_save")[1].request as RequestDefinition;
    expect(renamed.name).toBe("Renamed");
    expect(renamed.spec.url).toBe("https://first-save.test/");
    expect(renamed.revision_id).toBe("first-rev");

    fireEvent.change(urlField(), { target: { value: "https://new-draft.test/" } });
    await act(async () => saves[1].resolve({ ...renamed, revision_id: "rename-rev" }));
    expect(urlField().value).toBe("https://new-draft.test/");
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(1);
  });
});

describe("relocating a linked file", () => {
  const OLD = "/elsewhere/upload.bin";
  const NEW = "/home/me/upload.bin";
  const upload = (path: string) =>
    request("u1", "A", "Upload", { method: "POST", body: { type: "binary", attachment: { kind: "linked_file", path }, content_type: null } } as Partial<RequestSpec>);

  /** A backend whose `file_choose` runs `choose`; the saved request names OLD until `relocate` is called. */
  function linkedBackend(choose: (relocate: () => unknown) => unknown) {
    let status = [{ path: OLD, state: "unbound" }];
    const relocate = () => {
      requests.u1 = upload(NEW);
      status = [{ path: NEW, state: "bound" }];
      return [{ token: "binding-1", file_name: "upload.bin", path: NEW }];
    };
    backend({ linked_file_status: () => status, file_choose: () => choose(relocate) });
    requests.u1 = upload(OLD);
  }

  async function openBody() {
    await boot();
    await openTab("Upload");
    fireEvent.click(screen.getByRole("tab", { name: /^Body/ }));
    await screen.findByText("Not chosen on this device");
  }

  it("reloads the saved request into the editor's draft", async () => {
    linkedBackend((relocate) => relocate());
    await openBody();
    // An edit to a request naming a linked file cannot be saved here: the reload replaces it.
    fireEvent.change(urlField(), { target: { value: "https://draft.test/" } });
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(1);
    // The saved request is what a relocated file is used for: its host, not the draft's, is shown.
    expect(screen.getByTestId("linked-file").textContent).toContain("It is used for requests to u1.test.");
    expect(screen.getByTestId("linked-file").textContent).not.toContain("draft.test");

    ask.mockResolvedValueOnce(true);
    fireEvent.click(screen.getByRole("button", { name: /Choose new location…/ }));
    await waitFor(() => expect(screen.getByTestId("linked-file").textContent).toContain(NEW));
    expect(ask).toHaveBeenCalledTimes(1);
    expect(ask.mock.calls[0][0]).toContain("“Upload” has unsaved changes");
    expect(await screen.findByText("Chosen on this device")).toBeTruthy();
    expect(calls("file_choose")).toEqual([{ purpose: "linked_file_relocate", options: { multiple: false }, referrer: { kind: "request", id: "u1" }, oldPath: OLD }]);
    expect(calls("request_get").filter((a) => a.requestId === "u1")).toHaveLength(2);
    expect(urlField().value).toBe("https://u1.test/");
    expect(screen.queryByLabelText("unsaved")).toBeNull();
    expect(calls("request_save")).toHaveLength(0);
  });

  it("keeps the draft when the dialog is cancelled", async () => {
    linkedBackend(() => []);
    await openBody();
    fireEvent.change(urlField(), { target: { value: "https://draft.test/" } });
    ask.mockResolvedValueOnce(true);
    fireEvent.click(screen.getByRole("button", { name: /Choose new location…/ }));
    await waitFor(() => expect(calls("file_choose")).toHaveLength(1));
    await waitFor(() => expect((screen.getByRole("button", { name: /Choose new location…/ }) as HTMLButtonElement).disabled).toBe(false));
    expect(screen.getByTestId("linked-file").textContent).toContain(OLD);
    expect(calls("request_get").filter((a) => a.requestId === "u1")).toHaveLength(1);
    expect(urlField().value).toBe("https://draft.test/");
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(1);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("keeps unsaved edits, and relocates nothing, when discarding them is declined", async () => {
    linkedBackend((relocate) => relocate());
    await openBody();
    fireEvent.change(urlField(), { target: { value: "https://draft.test/" } });
    ask.mockResolvedValueOnce(false);
    fireEvent.click(screen.getByRole("button", { name: /Choose new location…/ }));
    await waitFor(() => expect(ask).toHaveBeenCalledTimes(1));
    expect(ask.mock.calls[0][1]).toMatchObject({ title: "Unsaved changes", kind: "warning" });
    await waitFor(() => expect((screen.getByRole("button", { name: /Choose new location…/ }) as HTMLButtonElement).disabled).toBe(false));
    expect(calls("file_choose")).toHaveLength(0);
    expect(calls("request_get").filter((a) => a.requestId === "u1")).toHaveLength(1);
    expect(screen.getByTestId("linked-file").textContent).toContain(OLD);
    expect(urlField().value).toBe("https://draft.test/");
    expect(screen.getAllByLabelText("unsaved")).toHaveLength(1);
  });

  it("asks nothing when the tab has no unsaved edits", async () => {
    linkedBackend((relocate) => relocate());
    await openBody();
    fireEvent.click(screen.getByRole("button", { name: /Choose new location…/ }));
    await waitFor(() => expect(screen.getByTestId("linked-file").textContent).toContain(NEW));
    expect(ask).not.toHaveBeenCalled();
    expect(calls("file_choose")).toHaveLength(1);
  });
});
