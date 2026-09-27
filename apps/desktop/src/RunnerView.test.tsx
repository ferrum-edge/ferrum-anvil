// Renderer tests for the collection runner's run slot and workspace scoping
// (jsdom; the Tauri backend is a scripted fake). A start that is still pending
// cannot be dispatched again, a run that finishes before `run_start` answers
// never comes back as running, and a Stop pressed during startup cancels the
// run once its id is known. Switching workspaces drops the previous
// workspace's selection, folder choice and pending confirmation, but keeps a
// live run's Stop control. An unsaved scenario edit is kept per workspace:
// hidden while another workspace is shown, restored on return, and dropped
// once its scenario is gone from the workspace.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

const { invoke, handlers } = vi.hoisted(() => ({
  invoke: vi.fn(),
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
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(), open: vi.fn(), save: vi.fn() }));

import type { RunEvent, Scenario, TreeNode } from "./api";
import { RunnerView } from "./RunnerView";

const now = "2026-01-01T00:00:00Z";
const scenario = (id: string, ws: string, name: string, trusted = true) =>
  ({ id, workspace_id: ws, name, schema_version: 1, created_at: now, updated_at: now, steps: [{ request_id: "r1" }], trusted }) as Scenario;
const folder = (id: string, name: string): TreeNode => ({ id, kind: "folder", name, favorite: false, children: [] });

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

let lists: Record<string, Scenario[] | Promise<Scenario[]>>;
const notify = vi.fn();

function backend(overrides: Record<string, (args: Record<string, unknown>) => unknown> = {}) {
  lists = { A: [scenario("sa", "A", "Scenario A")], B: [] };
  invoke.mockImplementation(async (cmd: string, args: Record<string, unknown> = {}) => {
    if (overrides[cmd]) return overrides[cmd](args);
    switch (cmd) {
      case "scenarios_list":
        return lists[args.workspaceId as string] ?? [];
      case "run_reports":
        return [];
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  });
}

const calls = (cmd: string) => invoke.mock.calls.filter((c) => c[0] === cmd).map((c) => c[1] as Record<string, unknown>);
const emit = (name: string, payload: unknown) => act(() => handlers.get(name)?.forEach((cb) => cb({ payload })));
const button = (name: string) => screen.getByRole("button", { name }) as HTMLButtonElement;
const view = (ws: string, tree: TreeNode[] = []) => (
  <RunnerView workspaceId={ws} tree={tree} environments={[]} activeEnvironment={null} notify={notify} />
);

async function mount(ws = "A", tree: TreeNode[] = []) {
  const r = render(view(ws, tree));
  if (ws === "A") await screen.findByText("Scenario A");
  else await screen.findByText("No scenarios yet.");
  return r;
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
  notify.mockReset();
  handlers.clear();
});

describe("starting a run", () => {
  it("dispatches one run for a double click while the start is pending", async () => {
    const start = deferred<string>();
    backend({ run_start: () => start.promise });
    await mount();

    fireEvent.click(button("Run folder"));
    fireEvent.click(button("Run folder"));
    expect(calls("run_start")).toHaveLength(1);
    expect(button("Run folder").disabled).toBe(true);
    expect(screen.getByText("Starting…")).toBeTruthy();

    await act(async () => start.resolve("run-1"));
    expect(calls("run_start")).toHaveLength(1);
    expect(button("Stop run")).toBeTruthy();
  });

  it("never shows a run that finished before its start answered", async () => {
    const start = deferred<string>();
    backend({ run_start: () => start.promise, run_cancel: () => false });
    await mount();

    fireEvent.click(button("Run folder"));
    emit("run-finished", { run_id: "run-fast", error: "folder contains no requests" });
    await act(async () => start.resolve("run-fast"));

    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
    expect(button("Run folder").disabled).toBe(false);
    expect(notify).toHaveBeenCalledWith("Run did not complete: folder contains no requests");
    expect(calls("run_cancel")).toHaveLength(0);
  });

  it("keeps the progress a run reported before its start answered", async () => {
    const start = deferred<string>();
    backend({ run_start: () => start.promise });
    await mount();

    fireEvent.click(button("Run folder"));
    const progress = { steps_done: 1, steps_total: 3, steps_failed: 0, iterations_done: 0, iterations_total: 1 };
    const step: Extract<RunEvent, { event: "step_finished" }> = {
      run_id: "run-1",
      iteration: 0,
      step: 0,
      status: "passed",
      http_status: 204,
      duration_ms: 5,
      progress,
      event: "step_finished",
    };
    emit("run-event", step);
    emit("run-event", { ...step, run_id: "run-other", http_status: 500 });
    await act(async () => start.resolve("run-1"));

    expect(screen.getByText("1/3 steps · 0 failed · iteration 0/1")).toBeTruthy();
    expect(screen.getByText("204")).toBeTruthy();
    expect(screen.queryByText("500")).toBeNull();
  });

  it("frees the slot when the start fails", async () => {
    let fail = true;
    backend({
      run_start: () => {
        if (fail) throw "no such folder";
        return "run-2";
      },
    });
    await mount();

    fireEvent.click(button("Run folder"));
    await waitFor(() => expect(notify).toHaveBeenCalledWith("no such folder"));
    expect(screen.queryByRole("button", { name: "Stop run" })).toBeNull();
    expect(button("Run folder").disabled).toBe(false);

    fail = false;
    fireEvent.click(button("Run folder"));
    await screen.findByRole("button", { name: "Stop run" });
    expect(calls("run_start")).toHaveLength(2);
  });

  it("cancels a run stopped during startup once its id is known", async () => {
    const start = deferred<string>();
    backend({ run_start: () => start.promise, run_cancel: () => true });
    await mount();

    fireEvent.click(button("Run folder"));
    fireEvent.click(button("Stop run"));
    expect(button("Stopping…").disabled).toBe(true);
    expect(calls("run_cancel")).toHaveLength(0);

    await act(async () => start.resolve("run-1"));
    await waitFor(() => expect(calls("run_cancel")).toEqual([{ runId: "run-1" }]));
    expect(button("Stopping…")).toBeTruthy();

    emit("run-finished", { run_id: "run-1" });
    await waitFor(() => expect(button("Run folder").disabled).toBe(false));
    expect(screen.queryByRole("button", { name: /Stop/ })).toBeNull();
  });

  it("clears a run the backend no longer knows when Stop is pressed", async () => {
    backend({ run_start: () => "run-1", run_cancel: () => false });
    await mount();

    fireEvent.click(button("Run folder"));
    fireEvent.click(await screen.findByRole("button", { name: "Stop run" }));
    await waitFor(() => expect(button("Run folder").disabled).toBe(false));
    expect(calls("run_cancel")).toEqual([{ runId: "run-1" }]);
    expect(screen.queryByRole("button", { name: /Stop/ })).toBeNull();
  });

  it("ignores the finish of a run that is not the live one", async () => {
    backend({ run_start: () => "run-2" });
    await mount();

    fireEvent.click(button("Run folder"));
    await screen.findByRole("button", { name: "Stop run" });
    emit("run-finished", { run_id: "run-1" });
    await act(async () => {});
    expect(button("Stop run")).toBeTruthy();
    expect(button("Run folder").disabled).toBe(true);
  });
});

describe("switching workspaces", () => {
  it("drops workspace A's scenario and its Run action, and restores nothing stale on return", async () => {
    backend({ run_start: () => "run-1" });
    const tree = [folder("fa", "Folder A")];
    const r = await mount("A", tree);
    fireEvent.click(screen.getByText("Scenario A"));
    expect(screen.getByRole("heading", { name: "Scenario A" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Folder to run"), { target: { value: "fa" } });

    r.rerender(view("B"));
    await screen.findByText("No scenarios yet.");
    expect(screen.queryByRole("heading", { name: "Scenario A" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Run" })).toBeNull();
    expect((screen.getByLabelText("Folder to run") as HTMLSelectElement).value).toBe("");

    fireEvent.click(button("Run folder"));
    await waitFor(() => expect(calls("run_start")).toHaveLength(1));
    expect(calls("run_start")[0].target).toEqual({ kind: "folder", workspace_id: "B", folder_id: null });
  });

  it("does not bring back A's selection after A -> B -> A", async () => {
    backend({ run_start: () => "run-1" });
    const r = await mount("A");
    fireEvent.click(screen.getByText("Scenario A"));

    r.rerender(view("B"));
    await screen.findByText("No scenarios yet.");
    r.rerender(view("A"));
    await screen.findByText("Scenario A");
    expect(screen.queryByRole("button", { name: "Run" })).toBeNull();

    fireEvent.click(screen.getByText("Scenario A"));
    fireEvent.click(button("Run"));
    await waitFor(() => expect(calls("run_start")).toHaveLength(1));
    expect(calls("run_start")[0].target).toEqual({ kind: "scenario", scenario_id: "sa" });
  });

  it("closes a pending untrusted-scenario confirmation", async () => {
    backend({ run_start: () => "run-1" });
    lists = { A: [scenario("su", "A", "Imported A", false)], B: [] };
    const r = render(view("A"));
    fireEvent.click(await screen.findByText("Imported A"));
    fireEvent.click(button("Run"));
    expect(screen.getByText("Run an imported scenario?")).toBeTruthy();

    r.rerender(view("B"));
    expect(screen.queryByText("Run an imported scenario?")).toBeNull();
    await screen.findByText("No scenarios yet.");
    expect(screen.queryByRole("button", { name: "Run once" })).toBeNull();
    expect(calls("run_start")).toHaveLength(0);
  });

  it("does not run a scenario trusted in A once B is shown", async () => {
    const trust = deferred<Scenario>();
    backend({ run_start: () => "run-1", scenario_trust: () => trust.promise });
    lists = { A: [scenario("su", "A", "Imported A", false)], B: [] };
    const r = render(view("A"));
    fireEvent.click(await screen.findByText("Imported A"));
    fireEvent.click(button("Run"));
    fireEvent.click(button("Trust and run"));

    r.rerender(view("B"));
    await screen.findByText("No scenarios yet.");
    await act(async () => trust.resolve(scenario("su", "A", "Imported A")));
    await act(async () => {});
    expect(calls("run_start")).toHaveLength(0);
  });

  it("shows no stale list or editor while B's lists load, nor after A's late reply", async () => {
    backend();
    const aLate = deferred<Scenario[]>();
    const bLists = deferred<Scenario[]>();
    const r = await mount("A");
    fireEvent.click(screen.getByText("Scenario A"));

    lists.B = bLists.promise;
    r.rerender(view("B"));
    expect(screen.queryByText("Scenario A")).toBeNull();
    expect(screen.queryByRole("button", { name: "Run" })).toBeNull();

    lists.A = aLate.promise;
    r.rerender(view("A"));
    r.rerender(view("B"));
    await act(async () => bLists.resolve([scenario("sb", "B", "Scenario B")]));
    await screen.findByText("Scenario B");
    await act(async () => aLate.resolve([scenario("sa", "A", "Scenario A")]));
    expect(screen.queryByText("Scenario A")).toBeNull();
    expect(screen.getByText("Scenario B")).toBeTruthy();
  });

  it("keeps a live run's Stop control", async () => {
    backend({ run_start: () => "run-1", run_cancel: () => true });
    const r = await mount("A");
    fireEvent.click(button("Run folder"));
    await screen.findByRole("button", { name: "Stop run" });

    r.rerender(view("B"));
    await waitFor(() => expect(calls("scenarios_list").some((c) => c.workspaceId === "B")).toBe(true));
    fireEvent.click(button("Stop run"));
    await waitFor(() => expect(calls("run_cancel")).toEqual([{ runId: "run-1" }]));
  });
});

describe("unsaved scenario edits", () => {
  const iterations = () => screen.getByLabelText("Iterations") as HTMLInputElement;

  it("hides A's edit while B is shown and restores it, still unsaved, on return to A", async () => {
    backend({
      scenario_save: (a) => {
        lists.A = [a.scenario as Scenario];
        return a.scenario;
      },
    });
    lists.B = [scenario("sb", "B", "Scenario B")];
    const r = await mount("A");
    fireEvent.click(screen.getByText("Scenario A"));
    fireEvent.change(iterations(), { target: { value: "7" } });
    expect(screen.getByText("1 step · 7 iterations")).toBeTruthy();
    expect(screen.getAllByText("unsaved")).toHaveLength(2);

    r.rerender(view("B"));
    await screen.findByText("Scenario B");
    expect(screen.queryByText("unsaved")).toBeNull();
    expect(screen.queryByLabelText("Iterations")).toBeNull();
    expect(screen.queryByRole("button", { name: "Run" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
    fireEvent.click(screen.getByText("Scenario B"));
    expect(iterations().value).toBe("1");
    expect(screen.queryByText("unsaved")).toBeNull();

    r.rerender(view("A"));
    await screen.findByText("Scenario A");
    expect(screen.getAllByText("unsaved")).toHaveLength(1);
    fireEvent.click(screen.getByText("Scenario A"));
    expect(iterations().value).toBe("7");
    expect(screen.getByText("1 step · 7 iterations")).toBeTruthy();
    expect(screen.getAllByText("unsaved")).toHaveLength(2);
    expect(calls("scenario_save")).toHaveLength(0);

    fireEvent.click(button("Save"));
    await waitFor(() => expect(screen.queryByText("unsaved")).toBeNull());
    expect(iterations().value).toBe("7");
    expect((calls("scenario_save")[0].scenario as Scenario).iterations).toBe(7);
  });

  it("drops the edit of a scenario gone from A's refreshed list", async () => {
    backend();
    const r = await mount("A");
    fireEvent.click(screen.getByText("Scenario A"));
    fireEvent.change(iterations(), { target: { value: "7" } });

    r.rerender(view("B"));
    await screen.findByText("No scenarios yet.");
    lists.A = [scenario("sa2", "A", "Other A")];
    r.rerender(view("A"));
    await screen.findByText("Other A");
    expect(screen.queryByText("unsaved")).toBeNull();
    fireEvent.click(screen.getByText("Other A"));
    expect(iterations().value).toBe("1");

    // Back again: the scenario returns, but its dropped edit does not.
    r.rerender(view("B"));
    await screen.findByText("No scenarios yet.");
    lists.A = [scenario("sa", "A", "Scenario A")];
    r.rerender(view("A"));
    fireEvent.click(await screen.findByText("Scenario A"));
    expect(iterations().value).toBe("1");
    expect(screen.queryByText("unsaved")).toBeNull();
  });

  it("drops the edit of a deleted scenario while it is shown", async () => {
    backend({
      scenario_delete: () => {
        lists.A = [];
      },
    });
    await mount("A");
    fireEvent.click(screen.getByText("Scenario A"));
    fireEvent.change(iterations(), { target: { value: "7" } });

    fireEvent.click(button("Delete scenario"));
    await screen.findByText("No scenarios yet.");
    expect(screen.queryByText("unsaved")).toBeNull();
    expect(screen.queryByLabelText("Iterations")).toBeNull();
  });
});
