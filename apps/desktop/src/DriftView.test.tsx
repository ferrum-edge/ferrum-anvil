// Renderer tests for contract drift (jsdom; the Tauri backend is a scripted
// fake). The Live traffic page lists differences with their suggested
// revisions, preselects additions but not relaxations, previews a reimport
// before applying the chosen ids, and saves the revision through a save
// grant. The response panel shows a Contract tab only for a send its
// import's description covers.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: async () => () => {} }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(), open: vi.fn(), save: vi.fn() }));

import type { DriftReport, ExecutionView } from "./api";
import { DriftPage } from "./DriftView";
import { ResponsePanel } from "./ResponsePanel";

const report = (): DriftReport => ({
  spec: { title: "Shop", version: "1", dialect: "open_api31", sha256: "ab", size_bytes: 10, operations: 2 },
  observations: 4,
  matched: 3,
  without_response: 0,
  ignored: 0,
  findings: [
    {
      kind: "undeclared_status",
      severity: "warn",
      message: "GET /orders/{id} returned 404, which is not a documented response",
      operation: "GET /orders/{id}",
      pointer: "/paths/~1orders~1{id}/get/responses",
      line: 40,
      count: 2,
      observations: ["h1", "h2"],
      suggestions: ["s404"],
    },
    {
      kind: "response_schema_mismatch",
      severity: "error",
      message: "The 200 response of GET /orders/{id} does not match its schema: `/note` is null, expected string",
      operation: "GET /orders/{id}",
      count: 1,
      observations: ["h3"],
      suggestions: ["snull"],
    },
  ],
  operations: [
    { operation: "GET /orders", method: "GET", path: "/orders", pointer: "/paths/~1orders/get", calls: 0, statuses: {}, declared_statuses: ["200"], budget: {}, findings: 0 },
    {
      operation: "GET /orders/{id}",
      method: "GET",
      path: "/orders/{id}",
      pointer: "/paths/~1orders~1{id}/get",
      calls: 3,
      statuses: { "200": 1, "404": 2 },
      declared_statuses: ["200"],
      latency_ms: { p50: 20, p95: 250, max: 250 },
      budget: { max_latency_ms: 100 },
      findings: 3,
    },
  ],
  undeclared: [{ method: "GET", path: "/customers/{customerId}", calls: 1, statuses: { "200": 1 }, examples: ["/api/customers/42"] }],
  suggestions: [
    { id: "s404", title: "Document the 404 response of GET /orders/{id}", detail: "d", kind: "addition", recommended: true, pointer: "/p", ops: [], snippet: "paths: {}\n" },
    { id: "snull", title: "Allow null at Order.note", detail: "d", kind: "relaxation", recommended: false, pointer: "/c", ops: [], snippet: "components: {}\n" },
  ],
  notes: ["response bodies not checked: history keeps no response bodies (1×)"],
});

const notify = vi.fn();
const calls = (cmd: string) => invoke.mock.calls.filter((c) => c[0] === cmd).map((c) => c[1] as Record<string, unknown>);

function backend(overrides: Record<string, (args: Record<string, unknown>) => unknown> = {}) {
  invoke.mockImplementation(async (cmd: string, args: Record<string, unknown> = {}) => {
    if (overrides[cmd]) return overrides[cmd](args);
    switch (cmd) {
      case "drift_report":
        return report();
      case "drift_reimport_plan":
        return { revision: { text: "", json_patch: [], applied: args.suggestionIds, skipped: [] }, added: ["GET /customers/{customerId}"], updated: 1, conflicts: 0, removed: 0, unchanged: 3 };
      case "drift_reimport_apply":
        return 2;
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  });
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
  notify.mockReset();
});

test("differences are listed with their revisions; additions are preselected, relaxations are not", async () => {
  backend();
  render(<DriftPage importId="i1" fileName="shop.yaml" notify={notify} onReimported={() => {}} />);
  const card = await screen.findByRole("article", { name: /returned 404/ });
  expect(within(card).getByText("×2")).toBeTruthy();
  expect(within(card).getByText("Line 40")).toBeTruthy();
  expect(within(card).getByText("Document the 404 response of GET /orders/{id}")).toBeTruthy();
  const add = screen.getByRole("checkbox", { name: "Document the 404 response of GET /orders/{id}" }) as HTMLInputElement;
  const relax = screen.getByRole("checkbox", { name: "Allow null at Order.note" }) as HTMLInputElement;
  expect([add.checked, relax.checked]).toEqual([true, false]);
  expect(screen.getByText("1/2")).toBeTruthy();
  expect(screen.getByText(/history keeps no response bodies/)).toBeTruthy();
  expect(screen.getByText("GET /customers/{customerId}")).toBeTruthy();
});

test("updating the import previews the reimport, then applies exactly the chosen revisions", async () => {
  backend();
  const onReimported = vi.fn();
  render(<DriftPage importId="i1" fileName="shop.yaml" notify={notify} onReimported={onReimported} />);
  fireEvent.click(await screen.findByRole("checkbox", { name: "Allow null at Order.note" }));
  fireEvent.click(screen.getByRole("button", { name: "Update the import…" }));
  expect(await screen.findByText(/New requests: GET \/customers\/\{customerId\}/)).toBeTruthy();
  expect(calls("drift_reimport_plan")).toEqual([{ importId: "i1", suggestionIds: ["s404", "snull"] }]);
  fireEvent.click(screen.getByRole("button", { name: "Update import" }));
  await waitFor(() => expect(calls("drift_reimport_apply")).toEqual([{ importId: "i1", suggestionIds: ["s404", "snull"] }]));
  await waitFor(() => expect(onReimported).toHaveBeenCalled());
  expect(notify).toHaveBeenCalledWith("Updated the import (2 requests changed)");
  // The report is read again afterwards.
  await waitFor(() => expect(calls("drift_report")).toHaveLength(2));
});

test("the revised spec is saved through a save grant", async () => {
  backend({
    file_choose: (a) => {
      expect(a.purpose).toBe("spec_revision_export");
      expect((a.options as { file_name: string }).file_name).toBe("shop.revised.yaml");
      return [{ token: "g-out", file_name: "shop.revised.yaml" }];
    },
    drift_export: () => 100,
  });
  render(<DriftPage importId="i1" fileName="shop.yaml" notify={notify} onReimported={() => {}} />);
  fireEvent.click(await screen.findByRole("button", { name: /Save revised spec/ }));
  await waitFor(() => expect(calls("drift_export")).toEqual([{ importId: "i1", suggestionIds: ["s404"], format: "spec", grant: "g-out" }]));
  fireEvent.click(screen.getByRole("button", { name: "Select none" }));
  expect((screen.getByRole("button", { name: /Save revised spec/ }) as HTMLButtonElement).disabled).toBe(true);
});

function sent(requestId: string | null): ExecutionView {
  return {
    record: {
      id: "11111111-1111-4111-8111-111111111111",
      request_id: requestId,
      prepared: { method: "GET", url: "https://shop.example/api/orders/8", headers: [] },
      attempts: [{ index: 1, duration_us: 1500, phases: [], dispatch: "dispatched", bytes: {} }],
      response: {
        status: 404,
        reason: "Not Found",
        headers: [],
        trailers: [],
        trailers_received: false,
        body: { completeness: "complete", wire_bytes: 2, captured_bytes: 2, display_truncated: false, content_type: "application/json" },
      },
      outcome: { transport: "completed", application: "client_error", assertions: "not_run", dispatch: "dispatched", warnings: [], summary: "HTTP 404" },
      assertion_results: [],
      findings: [],
    },
    body: { text: "{}", pretty: null, hex: null, is_binary: false, decoded: false, shown_bytes: 2, captured_bytes: 2 },
  } as unknown as ExecutionView;
}

test("a send of an imported request gets a Contract tab; other sends do not", async () => {
  const one = report();
  one.findings = [one.findings[0]];
  one.findings[0].count = 1;
  backend({ drift_check_execution: () => ({ import_id: "i1", file_name: "shop.yaml", title: "Shop", report: one }) });
  const r = render(<ResponsePanel view={sent("22222222-2222-4222-8222-222222222222")} running={false} progressBytes={null} onCancel={() => {}} />);
  fireEvent.click(await screen.findByRole("tab", { name: /Contract/ }));
  expect(screen.getByText(/returned 404, which is not a documented response/)).toBeTruthy();
  expect(screen.getByText("GET /orders/{id}", { selector: ".mono" })).toBeTruthy();
  expect(calls("drift_check_execution")).toEqual([{ executionId: "11111111-1111-4111-8111-111111111111" }]);
  cleanup();
  invoke.mockClear();
  // An unsaved draft is never checked.
  render(<ResponsePanel view={sent(null)} running={false} progressBytes={null} onCancel={() => {}} />);
  await new Promise((res) => setTimeout(res, 20));
  expect(screen.queryByRole("tab", { name: /Contract/ })).toBeNull();
  expect(calls("drift_check_execution")).toEqual([]);
  void r;
});
