// Renderer tests for the API contract view (jsdom; the Tauri backend is a
// scripted fake). Only OpenAPI imports are offered; picking one lints its
// stored original and lists each finding with its line and fix; severity
// cards filter the list; exports lint the same target again; ruleset changes
// go through their own commands and re-run the shown check; a refused ruleset
// is reported, not kept; and a workspace switch drops the other workspace's
// selection.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: async () => () => {} }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(), open: vi.fn(), save: vi.fn() }));

import type { LintReport, SpecSourceRecord, StandardsView } from "./api";
import { ContractView } from "./ContractView";

const now = "2026-09-30T10:00:00Z";
const source = (id: string, kind: string, title: string, dialect = "open_api31"): SpecSourceRecord => ({
  source: { import_id: id, kind, dialect, title, sha256: "ab", size_bytes: 10, imported_at: now },
  workspace_id: "A",
  original_sha256: "ab",
  file_name: `${title.toLowerCase()}.yaml`,
});

const report = (): LintReport => ({
  spec: { title: "Orders", version: "1.0.0", dialect: "open_api31", sha256: "ab", size_bytes: 10, operations: 2 },
  rulesets: [{ name: "Anvil recommended", source: "anvil:recommended", builtin: true, sha256: "x" }],
  rules_run: 25,
  rules_skipped: 0,
  counts: { error: 1, warn: 1, info: 0, hint: 0 },
  dropped: 0,
  findings: [
    {
      rule: "path-params-declared",
      severity: "error",
      message: "GET /v1/orders/{orderId} uses path parameter(s) orderId that are not declared.",
      pointer: "/paths/~1v1~1orders~1{orderId}/get",
      line: 42,
      column: 5,
      target: "operation",
      label: "GET /v1/orders/{orderId}",
      how_to_fix: "Add each one to `parameters` with `in: path` and `required: true`.",
      ruleset: "Anvil recommended",
    },
    {
      rule: "server-https",
      severity: "warn",
      message: "Server http://orders.example/v1 uses plain HTTP.",
      pointer: "/servers/0",
      line: 9,
      column: 3,
      target: "server",
      label: "server http://orders.example/v1",
      ruleset: "Anvil recommended",
    },
  ],
});

let standards: StandardsView;
const notify = vi.fn();

function backend(overrides: Record<string, (args: Record<string, unknown>) => unknown> = {}) {
  standards = {
    standards: { include_recommended: true, rulesets: [] },
    sources: [{ name: "Anvil recommended", source: "anvil:recommended", builtin: true, sha256: "x" }],
    rules: [{ id: "path-params-declared", severity: "error", given: "operation", formats: [], ruleset: "Anvil recommended", description: "Declared path params." }],
    disabled: [],
  };
  invoke.mockImplementation(async (cmd: string, args: Record<string, unknown> = {}) => {
    if (overrides[cmd]) return overrides[cmd](args);
    switch (cmd) {
      case "spec_sources":
        return args.workspaceId === "A" ? [source("i1", "open_api", "Orders"), source("i2", "postman_collection", "Postman thing", "postman_v21")] : [];
      case "standards_view":
        return standards;
      case "standards_lint":
        return report();
      case "standards_set_recommended":
        standards = { ...standards, standards: { ...standards.standards, include_recommended: args.include as boolean } };
        return standards.standards;
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  });
}

const calls = (cmd: string) => invoke.mock.calls.filter((c) => c[0] === cmd).map((c) => c[1] as Record<string, unknown>);

afterEach(() => {
  cleanup();
  invoke.mockReset();
  notify.mockReset();
});

test("only OpenAPI imports are offered, and picking one lists its findings with line and fix", async () => {
  backend();
  render(<ContractView workspaceId="A" notify={notify} />);
  fireEvent.click(await screen.findByText("Orders"));
  expect(screen.queryByText("Postman thing")).toBeNull();
  expect(await screen.findByText(/uses path parameter\(s\) orderId/)).toBeTruthy();
  expect(calls("standards_lint")[0]).toEqual({ target: { kind: "import", import_id: "i1" } });
  expect(screen.getByText("Line 42:5")).toBeTruthy();
  // The fix renders `backticked` names as code.
  expect(screen.getByText("parameters", { selector: "code" }).parentElement?.textContent).toBe("Add each one to parameters with in: path and required: true.");
  expect(screen.getByText("does not meet the standards")).toBeTruthy();
  // The severity cards filter the list.
  fireEvent.click(screen.getByRole("button", { name: /Warnings/ }));
  expect(screen.queryByText(/uses path parameter/)).toBeNull();
  expect(screen.getByText(/uses plain HTTP/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /Warnings/ }));
  expect(screen.getByText(/uses path parameter/)).toBeTruthy();
});

test("an export lints the same target again and writes through a save grant", async () => {
  backend({
    file_choose: (a) => {
      expect(a.purpose).toBe("lint_report_export");
      return [{ token: "g-out", file_name: "orders.standards.sarif" }];
    },
    standards_report_export: () => 1234,
  });
  render(<ContractView workspaceId="A" notify={notify} />);
  fireEvent.click(await screen.findByText("Orders"));
  await screen.findByText(/uses path parameter/);
  fireEvent.click(screen.getByRole("button", { name: /SARIF/ }));
  await waitFor(() => expect(calls("standards_report_export")).toHaveLength(1));
  expect(calls("standards_report_export")[0]).toEqual({
    target: { kind: "import", import_id: "i1" },
    format: "sarif",
    artifact: "orders.yaml",
    grant: "g-out",
  });
  await waitFor(() => expect(notify).toHaveBeenCalledWith("Exported to orders.standards.sarif"));
});

test("a spec file is linted through its grant", async () => {
  backend({ file_choose: () => [{ token: "g-spec", file_name: "billing.yaml" }] });
  render(<ContractView workspaceId="B" notify={notify} />);
  fireEvent.click((await screen.findAllByRole("button", { name: /Check a spec file/ }))[0]);
  await screen.findByText(/uses path parameter/);
  expect(calls("standards_lint")[0]).toEqual({ target: { kind: "spec", input: { kind: "file", grant: "g-spec" } } });
});

test("changing the standards re-runs the shown check; a refused ruleset is reported", async () => {
  backend({
    file_choose: (a) => {
      expect(a.purpose).toBe("ruleset");
      return [{ token: "g-rules", file_name: "team.yaml" }];
    },
    standards_add: () => {
      throw "team.yaml: rule 'x': no inherited rule has this id";
    },
  });
  render(<ContractView workspaceId="A" notify={notify} />);
  fireEvent.click(await screen.findByText("Orders"));
  await screen.findByText(/uses path parameter/);
  const recommended = screen.getByRole("checkbox", { name: "Include Anvil recommended rules" }) as HTMLInputElement;
  expect(recommended.checked).toBe(true);
  fireEvent.click(recommended);
  await waitFor(() => expect(calls("standards_set_recommended")).toEqual([{ include: false }]));
  await waitFor(() => expect(calls("standards_lint")).toHaveLength(2));
  fireEvent.click(screen.getByRole("button", { name: "Add a ruleset file" }));
  await waitFor(() => expect(notify).toHaveBeenCalledWith(expect.stringContaining("no inherited rule")));
  expect(calls("standards_add")).toEqual([{ grant: "g-rules" }]);
});

test("rules in effect are listed with where they come from", async () => {
  backend();
  render(<ContractView workspaceId="A" notify={notify} />);
  fireEvent.click(await screen.findByText("Rules in effect"));
  expect(await screen.findByText("Declared path params.")).toBeTruthy();
  expect(screen.getByText(/Layered in order: Anvil recommended/)).toBeTruthy();
});

test("switching workspaces drops the previous workspace's selected import", async () => {
  backend();
  const r = render(<ContractView workspaceId="A" notify={notify} />);
  fireEvent.click(await screen.findByText("Orders"));
  await screen.findByText(/uses path parameter/);
  r.rerender(<ContractView workspaceId="B" notify={notify} />);
  await waitFor(() => expect(screen.queryByText(/uses path parameter/)).toBeNull());
  expect(screen.getByText(/Import an OpenAPI or Swagger description/)).toBeTruthy();
});
