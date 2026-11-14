// The reimport dialog (jsdom; the Tauri backend is a scripted fake): it plans
// against the import and source the user picked, shows what would change,
// sends back exactly the native approval with the user's decisions, asks
// again before replacing edits or deleting, and never applies a stale plan.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: async () => () => {} }));

import { SpecReimportDialog, planChanges } from "./SpecReimport";
import type { ReimportPlan, ReviewedReimport, SpecSourceRecord } from "./api";
import type { RequestDefinition } from "./generated/contracts";

const now = "2026-01-01T00:00:00Z";
const record = (id: string, title: string, file: string): SpecSourceRecord => ({
  source: { import_id: id, kind: "open_api", dialect: "open_api31", title, sha256: "s", size_bytes: 10, imported_at: now },
  workspace_id: "ws",
  original_sha256: "o",
  file_name: file,
});
const req = (id: string, name: string, method = "GET") => ({ id, name, workspace_id: "ws", spec: { method, url: `https://${id}.invalid/` } }) as unknown as RequestDefinition;
const empty: ReimportPlan = {
  import_id: "next",
  added: [],
  added_folders: [],
  updated: [],
  conflicts: [],
  preserved_edits: [],
  unchanged: [],
  removed: [],
  unlinked: [],
  scope_updated: [],
  scope_conflicts: [],
  scope_preserved_edits: [],
  scope_removed: [],
};
const plan: ReimportPlan = {
  ...empty,
  added: [req("new", "Create order", "POST")],
  updated: [{ existing_id: "r1", operation_key: "listOrders", user_edited: false, changed_fields: ["url"], upstream_fields: ["spec"], fresh: req("f1", "List orders") }],
  conflicts: [
    {
      existing_id: "r2",
      operation_key: "getOrder",
      user_edited: true,
      changed_fields: ["headers", "name"],
      upstream_fields: ["spec", "name"],
      conflicting_fields: ["name"],
      fresh: req("f2", "Get order"),
    },
  ],
  removed: [{ existing_id: "r3", operation_key: "deleteOrder", user_edited: true }],
  unchanged: ["r4"],
  scope_conflicts: [{ key: "variables/region", label: "variable region", user_edited: true }],
  scope_removed: [{ key: "environments/e1", label: 'environment "Staging"', user_edited: false, whole_environment: true }],
};
const binding = { source_sha256: "source-digest", plan_sha256: "plan-digest" };
const reviewed: ReviewedReimport = { plan, approval: { binding, scope: "native-scope" } };
const NONE = { overwrite: [], delete: [], overwrite_scope: [], delete_scope: [] };
const names: Record<string, string> = { r2: "My order", r3: "Remove order" };

function backend(overrides: Record<string, (args: Record<string, unknown>) => unknown> = {}) {
  invoke.mockImplementation(async (cmd: string, args: Record<string, unknown> = {}) => {
    if (overrides[cmd]) return overrides[cmd](args);
    switch (cmd) {
      case "spec_sources":
        return [record("i1", "Orders", "orders.yaml"), record("i2", "Billing", "billing.json")];
      case "file_choose":
        return [{ token: "grant-v2", file_name: "orders-v2.yaml" }];
      case "spec_reimport_plan":
        return reviewed;
      case "spec_reimport_apply":
        return 3;
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  });
}

const calls = (cmd: string) => invoke.mock.calls.filter((c) => c[0] === cmd).map((c) => c[1] as Record<string, unknown>);
const onReimported = vi.fn();
const onClose = vi.fn();

afterEach(() => {
  cleanup();
  invoke.mockReset();
  onReimported.mockReset();
  onClose.mockReset();
});

async function open() {
  render(<SpecReimportDialog workspaceId="ws" workspaceName="Shop" requestName={(id) => names[id]} onClose={onClose} onReimported={onReimported} />);
  const dialog = await screen.findByRole("dialog", { name: "Reimport a changed spec" });
  await within(dialog).findByLabelText("Import to update");
  return dialog;
}

async function chooseAndReview(dialog: HTMLElement) {
  fireEvent.click(within(dialog).getByRole("button", { name: /Choose the new version/ }));
  await within(dialog).findByText("orders-v2.yaml");
  fireEvent.click(within(dialog).getByRole("button", { name: "Review changes" }));
  await within(dialog).findByText("Edited here and changed in the source");
}

const applyButton = (dialog: HTMLElement) => within(dialog).getByRole("button", { name: /Apply|Confirm and apply/ }) as HTMLButtonElement;

it("plans the chosen import against the chosen file and applies exactly the reviewed approval", async () => {
  backend();
  const dialog = await open();
  expect(calls("spec_sources")).toEqual([{ workspaceId: "ws" }]);
  fireEvent.change(within(dialog).getByLabelText("Import to update"), { target: { value: "i2" } });
  expect(within(dialog).queryByRole("button", { name: /Apply/ })).toBeNull();
  await chooseAndReview(dialog);
  expect(calls("file_choose")[0]).toMatchObject({ purpose: "spec_source" });
  expect(calls("spec_reimport_plan")).toEqual([{ importId: "i2", input: { kind: "file", grant: "grant-v2" } }]);

  // What would change, by the stored names where they are known.
  expect(dialog.textContent).toContain("POST Create order");
  expect(dialog.textContent).toContain("both changed name");
  within(dialog).getByLabelText("Overwrite your edits to My order");
  within(dialog).getByLabelText("Delete Remove order");
  within(dialog).getByLabelText('Delete environment "Staging"');

  // Nothing ticked: no edit is replaced and nothing deleted, so it applies at once.
  fireEvent.click(applyButton(dialog));
  await waitFor(() =>
    expect(calls("spec_reimport_apply")).toEqual([{ importId: "i2", input: { kind: "file", grant: "grant-v2" }, decisions: NONE, approval: reviewed.approval }]),
  );
  await waitFor(() => expect(onReimported).toHaveBeenCalledWith({ requests: 3, fileName: "orders-v2.yaml" }));
});

it("asks again before replacing edits or deleting, and sends the ticked ids and keys", async () => {
  backend();
  const dialog = await open();
  await chooseAndReview(dialog);
  fireEvent.click(within(dialog).getByLabelText("Overwrite your edits to My order"));
  fireEvent.click(within(dialog).getByLabelText("Delete Remove order"));
  fireEvent.click(within(dialog).getByLabelText("Overwrite your edits to variable region"));
  fireEvent.click(within(dialog).getByLabelText('Delete environment "Staging"'));

  fireEvent.click(within(dialog).getByRole("button", { name: /Apply…/ }));
  const warning = await within(dialog).findByText(/will be replaced with the source's version/);
  expect(warning.textContent).toContain("2 items");
  expect(dialog.textContent).toContain("2 items the source no longer has will be deleted from “Shop”");
  expect(calls("spec_reimport_apply")).toHaveLength(0);

  // Back keeps the choices and applies nothing.
  fireEvent.click(within(dialog).getByRole("button", { name: "Back" }));
  expect(within(dialog).queryByText(/will be replaced/)).toBeNull();
  expect(calls("spec_reimport_apply")).toHaveLength(0);

  fireEvent.click(within(dialog).getByRole("button", { name: /Apply…/ }));
  fireEvent.click(await within(dialog).findByRole("button", { name: /Confirm and apply/ }));
  await waitFor(() => expect(calls("spec_reimport_apply")).toHaveLength(1));
  expect(calls("spec_reimport_apply")[0]).toEqual({
    importId: "i1",
    input: { kind: "file", grant: "grant-v2" },
    decisions: { overwrite: ["r2"], delete: ["r3"], overwrite_scope: ["variables/region"], delete_scope: ["environments/e1"] },
    approval: reviewed.approval,
  });
});

it("drops the plan when the source or the import changes, and ignores a plan that arrives late", async () => {
  let finish!: (r: ReviewedReimport) => void;
  backend({
    spec_reimport_plan: () =>
      new Promise<ReviewedReimport>((resolve) => {
        finish = resolve;
      }),
  });
  const dialog = await open();
  const paste = within(dialog).getByLabelText(/paste the new version/);
  fireEvent.change(paste, { target: { value: '{"openapi":"3.1.0"}' } });
  fireEvent.click(within(dialog).getByRole("button", { name: "Review changes" }));
  await waitFor(() => expect(calls("spec_reimport_plan")).toEqual([{ importId: "i1", input: { kind: "text", text: '{"openapi":"3.1.0"}', name: "pasted.txt" } }]));
  fireEvent.change(paste, { target: { value: '{"openapi":"3.1.1"}' } });
  await act(async () => finish(reviewed));
  expect(within(dialog).queryByText("Edited here and changed in the source")).toBeNull();
  expect(within(dialog).queryByRole("button", { name: /Apply/ })).toBeNull();

  // A plan shown, then another import picked: the plan is gone.
  fireEvent.click(within(dialog).getByRole("button", { name: "Review changes" }));
  await act(async () => finish(reviewed));
  await within(dialog).findByText("Edited here and changed in the source");
  fireEvent.change(within(dialog).getByLabelText("Import to update"), { target: { value: "i2" } });
  expect(within(dialog).queryByText("Edited here and changed in the source")).toBeNull();
  expect(within(dialog).queryByRole("button", { name: /Apply/ })).toBeNull();
});

it("shows a refused apply and requires a new review", async () => {
  backend({
    spec_reimport_apply: () => {
      throw "the source or plan changed since review; preview it again";
    },
  });
  const dialog = await open();
  await chooseAndReview(dialog);
  fireEvent.click(applyButton(dialog));
  const alert = await within(dialog).findByRole("alert");
  expect(alert.textContent).toContain("the source or plan changed since review");
  expect(alert.textContent).toContain("Review the changes again");
  expect(within(dialog).queryByRole("button", { name: /Apply/ })).toBeNull();
  expect(onReimported).not.toHaveBeenCalled();
});

it("shows why a plan could not be made", async () => {
  backend({
    spec_reimport_plan: () => {
      throw "the import's root folder was deleted; import the source again";
    },
  });
  const dialog = await open();
  fireEvent.click(within(dialog).getByRole("button", { name: /Choose the new version/ }));
  await within(dialog).findByText("orders-v2.yaml");
  fireEvent.click(within(dialog).getByRole("button", { name: "Review changes" }));
  expect((await within(dialog).findByRole("alert")).textContent).toContain("root folder was deleted");
  expect(within(dialog).queryByRole("button", { name: /Apply/ })).toBeNull();
});

it("says so when the workspace has no import", async () => {
  backend({ spec_sources: () => [] });
  render(<SpecReimportDialog workspaceId="ws" workspaceName="Shop" requestName={() => undefined} onClose={onClose} onReimported={onReimported} />);
  const dialog = await screen.findByRole("dialog", { name: "Reimport a changed spec" });
  await within(dialog).findByText(/“Shop” has no imported spec or collection/);
  expect(within(dialog).queryByRole("button", { name: "Review changes" })).toBeNull();
});

it("says when a new version changes nothing", async () => {
  backend({ spec_reimport_plan: () => ({ plan: { ...empty, unchanged: ["r1"] }, approval: reviewed.approval }) });
  expect(planChanges(empty)).toBe(false);
  expect(planChanges(plan)).toBe(true);
  const dialog = await open();
  fireEvent.click(within(dialog).getByRole("button", { name: /Choose the new version/ }));
  await within(dialog).findByText("orders-v2.yaml");
  fireEvent.click(within(dialog).getByRole("button", { name: "Review changes" }));
  await within(dialog).findByText(/changes nothing here/);
  expect(applyButton(dialog).textContent).toContain("Apply");
});
