import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: async () => () => {} }));

import { SpecImport } from "./SpecImport";
import { DEFAULT_IMPORT_OPTIONS, type SpecPreview } from "./api";

const binding = { source_sha256: "source-digest", plan_sha256: "plan-digest" };
const reviewed: SpecPreview = {
  binding,
  approval: { binding, scope: "native-scope" },
  detected: { kind: "openapi", dialect: "open_api31", syntax: "json" },
  report: {
    warnings: [],
    unsupported: [],
    external_refs: [],
    scripts: [],
    inactive_settings: [],
    redactions: [],
    required_variables: [],
    counts: {
      operations_found: 1,
      requests: 1,
      folders: 0,
      environments: 0,
      skipped_operations: 0,
      warnings: 0,
    },
  },
  folders: 0,
  requests: 1,
  environments: 0,
  sample: ["GET reviewed"],
};

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

function boot() {
  render(<SpecImport workspaceId="ws" workspaceName="Workspace" onImported={vi.fn()} />);
  fireEvent.change(screen.getByPlaceholderText(/curl -X POST/), {
    target: { value: "curl https://reviewed.invalid" },
  });
}

it("requires review and sends the exact native approval and destination to apply", async () => {
  invoke.mockImplementation(async (cmd: string) => (cmd === "spec_preview" ? reviewed : {}));
  boot();
  const apply = screen.getByRole("button", { name: /^Import$/ }) as HTMLButtonElement;
  expect(apply.disabled).toBe(true);
  fireEvent.click(screen.getByLabelText(/Into “Workspace”/));
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  await waitFor(() => expect(apply.disabled).toBe(false));
  fireEvent.click(apply);
  await waitFor(() =>
    expect(invoke).toHaveBeenCalledWith("spec_import", {
      input: { kind: "text", text: "curl https://reviewed.invalid", name: "pasted.txt" },
      options: DEFAULT_IMPORT_OPTIONS,
      target: { kind: "workspace", workspace_id: "ws" },
      approval: reviewed.approval,
    }),
  );
});

it("invalidates approval on destination changes and failed native verification", async () => {
  invoke.mockImplementation(async (cmd: string) => {
    if (cmd === "spec_preview") return reviewed;
    throw new Error("the source or plan changed since review; preview it again");
  });
  boot();
  const apply = screen.getByRole("button", { name: /^Import$/ }) as HTMLButtonElement;
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  await waitFor(() => expect(apply.disabled).toBe(false));
  fireEvent.click(screen.getByLabelText(/Into “Workspace”/));
  expect(apply.disabled).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  await waitFor(() => expect(apply.disabled).toBe(false));
  fireEvent.click(apply);
  await screen.findByText(/source or plan changed/);
  expect(apply.disabled).toBe(true);
});

it("discards a preview completed after its source or options were edited", async () => {
  let finish!: (value: SpecPreview) => void;
  invoke.mockReturnValue(
    new Promise<SpecPreview>((resolve) => {
      finish = resolve;
    }),
  );
  boot();
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  fireEvent.change(screen.getByPlaceholderText(/curl -X POST/), {
    target: { value: "curl https://changed.invalid" },
  });
  fireEvent.click(screen.getByLabelText("Include optional fields"));
  await act(async () => finish(reviewed));
  expect(screen.queryByText("Requests / folders / environments")).toBeNull();
  const apply = screen.getByRole("button", { name: /^Import$/ }) as HTMLButtonElement;
  expect(apply.disabled).toBe(true);
});
