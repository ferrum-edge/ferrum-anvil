// Import dialog: a preview or import runs under a fresh attempt id, Cancel
// ends it through `import_cancel` while its key is derived (an import that
// has begun writing reports its own result instead), and a busy refusal is
// worded rather than shown as a raw error.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(), open: vi.fn(), save: vi.fn() }));

import { IMPORT_BUSY_TEXT, ImportDialog } from "./Dialogs";
import type { ImportReport } from "./api";

const GRANT = { token: "fg-0123456789abcdef0123456789abcdef", file_name: "backup.anvil" };

const report: ImportReport = {
  plan: {
    policy: "merge",
    to_create: 2,
    to_replace: 0,
    skipped_existing: 0,
    conflicts: [],
    foreign_secrets: [],
    foreign_objects: [],
    existing_workspaces: [],
  },
  warnings: [],
  secrets_restored: true,
  missing_secrets: [],
  linked_files: [],
  workspaces: ["W"],
  workspace_ids: ["ws-1"],
  full_backup: true,
  api_standards_count: 0,
  bundle_sha256: "abc",
};

type Args = Record<string, unknown>;

/** A backend reply the test settles itself. */
function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function backend(overrides: Record<string, (args: Args) => unknown>) {
  invoke.mockImplementation(async (cmd: string, args?: Args) => {
    if (overrides[cmd]) return overrides[cmd](args ?? {});
    if (cmd === "file_choose") return [GRANT];
    throw new Error(`unexpected command ${cmd}`);
  });
}

const calls = (cmd: string) => invoke.mock.calls.filter(([c]) => c === cmd).map(([, args]) => args as Args);
const button = (name: string) => screen.getByRole("button", { name }) as HTMLButtonElement;

async function open() {
  const onImported = vi.fn();
  const onClose = vi.fn();
  render(<ImportDialog onClose={onClose} onImported={onImported} workspaceId={null} workspaceName={null} onSpecImported={vi.fn()} />);
  fireEvent.click(screen.getByRole("tab", { name: "Anvil bundle / backup" }));
  fireEvent.click(screen.getByText("Choose bundle…"));
  await screen.findByText(GRANT.file_name);
  fireEvent.change(screen.getByLabelText("Passphrase (for encrypted bundles)"), { target: { value: "backup passphrase" } });
  return { onImported, onClose };
}

async function previewed() {
  const opened = await open();
  fireEvent.click(button("Preview"));
  await waitFor(() => expect(button("Import").disabled).toBe(false));
  return opened;
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

describe("import dialog cancellation", () => {
  it("cancels a preview while its key is derived", async () => {
    const reply = deferred<ImportReport>();
    backend({
      import_preview: () => reply.promise,
      import_cancel: () => {
        reply.reject("CANCELED");
        return true;
      },
    });
    await open();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    fireEvent.click(button("Preview"));
    await screen.findByRole("button", { name: "Cancel" });
    fireEvent.click(screen.getByRole("tab", { name: "API spec or collection" }));
    expect(screen.getByRole("tab", { name: "Anvil bundle / backup" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("button", { name: "Cancel" })).toBeTruthy();
    const attempt = calls("import_preview")[0].attempt;
    expect(typeof attempt).toBe("string");
    expect(attempt).not.toBe("");
    expect(button("Previewing…").disabled).toBe(true);
    expect(button("Import").disabled).toBe(true);
    expect(screen.getByRole("status").textContent).toContain("deriving its key");

    fireEvent.click(button("Cancel"));
    await screen.findByText("Preview canceled.");
    expect(calls("import_cancel")).toEqual([{ attempt }]);
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    expect(button("Preview").disabled).toBe(false);
    expect(document.querySelector(".bad-box")).toBeNull();
  });

  it("cancels an import before it writes, and imports nothing", async () => {
    const reply = deferred<ImportReport>();
    backend({
      import_preview: () => report,
      import_apply: () => reply.promise,
      import_cancel: () => {
        reply.reject("CANCELED");
        return true;
      },
    });
    const { onImported, onClose } = await previewed();
    fireEvent.click(button("Import"));
    await screen.findByRole("button", { name: "Cancel" });
    const attempt = calls("import_apply")[0].attempt;
    expect(typeof attempt).toBe("string");
    // Each run has its own attempt id.
    expect(attempt).not.toBe(calls("import_preview")[0].attempt);
    expect(button("Importing…").disabled).toBe(true);

    fireEvent.click(button("Cancel"));
    await screen.findByText("Import canceled; nothing was imported.");
    expect(calls("import_cancel")).toEqual([{ attempt }]);
    expect(onImported).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    // The preview stays, so the import can be started again.
    expect(button("Import").disabled).toBe(false);
  });

  it("reports an import whose writes began before the cancel", async () => {
    const reply = deferred<ImportReport>();
    backend({ import_preview: () => report, import_apply: () => reply.promise, import_cancel: () => true });
    const { onImported, onClose } = await previewed();
    fireEvent.click(button("Import"));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(button("Canceling…").disabled).toBe(true));
    expect(screen.getByRole("status").textContent).toContain("already begun writing finishes");
    reply.resolve(report);
    await waitFor(() => expect(onImported).toHaveBeenCalledWith(["ws-1"]));
    expect(onClose).toHaveBeenCalled();
  });

  it("words a busy refusal instead of showing the raw code", async () => {
    backend({
      import_preview: () => {
        throw "IMPORT_BUSY";
      },
    });
    await open();
    fireEvent.click(button("Preview"));
    await screen.findByText(IMPORT_BUSY_TEXT);
    expect(screen.queryByText("IMPORT_BUSY")).toBeNull();
    expect(document.querySelector(".bad-box")).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    expect(button("Preview").disabled).toBe(false);
  });

  it("cancels a running preview when the dialog is closed", async () => {
    const reply = deferred<ImportReport>();
    backend({ import_preview: () => reply.promise, import_cancel: () => true });
    const { onClose } = await open();
    fireEvent.click(button("Preview"));
    await screen.findByRole("button", { name: "Cancel" });
    const attempt = calls("import_preview")[0].attempt;
    fireEvent.click(button("Close"));
    expect(onClose).toHaveBeenCalled();
    await waitFor(() => expect(calls("import_cancel")).toEqual([{ attempt }]));
  });
});

describe("import dialog: linked local files", () => {
  it("points to where each linked file is chosen on this device", async () => {
    backend({ import_preview: () => ({ ...report, linked_files: ["request 'Upload': /home/me/upload.bin"] }) });
    await previewed();
    expect(screen.getByTestId("import-linked-files").textContent).toContain("Choose file…");
  });

  it("says nothing when the bundle names no linked file", async () => {
    backend({ import_preview: () => report });
    await previewed();
    expect(screen.queryByTestId("import-linked-files")).toBeNull();
  });
});
