// Export dialog: the preview lists each linked local file path the bundle
// carries, with the request or dataset that names it, and shows a Windows
// verbatim path without its `\\?\` prefix. A full-backup preview has no list.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(), open: vi.fn(), save: vi.fn() }));

import { ExportDialog, displayLinkedFile } from "./Dialogs";
import type { ExportPreview } from "./api";
import type { Workspace } from "./generated/contracts";

const WORKSPACE = { id: "ws-1", schema_version: 1, created_at: "", updated_at: "", name: "W" } as Workspace;

function preview(linked_files?: string[]): ExportPreview {
  return {
    manifest: {
      mode: "share_safely",
      counts: { requests: 2 },
      excluded: [],
      placeholders: [],
      device_bindings: ["Requests or datasets name linked local files; attach them, or choose them again on the target machine."],
      content_warnings: [],
    },
    secrets_included: 0,
    literals_moved: 0,
    ...(linked_files ? { linked_files } : {}),
  };
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

function backend(p: ExportPreview) {
  invoke.mockImplementation(async (cmd: string) => {
    if (cmd === "export_preview") return p;
    throw new Error(`unexpected command ${cmd}`);
  });
}

describe("export linked files", () => {
  it("leaves API standards out by default and previews the explicit opt-in", async () => {
    backend(preview());
    render(<ExportDialog workspace={WORKSPACE} onClose={vi.fn()} notify={vi.fn()} />);
    const option = await screen.findByRole("checkbox", { name: "Include API standards" });
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("export_preview", expect.objectContaining({ includeStandards: false })),
    );
    fireEvent.click(option);
    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("export_preview", expect.objectContaining({ includeStandards: true })),
    );
  });

  it("lists each linked file path under the rebinding warning", async () => {
    backend(preview(["request 'Upload': /home/me/upload.bin", "dataset 'Users': \\\\?\\C:\\Users\\me\\users.csv"]));
    render(<ExportDialog workspace={WORKSPACE} onClose={vi.fn()} notify={vi.fn()} />);
    const list = await screen.findByTestId("export-linked-files");
    const items = Array.from(list.querySelectorAll("li")).map((li) => li.textContent);
    expect(items).toEqual(["request 'Upload': /home/me/upload.bin", "dataset 'Users': C:\\Users\\me\\users.csv"]);
    expect(list.textContent).not.toContain("\\\\?\\");
  });

  it("shows no list when the preview has none", async () => {
    backend(preview());
    render(<ExportDialog workspace={null} onClose={vi.fn()} notify={vi.fn()} />);
    await screen.findByText(/Needs rebinding on the other machine/);
    expect(screen.queryByTestId("export-linked-files")).toBeNull();
  });

  it("drops only the verbatim prefix of the path", () => {
    expect(displayLinkedFile("request 'Up': \\\\?\\UNC\\server\\share\\a.bin")).toBe("request 'Up': \\\\server\\share\\a.bin");
    expect(displayLinkedFile("request 'a': b': \\\\?\\C:\\x")).toBe("request 'a': b': C:\\x");
    expect(displayLinkedFile("request 'Up': C:\\Users\\me\\a.bin")).toBe("request 'Up': C:\\Users\\me\\a.bin");
    expect(displayLinkedFile("request 'Up': /tmp/a.bin")).toBe("request 'Up': /tmp/a.bin");
  });
});
