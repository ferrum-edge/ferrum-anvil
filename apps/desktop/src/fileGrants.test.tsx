// The renderer never hands a file path to a file command: files come from the
// backend's own native dialog (`file_choose`) as opaque grants, and only the
// grant goes back. The Rust side is covered by crates/anvil-app/tests/
// file_grants.rs and the native E2E spec 10-file-grants.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import capabilities from "../src-tauri/capabilities/default.json";
import type { TlsProfile } from "./generated/contracts";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn(), ask: vi.fn() }));

import { api } from "./api";
import { TlsForm } from "./Dialogs";

const GRANT = { token: "fg-0123456789abcdef0123456789abcdef", file_name: "ca.pem" };

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

/** Every argument object sent to a command, flattened one level (spec inputs nest). */
function argKeys(): string[] {
  return invoke.mock.calls.flatMap(([, args]) =>
    Object.entries((args ?? {}) as Record<string, unknown>).flatMap(([k, v]) => (v && typeof v === "object" && !Array.isArray(v) ? [k, ...Object.keys(v)] : [k])),
  );
}

describe("file grants in the renderer", () => {
  it("asks the backend for the dialog and returns its grant", async () => {
    invoke.mockResolvedValueOnce([GRANT]);
    expect(await api.chooseFile("pem_file")).toEqual(GRANT);
    expect(invoke).toHaveBeenLastCalledWith("file_choose", { purpose: "pem_file", options: { multiple: false } });
    invoke.mockResolvedValueOnce([]);
    expect(await api.chooseFile("bundle_export", { file_name: "backup.anvil" })).toBeNull();
    expect(invoke).toHaveBeenLastCalledWith("file_choose", { purpose: "bundle_export", options: { file_name: "backup.anvil", multiple: false } });
  });

  it("passes only the grant to file commands", async () => {
    invoke.mockResolvedValue(undefined);
    const t = GRANT.token;
    await api.readTextFile(t, "ws", null);
    await api.attachmentAdd(t, null);
    await api.importPreview(t, null, "duplicate");
    await api.importApply(t, null, "duplicate");
    await api.exportToPath(null, "share_safely", null, t);
    await api.addDataset("ws", t, "users", []);
    await api.exportLoadReport("run", "json", t);
    await api.exportRunReport("run", "junit", t);
    await api.specPreview({ kind: "file", grant: t }, {} as never);
    expect(argKeys()).not.toContain("path");
    for (const [, args] of invoke.mock.calls) expect(JSON.stringify(args)).toContain(t);
  });

  it("loads a CA file through a grant, never a path", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "file_choose") return [GRANT];
      if (cmd === "read_text_file") return { text: "-----BEGIN CERTIFICATE-----" };
      throw new Error(`unexpected ${cmd}`);
    });
    const onChange = vi.fn();
    const p = { id: "t", workspace_id: "ws", name: "p", verify: true, use_system_roots: true, extra_roots_pem: [], bindings: [] } as unknown as TlsProfile;
    render(<TlsForm p={p} onChange={onChange} />);
    fireEvent.click(screen.getByText("Add CA from file…"));
    await waitFor(() => expect(onChange).toHaveBeenCalled());
    expect(invoke.mock.calls.map(([cmd]) => cmd)).toEqual(["file_choose", "read_text_file"]);
    expect(invoke.mock.calls[0][1]).toEqual({ purpose: "pem_file", options: { multiple: false } });
    expect(invoke.mock.calls[1][1]).toEqual({ grant: GRANT.token, workspaceId: "ws", storeAsSecret: null, base64: false });
    expect(onChange.mock.calls[0][0].extra_roots_pem).toEqual(["-----BEGIN CERTIFICATE-----"]);
  });

  it("does not let the webview open a file dialog or the filesystem", () => {
    const perms = capabilities.permissions as string[];
    expect(perms).not.toContain("dialog:allow-save");
    expect(perms).not.toContain("dialog:allow-open");
    expect(perms).not.toContain("dialog:default");
    expect(perms.filter((p) => p.startsWith("fs:"))).toEqual([]);
  });

  it("uses the dialog plugin only for confirmations", () => {
    const sources = import.meta.glob(["./*.tsx", "./*.ts", "!./*.test.tsx", "!./*.test.ts"], { query: "?raw", import: "default", eager: true }) as Record<string, string>;
    const importers: Record<string, string[]> = {};
    for (const [file, text] of Object.entries(sources)) {
      for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*"@tauri-apps\/plugin-dialog"/g)) {
        importers[file] = m[1].split(",").map((s) => s.trim()).filter(Boolean);
      }
    }
    expect(importers).toEqual({ "./Workbench.tsx": ["ask"] });
  });
});
