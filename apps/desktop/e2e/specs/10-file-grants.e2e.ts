// File commands accept only grants from the backend's own native dialog. The
// real IPC refuses a file path, a made-up grant and the old path arguments,
// and nothing on disk is read into the webview or written.
import { expect } from "@wdio/globals";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type IpcResult, invoke, waitForWorkbench } from "../helpers";

const CANARY = "anvil-e2e-file-grant-canary";
const UNKNOWN = "the file selection is unknown or has expired";
const IMPORT_OPTIONS = {
  mode: "sample",
  seed: 0,
  group_by: "tags",
  include_optional: false,
  server_index: 0,
  include_credentials: false,
  max_operations: 5000,
  max_bytes: 32 * 1024 * 1024,
  max_ref_depth: 32,
  max_nodes: 2_000_000,
  max_ref_expansions: 250_000,
  max_sample_nodes: 20_000,
};

describe("file grants", () => {
  let dir = "";
  let source = "";
  let workspaceId = "";

  before(async () => {
    await waitForWorkbench();
    dir = mkdtempSync(join(tmpdir(), "anvil-e2e-grants-"));
    source = join(dir, "source.json");
    writeFileSync(source, JSON.stringify({ canary: CANARY }));
    const list = await invoke<{ id: string }[]>("workspaces_list");
    expect(list.err).toBeUndefined();
    workspaceId = list.ok![0].id;
  });

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function expectRefused(label: string, r: IpcResult<unknown>, reason?: string): void {
    expect({ label, ok: r.ok }).toEqual({ label, ok: undefined });
    expect(r.err ?? "").not.toContain(CANARY);
    if (reason) expect({ label, err: r.err }).toEqual({ label, err: expect.stringContaining(reason) });
  }

  it("never reads a path or a made-up grant", async () => {
    for (const grant of [source, `fg-${"0".repeat(32)}`, "source.json"]) {
      const calls: [string, Record<string, unknown>][] = [
        ["read_text_file", { grant, workspaceId: null, storeAsSecret: null, base64: false }],
        ["read_text_file", { grant, workspaceId: null, storeAsSecret: "p12", base64: true }],
        ["attachment_add", { grant, mediaType: null }],
        ["import_preview", { grant, passphrase: null, conflictPolicy: "duplicate" }],
        ["import_apply", { grant, passphrase: null, conflictPolicy: "duplicate" }],
        ["dataset_add", { workspaceId, grant, name: "d", sensitiveColumns: [] }],
        ["spec_preview", { input: { kind: "file", grant }, options: IMPORT_OPTIONS }],
      ];
      for (const [cmd, args] of calls) expectRefused(`${cmd} ${grant}`, await invoke(cmd, args), UNKNOWN);
    }
  });

  it("has no command argument that takes a path", async () => {
    const calls: [string, Record<string, unknown>][] = [
      ["read_text_file", { path: source, workspaceId: null, storeAsSecret: null, base64: false }],
      ["attachment_add", { path: source, mediaType: null }],
      ["import_preview", { path: source, passphrase: null, conflictPolicy: "duplicate" }],
      ["dataset_add", { workspaceId, path: source, name: "d", sensitiveColumns: [] }],
      ["spec_preview", { input: { kind: "path", path: source }, options: IMPORT_OPTIONS }],
    ];
    for (const [cmd, args] of calls) expectRefused(cmd, await invoke(cmd, args));
  });

  it("never writes to a path or a made-up grant", async () => {
    const existing = join(dir, "keep.txt");
    writeFileSync(existing, "original");
    const fresh = join(dir, "fresh.anvil");
    for (const grant of [existing, fresh, `fg-${"0".repeat(32)}`]) {
      const args = { workspaceId, exportMode: "share_safely", passphrase: null, grant };
      expectRefused(`export_to_path ${grant}`, await invoke("export_to_path", args), UNKNOWN);
    }
    expectRefused("export_to_path path", await invoke("export_to_path", { workspaceId, exportMode: "share_safely", passphrase: null, path: fresh }));
    expect(readFileSync(existing, "utf8")).toBe("original");
    expect(existsSync(fresh)).toBe(false);
  });

  it("refuses a multi-file save dialog before showing anything", async () => {
    const r = await invoke("file_choose", { purpose: "bundle_export", options: { multiple: true } });
    expectRefused("file_choose", r, "a save dialog chooses one file");
  });
});
