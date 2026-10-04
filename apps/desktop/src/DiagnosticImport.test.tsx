import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";
import type { ImportedDiagnosticPreview } from "./diagnosticImport";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: unknown) => invoke(cmd, args),
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(), open: vi.fn(), save: vi.fn() }));

import { DiagnosticImport } from "./DiagnosticImport";
import { ImportDialog } from "./Dialogs";
import { DIAGNOSTIC_MAX_BYTES } from "./diagnosticImport";

const report = JSON.stringify({
  schema: "ferrum.diagnostic_report",
  schema_version: "1.0",
  collection: {
    collector: { kind: "alloy", name: "fixture" },
    method: "live_export",
    verification: "verified",
  },
  authenticated: true,
});

const result: ImportedDiagnosticPreview = {
  kind: "report",
  trust: "unverified",
  confidence: "unknown",
  observation_count: 0,
  finding_count: 1,
  reported: {
    ...JSON.parse(report),
    findings: [{ confidence: "confirmed", title: '<img src="https://example.test/x">' }],
    note: "[run me](javascript:alert(1)) file:///etc/passwd https://example.test/claims",
    authorization: "‹redacted›",
  },
  warnings: ["Supplied findings are unverified claims."],
};

function backend() {
  const effects = { requests: 0, profiles: 0, history: 0, grants: 0, secrets: 0, lookups: 0 };
  invoke.mockImplementation(async (command: string) => {
    if (command === "diagnostic_import_preview") return result;
    if (command === "send_request") effects.requests += 1;
    if (command.startsWith("profile")) effects.profiles += 1;
    if (command.startsWith("history")) effects.history += 1;
    if (command.includes("file") || command.includes("grant")) effects.grants += 1;
    if (command.includes("secret") || command.includes("vault")) effects.secrets += 1;
    if (command.includes("lookup") || command.includes("gateway")) effects.lookups += 1;
    throw new Error(`unexpected command ${command}`);
  });
  return effects;
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

it("opens from Import and renders escaped claims with no effects", async () => {
  const effects = backend();
  const imported = vi.fn();
  const specImported = vi.fn();
  render(
    <ImportDialog
      onClose={vi.fn()}
      onImported={imported}
      workspaceId={null}
      workspaceName={null}
      onSpecImported={specImported}
    />,
  );
  fireEvent.click(screen.getByRole("tab", { name: "Diagnostic preview" }));
  fireEvent.change(screen.getByLabelText("Paste diagnostic JSON"), { target: { value: report } });
  fireEvent.click(screen.getByRole("button", { name: "Preview diagnostic" }));
  const view = await screen.findByRole("region", { name: "Unverified diagnostic preview" });
  expect(view.textContent).toContain("Anvil confidence: unknown");
  expect(view.textContent).toContain('"authenticated": true');
  expect(view.textContent).toContain('"confidence": "confirmed"');
  expect(view.textContent).toContain("‹redacted›");
  expect(view.querySelector("img, a, script, iframe")).toBeNull();
  expect(screen.queryByRole("button", { name: /^Import$/ })).toBeNull();
  expect(invoke.mock.calls).toEqual([["diagnostic_import_preview", { input: { text: report } }]]);
  expect(effects).toEqual({
    requests: 0,
    profiles: 0,
    history: 0,
    grants: 0,
    secrets: 0,
    lookups: 0,
  });
  expect(imported).not.toHaveBeenCalled();
  expect(specImported).not.toHaveBeenCalled();
  expect((screen.getByLabelText("Paste diagnostic JSON") as HTMLTextAreaElement).value).toBe("");
});

it("reads only a bounded browser File and passes text through the dedicated command", async () => {
  backend();
  render(<DiagnosticImport />);
  const bytes = new TextEncoder().encode(report);
  const slice = vi.fn(() => ({ arrayBuffer: async () => bytes.buffer }));
  const file = new File([report], "diagnostic.json", { type: "application/json" });
  Object.defineProperty(file, "slice", { value: slice });
  fireEvent.change(screen.getByLabelText("Diagnostic JSON file"), { target: { files: [file] } });
  await screen.findByRole("region", { name: "Unverified diagnostic preview" });
  expect(slice).toHaveBeenCalledWith(0, DIAGNOSTIC_MAX_BYTES + 1);
  expect(invoke.mock.calls).toEqual([["diagnostic_import_preview", { input: { text: report } }]]);
});

it("refuses oversized files before reading and multibyte pastes before IPC", async () => {
  backend();
  render(<DiagnosticImport />);
  const slice = vi.fn();
  const file = new File([], "large.json");
  Object.defineProperties(file, {
    size: { value: DIAGNOSTIC_MAX_BYTES + 1 },
    slice: { value: slice },
  });
  fireEvent.change(screen.getByLabelText("Diagnostic JSON file"), { target: { files: [file] } });
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(slice).not.toHaveBeenCalled();
  const oversized = "é".repeat(DIAGNOSTIC_MAX_BYTES / 2 + 1);
  fireEvent.change(screen.getByLabelText("Paste diagnostic JSON"), {
    target: { value: oversized },
  });
  fireEvent.click(screen.getByRole("button", { name: "Preview diagnostic" }));
  await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
  expect(invoke).not.toHaveBeenCalled();
});

it("rejects malformed UTF-8 file bytes before IPC", async () => {
  backend();
  render(<DiagnosticImport />);
  const file = new File(["x"], "invalid.json");
  Object.defineProperty(file, "slice", {
    value: () => ({ arrayBuffer: async () => new Uint8Array([0xff]).buffer }),
  });
  fireEvent.change(screen.getByLabelText("Diagnostic JSON file"), { target: { files: [file] } });
  await screen.findByRole("alert");
  expect(invoke).not.toHaveBeenCalled();
});

it("clears the preview and ignores a late IPC response", async () => {
  let resolve!: (value: ImportedDiagnosticPreview) => void;
  invoke.mockReturnValue(
    new Promise<ImportedDiagnosticPreview>((done) => {
      resolve = done;
    }),
  );
  render(<DiagnosticImport />);
  fireEvent.change(screen.getByLabelText("Paste diagnostic JSON"), { target: { value: report } });
  fireEvent.click(screen.getByRole("button", { name: "Preview diagnostic" }));
  fireEvent.click(screen.getByRole("button", { name: "Clear preview" }));
  resolve(result);
  await waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
  expect(screen.queryByRole("region", { name: "Unverified diagnostic preview" })).toBeNull();
});

it("shows a bounded generic error without reflecting untrusted backend text", async () => {
  invoke.mockRejectedValue(new Error("credential-bearing-untrusted-error"));
  render(<DiagnosticImport />);
  fireEvent.change(screen.getByLabelText("Paste diagnostic JSON"), { target: { value: "{}" } });
  fireEvent.click(screen.getByRole("button", { name: "Preview diagnostic" }));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("Cannot preview");
  expect(alert.textContent).not.toContain("credential-bearing");
});

it("bounds rendered UTF-8 text and escapes bidirectional controls", async () => {
  invoke.mockResolvedValue({
    ...result,
    reported: { control: "\u202e", note: "é".repeat(64 * 1024) },
  });
  render(<DiagnosticImport />);
  fireEvent.change(screen.getByLabelText("Paste diagnostic JSON"), { target: { value: report } });
  fireEvent.click(screen.getByRole("button", { name: "Preview diagnostic" }));
  const text = (await screen.findByTestId("diagnostic-reported")).textContent ?? "";
  expect(new TextEncoder().encode(text).byteLength).toBeLessThanOrEqual(64 * 1024);
  expect(text).toContain("\\u202e");
  expect(text).not.toContain("\u202e");
  expect(
    screen.getByText("Presentation limited to the first 64 KiB of reported JSON."),
  ).toBeTruthy();
});
