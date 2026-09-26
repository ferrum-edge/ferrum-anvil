// Renderer tests for the workspace settings' device-identity seal (jsdom; IPC
// mocked). A bundle import seals a workspace from this device's workload
// identity; the dialog says so and lifts the seal only after the user
// confirms. The seal itself is enforced by the backend (anvil-app tests).
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { Workspace } from "./generated/contracts";

const invoke = vi.fn();
const ask = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: (...a: unknown[]) => ask(...a), open: vi.fn(), save: vi.fn() }));

import { ScopeSettingsDialog } from "./ScopeSettings";

const now = "2026-01-01T00:00:00Z";
const ws = { id: "ws-1", name: "Imported", schema_version: 1, created_at: now, updated_at: now } as Workspace;
const BANNER = /A bundle import wrote into this workspace/;

afterEach(() => {
  cleanup();
  invoke.mockReset();
  ask.mockReset();
});

function backend(sealed: boolean) {
  invoke.mockImplementation(async (cmd: string) => {
    switch (cmd) {
      case "workspace_device_identity_sealed":
        return sealed;
      case "workspace_allow_device_identity":
        sealed = false;
        return true;
      default:
        // Anything else the editors read stays pending: it is not under test.
        return new Promise(() => {});
    }
  });
}

function renderWorkspace() {
  const profiles = { tls: [], proxy: [], integrations: [] };
  render(<ScopeSettingsDialog target={{ kind: "workspace", workspace: ws }} workspaceId={ws.id} profiles={profiles} onClose={() => {}} onSaved={() => {}} />);
}

const calls = (cmd: string) => invoke.mock.calls.filter((c) => c[0] === cmd).map((c) => c[1] as Record<string, unknown>);

test("a sealed workspace says so and is allowed only after the user confirms", async () => {
  backend(true);
  renderWorkspace();
  await screen.findByText(BANNER);
  expect(calls("workspace_device_identity_sealed")).toEqual([{ workspaceId: ws.id }]);

  // Declining the confirmation changes nothing.
  ask.mockResolvedValueOnce(false);
  fireEvent.click(screen.getByRole("button", { name: "Allow on this device" }));
  await waitFor(() => expect(ask).toHaveBeenCalledTimes(1));
  expect(calls("workspace_allow_device_identity")).toEqual([]);
  expect(screen.getByText(BANNER)).toBeTruthy();

  ask.mockResolvedValueOnce(true);
  fireEvent.click(screen.getByRole("button", { name: "Allow on this device" }));
  await waitFor(() => expect(screen.queryByText(BANNER)).toBeNull());
  expect(calls("workspace_allow_device_identity")).toEqual([{ workspaceId: ws.id }]);
});

test("a workspace that is not sealed shows no seal", async () => {
  backend(false);
  renderWorkspace();
  await waitFor(() => expect(calls("workspace_device_identity_sealed")).toEqual([{ workspaceId: ws.id }]));
  expect(screen.queryByText(BANNER)).toBeNull();
  expect(screen.queryByRole("button", { name: "Allow on this device" })).toBeNull();
});
