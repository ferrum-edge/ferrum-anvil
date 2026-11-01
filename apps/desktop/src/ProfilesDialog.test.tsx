// Connection profiles dialog: a saved Ferrum gateway profile can be removed
// through `integration_delete`, and a new one that was never saved offers
// no removal.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));

import { ProfilesDialog } from "./Dialogs";
import type { IntegrationProfile } from "./api";

type Args = Record<string, unknown>;

const gateway: IntegrationProfile = {
  id: "gw-1",
  workspace_id: "ws-1",
  name: "Ferrum gateway 127.0.0.1",
  kind: "ferrum_gateway",
  hosts: [{ host: "127.0.0.1" }],
  compatibility_id: "ferrum-edge-0.9.15",
  require_verified_tls: false,
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
};

let saved: IntegrationProfile[] = [];

function backend() {
  invoke.mockImplementation(async (cmd: string, args?: Args) => {
    switch (cmd) {
      case "tls_profiles_list":
      case "proxy_profiles_list":
        return [];
      case "integrations_list":
        return saved;
      case "integration_delete":
        saved = saved.filter((p) => p.id !== args?.profileId);
        return null;
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  });
}

const calls = (cmd: string) => invoke.mock.calls.filter(([c]) => c === cmd).map(([, args]) => args as Args);

async function openGateways() {
  const onChanged = vi.fn();
  render(<ProfilesDialog workspaceId="ws-1" onClose={vi.fn()} onChanged={onChanged} />);
  await waitFor(() => expect(calls("integrations_list")).toHaveLength(1));
  fireEvent.click(screen.getByRole("tab", { name: /Ferrum gateways/ }));
  return onChanged;
}

beforeEach(() => {
  saved = [gateway];
  backend();
});

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

describe("Ferrum gateway profiles", () => {
  it("removes a saved gateway profile", async () => {
    const onChanged = await openGateways();
    fireEvent.click(await screen.findByText(gateway.name));
    fireEvent.click(screen.getByRole("button", { name: "Remove gateway" }));
    await waitFor(() => expect(calls("integration_delete")).toEqual([{ profileId: "gw-1" }]));
    expect(await screen.findByText("No gateways declared.")).toBeTruthy();
    expect(onChanged).toHaveBeenCalled();
  });

  it("offers no removal for a gateway that was never saved", async () => {
    await openGateways();
    fireEvent.click(screen.getByRole("button", { name: "New gateway" }));
    expect(screen.queryByRole("button", { name: "Remove gateway" })).toBeNull();
    expect(calls("integration_delete")).toHaveLength(0);
  });
});
