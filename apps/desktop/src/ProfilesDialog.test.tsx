// Connection profiles dialog: a saved Ferrum gateway profile can be removed
// through `integration_delete` once the in-window prompt is confirmed, and a
// new one that was never saved offers no removal.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
  it("removes a saved gateway profile once the prompt is confirmed", async () => {
    const onChanged = await openGateways();
    fireEvent.click(await screen.findByText(gateway.name));
    fireEvent.click(screen.getByRole("button", { name: "Remove gateway" }));
    const prompt = await screen.findByRole("dialog", { name: "Remove gateway" });
    expect(prompt.textContent).toContain(`Remove gateway “${gateway.name}”?`);
    expect(calls("integration_delete")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(calls("integration_delete")).toEqual([{ profileId: "gw-1" }]));
    expect(await screen.findByText("No gateways declared.")).toBeTruthy();
    expect(onChanged).toHaveBeenCalled();
  });

  it("keeps the profile, and the dialog, when the prompt is cancelled", async () => {
    const onClose = vi.fn();
    render(<ProfilesDialog workspaceId="ws-1" onClose={onClose} onChanged={vi.fn()} />);
    await waitFor(() => expect(calls("integrations_list")).toHaveLength(1));
    fireEvent.click(screen.getByRole("tab", { name: /Ferrum gateways/ }));
    fireEvent.click(await screen.findByText(gateway.name));
    fireEvent.click(screen.getByRole("button", { name: "Remove gateway" }));
    await screen.findByRole("dialog", { name: "Remove gateway" });
    // The profiles dialog is inert under the prompt: its Save profile cannot be reached.
    const profiles = screen.getByRole("dialog", { name: "Connection profiles", hidden: true });
    expect(profiles.closest("[inert]")).not.toBeNull();
    // Escape answers the prompt only.
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Remove gateway" })).toBeNull());
    expect(onClose).not.toHaveBeenCalled();
    expect(calls("integration_delete")).toHaveLength(0);
    expect(profiles.closest("[inert]")).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Remove gateway" }));
  });

  it("keeps a draft opened while a removal is still being written", async () => {
    const answer = invoke.getMockImplementation()!;
    let finish!: () => void;
    const written = new Promise<void>((resolve) => (finish = resolve));
    invoke.mockImplementation(async (cmd: string, args?: Args) => {
      if (cmd === "integration_delete") await written;
      return answer(cmd, args);
    });
    await openGateways();
    fireEvent.click(await screen.findByText(gateway.name));
    fireEvent.click(screen.getByRole("button", { name: "Remove gateway" }));
    await screen.findByRole("dialog", { name: "Remove gateway" });
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(calls("integration_delete")).toHaveLength(1));
    // While it is written, the profile cannot be saved back or removed again.
    expect((screen.getByRole("button", { name: "Save profile" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Remove gateway" }) as HTMLButtonElement).disabled).toBe(true);
    // Back to the list, and a new draft, before the delete returns.
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    fireEvent.click(screen.getByRole("button", { name: "New gateway" }));
    expect(screen.getByRole("button", { name: "Save profile" })).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save profile" }) as HTMLButtonElement).disabled).toBe(false);
    await act(async () => finish());
    await waitFor(() => expect(calls("integrations_list").length).toBeGreaterThan(1));
    expect(screen.getByRole("button", { name: "Save profile" })).toBeTruthy();
    expect(calls("integration_save")).toHaveLength(0);
  });

  it("keeps every profile whose removal is still being written from being saved back", async () => {
    const other: IntegrationProfile = { ...gateway, id: "gw-2", name: "Second gateway" };
    saved = [gateway, other];
    const answer = invoke.getMockImplementation()!;
    const finish = new Map<string, () => void>();
    invoke.mockImplementation(async (cmd: string, args?: Args) => {
      if (cmd === "integration_delete") await new Promise<void>((resolve) => finish.set(args?.profileId as string, resolve));
      return answer(cmd, args);
    });
    const remove = async (name: string) => {
      fireEvent.click(await screen.findByText(name));
      fireEvent.click(screen.getByRole("button", { name: "Remove gateway" }));
      await screen.findByRole("dialog", { name: "Remove gateway" });
      fireEvent.click(screen.getByRole("button", { name: "Remove" }));
      fireEvent.click(screen.getByRole("button", { name: "Back" }));
    };
    const blocked = async (name: string) => {
      fireEvent.click(await screen.findByText(name));
      const disabled = ["Save profile", "Remove gateway"].map((n) => (screen.getByRole("button", { name: n }) as HTMLButtonElement).disabled);
      fireEvent.click(screen.getByRole("button", { name: "Back" }));
      return disabled;
    };
    await openGateways();
    await remove(gateway.name);
    await remove(other.name);
    await waitFor(() => expect(finish.size).toBe(2));
    // Both stay blocked while both removals are pending.
    expect(await blocked(gateway.name)).toEqual([true, true]);
    expect(await blocked(other.name)).toEqual([true, true]);
    // One settling releases only its own.
    await act(async () => finish.get("gw-2")!());
    expect(await blocked(gateway.name)).toEqual([true, true]);
    await act(async () => finish.get("gw-1")!());
    expect(calls("integration_save")).toHaveLength(0);
  });

  it("keeps the profile and its editor when the removal fails", async () => {
    const answer = invoke.getMockImplementation()!;
    invoke.mockImplementation(async (cmd: string, args?: Args) => {
      if (cmd === "integration_delete") throw "the store is busy";
      return answer(cmd, args);
    });
    const onChanged = await openGateways();
    fireEvent.click(await screen.findByText(gateway.name));
    fireEvent.click(screen.getByRole("button", { name: "Remove gateway" }));
    await screen.findByRole("dialog", { name: "Remove gateway" });
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(await screen.findByText("the store is busy")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Remove gateway" }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByRole("button", { name: "Save profile" })).toBeTruthy();
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("names the saved profile, not an unsaved edit of its name", async () => {
    await openGateways();
    fireEvent.click(await screen.findByText(gateway.name));
    fireEvent.change(screen.getByDisplayValue(gateway.name), { target: { value: "Renamed, not saved" } });
    fireEvent.click(screen.getByRole("button", { name: "Remove gateway" }));
    const prompt = await screen.findByRole("dialog", { name: "Remove gateway" });
    expect(prompt.textContent).toContain(`Remove gateway “${gateway.name}”?`);
  });

  it("offers no removal for a gateway that was never saved", async () => {
    await openGateways();
    fireEvent.click(screen.getByRole("button", { name: "New gateway" }));
    expect(screen.queryByRole("button", { name: "Remove gateway" })).toBeNull();
    expect(calls("integration_delete")).toHaveLength(0);
  });
});
