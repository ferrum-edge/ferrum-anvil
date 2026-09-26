// Settings → unlock passphrase: a keychain profile is converted, a passphrase
// profile changes its passphrase, and neither is offered before the profile's
// mode is known. The recovery key shown by a conversion stays until the user
// confirms they stored it, and a keychain entry the store kept is listed.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(), open: vi.fn(), save: vi.fn() }));

import { SettingsDialog } from "./Dialogs";
import type { AppSettings } from "./generated/contracts";

const settings = {
  schema_version: 1,
  defaults: {},
  theme: "system",
  history: { enabled: true, keep_response_bodies: false, max_age_days: 30, max_total_bytes: 64 * 1024 * 1024 },
  lock: { idle_minutes: 15, lock_on_os_lock: true },
  autosave: true,
  redaction_names: [],
  check_for_updates: false,
} as unknown as AppSettings;

type Profile = { profile_id: string; display_name: string; protection: "passphrase" | "os_keychain"; leftover_keychain_entry?: { service: string; account: string } | null };

function backend(overrides: Record<string, (args: unknown) => unknown>) {
  invoke.mockImplementation(async (cmd: string, args?: unknown) => {
    if (overrides[cmd]) return overrides[cmd](args);
    if (cmd === "settings_get") return settings;
    if (cmd === "system_info") return null;
    if (cmd === "login_providers") return [];
    if (cmd === "profiles_list") return [];
    throw new Error(`unexpected command ${cmd}`);
  });
}

const status = (protection: "passphrase" | "os_keychain") => ({ state: "unlocked", profile: "Local", protection, version: "0.1.0" });

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

async function fillPassphrase() {
  const field = await screen.findByLabelText("New passphrase");
  fireEvent.change(field, { target: { value: "new passphrase 1" } });
  fireEvent.change(screen.getByLabelText("Repeat passphrase"), { target: { value: "new passphrase 1" } });
  // The passphrase box has its own Save, apart from the dialog's.
  fireEvent.click(within(field.closest("fieldset")!).getByRole("button", { name: "Save" }));
}

describe("unlock passphrase", () => {
  it("offers nothing until the profile's mode is known, then converts a keychain profile", async () => {
    let resolveStatus: (s: unknown) => void = () => {};
    backend({
      app_status: () => new Promise((resolve) => (resolveStatus = resolve)),
      profile_convert_to_passphrase: () => ({ recovery_key: "AAAA-BBBB", keychain_entry_removed: true }),
    });
    render(<SettingsDialog onClose={vi.fn()} onSaved={vi.fn()} />);
    const pending = (await screen.findByRole("button", { name: "Unlock passphrase…" })) as HTMLButtonElement;
    expect(pending.disabled).toBe(true);
    expect(screen.queryByRole("button", { name: /Change unlock passphrase/ })).toBeNull();

    resolveStatus(status("os_keychain"));
    fireEvent.click(await screen.findByRole("button", { name: "Require an unlock passphrase…" }));
    await fillPassphrase();
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("profile_convert_to_passphrase", { newPassphrase: "new passphrase 1" }));
    expect(invoke).not.toHaveBeenCalledWith("profile_change_passphrase", expect.anything());
    expect((await screen.findByLabelText("Recovery key")).textContent).toBe("AAAA-BBBB");
  });

  it("offers a retry, never a passphrase change, when the mode cannot be read", async () => {
    let calls = 0;
    backend({
      app_status: () => {
        calls += 1;
        if (calls === 1) throw "backend unavailable";
        return status("os_keychain");
      },
    });
    render(<SettingsDialog onClose={vi.fn()} onSaved={vi.fn()} />);
    await screen.findByText(/Could not read how this profile is protected: backend unavailable/);
    expect((screen.getByRole("button", { name: "Unlock passphrase…" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("button", { name: /Change unlock passphrase/ })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("button", { name: "Require an unlock passphrase…" })).toBeTruthy();
    expect(screen.queryByText(/Could not read how this profile is protected/)).toBeNull();
  });

  it("changes the passphrase of a passphrase profile", async () => {
    backend({ app_status: () => status("passphrase"), profile_change_passphrase: () => null });
    render(<SettingsDialog onClose={vi.fn()} onSaved={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Change unlock passphrase…" }));
    await fillPassphrase();
    await screen.findByText("Passphrase changed. The recovery key still works.");
    expect(invoke).toHaveBeenCalledWith("profile_change_passphrase", { newPassphrase: "new passphrase 1" });
    expect(invoke).not.toHaveBeenCalledWith("profile_convert_to_passphrase", expect.anything());
  });

  it("keeps the recovery key on screen until it is confirmed stored", async () => {
    backend({
      app_status: () => status("os_keychain"),
      profile_convert_to_passphrase: () => ({ recovery_key: "AAAA-BBBB", keychain_entry_removed: true }),
    });
    const onClose = vi.fn();
    const onSaved = vi.fn();
    render(<SettingsDialog onClose={onClose} onSaved={onSaved} />);
    fireEvent.click(await screen.findByRole("button", { name: "Require an unlock passphrase…" }));
    await fillPassphrase();
    await screen.findByLabelText("Recovery key");

    // Neither the close button, Escape nor saving the settings closes it.
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    fireEvent.keyDown(window, { key: "Escape" });
    backend({ app_status: () => status("passphrase"), settings_save: () => null });
    const saves = screen.getAllByRole("button", { name: "Save" });
    fireEvent.click(saves[saves.length - 1]);
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toMatch(/Store the recovery key before closing Settings/);
    expect(screen.getByLabelText("Recovery key").textContent).toBe("AAAA-BBBB");

    fireEvent.click(screen.getByRole("button", { name: "I stored it safely" }));
    expect(screen.queryByLabelText("Recovery key")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("lists a keychain entry the credential store kept", async () => {
    const converted: Profile = { profile_id: "k1", display_name: "Local", protection: "passphrase" };
    let profiles: Profile[] = [converted];
    backend({
      app_status: () => status("os_keychain"),
      profiles_list: () => profiles,
      profile_convert_to_passphrase: () => {
        profiles = [{ ...converted, leftover_keychain_entry: { service: "com.ferrumedge.anvil", account: "profile-k1" } }];
        return { recovery_key: "AAAA-BBBB", keychain_entry_removed: false };
      },
    });
    render(<SettingsDialog onClose={vi.fn()} onSaved={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Require an unlock passphrase…" }));
    expect(screen.queryByText(/is still waiting to be removed/)).toBeNull();
    await fillPassphrase();
    await screen.findByText(/its old entry could not be removed yet and removal is retried at each unlock/);
    const note = await screen.findByText(/The old OS keychain entry of “Local” is still waiting to be removed/);
    expect(note.textContent).toMatch(/profile-k1/);
    expect(note.textContent).toMatch(/com\.ferrumedge\.anvil/);
  });

  it("shows a pending removal when Settings opens", async () => {
    backend({
      app_status: () => status("passphrase"),
      profiles_list: () => [{ profile_id: "k1", display_name: "Local", protection: "passphrase", leftover_keychain_entry: { service: "com.ferrumedge.anvil", account: "profile-k1" } }],
    });
    render(<SettingsDialog onClose={vi.fn()} onSaved={vi.fn()} />);
    const note = await screen.findByText(/The old OS keychain entry of “Local” is still waiting to be removed/);
    expect(note.textContent).toMatch(/retries removing it at each unlock until it is gone/);
  });
});
