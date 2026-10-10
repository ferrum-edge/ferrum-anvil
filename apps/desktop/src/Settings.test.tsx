// Settings → unlock passphrase: a keychain profile is converted, a passphrase
// profile changes its passphrase, and neither is offered before the profile's
// mode is known. The recovery key shown by a conversion stays until the user
// confirms they stored it, and a keychain entry the store kept is listed.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));

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
    // The reply exists before the component asks: the section mounts after the
    // settings load, and its mount effect may run after the pending button is
    // already on screen, so the test must not depend on when app_status is invoked.
    let resolveStatus: (s: unknown) => void = () => {};
    const statusReply = new Promise((resolve) => (resolveStatus = resolve));
    backend({
      app_status: () => statusReply,
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
    await screen.findByText("Passphrase set. The OS keychain no longer opens this profile.");
    expect(screen.queryByLabelText("Recovery key")).toBeNull();
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
    await screen.findByText("Encryption key rotated. Reopen with the new passphrase or the replacement recovery key saved in the native dialog.");
    expect(invoke).toHaveBeenCalledWith("profile_change_passphrase", { newPassphrase: "new passphrase 1" });
    expect(invoke).not.toHaveBeenCalledWith("profile_convert_to_passphrase", expect.anything());
  });

  it("reports native refusal without presenting an unsaved replacement", async () => {
    backend({ app_status: () => status("os_keychain"), profile_convert_to_passphrase: () => { throw "NOT_CONFIRMED"; } });
    render(<SettingsDialog onClose={vi.fn()} onSaved={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Require an unlock passphrase…" }));
    await fillPassphrase();
    await screen.findByText(/NOT_CONFIRMED|not confirmed|declined/i);
    expect(screen.queryByLabelText("Recovery key")).toBeNull();
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

describe("storage", () => {
  it("reads nothing until asked, removes damaged revisions through the backend, and keeps one a newer Anvil may have written", async () => {
    let revisions = [
      { id: "rev-1", updated_at: 0, cause: "damaged" },
      { id: "rev-2", updated_at: 0, cause: "damaged" },
      { id: "rev-3", updated_at: 0, cause: "unknown_format" },
    ];
    let confirmed = false;
    backend({
      app_status: () => status("passphrase"),
      storage_cleanup_last: () => ({
        ran_at: "2026-01-01T00:00:00Z",
        result: { orphaned_revisions: 0, released_attachments: 0, undecodable: revisions.map((r) => ({ kind: "revision", id: r.id })) },
      }),
      storage_undecodable_revisions: () => revisions,
      storage_revisions_remove: (args) => {
        // The backend asks in its own native dialog; declined the first time.
        if (!confirmed) {
          confirmed = true;
          throw "NOT_CONFIRMED";
        }
        const ids = (args as { revisionIds: string[] }).revisionIds;
        revisions = revisions.filter((r) => !ids.includes(r.id));
        return { removed: ids, checkpoint: "before-removing-revisions.db" };
      },
    });
    render(<SettingsDialog onClose={vi.fn()} onSaved={vi.fn()} />);
    const check = await screen.findByRole("button", { name: "Check storage" });
    // Finding them decrypts every revision: not each time Settings opens.
    expect(invoke).not.toHaveBeenCalledWith("storage_undecodable_revisions", undefined);
    fireEvent.click(check);
    expect(await screen.findByText(/3 stored revision\(s\) do not decode/)).toBeTruthy();
    // One a newer Anvil may have written offers no removal.
    expect(screen.queryByRole("button", { name: "Remove revision rev-3" })).toBeNull();
    expect(screen.getByText(/written by a newer Anvil, or in a format this version cannot read: kept/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Remove revision rev-1" }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("storage_revisions_remove", { revisionIds: ["rev-1"] }));
    expect(await screen.findByText("Not done: it was not confirmed in the system dialog.")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Remove all 2 damaged…" }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("storage_revisions_remove", { revisionIds: ["rev-1", "rev-2"] }));
    expect(await screen.findByText("Removed 2 damaged revision(s). The checkpoint before-removing-revisions.db keeps them.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Remove revision/ })).toBeNull();
    expect(screen.getByText(/1 stored revision\(s\) do not decode/)).toBeTruthy();
  });
});
