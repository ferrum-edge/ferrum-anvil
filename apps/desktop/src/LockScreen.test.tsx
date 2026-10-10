// First-run and launch behaviour of the lock screen: starting without a
// password is the obvious default, the passphrase path stays one click away,
// and a keychain profile opens by itself at launch but never after a lock.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));

import { LockScreen } from "./LockScreen";

type Profile = { profile_id: string; display_name: string; protection: "passphrase" | "os_keychain" };

function backend(profiles: Profile[], overrides: Record<string, (args: unknown) => unknown> = {}) {
  invoke.mockImplementation(async (cmd: string, args?: unknown) => {
    if (overrides[cmd]) return overrides[cmd](args);
    if (cmd === "profiles_list") return profiles;
    if (cmd === "profile_create") return { profile_id: "p1", recovery_key: null };
    if (cmd === "profile_unlock") return null;
    throw new Error(`unexpected command ${cmd}`);
  });
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

describe("first run", () => {
  it("defaults to starting without a password and creates a keychain profile", async () => {
    backend([]);
    const onUnlocked = vi.fn();
    render(<LockScreen onUnlocked={onUnlocked} />);
    const start = (await screen.findByRole("radio", { name: /Start now — no password/ })) as HTMLInputElement;
    expect(start.checked).toBe(true);
    expect(screen.getByText(/No account, no sign-up/)).toBeTruthy();
    expect(screen.queryByLabelText(/Unlock passphrase/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Start working" }));
    await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
    expect(invoke).toHaveBeenCalledWith("profile_create", { name: "Local", passphrase: null, keychain: true });
  });

  it("offers the passphrase path and falls back to it when there is no OS keychain", async () => {
    backend([], {
      profile_create: () => {
        throw "the OS credential store is unavailable (no secret service); use a passphrase-protected profile instead";
      },
    });
    render(<LockScreen onUnlocked={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Start working" }));
    await screen.findByText(/no OS keychain Anvil can use/);
    expect((screen.getByRole("radio", { name: /Protect with a passphrase/ }) as HTMLInputElement).checked).toBe(true);
    expect(screen.getByLabelText(/Unlock passphrase/)).toBeTruthy();
  });
});

describe("launch", () => {
  const keychain: Profile = { profile_id: "k1", display_name: "Local", protection: "os_keychain" };

  it("opens a single keychain profile without any input", async () => {
    backend([keychain]);
    const onUnlocked = vi.fn();
    render(<LockScreen onUnlocked={onUnlocked} />);
    await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
    expect(invoke).toHaveBeenCalledWith("profile_unlock", { profileId: "k1", passphrase: null, recoveryKey: null });
  });

  it("never opens by itself after a lock", async () => {
    backend([keychain]);
    const onUnlocked = vi.fn();
    render(<LockScreen onUnlocked={onUnlocked} reason="manual" />);
    await screen.findByRole("button", { name: "Unlock" });
    expect(onUnlocked).not.toHaveBeenCalled();
    expect(invoke).not.toHaveBeenCalledWith("profile_unlock", expect.anything());
  });

  it("asks for the passphrase of a passphrase profile", async () => {
    backend([{ profile_id: "p1", display_name: "Work", protection: "passphrase" }]);
    const onUnlocked = vi.fn();
    render(<LockScreen onUnlocked={onUnlocked} />);
    await screen.findByLabelText("Passphrase");
    expect(onUnlocked).not.toHaveBeenCalled();
  });
});

describe("legacy policy enrollment", () => {
  it("keeps a keychain profile locked until explicit native enrollment completes and then asks for the new passphrase", async () => {
    let enrolled = false;
    backend([], {
      profiles_list: () => [{ profile_id: "k1", display_name: "Local", protection: enrolled ? "passphrase" : "os_keychain" }],
      profile_unlock: () => { throw new Error("POLICY_ENROLLMENT_REQUIRED: policy is unknown"); },
      profile_enroll_unlinked: () => { enrolled = true; },
    });
    const onUnlocked = vi.fn();
    render(<LockScreen onUnlocked={onUnlocked} />);
    await screen.findByRole("heading", { name: "Enroll legacy policy" });
    expect(onUnlocked).not.toHaveBeenCalled();
    expect(invoke).not.toHaveBeenCalledWith("profile_enroll_unlinked", expect.anything());
    fireEvent.change(screen.getByLabelText("New passphrase"), { target: { value: "replacement passphrase" } });
    fireEvent.change(screen.getByLabelText("Repeat new passphrase"), { target: { value: "replacement passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: "Replace unknown policy and rotate…" }));
    await screen.findByText("Policy enrolled and encryption key rotated. Unlock with your new passphrase.");
    expect(invoke).toHaveBeenCalledWith("profile_enroll_unlinked", {
      profileId: "k1", passphrase: null, recoveryKey: null, newPassphrase: "replacement passphrase",
    });
    expect(screen.getByLabelText("Passphrase")).toBeTruthy();
    expect(onUnlocked).not.toHaveBeenCalled();
    expect(screen.queryByLabelText("Recovery key")).toBeNull();
  });

  it("keeps native enrollment refusal on the consent screen without unlocking", async () => {
    backend([{ profile_id: "k1", display_name: "Local", protection: "os_keychain" }], {
      profile_unlock: () => { throw new Error("POLICY_ENROLLMENT_REQUIRED: policy is unknown"); },
      profile_enroll_unlinked: () => { throw new Error("NOT_CONFIRMED"); },
    });
    const onUnlocked = vi.fn();
    render(<LockScreen onUnlocked={onUnlocked} />);
    await screen.findByRole("heading", { name: "Enroll legacy policy" });
    fireEvent.change(screen.getByLabelText("New passphrase"), { target: { value: "replacement passphrase" } });
    fireEvent.change(screen.getByLabelText("Repeat new passphrase"), { target: { value: "replacement passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: "Replace unknown policy and rotate…" }));
    await screen.findByText("POLICY_ENROLLMENT_REQUIRED: NOT_CONFIRMED");
    expect(onUnlocked).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Enroll legacy policy" })).toBeTruthy();
  });
});
