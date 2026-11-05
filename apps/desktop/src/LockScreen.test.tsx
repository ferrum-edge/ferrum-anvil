// First-run and launch behaviour of the lock screen: starting without a
// password is the obvious default, the passphrase path stays one click away,
// and a keychain profile opens by itself at launch but never after a lock.
// A lock that lands while the lock screen shows always leads back to the
// unlock form, and the reason it shows is the backend's.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
// Backend events by name (the `locked` event App listens to).
const listeners = new Map<string, (ev: { payload: unknown }) => void>();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, cb: (ev: { payload: unknown }) => void) => {
    listeners.set(name, cb);
    return () => listeners.delete(name);
  }),
}));

import { App } from "./App";
import { LockScreen, lockScreen } from "./LockScreen";

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
  listeners.clear();
});

/** The backend emits `locked` with `payload` (a `LockReason`). */
const emitLocked = (payload: unknown) => act(async () => listeners.get("locked")?.({ payload }));

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
    fireEvent.click(screen.getByRole("button", { name: "Enroll policy and rotate…" }));
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
    fireEvent.click(screen.getByRole("button", { name: "Enroll policy and rotate…" }));
    await screen.findByText("POLICY_ENROLLMENT_REQUIRED: Not done: it was not confirmed in the system dialog.");
    expect(onUnlocked).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Enroll legacy policy" })).toBeTruthy();
  });
});

describe("a lock while the lock screen shows", () => {
  const work: Profile = { profile_id: "p1", display_name: "Work", protection: "passphrase" };
  // The backend stays locked for App: a recovery-key unlock leaves App on the
  // lock screen, and the auto-lock locks again.
  const lockedBackend = () => backend([work], { app_status: () => ({ state: "locked", profile: null }) });

  it("leaves the new-passphrase step of a recovery-key unlock for the unlock form", async () => {
    lockedBackend();
    render(<App />);
    await screen.findByLabelText("Passphrase");
    // An earlier idle lock: the next one has the same reason.
    await emitLocked("idle");
    await screen.findByText(/Locked \(inactivity\)/);

    fireEvent.click(screen.getByRole("button", { name: "Use recovery key" }));
    fireEvent.change(screen.getByLabelText("Recovery key"), { target: { value: "RECOVERY-KEY" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    await screen.findByRole("heading", { name: "Set a new passphrase" });
    expect(invoke).toHaveBeenCalledWith("profile_unlock", { profileId: "p1", passphrase: null, recoveryKey: "RECOVERY-KEY" });
    fireEvent.change(screen.getByLabelText("New passphrase"), { target: { value: "typed, never saved" } });

    // The idle lock fires while the step shows: the step needs an unlocked backend.
    await emitLocked("idle");
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Set a new passphrase" })).toBeNull());
    expect(screen.getByText(/Locked \(inactivity\)/)).toBeTruthy();
    expect((screen.getByLabelText("Passphrase") as HTMLInputElement).value).toBe("");
    expect(screen.getByRole("button", { name: "Unlock" })).toBeTruthy();
    expect(invoke).not.toHaveBeenCalledWith("profile_change_passphrase", expect.anything());
  });

  it("names an integrity lock as one", async () => {
    lockedBackend();
    render(<App />);
    await screen.findByLabelText("Passphrase");
    await emitLocked("integrity");
    await screen.findByText(/Locked \(a stored record failed its integrity check\)/);
    expect(screen.queryByText(/manually/)).toBeNull();
    // A lock with no reason (an older backend) reads as a manual one.
    await emitLocked(null);
    await screen.findByText(/Locked \(manually\)/);
  });
});

// A backend reply the test completes by hand.
function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

describe("results the backend already committed", () => {
  const work: Profile = { profile_id: "p1", display_name: "Work", protection: "passphrase" };
  const form = (mode: "unlock" | "create" | "recovery") => ({ screen: { kind: "form" as const, mode }, error: null });

  it("are never dropped by the transition function, whatever form shows by then", () => {
    for (const mode of ["unlock", "create", "recovery"] as const) {
      expect(lockScreen(form(mode), { type: "created", recoveryKey: "RK" }).screen).toEqual({ kind: "showRecovery", key: "RK" });
      expect(lockScreen(form(mode), { type: "recoveryUnlocked" }).screen).toEqual({ kind: "resetPassphrase" });
    }
  });

  it("show a new profile's recovery key although Back was clicked while it was created", async () => {
    const created = deferred<{ profile_id: string; recovery_key: string }>();
    backend([work], { profile_create: () => created.promise });
    render(<LockScreen onUnlocked={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "New profile" }));
    fireEvent.click(screen.getByRole("radio", { name: /Protect with a passphrase/ }));
    fireEvent.change(screen.getByLabelText("Unlock passphrase"), { target: { value: "a long passphrase" } });
    fireEvent.change(screen.getByLabelText("Repeat passphrase"), { target: { value: "a long passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: "Create profile" }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("profile_create", expect.anything()));
    fireEvent.click(screen.getByRole("button", { name: "Back to unlock" }));
    await act(async () => created.resolve({ profile_id: "p2", recovery_key: "RK-ONCE" }));
    await screen.findByRole("heading", { name: "Save your recovery key" });
    expect(screen.getByLabelText("Recovery key").textContent).toBe("RK-ONCE");
  });

  it("offer the new passphrase after a recovery-key unlock although the form was switched meanwhile", async () => {
    const unlocked = deferred<null>();
    backend([work], { profile_unlock: () => unlocked.promise });
    render(<LockScreen onUnlocked={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Use recovery key" }));
    fireEvent.change(screen.getByLabelText("Recovery key"), { target: { value: "RECOVERY-KEY" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("profile_unlock", expect.anything()));
    fireEvent.click(screen.getByRole("button", { name: "Use passphrase" }));
    await act(async () => unlocked.resolve(null));
    await screen.findByRole("heading", { name: "Set a new passphrase" });
  });
});

describe("every screen a lock leaves has a way forward", () => {
  const work: Profile = { profile_id: "p1", display_name: "Work", protection: "passphrase" };

  it("leads from a first-run recovery key shown across a lock to unlocking the new profile", async () => {
    let profiles: Profile[] = [];
    backend([], {
      app_status: () => ({ state: "locked", profile: null }),
      profiles_list: () => profiles,
      profile_create: () => {
        profiles = [work];
        return { profile_id: "p1", recovery_key: "RK-FIRST" };
      },
    });
    render(<App />);
    fireEvent.click(await screen.findByRole("radio", { name: /Protect with a passphrase/ }));
    fireEvent.change(screen.getByLabelText("Unlock passphrase"), { target: { value: "a long passphrase" } });
    fireEvent.change(screen.getByLabelText("Repeat passphrase"), { target: { value: "a long passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: "Create profile" }));
    await screen.findByRole("heading", { name: "Save your recovery key" });

    // The backend locks while the key shows: the key stays until it is acknowledged.
    await emitLocked("idle");
    expect(screen.getByLabelText("Recovery key").textContent).toBe("RK-FIRST");
    fireEvent.click(screen.getByRole("button", { name: /I stored it safely/ }));

    // The backend stayed locked: the unlock form offers the new profile.
    await screen.findByLabelText("Passphrase");
    expect((screen.getByLabelText("Profile") as HTMLSelectElement).value).toBe("p1");
    expect(screen.getByRole("button", { name: "Unlock" })).toBeTruthy();
  });

  it("leaves the new-passphrase step on Not now when the backend locked without an event", async () => {
    backend([work], { app_status: () => ({ state: "locked", profile: null }) });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Use recovery key" }));
    fireEvent.change(screen.getByLabelText("Recovery key"), { target: { value: "RECOVERY-KEY" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    await screen.findByRole("heading", { name: "Set a new passphrase" });
    fireEvent.click(screen.getByRole("button", { name: "Not now" }));
    await screen.findByLabelText("Passphrase");
    expect(screen.queryByRole("heading", { name: "Set a new passphrase" })).toBeNull();
  });

  it("returns from an enrollment entered while creating to the create form", () => {
    const enroll = lockScreen({ screen: { kind: "form", mode: "create" }, error: null }, { type: "failed", on: "form", message: "POLICY_ENROLLMENT_REQUIRED: x" });
    expect(enroll.screen).toEqual({ kind: "enroll", mode: "create", afterReset: false });
    expect(lockScreen(enroll, { type: "enrollBack" }).screen).toEqual({ kind: "form", mode: "create" });
  });
});
