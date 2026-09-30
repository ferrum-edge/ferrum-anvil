// Updates: the launch check is opt-in (a setting saved with the others), a
// check on demand reports "up to date" or the release, a build that cannot
// verify updates sends the user to the release page, and one that can
// downloads, installs and restarts only when asked. "Later" puts the launch
// prompt off for the rest of the launch.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
const listeners = new Map<string, (ev: { payload: unknown }) => void>();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, cb: (ev: { payload: unknown }) => void) => {
    listeners.set(name, cb);
    return () => listeners.delete(name);
  }),
}));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(), open: vi.fn(), save: vi.fn() }));

import { SettingsDialog } from "./Dialogs";
import { UpdatePanel, UpdatePrompt, resetUpdateState, useLaunchUpdate } from "./Update";
import type { UpdateCheck } from "./api";
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

const update = { version: "0.2.0", name: "Ferrum Anvil 0.2.0", notes: "Faster sends.\n<b>not html</b>", published_at: "2026-10-01T00:00:00Z", url: "https://github.com/x" };
const available = (install: UpdateCheck["install"], install_quits = false): UpdateCheck => ({ current: "0.1.0", update, install, install_quits });

function backend(overrides: Record<string, (args: Record<string, unknown>) => unknown>) {
  invoke.mockImplementation(async (cmd: string, args: Record<string, unknown> = {}) => {
    if (overrides[cmd]) return overrides[cmd](args);
    if (cmd === "settings_get") return settings;
    if (cmd === "system_info") return null;
    if (cmd === "login_providers") return [];
    if (cmd === "profiles_list") return [];
    if (cmd === "app_status") return { state: "unlocked", profile: "Local", protection: "passphrase" };
    throw new Error(`unexpected command ${cmd}`);
  });
}

afterEach(() => {
  cleanup();
  resetUpdateState();
  invoke.mockReset();
  listeners.clear();
});

describe("Settings → Updates", () => {
  it("saves the opt-in launch check with the other settings", async () => {
    const saved: unknown[] = [];
    backend({ settings_save: (a) => saved.push(a.settings) });
    render(<SettingsDialog onClose={() => {}} onSaved={() => {}} />);
    const box = await screen.findByLabelText("Check for updates when Anvil opens");
    expect((box as HTMLInputElement).checked).toBe(false);
    fireEvent.click(box);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saved).toHaveLength(1));
    expect((saved[0] as AppSettings).check_for_updates).toBe(true);
  });

  it("checks on demand and says when Anvil is up to date", async () => {
    backend({ update_check: () => ({ current: "0.1.0", update: null, install: "release_page", install_quits: false }) });
    render(<SettingsDialog onClose={() => {}} onSaved={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Check now" }));
    expect(await screen.findByText("Ferrum Anvil 0.1.0 is up to date.")).toBeTruthy();
  });

  it("shows why a check failed", async () => {
    backend({
      update_check: () => {
        throw "GitHub's limit for update checks from this network was reached. Try again later.";
      },
    });
    render(<SettingsDialog onClose={() => {}} onSaved={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Check now" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Try again later");
  });

  it("offers a newer release found on demand", async () => {
    backend({ update_check: () => available("release_page") });
    render(<SettingsDialog onClose={() => {}} onSaved={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Check now" }));
    expect(await screen.findByText("Version 0.2.0 is available. You have 0.1.0.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open release page" })).toBeTruthy();
  });
});

describe("upgrading", () => {
  it("sends a build that cannot verify updates to the release page", async () => {
    const opened: unknown[] = [];
    backend({ update_open_release_page: (a) => opened.push(a.version) });
    render(<UpdatePanel check={available("release_page")} />);
    // Release notes are text, never markup.
    expect(screen.getByLabelText("Release notes").textContent).toContain("<b>not html</b>");
    expect(screen.queryByRole("button", { name: /Download and install/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Open release page" }));
    await waitFor(() => expect(opened).toEqual(["0.2.0"]));
  });

  it("downloads, installs and restarts only when asked", async () => {
    let finish: () => void = () => {};
    const calls: string[] = [];
    backend({
      update_install: (a) => {
        calls.push(`install ${a.version}`);
        return new Promise<void>((resolve) => (finish = resolve));
      },
      update_restart: () => void calls.push("restart"),
    });
    render(<UpdatePanel check={available("in_app")} />);
    expect(screen.getByText(/The new version starts when you restart Anvil/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Download and install" }));
    await waitFor(() => expect(calls).toEqual(["install 0.2.0"]));
    act(() => listeners.get("update-progress")!({ payload: { downloaded: 1024 * 1024, total: 4 * 1024 * 1024 } }));
    expect((await screen.findByRole("status")).textContent).toBe("Downloading… 1.00 MB of 4.00 MB");
    act(() => finish());
    await screen.findByText(/Ferrum Anvil 0\.2\.0 is installed\. Restart to use it\./);
    expect(calls).toEqual(["install 0.2.0"]);
    fireEvent.click(screen.getByRole("button", { name: "Restart now" }));
    await waitFor(() => expect(calls).toEqual(["install 0.2.0", "restart"]));
    expect(listeners.has("update-progress")).toBe(false);
  });

  it("keeps an install's progress when the dialog is closed and opened again", async () => {
    let finish: () => void = () => {};
    backend({ update_install: () => new Promise<void>((resolve) => (finish = resolve)) });
    const first = render(<UpdatePanel check={available("in_app")} />);
    fireEvent.click(screen.getByRole("button", { name: "Download and install" }));
    await waitFor(() => expect(listeners.has("update-progress")).toBe(true));
    act(() => listeners.get("update-progress")!({ payload: { downloaded: 2 * 1024 * 1024, total: 4 * 1024 * 1024 } }));
    first.unmount();
    render(<UpdatePanel check={available("in_app")} />);
    expect(screen.getByRole("status").textContent).toBe("Downloading… 2.00 MB of 4.00 MB");
    expect(screen.queryByRole("button", { name: "Download and install" })).toBeNull();
    act(() => finish());
    expect(await screen.findByRole("button", { name: "Restart now" })).toBeTruthy();
  });

  it("warns that the Windows installer closes Anvil", () => {
    render(<UpdatePanel check={available("in_app", true)} />);
    expect(screen.getByText(/Anvil closes while the installer runs/)).toBeTruthy();
  });

  it("reports a failed install and offers the release page", async () => {
    backend({
      update_install: () => {
        throw "The update was not installed: signature verification failed";
      },
    });
    render(<UpdatePanel check={available("in_app")} />);
    fireEvent.click(screen.getByRole("button", { name: "Download and install" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("signature verification failed");
    expect(screen.getByRole("button", { name: "Open release page" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });
});

describe("the launch prompt", () => {
  function Host(props: { onUpgrade: () => void }) {
    const check = useLaunchUpdate();
    return <UpdatePrompt check={check} onUpgrade={props.onUpgrade} />;
  }

  it("shows nothing while the setting is off", async () => {
    backend({ update_check_on_launch: () => null });
    render(<Host onUpgrade={() => {}} />);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("update_check_on_launch", undefined));
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("stays silent when the launch check fails", async () => {
    backend({
      update_check_on_launch: () => {
        throw "Could not reach GitHub";
      },
    });
    render(<Host onUpgrade={() => {}} />);
    await waitFor(() => expect(invoke).toHaveBeenCalled());
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("offers the upgrade, and Later puts it off for the rest of the launch", async () => {
    backend({ update_check_on_launch: () => available("in_app") });
    const upgrade = vi.fn();
    const { unmount } = render(<Host onUpgrade={upgrade} />);
    const prompt = await screen.findByRole("alertdialog", { name: "Update available" });
    expect(prompt.textContent).toContain("Ferrum Anvil 0.2.0 is available.");
    fireEvent.click(screen.getByRole("button", { name: "Upgrade…" }));
    expect(upgrade).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alertdialog")).toBeNull();
    // A lock and unlock mounts the workbench again: no second prompt.
    unmount();
    render(<Host onUpgrade={upgrade} />);
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });
});
