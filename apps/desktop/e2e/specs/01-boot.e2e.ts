// (a) The E2E build unlocks its throw-away profile from the environment at
// startup, so the app boots straight into the workbench.
import { $, browser, expect } from "@wdio/globals";
import { invoke, profileName, screenshot, waitForWorkbench } from "../helpers";

describe("boot", () => {
  it("opens the unlocked workbench for the E2E profile", async () => {
    await waitForWorkbench();
    expect(await $(".lock").isExisting()).toBe(false);
    await expect($("footer.statusbar")).toHaveText(expect.stringContaining(`Profile: ${profileName()}`));
    await expect($("footer.statusbar")).toHaveText(expect.stringContaining("Local-only · no account"));
    await expect($("footer.statusbar")).toHaveText(expect.stringContaining("Diagnostics catalog findings:"));
  });

  it("reports the unlocked state from the Rust backend, not only the UI", async () => {
    const status = await invoke<{ state: string; profile?: string }>("app_status");
    expect(status.err).toBeUndefined();
    expect(status.ok?.state).toBe("unlocked");
    expect(status.ok?.profile).toBe(profileName());
    const info = await invoke<{ data_dir: string; catalog: string }>("system_info");
    // The run uses its own temporary data directory, never the user's profile store.
    expect(info.ok?.data_dir).toBe(process.env.ANVIL_DATA_DIR);
    expect(info.ok?.catalog).toMatch(/^findings:\S+ ferrum:ferrum-edge-/);
  });

  it("shows the empty workbench", async () => {
    await expect($("button=New request")).toBeDisplayed();
    expect(await browser.getTitle()).toBe("Ferrum Anvil");
    await screenshot("01-workbench");
  });
});
