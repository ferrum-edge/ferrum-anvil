// REL-003, built bundle, run 2 of 3: relaunched after the refusals, the
// bundle is byte-for-byte what was installed, reports its own version and
// unlocks the same profile with the same workspaces. Then the control: an
// update signed by the bundle's key for the version it is offered as installs
// through the same `update_install` command and replaces the bundle with the
// 0.2.0 build. On Windows the plugin hands the verified installer (NSIS
// `/P /UPDATE`, or msiexec `/i … /passive`) to the shell and ends the app
// (`std::process::exit`), and the installer restarts it: the install is
// observed from outside, in the installed executable's version.
import { browser, expect } from "@wdio/globals";
import { readFileSync } from "node:fs";
import { invoke, profileName, waitForWorkbench } from "../helpers";
import {
  INSTALLED_VERSION,
  OFFERED,
  appVersion,
  contents,
  fixture,
  fixturePath,
  installed,
  installedExeVersion,
  notShm,
  required,
  runningInstalledApps,
  runningInstallers,
  snapshot,
  startUpdateServer,
  statePath,
  stopInstalledApps,
  until,
} from "./update";

describe("REL-003: after the refusals, the relaunched bundle is unchanged and a valid update installs", () => {
  before(async () => {
    await waitForWorkbench();
  });

  it("relaunches the untouched bundle at its own version with the same profile", async () => {
    const recorded = JSON.parse(readFileSync(statePath(), "utf8"));
    expect(contents(installed())).toEqual(recorded.installed);
    expect(await appVersion()).toBe(INSTALLED_VERSION);
    const status = await invoke<{ state: string; profile?: string }>("app_status");
    expect(status.ok?.state).toBe("unlocked");
    expect(status.ok?.profile).toBe(profileName());
    expect((await invoke<unknown[]>("workspaces_list")).ok).toEqual(recorded.workspaces);
  });

  it("installs a validly signed update", async () => {
    const server = await startUpdateServer();
    if (process.platform === "win32") {
      try {
        const profileBefore = contents(required("ANVIL_DATA_DIR"), notShm);
        server.offer(fixture("update.sig").toString("utf8").trim(), fixture("update.bin"));
        // update_install never answers on Windows (the app exits once the
        // installer is started), so it is started without waiting for it.
        await browser.execute((v: string) => {
          const internals = (window as unknown as { __TAURI_INTERNALS__: { invoke: (c: string, a: unknown) => Promise<unknown> } }).__TAURI_INTERNALS__;
          void internals.invoke("update_install", { version: v }).catch(() => {});
        }, OFFERED);
        await until("the update to be downloaded", () => server.requests.includes("/update"), 120_000);
        await until(`the installed executable to report ${OFFERED}`, () => installedExeVersion() === OFFERED, 300_000);
        await until("the update installer to finish", () => runningInstallers().length === 0, 300_000);
        expect(server.requests).toEqual(["/latest.json", "/update"]);
        // The installer restarts the app into the update; stop it so run 3
        // launches the installed update itself.
        await until("the installer to restart the app", () => runningInstalledApps().length > 0, 120_000);
        stopInstalledApps();
        await until("the restarted app to stop", () => runningInstalledApps().length === 0, 60_000);
        // The install changed no profile file.
        expect(contents(required("ANVIL_DATA_DIR"), notShm)).toEqual(profileBefore);
      } finally {
        await server.close();
      }
      return;
    }
    try {
      const profileBefore = snapshot(required("ANVIL_DATA_DIR"), notShm);
      server.offer(fixture("update.sig").toString("utf8").trim(), fixture("update.bin"));

      const r = await invoke<null>("update_install", { version: OFFERED });

      expect(r.err).toBeUndefined();
      expect(server.requests).toEqual(["/latest.json", "/update"]);
      // Linux: the AppImage file is now the 0.2.0 AppImage. macOS: the .app
      // folder now holds the 0.2.0 bundle the archive was made from.
      const expected = process.platform === "darwin" ? contents(fixturePath("expected.app")) : contents(fixturePath("update.bin"));
      expect(contents(installed())).toEqual(expected);
      expect(snapshot(required("ANVIL_DATA_DIR"), notShm)).toEqual(profileBefore);
    } finally {
      await server.close();
    }
  });
});
