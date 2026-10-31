// REL-003, built bundle, run 1 of 3: the installed bundle refuses an update
// signed by another key, one with a corrupted signature and one altered after
// signing. Each attempt goes through the app's real `update_install` command
// (pinned tauri-plugin-updater, the bundle's compiled-in test key and
// endpoint), after the app requested the manifest and the artifact, and
// leaves the bundle, the reported version and the persistent profile files
// (SQLite's -shm read index aside) unchanged.
import { expect } from "@wdio/globals";
import { writeFileSync } from "node:fs";
import { invoke, profileName, waitForWorkbench } from "../helpers";
import {
  INSTALLED_VERSION,
  OFFERED,
  altered,
  appVersion,
  contents,
  corruptSignature,
  fixture,
  installed,
  notShm,
  required,
  snapshot,
  startUpdateServer,
  statePath,
  type UpdateServer,
} from "./update";

describe("REL-003: the built bundle refuses tampered updates", () => {
  let server: UpdateServer;
  const update = fixture("update.bin");
  const signature = fixture("update.sig").toString("utf8").trim();

  before(async () => {
    await waitForWorkbench();
    server = await startUpdateServer();
  });
  after(async () => server?.close());

  it("runs the installed bundle at its own version with the E2E profile unlocked", async () => {
    expect(INSTALLED_VERSION).not.toBe(OFFERED);
    expect(await appVersion()).toBe(INSTALLED_VERSION);
    const status = await invoke<{ state: string; profile?: string }>("app_status");
    expect(status.ok?.state).toBe("unlocked");
    expect(status.ok?.profile).toBe(profileName());
    // Run 2 relaunches this bundle and compares it, and the profile's
    // workspaces as the app reads them, with this record.
    const workspaces = await invoke<unknown[]>("workspaces_list");
    expect(workspaces.err).toBeUndefined();
    expect(workspaces.ok?.length).toBeGreaterThan(0);
    writeFileSync(statePath(), JSON.stringify({ installed: contents(installed()), workspaces: workspaces.ok }));
  });

  const cases: [string, () => string, () => Buffer, string][] = [
    ["signed by another key", () => fixture("wrong-key.sig").toString("utf8").trim(), () => update, "The signature was created with a different key than the one provided"],
    ["with a corrupted signature", () => corruptSignature(signature), () => update, "The signature verification failed"],
    ["altered after signing", () => signature, () => altered(update), "The signature verification failed"],
  ];
  for (const [name, sig, artifact, why] of cases) {
    it(`refuses an update ${name} and changes nothing`, async () => {
      const bundleBefore = snapshot(installed());
      const profileBefore = snapshot(required("ANVIL_DATA_DIR"), notShm);
      server.offer(sig(), artifact());

      const r = await invoke<null>("update_install", { version: OFFERED });

      expect(r.err).toBe(`The update was not installed: ${why}`);
      // The app read the manifest and requested the artifact: the refusal is
      // the signature check (the plugin verifies after the download).
      expect(server.requests).toEqual(["/latest.json", "/update"]);
      expect(snapshot(installed())).toEqual(bundleBefore);
      expect(snapshot(required("ANVIL_DATA_DIR"), notShm)).toEqual(profileBefore);
      expect(await appVersion()).toBe(INSTALLED_VERSION);
      expect((await invoke<{ state: string }>("app_status")).ok?.state).toBe("unlocked");
    });
  }
});
