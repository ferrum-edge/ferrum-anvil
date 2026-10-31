// REL-003, built bundle, run 2 of 3: relaunched after the refusals, the
// bundle is byte-for-byte what was installed, reports its own version and
// unlocks the same profile. Then the control: an update signed by the
// bundle's key for the version it is offered as installs through the same
// `update_install` command and replaces the bundle with the 0.2.0 build.
import { expect } from "@wdio/globals";
import { readFileSync } from "node:fs";
import { invoke, profileName, waitForWorkbench } from "../helpers";
import { INSTALLED_VERSION, OFFERED, appVersion, contents, fixture, fixturePath, installed, notShm, required, snapshot, startUpdateServer, statePath } from "./update";

describe("REL-003: after the refusals, the relaunched bundle is unchanged and a valid update installs", () => {
  before(async () => {
    await waitForWorkbench();
  });

  it("relaunches the untouched bundle at its own version with the same profile", async () => {
    const recorded = JSON.parse(readFileSync(statePath(), "utf8")).installed;
    expect(contents(installed())).toEqual(recorded);
    expect(await appVersion()).toBe(INSTALLED_VERSION);
    const status = await invoke<{ state: string; profile?: string }>("app_status");
    expect(status.ok?.state).toBe("unlocked");
    expect(status.ok?.profile).toBe(profileName());
  });

  it("installs a validly signed update", async () => {
    const server = await startUpdateServer();
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
