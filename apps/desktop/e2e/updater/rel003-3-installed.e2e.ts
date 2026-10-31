// REL-003, built bundle, run 3 of 3: relaunched after the valid update, the
// installed bundle is the update (it reports the offered version) and unlocks
// the same profile.
import { expect } from "@wdio/globals";
import { invoke, profileName, waitForWorkbench } from "../helpers";
import { OFFERED, appVersion } from "./update";

describe("REL-003: the relaunched bundle runs the installed update", () => {
  it("reports the offered version and unlocks the same profile", async () => {
    await waitForWorkbench();
    expect(await appVersion()).toBe(OFFERED);
    const status = await invoke<{ state: string; profile?: string }>("app_status");
    expect(status.ok?.state).toBe("unlocked");
    expect(status.ok?.profile).toBe(profileName());
  });
});
