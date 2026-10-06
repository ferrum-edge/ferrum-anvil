// (d) Locking is enforced in Rust, not only by the UI: after the Lock button,
// the lock screen is shown AND the backend refuses data commands.
// Runs last: the app stays locked for the rest of the session (unlocking
// would mean typing the passphrase into the UI, which E2E never does).
import { $, expect } from "@wdio/globals";
import { invoke, screenshot, waitForWorkbench } from "../helpers";

describe("lock", () => {
  let workspaceId = "";

  before(async () => {
    await waitForWorkbench();
    const list = await invoke<{ id: string }[]>("workspaces_list");
    expect(list.err).toBeUndefined();
    workspaceId = list.ok![0].id;
    const history = await invoke<unknown[]>("history_list", { workspaceId, requestId: null, limit: 10 });
    expect(history.err).toBeUndefined(); // unlocked: allowed
  });

  it("shows the lock screen after Lock", async () => {
    await $('header.topbar button[title^="Lock"]').click();
    await expect($("form.lock-card")).toBeDisplayed();
    await expect($("form.lock-card")).toHaveText(expect.stringContaining("Locked (manually)"));
    await expect($("form.lock-card button[type=submit]")).toHaveText("Unlock");
    expect(await $("header.topbar").isExisting()).toBe(false);
    await screenshot("05-lock-screen");
  });

  it("refuses data commands in the backend while locked", async () => {
    const status = await invoke<{ state: string }>("app_status");
    expect(status.ok?.state).toBe("locked");
    for (const [cmd, args] of [
      ["history_list", { workspaceId, requestId: null, limit: 10 }],
      ["workspaces_list", {}],
      ["tree_get", { workspaceId }],
      ["settings_get", {}],
      // No file dialog opens and no file is read while locked.
      ["file_choose", { purpose: "attachment", options: null }],
      ["certificate_file_choose", {}],
      ["private_key_file_choose", {}],
      ["read_certificate_file", { grant: `fg-${"0".repeat(32)}` }],
      ["import_private_key_file", { grant: `fg-${"0".repeat(32)}`, workspaceId, label: "key" }],
      ["import_pkcs12_file", { grant: `fg-${"0".repeat(32)}`, workspaceId, label: "p12" }],
      ["linked_file_status", { referrer: { kind: "request", id: "00000000-0000-0000-0000-000000000000" } }],
    ] as const) {
      const r = await invoke(cmd, args);
      expect({ cmd, ok: r.ok, err: r.err }).toEqual({ cmd, ok: undefined, err: "LOCKED" });
    }
  });
});
