// A short load run through the real worker process (the app re-launches
// itself with --anvil-load-worker), started only after the explicit
// authorization acknowledgement, ending in a saved report.
import { $, browser, expect } from "@wdio/globals";
import { type Fixture, cls, invoke, startJsonFixture, screenshot, waitForWorkbench } from "../helpers";

describe("Load test — acknowledged run and saved report", () => {
  let fixture: Fixture;
  const planName = "E2E smoke load";

  before(async () => {
    fixture = await startJsonFixture();
    await waitForWorkbench();
    const ws = await $('select[aria-label="Workspace"]').getValue();
    const req = await invoke<{ id: string }>("request_create", {
      workspaceId: ws,
      folderId: null,
      name: "Load target",
      spec: { protocol: "http", method: "GET", url: `${fixture.url}/items`, params: [], headers: [], body: { type: "none" }, auth: { type: "none" } },
    });
    expect(req.err).toBeUndefined();
    const now = new Date().toISOString();
    const plan = await invoke("load_plan_save", {
      plan: {
        id: crypto.randomUUID(),
        workspace_id: ws,
        name: planName,
        workload: { model: "iterations", iterations: 300, concurrency: 6 },
        chain: [req.ok!.id],
        mix: [],
        connection_mode: "persistent",
        warmup_secs: 0,
        seed: 1,
        trusted: true,
        created_at: now,
        updated_at: now,
      },
    });
    expect(plan.err).toBeUndefined();
  });
  after(async () => fixture.close());

  it("refuses to start without acknowledgement, then runs and saves the report", async () => {
    await $('//div[@aria-label="View"]/button[normalize-space()="Load tests"]').click();
    await $(`//aside//div[${cls("tree-row")}][normalize-space()="${planName}"]`).click();
    await $('//button[normalize-space()="Run…"]').click();
    const start = $('//div[@role="dialog"]//button[normalize-space()="Start load"]');
    await expect(start).toBeDisabled();
    await $('//div[@role="dialog"]//label[contains(., "authorized to load-test")]/input').click();
    await expect(start).toBeEnabled();
    await start.click();
    const done = $(`//section//span[${cls("badge")}][normalize-space()="completed"]`);
    await done.waitForDisplayed({ timeout: 90_000 });
    await browser.pause(300);
    expect(fixture.requests.length).toBe(300);
    await screenshot("08-load-report");
    // Specs share one app instance: leave it in the Requests view.
    await $('//div[@aria-label="View"]/button[normalize-space()="Requests"]').click();
  });
});
