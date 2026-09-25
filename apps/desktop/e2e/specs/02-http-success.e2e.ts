// (b) Happy path through the real native engine: a request to a local JSON
// fixture started by this test (or, with ANVIL_E2E_GATEWAY, through the real
// Ferrum Edge lab gateway) completes, and the body is shown as JSON.
import { $, expect } from "@wdio/globals";
import { dimension, type Fixture, newRequest, responseTab, screenshot, send, setUrl, startJsonFixture, waitForWorkbench } from "../helpers";

describe("HTTP request — success", () => {
  let fixture: Fixture | null = null;
  const gateway = process.env.ANVIL_E2E_GATEWAY?.replace(/\/+$/, "");

  before(async () => {
    if (!gateway) fixture = await startJsonFixture();
    await waitForWorkbench();
  });
  after(async () => fixture?.close());

  it("sends a GET and reports a completed, successful exchange", async () => {
    const url = gateway ? `${gateway}/ok/echo?from=anvil-e2e` : `${fixture!.url}/items/42?from=anvil-e2e`;
    await newRequest();
    await setUrl(url);
    await send();

    await expect($(".resp-head .status-code")).toHaveText("200");
    expect(await dimension("Transport")).toBe("completed");
    expect(await dimension("Application")).toBe("success");
    if (fixture) {
      // The fixture saw exactly the request the app sent — over a real socket.
      expect(fixture.requests).toHaveLength(1);
      expect(fixture.requests[0]).toMatchObject({ method: "GET", url: "/items/42?from=anvil-e2e" });
    }
  });

  it("shows the JSON body", async () => {
    await responseTab("Body");
    const pre = $('pre[aria-label="Response body"]');
    await pre.waitForDisplayed();
    const parsed = JSON.parse(await pre.getText());
    if (fixture) {
      expect(parsed).toEqual({ fixture: "anvil-e2e", ok: true, method: "GET", path: "/items/42?from=anvil-e2e" });
    } else {
      expect(typeof parsed).toBe("object");
    }
    await expect($(".resp .pane")).toHaveText(expect.stringContaining("application/json"));
    await screenshot("02-http-success-body");
  });

  it("records the exchange in history", async () => {
    await $('//button[@role="tab"][normalize-space()="History"]').click();
    await expect($(".hist-row")).toBeDisplayed();
    await expect($(".hist-row")).toHaveText(expect.stringContaining("200"));
    await $('//button[@role="tab"][normalize-space()="Collections"]').click();
  });
});
