// (e) The Effective request tab shows what Send will put on the wire — the
// user's headers plus the ones Anvil adds — with secret header values
// redacted by the backend before they reach the webview.
import { $, $$, browser, expect } from "@wdio/globals";
import { randomBytes } from "node:crypto";
import { type Fixture, newRequest, requestTab, screenshot, setUrl, startJsonFixture, waitForWorkbench } from "../helpers";

describe("effective request", () => {
  let fixture: Fixture;
  const canary = `e2e-canary-${randomBytes(8).toString("hex")}`;

  before(async () => {
    fixture = await startJsonFixture();
    await waitForWorkbench();
  });
  after(async () => fixture.close());

  async function addHeader(name: string, value: string) {
    const names = () => $$('.editor .kv input[placeholder="name"]');
    const before = await names().length;
    await $('//div[contains(concat(" ", normalize-space(@class), " "), " kv ")]//button[normalize-space()="+ Add"]').click();
    await browser.waitUntil(async () => (await names().length) > before);
    await (await names())[before].setValue(name);
    await (await $$('.editor .kv input[placeholder="value or {{variable}}"]'))[before].setValue(value);
  }

  it("lists user headers, inferred headers and redacts secrets", async () => {
    await newRequest();
    await setUrl(`${fixture.url}/effective`);
    await requestTab("Headers");
    await addHeader("X-E2E-Trace", "trace-123");
    await addHeader("Authorization", `Bearer ${canary}`);

    await requestTab("Effective request");
    const code = $(".editor .pane pre.code");
    await expect(code).toHaveText(`GET ${fixture.url}/effective`);

    const headerRows = async () =>
      Object.fromEntries(
        await $$('//h4[normalize-space()="Headers"]/following-sibling::table[1]//tr').map(async (tr) => [
          (await tr.$("td.k").getText()).toLowerCase(),
          await tr.$("td.v").getText(),
        ]),
      ) as Record<string, string>;
    await browser.waitUntil(async () => "x-e2e-trace" in (await headerRows()), { timeoutMsg: "user header missing from the effective request" });
    const headers = await headerRows();
    expect(headers["x-e2e-trace"]).toBe("trace-123");
    expect(headers).toHaveProperty("authorization");
    expect(headers.authorization).not.toContain(canary);
    expect(headers.authorization).toMatch(/^Bearer .*redacted/);
    // Headers Anvil adds at send time are listed too.
    expect(headers["user-agent"]).toMatch(/^Ferrum-Anvil\//);
    await expect($('//h4[normalize-space()="Added by Anvil"]')).toBeExisting();
    // The secret never reaches the rendered page.
    expect(await $("body").getText()).not.toContain(canary);
    await expect($(".editor .pane")).toHaveText(expect.stringContaining("verification on"));
    const heading = await $('//h4[normalize-space()="Headers"]');
    await browser.execute((el: HTMLElement) => el.scrollIntoView({ block: "start" }), heading as unknown as HTMLElement);
    await screenshot("04-effective-request");
  });
});
