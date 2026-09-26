// (c) Critical error family through the real engine: a connection to a closed
// loopback port is refused. The UI must report the transport failure and a
// connect-refused diagnosis with its confidence and an explicit
// "This does not prove" section — no response is invented.
import { $, $$, expect } from "@wdio/globals";
import { closedPort, cls, dimension, newRequest, responseTab, screenshot, send, setUrl, waitForWorkbench } from "../helpers";

describe("HTTP request — connection refused diagnosis", () => {
  let url = "";

  before(async () => {
    await waitForWorkbench();
    url = `http://127.0.0.1:${await closedPort()}/orders`;
  });

  it("reports a failed transport and no response", async () => {
    await newRequest();
    await setUrl(url);
    await send();
    await expect($(".resp-head .status-code")).toHaveText("No response");
    expect(await dimension("Transport")).toBe("failed");
    // Nothing reached a server, so no application result is claimed.
    expect(await dimension("Application")).toBe("not evaluated");
    expect(await dimension("Dispatch")).toBe("not dispatched");
  });

  it("explains the refusal with confidence, scope and what it does not prove", async () => {
    // The response panel keeps the tab chosen for an earlier exchange (Body in
    // the previous spec), so select Diagnosis explicitly. It must list one finding.
    await responseTab("Diagnosis");
    const tab = $(`//div[${cls("resp")}]/div[${cls("subtabs")}]/button[@role="tab"][starts-with(normalize-space(.),"Diagnosis")]`);
    await expect(tab).toHaveAttribute("aria-selected", "true");
    expect(await tab.getText()).toMatch(/^Diagnosis\s*[1-9]/);

    const card = $('article.finding[aria-label="The connection was refused"]');
    await expect(card).toBeDisplayed();
    await expect(card.$(".badge.conf-confirmed")).toHaveText("Confirmed");
    await expect(card).toHaveText(expect.stringContaining("client.connect.refused"));
    await expect(card).toHaveText(expect.stringContaining("Your connection → destination"));

    const headings = await card.$$("h4").map((h) => h.getText());
    expect(headings).toContain("This does not prove");
    const notProven = card.$('//h4[normalize-space()="This does not prove"]/following-sibling::ul[1]');
    const items = await notProven.$$("li").map((li) => li.getText());
    expect(items.length).toBeGreaterThan(0);
    expect(items.join("\n")).toMatch(/gateway's backend failed/);
    // No gateway attribution for a plain loopback destination.
    const codes = await $$("article.finding .mono").map((m) => m.getText());
    expect(codes.filter((c) => c.startsWith("ferrum."))).toEqual([]);
    await screenshot("03-diagnosis-connect-refused");
  });
});
