// Through the real Ferrum Edge lab gateway (ANVIL_E2E_GATEWAY, `anvil-lab up
// core`): a route whose backend refuses connections. With the gateway
// declared as a Ferrum gateway profile, the diagnosis attributes the failure
// to the gateway→backend leg at "likely" (markers are coarse and spoofable on
// v0.9.5) and never claims TLS or DNS. Skipped without a lab gateway.
import { $, $$, expect } from "@wdio/globals";
import { invoke, newRequest, responseTab, screenshot, send, setUrl, waitForWorkbench } from "../helpers";

const gateway = process.env.ANVIL_E2E_GATEWAY?.replace(/\/+$/, "");

(gateway ? describe : describe.skip)("Ferrum gateway — backend connection failure", () => {
  before(async () => {
    await waitForWorkbench();
    const ws = await $('select[aria-label="Workspace"]').getValue();
    const u = new URL(gateway!);
    const now = new Date().toISOString();
    const saved = await invoke("integration_save", {
      profile: {
        id: crypto.randomUUID(),
        workspace_id: ws,
        name: "Lab gateway (v0.9.5)",
        kind: "ferrum_gateway",
        hosts: [{ host: u.hostname, port: Number(u.port) }],
        compatibility_id: "ferrum-edge-0.9.5",
        require_verified_tls: false,
        created_at: now,
        updated_at: now,
      },
    });
    expect(saved.err).toBeUndefined();
  });

  it("attributes the failure to the gateway→backend leg at likely, without claiming TLS", async () => {
    await newRequest();
    await setUrl(`${gateway}/up/refused/orders?id=42`);
    await send();
    await expect($(".resp-head .status-code")).toHaveText("502");
    await responseTab("Diagnosis");
    const first = $("article.finding");
    await expect(first).toHaveAttribute("aria-label", "Gateway could not prepare a connection to the backend");
    await expect(first.$(".badge.conf-likely")).toHaveText("Likely");
    await expect(first).toHaveText(expect.stringContaining("Gateway → backend"));
    const notProven = await first.$$('//h4[normalize-space()="This does not prove"]/following-sibling::ul[1]/li').map((li) => li.getText());
    expect(notProven.join("\n")).toMatch(/TLS failed/);
    // No gateway claim is ever "confirmed" from the public marker.
    const confirmedGateway = await $$("article.finding").filter(async (f) => {
      const code = await f.$(".mono").getText();
      return code.startsWith("ferrum.") && (await f.$(".badge.conf-confirmed").isExisting());
    });
    expect(confirmedGateway).toHaveLength(0);
    await screenshot("06-gateway-backend-connection-failure");
  });
});
