// Runs against the native app launched by the existing WDIO service. No IPC
// mocks: these calls traverse Tauri deserialization and the production command.
import { $, browser, expect } from "@wdio/globals";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ImportedDiagnosticPreview } from "../../src/generated/contracts";
import { type Fixture, invoke, startJsonFixture, waitForWorkbench } from "../helpers";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const fixtures = join(repo, "contracts/ferrum-contracts/fixtures");
const golden = readFileSync(
  join(repo, "crates/anvil-diagnostics/tests/fixtures/alloy/diagnosis-edge-0.9.10.json"),
  "utf8",
);
const forged = readFileSync(
  join(fixtures, "diagnostic-report/valid/forged-verified-claim.json"),
  "utf8",
);
const preview = (text: string) =>
  invoke<ImportedDiagnosticPreview>("diagnostic_import_preview", { input: { text } });

// Compare numeric lexemes as strings, including every long timestamp in the
// actual exporter capture. Neither this check nor the renderer parses them.
function timestamps(text: string): string[] {
  return Array.from(text.matchAll(/"(?:start|end)_unix_nano"\s*:\s*(\d+)/g), (m) => m[1]);
}

// Hash the throw-away profile's persisted bytes, including encrypted vault,
// database/WAL, history and profile header. Never decrypt or resolve a secret.
function persistedBytes(root: string): Record<string, string> {
  const hashes: Record<string, string> = {};
  function visit(relative: string) {
    for (const entry of readdirSync(join(root, relative), { withFileTypes: true })) {
      const name = join(relative, entry.name);
      if (entry.isDirectory()) visit(name);
      else if (entry.isFile()) {
        hashes[name] = createHash("sha256").update(readFileSync(join(root, name))).digest("hex");
      }
    }
  }
  visit("");
  return hashes;
}

async function visibleState(workspaceId: string): Promise<unknown[]> {
  const calls: [string, Record<string, unknown>][] = [
    ["app_status", {}],
    ["profiles_list", {}],
    ["workspaces_list", {}],
    ["tree_get", { workspaceId }],
    ["environments_list", { workspaceId }],
    ["tls_profiles_list", { workspaceId }],
    ["proxy_profiles_list", { workspaceId }],
    ["integrations_list", { workspaceId }],
    ["history_list", { workspaceId, requestId: null, limit: 500 }],
    ["settings_get", {}],
  ];
  const state: unknown[] = [];
  for (const [command, args] of calls) {
    const result = await invoke(command, args);
    expect(result.err === undefined).toBe(true);
    state.push(result.ok);
  }
  return state;
}

async function paste(text: string): Promise<void> {
  // Native input setter + input event drives React's real onChange. This also
  // avoids WebDriver key-by-key entry of multi-megabyte negative controls.
  await browser.execute((value: string) => {
    const field = document.querySelector('[role="dialog"] textarea') as HTMLTextAreaElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
    setter.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
  }, text);
  await $('//button[normalize-space()="Preview diagnostic"]').click();
}

describe("read-only diagnostic import through native IPC", () => {
  let fixture: Fixture;
  let workspaceId = "";

  before(async () => {
    await waitForWorkbench();
    fixture = await startJsonFixture();
    workspaceId = await $('select[aria-label="Workspace"]').getValue();
  });

  after(async () => fixture.close());

  it("accepts all shared positives and refuses all shared negatives through Tauri", async () => {
    let count = 0;
    for (const contract of ["diagnostic-report", "diagnostic-finding", "diagnostic-ref"]) {
      for (const group of ["valid", "invalid"]) {
        const dir = join(fixtures, contract, group);
        for (const name of readdirSync(dir).sort()) {
          const result = await preview(readFileSync(join(dir, name), "utf8"));
          expect({ name, accepted: result.ok !== undefined }).toEqual({
            name,
            accepted: group === "valid",
          });
          if (result.ok) {
            expect(result.ok.trust).toBe("unverified");
            expect(result.ok.confidence).toBe("unknown");
            expect(typeof result.ok.reported_json).toBe("string");
          }
          count += 1;
        }
      }
    }
    expect(count).toBe(27);
  });

  it("keeps actual Alloy timestamps exact in the IPC DTO and the real preview UI", async () => {
    const result = await preview(golden);
    expect(result.err).toBeUndefined();
    expect(result.ok!.finding_count).toBe(2);
    expect(result.ok!.trust).toBe("unverified");
    expect(result.ok!.confidence).toBe("unknown");
    expect(timestamps(golden).length).toBeGreaterThan(0);
    expect(timestamps(result.ok!.reported_json)).toEqual(timestamps(golden));
    expect(result.ok!.reported_json.includes("1791123618658684620")).toBe(true);
    expect(result.ok!.reported_json).toBe(golden.trimEnd());
    // Source-derived CLI envelope around untouched golden bytes, not a CLI capture.
    const cli = await preview(`{"report":${golden},"warnings":[],"claimed_verification":"verified"}`);
    expect(cli.ok!.kind).toBe("alloy_cli");
    expect(timestamps(cli.ok!.reported_json)).toEqual(timestamps(golden));

    await $('button[aria-label="Import"]').click();
    await $('//button[@role="tab"][normalize-space()="Diagnostic preview"]').click();
    await paste(golden);
    const view = $('[data-testid="diagnostic-reported"]');
    await view.waitForDisplayed();
    const displayed = await browser.execute(() =>
      document.querySelector('[data-testid="diagnostic-reported"]')!.textContent,
    );
    expect(displayed).toBe(result.ok!.reported_json);
    expect(timestamps(displayed!)).toEqual(timestamps(golden));
    await expect($('section[aria-label="Unverified diagnostic preview"]')).toHaveText(
      expect.stringContaining("Anvil confidence: unknown"),
    );
    await $('[role="dialog"] button[aria-label="Close"]').click();
  });

  it("redacts structured credential echoes without state, network, history or vault writes", async () => {
    // Only this small forged fixture is decoded by JS; the exporter golden above
    // always stays text. These are synthetic canaries, never real credentials.
    const report = JSON.parse(forged);
    report.authenticated = true;
    report.provenance = { authenticated: true, verification: "verified" };
    const canaries = [
      "planted-secret-123",
      "set-cookie-canary",
      "pair-cookie-canary",
      "pair-set-canary",
      "url%2Duser",
      "url-user",
      "url%252Dpassword",
      "url%2Dpassword",
      "url-password",
      "bearer-canary",
      "api-key-canary",
      "dXNlcjpwYXNzd29yZA==",
      "overlap-token-long",
      "overlap-token",
    ];
    report.extensions = {
      cookie: "sid=planted-secret-123; other=ok",
      "set-cookie": ["sid=\"set-cookie-canary\"; Path=/ordinary"],
      headers: [
        { name: "Cookie", value: "sid=pair-cookie-canary; other=ok" },
        { key: "header.set-cookie", value: "sid=pair-set-canary; Path=/ordinary" },
      ],
      url: fixture.url.replace("://", "://url%2Duser:url%252Dpassword@"),
      authorization: "Bearer bearer-canary",
      basic: "Basic dXNlcjpwYXNzd29yZA==",
      api_key: "api-key-canary",
      passwords: ["overlap-token", "overlap-token-long", "overlap-token"],
      echo: canaries.join(" "),
      note: `<img src="${fixture.url}/image"> [click](${fixture.url}/link)`,
    };
    const text = JSON.stringify(report);
    const state = await visibleState(workspaceId);
    const profile = persistedBytes(process.env.ANVIL_DATA_DIR!);
    const result = await preview(text);
    expect(result.err === undefined).toBe(true);
    expect(result.ok!.trust).toBe("unverified");
    expect(result.ok!.confidence).toBe("unknown");
    expect(result.ok!.reported_json.includes('"authenticated": true')).toBe(true);
    expect(result.ok!.reported_json.includes('"verification": "verified"')).toBe(true);
    expect(result.ok!.reported_json.includes('"trust": "verified"')).toBe(true);
    // Boolean assertions never print canary-bearing DTOs or expected secrets.
    for (const canary of canaries) {
      expect(JSON.stringify(result).includes(canary)).toBe(false);
    }

    await $('button[aria-label="Import"]').click();
    await $('//button[@role="tab"][normalize-space()="Diagnostic preview"]').click();
    await paste(text);
    const view = $('[data-testid="diagnostic-reported"]');
    await view.waitForDisplayed();
    const displayed = await view.getText();
    for (const canary of canaries) expect(displayed.includes(canary)).toBe(false);
    expect(
      await browser.execute(() => {
        const region = document.querySelector('section[aria-label="Unverified diagnostic preview"]')!;
        return region.querySelectorAll("a, img, script, iframe").length;
      }),
    ).toBe(0);
    expect(await $('[role="dialog"] textarea').getValue()).toBe("");
    await $('[role="dialog"] button[aria-label="Close"]').click();
    expect(await visibleState(workspaceId)).toEqual(state);
    expect(persistedBytes(process.env.ANVIL_DATA_DIR!)).toEqual(profile);
    expect(fixture.requests.length).toBe(0);
  });

  it("refuses truncated, over-budget and capability-bearing input with fixed errors", async () => {
    const report = JSON.parse(forged);
    const invalidAttribute = JSON.parse(forged);
    invalidAttribute.observations[0].attributes.authorization = 42;
    for (const extensions of [
      { passwords: Array(128).fill("credential-canary") },
      { passwords: Array(32).fill("x".repeat(2048)) },
      { note: "é".repeat(1024) },
      { notes: Array(5000).fill("ordinary") },
    ]) {
      const result = await preview(JSON.stringify({ ...report, extensions }));
      expect(result.ok !== undefined).toBe(true);
      expect(result.ok!.trust).toBe("unverified");
    }
    const cases = [
      golden.slice(0, -20),
      " ".repeat(4 * 1024 * 1024 + 1),
      JSON.stringify({ ...report, extensions: { password: "x".repeat(2049) } }),
      JSON.stringify({
        ...report,
        extensions: { passwords: Array(129).fill("credential-canary") },
      }),
      JSON.stringify({ ...report, extensions: { passwords: Array(33).fill("x".repeat(2048)) } }),
      JSON.stringify({ ...report, extensions: { cookie: "a=x; b=y; ".repeat(65) } }),
      JSON.stringify({ ...report, extensions: { note: "é".repeat(1025) } }),
      JSON.stringify({ ...report, extensions: { notes: Array(5001).fill("ordinary") } }),
      JSON.stringify(invalidAttribute),
      JSON.stringify({ ...report, schema_version: "2.0" }),
      '{"schema":null,"schema":"ferrum.diagnostic_report"}',
      `{"report":${golden},"warnings":null,"claimed_verification":"verified"}`,
    ];
    for (const text of cases) {
      const result = await preview(text);
      expect(result.ok === undefined).toBe(true);
      expect(result.err?.startsWith("Diagnostic ")).toBe(true);
      expect(result.err?.includes("credential-canary")).toBe(false);
    }
    for (const input of [
      { text: forged, path: "/diagnostic.json" },
      { text: forged, url: fixture.url },
      { text: forged, grant: "forged" },
      { text: null },
    ]) {
      const result = await invoke("diagnostic_import_preview", { input });
      expect(result.ok === undefined).toBe(true);
    }
    expect(fixture.requests.length).toBe(0);
  });

  it("bounds native preview presentation and clears errors and stale content", async () => {
    const report = JSON.parse(forged);
    report.extensions = { control: "\u202e", notes: Array(40).fill("é".repeat(1024)) };
    await $('button[aria-label="Import"]').click();
    await $('//button[@role="tab"][normalize-space()="Diagnostic preview"]').click();
    await paste(JSON.stringify(report));
    const view = $('[data-testid="diagnostic-reported"]');
    await view.waitForDisplayed();
    const displayed = await view.getText();
    expect(Buffer.byteLength(displayed, "utf8")).toBeLessThanOrEqual(64 * 1024);
    expect(displayed.includes("\\u202e")).toBe(true);
    expect(displayed.includes("\u202e")).toBe(false);
    await expect($('[role="dialog"]')).toHaveText(
      expect.stringContaining("Presentation limited to the first 64 KiB"),
    );
    await $('//button[normalize-space()="Clear preview"]').click();
    expect(await view.isExisting()).toBe(false);
    await paste("credential-canary-not-json");
    const alert = $('[role="dialog"] [role="alert"]');
    await alert.waitForDisplayed();
    expect((await alert.getText()).includes("credential-canary")).toBe(false);
    expect(await view.isExisting()).toBe(false);
    await $('//button[normalize-space()="Clear preview"]').click();
    expect(await alert.isExisting()).toBe(false);
    await $('[role="dialog"] button[aria-label="Close"]').click();
  });
});
