// WebdriverIO against a RELEASE-profile build without the test-only `e2e`
// feature (REL-003, .github/workflows/updater-e2e.yml): the app has no
// embedded WebDriver and no environment-driven unlock, so it is driven
// through the official `tauri-driver` (the @wdio/tauri-service "external"
// provider), which starts the platform's own WebDriver: WebKitWebDriver on
// Linux, msedgedriver (matched to the WebView2 runtime) on Windows. Tauri
// enables webview automation for the process tauri-driver launches
// (TAURI_WEBVIEW_AUTOMATION); Anvil's code is the shipped release code. The
// profile is created beforehand with the release CLI and unlocked through the
// lock screen by the specs (apps/desktop/e2e/updater/update.ts).
//
// Environment: ANVIL_E2E_APP (the installed app), ANVIL_DATA_DIR,
// ANVIL_E2E_PROFILE, ANVIL_E2E_PASSPHRASE, ANVIL_E2E_RELEASE=1.
import type { Options } from "@wdio/types";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const env = process.env;
for (const name of ["ANVIL_E2E_APP", "ANVIL_DATA_DIR", "ANVIL_E2E_PROFILE", "ANVIL_E2E_PASSPHRASE"]) {
  if (!env[name]) throw new Error(`${name} is not set; run this config through .github/workflows/updater-e2e.yml`);
}
env.ANVIL_E2E_RELEASE = "1";
const application = resolve(env.ANVIL_E2E_APP as string);
if (!existsSync(application)) throw new Error(`release app not found at ${application}`);

export const config: Options.Testrunner & { capabilities: WebdriverIO.Capabilities[] } = {
  runner: "local",
  specs: ["./e2e/updater/*.e2e.ts"],
  maxInstances: 1,
  capabilities: [
    {
      browserName: "tauri",
      "tauri:options": { application },
    } as WebdriverIO.Capabilities,
  ],
  services: [
    [
      "@wdio/tauri-service",
      {
        driverProvider: "external",
        autoInstallTauriDriver: false,
        autoDownloadEdgeDriver: true,
        captureBackendLogs: false,
        captureFrontendLogs: false,
      },
    ],
  ],
  logLevel: "warn",
  bail: 0,
  waitforTimeout: 20_000,
  connectionRetryTimeout: 120_000,
  connectionRetryCount: 2,
  framework: "mocha",
  mochaOpts: { ui: "bdd", timeout: 300_000 },
  reporters: ["spec"],
  async before(_capabilities, _specs, browser) {
    const [main] = await browser.getWindowHandles();
    await browser.switchToWindow(main);
  },
};
