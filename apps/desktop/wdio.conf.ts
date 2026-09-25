// Native desktop E2E for Ferrum Anvil (WebdriverIO + @wdio/tauri-service,
// embedded WebDriver provider = tauri-plugin-wdio-webdriver inside the app).
//
//   npm run e2e:build   # debug app build WITH the test-only `e2e` feature
//   npm run e2e         # run e2e/specs/*.e2e.ts against it
//
// The app under test is the real native build: requests go through the Rust
// engine; nothing is mocked. The `e2e` feature adds the embedded WebDriver
// server and an environment-driven profile unlock so no credential is ever
// typed into the UI; release builds never contain either
// (scripts/release-check.sh).
//
// Environment (all optional):
//   ANVIL_E2E_APP        path to the built app executable
//   ANVIL_E2E_GATEWAY    base URL of a running lab gateway (`anvil-lab up core`,
//                        e.g. http://127.0.0.1:18080); the success spec then
//                        goes through the real Ferrum Edge gateway
//   ANVIL_E2E_WD_PORT    WebDriver port (default: a free port)
//   ANVIL_DATA_DIR, ANVIL_E2E_PROFILE, ANVIL_E2E_PASSPHRASE
//                        normally generated per run (fresh temp data dir,
//                        random passphrase) and removed afterwards
import type { Options } from "@wdio/types";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../..");

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.once("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      s.close(() => ok(port));
    });
  });
}

function appBinary(): string {
  if (process.env.ANVIL_E2E_APP) return resolve(process.env.ANVIL_E2E_APP);
  const target = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : join(repo, "target");
  const exe = process.platform === "win32" ? "anvil-desktop.exe" : "anvil-desktop";
  return join(target, "debug", exe);
}

// The launcher evaluates this file first and spawns the app; workers inherit
// its environment, so every value below is generated exactly once per run.
const env = process.env;
const ownsDataDir = !env.ANVIL_DATA_DIR;
env.ANVIL_DATA_DIR ??= mkdtempSync(join(tmpdir(), "anvil-e2e-"));
env.ANVIL_E2E_PROFILE ??= "E2E profile";
env.ANVIL_E2E_PASSPHRASE ??= randomBytes(24).toString("base64url");
env.ANVIL_E2E_WD_PORT ??= String(await freePort());
// The service's direct-eval client reads TAURI_WEBDRIVER_PORT and otherwise
// defaults to 4445 — which may belong to another Tauri app under test on this
// machine. Pin it to the port of the app this run launches.
env.TAURI_WEBDRIVER_PORT = env.ANVIL_E2E_WD_PORT;
if (ownsDataDir) env.ANVIL_E2E_OWNS_DATA_DIR = "1";

const application = appBinary();
if (!existsSync(application)) {
  throw new Error(`E2E app not found at ${application}. Run \`npm run e2e:build\` first or set ANVIL_E2E_APP.`);
}

export const config: Options.Testrunner & { capabilities: WebdriverIO.Capabilities[] } = {
  runner: "local",
  specs: ["./e2e/specs/*.e2e.ts"],
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
        driverProvider: "embedded",
        embeddedPort: Number(env.ANVIL_E2E_WD_PORT),
        startTimeout: 120_000,
        captureBackendLogs: true,
        captureFrontendLogs: true,
        backendLogLevel: "warn",
        frontendLogLevel: "warn",
      },
    ],
  ],
  logLevel: "warn",
  bail: 0,
  waitforTimeout: 20_000,
  connectionRetryTimeout: 120_000,
  connectionRetryCount: 2,
  framework: "mocha",
  mochaOpts: { ui: "bdd", timeout: 120_000 },
  reporters: ["spec"],
  async before(_capabilities, _specs, browser) {
    // @wdio/tauri-service re-checks window focus before most commands through
    // its companion `tauri-plugin-wdio` (plugin:wdio|get_window_states), which
    // Anvil does not ship, so every check would wait for a timeout. Anvil has a
    // single window: selecting it explicitly turns that focus recovery off.
    const [main] = await browser.getWindowHandles();
    await browser.switchToWindow(main);
  },
  onComplete() {
    if (process.env.ANVIL_E2E_OWNS_DATA_DIR === "1" && process.env.ANVIL_DATA_DIR) {
      rmSync(process.env.ANVIL_DATA_DIR, { recursive: true, force: true });
    }
  },
};
