// REL-003 built-bundle updater E2E: shared fixture code for the three specs in
// this folder. They run only through .github/workflows/updater-e2e.yml (not
// `npm run e2e`), against a bundled app (AppImage on Linux, .app on macOS, the
// NSIS or MSI install on Windows) built with the test-only `e2e` feature, a
// test minisign key and the manifest endpoint
// https://127.0.0.1:$ANVIL_E2E_UPDATE_PORT/latest.json.
//
// Environment (set by the workflow):
//   ANVIL_E2E_UPDATE_INSTALLED  what the updater replaces: the AppImage file, the .app folder,
//                               or on Windows the install folder
//   ANVIL_E2E_UPDATE_BUNDLE     Windows: nsis or msi, the install under test (its latest.json key)
//   ANVIL_E2E_APP               the installed app's executable
//   ANVIL_E2E_UPDATE_OFFERED    the version the update offers (newer than the shipped one)
//   ANVIL_E2E_UPDATE_FIXTURES   folder with update.bin (the signed updater artifact of the
//                               offered build), update.sig (its signature from `tauri build`),
//                               wrong-key.sig (`tauri signer sign` with another key), on
//                               macOS expected.app (the offered bundle), tls-cert.pem and
//                               tls-key.pem (the endpoint's certificate, issued by a test CA
//                               the workflow added to the system trust store),
//                               untrusted-cert.pem and untrusted-key.pem (from a CA nobody
//                               trusts) and published-latest.json (the latest.json of the
//                               newest published release, whose shape every manifest served
//                               here copies)
//   ANVIL_E2E_UPDATE_PORT       the port compiled into the endpoint
//   ANVIL_DATA_DIR              the profile store, kept across the three runs
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { basename, join, relative } from "node:path";
import { invoke } from "../helpers";

export function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set; run this spec through .github/workflows/updater-e2e.yml`);
  return v;
}

/** The version the update offers: the update bundle was built with it (the shipped major + 1). */
export const OFFERED: string = required("ANVIL_E2E_UPDATE_OFFERED");

/** The installed bundle's version: the shipped tauri.conf.json version. */
export const INSTALLED_VERSION: string = JSON.parse(readFileSync(new URL("../../src-tauri/tauri.conf.json", import.meta.url), "utf8")).version;

export const installed = (): string => required("ANVIL_E2E_UPDATE_INSTALLED");
export const fixturePath = (name: string): string => join(required("ANVIL_E2E_UPDATE_FIXTURES"), name);
export const fixture = (name: string): Buffer => readFileSync(fixturePath(name));
/** Where run 1 records the installed bundle for run 2. */
export const statePath = (): string => fixturePath("rel003-state.json");

/** SQLite's shared-memory index changes on reads; it is not stored state. */
export const notShm = (rel: string): boolean => !rel.endsWith("-shm");

const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

export type Tree = Record<string, string>;

function walk(root: string, entry: (p: string, rel: string) => string, keep: (rel: string) => boolean): Tree {
  const out: Tree = {};
  const visit = (p: string) => {
    const rel = relative(root, p) || ".";
    if (!keep(rel)) return;
    out[rel] = entry(p, rel);
    if (lstatSync(p).isDirectory()) for (const name of readdirSync(p)) visit(join(p, name));
  };
  visit(root);
  return out;
}

/** Content of every file, link and folder under `root` (or of the file `root`): SHA-256s, link targets. */
export function contents(root: string, keep: (rel: string) => boolean = () => true): Tree {
  return walk(
    root,
    (p) => {
      const st = lstatSync(p);
      if (st.isSymbolicLink()) return `link ${readlinkSync(p)}`;
      return st.isDirectory() ? "dir" : `file ${sha256(readFileSync(p))}`;
    },
    keep,
  );
}

/** `contents` plus each entry's mode, size, inode and modification time. */
export function snapshot(root: string, keep: (rel: string) => boolean = () => true): Tree {
  const c = contents(root, keep);
  return walk(
    root,
    (p, rel) => {
      const st = lstatSync(p);
      return `${c[rel]} mode=${st.mode.toString(8)} size=${st.size} ino=${st.ino} mtime=${st.mtimeMs}`;
    },
    keep,
  );
}

/** Manifest keys as scripts/updater-manifest.mjs writes them for this platform. */
function platformKeys(): string[] {
  const arch = process.arch === "arm64" ? "aarch64" : "x86_64";
  if (process.platform === "win32") return [`windows-${arch}-${required("ANVIL_E2E_UPDATE_BUNDLE")}`];
  return process.platform === "darwin" ? [`darwin-${arch}-app`, `darwin-${arch}`] : [`linux-${arch}-appimage`];
}

/** The configured key's signature (base64 `.sig` text) with one bit of its Ed25519 signature flipped. */
export function corruptSignature(sig: string): string {
  const lines = Buffer.from(sig.trim(), "base64").toString("utf8").split("\n");
  const raw = Buffer.from(lines[1], "base64");
  raw[10 + 7] ^= 0x01;
  lines[1] = raw.toString("base64");
  return Buffer.from(lines.join("\n")).toString("base64");
}

/** `bytes` with one bit in the middle flipped. */
export function altered(bytes: Buffer): Buffer {
  const b = Buffer.from(bytes);
  b[b.length >> 1] ^= 0x01;
  return b;
}

/** The version the running app reports (Tauri's package info: what the updater compares). */
export async function appVersion(): Promise<string | undefined> {
  return (await invoke<string>("plugin:app|version")).ok;
}

export interface UpdateServer {
  /** Request paths since the last `offer`. */
  requests: string[];
  /** Serve a manifest offering OFFERED with this signature, and this artifact. */
  offer(signature: string, artifact: Buffer): void;
  /** Present the certificate from a CA the system does not trust (`true`), or the trusted one. */
  untrusted(on: boolean): void;
  close(): Promise<void>;
}

const tls = (cert: string, key: string) => ({ cert: fixture(cert), key: fixture(key) });

/**
 * The update endpoint the bundle was built with, over HTTPS: a static-format
 * latest.json and the artifact. Every manifest copies the published
 * latest.json (its fields and the platform entry's fields) and replaces only
 * the version, the URL and the signature.
 */
export async function startUpdateServer(): Promise<UpdateServer> {
  const port = Number(required("ANVIL_E2E_UPDATE_PORT"));
  const published = JSON.parse(fixture("published-latest.json").toString("utf8"));
  let manifest: Buffer = Buffer.alloc(0);
  let artifact: Buffer = Buffer.alloc(0);
  const requests: string[] = [];
  const server: Server = createServer(tls("tls-cert.pem", "tls-key.pem"), (req, res) => {
    requests.push(req.url ?? "");
    req.resume();
    const body = req.url === "/latest.json" ? manifest : req.url === "/update" ? artifact : undefined;
    if (!body) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": req.url === "/latest.json" ? "application/json" : "application/octet-stream", "content-length": body.length });
    res.end(body);
  });
  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(port, "127.0.0.1", () => ok());
  });
  return {
    requests,
    offer(signature, bytes) {
      artifact = bytes;
      const platforms = Object.fromEntries(
        platformKeys().map((k) => {
          if (!published.platforms?.[k]) throw new Error(`the published latest.json has no ${k} entry`);
          return [k, { ...published.platforms[k], signature, url: `https://127.0.0.1:${port}/update` }];
        }),
      );
      manifest = Buffer.from(JSON.stringify({ ...published, version: OFFERED, platforms }));
      requests.length = 0;
    },
    untrusted(on) {
      server.setSecureContext(on ? tls("untrusted-cert.pem", "untrusted-key.pem") : tls("tls-cert.pem", "tls-key.pem"));
    },
    close: () =>
      new Promise<void>((ok) => {
        server.closeAllConnections();
        server.close(() => ok());
      }),
  };
}

// ------------------------------------------------------------ Windows
const powershell = (script: string): string => execFileSync("powershell", ["-NoProfile", "-Command", script], { encoding: "utf8" }).trim();
const psQuote = (s: string): string => `'${s.replaceAll("'", "''")}'`;

/** Windows: the ProductVersion of the installed executable (what the installer wrote). */
export function installedExeVersion(): string {
  return powershell(`(Get-Item -LiteralPath ${psQuote(required("ANVIL_E2E_APP"))}).VersionInfo.ProductVersion`);
}

/** Windows: process ids of the installed executable that are running. */
export function runningInstalledApps(): number[] {
  const name = basename(required("ANVIL_E2E_APP"), ".exe");
  const out = powershell(`@(Get-Process -Name ${psQuote(name)} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id) -join ','`);
  return out ? out.split(",").map(Number) : [];
}

/** Windows: process ids of a running update installer (NSIS setup or msiexec). */
export function runningInstallers(): number[] {
  const out = powershell(
    // The updater stages the NSIS installer in the temp folder as
    // `<app>-<version>-installer.exe` (tauri-plugin-updater write_to_temp) and
    // starts msiexec `/i <msi>` for an MSI.
    "@(Get-CimInstance Win32_Process | Where-Object { $_.Name -like '*-installer.exe' -or $_.Name -like '*-setup.exe' -or ($_.Name -eq 'msiexec.exe' -and $_.CommandLine -match '/i ') } | Select-Object -ExpandProperty ProcessId) -join ','",
  );
  return out ? out.split(",").map(Number) : [];
}

/** Windows: end every running instance of the installed executable (and its WebView2 children). */
export function stopInstalledApps(): void {
  for (const pid of runningInstalledApps()) {
    try {
      execFileSync("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore" });
    } catch {
      // already gone
    }
  }
}

/**
 * Forget the WebDriver session of an app that has ended, so the runner's
 * teardown (wdio-runner `endSession`, which skips a browser without a
 * `sessionId`) does not try to delete a session nobody answers any more. The
 * `browser` exported by `@wdio/globals` is a read-only proxy (it has no `set`
 * trap): assigning through it lands on the proxy target and leaves the
 * runner's instance untouched, so this clears the instance the runner
 * registered itself.
 */
export function forgetEndedSession(): void {
  const registered = (globalThis as unknown as { _wdioGlobals?: Map<string, { sessionId?: string }> })._wdioGlobals?.get("browser");
  if (!registered) throw new Error("no WebdriverIO browser instance is registered");
  registered.sessionId = undefined;
}

export async function until(what: string, check: () => boolean, timeoutMs: number): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (check()) {
      // Progress goes to the worker's output as it happens, so a run whose
      // reporter output is lost still shows how far it got.
      console.log(`updater e2e: ${what} after ${Math.round((Date.now() - start) / 1000)} s`);
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`timed out after ${timeoutMs / 1000} s waiting for ${what}`);
}
