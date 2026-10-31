// REL-003 built-bundle updater E2E: shared fixture code for the three specs in
// this folder. They run only through .github/workflows/updater-e2e.yml (not
// `npm run e2e`), against a bundled app (AppImage on Linux, .app on macOS)
// built with the test-only `e2e` feature, a test minisign key and the
// manifest endpoint http://127.0.0.1:$ANVIL_E2E_UPDATE_PORT/latest.json.
//
// Environment (set by the workflow):
//   ANVIL_E2E_UPDATE_INSTALLED  what the updater replaces: the AppImage file or the .app folder
//   ANVIL_E2E_UPDATE_FIXTURES   folder with update.bin (the signed updater artifact of the
//                               0.2.0 build), update.sig (its signature from `tauri build`),
//                               wrong-key.sig (`tauri signer sign` with another key) and, on
//                               macOS, expected.app (the 0.2.0 bundle)
//   ANVIL_E2E_UPDATE_PORT       the port compiled into the endpoint
//   ANVIL_DATA_DIR              the profile store, kept across the three runs
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { join, relative } from "node:path";
import { invoke } from "../helpers";

export function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set; run this spec through .github/workflows/updater-e2e.yml`);
  return v;
}

/** The version the update offers: the update bundle was built with it. */
export const OFFERED = "0.2.0";

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
  close(): Promise<void>;
}

/** The update endpoint the bundle was built with: a static-format latest.json and the artifact. */
export async function startUpdateServer(): Promise<UpdateServer> {
  const port = Number(required("ANVIL_E2E_UPDATE_PORT"));
  let manifest: Buffer = Buffer.alloc(0);
  let artifact: Buffer = Buffer.alloc(0);
  const requests: string[] = [];
  const server: Server = createServer((req, res) => {
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
      const entry = { signature, url: `http://127.0.0.1:${port}/update` };
      const platforms = Object.fromEntries(platformKeys().map((k) => [k, entry]));
      manifest = Buffer.from(JSON.stringify({ version: OFFERED, notes: "REL-003 built-bundle E2E", pub_date: "2026-10-31T00:00:00Z", platforms }));
      requests.length = 0;
    },
    close: () =>
      new Promise<void>((ok) => {
        server.closeAllConnections();
        server.close(() => ok());
      }),
  };
}
