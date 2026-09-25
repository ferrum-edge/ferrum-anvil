// Shared helpers for the native E2E specs. They drive the real UI through the
// embedded WebDriver and, where a spec needs to observe the backend directly
// (e.g. to prove a lock is enforced in Rust), call the real IPC command —
// nothing here mocks a command or a network result.
import { $, $$, browser } from "@wdio/globals";
import { mkdirSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCREENSHOTS = join(dirname(fileURLToPath(import.meta.url)), "screenshots");

export const profileName = (): string => process.env.ANVIL_E2E_PROFILE ?? "";

/** Save a screenshot of the app window to e2e/screenshots/<name>.png. */
export async function screenshot(name: string): Promise<string> {
  mkdirSync(SCREENSHOTS, { recursive: true });
  const file = join(SCREENSHOTS, `${name}.png`);
  await browser.saveScreenshot(file);
  return file;
}

export interface IpcResult<T> {
  ok?: T;
  err?: string;
}

/** Call a real Tauri command in the app (no mocking) and capture success or the backend's error. */
export async function invoke<T>(cmd: string, args: Record<string, unknown> = {}): Promise<IpcResult<T>> {
  return browser.execute(
    async (c: string, a: Record<string, unknown>) => {
      const internals = (window as unknown as { __TAURI_INTERNALS__: { invoke: (c: string, a: unknown) => Promise<unknown> } }).__TAURI_INTERNALS__;
      try {
        return { ok: await internals.invoke(c, a) };
      } catch (e) {
        return { err: typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e) };
      }
    },
    cmd,
    args,
  ) as Promise<IpcResult<T>>;
}

/** Wait until the unlocked workbench is shown with a workspace selected. */
export async function waitForWorkbench(): Promise<void> {
  await $("header.topbar").waitForDisplayed({ timeout: 60_000 });
  const ws = $('select[aria-label="Workspace"]');
  await browser.waitUntil(async () => (await ws.getValue()) !== "", { timeout: 30_000, timeoutMsg: "no workspace was selected" });
}

const openTabs = () => $$('nav[aria-label="Open requests"] [role="tab"]');

/** Create a new request from the sidebar and wait for its editor. */
export async function newRequest(): Promise<void> {
  const before = await openTabs().length;
  await $('button[title^="New request ("]').click();
  await browser.waitUntil(async () => (await openTabs().length) > before, { timeout: 20_000, timeoutMsg: "new request tab did not open" });
  await $('input[aria-label="URL"]').waitForDisplayed();
}

export async function setUrl(url: string): Promise<void> {
  const input = $('input[aria-label="URL"]');
  await input.clearValue();
  await input.setValue(url);
  await browser.waitUntil(async () => (await input.getValue()) === url, { timeout: 10_000, timeoutMsg: `URL field did not take ${url}` });
}

/** Click Send and wait for the exchange to finish (response or failure). */
export async function send(): Promise<void> {
  await $(`//form[${cls("urlbar")}]//button[normalize-space()="Send"]`).click();
  await $(`//div[${cls("resp")}]/div[${cls("resp-head")}]`).waitForDisplayed({ timeout: 60_000 });
}

/** Value shown for an outcome dimension (Transport, Application, Tests, Dispatch). */
export async function dimension(label: string): Promise<string> {
  const b = $(`//div[${cls("resp-head")}]/span[${cls("dim")}][starts-with(normalize-space(.),"${label}")]/b`);
  return (await b.getText()).trim();
}

/** XPath predicate: the element has CSS class `name` (exact token). */
export function cls(name: string): string {
  return `contains(concat(" ", normalize-space(@class), " "), " ${name} ")`;
}

/** Select a tab of the response panel (Diagnosis, Body, Headers, ...). */
export async function responseTab(label: string): Promise<void> {
  await $(`//div[${cls("resp")}]/div[${cls("subtabs")}]/button[@role="tab"][starts-with(normalize-space(.),"${label}")]`).click();
}

/** Select a tab of the request editor (Params, Headers, ..., Effective request). */
export async function requestTab(label: string): Promise<void> {
  await $(`//div[${cls("editor")}]/div[not(${cls("resp")})]/div[${cls("subtabs")}]/button[@role="tab"][starts-with(normalize-space(.),"${label}")]`).click();
}

/** A local HTTP fixture started by the test process (not by the app). */
export interface Fixture {
  url: string;
  requests: { method: string; url: string; headers: Record<string, string | string[] | undefined> }[];
  close(): Promise<void>;
}

export async function startJsonFixture(): Promise<Fixture> {
  const requests: Fixture["requests"] = [];
  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    requests.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers });
    req.resume();
    req.on("end", () => {
      const body = JSON.stringify({ fixture: "anvil-e2e", ok: true, method: req.method, path: req.url });
      res.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
      res.end(body);
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((ok) => server.close(() => ok())),
  };
}

/** A loopback port with nothing listening (bound, then released). */
export async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((ok) => server.close(() => ok()));
  return port;
}
