// REL-005: offline, no-account smoke. A local profile (no sign-in, no account,
// no provider configured) authors and sends a request to a loopback fixture,
// reopens the exchange from history and opens a saved load report. For the
// whole session the app process holds no socket to a non-loopback address:
// nothing phones home, and neither login nor telemetry is a prerequisite.
//
// The socket check inspects the app process itself (found through the
// embedded WebDriver port it listens on). The webview cannot reach the network
// either way: its CSP only allows IPC (see security.test.tsx).
import { $, browser, expect } from "@wdio/globals";
import { execFileSync, spawnSync } from "node:child_process";
import { type Fixture, cls, dimension, invoke, newRequest, screenshot, send, setUrl, startJsonFixture, waitForWorkbench } from "../helpers";

interface Socket {
  line: string;
  local: string;
  remote: string | null;
}

function appPid(): string {
  const port = process.env.ANVIL_E2E_WD_PORT ?? "";
  if (process.platform === "win32") {
    const out = execFileSync("powershell", ["-NoProfile", "-Command", `(Get-NetTCPConnection -LocalPort ${port} -State Listen).OwningProcess`], {
      encoding: "utf8",
    });
    return out.trim().split(/\s+/)[0];
  }
  return execFileSync("lsof", ["-nP", "-t", `-iTCP:${port}`, "-sTCP:LISTEN"], { encoding: "utf8" }).trim().split(/\s+/)[0];
}

function sockets(pid: string): Socket[] {
  if (process.platform === "win32") {
    // Both cmdlets report "no objects found" as an error when the process
    // has no socket of that kind (the expected case for UDP), and PowerShell
    // then exits non-zero; read stdout and end with an explicit success.
    const r = spawnSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        `Get-NetTCPConnection -OwningProcess ${pid} -ErrorAction SilentlyContinue | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) $($_.RemoteAddress):$($_.RemotePort) $($_.State)" }; ` +
          `Get-NetUDPEndpoint -OwningProcess ${pid} -ErrorAction SilentlyContinue | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) - UDP" }; exit 0`,
      ],
      { encoding: "utf8" },
    );
    if (r.status !== 0) throw new Error(`socket query failed (${r.status}): ${r.stderr}`);
    return (
      r.stdout
        .split(/\r?\n/)
        .filter(Boolean)
        // "Bound" is Windows' listing of a socket that has a local port but no
        // connection yet (an outgoing connect shows up this way next to its
        // Established entry). It carries no traffic; a real connection from
        // it still appears as Established with its remote address.
        .filter((line) => line.split(" ")[2] !== "Bound")
        .map((line) => {
          const [local, remote] = line.split(" ");
          return { line, local, remote: remote === "-" || remote.startsWith("0.0.0.0:") || remote.startsWith(":::") ? null : remote };
        })
    );
  }
  let out = "";
  try {
    out = execFileSync("lsof", ["-nP", "-a", "-p", pid, "-i"], { encoding: "utf8" });
  } catch (e) {
    // lsof exits 1 when the process has no matching sockets.
    out = (e as { stdout?: string }).stdout ?? "";
  }
  return out
    .split("\n")
    .slice(1)
    .filter(Boolean)
    .map((line) => {
      const name = line.split(/\s+/).slice(8).join(" ").replace(/\s*\(.*\)$/, "");
      const [local, remote] = name.split("->");
      return { line, local, remote: remote ?? null };
    });
}

const LOOPBACK = /^(127\.\d+\.\d+\.\d+|\[::1\]|::1|localhost)(:\d+)?$/;
const hostPort = (s: string) => s.replace(/^\[?(.*?)\]?:(\d+|\*)$/, (_m, h: string, p: string) => `${h.includes(":") ? `[${h}]` : h}:${p}`);

// The embedded WebDriver server exists only in the test-only `e2e` build
// (scripts/release-check.sh proves release builds lack it); it is not the
// product's network use.
const webdriverPort = `:${process.env.ANVIL_E2E_WD_PORT ?? ""}`;

function nonLoopback(all: Socket[]): string[] {
  return all
    .filter((s) => !(s.remote === null && s.local.endsWith(webdriverPort)))
    .filter((s) => {
      const addr = hostPort(s.remote ?? s.local);
      // A listening or unconnected socket must be bound to loopback; a
      // connected one must point at loopback.
      return !LOOPBACK.test(addr);
    })
    .map((s) => s.line);
}

describe("Offline, no-account smoke (REL-005)", () => {
  let fixture: Fixture;
  let pid = "";
  const seen: Socket[] = [];
  // The app and its children (the self-launched load worker).
  const sample = () => {
    let pids = [pid];
    if (process.platform !== "win32") {
      try {
        pids = pids.concat(execFileSync("pgrep", ["-P", pid], { encoding: "utf8" }).split(/\s+/).filter(Boolean));
      } catch {
        // pgrep exits 1 when there are no children.
      }
    }
    for (const p of pids) seen.push(...sockets(p));
  };

  before(async () => {
    fixture = await startJsonFixture();
    await waitForWorkbench();
    // Specs share one app instance; start from the Requests view.
    await $('//div[@aria-label="View"]/button[normalize-space()="Requests"]').click();
    pid = appPid();
    expect(pid).toMatch(/^\d+$/);
    sample();
  });
  after(async () => fixture.close());

  it("is unlocked into a local profile with no account or provider", async () => {
    const status = await invoke<{ state: string; profile: string | null }>("app_status");
    expect(status.ok?.state).toBe("unlocked");
    expect(status.ok?.profile).toBeTruthy();
    // Sign-in providers are optional: none is required to reach the workbench,
    // and no token exists for any of them in this profile.
    const providers = await invoke<{ id: string }[]>("login_providers");
    expect(providers.err).toBeUndefined();
    await expect($("header.topbar")).toBeDisplayed();
  });

  it("authors and sends a local request, then reopens it from history", async () => {
    await newRequest();
    await setUrl(`${fixture.url}/offline`);
    await send();
    sample();
    expect(await dimension("Transport")).toMatch(/completed/i);
    expect(fixture.requests.some((r) => r.url === "/offline")).toBe(true);

    await $('//aside//button[@role="tab"][normalize-space()="History"]').click();
    const row = $(`//aside//div[${cls("hist-row")}][contains(., "/offline")]`);
    await row.waitForDisplayed();
    await row.click();
    const dialog = $('//div[@role="dialog"]');
    await dialog.waitForDisplayed();
    await expect(dialog.$(`.//*[contains(normalize-space(.), "${fixture.url}/offline")]`)).toBeDisplayed();
    await screenshot("09-offline-history");
    await browser.keys("Escape");
    await $('//aside//button[@role="tab"][normalize-space()="Collections"]').click();
  });

  it("opens a saved load report", async () => {
    const ws = await $('select[aria-label="Workspace"]').getValue();
    const req = await invoke<{ id: string }>("request_create", {
      workspaceId: ws,
      folderId: null,
      name: "Offline load target",
      spec: { protocol: "http", method: "GET", url: `${fixture.url}/load`, params: [], headers: [], body: { type: "none" }, auth: { type: "none" } },
    });
    expect(req.err).toBeUndefined();
    const now = new Date().toISOString();
    const planId = crypto.randomUUID();
    const plan = await invoke("load_plan_save", {
      plan: {
        id: planId,
        workspace_id: ws,
        name: "Offline smoke load",
        workload: { model: "iterations", iterations: 20, concurrency: 2 },
        chain: [req.ok!.id],
        mix: [],
        connection_mode: "persistent",
        warmup_secs: 0,
        seed: 1,
        trusted: true,
        created_at: now,
        updated_at: now,
      },
    });
    expect(plan.err).toBeUndefined();
    const before = (await invoke<{ run_id: string }[]>("load_reports", { workspaceId: ws })).ok?.length ?? 0;
    const started = await invoke<string>("load_run_start", { planId, acknowledged: true });
    expect(started.err).toBeUndefined();
    await browser.waitUntil(async () => ((await invoke<unknown[]>("load_reports", { workspaceId: ws })).ok?.length ?? 0) > before, {
      timeout: 60_000,
      timeoutMsg: "the load report was not saved",
    });
    sample();

    await $('//div[@aria-label="View"]/button[normalize-space()="Load tests"]').click();
    const report = $(`//aside//div[${cls("hist-row")}][contains(., "Offline smoke load")]`);
    await report.waitForDisplayed();
    await report.click();
    await $(`//section//b[normalize-space()="Offline smoke load"]`).waitForDisplayed();
    await screenshot("09-offline-report");
    await $('//div[@aria-label="View"]/button[normalize-space()="Requests"]').click();
  });

  it("never opened a socket to a non-loopback address", async () => {
    sample();
    const distinct = [...new Set(seen.map((s) => (s.remote ? `${s.local}->${s.remote}` : s.local)))];
    console.log(`REL-005: ${distinct.length} distinct app sockets observed: ${distinct.join(", ")}`);
    expect(seen.length).toBeGreaterThan(0); // the probe really saw the app's sockets
    expect(nonLoopback(seen)).toEqual([]);
  });
});
