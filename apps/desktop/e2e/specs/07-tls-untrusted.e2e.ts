// Frontend certificate problem: an HTTPS server whose certificate was issued
// by a throwaway CA (generated per run, never trusted globally). The diagnosis is
// an untrusted issuer on the caller's leg; verification stays on and the
// remediation never leads with disabling it. Skipped where openssl is absent.
import { $, expect } from "@wdio/globals";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dimension, newRequest, responseTab, screenshot, send, setUrl, waitForWorkbench } from "../helpers";

/** A leaf certificate for localhost signed by a throwaway CA that nothing trusts. */
function untrustedLeaf(): { key: Buffer; cert: Buffer; dir: string } | null {
  const dir = mkdtempSync(join(tmpdir(), "anvil-e2e-tls-"));
  const f = (n: string) => join(dir, n);
  try {
    const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
    execFileSync("openssl", ["req", "-x509", ...ec, "-days", "1", "-subj", "/CN=Anvil E2E throwaway CA", "-keyout", f("ca.key"), "-out", f("ca.pem")], { stdio: "ignore" });
    execFileSync("openssl", ["req", ...ec, "-subj", "/CN=localhost", "-keyout", f("key.pem"), "-out", f("leaf.csr")], { stdio: "ignore" });
    writeFileSync(f("ext.cnf"), "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n");
    execFileSync(
      "openssl",
      ["x509", "-req", "-in", f("leaf.csr"), "-CA", f("ca.pem"), "-CAkey", f("ca.key"), "-CAcreateserial", "-days", "1", "-extfile", f("ext.cnf"), "-out", f("cert.pem")],
      { stdio: "ignore" },
    );
    return { key: readFileSync(f("key.pem")), cert: readFileSync(f("cert.pem")), dir };
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return null;
  }
}

const material = untrustedLeaf();

(material ? describe : describe.skip)("HTTPS — untrusted certificate", () => {
  let server: Server;
  let url = "";
  before(async () => {
    server = createServer({ key: material!.key, cert: material!.cert }, (_req, res) => res.end("unreachable"));
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    url = `https://localhost:${(server.address() as AddressInfo).port}/account`;
    await waitForWorkbench();
  });
  after(async () => {
    await new Promise<void>((ok) => server.close(() => ok()));
    rmSync(material!.dir, { recursive: true, force: true });
  });

  it("diagnoses an untrusted issuer on the caller's leg and keeps verification on", async () => {
    await newRequest();
    await setUrl(url);
    await send();
    expect(await dimension("Transport")).toBe("failed");
    expect(await dimension("Dispatch")).toBe("not dispatched");
    await responseTab("Diagnosis");
    const card = $("article.finding");
    await expect(card).toHaveText(expect.stringContaining("client.tls.untrusted_issuer"));
    await expect(card).toHaveText(expect.stringContaining("Your connection → destination"));
    const steps = await card.$$('//h4[normalize-space()="What to check next"]/following-sibling::ul[1]/li').map((li) => li.getText());
    expect(steps.length).toBeGreaterThan(0);
    expect(steps[0].toLowerCase()).not.toMatch(/disable|bypass|turn off verification/);
    await screenshot("07-tls-untrusted-certificate");
  });
});
