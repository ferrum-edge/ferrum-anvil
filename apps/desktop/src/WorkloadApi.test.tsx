// Renderer tests for the SPIFFE Workload API editors and evidence (jsdom; no
// engine). The Workload API itself is exercised by the Rust tests and the
// `workload` lab; here: the JWT-SVID auth editor, the TLS profile's Workload
// API identity, the probe (IPC mocked) and the record's evidence view.
import { useState } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { AuthConfig, TlsProfile } from "./generated/contracts";
import type { ExecutionView, WorkloadProbe } from "./api";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

import { AuthEditor } from "./AuthEditor";
import { TlsForm } from "./Dialogs";
import { ResponsePanel } from "./ResponsePanel";

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

function AuthHarness(props: { onValue: (a: AuthConfig) => void }) {
  const [a, setA] = useState<AuthConfig>({ type: "none" });
  return (
    <AuthEditor
      value={a}
      workspaceId="ws"
      onChange={(n) => {
        setA(n);
        props.onValue(n);
      }}
    />
  );
}

function tlsProfile(): TlsProfile {
  return {
    id: "00000000-0000-0000-0000-00000000000a",
    workspace_id: "ws",
    name: "mesh",
    verify: true,
    use_system_roots: false,
    extra_roots_pem: [],
    bindings: [],
    server_spiffe: { expected_server_spiffe_id: "spiffe://example.org/ns/a/sa/api" },
    created_at: "2026-09-26T00:00:00Z",
    updated_at: "2026-09-26T00:00:00Z",
  } as TlsProfile;
}

function TlsHarness(props: { onValue: (p: TlsProfile) => void }) {
  const [p, setP] = useState<TlsProfile>(tlsProfile());
  return (
    <TlsForm
      p={p}
      onChange={(n) => {
        setP(n);
        props.onValue(n);
      }}
    />
  );
}

const PROBE: WorkloadProbe = {
  endpoint: "unix:///run/spire/sockets/agent.sock",
  endpoint_source: "setting",
  calls: [
    { rpc: "FetchX509SVID", endpoint: "unix:///run/spire/sockets/agent.sock", endpoint_source: "setting", purpose: "Workload API probe", result: { result: "ok" } },
    {
      rpc: "FetchJWTSVID",
      endpoint: "unix:///run/spire/sockets/agent.sock",
      endpoint_source: "setting",
      purpose: "Workload API probe",
      caller_uid: 501,
      result: { result: "status", code: 7, code_name: "PERMISSION_DENIED", message: "no identity issued" },
    },
  ],
  x509_svids: [{ spiffe_id: "spiffe://example.org/ns/a/sa/client", not_after: "2026-09-26T01:00:00Z", chain_length: 1, bundle_certificates: 1 }],
  federated_trust_domains: [],
  jwt_bundles: [{ trust_domain: "example.org", key_ids: ["k1"] }],
};

describe("JWT-SVID auth editor", () => {
  it("defaults to the Workload API with bundle verification and edits audiences and sources", async () => {
    let last = { type: "none" } as AuthConfig;
    render(<AuthHarness onValue={(a) => (last = a)} />);
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "jwt_svid" } });
    expect(last).toEqual({
      type: "jwt_svid",
      config: {
        source: { kind: "workload_api" },
        audiences: [],
        endpoint: "",
        verify_with_bundles: true,
        send_despite_failed_checks: false,
        header_name: "Authorization",
        prefix: "Bearer",
      },
    });
    expect(screen.getByText(/refused before anything is sent/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/Audiences/), { target: { value: "spiffe://example.org/api, other" } });
    expect(last.type === "jwt_svid" && last.config.audiences).toEqual(["spiffe://example.org/api", "other"]);
    fireEvent.change(screen.getByLabelText(/Workload API endpoint/), { target: { value: "unix:///tmp/agent.sock" } });
    expect(last.type === "jwt_svid" && last.config.endpoint).toBe("unix:///tmp/agent.sock");
    // A token from a variable; without bundle verification no endpoint is needed.
    fireEvent.change(screen.getByLabelText("Token source"), { target: { value: "value" } });
    expect(last.type === "jwt_svid" && last.config.source).toEqual({ kind: "value", token: { kind: "template", value: "" } });
    fireEvent.click(screen.getByLabelText(/Verify the signature/));
    expect(screen.queryByLabelText(/Workload API endpoint/)).toBeNull();
    // A token file comes only from the backend's dialog, which binds it; the path is not typed.
    fireEvent.change(screen.getByLabelText("Token source"), { target: { value: "file" } });
    expect((screen.getByLabelText("Token file") as HTMLInputElement).readOnly).toBe(true);
    invoke.mockImplementation(async (cmd: string) => (cmd === "file_choose" ? [{ token: "binding", file_name: "jwt", path: "/run/secrets/jwt" }] : null));
    fireEvent.click(screen.getByRole("button", { name: "Choose…" }));
    await waitFor(() => expect(last.type === "jwt_svid" && last.config.source).toEqual({ kind: "file", path: "/run/secrets/jwt" }));
    expect(invoke).toHaveBeenCalledWith("file_choose", { purpose: "jwt_svid_file", options: { multiple: false } });
  });

  it("lists the token files chosen on this device and removes one chosen by mistake", async () => {
    let bound = [
      { id: "b1", path: "/run/secrets/jwt", bound_at: "2026-01-01T00:00:00Z" },
      { id: "b2", path: "/home/me/.ssh/id_ed25519", bound_at: "2026-01-02T00:00:00Z" },
    ];
    invoke.mockImplementation(async (cmd: string, args?: { bindingId?: string }) => {
      if (cmd === "token_files_list") return bound;
      if (cmd === "token_file_remove") bound = bound.filter((b) => b.id !== args?.bindingId);
      return null;
    });
    let last = { type: "none" } as AuthConfig;
    render(<AuthHarness onValue={(a) => (last = a)} />);
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "jwt_svid" } });
    fireEvent.change(screen.getByLabelText("Token source"), { target: { value: "file" } });
    const list = await screen.findByRole("table", { name: "Token files chosen on this device" });
    expect(list.textContent).toContain("/run/secrets/jwt");
    expect(list.textContent).toContain("/home/me/.ssh/id_ed25519");

    fireEvent.click(screen.getByRole("button", { name: "Remove /home/me/.ssh/id_ed25519" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Remove /home/me/.ssh/id_ed25519" })).toBeNull());
    expect(invoke).toHaveBeenCalledWith("token_file_remove", { bindingId: "b2" });
    expect(screen.getByRole("button", { name: "Remove /run/secrets/jwt" })).toBeTruthy();
    // Removing a binding does not edit the auth setting.
    expect(last.type === "jwt_svid" && last.config.source).toEqual({ kind: "file", path: "" });

    fireEvent.click(screen.getByRole("button", { name: "Remove /run/secrets/jwt" }));
    await waitFor(() => expect(screen.queryByRole("table", { name: "Token files chosen on this device" })).toBeNull());
    expect(bound).toEqual([]);
  });

  it("warns before sending a token that failed its checks", () => {
    let last = { type: "none" } as AuthConfig;
    render(<AuthHarness onValue={(a) => (last = a)} />);
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "jwt_svid" } });
    expect(screen.queryByText(/will be sent/)).toBeNull();
    fireEvent.click(screen.getByLabelText(/Send even when a local check fails/));
    expect(last.type === "jwt_svid" && last.config.send_despite_failed_checks).toBe(true);
    expect(screen.getByText(/An expired, mis-addressed or unverifiable JWT-SVID will be sent/)).toBeTruthy();
  });

  it("probes the Workload API through the backend and shows only public results", async () => {
    invoke.mockImplementation(async (cmd: string) => (cmd === "workload_probe" ? PROBE : null));
    render(<AuthHarness onValue={() => {}} />);
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "jwt_svid" } });
    fireEvent.change(screen.getByLabelText(/Audiences/), { target: { value: "spiffe://example.org/api" } });
    fireEvent.click(screen.getByRole("button", { name: "Test the Workload API" }));
    await waitFor(() => expect(screen.getByTestId("workload-probe")).toBeTruthy());
    expect(invoke).toHaveBeenCalledWith("workload_probe", { endpoint: "", audience: "spiffe://example.org/api" });
    const text = screen.getByTestId("workload-probe").textContent ?? "";
    expect(text).toContain("spiffe://example.org/ns/a/sa/client");
    expect(text).toContain('PERMISSION_DENIED "no identity issued"');
    expect(text).toContain("Anvil runs as uid 501");
  });
});

describe("TLS profile: Workload API identity", () => {
  it("selects an X.509-SVID from the Workload API and its bundle as trust", () => {
    let last = tlsProfile();
    render(<TlsHarness onValue={(p) => (last = p)} />);
    expect(screen.getByText(/SPIFFE verification needs them/)).toBeTruthy();
    fireEvent.change(screen.getByDisplayValue("None"), { target: { value: "workload_api" } });
    expect(last.client_identity).toEqual({ format: "workload_api", endpoint: "", trust_bundle: true });
    // The bundle comes from the Workload API, so the missing-CA warning goes away.
    expect(screen.queryByText(/SPIFFE verification needs them/)).toBeNull();
    fireEvent.change(screen.getByLabelText(/Workload API endpoint/), { target: { value: "unix:///run/spire/sockets/agent.sock" } });
    fireEvent.change(screen.getByLabelText(/SPIFFE ID \(when the workload holds several/), { target: { value: "spiffe://example.org/ns/a/sa/client" } });
    expect(last.client_identity).toEqual({
      format: "workload_api",
      endpoint: "unix:///run/spire/sockets/agent.sock",
      spiffe_id: "spiffe://example.org/ns/a/sa/client",
      trust_bundle: true,
    });
    expect(screen.getByText(/fetched again at half its lifetime/)).toBeTruthy();
  });
});

describe("Workload API evidence", () => {
  it("shows the endpoint, the SVID and the JWT-SVID checks on the Connection tab", () => {
    const record = {
      id: "00000000-0000-0000-0000-000000000002",
      prepared: {
        method: "GET",
        url: "https://127.0.0.1:17406/echo",
        headers: [],
        workload_api: {
          calls: [
            { rpc: "FetchX509SVID", endpoint: "unix:///tmp/wl.sock", endpoint_source: "environment", purpose: "TLS profile 'mesh' client identity", cached: true, result: { result: "ok" } },
          ],
          x509_svids: [
            {
              tls_profile: "mesh",
              spiffe_id: "spiffe://example.org/ns/a/sa/client",
              certificate: { subject: "CN=x", issuer: "CN=ca", subject_alt_names: [], not_before: "a", not_after: "2026-09-27", serial_hex: "01", sha256_fingerprint: "AA", is_ca: false, key_algorithm: "EC-256" },
              chain_length: 1,
              offered_spiffe_ids: [],
              bundle_trusted: true,
              bundle_certificates: 1,
              federated_trust_domains: ["partner.example"],
            },
          ],
          jwt_svid: {
            source: "workload_api",
            requested_audiences: ["aud"],
            subject: "spiffe://example.org/ns/a/sa/client",
            audiences: ["aud"],
            algorithm: "ES256",
            checks: [
              { check: "expiry", result: "failed", detail: "exp is 3s in the past by this machine's clock" },
              { check: "signature", result: "not_run", detail: "bundle verification is off" },
            ],
            sent_despite_failed_checks: true,
          },
        },
      },
      attempts: [{ index: 0, duration_us: 10, phases: [], dispatch: "sent", bytes: {} }],
      response: null,
      outcome: { transport: "failed", application: "not_evaluated", assertions: "not_run", dispatch: "not_dispatched", warnings: [], summary: "x" },
      assertion_results: [],
      findings: [],
    };
    const view = { record, body: { text: null, pretty: null, hex: null, is_binary: false, decoded: false, shown_bytes: 0, captured_bytes: 0 } } as unknown as ExecutionView;
    render(<ResponsePanel view={view} running={false} progressBytes={null} onCancel={() => {}} />);
    fireEvent.click(screen.getByRole("tab", { name: /Connection/ }));
    const ev = screen.getByTestId("workload-evidence").textContent ?? "";
    expect(ev).toContain("unix:///tmp/wl.sock (SPIFFE_ENDPOINT_SOCKET)");
    expect(ev).toContain("OK (cached)");
    expect(ev).toContain("trust-domain bundle trusted (1 CA)");
    expect(ev).toContain("federated bundles recorded, not trusted: partner.example");
    expect(ev).toContain("exp is 3s in the past");
    expect(ev).toContain("despite failed checks");
    expect(ev).toContain("never recorded");
  });
});
