// Renderer unit tests for the diagnosis/response view: confidence and scope
// wording, the explicit "does not prove" section, and inert rendering of
// untrusted response bodies. jsdom only — the native path is covered by
// apps/desktop/e2e.
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import type { ExecutionView } from "./api";
import type { DiagnosticFinding } from "./generated/contracts";
import { FindingCard, ResponsePanel } from "./ResponsePanel";

afterEach(cleanup);

function finding(patch: Partial<DiagnosticFinding> = {}): DiagnosticFinding {
  return {
    code: "client.connect.refused",
    rule_id: "network.connect",
    rule_version: 1,
    title: "The destination refused the connection",
    explanation: "Nothing accepted a TCP connection on 127.0.0.1:9.",
    scope: "client_to_peer",
    confidence: "confirmed",
    severity: "error",
    evidence: [{ source: "native_transport", key: "failure.kind", value: "ConnectRefused" }],
    alternatives: ["A firewall rejected the connection on the host's behalf."],
    does_not_prove: ["That the API itself is down."],
    remediation: [{ text: "Check that the service is listening on that port.", owner: "caller" }],
    owner: "caller",
    confirm_with: ["Try the port with another client from the same machine."],
    ...patch,
  };
}

describe("FindingCard", () => {
  it("shows the confidence badge, scope label, owner and code", () => {
    render(<FindingCard f={finding()} />);
    const card = screen.getByRole("article", { name: "The destination refused the connection" });
    expect(within(card).getByText("Confirmed")).toHaveProperty("className", "badge conf-confirmed");
    expect(within(card).getByText("Your connection → destination")).toBeTruthy();
    expect(within(card).getByText("Owner: caller")).toBeTruthy();
    expect(within(card).getByText("client.connect.refused")).toBeTruthy();
  });

  it.each([
    ["likely", "Likely"],
    ["unknown", "Unknown"],
    ["conflicting_evidence", "Conflicting evidence"],
  ] as const)("labels %s confidence honestly", (confidence, label) => {
    render(<FindingCard f={finding({ confidence })} />);
    expect(screen.getByText(label).className).toBe(`badge conf-${confidence}`);
  });

  it("labels an unestablished origin instead of guessing a component", () => {
    render(<FindingCard f={finding({ scope: "unknown", owner: "unknown" })} />);
    expect(screen.getByText("Origin not established")).toBeTruthy();
    expect(screen.getByText("Owner: unknown")).toBeTruthy();
  });

  it("renders the 'This does not prove' section with each statement", () => {
    render(<FindingCard f={finding({ does_not_prove: ["That the API itself is down.", "That TLS is misconfigured."] })} />);
    const heading = screen.getByRole("heading", { name: "This does not prove" });
    const list = heading.nextElementSibling as HTMLElement;
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "That the API itself is down.",
      "That TLS is misconfigured.",
    ]);
  });

  it("omits empty sections rather than rendering empty headings", () => {
    render(<FindingCard f={finding({ does_not_prove: [], alternatives: [], confirm_with: [], remediation: [], evidence: [] })} />);
    expect(screen.queryByRole("heading", { name: "This does not prove" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Other possibilities" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "What to check next" })).toBeNull();
    expect(screen.queryByText(/^Evidence \(/)).toBeNull();
  });

  it("lists remediation with its owner and exposes evidence rows", () => {
    render(<FindingCard f={finding()} />);
    expect(screen.getByRole("heading", { name: "What to check next" })).toBeTruthy();
    expect(screen.getByText(/Check that the service is listening/).textContent).toContain("— caller");
    expect(screen.getByText("Evidence (1)")).toBeTruthy();
    expect(screen.getByText("ConnectRefused")).toBeTruthy();
  });
});

function view(patch: { findings?: DiagnosticFinding[]; bodyText?: string; transport?: string; application?: string }): ExecutionView {
  const withResponse = patch.bodyText != null;
  const record = {
    id: "00000000-0000-0000-0000-000000000001",
    catalog_version: "findings:test ferrum:test",
    prepared: { method: "GET", url: "http://127.0.0.1:9/", headers: [] },
    attempts: [{ index: 1, duration_us: 1500, phases: [], dispatch: "not_dispatched", bytes: {} }],
    response: withResponse
      ? {
          status: 200,
          reason: "OK",
          http_version: "HTTP/1.1",
          headers: [{ name: "content-type", value: "text/html" }],
          trailers: [],
          trailers_received: false,
          body: { completeness: "complete", wire_bytes: 40, captured_bytes: 40, display_truncated: false, content_type: "text/html" },
        }
      : null,
    outcome: {
      transport: patch.transport ?? (withResponse ? "completed" : "failed"),
      application: patch.application ?? (withResponse ? "success" : "not_evaluated"),
      assertions: "not_run",
      dispatch: "not_dispatched",
      warnings: [],
      summary: withResponse ? "HTTP 200 OK" : "Connection refused before anything was sent",
    },
    assertion_results: [],
    findings: patch.findings ?? [],
  };
  return {
    record,
    body: { text: patch.bodyText ?? null, pretty: null, hex: null, is_binary: false, decoded: false, shown_bytes: 40, captured_bytes: 40 },
  } as unknown as ExecutionView;
}

describe("ResponsePanel", () => {
  it("opens on the diagnosis for a failed exchange and keeps transport and application distinct", () => {
    render(<ResponsePanel view={view({ findings: [finding()] })} running={false} progressBytes={null} onCancel={() => {}} />);
    expect(screen.getByText("No response")).toBeTruthy();
    expect(screen.getByText("Transport").querySelector("b")?.textContent).toBe("failed");
    expect(screen.getByText("Application").querySelector("b")?.textContent).toBe("not evaluated");
    expect(screen.getByRole("tab", { name: /Diagnosis/ }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("article", { name: "The destination refused the connection" })).toBeTruthy();
    expect(screen.getByText(/“Unknown” means the evidence cannot distinguish/)).toBeTruthy();
  });

  it("renders an untrusted HTML body as inert text", () => {
    const hostile = '<img src=x onerror="window.pwned=1"><script>window.pwned=2</script>';
    const { container } = render(<ResponsePanel view={view({ bodyText: hostile })} running={false} progressBytes={null} onCancel={() => {}} />);
    // No findings and a completed exchange: the Body tab is shown.
    const body = screen.getByLabelText("Response body");
    expect(body.textContent).toBe(hostile);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });

  it("shows a cancel control while a request is running", () => {
    const onCancel = vi.fn();
    render(<ResponsePanel view={null} running progressBytes={2048} onCancel={onCancel} />);
    expect(screen.getByText("2.0 KB received")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel (Esc)" }));
    expect(onCancel).toHaveBeenCalledOnce();
  });
});
