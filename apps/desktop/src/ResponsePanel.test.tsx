// Renderer unit tests for the diagnosis/response view: confidence and scope
// wording, the explicit "does not prove" section, and inert rendering of
// untrusted response bodies. jsdom only — the native path is covered by
// apps/desktop/e2e.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

  it("notifies when copying the response body fails", async () => {
    const clipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
    const writeText = vi.fn().mockRejectedValue(new Error("clipboard unavailable"));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const notify = vi.fn();

    try {
      render(
        <ResponsePanel
          view={view({ bodyText: "response" })}
          running={false}
          progressBytes={null}
          onCancel={() => {}}
          notify={notify}
        />,
      );
      fireEvent.click(screen.getByRole("button", { name: "Copy" }));
      await waitFor(() => expect(notify).toHaveBeenCalledWith("Could not copy response body: clipboard unavailable"));
    } finally {
      if (clipboard) Object.defineProperty(navigator, "clipboard", clipboard);
      else Reflect.deleteProperty(navigator, "clipboard");
    }
  });

  it("names the MASQUE proxy and its refusal in the UDP badge, never the target", () => {
    const tunnel = (connect_status: number, closed_by: string, encoding: string | null) => ({
      protocol: "udp",
      datagrams_sent: connect_status === 200 ? 2 : 0,
      datagrams_received: connect_status === 200 ? 2 : 0,
      window_ms: 800,
      masque: { proxy: "127.0.0.1:18843", target: "127.0.0.1:19807", connect_status, encoding, closed_by, sent_quic_datagrams: 0, sent_capsules: 2, received_quic_datagrams: 0, received_capsules: 2 },
    });
    const refused = view({ findings: [] });
    (refused.record.outcome as unknown as { protocol_status: unknown }).protocol_status = tunnel(403, "not_closed", "capsule");
    render(<ResponsePanel view={refused} running={false} progressBytes={null} onCancel={() => {}} />);
    expect(screen.getByText(/MASQUE proxy 127\.0\.0\.1:18843 refused \(403\)/)).toBeTruthy();
    cleanup();
    const open = view({ findings: [] });
    (open.record.outcome as unknown as { protocol_status: unknown }).protocol_status = tunnel(200, "client", "capsule");
    render(<ResponsePanel view={open} running={false} progressBytes={null} onCancel={() => {}} />);
    expect(screen.getByText(/2 received in 800 ms · via MASQUE 127\.0\.0\.1:18843 \(capsules\)/)).toBeTruthy();
  });

  it("names the HBONE endpoint for UDP through a datagram tunnel, how the tunnel ended, and its refusal", () => {
    const udpThroughHbone = (connect_status: number, closed_by: string, patch: Record<string, unknown> = {}) => {
      const v = view({ findings: [] });
      const rec = v.record as unknown as { outcome: { protocol_status: unknown }; attempts: Record<string, unknown>[] };
      const open = connect_status === 200;
      rec.outcome.protocol_status = { protocol: "udp", datagrams_sent: open ? 3 : 0, datagrams_received: open ? 1 : 0, window_ms: 1000, masque: null };
      rec.attempts[0].connection = {
        id: 1,
        reused: false,
        resolved_addresses: [],
        connect_attempts: [],
        protocol: "udp",
        via_proxy: "lab mesh HBONE (127.0.0.1:17606)",
        prior_requests: 0,
        tunnel: {
          kind: "hbone",
          endpoint: "lab mesh HBONE (127.0.0.1:17606)",
          authority: "127.0.0.1:17802",
          resolved_addresses: [],
          connect_attempts: [],
          phases: [],
          connect_headers: [{ name: "x-ferrum-mesh-protocol", value: "udp" }],
          connect_status,
          response_headers: [],
          datagrams: { records_sent: open ? 3 : 0, records_received: open ? 1 : 0, oversize_refused: 0, truncated_tail_bytes: 0, closed_by, ...patch },
        },
      };
      return v;
    };
    render(<ResponsePanel view={udpThroughHbone(200, "peer")} running={false} progressBytes={null} onCancel={() => {}} />);
    const badge = screen.getByText(/3 sent · 1 received in 1000 ms · via HBONE lab mesh HBONE \(127\.0\.0\.1:17606\) · ended by the endpoint/);
    expect(badge.className).toBe("badge");
    expect(badge.getAttribute("title")).toContain("127.0.0.1:17802");
    fireEvent.click(screen.getByRole("tab", { name: /Connection/ }));
    expect(screen.getByText("HBONE UDP tunnel (outer leg)")).toBeTruthy();
    expect(screen.getByText(/3 sent · 1 received \(\[u16 length\]\[payload\] on the CONNECT stream\)/)).toBeTruthy();
    expect(screen.getByText("x-ferrum-mesh-protocol: udp")).toBeTruthy();
    cleanup();

    // An abnormal end with a reset code and a truncated record is flagged, with both facts shown.
    render(<ResponsePanel view={udpThroughHbone(200, "abnormal", { reset_code: "CANCEL", truncated_tail_bytes: 6, oversize_refused: 1 })} running={false} progressBytes={null} onCancel={() => {}} />);
    expect(screen.getByText(/via HBONE lab mesh HBONE/).className).toBe("badge bad");
    fireEvent.click(screen.getByRole("tab", { name: /Connection/ }));
    expect(screen.getByText(/Abnormal \(CANCEL\)/i)).toBeTruthy();
    expect(screen.getByText(/6 byte\(s\) of an incomplete record discarded/)).toBeTruthy();
    expect(screen.getByText(/1 datagram\(s\) over 65,535 bytes, not sent/)).toBeTruthy();
    cleanup();

    // A refused datagram CONNECT names the endpoint, never the UDP destination.
    render(<ResponsePanel view={udpThroughHbone(403, "not_closed")} running={false} progressBytes={null} onCancel={() => {}} />);
    expect(screen.getByText(/HBONE endpoint lab mesh HBONE \(127\.0\.0\.1:17606\) refused \(403\)/)).toBeTruthy();
  });

  it("shows DTLS inside a CONNECT-UDP tunnel as two legs: the DTLS peer and the MASQUE proxy", () => {
    const tlsObs = (patch: Record<string, unknown>) => ({
      sni: null,
      server_name: "127.0.0.1",
      server_name_overridden: false,
      version: "TLSv1_3",
      alpn_offered: [],
      verification: { result: "verified" },
      peer_certificates: [],
      client_certificate_requested: null,
      ...patch,
    });
    const v = view({ findings: [] });
    const attempt = v.record.attempts[0] as unknown as Record<string, unknown>;
    attempt.connection = {
      id: 7,
      reused: false,
      protocol: "dtlsv1_2",
      resolved_addresses: [],
      connect_attempts: [],
      prior_requests: 0,
      via_proxy: "MASQUE CONNECT-UDP proxy 127.0.0.1:18843",
      tls: tlsObs({ version: "DTLSv1_2", client_certificate_requested: false }),
      tunnel: {
        kind: "connect_udp",
        endpoint: "127.0.0.1:18843 (MASQUE CONNECT-UDP proxy)",
        authority: "127.0.0.1:19808",
        resolved_addresses: ["127.0.0.1:18843"],
        connect_attempts: [],
        phases: [],
        tls: tlsObs({ alpn_offered: ["h3"], alpn_negotiated: "h3" }),
        connect_headers: [{ name: "capsule-protocol", value: "?1" }],
        connect_status: 200,
        response_headers: [],
      },
    };
    render(<ResponsePanel view={v} running={false} progressBytes={null} onCancel={() => {}} />);
    fireEvent.click(screen.getByRole("tab", { name: /Connection/ }));
    expect(screen.getByText("CONNECT-UDP (MASQUE) tunnel (outer leg)")).toBeTruthy();
    expect(screen.getByText("QUIC TLS with the MASQUE proxy")).toBeTruthy();
    expect(screen.getByText("DTLS with the destination (inside the tunnel)")).toBeTruthy();
    expect(screen.getByText("UDP target (in the CONNECT :path)").nextElementSibling?.textContent).toBe("127.0.0.1:19808");
    expect(screen.queryByText(/HBONE/)).toBeNull();
  });

  it("shows DTLS inside an HBONE datagram tunnel as two legs: the DTLS peer and the HBONE endpoint", () => {
    const tlsObs = (patch: Record<string, unknown>) => ({
      sni: null,
      server_name: "127.0.0.1",
      server_name_overridden: false,
      version: "TLSv1_3",
      alpn_offered: [],
      verification: { result: "verified" },
      peer_certificates: [],
      client_certificate_requested: null,
      ...patch,
    });
    const v = view({ findings: [] });
    const rec = v.record as unknown as { outcome: { protocol_status: unknown }; attempts: Record<string, unknown>[] };
    rec.outcome.protocol_status = { protocol: "udp", datagrams_sent: 1, datagrams_received: 1, window_ms: 500, masque: null };
    rec.attempts[0].connection = {
      id: 9,
      reused: false,
      protocol: "dtlsv1_2",
      resolved_addresses: [],
      connect_attempts: [],
      prior_requests: 0,
      via_proxy: "lab mesh HBONE (127.0.0.1:17606)",
      tls: tlsObs({ version: "DTLSv1_2", client_certificate_requested: false }),
      tunnel: {
        kind: "hbone",
        endpoint: "lab mesh HBONE (127.0.0.1:17606)",
        authority: "127.0.0.1:17806",
        resolved_addresses: ["127.0.0.1:17606"],
        connect_attempts: [],
        phases: [],
        tls: tlsObs({ alpn_offered: ["h2"], alpn_negotiated: "h2", peer_spiffe_id: "spiffe://cluster.local/ns/ferrum/sa/anvil-lab-svc" }),
        connect_headers: [{ name: "x-ferrum-mesh-protocol", value: "udp" }],
        connect_status: 200,
        response_headers: [],
        datagrams: { records_sent: 5, records_received: 4, oversize_refused: 0, truncated_tail_bytes: 0, closed_by: "client" },
      },
    };
    render(<ResponsePanel view={v} running={false} progressBytes={null} onCancel={() => {}} />);
    expect(screen.getByText(/1 sent · 1 received in 500 ms · via HBONE lab mesh HBONE \(127\.0\.0\.1:17606\)/)).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: /Connection/ }));
    expect(screen.getByText("HBONE UDP tunnel (outer leg)")).toBeTruthy();
    expect(screen.getByText("Mutual TLS with the HBONE endpoint")).toBeTruthy();
    expect(screen.getByText("DTLS with the destination (inside the tunnel)")).toBeTruthy();
    expect(screen.getByText("DTLS records").nextElementSibling?.textContent).toBe(
      "5 sent · 4 received ([u16 length][payload] on the CONNECT stream; handshake flights included)",
    );
    expect(screen.getByText("CONNECT :authority").nextElementSibling?.textContent).toBe("127.0.0.1:17806");
    expect(screen.queryByText(/MASQUE/)).toBeNull();
  });

  it("shows a cancel control while a request is running", () => {
    const onCancel = vi.fn();
    render(<ResponsePanel view={null} running progressBytes={2048} onCancel={onCancel} />);
    expect(screen.getByText("2.0 KB received")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel (Esc)" }));
    expect(onCancel).toHaveBeenCalledOnce();
  });
});
