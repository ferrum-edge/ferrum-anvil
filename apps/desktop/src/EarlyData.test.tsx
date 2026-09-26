// Renderer tests for 0-RTT early data (jsdom; no engine): the settings
// editor is off by default and only offers idempotent extra methods, and the
// evidence views say what the handshake did without overclaiming.
import { useState } from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import type { ExecutionView } from "./api";
import type { EarlyDataObservation, EarlyDataPolicy } from "./generated/contracts";
import { EarlyDataEvidence, EarlyDataSettings, earlyDataSummary } from "./EarlyData";
import { ResponsePanel } from "./ResponsePanel";

afterEach(cleanup);

function Harness(props: { initial?: EarlyDataPolicy | null; onValue: (v: EarlyDataPolicy | null) => void }) {
  const [v, setV] = useState<EarlyDataPolicy | null>(props.initial ?? null);
  return (
    <EarlyDataSettings
      value={v}
      onChange={(n) => {
        setV(n);
        props.onValue(n);
      }}
    />
  );
}

function evidence(patch: Partial<EarlyDataObservation>): EarlyDataObservation {
  return {
    transport: "quic",
    method_eligible: true,
    resumption_attempted: true,
    resumption_accepted: true,
    offered: true,
    accepted: true,
    bytes: 183,
    bytes_estimated: true,
    resent_after_handshake: false,
    tickets_received: 2,
    ticket_max_early_data: 4294967295,
    ...patch,
  };
}

describe("EarlyDataSettings", () => {
  it("inherits by default, turns on with a replay warning and offers only idempotent extra methods", () => {
    let last: EarlyDataPolicy | null = null;
    render(<Harness onValue={(v) => (last = v)} />);
    const select = screen.getByLabelText("Early data", { selector: "select" }) as HTMLSelectElement;
    expect(select.value).toBe("inherit");
    expect(screen.queryByRole("note")).toBeNull();
    fireEvent.change(select, { target: { value: "on" } });
    expect(last).toEqual({ enabled: true, extra_methods: [] });
    expect(screen.getByRole("note").textContent).toContain("replayed");
    const boxes = screen.getAllByRole("checkbox").map((b) => (b.parentElement?.textContent ?? "").trim());
    expect(boxes).toEqual(["PUT", "DELETE", "TRACE"]);
    expect(screen.queryByText("POST")).toBeNull();
    fireEvent.click(screen.getByLabelText("PUT"));
    expect(last).toEqual({ enabled: true, extra_methods: ["PUT"] });
    fireEvent.click(screen.getByLabelText("PUT"));
    expect(last).toEqual({ enabled: true, extra_methods: [] });
    fireEvent.change(select, { target: { value: "off" } });
    expect(last).toEqual({ enabled: false, extra_methods: [] });
    fireEvent.change(select, { target: { value: "inherit" } });
    expect(last).toBeNull();
  });

  it("flags a stored non-idempotent method as refused before sending", () => {
    render(<Harness initial={{ enabled: true, extra_methods: ["POST"] }} onValue={() => {}} />);
    expect(screen.getByRole("alert").textContent).toContain("refused before sending");
  });
});

describe("EarlyDataEvidence", () => {
  it("shows accepted early data with its size and the replay note", () => {
    render(<EarlyDataEvidence e={evidence({})} />);
    const box = screen.getByLabelText("Early data evidence");
    expect(within(box).getByText("accepted")).toBeTruthy();
    expect(box.textContent).toContain("183 bytes (HTTP/3 request, header size estimated)");
    expect(box.textContent).toContain("ticket offered, resumed");
    expect(box.textContent).toContain("can be replayed");
  });

  it("explains a rejection as the protocol re-sending, not an application retry", () => {
    render(<EarlyDataEvidence e={evidence({ transport: "tls", accepted: false, resent_after_handshake: true, bytes_estimated: false })} />);
    const box = screen.getByLabelText("Early data evidence");
    expect(box.textContent).toContain("rejected by the server");
    expect(box.textContent).toContain("not an application retry");
    expect(box.textContent).toContain("(TLS plaintext)");
    expect(box.textContent).not.toContain("can be replayed");
  });

  it("names why early data was not used", () => {
    render(<EarlyDataEvidence e={evidence({ offered: false, accepted: null, resumption_attempted: false, resumption_accepted: null, not_used: "no_ticket", ticket_max_early_data: 0 })} />);
    const box = screen.getByLabelText("Early data evidence");
    expect(box.textContent).toContain("no session ticket from an earlier connection");
    expect(box.textContent).toContain("2 (no early data)");
    expect(earlyDataSummary(evidence({ offered: false, not_used: "method_not_eligible" }))).toBe("no 0-RTT (method not eligible)");
  });
});

describe("ResponsePanel with early data", () => {
  it("lists the 425 retry and the early-data outcome per attempt", () => {
    const record = {
      id: "00000000-0000-0000-0000-000000000002",
      catalog_version: "findings:test ferrum:test",
      prepared: { method: "PUT", url: "https://127.0.0.1:17243/early/echo", headers: [] },
      attempts: [
        { index: 0, reason: { reason: "initial" }, method: "PUT", url: "https://127.0.0.1:17243/early/echo", duration_us: 900, phases: [], dispatch: "sent", bytes: {}, response_status: 425, early_data: evidence({}) },
        {
          index: 1,
          reason: { reason: "too_early_retry" },
          method: "PUT",
          url: "https://127.0.0.1:17243/early/echo",
          duration_us: 700,
          phases: [],
          dispatch: "sent",
          bytes: {},
          response_status: 200,
          connection: { id: 7, reused: true, resolved_addresses: [], connect_attempts: [], prior_requests: 1 },
          early_data: evidence({ offered: false, accepted: null, not_used: "retry_after_too_early" }),
        },
      ],
      response: {
        status: 200,
        reason: "OK",
        http_version: "HTTP/3",
        headers: [],
        trailers: [],
        trailers_received: false,
        body: { completeness: "complete", wire_bytes: 2, captured_bytes: 2, display_truncated: false },
      },
      outcome: { transport: "completed", application: "success", assertions: "not_run", dispatch: "sent", warnings: [], summary: "HTTP 200 OK" },
      assertion_results: [],
      findings: [],
    };
    const v = { record, body: { text: "{}", pretty: null, hex: null, is_binary: false, decoded: false, shown_bytes: 2, captured_bytes: 2 } } as unknown as ExecutionView;
    render(<ResponsePanel view={v} running={false} progressBytes={null} onCancel={() => {}} />);
    fireEvent.click(screen.getByRole("tab", { name: /Attempts/ }));
    expect(screen.getByText("retry after 425 Too Early (after the handshake)")).toBeTruthy();
    expect(screen.getByText(/0-RTT accepted/)).toBeTruthy();
    expect(screen.getByText(/no 0-RTT \(retry after too early\)/)).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: /Connection/ }));
    expect(screen.getByLabelText("Early data evidence").textContent).toContain("retry after 425 Too Early — retries are never early data");
  });
});
