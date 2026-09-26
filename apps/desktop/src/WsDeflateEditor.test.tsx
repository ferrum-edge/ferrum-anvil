// Renderer tests for the WebSocket permessage-deflate editor and evidence
// (jsdom; no engine). The engine validates the offer and the answer.
import { useState } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ExecutionView } from "./api";
import type { WsDeflateOffer, WsExtensions } from "./generated/contracts";
import { ResponsePanel } from "./ResponsePanel";
import { WsDeflateEditor, WsExtensionsEvidence } from "./WsDeflateEditor";

afterEach(cleanup);

function Harness(props: { initial?: WsDeflateOffer; onValue: (v: WsDeflateOffer) => void }) {
  const [v, setV] = useState<WsDeflateOffer | undefined>(props.initial);
  return (
    <WsDeflateEditor
      value={v}
      onChange={(n) => {
        setV(n);
        props.onValue(n);
      }}
    />
  );
}

describe("WsDeflateEditor", () => {
  it("is off for requests saved without the field and builds an offer with parameters", () => {
    let last: WsDeflateOffer | null = null;
    render(<Harness onValue={(v) => (last = v)} />);
    const toggle = screen.getByLabelText("Offer permessage-deflate (RFC 7692)") as HTMLInputElement;
    expect(toggle.checked).toBe(false);
    expect(screen.queryByLabelText("server_max_window_bits")).toBeNull();
    fireEvent.click(toggle);
    expect(last).toEqual({ enabled: true });
    fireEvent.click(screen.getByLabelText(/server_no_context_takeover/));
    fireEvent.change(screen.getByLabelText("server_max_window_bits"), { target: { value: "10" } });
    fireEvent.change(screen.getByLabelText("client_max_window_bits"), { target: { value: "12" } });
    expect(last).toEqual({ enabled: true, server_no_context_takeover: true, server_max_window_bits: 10, client_max_window_bits: 12 });
    // Back to the bare client_max_window_bits hint.
    fireEvent.change(screen.getByLabelText("client_max_window_bits"), { target: { value: "" } });
    expect(last!.client_max_window_bits).toBeNull();
    const options = Array.from((screen.getByLabelText("server_max_window_bits") as HTMLSelectElement).options).map((o) => o.value);
    expect(options).toEqual(["", "8", "9", "10", "11", "12", "13", "14", "15"]);
  });

  it("keeps the parameters when compression is switched off, and explains the defaults", () => {
    let last: WsDeflateOffer | null = null;
    render(<Harness initial={{ enabled: true, client_no_context_takeover: true }} onValue={(v) => (last = v)} />);
    fireEvent.click(screen.getByLabelText("Offer permessage-deflate (RFC 7692)"));
    expect(last).toEqual({ enabled: false, client_no_context_takeover: true });
    const help = screen.getByTestId("ws-deflate-help").textContent ?? "";
    expect(help).toContain("Off by default");
    expect(help).toContain("strip the offer, which is not an error");
    expect(help).toContain("after decompression");
  });
});

const negotiated: WsExtensions = {
  offered: "permessage-deflate; client_max_window_bits",
  answered: "permessage-deflate; server_no_context_takeover",
  negotiation: "negotiated",
  deflate: { server_no_context_takeover: true, client_no_context_takeover: false, client_compresses: true },
  traffic: {
    sent: { messages: 2, compressed_messages: 2, payload_bytes: 4000, wire_bytes: 200 },
    received: { messages: 2, compressed_messages: 2, payload_bytes: 4000, wire_bytes: 400 },
  },
};

describe("WsExtensionsEvidence", () => {
  it("shows the offer, the answer, the agreed parameters and the compression ratio", () => {
    render(<WsExtensionsEvidence e={negotiated} />);
    expect(screen.getByText("Negotiated")).toBeTruthy();
    expect(screen.getByText("permessage-deflate; server_no_context_takeover")).toBeTruthy();
    expect(screen.getByText(/server window 2\^15 without context takeover · Anvil window 2\^15 with context takeover/)).toBeTruthy();
    expect(screen.getByText(/2 message\(s\), 2 compressed .* \(5% on the wire\)/)).toBeTruthy();
  });

  it("says an offer that was not accepted plainly, and names what ended a session", () => {
    render(<WsExtensionsEvidence e={{ offered: "permessage-deflate; client_max_window_bits", negotiation: "not_negotiated" }} />);
    expect(screen.getByText("Offered, not negotiated (uncompressed)")).toBeTruthy();
    expect(screen.getByText("no extension")).toBeTruthy();
    cleanup();
    render(
      <WsExtensionsEvidence
        e={{ ...negotiated, violation: { kind: "too_large_after_decompression", limit_bytes: 1048576, compressed_bytes: 33000 } }}
      />,
    );
    expect(screen.getByText("Anvil's message limit, reached while decompressing")).toBeTruthy();
    cleanup();
    render(<WsExtensionsEvidence e={{ offered: "permessage-deflate", answered: "permessage-deflate; mystery", negotiation: "rejected", problem: "mystery is not a permessage-deflate parameter" }} />);
    expect(screen.getByText(/mystery is not a permessage-deflate parameter/)).toBeTruthy();
  });
});

describe("ResponsePanel with WebSocket extensions", () => {
  it("labels a declined offer in the badge and shows the evidence above the transcript", () => {
    const record = {
      id: "00000000-0000-0000-0000-000000000002",
      catalog_version: "findings:test ferrum:test",
      prepared: { method: "GET", url: "ws://127.0.0.1:9/ws", headers: [] },
      attempts: [{ index: 0, duration_us: 1500, phases: [], dispatch: "sent", bytes: {} }],
      response: null,
      stream: { messages: [], dropped_messages: 0, sent_count: 1, received_count: 1, sent_bytes: 5, received_bytes: 5 },
      outcome: {
        transport: "completed",
        application: "success",
        assertions: "not_run",
        dispatch: "sent",
        warnings: [],
        summary: "WebSocket closed 1000",
        protocol_status: {
          protocol: "websocket",
          handshake_status: 101,
          close_code: 1000,
          closed_by: "peer",
          extensions: { offered: "permessage-deflate; client_max_window_bits", negotiation: "not_negotiated" },
        },
      },
      assertion_results: [],
      findings: [],
    };
    const view = { record, body: { text: null, pretty: null, hex: null, is_binary: false, decoded: false, shown_bytes: 0, captured_bytes: 0 } } as unknown as ExecutionView;
    render(<ResponsePanel view={view} running={false} progressBytes={null} onCancel={() => {}} />);
    expect(screen.getByText(/WebSocket closed 1000 by peer · deflate not negotiated/)).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: /Messages/ }));
    expect(screen.getByTestId("ws-extensions").textContent).toContain("Offered, not negotiated");
  });
});
