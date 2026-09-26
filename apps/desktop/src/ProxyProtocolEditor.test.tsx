// Renderer tests for the PROXY protocol editors (jsdom; no engine).
import { useState } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { DatagramEnvelopeSpec, ProxyHeaderSpec } from "./generated/contracts";
import { DatagramEnvelopeEditor, ProxyHeaderEditor, ProxyHeaderEvidence } from "./ProxyProtocolEditor";

afterEach(cleanup);

function HeaderHarness(props: { onValue: (v: ProxyHeaderSpec | null) => void }) {
  const [v, setV] = useState<ProxyHeaderSpec | null>(null);
  return (
    <ProxyHeaderEditor
      value={v}
      onChange={(n) => {
        setV(n);
        props.onValue(n);
      }}
    />
  );
}

function EnvelopeHarness(props: { onValue: (v: DatagramEnvelopeSpec | null) => void; dtls: boolean }) {
  const [v, setV] = useState<DatagramEnvelopeSpec | null>(null);
  return (
    <DatagramEnvelopeEditor
      value={v}
      workspaceId={null}
      dtls={props.dtls}
      onChange={(n) => {
        setV(n);
        props.onValue(n);
      }}
    />
  );
}

describe("ProxyHeaderEditor", () => {
  it("is off by default and builds a v2 header with an explicit source", () => {
    let last: ProxyHeaderSpec | null = null;
    render(<HeaderHarness onValue={(v) => (last = v)} />);
    expect(screen.queryByLabelText(/Source \(client\)/)).toBeNull();
    fireEvent.change(screen.getByLabelText("PROXY protocol header", { selector: "select" }), { target: { value: "v2" } });
    fireEvent.change(screen.getByLabelText(/Source \(client\)/), { target: { value: "203.0.113.7:4242" } });
    expect(last).toEqual({ version: "v2", source: "203.0.113.7:4242" });
    // LOCAL carries no addresses, so the address fields disappear.
    fireEvent.change(screen.getByDisplayValue("PROXY (relayed client)"), { target: { value: "local" } });
    expect(screen.queryByLabelText(/Source \(client\)/)).toBeNull();
    fireEvent.change(screen.getByLabelText("PROXY protocol header", { selector: "select" }), { target: { value: "off" } });
    expect(last).toBeNull();
  });

  it("offers raw bytes for deliberately malformed headers", () => {
    let last: ProxyHeaderSpec | null = null;
    render(<HeaderHarness onValue={(v) => (last = v)} />);
    fireEvent.change(screen.getByLabelText("PROXY protocol header", { selector: "select" }), { target: { value: "raw" } });
    fireEvent.change(screen.getByLabelText(/Header bytes \(hex\)/), { target: { value: "50524f5859" } });
    expect(last).toEqual({ version: "raw", raw_hex: "50524f5859" });
  });
});

describe("ProxyHeaderEvidence", () => {
  it("shows what was sent, including a malformed header's problem and the authenticated binding", () => {
    render(
      <ProxyHeaderEvidence
        h={{
          format: "v2_datagram",
          command: "proxy",
          family: "AF_INET",
          source: "203.0.113.9:5000",
          source_origin: "configured",
          destination: "127.0.0.1:18911",
          destination_origin: "socket",
          length: 95,
          hex: "0d0a0d0a000d0a515549540a2112004fe1‹tag›",
          tlvs: ["0xE0 authentication tag (32 bytes, not recorded)"],
          well_formed: true,
          authenticated: true,
          listener_binding: "udp 127.0.0.1:18911",
          sender_id: 7,
          epoch: 42,
          first_sequence: 0,
          last_sequence: 3,
          datagrams: 4,
        }}
      />,
    );
    expect(screen.getByText(/PROXY v2 DGRAM envelope/)).toBeTruthy();
    expect(screen.getByText(/udp 127.0.0.1:18911 \(sender 7, epoch 42\)/)).toBeTruthy();
    expect(screen.getByText(/‹tag›$/)).toBeTruthy();
  });
});

describe("DatagramEnvelopeEditor", () => {
  it("adds authentication with a masked secret and the DTLS boundary by default for DTLS", () => {
    let last: DatagramEnvelopeSpec | null = null;
    render(<EnvelopeHarness dtls={true} onValue={(v) => (last = v)} />);
    fireEvent.change(screen.getByLabelText("PROXY v2 datagram envelope", { selector: "select" }), { target: { value: "proxy" } });
    fireEvent.click(screen.getByLabelText(/Authenticate/));
    const secret = screen.getByPlaceholderText("{{variable}} or a value to keep in the vault") as HTMLInputElement;
    expect(secret.type).toBe("password");
    expect((screen.getByDisplayValue("DTLS terminated by the listener") as HTMLSelectElement).value).toBe("dtls");
    fireEvent.change(secret, { target: { value: "{{pp_secret}}" } });
    expect(last!.authentication!.secret).toEqual({ kind: "template", value: "{{pp_secret}}" });
    expect(last!.authentication!.listener_bind_address).toBe("0.0.0.0");
  });
});
