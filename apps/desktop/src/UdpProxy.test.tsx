// Renderer tests for UDP through a proxy profile (jsdom; no engine): the
// request settings say which proxy profiles can carry UDP (only HBONE, as a
// datagram tunnel), the UDP tab explains the mesh option, and the HBONE
// profile form states the UDP marker it will send. The engine refuses the
// unsupported combinations before traffic.
import { useState } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ProxyProfile, RequestSpec, SettingsOverrides } from "./generated/contracts";
import { ProxyForm } from "./Dialogs";
import { ProtocolEditor, SettingsOverridesEditor, type Profiles } from "./RequestEditor";

afterEach(cleanup);

function proxy(id: string, name: string, kind: ProxyProfile["kind"], marker?: "none" | "ferrum_mesh_protocol" | "istio_protocol"): ProxyProfile {
  return {
    id,
    workspace_id: "ws",
    name,
    kind,
    address: kind === "hbone" ? "127.0.0.1:17606" : "127.0.0.1:3128",
    no_proxy: "",
    tls_profile_id: kind === "hbone" ? "tls-1" : null,
    hbone: kind === "hbone" ? { marker: marker ?? "none", extra_headers: [] } : null,
    created_at: "2026-09-26T00:00:00Z",
    updated_at: "2026-09-26T00:00:00Z",
  } as ProxyProfile;
}

const profiles: Profiles = {
  tls: [],
  proxy: [proxy("p-mesh", "mesh sidecar", "hbone"), proxy("p-corp", "corp proxy", "http"), proxy("p-istio", "istio ztunnel", "hbone", "istio_protocol")],
  integrations: [],
};

function Harness(props: { protocol: RequestSpec["protocol"] }) {
  const [s, setS] = useState<SettingsOverrides>({});
  return <SettingsOverridesEditor value={s} onChange={setS} profiles={profiles} protocol={props.protocol} />;
}

function proxySelect(): HTMLSelectElement {
  return screen.getByText("Proxy").querySelector("select") as HTMLSelectElement;
}

describe("UDP through a proxy profile", () => {
  it("marks HBONE profiles as carrying UDP and refuses HTTP/SOCKS proxies for UDP", () => {
    render(<Harness protocol="udp" />);
    const labels = Array.from(proxySelect().options).map((o) => o.textContent);
    expect(labels).toContain("mesh sidecar (hbone 127.0.0.1:17606) — carries UDP as a datagram tunnel");
    expect(labels).toContain("corp proxy (http 127.0.0.1:3128) — TCP only: refused for UDP");

    fireEvent.change(proxySelect(), { target: { value: "p-mesh" } });
    const help = screen.getByTestId("udp-proxy-help").textContent ?? "";
    expect(help).toContain("HBONE datagram tunnel");
    expect(help).toContain("x-ferrum-mesh-protocol: udp");
    expect(help).toContain("65,535");
    expect(help).toContain("With dtls:// the DTLS handshake runs inside the tunnel");
    expect(help).toContain("A PROXY protocol envelope is refused");
    expect(help).not.toContain("DTLS and a PROXY");
    expect(screen.queryByRole("alert")).toBeNull();

    fireEvent.change(proxySelect(), { target: { value: "p-istio" } });
    expect(screen.getByTestId("udp-proxy-help").textContent).toContain("x-istio-protocol: udp");

    fireEvent.change(proxySelect(), { target: { value: "p-corp" } });
    expect(screen.getByRole("alert").textContent).toContain("HTTP CONNECT tunnels carry TCP only");
    expect(screen.queryByTestId("udp-proxy-help")).toBeNull();
  });

  it("keeps the proxy list unannotated for other protocols and scopes", () => {
    render(<Harness protocol="http" />);
    const labels = Array.from(proxySelect().options).map((o) => o.textContent);
    expect(labels).toContain("mesh sidecar (hbone 127.0.0.1:17606)");
    fireEvent.change(proxySelect(), { target: { value: "p-corp" } });
    expect(screen.queryByRole("alert")).toBeNull();
    cleanup();
    render(<Harness protocol={undefined} />);
    expect(Array.from(proxySelect().options).some((o) => (o.textContent ?? "").includes("UDP"))).toBe(false);
  });

  it("explains the HBONE datagram tunnel on the UDP tab", () => {
    const spec = { method: "GET", url: "udp://127.0.0.1:17802", protocol: "udp", udp: { datagrams: [] } } as unknown as RequestSpec;
    render(<ProtocolEditor spec={spec} set={() => {}} workspaceId="ws" />);
    const help = screen.getByTestId("udp-hbone-help").textContent ?? "";
    expect(help).toContain("HBONE datagram tunnel");
    expect(help).toContain("[u16 length][payload]");
    expect(help).toContain("With dtls:// the DTLS handshake and session run inside that tunnel");
    expect(help).toContain("every DTLS record is one record");
    expect(help).not.toContain("not supported yet");
  });

  it("states the udp marker an HBONE profile sends for UDP requests", () => {
    const onChange = vi.fn();
    render(<ProxyForm p={proxy("p-mesh", "mesh sidecar", "hbone", "ferrum_mesh_protocol")} tlsProfiles={[]} onChange={onChange} />);
    expect(screen.getByTestId("hbone-udp-help").textContent).toContain("x-ferrum-mesh-protocol: udp");
    cleanup();
    render(<ProxyForm p={proxy("p-istio", "istio ztunnel", "hbone", "istio_protocol")} tlsProfiles={[]} onChange={onChange} />);
    expect(screen.getByTestId("hbone-udp-help").textContent).toContain("x-istio-protocol: udp");
  });
});
