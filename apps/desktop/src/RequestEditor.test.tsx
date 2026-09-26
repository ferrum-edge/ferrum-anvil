// Renderer unit tests for the gRPC section of the request editor (jsdom; no
// native engine). The engine refuses unsupported combinations before traffic;
// these tests check that the editor offers the wire formats and explains them.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { GrpcSpec, RequestSpec } from "./generated/contracts";
import { ProtocolEditor, SettingsEditor } from "./RequestEditor";

afterEach(cleanup);

function grpcSpec(grpc: Partial<GrpcSpec>): RequestSpec {
  return {
    method: "POST",
    url: "grpcs://example.test",
    protocol: "grpc",
    grpc: { service: "a.v1.S", method: "M", schema: { kind: "proto_files", files: [] }, messages: ["{}"], ...grpc },
  } as RequestSpec;
}

describe("gRPC protocol editor", () => {
  it("offers native gRPC and gRPC-Web wire formats, defaulting to native for older records", () => {
    const set = vi.fn();
    render(<ProtocolEditor spec={grpcSpec({})} set={set} workspaceId="ws" />);
    const wire = screen.getByLabelText("Wire format") as HTMLSelectElement;
    expect(wire.value).toBe("grpc");
    expect(Array.from(wire.options).map((o) => o.value)).toEqual(["grpc", "grpc_web", "grpc_web_text"]);
    fireEvent.change(wire, { target: { value: "grpc_web_text" } });
    expect(set).toHaveBeenCalledWith({ grpc: expect.objectContaining({ wire: "grpc_web_text", service: "a.v1.S" }) });
  });

  it("explains the HTTP versions for native gRPC, including HTTP/3 and the HTTP/1.1 refusal", () => {
    render(<ProtocolEditor spec={grpcSpec({ wire: "grpc" })} set={() => {}} workspaceId="ws" />);
    const help = screen.getByTestId("grpc-http-version-help").textContent ?? "";
    expect(help).toContain("HTTP/3");
    expect(help).toContain("HTTP/1.1-only is refused");
    expect(screen.getByLabelText("h2c (cleartext) for http:// targets")).toBeTruthy();
  });

  it("explains gRPC-Web versions and framing, and hides the native-only h2c switch", () => {
    render(<ProtocolEditor spec={grpcSpec({ wire: "grpc_web_text" })} set={() => {}} workspaceId="ws" />);
    const help = screen.getByTestId("grpc-http-version-help").textContent ?? "";
    expect(help).toContain("HTTP/1.1");
    expect(help).toContain("trailer frame");
    expect(help).toContain("base64");
    expect(screen.queryByLabelText("h2c (cleartext) for http:// targets")).toBeNull();
    const reflection = Array.from((screen.getByLabelText("Schema source") as HTMLSelectElement).options).find((o) => o.value === "reflection");
    expect(reflection?.disabled).toBe(true);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("warns that gRPC-Web cannot carry client or bidirectional streaming", () => {
    render(<ProtocolEditor spec={grpcSpec({ wire: "grpc_web", mode: "bidirectional" })} set={() => {}} workspaceId="ws" />);
    expect(screen.getByRole("alert").textContent).toContain("only unary and server-streaming");
  });
});

describe("request settings: PROXY protocol header for HTTP-family requests", () => {
  const profiles = { tls: [], proxy: [], integrations: [] };
  const spec = (protocol: RequestSpec["protocol"], patch: Partial<RequestSpec> = {}): RequestSpec => ({ method: "GET", url: "https://example.test", protocol, ...patch }) as RequestSpec;

  it.each(["http", "web_socket", "grpc", "sse"] as const)("offers the TCP header editor for %s requests", (protocol) => {
    const set = vi.fn();
    render(<SettingsEditor spec={spec(protocol)} set={set} profiles={profiles} />);
    fireEvent.change(screen.getByLabelText("PROXY protocol header", { selector: "select" }), { target: { value: "v1" } });
    expect(set).toHaveBeenCalledWith({ proxy_protocol: { version: "v1" } });
  });

  it("explains per-connection pooling, redirects and the HTTP/3 and proxy refusals", () => {
    render(<SettingsEditor spec={spec("http", { proxy_protocol: { version: "v2", source: "203.0.113.7:4242" } })} set={() => {}} profiles={profiles} />);
    const hint = screen.getByTestId("proxy-header-http-hint").textContent ?? "";
    expect(hint).toContain("once on every new TCP connection");
    expect(hint).toContain("pooled");
    expect(hint).toContain("Redirects to another host or port");
    expect(hint).toContain("HTTP/3");
    expect(hint).toContain("never as the cause");
    expect((screen.getByLabelText(/Source \(client\)/) as HTMLInputElement).value).toBe("203.0.113.7:4242");
  });

  it.each(["tcp", "udp"] as const)("leaves %s requests to their protocol tab", (protocol) => {
    render(<SettingsEditor spec={spec(protocol)} set={() => {}} profiles={profiles} />);
    expect(screen.queryByLabelText("PROXY protocol header", { selector: "select" })).toBeNull();
  });
});
