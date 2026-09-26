// Renderer unit tests for the gRPC section of the request editor (jsdom; no
// native engine). The engine refuses unsupported combinations before traffic;
// these tests check that the editor offers the wire formats and explains them.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { GrpcSpec, RequestSpec } from "./generated/contracts";
import { ProtocolEditor } from "./RequestEditor";

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
    render(<ProtocolEditor spec={grpcSpec({})} set={set} />);
    const wire = screen.getByLabelText("Wire format") as HTMLSelectElement;
    expect(wire.value).toBe("grpc");
    expect(Array.from(wire.options).map((o) => o.value)).toEqual(["grpc", "grpc_web", "grpc_web_text"]);
    fireEvent.change(wire, { target: { value: "grpc_web_text" } });
    expect(set).toHaveBeenCalledWith({ grpc: expect.objectContaining({ wire: "grpc_web_text", service: "a.v1.S" }) });
  });

  it("explains the HTTP versions for native gRPC, including HTTP/3 and the HTTP/1.1 refusal", () => {
    render(<ProtocolEditor spec={grpcSpec({ wire: "grpc" })} set={() => {}} />);
    const help = screen.getByTestId("grpc-http-version-help").textContent ?? "";
    expect(help).toContain("HTTP/3");
    expect(help).toContain("HTTP/1.1-only is refused");
    expect(screen.getByLabelText("h2c (cleartext) for http:// targets")).toBeTruthy();
  });

  it("explains gRPC-Web versions and framing, and hides the native-only h2c switch", () => {
    render(<ProtocolEditor spec={grpcSpec({ wire: "grpc_web_text" })} set={() => {}} />);
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
    render(<ProtocolEditor spec={grpcSpec({ wire: "grpc_web", mode: "bidirectional" })} set={() => {}} />);
    expect(screen.getByRole("alert").textContent).toContain("only unary and server-streaming");
  });
});
