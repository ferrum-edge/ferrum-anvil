// Renderer unit tests for the gRPC section of the request editor (jsdom; no
// native engine). The engine refuses unsupported combinations before traffic;
// these tests check that the editor offers the wire formats and explains them.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { GrpcSpec, RequestDefinition, RequestSpec } from "./generated/contracts";
import { newSpec, ProtocolEditor, RequestEditor, SettingsEditor, type Profiles } from "./RequestEditor";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

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

describe("gRPC schema source chooser", () => {
  it("records a .proto files choice as proto_files even when the control re-renders while the dialog is open", async () => {
    let release!: (grants: unknown[]) => void;
    invoke.mockImplementation((cmd: string) => {
      if (cmd === "file_choose") return new Promise((resolve) => (release = resolve));
      if (cmd === "attachment_add") return Promise.resolve({ sha256: "a".repeat(64), size: 10, file_name: "svc.proto", kind: "stored" });
      return Promise.reject(new Error(`unexpected command ${cmd}`));
    });
    const set = vi.fn();
    const spec = grpcSpec({ schema: { kind: "reflection" } });
    const { rerender } = render(<ProtocolEditor spec={spec} set={set} workspaceId="ws" />);
    fireEvent.change(screen.getByLabelText("Schema source"), { target: { value: "proto_files" } });
    // React resets the controlled select to the saved kind while the native dialog is open.
    rerender(<ProtocolEditor spec={spec} set={set} workspaceId="ws" />);
    await act(async () => {
      release([{ token: "g1", file_name: "svc.proto" }]);
    });
    await waitFor(() => expect(set).toHaveBeenCalled());
    expect(set).toHaveBeenCalledWith({ grpc: expect.objectContaining({ schema: { kind: "proto_files", files: [expect.objectContaining({ file_name: "svc.proto" })] } }) });
  });

  it("records a descriptor set choice as descriptor_set", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "file_choose") return [{ token: "g1", file_name: "svc.pb" }];
      if (cmd === "attachment_add") return { sha256: "b".repeat(64), size: 12, file_name: "svc.pb", kind: "stored" };
      throw new Error(`unexpected command ${cmd}`);
    });
    const set = vi.fn();
    render(<ProtocolEditor spec={grpcSpec({ schema: { kind: "reflection" } })} set={set} workspaceId="ws" />);
    fireEvent.change(screen.getByLabelText("Schema source"), { target: { value: "descriptor_set" } });
    await waitFor(() => expect(set).toHaveBeenCalled());
    expect(set).toHaveBeenCalledWith({
      grpc: expect.objectContaining({ schema: { kind: "descriptor_set", attachment: expect.objectContaining({ file_name: "svc.pb" }) } }),
    });
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

describe("MCP protocol editor", () => {
  const mcpSpec = (mcp?: RequestSpec["mcp"]): RequestSpec => ({ method: "POST", url: "https://gw.example/mcp", protocol: "mcp", mcp }) as RequestSpec;

  it("starts a new MCP request with tools/list and edits a tool call", () => {
    const set = vi.fn();
    render(<ProtocolEditor spec={mcpSpec()} set={set} workspaceId="ws" requestId="r1" />);
    const op = screen.getByLabelText("MCP operation") as HTMLSelectElement;
    expect(op.value).toBe("tools_list");
    expect(Array.from(op.options).map((o) => o.textContent)).toContain("tools/call");
    fireEvent.change(op, { target: { value: "tools_call" } });
    expect(set).toHaveBeenCalledWith({ mcp: expect.objectContaining({ operation: { kind: "tools_call", name: "", arguments: "{}" } }) });
  });

  it("asks for a saved request before discovering tools", () => {
    render(<ProtocolEditor spec={mcpSpec({ operation: { kind: "tools_list" } })} set={() => {}} workspaceId="ws" requestId="r1" dirty />);
    const discover = screen.getByRole("button", { name: /Discover tools/ }) as HTMLButtonElement;
    expect(discover.disabled).toBe(true);
    expect(screen.getByText(/Save the request first/)).toBeTruthy();
  });
});

describe("protocol selection defaults", () => {
  const profiles: Profiles = { tls: [], proxy: [], integrations: [] };
  const def = (spec: RequestSpec): RequestDefinition =>
    ({ id: "r1", workspace_id: "ws", name: "R", schema_version: 1, created_at: "", updated_at: "", sort_key: 0, spec }) as RequestDefinition;
  const renderEditor = (spec: RequestSpec) => {
    const onChange = vi.fn();
    render(
      <RequestEditor
        req={def(spec)}
        onChange={onChange}
        onSend={() => {}}
        onConnect={() => {}}
        connected={false}
        onSave={() => {}}
        onCancel={() => {}}
        running={false}
        dirty={false}
        workspaceId="ws"
        environmentId={null}
        profiles={profiles}
      />,
    );
    return onChange;
  };

  it("saves the tools/list default when a request is switched to MCP, so Send accepts it", () => {
    const onChange = renderEditor(newSpec());
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "mcp" } });
    const next = onChange.mock.calls[0][0] as RequestDefinition;
    expect(next.spec.protocol).toBe("mcp");
    expect(next.spec.mcp).toEqual({ operation: { kind: "tools_list" } });
  });

  it("keeps an already saved MCP operation when re-selecting MCP", () => {
    const operation = { kind: "tools_call" as const, name: "get_weather", arguments: "{}" };
    const onChange = renderEditor({ ...newSpec(), protocol: "http", mcp: { operation } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "mcp" } });
    const next = onChange.mock.calls[0][0] as RequestDefinition;
    expect(next.spec.mcp?.operation).toEqual(operation);
  });
});
