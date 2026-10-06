// Effective-request preview of an event stream: the engine's note that each
// send (the initial one, the TCP fallback, each reconnection) is signed again
// is shown under "Added by Anvil", as the gRPC server reflection note is.
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));

import { EffectivePanel } from "./RequestEditor";
import type { EffectiveRequest } from "./api";
import type { RequestDefinition, RequestSpec } from "./generated/contracts";

const NOTE = "each send (initial, TCP fallback, each reconnection) is signed again when it is sent, not with the signature shown";

const SPEC = { method: "GET", url: "https://sse.example.test/events", protocol: "sse" } as RequestSpec;

function effective(inferred: string[]): EffectiveRequest {
  return {
    method: "GET",
    url: "https://sse.example.test/events",
    destination: "sse.example.test:443",
    authority: "sse.example.test",
    headers: [{ name: "Authorization", value: "hmac username=\"client\", signature=\"…\"" }],
    body_bytes: 0,
    body_preview: "",
    auth: "hmac",
    auth_varies_per_send: true,
    tls_verification: true,
    settings: { http_version: "http3_with_fallback", sources: [] },
    variables_used: [],
    inferred,
    omitted_secrets: 0,
  } as unknown as EffectiveRequest;
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

describe("SSE effective request", () => {
  it("says each send is signed again, not with the signature shown", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "effective_request") return effective([NOTE]);
      throw new Error(`unexpected command ${cmd}`);
    });
    render(<EffectivePanel req={{ id: "req-1", spec: SPEC } as RequestDefinition} workspaceId="ws-1" environmentId={null} />);
    expect(await screen.findByText(NOTE)).toBeTruthy();
    expect(screen.getByText("Added by Anvil")).toBeTruthy();
    expect(screen.getByText("hmac (computed per send)")).toBeTruthy();
    expect(invoke).toHaveBeenCalledWith("effective_request", { input: expect.objectContaining({ workspace_id: "ws-1", spec: SPEC }) });
  });
});
