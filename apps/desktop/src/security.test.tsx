// DATA-014: remote content is inert. A response carrying HTML, scripts and
// privileged URLs renders as text only; the CSP forbids remote code.
import tauriConf from "../src-tauri/tauri.conf.json";
import { render } from "@testing-library/react";
import { vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

import { ResponsePanel } from "./ResponsePanel";
import type { ExecutionView } from "./api";

const HOSTILE =
  "<html><body><h1>fixture</h1><script>window.__TAURI__ && window.__TAURI__.core.invoke('export_secrets')</script>" +
  '<img src=x onerror="alert(1)"><a href="tauri://localhost/">x</a><iframe src="https://evil.example"></iframe></body></html>';

function view(): ExecutionView {
  const now = new Date().toISOString();
  return {
    body: { text: HOSTILE, pretty: null, hex: null, is_binary: false, decoded: false, shown_bytes: HOSTILE.length, captured_bytes: HOSTILE.length },
    record: {
      id: "00000000-0000-7000-8000-000000000001",
      schema_version: 1,
      adapter_version: "test",
      catalog_version: "test",
      started_at: now,
      finished_at: now,
      prepared: {
        protocol: "http",
        method: "GET",
        url: "https://example.test/",
        headers: [],
        body_bytes: 0,
        auth_label: "none",
        tls_verification_enabled: true,
        settings: {} as never,
        inferred: [],
        omitted_secrets: [],
      },
      attempts: [],
      response: {
        status: 200,
        http_version: "HTTP/1.1",
        headers: [{ name: "content-type", value: "text/html" }],
        trailers: [],
        trailers_received: false,
        body: { completeness: "complete", wire_bytes: HOSTILE.length, captured_bytes: HOSTILE.length, display_truncated: false, content_type: "text/html" },
      },
      outcome: {
        transport: "completed",
        application: "success",
        assertions: "not_run",
        protocol_status: { protocol: "http", status: 200 },
        dispatch: "sent",
        warnings: [],
        summary: "HTTP 200",
      },
      assertion_results: [],
      extracted: [],
      findings: [],
    },
  } as ExecutionView;
}

test("data_014 hostile HTML response renders as inert text", () => {
  const { container } = render(<ResponsePanel view={view()} running={false} progressBytes={null} onCancel={() => {}} />);
  // Nothing from the body became live DOM.
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("iframe")).toBeNull();
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector('a[href^="tauri:"]')).toBeNull();
  // The markup is shown verbatim as text.
  const pre = container.querySelector('pre[aria-label="Response body"]');
  expect(pre?.textContent).toContain("<script>window.__TAURI__");
});

test("data_014 CSP forbids remote scripts, frames and fetches", () => {
  const conf = tauriConf as { app: { security: { csp: string }; withGlobalTauri: boolean } };
  const csp: string = conf.app.security.csp;
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("frame-src 'none'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).not.toMatch(/script-src[^;]*(https?:|\*|'unsafe-eval'|'unsafe-inline')/);
  expect(csp).toMatch(/connect-src ipc: http:\/\/ipc\.localhost(;|$)/);
  expect(conf.app.withGlobalTauri).toBe(false);
});
