// Renderer tests for per-protocol load (LOAD-013): the plan editor names the
// load unit or shows the typed refusal (and then cannot start a run), and
// reports show protocol denominators with honest wording — sent and received
// datagrams stay separate, a round trip exists only when defined, and a
// distribution without samples shows "—", never 0 µs. jsdom only.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

import type { LoadPlanCheck } from "./api";
import type { LatencySummary, LoadPlan, LoadReport, ProtocolLoadMetrics, RequestCounts, UnitSemantics } from "./generated/contracts";
import { PlanEditor, ProtocolCards, ProtocolPanel, ReportView, UnitBox } from "./LoadView";

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

const none: LatencySummary = { count: 0, min_us: 0, max_us: 0, mean_us: 0, p50_us: 0, p90_us: 0, p95_us: 0, p99_us: 0 };
const some: LatencySummary = { count: 6, min_us: 800, max_us: 4_000, mean_us: 1_200, p50_us: 1_000, p90_us: 2_000, p95_us: 3_000, p99_us: 4_000 };

function sem(one: string, many: string): UnitSemantics {
  return {
    unit_singular: one,
    unit_plural: many,
    completed_means: `a ${one} ran to its end`,
    success_means: "completed and assertions passed",
    latency_means: "time to first response",
    connection_mode_means: `Each ${one} uses its own socket.`,
  };
}

function udp(silent: boolean): ProtocolLoadMetrics {
  return {
    version: 1,
    unit: "udp_exchange",
    semantics: sem("exchange", "exchanges"),
    datagram: {
      datagrams_sent: 24,
      datagrams_received: silent ? 0 : 12,
      exchanges_with_response: silent ? 0 : 6,
      exchanges_silent: silent ? 6 : 0,
      repeated_payloads: 0,
      echoed_payloads: silent ? 0 : 12,
      icmp_unreachable_exchanges: 0,
      time_to_first_datagram: silent ? none : some,
    },
  };
}

const units = (patch: Partial<RequestCounts> = {}): RequestCounts => ({
  started: 6,
  completed: 6,
  transport_failures: 0,
  timeouts: 0,
  canceled: 0,
  in_flight_at_end: 0,
  application_failures: 0,
  assertion_failures: 0,
  connections_opened: 6,
  connections_reused: 0,
  ...patch,
});

describe("UnitBox", () => {
  it("names the load unit and its definitions", () => {
    const check: LoadPlanCheck = { unit: "websocket_session", unit_label: "WebSocket sessions", semantics: sem("session", "sessions"), protocols: [] };
    render(<UnitBox check={check} />);
    const box = screen.getByTestId("load-unit");
    expect(box.textContent).toContain("Load unit: WebSocket sessions");
    expect(box.textContent).toContain("every count, rate and latency is per session");
    expect(within(box).getByText(/Completed: a session ran to its end/)).toBeTruthy();
  });

  it("shows a typed refusal as an alert", () => {
    const check: LoadPlanCheck = {
      refusal: { code: "mixed_unit_kinds", message: "a load plan measures one kind of unit" },
      protocols: [],
    };
    render(<UnitBox check={check} />);
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Not supported for load");
    expect(alert.textContent).toContain("mixed_unit_kinds");
  });
});

describe("ProtocolPanel", () => {
  it("keeps sent and received datagrams separate and labels the ratio as an observation", () => {
    render(<ProtocolPanel p={udp(false)} requests={units()} />);
    const t = screen.getByTestId("datagram-summary").textContent ?? "";
    expect(t).toContain("Datagrams sent24");
    expect(t).toContain("Datagrams received12");
    expect(t).toContain("Received per sent (observed ratio, not a delivery rate)0.500");
    expect(screen.getByText(/nothing here claims delivery or loss/)).toBeTruthy();
    expect(screen.queryByText(/delivered/i)).toBeNull();
  });

  it("shows no latency for silent exchanges (— rather than 0 µs)", () => {
    render(<ProtocolPanel p={udp(true)} requests={units()} />);
    expect(screen.getByTestId("datagram-summary").textContent).toContain("Exchanges with no response observed6");
    const row = screen.getByText("Time to first response").closest("tr")!;
    expect(row.textContent).toContain("—");
    expect(row.textContent).not.toContain("0 µs");
  });

  it("claims no WebSocket round trip unless the request defines one", () => {
    const p: ProtocolLoadMetrics = {
      version: 1,
      unit: "websocket_session",
      semantics: sem("session", "sessions"),
      websocket: {
        opened: 4,
        handshake_rejected: 1,
        not_opened: 1,
        closed_cleanly: 4,
        messages_sent: 4,
        messages_received: 4,
        rtt_defined: false,
        rtt_pairs: 0,
        rtt: none,
        rtt_unpaired_sessions: 0,
        close_codes: [{ closed_by: "client", code: 1000, count: 4 }],
      },
    };
    render(<ProtocolPanel p={p} requests={units()} />);
    expect(screen.getByTestId("ws-no-rtt").textContent).toContain("not defined");
    const t = screen.getByTestId("ws-summary").textContent ?? "";
    expect(t).toContain("Handshake rejected (server answered another status)1");
    expect(t).toContain("Closed by client (stop condition or close), code 10004");
    expect(screen.queryByText(/Round trip \(/)).toBeNull();
  });

  it("names gRPC status codes and keeps a missing status apart from codes", () => {
    const p: ProtocolLoadMetrics = {
      version: 1,
      unit: "grpc_call",
      semantics: sem("call", "calls"),
      grpc: { status_codes: [[0, 15], [5, 5], [7, 5]], ok: 15, non_ok: 10, missing_status: 5, protocol_fallback_attempts: 0 },
    };
    render(<ProtocolPanel p={p} requests={units({ started: 30, completed: 25, transport_failures: 5, application_failures: 10 })} />);
    const codes = screen.getByTestId("grpc-codes").textContent ?? "";
    expect(codes).toContain("7 PERMISSION_DENIED5");
    expect(codes).toContain("0 OK15");
    expect(screen.getByTestId("grpc-summary").textContent).toContain("Response without a terminal status (incomplete, never success)5");
  });

  it("live cards call received datagrams a separate count, not deliveries", () => {
    render(<ProtocolCards p={udp(false)} />);
    expect(screen.getByTestId("protocol-cards").textContent).toContain("a separate count, not deliveries");
  });
});

function plan(): LoadPlan {
  return {
    id: "plan-1",
    workspace_id: "ws-1",
    name: "Sockets",
    workload: { model: "iterations", iterations: 10, concurrency: 2 },
    chain: ["req-ws", "req-http"],
    mix: [],
    connection_mode: "persistent",
    warmup_secs: 0,
    seed: 1,
    trusted: true,
    created_at: "2026-09-26T00:00:00Z",
    updated_at: "2026-09-26T00:00:00Z",
  };
}

const editorProps = {
  requests: [
    { id: "req-ws", label: "Socket", method: "GET" },
    { id: "req-http", label: "Echo", method: "GET" },
  ],
  environments: [],
  datasets: [],
  onDatasetsChanged: () => {},
  onSaved: () => {},
  onDeleted: () => {},
  onStarted: () => {},
};

describe("PlanEditor", () => {
  it("disables Run and shows the refusal for a mixed-protocol plan", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "load_plan_check")
        return {
          refusal: { code: "mixed_unit_kinds", message: "this one mixes WebSocket sessions with HTTP requests" },
          protocols: [
            ["req-ws", "web_socket"],
            ["req-http", "http"],
          ],
        } satisfies LoadPlanCheck;
      throw new Error(`unexpected ${cmd}`);
    });
    render(<PlanEditor plan={plan()} {...editorProps} />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("mixes WebSocket sessions with HTTP requests");
    expect((screen.getByRole("button", { name: "Run…" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("WebSocket")).toBeTruthy();
    expect(screen.getByText("HTTP")).toBeTruthy();
  });

  it("names the unit for a single-protocol plan and keeps Run enabled", async () => {
    invoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === "load_plan_check") {
        const chain = (args as { plan: LoadPlan }).plan.chain ?? [];
        return { unit: "websocket_session", unit_label: "WebSocket sessions", semantics: sem("session", "sessions"), protocols: chain.map((id) => [id, "web_socket"]) } satisfies LoadPlanCheck;
      }
      throw new Error(`unexpected ${cmd}`);
    });
    const p = { ...plan(), chain: ["req-ws"] };
    render(<PlanEditor plan={p} {...editorProps} />);
    expect((await screen.findByTestId("load-unit")).textContent).toContain("Load unit: WebSocket sessions");
    expect((screen.getByRole("button", { name: "Run…" }) as HTMLButtonElement).disabled).toBe(false);
    // Removing the request clears the unit (nothing to measure).
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(screen.queryByTestId("load-unit")).toBeNull());
  });
});

describe("ReportView", () => {
  it("counts exchanges, not requests, and shows the protocol panel", async () => {
    const report = {
      run_id: "run-1",
      schema_version: 1,
      engine: "anvil-native",
      engine_version: "x",
      plan: plan(),
      request_revisions: [],
      started_at: "2026-09-26T00:00:00Z",
      finished_at: "2026-09-26T00:00:05Z",
      completion: "completed",
      partial: false,
      warmup_included_in_metrics: false,
      destination_summary: ["udp://127.0.0.1:9"],
      counts: { scheduled: 6, started: 6, dropped: 0, completed: 6, transport_failures: 0, application_failures: 0, assertion_failures: 0, timeouts: 0, canceled: 0, in_flight_at_end: 0 },
      achieved_rate_per_sec: 1.2,
      latency_success: none,
      latency_failure: none,
      histogram_success_b64: "",
      status_distribution: [],
      failure_categories: [],
      timeline: [],
      bytes_sent: 10,
      bytes_received: 0,
      generator: { peak_cpu_percent: null, peak_rss_bytes: null, max_schedule_lag_us: 0, p99_schedule_lag_us: 0, target_not_achieved: false, notes: [] },
      notes: [],
      requests: units(),
      protocol_metrics: udp(true),
    } as unknown as LoadReport;
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "load_report") return report;
      throw new Error(`unexpected ${cmd}`);
    });
    render(<ReportView runId="run-1" reports={[]} notify={() => {}} onDeleted={() => {}} />);
    expect(await screen.findByText("Exchanges completed")).toBeTruthy();
    expect(screen.getByTestId("protocol-panel").textContent).toContain("Load unit: exchanges");
    const successRow = screen.getByText("Successful exchanges").closest("tr")!;
    expect(successRow.textContent).toContain("— (no samples)");
  });
});
