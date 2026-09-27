// Renderer tests for choosing a linked local file on this device (jsdom; the
// Tauri backend is a scripted fake). The backend shows the native dialog and
// binds the file only if the request or dataset names that exact path; the
// Rust side (canonical path, regular file, size, referrer) is covered by
// crates/anvil-app/tests/local_files.rs. Here: the binding status beside a
// linked request body, gRPC schema or dataset, Choose file… and Rebind…
// scoped to that referrer, Choose new location… for a file that is elsewhere
// now, and that a cancelled dialog changes nothing.
import { useState } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn(), ask: vi.fn() }));

import type { LinkedFileReferrer, LinkedFileStatus } from "./api";
import type { Dataset, LoadPlan, RequestSpec } from "./generated/contracts";
import { LinkedFileBinding } from "./LinkedFile";
import { PlanEditor } from "./LoadView";
import { BodyEditor, ProtocolEditor } from "./RequestEditor";

const PATH = "/home/me/upload.bin";
const REQUEST: LinkedFileReferrer = { kind: "request", id: "req-1" };

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

type Args = Record<string, unknown>;

/**
 * A fake backend: `linked_file_status` reports `status`; `file_choose` runs `choose`,
 * which returns the dialog's grants (empty when cancelled) and may change `status`.
 */
function backend(initial: LinkedFileStatus[], choose: (s: { status: LinkedFileStatus[] }) => unknown = () => []) {
  const state = { status: initial };
  invoke.mockImplementation(async (cmd: string) => {
    if (cmd === "linked_file_status") return state.status;
    if (cmd === "file_choose") return choose(state);
    throw new Error(`unexpected command ${cmd}`);
  });
  return state;
}

const calls = (cmd: string) => invoke.mock.calls.filter(([c]) => c === cmd).map(([, args]) => args as Args);
const stateBadge = async () => (await screen.findByTestId("linked-file-state")).textContent;
const grant = (path: string) => [{ token: "binding-1", file_name: path.split("/").pop(), path }];

describe("linked file binding status", () => {
  it("shows a file not chosen on this device, with Choose file…", async () => {
    backend([{ path: PATH, state: "unbound" }]);
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await stateBadge()).toBe("Not chosen on this device");
    expect(screen.getByTestId("linked-file").textContent).toContain(PATH);
    expect(screen.getByRole("button", { name: /Choose file…/ })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Rebind…/ })).toBeNull();
    expect(screen.getByText(/only once you choose it here, on this device, for this request/)).toBeTruthy();
    expect(calls("linked_file_status")).toEqual([{ referrer: REQUEST }]);
  });

  it("shows a bound file as chosen, with Rebind…", async () => {
    backend([{ path: PATH, state: "bound" }]);
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await stateBadge()).toBe("Chosen on this device");
    expect(screen.getByRole("button", { name: /Rebind…/ })).toBeTruthy();
    expect(screen.queryByText(/only once you choose it/)).toBeNull();
  });

  it("shows a bound file that moved as missing, with why and how to recover", async () => {
    backend([{ path: PATH, state: "invalid", problem: "the file is no longer at this path" }]);
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await stateBadge()).toBe("Missing or changed");
    const text = screen.getByTestId("linked-file").textContent ?? "";
    expect(text).toContain("Chosen before, but the file is no longer at this path.");
    expect(text).toContain("put it back there and choose it again with Rebind…");
    expect(screen.getByRole("button", { name: /Rebind…/ })).toBeTruthy();
  });

  it("reports only the status of its own path", async () => {
    backend([
      { path: "/home/me/other.bin", state: "bound" },
      { path: PATH, state: "unbound" },
    ]);
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await stateBadge()).toBe("Not chosen on this device");
  });

  it("offers no chooser for a request that is not saved", () => {
    backend([]);
    render(<LinkedFileBinding referrer={null} path={PATH} />);
    expect(screen.getByText(/can be chosen only for a saved request that names it/)).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
    expect(invoke).not.toHaveBeenCalled();
  });

  it("shows a status the backend refused as an error", async () => {
    invoke.mockImplementation(async () => {
      throw "not found: request req-1";
    });
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect((await screen.findByRole("alert")).textContent).toContain("not found");
    expect(screen.queryByRole("button", { name: /Choose file…|Rebind…/ })).toBeNull();
    expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
  });

  it("retries a status that failed to load, and clears the error once it loads", async () => {
    let fail = true;
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd !== "linked_file_status") throw new Error(`unexpected command ${cmd}`);
      if (fail) throw "the store is busy";
      return [{ path: PATH, state: "bound" }];
    });
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect((await screen.findByRole("alert")).textContent).toContain("the store is busy");
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await stateBadge()).toBe("Chosen on this device");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
    expect(calls("linked_file_status")).toEqual([{ referrer: REQUEST }, { referrer: REQUEST }]);
  });

  it("never shows the previous request's or path's status while another one loads", async () => {
    const other: LinkedFileReferrer = { kind: "dataset", id: "ds-2" };
    invoke.mockImplementation(async (cmd: string, args?: Args) => {
      if (cmd !== "linked_file_status") throw new Error(`unexpected command ${cmd}`);
      // Only the first request's status ever loads.
      if ((args?.referrer as LinkedFileReferrer).id !== REQUEST.id) return new Promise(() => {});
      return [
        { path: PATH, state: "bound" },
        { path: "/home/me/other.bin", state: "bound" },
      ];
    });
    const { rerender } = render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await stateBadge()).toBe("Chosen on this device");

    rerender(<LinkedFileBinding referrer={other} path={PATH} />);
    expect(screen.queryByTestId("linked-file-state")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
    await waitFor(() => expect(calls("linked_file_status")).toHaveLength(2));
    expect(screen.queryByTestId("linked-file-state")).toBeNull();

    // Back to the first request, at another path: its own status loads, not the earlier one's.
    rerender(<LinkedFileBinding referrer={REQUEST} path="/home/me/other.bin" />);
    expect(screen.queryByTestId("linked-file-state")).toBeNull();
    expect(await stateBadge()).toBe("Chosen on this device");
    expect(calls("linked_file_status")).toHaveLength(3);
  });

  it("never shows an earlier request's error for another one", async () => {
    const other: LinkedFileReferrer = { kind: "request", id: "req-2" };
    invoke.mockImplementation(async (cmd: string, args?: Args) => {
      if (cmd !== "linked_file_status") throw new Error(`unexpected command ${cmd}`);
      if ((args?.referrer as LinkedFileReferrer).id === REQUEST.id) throw "not found: request req-1";
      return new Promise(() => {});
    });
    const { rerender } = render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    rerender(<LinkedFileBinding referrer={other} path={PATH} />);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });

  it("says a file the saved request does not name cannot be chosen, and never suggests saving", async () => {
    backend([{ path: "/home/me/other.bin", state: "unbound" }]);
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await screen.findByText(/The saved request does not name this file, so it cannot be chosen for it on this device/)).toBeTruthy();
    expect(screen.queryByText(/save it/i)).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
  });
});

describe("choosing a linked file", () => {
  it("changes nothing when the dialog is cancelled", async () => {
    backend([{ path: PATH, state: "unbound" }], () => []);
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await stateBadge()).toBe("Not chosen on this device");
    fireEvent.click(screen.getByRole("button", { name: /Choose file…/ }));
    await waitFor(() => expect(calls("file_choose")).toHaveLength(1));
    await waitFor(() => expect((screen.getByRole("button", { name: /Choose file…/ }) as HTMLButtonElement).disabled).toBe(false));
    expect(calls("linked_file_status")).toHaveLength(1);
    expect(screen.getByTestId("linked-file-state").textContent).toBe("Not chosen on this device");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("binds a newly chosen file for this request and shows it as chosen", async () => {
    backend([{ path: PATH, state: "unbound" }], (s) => {
      s.status = [{ path: PATH, state: "bound" }];
      return grant(PATH);
    });
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    fireEvent.click(await screen.findByRole("button", { name: /Choose file…/ }));
    await waitFor(() => expect(screen.getByTestId("linked-file-state").textContent).toBe("Chosen on this device"));
    // The dialog is for this request: the backend binds only a file it names.
    expect(calls("file_choose")).toEqual([{ purpose: "linked_file", options: { multiple: false }, referrer: REQUEST }]);
    expect(calls("linked_file_status")).toEqual([{ referrer: REQUEST }, { referrer: REQUEST }]);
    expect(screen.getByRole("button", { name: /Rebind…/ })).toBeTruthy();
  });

  it("rebinds a file put back after it moved, and shows the refusal of a file chosen elsewhere", async () => {
    const moved = "/home/me/moved/upload.bin";
    let picked = moved;
    backend([{ path: PATH, state: "invalid", problem: "the file is no longer at this path" }], (s) => {
      if (picked !== PATH) throw `the chosen file '${picked}' is not the linked file this request names; attach the file instead`;
      s.status = [{ path: PATH, state: "bound" }];
      return grant(PATH);
    });
    render(<LinkedFileBinding referrer={REQUEST} path={PATH} />);
    expect(await stateBadge()).toBe("Missing or changed");

    // The file at its new place is refused: the request names only the old path.
    fireEvent.click(screen.getByRole("button", { name: /Rebind…/ }));
    expect((await screen.findByRole("alert")).textContent).toContain("is not the linked file this request names");
    expect(screen.getByTestId("linked-file-state").textContent).toBe("Missing or changed");
    expect(calls("linked_file_status")).toHaveLength(1);

    // Put back at its path and chosen again, it is usable, and the error clears.
    picked = PATH;
    fireEvent.click(screen.getByRole("button", { name: /Rebind…/ }));
    await waitFor(() => expect(screen.getByTestId("linked-file-state").textContent).toBe("Chosen on this device"));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(calls("file_choose")).toHaveLength(2);
    for (const args of calls("file_choose")) expect(args.referrer).toEqual(REQUEST);
  });

  it("reloads every linked file of the request when the chosen file is another one it names", async () => {
    const other = "/home/me/other.bin";
    backend(
      [
        { path: PATH, state: "unbound" },
        { path: other, state: "unbound" },
      ],
      (s) => {
        // The dialog opened beside PATH, but the user picked the other file the request names.
        s.status = [
          { path: PATH, state: "unbound" },
          { path: other, state: "bound" },
        ];
        return grant(other);
      },
    );
    render(
      <>
        <LinkedFileBinding referrer={REQUEST} path={PATH} />
        <LinkedFileBinding referrer={REQUEST} path={other} />
      </>,
    );
    await waitFor(() => expect(screen.getAllByTestId("linked-file-state").map((b) => b.textContent)).toEqual(["Not chosen on this device", "Not chosen on this device"]));
    const [first] = screen.getAllByTestId("linked-file");
    fireEvent.click(within(first).getByRole("button", { name: /Choose file…/ }));
    await waitFor(() => expect(screen.getAllByTestId("linked-file-state").map((b) => b.textContent)).toEqual(["Not chosen on this device", "Chosen on this device"]));
    expect(calls("linked_file_status")).toHaveLength(4);
  });

  it("chooses a dataset's file for that dataset", async () => {
    const dataset: LinkedFileReferrer = { kind: "dataset", id: "ds-1" };
    backend([{ path: "/data/rows.csv", state: "unbound" }], (s) => {
      s.status = [{ path: "/data/rows.csv", state: "bound" }];
      return grant("/data/rows.csv");
    });
    render(<LinkedFileBinding referrer={dataset} path="/data/rows.csv" />);
    expect(await screen.findByText(/for this dataset/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Choose file…/ }));
    await waitFor(() => expect(screen.getByTestId("linked-file-state").textContent).toBe("Chosen on this device"));
    expect(calls("file_choose")).toEqual([{ purpose: "linked_file", options: { multiple: false }, referrer: dataset }]);
  });
});

describe("where linked files are chosen", () => {
  const http = (patch: Partial<RequestSpec>): RequestSpec => ({ method: "POST", url: "https://example.test", ...patch }) as RequestSpec;

  it("shows a linked binary body's status for the saved request", async () => {
    backend([{ path: PATH, state: "unbound" }]);
    render(<BodyEditor spec={http({ body: { type: "binary", attachment: { kind: "linked_file", path: PATH } } })} set={() => {}} requestId="req-1" />);
    expect(await stateBadge()).toBe("Not chosen on this device");
    expect(calls("linked_file_status")).toEqual([{ referrer: REQUEST }]);
    // Attaching a copy instead is still offered.
    expect(screen.getByRole("button", { name: "Choose another file…" })).toBeTruthy();
  });

  it("shows each linked multipart file, and no status for a stored one", async () => {
    backend([{ path: PATH, state: "bound" }]);
    const stored = { kind: "stored" as const, sha256: "ab", size: 1, file_name: "a.txt" };
    const parts = [
      { name: "a", part_kind: "file" as const, attachment: stored, enabled: true },
      { name: "b", part_kind: "file" as const, attachment: { kind: "linked_file" as const, path: PATH }, enabled: true },
    ];
    render(<BodyEditor spec={http({ body: { type: "multipart", parts } })} set={() => {}} requestId="req-1" />);
    expect(await stateBadge()).toBe("Chosen on this device");
    expect(screen.getAllByTestId("linked-file")).toHaveLength(1);
    expect(screen.getByText("a.txt · 1 B")).toBeTruthy();
  });

  it("lists a gRPC schema's linked files with their status", async () => {
    const proto = "/home/me/echo.proto";
    backend([{ path: proto, state: "invalid", problem: "the path no longer leads to a regular file" }]);
    const spec = {
      method: "POST",
      url: "grpcs://example.test",
      protocol: "grpc",
      grpc: { service: "a.v1.S", method: "M", schema: { kind: "proto_files", files: [{ kind: "linked_file", path: proto }] }, messages: ["{}"] },
    } as RequestSpec;
    render(<ProtocolEditor spec={spec} set={() => {}} workspaceId="ws" requestId="req-1" />);
    const list = screen.getByTestId("grpc-linked-schema");
    expect(within(list).getByText(proto)).toBeTruthy();
    expect(await stateBadge()).toBe("Missing or changed");
    expect(within(list).getByRole("button", { name: /Rebind…/ })).toBeTruthy();
    expect(calls("linked_file_status")).toEqual([{ referrer: REQUEST }]);
  });

  it("lists nothing for a gRPC schema of stored files", () => {
    backend([]);
    const spec = {
      method: "POST",
      url: "grpcs://example.test",
      protocol: "grpc",
      grpc: { service: "a.v1.S", method: "M", schema: { kind: "descriptor_set", attachment: { kind: "stored", sha256: "ab", size: 1, file_name: "d.pb" } }, messages: ["{}"] },
    } as RequestSpec;
    render(<ProtocolEditor spec={spec} set={() => {}} workspaceId="ws" requestId="req-1" />);
    expect(screen.queryByTestId("grpc-linked-schema")).toBeNull();
    expect(calls("linked_file_status")).toEqual([]);
  });

  it("shows the selected linked dataset's status in the load plan", async () => {
    const dataset: Dataset = {
      id: "ds-1",
      schema_version: 1,
      created_at: "2026-09-26T00:00:00Z",
      updated_at: "2026-09-26T00:00:00Z",
      workspace_id: "ws-1",
      name: "rows",
      format: "csv",
      attachment: { kind: "linked_file", path: "/data/rows.csv" },
    };
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "linked_file_status") return [{ path: "/data/rows.csv", state: "unbound" }];
      // The plan's unit check is not under test.
      if (cmd === "load_plan_check") return new Promise(() => {});
      throw new Error(`unexpected command ${cmd}`);
    });
    const plan: LoadPlan = {
      id: "plan-1",
      workspace_id: "ws-1",
      name: "Rows",
      workload: { model: "iterations", iterations: 1, concurrency: 1 },
      chain: ["req-1"],
      mix: [],
      dataset_id: "ds-1",
      connection_mode: "persistent",
      warmup_secs: 0,
      seed: 1,
      trusted: true,
      created_at: "2026-09-26T00:00:00Z",
      updated_at: "2026-09-26T00:00:00Z",
    };
    const noop = () => {};
    render(
      <PlanEditor
        plan={plan}
        requests={[{ id: "req-1", label: "Upload", method: "POST" }]}
        environments={[]}
        datasets={[dataset]}
        onDatasetsChanged={noop}
        onSaved={noop}
        onDeleted={noop}
        onStarted={noop}
      />,
    );
    expect(await stateBadge()).toBe("Not chosen on this device");
    expect(calls("linked_file_status")).toEqual([{ referrer: { kind: "dataset", id: "ds-1" } }]);
    // No dataset selected: no status.
    fireEvent.change(screen.getByLabelText("Dataset (one row per iteration)"), { target: { value: "" } });
    expect(screen.queryByTestId("linked-file")).toBeNull();
  });
});

describe("choosing a new location for a linked file", () => {
  const NEW = "/home/me/moved/upload.bin";

  /** The saved request as its editor shows it: `onRelocated` reloads it, which then names NEW. */
  function Editor({ onRelocated }: { onRelocated: () => void }) {
    const [path, setPath] = useState(PATH);
    return (
      <LinkedFileBinding
        referrer={REQUEST}
        path={path}
        onRelocated={async () => {
          onRelocated();
          setPath(NEW);
        }}
      />
    );
  }

  const relocateButton = () => screen.queryByRole("button", { name: /Choose new location…/ });

  it("is offered for a file not chosen here, or missing or changed, where the saved request can be reloaded", async () => {
    for (const state of ["unbound", "invalid"] as const) {
      backend([{ path: PATH, state, problem: state === "invalid" ? "the file is no longer at this path" : undefined }]);
      render(<LinkedFileBinding referrer={REQUEST} path={PATH} onRelocated={() => {}} />);
      await screen.findByTestId("linked-file-state");
      expect(relocateButton()).toBeTruthy();
      expect(screen.getByTestId("linked-file").textContent).toMatch(/Choose new location… changes this request to name it/);
      cleanup();
      invoke.mockReset();
    }
    // Not for a file that is usable where it is.
    backend([{ path: PATH, state: "bound" }]);
    const { unmount } = render(<LinkedFileBinding referrer={REQUEST} path={PATH} onRelocated={() => {}} />);
    expect(await stateBadge()).toBe("Chosen on this device");
    expect(relocateButton()).toBeNull();
    unmount();
    // Nor where nothing reloads what is shown of the request or dataset.
    backend([{ path: PATH, state: "invalid", problem: "the file is no longer at this path" }]);
    render(<LinkedFileBinding referrer={{ kind: "dataset", id: "ds-1" }} path={PATH} />);
    expect(await stateBadge()).toBe("Missing or changed");
    expect(relocateButton()).toBeNull();
    expect(screen.getByTestId("linked-file").textContent).not.toContain("Choose new location");
  });

  it("repoints the saved request to the file chosen in the dialog, then reloads it", async () => {
    const reloaded = vi.fn();
    backend([{ path: PATH, state: "invalid", problem: "the file is no longer at this path" }], (s) => {
      s.status = [{ path: NEW, state: "bound" }];
      return grant(NEW);
    });
    render(<Editor onRelocated={reloaded} />);
    expect(await stateBadge()).toBe("Missing or changed");
    fireEvent.click(relocateButton()!);
    await waitFor(() => expect(screen.getByTestId("linked-file").textContent).toContain(NEW));
    expect(await stateBadge()).toBe("Chosen on this device");
    // The dialog is for this request and the reference it names; the new path comes from the dialog.
    expect(calls("file_choose")).toEqual([{ purpose: "linked_file_relocate", options: { multiple: false }, referrer: REQUEST, oldPath: PATH }]);
    expect(reloaded).toHaveBeenCalledTimes(1);
    expect(relocateButton()).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("changes nothing when the dialog is cancelled", async () => {
    const reloaded = vi.fn();
    backend([{ path: PATH, state: "unbound" }], () => []);
    render(<Editor onRelocated={reloaded} />);
    expect(await stateBadge()).toBe("Not chosen on this device");
    fireEvent.click(relocateButton()!);
    await waitFor(() => expect(calls("file_choose")).toHaveLength(1));
    await waitFor(() => expect((relocateButton() as HTMLButtonElement).disabled).toBe(false));
    expect(reloaded).not.toHaveBeenCalled();
    expect(calls("linked_file_status")).toHaveLength(1);
    expect(screen.getByTestId("linked-file").textContent).toContain(PATH);
    expect(screen.getByTestId("linked-file-state").textContent).toBe("Not chosen on this device");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows a refused relocation and reloads nothing", async () => {
    const reloaded = vi.fn();
    backend([{ path: PATH, state: "invalid", problem: "the file is no longer at this path" }], () => {
      throw "the chosen linked file is not a regular file";
    });
    render(<Editor onRelocated={reloaded} />);
    expect(await stateBadge()).toBe("Missing or changed");
    fireEvent.click(relocateButton()!);
    expect((await screen.findByRole("alert")).textContent).toContain("not a regular file");
    expect(reloaded).not.toHaveBeenCalled();
    expect(screen.getByTestId("linked-file").textContent).toContain(PATH);
    expect(screen.getByTestId("linked-file-state").textContent).toBe("Missing or changed");
  });

  it("is passed through the request body and gRPC schema editors", async () => {
    const reloaded = vi.fn(async () => {});
    backend([{ path: PATH, state: "unbound" }], (s) => {
      s.status = [{ path: NEW, state: "bound" }];
      return grant(NEW);
    });
    const spec = { method: "POST", url: "https://example.test", body: { type: "binary", attachment: { kind: "linked_file", path: PATH } } } as RequestSpec;
    const { unmount } = render(<BodyEditor spec={spec} set={() => {}} requestId="req-1" onRelocated={reloaded} />);
    fireEvent.click(await screen.findByRole("button", { name: /Choose new location…/ }));
    await waitFor(() => expect(reloaded).toHaveBeenCalledTimes(1));
    unmount();

    backend([{ path: PATH, state: "unbound" }]);
    const grpc = {
      method: "POST",
      url: "grpcs://example.test",
      protocol: "grpc",
      grpc: { service: "a.v1.S", method: "M", schema: { kind: "proto_files", files: [{ kind: "linked_file", path: PATH }] }, messages: ["{}"] },
    } as RequestSpec;
    render(<ProtocolEditor spec={grpc} set={() => {}} workspaceId="ws" requestId="req-1" onRelocated={reloaded} />);
    expect(await within(screen.getByTestId("grpc-linked-schema")).findByRole("button", { name: /Choose new location…/ })).toBeTruthy();
  });
});
