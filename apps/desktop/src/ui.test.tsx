// Renderer unit tests for the shared UI helpers. These run in jsdom and do not
// exercise the native engine (see apps/desktop/e2e for native E2E).
import { useState } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { KeyValue, SensitiveValue } from "./generated/contracts";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));

import { KeyValueEditor, ListText, Modal, SecretField, fmtBytes, fmtUs, humanize, modalOpen } from "./ui";

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

describe("SecretField", () => {
  it("keeps the value and says why when the vault refuses it", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "secret_create") throw "LOCKED";
      throw new Error(`unexpected ${cmd}`);
    });
    const onChange = vi.fn();
    const value: SensitiveValue = { kind: "template", value: "tok-SENSITIVE-ui-vault" };
    render(<SecretField label="Token" value={value} onChange={onChange} workspaceId="ws" />);
    fireEvent.click(screen.getByRole("button", { name: "Store in vault" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Not stored in the vault: LOCKED");
    expect(onChange).not.toHaveBeenCalled();
    expect((screen.getByRole("button", { name: "Store in vault" }) as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("fmtBytes", () => {
  it("renders missing values as an em dash, not zero", () => {
    expect(fmtBytes(undefined)).toBe("—");
    expect(fmtBytes(null)).toBe("—");
  });
  it("uses bytes below 1 KiB and binary multiples above", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(1023)).toBe("1023 B");
    expect(fmtBytes(1024)).toBe("1.0 KB");
    expect(fmtBytes(1536)).toBe("1.5 KB");
    expect(fmtBytes(1024 * 1024)).toBe("1.00 MB");
    expect(fmtBytes(5 * 1024 * 1024 + 512 * 1024)).toBe("5.50 MB");
  });
});

describe("fmtUs", () => {
  it("renders missing durations as an em dash", () => {
    expect(fmtUs(undefined)).toBe("—");
    expect(fmtUs(null)).toBe("—");
  });
  it("switches units at 1 ms and 1 s", () => {
    expect(fmtUs(0)).toBe("0 µs");
    expect(fmtUs(999)).toBe("999 µs");
    expect(fmtUs(1000)).toBe("1.0 ms");
    expect(fmtUs(12_345)).toBe("12.3 ms");
    expect(fmtUs(999_999)).toBe("1000.0 ms");
    expect(fmtUs(1_000_000)).toBe("1.00 s");
    expect(fmtUs(2_500_000)).toBe("2.50 s");
  });
});

describe("humanize", () => {
  it("replaces every underscore with a space", () => {
    expect(humanize("may_have_been_sent")).toBe("may have been sent");
    expect(humanize("completed")).toBe("completed");
    expect(humanize("")).toBe("");
  });
});

function Harness(props: { initial: KeyValue[] }) {
  const [rows, setRows] = useState(props.initial);
  return <KeyValueEditor rows={rows} onChange={setRows} nameLabel="Header" />;
}

function valueInputFor(name: string): HTMLInputElement {
  const nameInput = screen.getByDisplayValue(name);
  // Row layout: [enabled] [name] [value (+reveal)] [remove]
  const valueCell = nameInput.nextElementSibling as HTMLElement;
  return valueCell.querySelector("input") as HTMLInputElement;
}

describe("KeyValueEditor", () => {
  it("masks values of sensitive header names and leaves ordinary ones visible", () => {
    render(
      <Harness
        initial={[
          { name: "Authorization", value: "Bearer abc.def.ghi", enabled: true },
          { name: "X-Api-Key", value: "k-123", enabled: true },
          { name: "Cookie", value: "sid=1", enabled: true },
          { name: "Accept", value: "application/json", enabled: true },
        ]}
      />,
    );
    expect(valueInputFor("Authorization").type).toBe("password");
    expect(valueInputFor("X-Api-Key").type).toBe("password");
    expect(valueInputFor("Cookie").type).toBe("password");
    expect(valueInputFor("Accept").type).toBe("text");
  });

  it("masks rows explicitly flagged sensitive regardless of name", () => {
    render(<Harness initial={[{ name: "X-Custom", value: "s3cr3t", enabled: true, sensitive: true }]} />);
    expect(valueInputFor("X-Custom").type).toBe("password");
  });

  it("shows {{variable}} references in clear text because they are not secret values", () => {
    render(<Harness initial={[{ name: "Authorization", value: "{{token}}", enabled: true }]} />);
    expect(valueInputFor("Authorization").type).toBe("text");
  });

  it("reveals and re-hides a masked value only on explicit request", () => {
    render(<Harness initial={[{ name: "Authorization", value: "Bearer x", enabled: true }]} />);
    const input = valueInputFor("Authorization");
    expect(input.type).toBe("password");
    fireEvent.click(screen.getByRole("button", { name: "Reveal value" }));
    expect(valueInputFor("Authorization").type).toBe("text");
    fireEvent.click(screen.getByRole("button", { name: "Hide value" }));
    expect(valueInputFor("Authorization").type).toBe("password");
  });

  it("masks a value as soon as its name becomes sensitive", () => {
    render(<Harness initial={[{ name: "X-Trace", value: "abc", enabled: true }]} />);
    expect(valueInputFor("X-Trace").type).toBe("text");
    fireEvent.change(screen.getByDisplayValue("X-Trace"), { target: { value: "X-Session-Token" } });
    expect(valueInputFor("X-Session-Token").type).toBe("password");
  });

  it("has no reveal control for non-sensitive rows", () => {
    render(<Harness initial={[{ name: "Accept", value: "*/*", enabled: true }]} />);
    expect(screen.queryByRole("button", { name: "Reveal value" })).toBeNull();
  });
});

function Dialog() {
  const [open, setOpen] = useState(true);
  return open ? (
    <Modal title="Child dialog" onClose={() => setOpen(false)}>
      <p>body</p>
    </Modal>
  ) : null;
}

describe("modalOpen", () => {
  it("is true while any Modal is mounted, whoever opened it", () => {
    expect(modalOpen()).toBe(false);
    const a = render(<Dialog />);
    const b = render(<Dialog />);
    expect(modalOpen()).toBe(true);
    a.unmount();
    expect(modalOpen()).toBe(true);
    b.unmount();
    expect(modalOpen()).toBe(false);
  });

  it("still claims the Escape that closed the modal for a later window listener", () => {
    render(<Dialog />);
    // Registered after the modal's own Escape handler, so it runs after it.
    const seen: boolean[] = [];
    const later = (e: KeyboardEvent) => seen.push(modalOpen(e));
    window.addEventListener("keydown", later);
    try {
      fireEvent.keyDown(window, { key: "Escape" });
      expect(screen.queryByRole("dialog", { name: "Child dialog" })).toBeNull();
      expect(modalOpen()).toBe(false);
      expect(seen).toEqual([true]);
      // A key pressed with no modal open is not claimed.
      fireEvent.keyDown(window, { key: "Escape" });
      expect(seen).toEqual([true, false]);
    } finally {
      window.removeEventListener("keydown", later);
    }
  });
});

describe("ListText", () => {
  // A parent that stores the parsed list, as the editors do.
  function Harness(props: { initial: string[]; multiline?: boolean; onList: (l: string[]) => void }) {
    const [list, setList] = useState(props.initial);
    const sep = props.multiline ? "\n" : ",";
    return (
      <>
        <label>
          Items
          <ListText<string>
            multiline={props.multiline}
            value={list}
            format={(l) => l.join(props.multiline ? "\n" : ", ")}
            parse={(t) => t.split(sep).map((x) => x.trim()).filter(Boolean)}
            onChange={(l) => {
              setList(l);
              props.onList(l);
            }}
          />
        </label>
        <button onClick={() => setList(["x", "y"])}>Replace</button>
      </>
    );
  }

  it("keeps the separator just typed, so a second item can be entered (#514)", () => {
    const seen: string[][] = [];
    render(<Harness initial={[]} onList={(l) => seen.push(l)} />);
    const field = screen.getByLabelText("Items") as HTMLInputElement;
    for (const typed of ["a", "a,", "a, ", "a, b"]) {
      fireEvent.change(field, { target: { value: typed } });
      expect(field.value).toBe(typed);
    }
    expect(seen).toEqual([["a"], ["a"], ["a"], ["a", "b"]]);
  });

  it("keeps an empty line while typing in a multi-line list", () => {
    const seen: string[][] = [];
    render(<Harness initial={["one"]} multiline onList={(l) => seen.push(l)} />);
    const field = screen.getByLabelText("Items") as HTMLTextAreaElement;
    expect(field.value).toBe("one");
    for (const typed of ["one\n", "one\nt", "one\ntwo"]) {
      fireEvent.change(field, { target: { value: typed } });
      expect(field.value).toBe(typed);
    }
    expect(seen.at(-1)).toEqual(["one", "two"]);
  });

  it("shows a list replaced from elsewhere", () => {
    render(<Harness initial={["a"]} onList={() => {}} />);
    const field = screen.getByLabelText("Items") as HTMLInputElement;
    fireEvent.change(field, { target: { value: "a," } });
    fireEvent.click(screen.getByRole("button", { name: "Replace" }));
    expect(field.value).toBe("x, y");
  });
});
