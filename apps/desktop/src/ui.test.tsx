// Renderer unit tests for the shared UI helpers. These run in jsdom and do not
// exercise the native engine (see apps/desktop/e2e for native E2E).
import { useState } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { KeyValue } from "./generated/contracts";
import { KeyValueEditor, fmtBytes, fmtUs, humanize } from "./ui";

afterEach(cleanup);

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
