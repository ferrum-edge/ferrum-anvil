// The in-window confirmation that replaced the webview's native ask dialog:
// it answers once, OK only by its OK button, and shows prompts one at a time.
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useConfirm, type Confirm } from "./Confirm";

afterEach(cleanup);

let confirm: Confirm;
function Host() {
  const c = useConfirm();
  confirm = c.confirm;
  return (
    <>
      <span data-testid="open">{String(c.open)}</span>
      {c.prompt}
    </>
  );
}

const ask = (message: string) => {
  let answer: Promise<boolean> = Promise.resolve(false);
  act(() => {
    answer = confirm(message, { title: "Unsaved changes", kind: "warning", okLabel: "Discard", cancelLabel: "Keep open" });
  });
  return answer;
};

describe("useConfirm", () => {
  it("resolves true only from its OK button", async () => {
    render(<Host />);
    expect(screen.queryByRole("dialog")).toBeNull();
    const answer = ask("Close without saving?");
    expect(screen.getByRole("dialog", { name: "Unsaved changes" }).textContent).toContain("Close without saving?");
    expect(screen.getByTestId("open").textContent).toBe("true");
    // The safe choice has the focus.
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Keep open" }));
    fireEvent.click(screen.getByRole("button", { name: "Discard" }));
    await expect(answer).resolves.toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByTestId("open").textContent).toBe("false");
  });

  it("resolves false from Cancel, Escape and the close button", async () => {
    render(<Host />);
    const cancel = ask("one");
    fireEvent.click(screen.getByRole("button", { name: "Keep open" }));
    await expect(cancel).resolves.toBe(false);
    const escape = ask("two");
    fireEvent.keyDown(window, { key: "Escape" });
    await expect(escape).resolves.toBe(false);
    const close = ask("three");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await expect(close).resolves.toBe(false);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("shows prompts one at a time, and a second click does not answer the next one", async () => {
    render(<Host />);
    const first = ask("first");
    const second = ask("second");
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(screen.getByRole("dialog").textContent).toContain("first");
    const ok = screen.getByRole("button", { name: "Discard" });
    fireEvent.click(ok);
    fireEvent.click(ok);
    await expect(first).resolves.toBe(true);
    expect(screen.getByRole("dialog").textContent).toContain("second");
    fireEvent.click(screen.getByRole("button", { name: "Keep open" }));
    await expect(second).resolves.toBe(false);
  });
});
