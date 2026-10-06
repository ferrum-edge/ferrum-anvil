// In-app confirmations. The webview holds no dialog permission (see
// src-tauri/capabilities/default.json), so it cannot open a native message or
// ask dialog: a prompt it shows is drawn inside the window, never one that
// could pass for the backend's own native confirmations, which guard security
// changes (src-tauri/src/presence.rs).
import { useCallback, useRef, useState, type ReactNode } from "react";
import { Modal } from "./ui";

export interface ConfirmOptions {
  title: string;
  /** A warning's OK button is styled as a destructive action. */
  kind?: "warning" | "info";
  okLabel?: string;
  cancelLabel?: string;
}

/** Ask the user to confirm `message`: true for OK; false for Cancel, Escape or closing the prompt. */
export type Confirm = (message: string, options: ConfirmOptions) => Promise<boolean>;

interface Prompt {
  message: string;
  options: ConfirmOptions;
  resolve: (ok: boolean) => void;
}

/**
 * A confirm function, the element that shows its prompts (render it once),
 * and whether a prompt is showing. Prompts show one at a time, in the order
 * asked; a prompt still showing when its owner unmounts is never answered.
 */
export function useConfirm(): { confirm: Confirm; prompt: ReactNode; open: boolean } {
  const [queue, setQueue] = useState<Prompt[]>([]);
  const confirm = useCallback<Confirm>(
    (message, options) => new Promise<boolean>((resolve) => setQueue((q) => [...q, { message, options, resolve }])),
    [],
  );
  // Each prompt gets its own key, so the next one mounts afresh and takes the focus.
  const keys = useRef(new WeakMap<Prompt, number>());
  const next = useRef(0);
  const current = queue[0];
  if (current && !keys.current.has(current)) keys.current.set(current, next.current++);
  // Answered once: a second click, or Escape after a click, is not taken for the next prompt.
  const answer = (p: Prompt, ok: boolean) => {
    p.resolve(ok);
    setQueue((q) => (q[0] === p ? q.slice(1) : q));
  };
  const prompt = current ? <ConfirmDialog key={keys.current.get(current)} prompt={current} onAnswer={(ok) => answer(current, ok)} /> : null;
  return { confirm, prompt, open: !!current };
}

function ConfirmDialog(props: { prompt: Prompt; onAnswer: (ok: boolean) => void }) {
  const { message, options } = props.prompt;
  return (
    <Modal
      title={options.title}
      onClose={() => props.onAnswer(false)}
      footer={
        <>
          <button className="btn" data-autofocus onClick={() => props.onAnswer(false)}>
            {options.cancelLabel ?? "Cancel"}
          </button>
          <button className={`btn ${options.kind === "warning" ? "danger" : "primary"}`} onClick={() => props.onAnswer(true)}>
            {options.okLabel ?? "OK"}
          </button>
        </>
      }
    >
      <p className="confirm-message">{message}</p>
    </Modal>
  );
}
