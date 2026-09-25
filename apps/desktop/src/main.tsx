import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// The renderer never evaluates remote content: responses are shown as text,
// and the CSP in tauri.conf.json forbids remote scripts, frames and fetches.
// Technical input (URLs, header names, JSON) must never be autocorrected or
// auto-capitalised by the platform webview.
document.addEventListener(
  "focusin",
  (e) => {
    const el = e.target;
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      el.setAttribute("autocorrect", "off");
      el.setAttribute("autocapitalize", "off");
      el.setAttribute("autocomplete", el.getAttribute("autocomplete") ?? "off");
      el.spellcheck = false;
    }
  },
  true,
);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
