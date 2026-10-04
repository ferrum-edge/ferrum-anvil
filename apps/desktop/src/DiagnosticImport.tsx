import { useEffect, useRef, useState } from "react";
import {
  DIAGNOSTIC_MAX_BYTES,
  diagnosticImportPreview,
  type ImportedDiagnosticPreview,
} from "./diagnosticImportSource";

export function DiagnosticImport() {
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<ImportedDiagnosticPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const attempt = useRef(0);
  useEffect(
    () => () => {
      attempt.current += 1;
    },
    [],
  );
  const reported = preview ? JSON.stringify(preview.reported, null, 2) : "";
  const displayLimit = 64 * 1024;
  const escaped = reported.replace(/[\u202a-\u202e\u2066-\u2069]/g, (c) =>
    `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  const reportedBytes = new TextEncoder().encode(escaped);
  const displayed = new TextDecoder().decode(reportedBytes.subarray(0, displayLimit), {
    stream: true,
  });

  const clear = () => {
    attempt.current += 1;
    setText("");
    setPreview(null);
    setError(null);
    setBusy(false);
  };

  const show = async (input: string, id: number) => {
    setBusy(true);
    setPreview(null);
    setError(null);
    try {
      const result = await diagnosticImportPreview(input);
      if (attempt.current === id) {
        setPreview(result);
        setText("");
      }
    } catch {
      if (attempt.current === id) {
        setError(
          "Cannot preview this input. Use bounded UTF-8 diagnostic v1 JSON with valid references.",
        );
      }
    } finally {
      if (attempt.current === id) setBusy(false);
    }
  };

  const choose = async (file?: File) => {
    if (!file) return;
    const id = ++attempt.current;
    setText("");
    setPreview(null);
    setError(null);
    if (file.size > DIAGNOSTIC_MAX_BYTES) {
      setError("Diagnostic JSON exceeds the 4 MiB byte limit.");
      return;
    }
    setBusy(true);
    try {
      // Browser File bytes only: no native picker, grant, backend path or URL.
      const bytes = await file.slice(0, DIAGNOSTIC_MAX_BYTES + 1).arrayBuffer();
      if (attempt.current !== id) return;
      if (bytes.byteLength > DIAGNOSTIC_MAX_BYTES) throw new Error("limit");
      const input = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      await show(input, id);
    } catch {
      if (attempt.current === id) {
        setError("Cannot read this file as bounded UTF-8 JSON.");
        setBusy(false);
      }
    }
  };

  return (
    <div className="col">
      <p className="hint">
        Read-only diagnostic preview. Paste a report, Alloy CLI JSON, finding or reference,
        or select a JSON file up to 4 MiB. Imported authentication and confidence are claims.
      </p>
      <label className="lbl">
        Diagnostic JSON file
        <input
          type="file"
          accept=".json,application/json"
          disabled={busy}
          onChange={(event) => {
            const file = event.target.files?.[0];
            event.target.value = "";
            void choose(file);
          }}
        />
      </label>
      <label className="lbl">
        Paste diagnostic JSON
        <textarea
          className="field mono"
          rows={6}
          maxLength={DIAGNOSTIC_MAX_BYTES}
          value={text}
          disabled={busy}
          onPaste={(event) => {
            const pasted = event.clipboardData.getData("text");
            if (
              pasted.length > DIAGNOSTIC_MAX_BYTES ||
              new TextEncoder().encode(pasted).byteLength > DIAGNOSTIC_MAX_BYTES
            ) {
              event.preventDefault();
              setError("Diagnostic JSON exceeds the 4 MiB byte limit.");
              setPreview(null);
            }
          }}
          onChange={(event) => {
            attempt.current += 1;
            setText(event.target.value);
            setPreview(null);
            setError(null);
          }}
        />
      </label>
      <div className="row">
        <button
          className="btn"
          disabled={busy || !text.trim()}
          onClick={() => void show(text, ++attempt.current)}
        >
          {busy ? "Previewing…" : "Preview diagnostic"}
        </button>
        <button className="btn" onClick={clear}>
          Clear preview
        </button>
      </div>
      {error && (
        <div role="alert" className="bad-box">
          {error}
        </div>
      )}
      {preview && (
        <section aria-label="Unverified diagnostic preview" className="col">
          <div className="warn-box">
            Unverified offline claims — Anvil confidence: unknown.
            This preview does not confirm an actual client diagnosis.
          </div>
          <p>
            {preview.observation_count} reported observations; {preview.finding_count} reported
            findings.
          </p>
          <ul>
            {preview.warnings.map((warning, index) => (
              <li key={index}>{warning}</li>
            ))}
          </ul>
          <details open>
            <summary>Reported facts and claims (credentials redacted)</summary>
            <pre className="code" data-testid="diagnostic-reported">
              {displayed}
            </pre>
            {reportedBytes.byteLength > displayLimit && (
              <p className="hint">Presentation limited to the first 64 KiB of reported JSON.</p>
            )}
          </details>
        </section>
      )}
    </div>
  );
}
