// Dedicated ephemeral IPC DTO from anvil-domain::diagnostic_import; never
// an ExecutionRecord or a DiagnosticFinding used by the client diagnosis UI.
import { invoke } from "@tauri-apps/api/core";
import type { DiagnosticImportInput, ImportedDiagnosticPreview } from "./generated/contracts";

export type { ImportedDiagnosticPreview } from "./generated/contracts";

export const DIAGNOSTIC_MAX_BYTES = 4 * 1024 * 1024;

export function diagnosticImportPreview(text: string): Promise<ImportedDiagnosticPreview> {
  if (
    text.length > DIAGNOSTIC_MAX_BYTES ||
    new TextEncoder().encode(text).byteLength > DIAGNOSTIC_MAX_BYTES
  ) {
    return Promise.reject(new Error("Diagnostic JSON exceeds the 4 MiB byte limit."));
  }
  const input: DiagnosticImportInput = { text };
  return invoke<ImportedDiagnosticPreview>("diagnostic_import_preview", { input });
}
