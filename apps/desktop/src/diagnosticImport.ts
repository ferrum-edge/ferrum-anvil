// Dedicated ephemeral IPC DTO. Matches anvil-domain::diagnostic_import; never
// an ExecutionRecord or a DiagnosticFinding used by the client diagnosis UI.
import { invoke } from "@tauri-apps/api/core";

export const DIAGNOSTIC_MAX_BYTES = 4 * 1024 * 1024;

export type ImportedDiagnosticPreview = {
  kind: "report" | "alloy_cli" | "finding" | "reference";
  trust: "unverified";
  confidence: "unknown";
  observation_count: number;
  finding_count: number;
  reported: unknown;
  warnings: string[];
};

export function diagnosticImportPreview(text: string): Promise<ImportedDiagnosticPreview> {
  if (
    text.length > DIAGNOSTIC_MAX_BYTES ||
    new TextEncoder().encode(text).byteLength > DIAGNOSTIC_MAX_BYTES
  ) {
    return Promise.reject(new Error("Diagnostic JSON exceeds the 4 MiB byte limit."));
  }
  return invoke<ImportedDiagnosticPreview>("diagnostic_import_preview", { input: { text } });
}
