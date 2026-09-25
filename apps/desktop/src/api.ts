// Typed wrappers around the Rust IPC commands. The webview never performs
// network I/O or handles vault keys; it only renders redacted results.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppSettings,
  AttachmentRef,
  DiagnosticFinding,
  Environment,
  ExecutionEvent,
  ExecutionRecord,
  Folder,
  HeaderEntry,
  IntegrationProfile,
  ProtectionMode,
  ProxyProfile,
  RequestDefinition,
  RequestSpec,
  SecretRef,
  SettingsOverrides,
  TlsProfile,
  Workspace,
  EffectiveSettings,
} from "./generated/contracts";

export type {
  AppSettings,
  AttachmentRef,
  DiagnosticFinding,
  Environment,
  ExecutionEvent,
  ExecutionRecord,
  Folder,
  HeaderEntry,
  IntegrationProfile,
  ProxyProfile,
  RequestDefinition,
  RequestSpec,
  SecretRef,
  SettingsOverrides,
  TlsProfile,
  Workspace,
};

export interface Status {
  state: "no_profile" | "locked" | "unlocked";
  profile?: string;
  protection?: ProtectionMode;
  version: string;
}
export interface ProfileSummary {
  profile_id: string;
  display_name: string;
  protection: ProtectionMode;
  dir: string;
  created_at: string;
}
export interface TreeNode {
  id: string;
  kind: "folder" | "request";
  name: string;
  method?: string | null;
  url?: string | null;
  favorite: boolean;
  children: TreeNode[];
}
export interface BodyView {
  text?: string | null;
  pretty?: string | null;
  hex?: string | null;
  is_binary: boolean;
  decoded: boolean;
  shown_bytes: number;
  captured_bytes: number;
}
export interface ExecutionView {
  record: ExecutionRecord;
  body: BodyView;
}
export interface HistoryItem {
  id: string;
  started_at: number;
  method: string;
  url: string;
  summary: string;
  status?: number | null;
  request_id?: string | null;
}
export interface EffectiveRequest {
  method: string;
  url: string;
  destination: string;
  headers: HeaderEntry[];
  body_bytes: number;
  body_preview: string;
  content_type?: string | null;
  auth: string;
  auth_varies_per_send: boolean;
  tls_profile?: string | null;
  tls_verification: boolean;
  proxy?: string | null;
  ferrum_trust?: string | null;
  settings: EffectiveSettings;
  variables_used: [string, string][];
  inferred: string[];
  lint_warning?: string | null;
  omitted_secrets: number;
}
export interface LintIssue {
  line: number;
  column: number;
  message: string;
}
export type LintResult = { status: "valid" } | { status: "invalid"; issues: LintIssue[] } | { status: "skipped"; reason: string };
export interface SystemInfo {
  version: string;
  engine: string;
  catalog: string;
  system_roots: number;
  data_dir: string;
  platform: string;
}
export interface ExportPreview {
  manifest: {
    mode: string;
    counts: Record<string, number>;
    excluded: string[];
    placeholders: { pointer: string; placeholder: string }[];
    device_bindings: string[];
    content_warnings: { pointer: string; reason: string }[];
  };
  secrets_included: number;
  literals_moved: number;
}
export interface ImportReport {
  plan: { policy: string; to_create: number; to_replace: number; skipped_existing: number; conflicts: string[] };
  warnings: string[];
  secrets_restored: boolean;
  missing_secrets: string[];
  checkpoint?: string | null;
  workspaces: string[];
  workspace_ids: string[];
}
export interface JwtInspection {
  header: unknown;
  claims: unknown;
  time_status: "valid" | "expired" | "not_yet_valid" | "no_expiry";
  signature_verified: boolean;
  notes: string[];
}

export class ApiError extends Error {
  readonly locked: boolean;
  constructor(message: string) {
    super(message);
    this.locked = message === "LOCKED" || message === "NO_PROFILE";
  }
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    const msg = typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
    if (msg === "LOCKED") window.dispatchEvent(new CustomEvent("anvil-locked"));
    throw new ApiError(msg);
  }
}

export interface SendInput {
  workspace_id: string;
  request_id?: string | null;
  spec?: RequestSpec | null;
  environment_id?: string | null;
  send_anyway: boolean;
  run_override?: SettingsOverrides | null;
}

export const api = {
  status: () => call<Status>("app_status"),
  systemInfo: () => call<SystemInfo>("system_info"),
  profiles: () => call<ProfileSummary[]>("profiles_list"),
  createProfile: (name: string, passphrase: string | null, keychain: boolean) =>
    call<{ profile_id: string; recovery_key?: string | null }>("profile_create", { name, passphrase, keychain }),
  unlock: (profileId: string, passphrase: string | null, recoveryKey: string | null) =>
    call<void>("profile_unlock", { profileId, passphrase, recoveryKey }),
  lock: () => call<void>("app_lock"),
  touch: () => call<void>("touch"),

  workspaces: () => call<Workspace[]>("workspaces_list"),
  createWorkspace: (name: string) => call<Workspace>("workspace_create", { name }),
  saveWorkspace: (workspace: Workspace) => call<Workspace>("workspace_save", { workspace }),
  deleteWorkspace: (workspaceId: string) => call<void>("workspace_delete", { workspaceId }),
  tree: (workspaceId: string) => call<TreeNode[]>("tree_get", { workspaceId }),
  createFolder: (workspaceId: string, parentId: string | null, name: string) => call<Folder>("folder_create", { workspaceId, parentId, name }),
  getFolder: (folderId: string) => call<Folder>("folder_get", { folderId }),
  saveFolder: (folder: Folder) => call<Folder>("folder_save", { folder }),
  moveFolder: (folderId: string, parentId: string | null, sortKey: number) => call<Folder>("folder_move", { folderId, parentId, sortKey }),
  deleteFolder: (folderId: string) => call<void>("folder_delete", { folderId }),
  createRequest: (workspaceId: string, folderId: string | null, name: string, spec?: RequestSpec) =>
    call<RequestDefinition>("request_create", { workspaceId, folderId, name, spec }),
  getRequest: (requestId: string) => call<RequestDefinition>("request_get", { requestId }),
  saveRequest: (request: RequestDefinition) => call<RequestDefinition>("request_save", { request }),
  moveRequest: (requestId: string, folderId: string | null, sortKey: number) => call<RequestDefinition>("request_move", { requestId, folderId, sortKey }),
  duplicateRequest: (requestId: string) => call<RequestDefinition>("request_duplicate", { requestId }),
  deleteRequest: (requestId: string) => call<void>("request_delete", { requestId }),
  search: (workspaceId: string, query: string) => call<RequestDefinition[]>("search", { workspaceId, query }),

  environments: (workspaceId: string) => call<Environment[]>("environments_list", { workspaceId }),
  saveEnvironment: (environment: Environment) => call<Environment>("environment_save", { environment }),
  deleteEnvironment: (environmentId: string) => call<void>("environment_delete", { environmentId }),
  createSecret: (workspaceId: string | null, label: string, value: string) => call<SecretRef>("secret_create", { workspaceId, label, value }),
  updateSecret: (secret: SecretRef, workspaceId: string | null, value: string) => call<void>("secret_update", { secret, workspaceId, value }),
  generateDpopKey: (workspaceId: string | null, label: string) => call<{ secret: SecretRef; jkt: string }>("dpop_generate_key", { workspaceId, label }),

  tlsProfiles: (workspaceId: string) => call<TlsProfile[]>("tls_profiles_list", { workspaceId }),
  saveTlsProfile: (profile: TlsProfile) => call<TlsProfile>("tls_profile_save", { profile }),
  proxyProfiles: (workspaceId: string) => call<ProxyProfile[]>("proxy_profiles_list", { workspaceId }),
  saveProxyProfile: (profile: ProxyProfile) => call<ProxyProfile>("proxy_profile_save", { profile }),
  integrations: (workspaceId: string) => call<IntegrationProfile[]>("integrations_list", { workspaceId }),
  saveIntegration: (profile: IntegrationProfile) => call<IntegrationProfile>("integration_save", { profile }),
  settings: () => call<AppSettings>("settings_get"),
  saveSettings: (settings: AppSettings) => call<void>("settings_save", { settings }),

  effective: (input: SendInput) => call<EffectiveRequest>("effective_request", { input }),
  send: (input: SendInput, executionId: string) => call<ExecutionView>("send_request", { input, executionId }),
  cancel: (executionId: string) => call<boolean>("cancel_execution", { executionId }),
  history: (workspaceId: string, requestId: string | null, limit = 100) => call<HistoryItem[]>("history_list", { workspaceId, requestId, limit }),
  historyGet: (historyId: string) => call<ExecutionView>("history_get", { historyId }),
  historyClear: (workspaceId: string | null) => call<void>("history_clear", { workspaceId }),
  lint: (kind: string, text: string) => call<LintResult>("lint_body", { kind, text }),
  jwtInspect: (token: string) => call<JwtInspection>("jwt_inspect", { token }),

  exportPreview: (workspaceId: string | null, exportMode: string) => call<ExportPreview>("export_preview", { workspaceId, exportMode }),
  exportToPath: (workspaceId: string | null, exportMode: string, passphrase: string | null, path: string) =>
    call<number>("export_to_path", { workspaceId, exportMode, passphrase, path }),
  importPreview: (path: string, passphrase: string | null, conflictPolicy: string) => call<ImportReport>("import_preview", { path, passphrase, conflictPolicy }),
  importApply: (path: string, passphrase: string | null, conflictPolicy: string) => call<ImportReport>("import_apply", { path, passphrase, conflictPolicy }),
  attachmentAdd: (path: string, mediaType: string | null) => call<AttachmentRef>("attachment_add", { path, mediaType }),
  readTextFile: (path: string, workspaceId: string | null, storeAsSecret: string | null, base64 = false) =>
    call<{ text?: string | null; secret?: SecretRef | null }>("read_text_file", { path, workspaceId, storeAsSecret, base64 }),
};

export function onExecutionEvent(cb: (e: ExecutionEvent) => void): Promise<UnlistenFn> {
  return listen<ExecutionEvent>("execution-event", (ev) => cb(ev.payload));
}

export function onLocked(cb: (reason: string) => void): Promise<UnlistenFn> {
  return listen<string | null>("locked", (ev) => cb(ev.payload ?? "manual"));
}

export type { DiagnosticFinding as Finding };
