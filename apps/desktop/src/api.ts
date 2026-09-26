// Typed wrappers around the Rust IPC commands. The webview never performs
// network I/O or handles vault keys; it only renders redacted results.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppSettings,
  AttachmentRef,
  Dataset,
  LoadCounts,
  LatencySummary,
  LoadPlan,
  LoadReport,
  LoadUnitKind,
  ProtocolLoadMetrics,
  Protocol,
  RequestCounts,
  UnitSemantics,
  RunCompletion,
  RunEvent,
  RunReport,
  Scenario,
  SessionCommand,
  StreamMessage,
  TimeBucket,
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
  JwtSvidSummary,
  WorkloadApiCall,
  WorkloadEndpointSource,
} from "./generated/contracts";

export type {
  RunEvent,
  RunReport,
  Scenario,
  SessionCommand,
  StreamMessage,
  AppSettings,
  AttachmentRef,
  Dataset,
  LoadPlan,
  LoadReport,
  LoadUnitKind,
  ProtocolLoadMetrics,
  UnitSemantics,
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
export interface KeychainEntryName {
  service: string;
  account: string;
}
export interface ProfileSummary {
  profile_id: string;
  display_name: string;
  protection: ProtectionMode;
  dir: string;
  created_at: string;
  /** OS keychain entry left behind by converting to a passphrase; it no longer opens the profile and its removal is retried at each unlock. */
  leftover_keychain_entry?: KeychainEntryName | null;
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
  plan: {
    policy: string;
    to_create: number;
    to_replace: number;
    skipped_existing: number;
    conflicts: string[];
    foreign_secrets: string[];
    /** Objects stored here in another workspace under the same id; Replace refuses the bundle while any is listed. */
    foreign_objects: string[];
    /** Workspaces stored here that the bundle or full backup writes into (Merge/Replace); applying needs each one approved. */
    existing_workspaces: { id: string; name: string }[];
  };
  warnings: string[];
  secrets_restored: boolean;
  missing_secrets: string[];
  /** Linked local files the bundle names (`request 'Upload': /path`); each needs choosing on this device. */
  linked_files: string[];
  checkpoint?: string | null;
  workspaces: string[];
  workspace_ids: string[];
  /** A full backup (restored) rather than a bundle. */
  full_backup: boolean;
  /** SHA-256 of the file as read; applying passes it back so the approval holds only for the previewed file. */
  bundle_sha256: string;
}
export interface JwtInspection {
  header: unknown;
  claims: unknown;
  time_status: "valid" | "expired" | "not_yet_valid" | "no_expiry";
  signature_verified: boolean;
  notes: string[];
}

/** What a SPIFFE Workload API endpoint issues to this process (public data only). */
export interface WorkloadProbe {
  endpoint: string;
  endpoint_source?: WorkloadEndpointSource;
  endpoint_error?: string;
  calls: WorkloadApiCall[];
  x509_svids: { spiffe_id: string; not_after: string; chain_length: number; bundle_certificates: number; hint?: string }[];
  federated_trust_domains: string[];
  jwt_bundles: { trust_domain: string; key_ids: string[] }[];
  jwt_svid?: JwtSvidSummary;
}

export class ApiError extends Error {
  readonly locked: boolean;
  constructor(message: string) {
    super(message);
    this.locked = message === "LOCKED" || message === "NO_PROFILE";
  }
}

// ----------------------------------------------------------- native file dialogs
// The backend shows the open/save dialog itself and keeps the chosen path; the
// webview only gets an opaque grant for one purpose, which the file commands
// accept instead of a path.
export type FilePurpose =
  | "bundle_import"
  | "attachment"
  | "pem_file"
  | "pkcs12_file"
  | "spec_source"
  | "dataset"
  | "bundle_export"
  | "load_report_export"
  | "run_report_export"
  | "jwt_svid_file"
  | "linked_file";
export interface FileGrant {
  token: string;
  /** The chosen file's name without its folder, for display. */
  file_name: string;
  /** Only for `jwt_svid_file` and `linked_file`: the path the backend bound in the vault. */
  path?: string;
}
/** A JWT-SVID token file bound on this device through the native dialog. */
export interface TokenFileBinding {
  id: string;
  /** Canonical absolute path of the chosen file. */
  path: string;
  bound_at: string;
}
/** The saved request or dataset a linked local file is chosen for. */
export type LinkedFileReferrer = { kind: "request"; id: string } | { kind: "dataset"; id: string };
export interface FileDialogOptions {
  /** Suggested name for a save dialog. */
  file_name?: string;
  filters?: { name: string; extensions: string[] }[];
  /** Let the open dialog select several files (read purposes only). */
  multiple?: boolean;
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

// ------------------------------------------------------------------ load
export interface LoadPreflight {
  destinations: string[];
  workload: string;
  max_duration_secs: number;
  peak_target: number;
  dataset_rows?: number | null;
  trusted: boolean;
  warnings: string[];
  /** The unit every count in the report is per (LOAD-013). */
  unit: LoadUnitKind;
  unit_label: string;
  semantics: UnitSemantics;
}
/** Why a plan cannot be load tested; raised before any traffic (LOAD-013). */
export interface LoadRefusal {
  code:
    | "mixed_unit_kinds"
    | "grpc_client_streaming"
    | "grpc_bidirectional"
    | "grpc_reflection"
    | "sse_reconnect"
    | "udp_masque"
    | "udp_hbone"
    | "hbone_persistent"
    | "early_data"
    | "incomplete_request";
  request_id?: string | null;
  message: string;
}
/** What an edited plan would measure, or its typed refusal. Nothing is sent. */
export interface LoadPlanCheck {
  unit?: LoadUnitKind | null;
  unit_label?: string | null;
  semantics?: UnitSemantics | null;
  refusal?: LoadRefusal | null;
  /** [request id, protocol] in plan order. */
  protocols: [string, Protocol][];
}
export interface LoadReportSummary {
  run_id: string;
  plan_id: string;
  plan_name: string;
  started_at: string;
  completion: RunCompletion;
  partial: boolean;
  achieved_rate_per_sec: number;
  started: number;
  failures: number;
  /** p95 of successful units; null when none succeeded. */
  p95_us: number | null;
  unit: LoadUnitKind;
}
export interface LoadProgress {
  run_id: string;
  elapsed_secs: number;
  phase: "warmup" | "measuring" | "draining";
  in_flight: number;
  snapshot: {
    counts: LoadCounts;
    /** Unit ledger: one entry per request / call / stream / session / exchange. */
    requests: RequestCounts;
    /** Protocol denominators of the plan's unit kind. */
    protocol?: ProtocolLoadMetrics | null;
    achieved_rate_per_sec: number;
    offered_rate_per_sec?: number | null;
    latency_success: LatencySummary;
    latency_failure: LatencySummary;
    status_distribution: [number, number][];
    failure_categories: { category: string; count: number; examples: string[] }[];
    measured_duration_secs: number;
  };
  timeline_from: number;
  timeline_delta: TimeBucket[];
}
export interface LoadComparison {
  run_a: string;
  run_b: string;
  compatible: boolean;
  differences: { aspect: string; a: string; b: string; impact: string; explanation: string }[];
  summary: string;
}

// ----------------------------------------------------------- spec import
export type SpecInput = { kind: "file"; grant: string } | { kind: "text"; text: string; name: string };
export interface ImportOptions {
  mode: "blank" | "sample";
  seed: number;
  group_by: "tags" | "paths";
  include_optional: boolean;
  server_index: number;
  include_credentials: boolean;
  max_operations: number;
  max_bytes: number;
  max_ref_depth: number;
  max_nodes: number;
  max_ref_expansions: number;
  max_sample_nodes: number;
}
export const DEFAULT_IMPORT_OPTIONS: ImportOptions = {
  mode: "sample",
  seed: 0,
  group_by: "tags",
  include_optional: false,
  server_index: 0,
  include_credentials: false,
  max_operations: 5000,
  max_bytes: 32 * 1024 * 1024,
  max_ref_depth: 32,
  max_nodes: 2_000_000,
  max_ref_expansions: 250_000,
  max_sample_nodes: 20_000,
};
export interface SpecFinding {
  code: string;
  pointer: string;
  message: string;
}
export interface SpecImportReport {
  warnings: SpecFinding[];
  unsupported: SpecFinding[];
  external_refs: { reference: string; kind: string; pointers: string[]; requires_approval: boolean }[];
  scripts: { pointer: string; owner: string; event: string; language: string }[];
  inactive_settings: { pointer: string; setting: string; value: string; reason: string }[];
  redactions: { pointer: string; field: string; placeholder: string }[];
  required_variables: { name: string; secret: boolean; reason: string; pointers: string[] }[];
  counts: { operations_found: number; requests: number; folders: number; environments: number; skipped_operations: number; warnings: number };
}
export interface SpecPreview {
  detected: { kind: string; dialect: string; syntax: string; declared_version?: string | null; note?: string | null };
  title?: string | null;
  report: SpecImportReport;
  folders: number;
  requests: number;
  environments: number;
  sample: string[];
}
export interface SpecImported {
  workspace_id: string;
  root_folder_id?: string | null;
  import_id: string;
  requests: number;
  report: SpecImportReport;
}
export type SpecTarget = { kind: "new_workspace" } | { kind: "workspace"; workspace_id: string };

// ------------------------------------------------------------- runner/oauth
export type RunTarget = { kind: "scenario"; scenario_id: string } | { kind: "folder"; workspace_id: string; folder_id: string | null };
export interface RunInput {
  environment_id?: string | null;
  iterations?: number | null;
  stop_on_failure?: boolean | null;
  allow_untrusted?: boolean;
}
export interface TokenSummary {
  token_type: string;
  expires_at?: string | null;
  refresh_token_available: boolean;
}
export interface ApiAuthorization {
  profile_scope: string;
  grant: string;
  authorization_endpoint: string;
  token_endpoint: string;
  client_id: string;
  scope: string;
  token: TokenSummary;
}
export type FlowEvent =
  | { type: "listener_ready"; redirect_uri: string }
  | { type: "browser_opened"; authorization_url: string }
  | { type: "browser_open_failed"; authorization_url: string; error: string }
  | { type: "callback_ignored"; reason: string }
  | { type: "callback_accepted" }
  | { type: "exchanging_code" }
  | { type: "verifying_identity" }
  | { type: "completed" }
  | { type: "failed"; kind: string; message: string };
export interface ProviderInfo {
  id: string;
  display_name: string;
  availability: { status: "available" } | { status: "unavailable"; reason: string };
  native_flow: string;
  owner_actions: string[];
  needs_broker: boolean;
  test_only: boolean;
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
  changePassphrase: (newPassphrase: string) => call<void>("profile_change_passphrase", { newPassphrase }),
  convertToPassphrase: (newPassphrase: string) =>
    call<{ recovery_key: string; keychain_entry_removed: boolean }>("profile_convert_to_passphrase", { newPassphrase }),
  touch: () => call<void>("touch"),

  workspaces: () => call<Workspace[]>("workspaces_list"),
  createWorkspace: (name: string) => call<Workspace>("workspace_create", { name }),
  saveWorkspace: (workspace: Workspace) => call<Workspace>("workspace_save", { workspace }),
  deleteWorkspace: (workspaceId: string) => call<void>("workspace_delete", { workspaceId }),
  tree: (workspaceId: string) => call<TreeNode[]>("tree_get", { workspaceId }),
  createFolder: (workspaceId: string, parentId: string | null, name: string) => call<Folder>("folder_create", { workspaceId, parentId, name }),
  getFolder: (folderId: string) => call<Folder>("folder_get", { folderId }),
  saveFolder: (folder: Folder) => call<Folder>("folder_save", { folder }),
  /** Let an imported collection's root folder also resolve the workspace's scope (an explicit user choice). */
  setFolderWorkspaceScope: (folderId: string, allow: boolean) => call<Folder>("folder_set_workspace_scope", { folderId, allow }),
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
  /** A secret always belongs to a workspace: only that workspace's requests resolve it. */
  createSecret: (workspaceId: string, label: string, value: string) => call<SecretRef>("secret_create", { workspaceId, label, value }),
  generateDpopKey: (workspaceId: string, label: string) => call<{ secret: SecretRef; jkt: string }>("dpop_generate_key", { workspaceId, label }),

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
  workloadProbe: (endpoint: string, audience: string | null) => call<WorkloadProbe>("workload_probe", { endpoint, audience }),

  exportPreview: (workspaceId: string | null, exportMode: string) => call<ExportPreview>("export_preview", { workspaceId, exportMode }),
  /** Native open/save dialog for `purpose`; empty when the user cancels. */
  chooseFiles: (purpose: FilePurpose, options: FileDialogOptions = {}) => call<FileGrant[]>("file_choose", { purpose, options }),
  /** One file from the native open/save dialog for `purpose`; null when the user cancels. */
  chooseFile: async (purpose: FilePurpose, options: FileDialogOptions = {}): Promise<FileGrant | null> =>
    (await call<FileGrant[]>("file_choose", { purpose, options: { ...options, multiple: false } }))[0] ?? null,
  /** Bind, in the native open dialog, the linked local file a saved request or dataset names; null when the user cancels. */
  chooseLinkedFile: async (referrer: LinkedFileReferrer): Promise<FileGrant | null> =>
    (await call<FileGrant[]>("file_choose", { purpose: "linked_file", options: { multiple: false }, referrer }))[0] ?? null,
  /** JWT-SVID token files bound on this device, oldest first. */
  tokenFiles: () => call<TokenFileBinding[]>("token_files_list"),
  /** Stop reading a bound token file until it is chosen again. */
  removeTokenFile: (bindingId: string) => call<void>("token_file_remove", { bindingId }),
  exportToPath: (workspaceId: string | null, exportMode: string, passphrase: string | null, grant: string) =>
    call<number>("export_to_path", { workspaceId, exportMode, passphrase, grant }),
  importPreview: (grant: string, passphrase: string | null, conflictPolicy: string) => call<ImportReport>("import_preview", { grant, passphrase, conflictPolicy }),
  /**
   * `existingWorkspaces`: ids from the preview's `plan.existing_workspaces` the user confirmed writing into.
   * `bundleSha256`: the preview's `bundle_sha256`; the import is refused if the file changed since.
   */
  importApply: (
    grant: string,
    passphrase: string | null,
    conflictPolicy: string,
    existingWorkspaces: string[] = [],
    bundleSha256: string | null = null,
  ) =>
    call<ImportReport>("import_apply", {
      grant,
      passphrase,
      conflictPolicy,
      approval: { existing_workspaces: existingWorkspaces, bundle_sha256: bundleSha256 },
    }),
  attachmentAdd: (grant: string, mediaType: string | null) => call<AttachmentRef>("attachment_add", { grant, mediaType }),

  loadPlans: (workspaceId: string) => call<LoadPlan[]>("load_plans", { workspaceId }),
  saveLoadPlan: (plan: LoadPlan) => call<LoadPlan>("load_plan_save", { plan }),
  deleteLoadPlan: (planId: string) => call<void>("load_plan_delete", { planId }),
  loadPreflight: (planId: string) => call<LoadPreflight>("load_preflight", { planId }),
  loadPlanCheck: (plan: LoadPlan) => call<LoadPlanCheck>("load_plan_check", { plan }),
  loadRunStart: (planId: string, acknowledged: boolean) => call<string>("load_run_start", { planId, acknowledged }),
  loadRunCancel: (runKey: string) => call<boolean>("load_run_cancel", { runKey }),
  loadReports: (workspaceId: string) => call<LoadReportSummary[]>("load_reports", { workspaceId }),
  loadReport: (runId: string) => call<LoadReport>("load_report", { runId }),
  deleteLoadReport: (runId: string) => call<void>("load_report_delete", { runId }),
  exportLoadReport: (runId: string, format: "json" | "csv" | "timeline_csv" | "html", grant: string) => call<number>("load_report_export", { runId, format, grant }),
  compareLoadReports: (a: string, b: string) => call<LoadComparison>("load_compare", { a, b }),
  datasets: (workspaceId: string) => call<Dataset[]>("datasets_list", { workspaceId }),
  addDataset: (workspaceId: string, grant: string, name: string, sensitiveColumns: string[]) =>
    call<Dataset>("dataset_add", { workspaceId, grant, name, sensitiveColumns }),

  scenarios: (workspaceId: string) => call<Scenario[]>("scenarios_list", { workspaceId }),
  createScenario: (workspaceId: string, name: string, requestIds: string[]) => call<Scenario>("scenario_create", { workspaceId, name, requestIds }),
  saveScenario: (scenario: Scenario) => call<Scenario>("scenario_save", { scenario }),
  trustScenario: (scenarioId: string) => call<Scenario>("scenario_trust", { scenarioId }),
  deleteScenario: (scenarioId: string) => call<void>("scenario_delete", { scenarioId }),
  runStart: (target: RunTarget, input: RunInput) => call<string>("run_start", { target, input }),
  runCancel: (runId: string) => call<boolean>("run_cancel", { runId }),
  runReports: (workspaceId: string) => call<RunReport[]>("run_reports", { workspaceId }),
  runReport: (runId: string) => call<RunReport>("run_report", { runId }),
  deleteRunReport: (runId: string) => call<void>("run_report_delete", { runId }),
  exportRunReport: (runId: string, format: "json" | "junit" | "html", grant: string) => call<number>("run_report_export", { runId, format, grant }),

  oauthSignIn: (input: SendInput, attempt: string) => call<ApiAuthorization>("oauth_sign_in", { input, attempt }),
  oauthCancel: (attempt: string) => call<boolean>("oauth_cancel", { attempt }),
  oauthTokenStatus: (input: SendInput) => call<TokenSummary | null>("oauth_token_status", { input }),
  oauthSignOut: (input: SendInput) => call<boolean>("oauth_sign_out", { input }),
  loginProviders: () => call<ProviderInfo[]>("login_providers"),

  sessionOpen: (input: SendInput, executionId: string) => call<string>("session_open", { input, executionId }),
  sessionSend: (executionId: string, command: SessionCommand) => call<void>("session_send", { executionId, command }),
  sessionCancel: (executionId: string) => call<void>("session_cancel", { executionId }),

  specPreview: (input: SpecInput, options: ImportOptions) => call<SpecPreview>("spec_preview", { input, options }),
  specImport: (input: SpecInput, options: ImportOptions, target: SpecTarget) => call<SpecImported>("spec_import", { input, options, target }),
  readTextFile: (grant: string, workspaceId: string | null, storeAsSecret: string | null, base64 = false) =>
    call<{ text?: string | null; secret?: SecretRef | null }>("read_text_file", { grant, workspaceId, storeAsSecret, base64 }),
};

export function onExecutionEvent(cb: (e: ExecutionEvent) => void): Promise<UnlistenFn> {
  return listen<ExecutionEvent>("execution-event", (ev) => cb(ev.payload));
}

export function onLoadProgress(cb: (e: { run_key: string; progress: LoadProgress }) => void): Promise<UnlistenFn> {
  return listen<{ run_key: string; progress: LoadProgress }>("load-progress", (ev) => cb(ev.payload));
}

export function onLoadFinished(cb: (e: { run_key: string; run_id?: string | null; error?: string | null }) => void): Promise<UnlistenFn> {
  return listen<{ run_key: string; run_id?: string | null; error?: string | null }>("load-finished", (ev) => cb(ev.payload));
}

export function onSessionEnded(cb: (e: { execution_id: string; view?: ExecutionView | null; error?: string | null }) => void): Promise<UnlistenFn> {
  return listen<{ execution_id: string; view?: ExecutionView | null; error?: string | null }>("session-ended", (ev) => cb(ev.payload));
}

export function onRunEvent(cb: (e: RunEvent) => void): Promise<UnlistenFn> {
  return listen<RunEvent>("run-event", (ev) => cb(ev.payload));
}

export function onRunFinished(cb: (e: { run_id: string; error?: string | null }) => void): Promise<UnlistenFn> {
  return listen<{ run_id: string; error?: string | null }>("run-finished", (ev) => cb(ev.payload));
}

export function onOAuthFlow(cb: (e: { attempt: string; event: FlowEvent }) => void): Promise<UnlistenFn> {
  return listen<{ attempt: string; event: FlowEvent }>("oauth-flow", (ev) => cb(ev.payload));
}

export function onLocked(cb: (reason: string) => void): Promise<UnlistenFn> {
  return listen<string | null>("locked", (ev) => cb(ev.payload ?? "manual"));
}

export type { DiagnosticFinding as Finding };
