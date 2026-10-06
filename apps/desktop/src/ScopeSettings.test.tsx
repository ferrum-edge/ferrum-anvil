// Renderer tests for the workspace settings' device-identity seal and an
// import root's workspace scope (jsdom; IPC mocked). A bundle import or
// backup restore seals a workspace from this device's workload identity; the
// dialog says so, and the backend lifts the seal only once the user confirms
// it in the backend's own native dialog. An imported collection's root
// folder is isolated from its workspace until the user confirms opening it
// there; isolating it again needs no confirmation. The renderer asks
// nothing itself: a declined confirmation comes back as NOT_CONFIRMED and
// changes nothing. Both are enforced by the backend (anvil-app and desktop
// presence tests).
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { Folder, Workspace } from "./generated/contracts";

const invoke = vi.fn();
const ask = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: (...a: unknown[]) => ask(...a), open: vi.fn(), save: vi.fn() }));

import { ScopeSettingsDialog } from "./ScopeSettings";

const now = "2026-01-01T00:00:00Z";
const ws = { id: "ws-1", name: "Imported", schema_version: 1, created_at: now, updated_at: now } as Workspace;
const BANNER = /A bundle import or backup restore wrote into this workspace/;

afterEach(() => {
  cleanup();
  invoke.mockReset();
  ask.mockReset();
});

// `confirmed` stands in for the user's answer in the backend's native dialog.
function backend(sealed: boolean, confirmed: () => boolean = () => true) {
  invoke.mockImplementation(async (cmd: string) => {
    switch (cmd) {
      case "workspace_device_identity_sealed":
        return sealed;
      case "workspace_allow_device_identity":
        if (!confirmed()) throw "NOT_CONFIRMED";
        sealed = false;
        return true;
      default:
        // Anything else the editors read stays pending: it is not under test.
        return new Promise(() => {});
    }
  });
}

function renderWorkspace() {
  const profiles = { tls: [], proxy: [], integrations: [] };
  render(<ScopeSettingsDialog target={{ kind: "workspace", workspace: ws }} workspaceId={ws.id} profiles={profiles} onClose={() => {}} onSaved={() => {}} />);
}

const calls = (cmd: string) => invoke.mock.calls.filter((c) => c[0] === cmd).map((c) => c[1] as Record<string, unknown>);

test("a sealed workspace says so and is allowed only once the user confirms in the backend's dialog", async () => {
  const answers = [false, true];
  backend(true, () => answers.shift() ?? false);
  renderWorkspace();
  await screen.findByText(BANNER);
  expect(calls("workspace_device_identity_sealed")).toEqual([{ workspaceId: ws.id }]);

  // Declining the backend's confirmation changes nothing and is no error.
  fireEvent.click(screen.getByRole("button", { name: "Allow on this device" }));
  await waitFor(() => expect(calls("workspace_allow_device_identity")).toHaveLength(1));
  expect(screen.getByText(BANNER)).toBeTruthy();
  expect(screen.queryByText(/not confirmed/)).toBeNull();

  fireEvent.click(screen.getByRole("button", { name: "Allow on this device" }));
  await waitFor(() => expect(screen.queryByText(BANNER)).toBeNull());
  expect(calls("workspace_allow_device_identity")).toEqual([{ workspaceId: ws.id }, { workspaceId: ws.id }]);
  // The renderer never asks, nor passes an answer of its own.
  expect(ask).not.toHaveBeenCalled();
});

test("a workspace that is not sealed shows no seal", async () => {
  backend(false);
  renderWorkspace();
  await waitFor(() => expect(calls("workspace_device_identity_sealed")).toEqual([{ workspaceId: ws.id }]));
  expect(screen.queryByText(BANNER)).toBeNull();
  expect(screen.queryByRole("button", { name: "Allow on this device" })).toBeNull();
});

test("workspace settings explain the cookie and destination policy", async () => {
  backend(false);
  renderWorkspace();
  fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
  const text = screen.getByRole("note", { name: "HTTP policy" }).textContent;
  expect(text).not.toMatch(/draft|approval pending|candidate/i);
  expect(text).toContain("docs/security/http-state-and-destination-policy.md");
  expect(text).toContain("180 cookies / 128 KiB");
  expect(text).toContain("3,000 cookies / 2 MiB");
  expect(text).toContain("including configured credentials even when the cookie jar is off");
  expect(text).toContain("Unknown suffixes use host-only cookies");
  expect(text).toContain("Intentional private originals keep working");
  expect(text).toContain("names that resolve across several such zones");
  expect(text).toContain("until one hop is public; after that, redirects stay public");
  expect(text).toContain("A fake-IP redirect must return to the original host");
  expect(text).toContain("including same-host redirects");
  expect(text).toContain("Explicit original proxied requests remain supported");
  expect(text).toContain("literal-loopback HTTP on a direct connection");
  expect(text).toContain("localhost and DNS overrides do not qualify");
});

// ------------------------------------------------------ import root scope

const root = {
  id: "f-root",
  name: "Petstore",
  schema_version: 1,
  created_at: now,
  updated_at: now,
  workspace_id: ws.id,
  sort_key: 1,
  import_root: true,
  import_environment_ids: ["env-1"],
} as Folder;
const ISOLATED = /Isolated from the workspace/;
const OPENED = /Opened to the workspace on this device/;
const OPEN_BUTTON = { name: /Open to workspace/ };
const ISOLATE_BUTTON = { name: "Isolate again" };

// `scope` answers folder_set_workspace_scope: the stored folder, or an error
// the backend reports (as the IPC does, a string).
function folderBackend(folder: Folder, scope?: (allow: boolean) => Promise<Folder>) {
  let stored = { ...folder };
  invoke.mockImplementation(async (cmd: string, args?: Record<string, unknown>) => {
    switch (cmd) {
      case "folder_get":
        return stored;
      case "folder_set_workspace_scope": {
        const allow = args?.allow as boolean;
        if (scope) return scope(allow);
        stored = { ...stored, use_workspace_scope: allow };
        return stored;
      }
      case "folder_save":
        return args?.folder;
      default:
        return new Promise(() => {});
    }
  });
}

function renderFolder(id = root.id) {
  const profiles = { tls: [], proxy: [], integrations: [] };
  const onSaved = vi.fn();
  render(<ScopeSettingsDialog target={{ kind: "folder", id }} workspaceId={ws.id} profiles={profiles} onClose={() => {}} onSaved={onSaved} />);
  return onSaved;
}

async function openScopeTab() {
  fireEvent.click(await screen.findByRole("tab", { name: "Workspace scope" }));
}

test("folder settings show the same inherited HTTP policy without adding a bypass", async () => {
  folderBackend(root);
  renderFolder();
  fireEvent.click(await screen.findByRole("tab", { name: "Settings" }));
  expect(screen.getByRole("note", { name: "HTTP policy" }).textContent).toContain(
    "These limits also apply to inherited settings",
  );
  expect(screen.queryByRole("checkbox", { name: /bypass.*policy/i })).toBeNull();
  expect(calls("folder_set_workspace_scope")).toEqual([]);
});

test("an ordinary folder has no workspace scope control", async () => {
  const folder = { ...root, id: "f-plain", name: "Plain", import_root: false, import_environment_ids: undefined } as Folder;
  folderBackend(folder);
  renderFolder(folder.id);
  await screen.findByRole("tab", { name: "Auth" });
  expect(screen.queryByRole("tab", { name: "Workspace scope" })).toBeNull();
  expect(screen.queryByRole("button", OPEN_BUTTON)).toBeNull();
  expect(calls("folder_set_workspace_scope")).toEqual([]);
});

test("an import root is isolated by default and opens only once the user confirms in the backend's dialog", async () => {
  const answers = [false];
  let stored = { ...root };
  folderBackend(root, async (allow) => {
    // The backend's native dialog, declined first.
    if (allow && answers.length > 0 && !answers.shift()) throw "NOT_CONFIRMED";
    stored = { ...stored, use_workspace_scope: allow };
    return stored;
  });
  renderFolder();
  await openScopeTab();
  expect(screen.getByText(ISOLATED)).toBeTruthy();
  expect(screen.getByText("Not used while isolated")).toBeTruthy();
  expect(screen.getByText(/environments the import brought \(1\)/)).toBeTruthy();

  // Declining the backend's confirmation changes nothing and is no error.
  fireEvent.click(screen.getByRole("button", OPEN_BUTTON));
  await waitFor(() => expect(calls("folder_set_workspace_scope")).toHaveLength(1));
  await waitFor(() => expect((screen.getByRole("button", OPEN_BUTTON) as HTMLButtonElement).disabled).toBe(false));
  expect(screen.getByText(ISOLATED)).toBeTruthy();
  expect(screen.queryByText(/not confirmed/)).toBeNull();

  fireEvent.click(screen.getByRole("button", OPEN_BUTTON));
  await screen.findByText(OPENED);
  expect(calls("folder_set_workspace_scope")).toEqual([
    { folderId: root.id, allow: true },
    { folderId: root.id, allow: true },
  ]);
  expect(screen.getByText("Also used, because it is opened")).toBeTruthy();
  expect(screen.getByRole("button", ISOLATE_BUTTON)).toBeTruthy();
  // The renderer never asks, nor passes an answer of its own.
  expect(ask).not.toHaveBeenCalled();
});

test("an opened import root is isolated again without a confirmation", async () => {
  folderBackend({ ...root, use_workspace_scope: true });
  renderFolder();
  await openScopeTab();
  expect(screen.getByText(OPENED)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", ISOLATE_BUTTON));
  await screen.findByText(ISOLATED);
  expect(ask).not.toHaveBeenCalled();
  expect(calls("folder_set_workspace_scope")).toEqual([{ folderId: root.id, allow: false }]);
});

test("a click while the change is pending is ignored", async () => {
  let resolve: (f: Folder) => void = () => {};
  folderBackend({ ...root, use_workspace_scope: true }, () => new Promise<Folder>((r) => (resolve = r)));
  renderFolder();
  await openScopeTab();
  const button = screen.getByRole("button", ISOLATE_BUTTON) as HTMLButtonElement;
  fireEvent.click(button);
  await waitFor(() => expect(button.disabled).toBe(true));
  fireEvent.click(button);
  expect(calls("folder_set_workspace_scope")).toHaveLength(1);
  resolve({ ...root, use_workspace_scope: false });
  await screen.findByText(ISOLATED);
});

test("a refused change is shown and leaves the scope as it was", async () => {
  folderBackend(root, () => Promise.reject("invalid: only the root folder of an imported collection has a scope of its own"));
  renderFolder();
  await openScopeTab();
  fireEvent.click(screen.getByRole("button", OPEN_BUTTON));
  await screen.findByText(/only the root folder of an imported collection/);
  expect(screen.getByText(ISOLATED)).toBeTruthy();
  expect(screen.queryByText(OPENED)).toBeNull();
  expect((screen.getByRole("button", OPEN_BUTTON) as HTMLButtonElement).disabled).toBe(false);
});

test("a locked profile says so and leaves the scope as it was", async () => {
  const onLocked = vi.fn();
  window.addEventListener("anvil-locked", onLocked);
  try {
    folderBackend({ ...root, use_workspace_scope: true }, () => Promise.reject("LOCKED"));
    renderFolder();
    await openScopeTab();
    fireEvent.click(screen.getByRole("button", ISOLATE_BUTTON));
    await screen.findByText("The profile is locked. Unlock it and try again.");
    expect(onLocked).toHaveBeenCalledTimes(1);
    expect(screen.getByText(OPENED)).toBeTruthy();
    expect(screen.queryByText("LOCKED")).toBeNull();
  } finally {
    window.removeEventListener("anvil-locked", onLocked);
  }
});

test("changing the scope keeps unsaved edits in the other tabs", async () => {
  folderBackend(root);
  renderFolder();
  fireEvent.click(await screen.findByRole("tab", { name: "Name & description" }));
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Petstore v2" } });
  await openScopeTab();
  fireEvent.click(screen.getByRole("button", OPEN_BUTTON));
  await screen.findByText(OPENED);
  expect(screen.getByRole("dialog", { name: "Folder settings — Petstore v2" })).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(calls("folder_save")).toHaveLength(1));
  expect(calls("folder_save")[0].folder).toMatchObject({ id: root.id, name: "Petstore v2", use_workspace_scope: true });
});
