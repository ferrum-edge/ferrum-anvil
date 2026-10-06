// Auth, variables and settings for a folder or the whole workspace. Requests
// inherit these (request → folders → workspace → app defaults); the Effective
// request tab shows which layer each value came from.
import { useEffect, useState } from "react";
import { api, ApiError } from "./api";
import type { AuthConfig, Folder, SettingsOverrides, Variable, Workspace } from "./generated/contracts";
import { AuthEditor } from "./AuthEditor";
import { VariablesEditor } from "./Dialogs";
import { SettingsOverridesEditor, type Profiles } from "./RequestEditor";
import { Modal, Tabs } from "./ui";

type Target = { kind: "folder"; id: string } | { kind: "workspace"; workspace: Workspace };
type Tab = "auth" | "variables" | "settings" | "scope" | "about";

export function ScopeSettingsDialog(props: { target: Target; workspaceId: string; profiles: Profiles; onClose: () => void; onSaved: (w?: Workspace) => void }) {
  const [folder, setFolder] = useState<Folder | null>(null);
  const [ws, setWs] = useState<Workspace | null>(props.target.kind === "workspace" ? props.target.workspace : null);
  const [tab, setTab] = useState<Tab>("auth");
  const [err, setErr] = useState<string | null>(null);
  // Set by a bundle import or backup restore on this device; only the user lifts it.
  const [sealed, setSealed] = useState(false);
  useEffect(() => {
    if (props.target.kind === "folder") api.getFolder(props.target.id).then(setFolder);
    else api.deviceIdentitySealed(props.target.workspace.id).then(setSealed, () => setSealed(false));
  }, []);
  // The backend asks the user in its own native dialog before it lifts the
  // seal; declining there leaves the workspace sealed.
  const allowDeviceIdentity = async (w: Workspace) => {
    setErr(null);
    try {
      await api.allowDeviceIdentity(w.id);
      setSealed(false);
    } catch (e) {
      if (!(e instanceof ApiError && e.notConfirmed)) setErr(String((e as Error).message));
    }
  };
  // Opening an import root to its workspace is a device-local choice made
  // only here (or by `folder_set_workspace_scope`), and confirmed in the
  // backend's own native dialog; saving the folder keeps the stored value
  // whatever this dialog holds.
  const [scopeBusy, setScopeBusy] = useState(false);
  const [scopeErr, setScopeErr] = useState<string | null>(null);
  const setWorkspaceScope = async (f: Folder, allow: boolean) => {
    if (scopeBusy) return;
    setScopeBusy(true);
    setScopeErr(null);
    try {
      const saved = await api.setFolderWorkspaceScope(f.id, allow);
      // Keep unsaved edits in the other tabs; only the scope flag changed.
      setFolder((cur) => (cur ? { ...cur, use_workspace_scope: saved.use_workspace_scope ?? false } : cur));
    } catch (e) {
      if (e instanceof ApiError && e.notConfirmed) return;
      setScopeErr(e instanceof ApiError && e.locked ? "The profile is locked. Unlock it and try again." : String((e as Error).message));
    } finally {
      setScopeBusy(false);
    }
  };
  const obj = props.target.kind === "folder" ? folder : ws;
  if (!obj) return null;
  const importRoot = props.target.kind === "folder" && folder?.import_root === true ? folder : null;
  const auth = (obj.auth as AuthConfig | undefined) ?? { type: "inherit" };
  const vars: Variable[] = obj.variables ?? [];
  const settings: SettingsOverrides = obj.settings ?? {};
  const patch = (p: Partial<Folder & Workspace>) => (props.target.kind === "folder" ? setFolder({ ...(folder as Folder), ...p }) : setWs({ ...(ws as Workspace), ...p }));
  return (
    <Modal
      title={props.target.kind === "folder" ? `Folder settings — ${obj.name}` : `Workspace settings — ${obj.name}`}
      wide
      onClose={props.onClose}
      footer={
        <>
          <button className="btn" onClick={props.onClose}>
            Cancel
          </button>
          <button
            className="btn primary"
            onClick={async () => {
              setErr(null);
              try {
                if (props.target.kind === "folder" && folder) {
                  await api.saveFolder(folder);
                  props.onSaved();
                } else if (ws) {
                  props.onSaved(await api.saveWorkspace(ws));
                }
                props.onClose();
              } catch (e) {
                setErr(String((e as Error).message));
              }
            }}
          >
            Save
          </button>
        </>
      }
    >
      <Tabs
        tabs={[
          { id: "auth" as Tab, label: "Auth" },
          { id: "variables" as Tab, label: "Variables", count: vars.length || undefined },
          { id: "settings" as Tab, label: "Settings" },
          ...(importRoot ? [{ id: "scope" as Tab, label: "Workspace scope" }] : []),
          { id: "about" as Tab, label: "Name & description" },
        ]}
        value={tab}
        onChange={setTab}
      />
      {tab === "auth" && (
        <>
          <p className="hint">Requests set to “Inherit” use the nearest folder's auth, then the workspace's.</p>
          {sealed && ws && (
            <div className="warn-box row" role="note">
              <span className="grow">
                A bundle import or backup restore wrote into this workspace, so its requests do not use this device's workload identity (JWT-SVID or X.509-SVID), and its gateway profiles' diagnostic reference lookups are paused.
              </span>
              <button className="btn small" onClick={() => void allowDeviceIdentity(ws)}>
                Allow on this device
              </button>
            </div>
          )}
          <AuthEditor value={auth} onChange={(a) => patch({ auth: a })} workspaceId={props.workspaceId} allowInherit={props.target.kind === "folder"} />
        </>
      )}
      {tab === "variables" && (
        <>
          <p className="hint">
            {props.target.kind === "folder"
              ? "Folder variables override the environment and workspace for requests in this folder."
              : "Workspace base variables apply everywhere; the active environment overrides them."}
          </p>
          <VariablesEditor vars={vars} onChange={(v) => patch({ variables: v })} workspaceId={props.workspaceId} />
        </>
      )}
      {tab === "settings" && <SettingsOverridesEditor value={settings} onChange={(s) => patch({ settings: s })} profiles={props.profiles} />}
      {tab === "scope" && importRoot && <ImportRootScope folder={importRoot} busy={scopeBusy} error={scopeErr} onSet={(allow) => void setWorkspaceScope(importRoot, allow)} />}
      {tab === "about" && (
        <div className="form">
          <label className="lbl">
            Name
            <input className="field" value={obj.name} onChange={(e) => patch({ name: e.target.value })} />
          </label>
          <label className="lbl">
            Description
            <textarea className="field" rows={4} value={obj.description ?? ""} onChange={(e) => patch({ description: e.target.value })} />
          </label>
        </div>
      )}
      {err && <div className="bad-box">{err}</div>}
    </Modal>
  );
}

// What an imported collection's root folder resolves, sealed (the default)
// or opened to its workspace on this device (`Folder::use_workspace_scope`).
function ImportRootScope(props: { folder: Folder; busy: boolean; error: string | null; onSet: (allow: boolean) => void }) {
  const open = props.folder.use_workspace_scope === true;
  const envs = props.folder.import_environment_ids?.length ?? 0;
  return (
    <div className="form">
      <p className="hint">
        This folder is the root of an imported collection. Its requests resolve only the collection's own scope unless you open it to the workspace on this device. The choice applies to this
        device only and an import never carries it: this collection imported anywhere else starts isolated.
      </p>
      {open ? (
        <div className="warn-box row" role="status">
          <span className="grow">Opened to the workspace on this device. Requests in this collection resolve the workspace's scope like any other folder.</span>
          <button className="btn small" disabled={props.busy} onClick={() => props.onSet(false)}>
            Isolate again
          </button>
        </div>
      ) : (
        <div className="info-box row" role="status">
          <span className="grow">Isolated from the workspace (the default for imported collections).</span>
          <button className="btn small" disabled={props.busy} onClick={() => props.onSet(true)}>
            Open to workspace…
          </button>
        </div>
      )}
      <div>
        <strong>Always used</strong>
        <ul className="hint">
          <li>variables and auth of this folder, the folders under it and each request;</li>
          <li>environments the import brought ({envs === 0 ? "none" : envs}), when one is selected;</li>
          <li>values extracted in a run by requests in this collection.</li>
        </ul>
      </div>
      <div>
        <strong>{open ? "Also used, because it is opened" : "Not used while isolated"}</strong>
        <ul className="hint">
          <li>the workspace's variables and auth, the active environment, and folders above this one;</li>
          <li>values extracted by requests outside this collection, and the dataset rows of a run or load test;</li>
          <li>this device's workload identity (JWT-SVID or X.509-SVID) and TLS client identities not bound to hosts.</li>
        </ul>
      </div>
      {!open && (
        <p className="hint">
          So a <code>{"{{token}}"}</code> defined only by the workspace or its environment stays unresolved here and the request is not sent. Define it in this folder, or open the
          collection to the workspace if you trust it.
        </p>
      )}
      {props.error && <div className="bad-box">{props.error}</div>}
    </div>
  );
}
