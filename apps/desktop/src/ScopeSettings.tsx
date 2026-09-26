// Auth, variables and settings for a folder or the whole workspace. Requests
// inherit these (request → folders → workspace → app defaults); the Effective
// request tab shows which layer each value came from.
import { useEffect, useState } from "react";
import { ask } from "@tauri-apps/plugin-dialog";
import { api } from "./api";
import type { AuthConfig, Folder, SettingsOverrides, Variable, Workspace } from "./generated/contracts";
import { AuthEditor } from "./AuthEditor";
import { VariablesEditor } from "./Dialogs";
import { SettingsOverridesEditor, type Profiles } from "./RequestEditor";
import { Modal, Tabs } from "./ui";

type Target = { kind: "folder"; id: string } | { kind: "workspace"; workspace: Workspace };
type Tab = "auth" | "variables" | "settings" | "about";

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
  const allowDeviceIdentity = async (w: Workspace) => {
    const ok = await ask(
      `Let requests in “${w.name}” use this device's workload identity (JWT-SVID or X.509-SVID)? Only do this if you trust what was imported or restored into it.`,
      { title: "Allow this device's workload identity", kind: "warning", okLabel: "Allow" },
    );
    if (!ok) return;
    setErr(null);
    try {
      await api.allowDeviceIdentity(w.id);
      setSealed(false);
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };
  const obj = props.target.kind === "folder" ? folder : ws;
  if (!obj) return null;
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
                A bundle import or backup restore wrote into this workspace, so its requests do not use this device's workload identity (JWT-SVID or X.509-SVID).
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
