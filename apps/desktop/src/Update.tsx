// Update check and upgrade. The backend decides whether the launch check runs
// (the opt-in setting, once per launch) and whether this build can install an
// update itself (it needs the updater key to verify one); otherwise Upgrade
// opens the release page.
import { useEffect, useState, useSyncExternalStore } from "react";
import { api, onUpdateProgress, type UpdateCheck } from "./api";
import { Icon } from "./icons";
import { Modal, fmtBytes } from "./ui";

// Versions put off with "Later" in this launch: a lock and unlock does not
// prompt again (the status bar still offers them).
const later = new Set<string>();

type Phase = { step: "idle" } | { step: "downloading"; downloaded: number; total?: number | null } | { step: "installed" } | { step: "failed"; error: string };

// The install outlives the dialog that started it: closing and reopening it
// (or opening Settings) shows the same progress, and "Restart now" once done.
let installing: { version: string; phase: Phase } | null = null;
const subscribers = new Set<() => void>();
const setInstall = (next: typeof installing) => {
  installing = next;
  subscribers.forEach((f) => f());
};
const subscribe = (f: () => void) => {
  subscribers.add(f);
  return () => void subscribers.delete(f);
};

/** Tests only: forget "Later" and any install. */
export function resetUpdateState() {
  later.clear();
  setInstall(null);
}

/** The update the launch check found, if the setting is on. Failures stay silent: the user did not ask for this check. */
export function useLaunchUpdate(): UpdateCheck | null {
  const [check, setCheck] = useState<UpdateCheck | null>(null);
  useEffect(() => {
    let live = true;
    api
      .updateCheckOnLaunch()
      .then((c) => live && setCheck(c ?? null))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, []);
  return check;
}

/** Shown once per launch when a newer release exists. */
export function UpdatePrompt(props: { check: UpdateCheck | null; onUpgrade: () => void }) {
  const u = props.check?.update;
  const [, rerender] = useState(0);
  if (!u || later.has(u.version)) return null;
  const putOff = () => {
    later.add(u.version);
    rerender((n) => n + 1);
  };
  return (
    <div className="update-prompt" role="alertdialog" aria-label="Update available">
      <Icon name="download" />
      <div className="grow">
        <b>Ferrum Anvil {u.version} is available.</b> You have {props.check!.current}.
        <div className="row">
          <button
            className="btn primary small"
            onClick={() => {
              putOff();
              props.onUpgrade();
            }}
          >
            Upgrade…
          </button>
          <button className="btn small" onClick={putOff}>
            Later
          </button>
        </div>
      </div>
    </div>
  );
}

export function UpdateDialog(props: { check: UpdateCheck; onClose: () => void }) {
  return (
    <Modal title="Update Ferrum Anvil" onClose={props.onClose}>
      <UpdatePanel check={props.check} />
    </Modal>
  );
}

/** What the update brings and how to get it: installed in the app, or downloaded from the release page. */
export function UpdatePanel(props: { check: UpdateCheck }) {
  const { check } = props;
  const u = check.update;
  const current = useSyncExternalStore(subscribe, () => installing);
  const [openErr, setOpenErr] = useState<string | null>(null);
  if (!u) return null;
  const phase: Phase = current?.version === u.version ? current.phase : { step: "idle" };
  const setPhase = (p: Phase) => setInstall({ version: u.version, phase: p });
  const openPage = () => {
    setOpenErr(null);
    api.updateOpenReleasePage(u.version).catch((e: unknown) => setOpenErr((e as Error).message));
  };
  const install = async () => {
    setPhase({ step: "downloading", downloaded: 0 });
    const un = await onUpdateProgress((p) => setPhase({ step: "downloading", downloaded: p.downloaded, total: p.total }));
    try {
      await api.updateInstall(u.version);
      setPhase({ step: "installed" });
    } catch (e) {
      setPhase({ step: "failed", error: (e as Error).message });
    } finally {
      un();
    }
  };
  const published = u.published_at ? new Date(u.published_at) : null;
  return (
    <div className="update-panel">
      <p>
        <b>{u.name}</b>
        {published && !Number.isNaN(published.getTime()) && <> · released {published.toLocaleDateString()}</>}
        <br />
        <span className="hint">
          Version {u.version} is available. You have {check.current}.
        </span>
      </p>
      {u.notes && (
        <pre className="release-notes" aria-label="Release notes">
          {u.notes}
        </pre>
      )}
      {check.install === "in_app" ? (
        <>
          {phase.step === "idle" && (
            <>
              <p className="hint">
                Anvil downloads the update, verifies its signature and installs it.{" "}
                {check.install_quits
                  ? "Anvil closes while the installer runs and reopens when it is done."
                  : "The new version starts when you restart Anvil."}{" "}
                Unsaved request edits and running load tests or collection runs are lost when Anvil closes. Your profiles and their data are kept.
              </p>
              <div className="row">
                <button className="btn primary" onClick={() => void install()}>
                  <Icon name="download" size={14} />
                  Download and install
                </button>
                <button className="btn" onClick={openPage}>
                  Release page
                </button>
              </div>
            </>
          )}
          {phase.step === "downloading" && (
            <div className="update-progress" role="status">
              <progress max={phase.total ?? undefined} value={phase.total ? phase.downloaded : undefined} aria-label="Download progress" />
              <span className="hint">
                {phase.total && phase.downloaded >= phase.total
                  ? "Verifying and installing…"
                  : `Downloading… ${fmtBytes(phase.downloaded)}${phase.total ? ` of ${fmtBytes(phase.total)}` : ""}`}
              </span>
            </div>
          )}
          {phase.step === "installed" && (
            <div className="ok-box" role="status">
              Ferrum Anvil {u.version} is installed. Restart to use it.
              <div className="row">
                <button className="btn primary small" onClick={() => void api.updateRestart()}>
                  Restart now
                </button>
              </div>
            </div>
          )}
          {phase.step === "failed" && (
            <div className="bad-box" role="alert">
              {phase.error} Nothing was changed.
              <div className="row">
                <button className="btn small" onClick={() => void install()}>
                  Try again
                </button>
                <button className="btn small" onClick={openPage}>
                  Open release page
                </button>
              </div>
            </div>
          )}
        </>
      ) : (
        <>
          <p className="hint">
            This build cannot install updates itself: it has no key to verify their signature. Download version {u.version} from its release page and install it over
            this one. Your profiles and their data are kept.
          </p>
          <div className="row">
            <button className="btn primary" onClick={openPage}>
              <Icon name="globe" size={14} />
              Open release page
            </button>
          </div>
        </>
      )}
      {openErr && <div className="bad-box">{openErr}</div>}
    </div>
  );
}

/** Settings → Updates: the opt-in launch check and a check on demand. */
export function UpdateSettings(props: { enabled: boolean; onChange: (enabled: boolean) => void }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<UpdateCheck | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const checkNow = async () => {
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      setResult(await api.updateCheck());
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="settings-section">
      <h3>Updates</h3>
      <label className="check">
        <input type="checkbox" checked={props.enabled} onChange={(e) => props.onChange(e.target.checked)} />
        Check for updates when Anvil opens
      </label>
      <p className="hint">
        Asks GitHub (api.github.com) for the latest Ferrum Anvil release, once per launch, and offers to upgrade when it is newer. The request carries Anvil's version
        and nothing from your profiles. Off unless you turn it on.
      </p>
      <div className="row">
        <button className="btn small" disabled={busy} onClick={() => void checkNow()}>
          {busy ? "Checking…" : "Check now"}
        </button>
        {result && !result.update && (
          <span className="hint" role="status">
            Ferrum Anvil {result.current} is up to date.
          </span>
        )}
      </div>
      {result?.update && <UpdatePanel check={result} />}
      {err && (
        <div className="bad-box" role="alert">
          {err}
        </div>
      )}
    </section>
  );
}
