// A linked local file that a saved request (its body or gRPC schema) or a
// dataset names, with whether it was chosen on this device and the native
// dialog that chooses it. The backend binds a file only if that request or
// dataset names that exact path; an imported path alone never lets Anvil read
// it, and nothing here reads the file.
import { useEffect, useState } from "react";
import { api, type LinkedFileReferrer, type LinkedFileState, type LinkedFileStatus } from "./api";
import { Icon } from "./icons";

const BADGE: Record<LinkedFileState, { cls: string; icon: "checkCircle" | "alertTriangle" | "alertCircle"; label: string; title?: string }> = {
  bound: {
    cls: "ok",
    icon: "checkCircle",
    label: "Chosen on this device",
    title: "Chosen here, and still a regular file at this path. Its size is checked when it is read.",
  },
  unbound: { cls: "warn", icon: "alertTriangle", label: "Not chosen on this device" },
  invalid: { cls: "bad", icon: "alertCircle", label: "Missing or changed" },
};

// Reloads every linked file shown for a request or dataset once a file is chosen for it: the
// dialog opened beside one file may bind another one the same request names.
const reloaders = new Map<string, Set<() => void>>();

function onChosen(key: string, reload: () => void): () => void {
  const set = reloaders.get(key) ?? new Set<() => void>();
  reloaders.set(key, set);
  set.add(reload);
  return () => {
    set.delete(reload);
    if (set.size === 0) reloaders.delete(key);
  };
}

function chosen(key: string) {
  for (const reload of reloaders.get(key) ?? []) reload();
}

/**
 * The linked file at `path`, its binding status for `referrer`, and Choose file… (not chosen yet)
 * or Rebind… (chosen before). `referrer` is null only for a request that is not saved: only a saved
 * request or dataset that names the file can have it chosen.
 */
export function LinkedFileBinding({ referrer, path, className }: { referrer: LinkedFileReferrer | null; path: string; className?: string }) {
  const key = referrer ? `${referrer.kind}:${referrer.id}` : null;
  // Each result is kept with the request or dataset and path it is for, so a different one never
  // shows the previous one's status or error while its own loads.
  const shown = `${key}|${path}`;
  const [result, setResult] = useState<{ for: string; status: LinkedFileStatus | null } | null>(null);
  const [failure, setFailure] = useState<{ for: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  // Bumped to reload the status: after a file is chosen for this referrer, or on Retry.
  const [version, setVersion] = useState(0);
  const loaded = result?.for === shown;
  const status = result && result.for === shown ? result.status : null;
  const err = failure?.for === shown ? failure.message : null;
  const setErr = (message: string | null) => setFailure(message === null ? null : { for: shown, message });

  useEffect(() => {
    if (!key) return;
    return onChosen(key, () => setVersion((v) => v + 1));
  }, [key]);

  useEffect(() => {
    if (!referrer) return;
    let alive = true;
    api
      .linkedFileStatus(referrer)
      .then((all) => {
        if (!alive) return;
        setResult({ for: shown, status: (all ?? []).find((s) => s.path === path) ?? null });
        setFailure(null);
      })
      .catch((e) => alive && setFailure({ for: shown, message: String((e as Error).message) }));
    return () => {
      alive = false;
    };
  }, [key, path, version]);

  const retry = () => {
    setErr(null);
    setVersion((v) => v + 1);
  };

  const choose = async () => {
    if (!referrer || !key) return;
    setBusy(true);
    try {
      // Null when the dialog is cancelled: nothing was bound, so nothing changes.
      if (!(await api.chooseLinkedFile(referrer))) return;
      setErr(null);
      chosen(key);
    } catch (e) {
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  const noun = referrer?.kind ?? "request";
  const badge = status ? BADGE[status.state] : null;
  return (
    <div className={`linked-file${className ? ` ${className}` : ""}`} data-testid="linked-file">
      <span className="file-chip" title={path}>
        <Icon name="file" size={14} />
        <span className="mono">{path}</span>
      </span>
      {badge && (
        <span className={`badge ${badge.cls}`} data-testid="linked-file-state" title={badge.title}>
          <Icon name={badge.icon} size={12} />
          {badge.label}
        </span>
      )}
      {status && (
        <button className="btn small" disabled={busy} title={`Choose ${path} in the native dialog for this ${noun}`} onClick={() => void choose()}>
          <Icon name="file" size={13} />
          {status.state === "unbound" ? "Choose file…" : "Rebind…"}
        </button>
      )}
      {!referrer && <p className="hint">A linked file can be chosen only for a saved request that names it. Attach a copy instead.</p>}
      {referrer && loaded && !status && (
        <p className="hint">The saved {noun} does not name this file, so it cannot be chosen for it on this device. Attach a copy instead.</p>
      )}
      {status?.state === "unbound" && (
        <p className="hint">
          Anvil reads this file only once you choose it here, on this device, for this {noun}. Choose the file at this path, or attach a copy
          instead.
        </p>
      )}
      {status?.state === "invalid" && (
        <p className="hint">
          Chosen before, but {status.problem ?? "the file can no longer be read"}. Anvil reads it only at this path: put it back there and
          choose it again with Rebind…, or attach a copy instead.
        </p>
      )}
      {err && (
        <div className="bad-box" role="alert">
          {err}
        </div>
      )}
      {referrer && err && !loaded && (
        <button className="btn small" onClick={retry}>
          Retry
        </button>
      )}
    </div>
  );
}
