// A linked local file that a saved request (its body or gRPC schema) or a
// dataset names, with whether it was chosen on this device and the native
// dialog that chooses it. The backend binds a file only if that request or
// dataset names that exact path; an imported path alone never lets Anvil read
// it, and nothing here reads the file.
import { useEffect, useState } from "react";
import { api, type LinkedFileReferrer, type LinkedFileState, type LinkedFileStatus } from "./api";
import { Icon } from "./icons";

const BADGE: Record<LinkedFileState, { cls: string; icon: "checkCircle" | "alertTriangle" | "alertCircle"; label: string }> = {
  bound: { cls: "ok", icon: "checkCircle", label: "Chosen on this device" },
  unbound: { cls: "warn", icon: "alertTriangle", label: "Not chosen on this device" },
  invalid: { cls: "bad", icon: "alertCircle", label: "Missing or changed" },
};

/**
 * The linked file at `path`, its binding status for `referrer`, and Choose file… (not chosen yet)
 * or Rebind… (chosen before). `referrer` is null while the request is not saved: only a saved
 * request or dataset can have a file chosen for it.
 */
export function LinkedFileBinding({ referrer, path, className }: { referrer: LinkedFileReferrer | null; path: string; className?: string }) {
  const [status, setStatus] = useState<LinkedFileStatus | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Bumped after a file is chosen, to reload the status.
  const [version, setVersion] = useState(0);
  const key = referrer ? `${referrer.kind}:${referrer.id}` : null;
  useEffect(() => {
    if (!referrer) return;
    let alive = true;
    api
      .linkedFileStatus(referrer)
      .then((all) => {
        if (!alive) return;
        setStatus((all ?? []).find((s) => s.path === path) ?? null);
        setLoaded(true);
      })
      .catch((e) => alive && setErr(String((e as Error).message)));
    return () => {
      alive = false;
    };
  }, [key, path, version]);

  const choose = async () => {
    if (!referrer) return;
    setBusy(true);
    try {
      // Null when the dialog is cancelled: nothing was bound, so nothing changes.
      if (!(await api.chooseLinkedFile(referrer))) return;
      setErr(null);
      setVersion((v) => v + 1);
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
        <span className={`badge ${badge.cls}`} data-testid="linked-file-state">
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
      {!referrer && <p className="hint">Save the request to choose this linked file on this device.</p>}
      {referrer && loaded && !status && <p className="hint">The saved {noun} does not name this file; save it to check this file.</p>}
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
    </div>
  );
}
