// Profile selection, creation and unlock. Unlocking happens in Rust; this
// screen never holds the data key.
import { useEffect, useState } from "react";
import { api, type ProfileSummary } from "./api";

export function LockScreen(props: { onUnlocked: () => void; reason?: string | null }) {
  const [profiles, setProfiles] = useState<ProfileSummary[] | null>(null);
  const [mode, setMode] = useState<"unlock" | "create" | "recovery">("unlock");
  const [selected, setSelected] = useState<string>("");
  const [secret, setSecret] = useState("");
  const [name, setName] = useState("");
  const [pass2, setPass2] = useState("");
  const [useKeychain, setUseKeychain] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recovery, setRecovery] = useState<string | null>(null);

  useEffect(() => {
    api.profiles().then((p) => {
      setProfiles(p);
      if (p.length === 0) setMode("create");
      else setSelected(p[0].profile_id);
    });
  }, []);

  const current = profiles?.find((p) => p.profile_id === selected);

  async function unlock() {
    setBusy(true);
    setError(null);
    try {
      if (current?.protection === "os_keychain") await api.unlock(selected, null, null);
      else if (mode === "recovery") await api.unlock(selected, null, secret);
      else await api.unlock(selected, secret, null);
      setSecret("");
      props.onUnlocked();
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  async function create() {
    setError(null);
    if (!name.trim()) return setError("Choose a profile name.");
    if (!useKeychain) {
      if (secret.length < 8) return setError("The passphrase needs at least 8 characters.");
      if (secret !== pass2) return setError("The passphrases do not match.");
    }
    setBusy(true);
    try {
      const r = await api.createProfile(name.trim(), useKeychain ? null : secret, useKeychain);
      setSecret("");
      setPass2("");
      if (r.recovery_key) setRecovery(r.recovery_key);
      else props.onUnlocked();
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  if (recovery) {
    return (
      <div className="lock">
        <div className="lock-card">
          <h1>Save your recovery key</h1>
          <p className="muted">
            This key is the only way to open this profile if you forget the passphrase. It is shown once and is not stored anywhere. Keep it offline.
          </p>
          <div className="recovery" aria-label="Recovery key">
            {recovery}
          </div>
          <button className="btn primary" onClick={() => { setRecovery(null); props.onUnlocked(); }}>
            I stored it safely — continue
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="lock">
      <form
        className="lock-card"
        onSubmit={(e) => {
          e.preventDefault();
          void (mode === "create" ? create() : unlock());
        }}
      >
        <div className="row">
          <div className="brand-mark" aria-hidden>
            ⚒
          </div>
          <h1>Ferrum Anvil</h1>
        </div>
        <div className="tagline">Put your APIs to the test.</div>
        {props.reason && <div className="warn-box">Locked ({props.reason === "idle" ? "inactivity" : props.reason === "suspend" ? "the system went to sleep" : "manually"}). Active runs were stopped.</div>}

        {mode !== "create" && profiles && profiles.length > 0 && (
          <>
            <label className="lbl">
              Profile
              <select className="field" value={selected} onChange={(e) => setSelected(e.target.value)}>
                {profiles.map((p) => (
                  <option key={p.profile_id} value={p.profile_id}>
                    {p.display_name} — {p.protection === "os_keychain" ? "OS keychain" : "passphrase"}
                  </option>
                ))}
              </select>
            </label>
            {current?.protection === "os_keychain" ? (
              <p className="hint">This profile's data key is held by the operating system's credential store. Anyone using your unlocked OS session can open it.</p>
            ) : (
              <label className="lbl">
                {mode === "recovery" ? "Recovery key" : "Passphrase"}
                <input className="field" type={mode === "recovery" ? "text" : "password"} autoFocus value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="current-password" />
              </label>
            )}
            {error && <div className="bad-box" role="alert">{error}</div>}
            <button className="btn primary" type="submit" disabled={busy}>
              {busy ? "Unlocking…" : "Unlock"}
            </button>
            <div className="row">
              {current?.protection !== "os_keychain" && (
                <button type="button" className="btn ghost small" onClick={() => { setMode(mode === "recovery" ? "unlock" : "recovery"); setSecret(""); }}>
                  {mode === "recovery" ? "Use passphrase" : "Use recovery key"}
                </button>
              )}
              <span className="spacer" />
              <button type="button" className="btn ghost small" onClick={() => { setMode("create"); setSecret(""); setError(null); }}>
                New profile
              </button>
            </div>
          </>
        )}

        {mode === "create" && (
          <>
            <p className="muted" style={{ margin: 0 }}>
              Profiles are local. No account or network is needed. Everything you save — requests, history, secrets — is encrypted on this machine.
            </p>
            <label className="lbl">
              Profile name
              <input className="field" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. work" />
            </label>
            <label className="check">
              <input type="checkbox" checked={useKeychain} onChange={(e) => setUseKeychain(e.target.checked)} />
              Keep the data key in the OS keychain instead of a passphrase
            </label>
            {!useKeychain && (
              <>
                <label className="lbl">
                  Unlock passphrase
                  <input className="field" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" />
                </label>
                <label className="lbl">
                  Repeat passphrase
                  <input className="field" type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} autoComplete="new-password" />
                </label>
              </>
            )}
            {error && <div className="bad-box" role="alert">{error}</div>}
            <button className="btn primary" type="submit" disabled={busy}>
              {busy ? "Creating…" : "Create profile"}
            </button>
            {profiles && profiles.length > 0 && (
              <button type="button" className="btn ghost small" onClick={() => setMode("unlock")}>
                Back to unlock
              </button>
            )}
          </>
        )}
      </form>
    </div>
  );
}
