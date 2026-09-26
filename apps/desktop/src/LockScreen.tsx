// Profile selection, creation and unlock. Unlocking happens in Rust; this
// screen never holds the data key.
import { useEffect, useState } from "react";
import { api, type ProfileSummary } from "./api";

export function LockScreen(props: { onUnlocked: () => void; reason?: string | null }) {
  const [profiles, setProfiles] = useState<ProfileSummary[] | null>(null);
  const [mode, setMode] = useState<"unlock" | "create" | "recovery">("unlock");
  const [selected, setSelected] = useState<string>("");
  const [secret, setSecret] = useState("");
  const [name, setName] = useState("Local");
  const [pass2, setPass2] = useState("");
  // Default: start without a password; the data key goes to the OS keychain.
  const [useKeychain, setUseKeychain] = useState(true);
  const [autoOpening, setAutoOpening] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recovery, setRecovery] = useState<string | null>(null);
  const [resetStep, setResetStep] = useState(false);

  useEffect(() => {
    api.profiles().then(async (p) => {
      setProfiles(p);
      if (p.length === 0) return setMode("create");
      setSelected(p[0].profile_id);
      // At launch (not after a manual, idle or sleep lock), a single profile
      // kept in the OS keychain opens by itself: no password was chosen, so
      // there is nothing to ask for.
      if (!props.reason && p.length === 1 && p[0].protection === "os_keychain") {
        setAutoOpening(true);
        try {
          await api.unlock(p[0].profile_id, null, null);
          props.onUnlocked();
        } catch (e) {
          setError(String((e as Error).message));
        } finally {
          setAutoOpening(false);
        }
      }
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
      // After a recovery-key unlock, offer to set a new passphrase right away.
      if (mode === "recovery") setResetStep(true);
      else props.onUnlocked();
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  async function create() {
    setError(null);
    if (!name.trim()) return setError("Give the profile a name.");
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
      const msg = String((e as Error).message);
      if (useKeychain && msg.includes("credential store is unavailable")) {
        // No OS keychain here (e.g. Linux without a Secret Service). Anvil
        // never stores data unencrypted, so a passphrase is the only option.
        setUseKeychain(false);
        setError("This system has no OS keychain Anvil can use, so choose a passphrase instead. Anvil never stores your data unencrypted.");
      } else {
        setError(msg);
      }
    } finally {
      setBusy(false);
    }
  }

  if (resetStep) {
    return (
      <div className="lock">
        <form
          className="lock-card"
          onSubmit={async (e) => {
            e.preventDefault();
            setError(null);
            if (secret.length < 8) return setError("The passphrase needs at least 8 characters.");
            if (secret !== pass2) return setError("The passphrases do not match.");
            try {
              await api.changePassphrase(secret);
              setSecret("");
              setPass2("");
              props.onUnlocked();
            } catch (err) {
              setError(String((err as Error).message));
            }
          }}
        >
          <h1>Set a new passphrase</h1>
          <p className="muted">You unlocked with the recovery key. Choose a new passphrase; your recovery key keeps working.</p>
          <label className="lbl">
            New passphrase
            <input className="field" type="password" autoFocus value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" />
          </label>
          <label className="lbl">
            Repeat passphrase
            <input className="field" type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} autoComplete="new-password" />
          </label>
          {error && <div className="bad-box" role="alert">{error}</div>}
          <button className="btn primary" type="submit">
            Save passphrase
          </button>
          <button type="button" className="btn ghost small" onClick={() => props.onUnlocked()}>
            Not now
          </button>
        </form>
      </div>
    );
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

  if (autoOpening) {
    return (
      <div className="lock">
        <div className="lock-card" aria-busy="true">
          <h1>Ferrum Anvil</h1>
          <p className="muted">Opening your local profile…</p>
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
              No account, no sign-up and no network needed. What you save stays on this computer, encrypted.
            </p>
            <label className="lbl">
              Profile name
              <input className="field" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. work" />
            </label>
            <fieldset className="choices" aria-label="How to protect this profile">
              <label className={`choice ${useKeychain ? "selected" : ""}`}>
                <input type="radio" name="protection" checked={useKeychain} onChange={() => { setUseKeychain(true); setError(null); }} />
                <span>
                  <b>Start now — no password</b>
                  <span className="faint">
                    The encryption key is kept in your operating system's keychain, so Anvil opens without asking for anything. Anyone signed in to this computer
                    account can open it.
                  </span>
                </span>
              </label>
              <label className={`choice ${!useKeychain ? "selected" : ""}`}>
                <input type="radio" name="protection" checked={!useKeychain} onChange={() => { setUseKeychain(false); setError(null); }} />
                <span>
                  <b>Protect with a passphrase</b>
                  <span className="faint">You type it to unlock, and you get a recovery key. Better on a shared computer.</span>
                </span>
              </label>
            </fieldset>
            {!useKeychain && (
              <>
                <label className="lbl">
                  Unlock passphrase
                  <input className="field" type="password" autoFocus value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" />
                </label>
                <label className="lbl">
                  Repeat passphrase
                  <input className="field" type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} autoComplete="new-password" />
                </label>
              </>
            )}
            {error && <div className="bad-box" role="alert">{error}</div>}
            <button className="btn primary" type="submit" disabled={busy}>
              {busy ? "Creating…" : useKeychain ? "Start working" : "Create profile"}
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
