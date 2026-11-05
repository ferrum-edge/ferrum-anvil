// Profile selection, creation and unlock. Unlocking happens in Rust; this
// screen never holds the data key.
import { useEffect, useReducer, useRef, useState } from "react";
import { api, type LockReason, type ProfileSummary } from "./api";
import logo from "./assets/ferrum-anvil-logo.webp";
import { Icon } from "./icons";

type FormMode = "unlock" | "create" | "recovery";

/** The one screen the lock screen shows. */
export type Screen =
  /** Choose a profile and unlock it (passphrase or recovery key), or create one. */
  | { kind: "form"; mode: FormMode }
  /** A single keychain profile opening by itself at launch. */
  | { kind: "autoOpening" }
  /** A new profile's recovery key, shown once (the backend opened the profile). */
  | { kind: "showRecovery"; key: string }
  /** After a recovery-key unlock (the backend is unlocked): offer a new passphrase. */
  | { kind: "resetPassphrase" }
  /** A legacy profile that must enroll its policy before use. `mode`: the form Back returns
   * to (`recovery`: the current credential is the recovery key). `afterReset`: entered from
   * `resetPassphrase` with the backend still unlocked, which enrollment locks first. */
  | { kind: "enroll"; mode: FormMode; afterReset: boolean };

export interface LockState {
  screen: Screen;
  /** The message shown on the screen (an error, or the outcome of a rotation). */
  error: string | null;
}

export type LockAction =
  | { type: "profilesLoaded"; none: boolean }
  | { type: "autoOpenStarted" }
  | { type: "autoOpenEnded" }
  | { type: "setMode"; mode: FormMode; clearError: boolean }
  | { type: "clearError" }
  /** Already done in the backend: never dropped, whatever the form shows by now. */
  | { type: "recoveryUnlocked" }
  /** Already done in the backend, with a key shown only once: never dropped. */
  | { type: "created"; recoveryKey: string }
  | { type: "recoveryStored" }
  /** "Not now" on the new-passphrase step. */
  | { type: "resetSkipped" }
  | { type: "passphraseChanged" }
  | { type: "enrolled" }
  | { type: "enrollBack" }
  /** A refusal or failure of what was started on the screen `on`; stale once another shows. */
  | { type: "failed"; on: Screen["kind"]; message: string }
  /** The backend locked (any reason). */
  | { type: "locked" };

const ENROLLMENT_REQUIRED = "POLICY_ENROLLMENT_REQUIRED";
const UNLOCK: Screen = { kind: "form", mode: "unlock" };

/** The screen a refusal that requires policy enrollment leads to. */
function enrollFrom(screen: Screen): Screen {
  switch (screen.kind) {
    case "form":
      return { kind: "enroll", mode: screen.mode, afterReset: false };
    case "autoOpening":
      return { kind: "enroll", mode: "unlock", afterReset: false };
    case "resetPassphrase":
      return { kind: "enroll", mode: "recovery", afterReset: true };
    case "showRecovery":
    case "enroll":
      return screen;
  }
}

/** The lock screen's one transition function. */
export function lockScreen(s: LockState, a: LockAction): LockState {
  const { screen } = s;
  switch (a.type) {
    case "profilesLoaded":
      return screen.kind === "form" && a.none ? { ...s, screen: { kind: "form", mode: "create" } } : s;
    case "autoOpenStarted":
      return screen.kind === "form" ? { ...s, screen: { kind: "autoOpening" } } : s;
    case "autoOpenEnded":
      return screen.kind === "autoOpening" ? { ...s, screen: UNLOCK } : s;
    case "setMode":
      return screen.kind === "form" ? { screen: { kind: "form", mode: a.mode }, error: a.clearError ? null : s.error } : s;
    case "clearError":
      return { ...s, error: null };
    case "recoveryUnlocked":
      // Whatever the form shows by now; only a recovery key on display stays.
      return screen.kind === "showRecovery" ? s : { screen: { kind: "resetPassphrase" }, error: null };
    case "created":
      // The profile exists and its recovery key is returned only here.
      return { screen: { kind: "showRecovery", key: a.recoveryKey }, error: null };
    case "recoveryStored":
      return screen.kind === "showRecovery" ? { screen: UNLOCK, error: null } : s;
    case "resetSkipped":
      // The app opens if the backend is still unlocked; if it locked meanwhile, this form shows.
      return screen.kind === "resetPassphrase" ? { screen: UNLOCK, error: null } : s;
    case "passphraseChanged":
      // The rotation locks the profile; its `locked` event may come first.
      return screen.kind === "resetPassphrase" || screen.kind === "form"
        ? { screen: UNLOCK, error: "Encryption key rotated. Unlock with the new passphrase or saved replacement recovery key." }
        : s;
    case "enrolled":
      return screen.kind === "enroll" ? { screen: UNLOCK, error: "Policy enrolled and encryption key rotated. Unlock with your new passphrase." } : s;
    case "enrollBack":
      if (screen.kind !== "enroll") return s;
      return {
        screen: screen.afterReset ? { kind: "resetPassphrase" } : { kind: "form", mode: screen.mode },
        error: null,
      };
    case "failed":
      if (screen.kind !== a.on) return s;
      // The new-passphrase step needs an unlocked backend: a lock ends it.
      if (screen.kind === "resetPassphrase" && a.message === "LOCKED") {
        return { screen: UNLOCK, error: "The profile locked before the new passphrase was saved. Unlock it to continue." };
      }
      return { screen: a.message.includes(ENROLLMENT_REQUIRED) ? enrollFrom(screen) : screen, error: a.message };
    case "locked":
      switch (screen.kind) {
        // Unlocked screens the backend no longer backs: back to the unlock form.
        case "resetPassphrase":
        case "autoOpening":
          return { screen: UNLOCK, error: null };
        // Enrollment works on a locked profile; nothing is left to lock first.
        case "enroll":
          return { ...s, screen: { ...screen, afterReset: false } };
        // Kept: the key is shown once, and its button leads to the unlock form
        // with the new profile selected.
        case "showRecovery":
        case "form":
          return s;
      }
  }
}

function lockedBecause(reason: LockReason): string {
  switch (reason) {
    case "manual":
      return "manually";
    case "idle":
      return "inactivity";
    case "suspend":
      return "the system went to sleep";
    case "integrity":
      return "a stored record failed its integrity check";
  }
}

export function LockScreen(props: { onUnlocked: () => void; reason?: LockReason | null; locks?: number }) {
  const [profiles, setProfiles] = useState<ProfileSummary[] | null>(null);
  const [s, dispatch] = useReducer(lockScreen, { screen: UNLOCK, error: null });
  const { screen, error } = s;
  const [selected, setSelected] = useState<string>("");
  const [secret, setSecret] = useState("");
  const [name, setName] = useState("Local");
  const [pass2, setPass2] = useState("");
  // Default: start without a password; the data key goes to the OS keychain.
  const [useKeychain, setUseKeychain] = useState(true);
  const [busy, setBusy] = useState(false);
  const [enrollmentPass, setEnrollmentPass] = useState("");
  const [enrollmentRepeat, setEnrollmentRepeat] = useState("");
  const fail = (on: Screen["kind"], message: string) => dispatch({ type: "failed", on, message });
  // The list a new profile is in, with it selected (the unlock form shows it if a lock
  // lands before the app opens it).
  const reloadProfiles = async (select: string) => {
    try {
      const p = await api.profiles();
      setProfiles(p);
      setSelected(p.some((x) => x.profile_id === select) ? select : (p[0]?.profile_id ?? ""));
      dispatch({ type: "profilesLoaded", none: p.length === 0 });
    } catch {
      // Kept as it was: the list is read again when this screen next mounts.
    }
  };

  useEffect(() => {
    api.profiles().then(async (p) => {
      setProfiles(p);
      dispatch({ type: "profilesLoaded", none: p.length === 0 });
      if (p.length === 0) return;
      setSelected(p[0].profile_id);
      // At launch (not after a manual, idle or sleep lock), a single profile
      // kept in the OS keychain opens by itself: no password was chosen, so
      // there is nothing to ask for.
      if (!props.reason && p.length === 1 && p[0].protection === "os_keychain") {
        dispatch({ type: "autoOpenStarted" });
        try {
          await api.unlock(p[0].profile_id, null, null);
          props.onUnlocked();
        } catch (e) {
          fail("autoOpening", String((e as Error).message));
        } finally {
          dispatch({ type: "autoOpenEnded" });
        }
      }
    });
  }, []);

  // Any lock that lands while this screen shows (counted by App, since two in a
  // row may share a reason) leaves the screens only an unlocked backend backs.
  const locksSeen = useRef(props.locks ?? 0);
  useEffect(() => {
    const locks = props.locks ?? 0;
    if (locks === locksSeen.current) return;
    locksSeen.current = locks;
    if (screen.kind === "resetPassphrase") {
      // The new passphrase typed there must not end up in the unlock field.
      setSecret("");
      setPass2("");
    }
    dispatch({ type: "locked" });
  }, [props.locks]);

  const current = profiles?.find((p) => p.profile_id === selected);

  async function unlock(mode: FormMode) {
    setBusy(true);
    dispatch({ type: "clearError" });
    try {
      if (current?.protection === "os_keychain") await api.unlock(selected, null, null);
      else if (mode === "recovery") await api.unlock(selected, null, secret);
      else await api.unlock(selected, secret, null);
      setSecret("");
      // After a recovery-key unlock, offer to set a new passphrase right away.
      if (mode === "recovery") dispatch({ type: "recoveryUnlocked" });
      else props.onUnlocked();
    } catch (e) {
      fail("form", String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  async function create() {
    dispatch({ type: "clearError" });
    if (!name.trim()) return fail("form", "Give the profile a name.");
    if (!useKeychain) {
      if (secret.length < 8) return fail("form", "The passphrase needs at least 8 characters.");
      if (secret !== pass2) return fail("form", "The passphrases do not match.");
    }
    setBusy(true);
    try {
      const r = await api.createProfile(name.trim(), useKeychain ? null : secret, useKeychain);
      setSecret("");
      setPass2("");
      if (r.recovery_key) dispatch({ type: "created", recoveryKey: r.recovery_key });
      else props.onUnlocked();
      void reloadProfiles(r.profile_id);
    } catch (e) {
      const msg = String((e as Error).message);
      if (useKeychain && msg.includes("credential store is unavailable")) {
        // No OS keychain here (e.g. Linux without a Secret Service). Anvil
        // never stores data unencrypted, so a passphrase is the only option.
        setUseKeychain(false);
        fail("form", "This system has no OS keychain Anvil can use, so choose a passphrase instead. Anvil never stores your data unencrypted.");
      } else {
        fail("form", msg);
      }
    } finally {
      setBusy(false);
    }
  }

  if (screen.kind === "enroll") {
    const byRecovery = screen.mode === "recovery";
    return <div className="lock"><form className="lock-card" onSubmit={async (e) => {
      e.preventDefault();
      if (enrollmentPass.length < 8 || enrollmentPass !== enrollmentRepeat) return fail("enroll", `${ENROLLMENT_REQUIRED}: enter the same new passphrase twice (at least 8 characters).`);
      setBusy(true);
      try {
        if (screen.afterReset) await api.lock();
        await api.enrollUnlinkedPolicy(selected, current?.protection === "os_keychain" || byRecovery ? null : secret, byRecovery ? secret : null, enrollmentPass);
        setProfiles(await api.profiles()); setSecret(""); setEnrollmentPass(""); setEnrollmentRepeat("");
        dispatch({ type: "enrolled" });
      } catch (e) { fail("enroll", `${ENROLLMENT_REQUIRED}: ${(e as Error).message}`); }
      finally { setBusy(false); }
    }}>
      <h1>Enroll legacy policy</h1>
      <p className="lock-sub">This pre-catalogue profile needs key rotation and authenticated current records before active use. Enrollment preserves a surviving verified linked policy; if its policy is missing, explicitly confirm replacement with an unlinked policy. Save the replacement recovery key in the native dialog. A fresh-login policy needs its provider proof or the current recovery key. Historical data remains recoverable.</p>
      {current?.protection !== "os_keychain" && <label className="lbl">{byRecovery ? "Current recovery key" : "Current passphrase"}<input className="field" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} /></label>}
      <label className="lbl">New passphrase<input className="field" type="password" value={enrollmentPass} onChange={(e) => setEnrollmentPass(e.target.value)} autoComplete="new-password" /></label>
      <label className="lbl">Repeat new passphrase<input className="field" type="password" value={enrollmentRepeat} onChange={(e) => setEnrollmentRepeat(e.target.value)} autoComplete="new-password" /></label>
      <div className="bad-box" role="alert">{error}</div>
      <button className="btn primary" disabled={busy} type="submit">Enroll policy and rotate…</button>
      <button className="btn ghost" type="button" disabled={busy} onClick={() => dispatch({ type: "enrollBack" })}>Back</button>
    </form></div>;
  }

  if (screen.kind === "resetPassphrase") {
    return (
      <div className="lock">
        <form
          className="lock-card"
          onSubmit={async (e) => {
            e.preventDefault();
            dispatch({ type: "clearError" });
            if (secret.length < 8) return fail("resetPassphrase", "The passphrase needs at least 8 characters.");
            if (secret !== pass2) return fail("resetPassphrase", "The passphrases do not match.");
            try {
              await api.changePassphrase(secret);
              setSecret("");
              setPass2("");
              dispatch({ type: "passphraseChanged" });
            } catch (err) {
              fail("resetPassphrase", String((err as Error).message));
            }
          }}
        >
          <div className="lock-head">
            <span className="lock-icon">
              <Icon name="key" size={18} />
            </span>
            <h1>Set a new passphrase</h1>
          </div>
          <p className="lock-sub">Choose a new passphrase. Anvil will rotate the encryption key and re-encrypt active data. Save the replacement recovery key in the native dialog first. The old passphrase and recovery key stop opening active data; historical backups remain historical.</p>
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
          <button type="button" className="btn ghost" onClick={() => { dispatch({ type: "resetSkipped" }); props.onUnlocked(); }}>
            Not now
          </button>
        </form>
      </div>
    );
  }

  if (screen.kind === "showRecovery") {
    return (
      <div className="lock">
        <div className="lock-card">
          <div className="lock-head">
            <span className="lock-icon">
              <Icon name="key" size={18} />
            </span>
            <h1>Save your recovery key</h1>
          </div>
          <p className="lock-sub">
            This key is the only way to open this profile if you forget the passphrase. It is shown once and is not stored anywhere. Keep it offline.
          </p>
          <div className="recovery" aria-label="Recovery key">
            {screen.key}
          </div>
          <button className="btn primary" onClick={() => { dispatch({ type: "recoveryStored" }); props.onUnlocked(); }}>
            I stored it safely — continue
          </button>
        </div>
      </div>
    );
  }

  if (screen.kind === "autoOpening") {
    return (
      <div className="lock">
        <div className="lock-card" aria-busy="true">
          <img className="brand-logo" src={logo} alt="Ferrum Anvil — Put your APIs to the test." />
          <div className="lock-opening">
            <span className="spinner" />
            <span className="lock-sub">Opening your local profile…</span>
          </div>
        </div>
      </div>
    );
  }

  const { mode } = screen;
  const setMode = (m: FormMode, clearError = false) => dispatch({ type: "setMode", mode: m, clearError });
  return (
    <div className="lock">
      <form
        className="lock-card"
        onSubmit={(e) => {
          e.preventDefault();
          void (mode === "create" ? create() : unlock(mode));
        }}
      >
        <h1 className="sr-only">Ferrum Anvil — Put your APIs to the test.</h1>
        <img className="brand-logo" src={logo} alt="" />
        {props.reason && (
          <div className="warn-box">Locked ({lockedBecause(props.reason)}). Active runs were stopped.</div>
        )}

        {mode !== "create" && profiles && profiles.length > 0 && (
          <>
            <label className="lbl">
              Profile
              <select className="field" value={selected} disabled={busy} onChange={(e) => setSelected(e.target.value)}>
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
              {!busy && <Icon name="lock" size={14} />}
              {busy ? "Unlocking…" : "Unlock"}
            </button>
            <div className="lock-links">
              {current?.protection !== "os_keychain" ? (
                <button type="button" className="btn ghost small" disabled={busy} onClick={() => { setMode(mode === "recovery" ? "unlock" : "recovery"); setSecret(""); }}>
                  <Icon name="key" size={13} />
                  {mode === "recovery" ? "Use passphrase" : "Use recovery key"}
                </button>
              ) : (
                <span />
              )}
              <button type="button" className="btn ghost small" disabled={busy} onClick={() => { setMode("create", true); setSecret(""); }}>
                <Icon name="plus" size={13} />
                New profile
              </button>
            </div>
          </>
        )}

        {mode === "create" && (
          <>
            <div className="lock-intro">
              <h2>Create a local profile</h2>
              <p className="lock-sub">No account, no sign-up and no network needed. What you save stays on this computer, encrypted.</p>
            </div>
            <label className="lbl">
              Profile name
              <input className="field" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. work" />
            </label>
            <fieldset className="choices" aria-label="How to protect this profile">
              <label className={`choice ${useKeychain ? "selected" : ""}`}>
                <input type="radio" name="protection" checked={useKeychain} onChange={() => { setUseKeychain(true); dispatch({ type: "clearError" }); }} />
                <span>
                  <b>Start now — no password</b>
                  <span className="faint">
                    The encryption key is kept in your operating system's keychain, so Anvil opens without asking for anything. Anyone signed in to this computer
                    account can open it.
                  </span>
                </span>
              </label>
              <label className={`choice ${!useKeychain ? "selected" : ""}`}>
                <input type="radio" name="protection" checked={!useKeychain} onChange={() => { setUseKeychain(false); dispatch({ type: "clearError" }); }} />
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
              <button type="button" className="btn ghost" disabled={busy} onClick={() => setMode("unlock")}>
                <Icon name="chevronLeft" size={14} />
                Back to unlock
              </button>
            )}
          </>
        )}
      </form>
    </div>
  );
}
