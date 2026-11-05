// Top-level state machine: locked (LockScreen) ⇄ unlocked (Workbench). The
// lock itself is enforced in Rust; this only mirrors it.
import { useEffect, useState } from "react";
import { api, onLocked, type LockReason, type Status } from "./api";
import { LockScreen } from "./LockScreen";
import { Workbench } from "./Workbench";
import logo from "./assets/ferrum-anvil-logo.webp";

// Decode the lock-screen logo up front so a lock shows it immediately.
if (typeof Image !== "undefined") new Image().src = logo;

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [reason, setReason] = useState<LockReason | null>(null);
  // Counts the locks heard: a lock that lands while the lock screen shows
  // (after a recovery-key unlock, say) has the same reason as the last one.
  const [locks, setLocks] = useState(0);
  const [profileName, setProfileName] = useState("");

  const refresh = async () => {
    const s = await api.status();
    setStatus(s);
    if (s.state === "unlocked") setProfileName(s.profile ?? "");
  };

  useEffect(() => {
    void refresh();
    const un = onLocked((r) => {
      setReason(r);
      setLocks((n) => n + 1);
      void refresh();
    });
    const onLockedCall = () => {
      setReason((r) => r ?? "idle");
      setLocks((n) => n + 1);
      void refresh();
    };
    window.addEventListener("anvil-locked", onLockedCall);
    return () => {
      void un.then((f) => f());
      window.removeEventListener("anvil-locked", onLockedCall);
    };
  }, []);

  if (!status) return null;
  if (status.state !== "unlocked") {
    return (
      <LockScreen
        reason={reason}
        locks={locks}
        onUnlocked={() => {
          setReason(null);
          void refresh();
        }}
      />
    );
  }
  return (
    <Workbench
      key={status.profile}
      profileName={profileName}
      onLock={async () => {
        await api.lock();
        setReason("manual");
        await refresh();
      }}
    />
  );
}
