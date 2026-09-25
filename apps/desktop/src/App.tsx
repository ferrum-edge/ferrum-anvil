// Top-level state machine: locked (LockScreen) ⇄ unlocked (Workbench). The
// lock itself is enforced in Rust; this only mirrors it.
import { useEffect, useState } from "react";
import { api, onLocked, type Status } from "./api";
import { LockScreen } from "./LockScreen";
import { Workbench } from "./Workbench";

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [reason, setReason] = useState<string | null>(null);
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
      void refresh();
    });
    const onLockedCall = () => {
      setReason((r) => r ?? "idle");
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
