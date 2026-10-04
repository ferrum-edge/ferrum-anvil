# Upgrade guide

## Unreleased desktop session IPC proposal

**This compatibility break is a concrete, unapproved candidate in PR #307.**
It changes the released id-only interactive desktop IPC. Root must complete
whole-change review, obtain fresh independent review and verify all hosted CI,
then ask the owner to explicitly approve the break before merging or releasing
the candidate. This guide describes the candidate, not an activated release.

The candidate requires `attemptId` for `session_open`, `session_send` and
`session_cancel`. An OPEN without it is no longer accepted: native code does
not generate a hidden attempt. Missing or non-string identity fails JSON
decoding before admission, context building or engine work. OPEN validates the
UUID before registration; SEND/CANCEL require the exact string registered by
OPEN and reject an identity that does not own the current slot. Profile/epoch
and exact-slot checks continue to apply after admission.

An execution id can be reused once its slot retires, while the old renderer
console can remain visible until history finalization and completion delivery.
The attempt identifies which open that console owns. A SEND from it must not
control the replacement, even if the invocation first reaches native admission
after replacement. This does not depend on Tauri invocation reordering.

Direct callers must generate a fresh UUID attempt for each OPEN, retain both
identities, and pass the same `attemptId` string to every SEND and CANCEL for
that open. A reconnect uses a new attempt even when reusing an `executionId`.
For example, with an existing `SendInput` named `input`:

```ts
import { invoke } from "@tauri-apps/api/core";

const executionId = crypto.randomUUID();
const attemptId = crypto.randomUUID();
const identity = { executionId, attemptId };

const openedId = await invoke<string>("session_open", { input, ...identity });
// openedId remains executionId; it is not an attempt identity or an object.
await invoke<void>("session_send", {
  ...identity,
  command: { command: "send_text", text: "hello" },
});
await invoke<void>("session_cancel", identity);
```

Every SEND command, including `close`, `half_close`, `ping` and binary sends,
uses that same identity. Command bodies and protocol support are unchanged;
for example TCP half-close uses `{ command: "half_close" }`, and close uses
`{ command: "close", code: 1000, reason: "" }`. Keep the attempt that belongs
to the originating console/callback; do not substitute a newer attempt found
by execution id when an old action runs.

The bundled Workbench already passes an explicit attempt to OPEN and CANCEL;
the candidate also passes it through the SEND callback and desktop API. No
manual migration is needed for that bundled renderer. Direct IPC integrations
must update all three calls together. OPEN's return remains a string; no
string-to-object return migration is proposed.

Desktop interactive `execution-event` envelopes and `session-ended` packets
carry snake-case `attempt_id` alongside `execution_id`. Match both identities
before displaying messages or retiring an attempt. Manual-send events, domain
and CLI event shapes, and non-interactive RPC arguments are unchanged by this
proposal; it requires no shared generated-schema change.
