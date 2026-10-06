# Upgrade guide

## Unreleased

This release changes two groups of desktop IPC commands. Both changes only
affect code that calls the desktop's Tauri commands directly: the bundled
Workbench and import dialog already use the new shapes, and the `anvil` CLI,
its output and the domain event shapes are unchanged. Calls in the old shapes
fail to decode and do nothing.

### Interactive session attempts

`session_open`, `session_send` and `session_cancel` now require an
`attemptId` alongside the `executionId`.

| Command | Before | After |
| --- | --- | --- |
| `session_open` | `{ input, executionId }` | `{ input, executionId, attemptId }` |
| `session_send` | `{ executionId, command }` | `{ executionId, attemptId, command }` |
| `session_cancel` | `{ executionId }` | `{ executionId, attemptId }` |

- `attemptId` is a UUID string. Generate a fresh one for every OPEN, including
  a reconnect that reuses an `executionId`. The nil UUID is rejected.
- Pass the same `attemptId` string to every SEND and CANCEL for that open.
  A SEND or CANCEL whose attempt does not own the current session for its
  `executionId` is refused with "the session is no longer open".
- Keep the attempt that belongs to the console or callback that issues a
  command. Do not look up a newer attempt by execution id: the attempt is
  what stops a late command from an old console from controlling a newer
  session that reuses its execution id. The native side does not remember
  earlier attempts, so this only holds if each OPEN uses a fresh one.
- OPEN still returns the execution-id string. Session command bodies are
  unchanged; for example close is `{ command: "close", code: 1000, reason: "" }`
  and TCP half-close is `{ command: "half_close" }`.

```ts
import { invoke } from "@tauri-apps/api/core";

const executionId = crypto.randomUUID();
const attemptId = crypto.randomUUID();
const identity = { executionId, attemptId };

const openedId = await invoke<string>("session_open", { input, ...identity });
// openedId is still executionId.
await invoke<void>("session_send", {
  ...identity,
  command: { command: "send_text", text: "hello" },
});
await invoke<void>("session_cancel", identity);
```

Interactive-session `execution-event` packets and `session-ended` packets
now carry `attempt_id` beside `execution_id`:

```ts
// session-ended, before
{ execution_id: string; view?: ExecutionView | null; error?: string | null }
// session-ended, after
{ execution_id: string; attempt_id: string; view?: ExecutionView | null; error?: string | null }
```

Match both ids before showing a session's messages or retiring its controls.
Manual-send `execution-event` packets have no `attempt_id` and are unchanged.

### Spec import review approvals

An import or reimport now applies only the source and plan that were
reviewed. The review commands return an `approval`, and the apply commands
require it back unchanged:

```ts
type SpecApproval = {
  binding: { source_sha256: string; plan_sha256: string };
  scope: string;
};
```

| Command | Before | After |
| --- | --- | --- |
| `spec_preview` | `{ input, options }` returns the preview | `{ input, options, target }` returns the preview plus `binding` and `approval` |
| `spec_import` | `{ input, options, target }` | `{ input, options, target, approval }` |
| `spec_reimport_plan` | `{ importId, input }` returns the plan | `{ importId, input }` returns `{ plan, approval }` |
| `spec_reimport_apply` | `{ importId, input, approval: ReimportApproval }` | `{ importId, input, decisions: ReimportApproval, approval: SpecApproval }` |

- `spec_preview` needs the destination (`target`) up front, because the
  approval is bound to it. Pass the same `input`, `options` and `target` to
  `spec_import`.
- In `spec_reimport_apply`, the overwrite/delete choices
  (`{ overwrite, delete, overwrite_scope, delete_scope }`) moved from
  `approval` to `decisions`; `approval` is now the `SpecApproval` returned by
  `spec_reimport_plan`.
- An approval stops being valid when the source bytes, the options, the
  destination, the source file grant or the stored import change, and when
  the profile locks, unlocks or switches, or the desktop restarts. Apply then
  fails without writing anything; preview or plan again.

```ts
const target = { kind: "new_workspace" };
const preview = await invoke("spec_preview", { input, options, target });
await invoke("spec_import", { input, options, target, approval: preview.approval });

const { plan, approval } = await invoke("spec_reimport_plan", { importId, input });
const decisions = { overwrite: [], delete: [], overwrite_scope: [], delete_scope: [] };
await invoke("spec_reimport_apply", { importId, input, decisions, approval });
```

See [Imports](import.md#native-reviewapply-contract) for the full contract.
