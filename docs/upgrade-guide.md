# Upgrade guide

## 0.1.4

0.1.4 keeps database schema 3 and the bundle and backup formats of 0.1.3.
These behaviour changes may need action; the [changelog](../CHANGELOG.md)
has the full list.

- Response extractions and dataset cells are sent literally: a value
  containing `{{...}}` is no longer expanded. If a workflow needs template
  expansion, store the template in an ordinary workspace or request variable.
- A redirected MCP initialize request is refused. Point the request at the
  final MCP endpoint.
- Rust code that constructs `anvil_engine::vars::VarEntry` directly must set
  `literal`: `false` for template-backed variables, `true` for values that
  must remain data.
- `anvil lint-spec` exits with 3 when its report is incomplete (a copy budget
  ran out), as it already did when operations were left out. Pass
  `--allow-incomplete` where an incomplete lint is acceptable.
- The System resolver keeps `localhost` and `*.localhost` on loopback. A
  hosts-file entry that points one of these names at another address now
  fails; use a DNS override to reach a non-loopback address.
- Findings that quote `X-Gateway-Error` values show them as received
  (redacted), no longer lowercased. Update anything that matches that quoted
  text in findings or saved history.

## 0.1.3

### Database schema 3

0.1.3 moves the profile database from schema 2 to schema 3 the first time it
opens or unlocks a profile. Earlier builds (0.1.0 to 0.1.2) then refuse that
database, and any full backup made by 0.1.3, as written by a newer version.
Portable bundles keep their format, so a bundle exported by 0.1.3 still
imports into an earlier build.

- Close every earlier build before upgrading. One that still has the profile
  open keeps writing revisions and history records the old way, and 0.1.3
  refuses those rows until they are deleted.
- Before migrating, 0.1.3 copies the database into the profile's
  `checkpoints` folder as `<time>-before-schema-3.db`. If that copy cannot be
  written (for example, the disk is full), the profile does not open or unlock
  until space is freed.
- To go back to an earlier build, restore that checkpoint as described in
  [Going back to an earlier build](storage-and-recovery.md#going-back-to-an-earlier-build).
  Everything changed since the upgrade is lost, so export what you need
  first.

## 0.1.2

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
