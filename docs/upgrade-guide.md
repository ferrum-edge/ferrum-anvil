# Upgrade guide

## 0.1.6

### Database schema 6

0.1.6 moves the profile database from schema 3 to schema 6 the first time it
opens or unlocks a profile. Earlier builds (0.1.5 and before) then refuse that
database, and any full backup made by 0.1.6, as written by a newer version.
Portable bundles keep their format.

- Close every earlier build before upgrading.
- Before migrating, 0.1.6 copies the database into the profile's
  `checkpoints` folder as `<time>-before-schema-<version>.db`. If that copy
  cannot be written, the profile does not open or unlock until space is
  freed. To go back to an earlier build, restore that checkpoint as described
  in [Going back to an earlier build](storage-and-recovery.md#going-back-to-an-earlier-build).
- A password change, a keychain conversion and an identity-policy change now
  rotate the data key, and a rotation deletes checkpoints sealed with the old
  key, this one included. Export a portable bundle first if you may want to
  go back.

### Behaviour changes

These behaviour changes may need action; the [changelog](../CHANGELOG.md)
has the full list.

- A browser sign-in authorization URL on `http://localhost` is refused. Use
  `http://127.0.0.1:<port>`, or `https`, for a local test issuer.
- RSA keys must be 2048–8192 bits: RS256 signing with a shorter key fails, and
  a JWT-SVID signed by a bundle key outside that range no longer verifies.
- `--env` on `anvil send`, `run` and `mcp-discover` refuses a name that two
  environments of the workspace share, listing their ids; pass the id.
- Linux installers are built on Ubuntu 26.04 and may need its newer glibc and
  system libraries; Ubuntu 22.04 and 24.04 are no longer release targets. The
  AppImage uses the host's `libwayland-client`.
- Rust code: `PolicyRotation` is an enum, and `SecretResolver` methods no
  longer have default implementations, so a wrapping resolver must forward
  each one.

## 0.1.5

0.1.5 keeps the database schema and the bundle and backup formats of 0.1.4;
no migration action is needed. Ferrum Edge v0.9.15 becomes the lab and
new-profile default.

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
- The System resolver keeps `localhost` and `*.localhost` on loopback: only
  loopback answers are kept, so a name that resolves to no loopback address
  now fails; use a DNS override to reach a non-loopback address.
- A sensitive extraction larger than 64 KiB now fails its step; the response
  is discarded and the value is not passed to later steps.
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

### Behaviour changes

These changes may need action; the
[HTTP state and destination policy](security/http-state-and-destination-policy.md#compatibility-changes)
has the full list, including the remaining network-zone restrictions.

- **Cookies.** Jars are bounded: eviction and output omission can end
  sessions or change load results. Cookies with an unknown suffix are
  host-only.
- **OAuth token endpoints** must be HTTPS, or `http://` to a literal loopback
  address on a direct connection: `localhost`, DNS names, DNS overrides and
  proxied routes are refused for HTTP. A load plan whose unit depends on a
  vault variable deferred for OAuth is refused before traffic.
- **Redirects and destinations.** Redirects through any proxy, redirect
  answers that mix public and non-public zones, returns to a non-public zone
  after a public hop, and fake-IP redirects that do not return to the
  original host are refused, as are original requests to special or reserved
  addresses (including `0.0.0.0`).
- **Bundles** over 256 MiB in total inflated bytes, with an entry over
  128 MiB, or holding more than 4 Mi JSON values (object keys included) no
  longer import, and a file over 128 MiB can no longer be attached. To move
  such a workspace, open it in the Anvil that exported it and export again in
  smaller parts: one workspace per bundle, without history, or with large
  files linked rather than attached. See the
  [bundle resource policy](security/bundle-resource-policy.md).

### Desktop IPC commands

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
