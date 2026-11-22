# Upgrade guide

## 0.1.9

0.1.9 opens 0.1.8 profiles unchanged: the profile database stays at schema 6
and the app settings format is the same, so no migration or enrollment runs.

### Workspace bundles and sensitive datasets (#602, GHSA-7p29-5g2w-wwq4)

The stored data of a dataset with `sensitive_columns` is no longer written as a
plaintext `attachments/` entry, nor is the same file when a request uses it.

- An encrypted transfer that includes the dataset carries that data inside
  its encrypted vault (a file missing on the exporting device is listed among
  the excluded items, as before). The import stores it only while a dataset with
  sensitive columns in the receiving profile uses it, so a Merge that keeps an
  existing dataset in place (a linked one, for example) can leave it unstored;
  the preview says so. Anvil 0.1.8 and
  earlier cannot read that data: they ignore it, so the dataset arrives
  without its stored file, and the import is refused (nothing is imported)
  when the receiving profile already stores content with the same hash.
  Upgrade the receiving Anvil to 0.1.9 first. The vault must hold the sealed data (under
  96 MiB of dataset files); a larger encrypted transfer is refused, and a full
  backup carries it.
- A share-safe bundle leaves that data out and lists the dataset, and any
  request using the same file, among its excluded items. The imported dataset
  (and any such request) names a linked file; choose it on the receiving machine with **Choose new
  location…**.
- A bundle of only another workspace, whose request uses the same file, leaves
  the file out in both modes and lists the request among its excluded items.
- Bundles made by 0.1.8 or earlier still carry such data as a plaintext entry.
  Treat them as containing those secrets, and export again with 0.1.9 where
  that matters.

### Native confirmation for vault-backed saves (#607, GHSA-qxwm-425v-8xgf)

The desktop app now asks for native OS confirmation before a save that
establishes or changes a vault-backed authority binding: creating or saving a
request, or saving a workspace, folder, environment, TLS profile, proxy profile
or the default connection settings, when the change affects where or how
vault-backed credentials or secrets are sent (for example a new destination,
routing or proxy, or TLS policy such as turning off certificate verification),
even if the destination URL and the credential stay the same. The check
compares a vault-backed request's effective settings, so changing one of them
(a response size limit, for example) can prompt as well. Ordinary edits, such
as renaming a request or editing a header other than `Host`, are saved without
a prompt when Anvil can verify that the binding is unchanged; when it cannot
resolve the request's destination, it asks. Declining the prompt, or the profile locking while it is open, leaves
the change unsaved.

### Other changes

- `anvil import-spec` given both a workspace and `--new-workspace` now fails as
  a usage error (exit 3) instead of ignoring the workspace (#603). Scripts
  should pass one or the other.
- An OpenAPI import whose document-level server variables sanitize to the same
  name (for example `{release-name}` and `{release_name}`) now gives each its
  own environment variable (`release_name_2`, `release_name`) instead of
  writing both as `release_name` (#580).

## 0.1.8

0.1.8 opens 0.1.7 profiles without a new migration or enrollment: the profile
database stays at schema 6. Going back is not supported: 0.1.8 no longer
stores the unused `autosave`, `lock.run_policy` and
`lock.clear_clipboard_on_lock` settings (#529), and 0.1.7 requires them, so
once 0.1.8 saves the app settings (for example after a Settings change),
0.1.7 cannot read them. If you may need to downgrade, keep a copy of each profile, or a full
backup made with 0.1.7, before upgrading. The changes below affect imports,
load-run scripts, gateway profiles and gateway diagnostics.

### Ferrum Edge v0.9.20 only (#481)

Ferrum Edge v0.9.20 is the only supported release. New gateway profiles and
the lab default to it, and existing profiles keep the release they declare. A
profile or import that names an earlier release with an embedded diagnostics
catalog (v0.9.5, v0.9.7 to v0.9.11, v0.9.14, v0.9.15) keeps its diagnoses.
`anvil-lab --release` refuses v0.9.5 to v0.9.15. Against an Edge listener
older than v0.9.20 that requests a client certificate (it sends an empty
`certificate_authorities` list), DTLS 1.3 with a client certificate fails
again: the handshake times out (`client.dtls.handshake_timeout`). DTLS 1.2,
and listeners that do not request a certificate, are unaffected. Upgrade the
gateway to v0.9.20.

### Import reports and auth placeholder names (#584)

- Import report messages, required-variable reasons and inactive-setting values
  changed wording and no longer quote source values. Tooling that parsed text
  out of `warnings[].message`, `unsupported[].message` or
  `required_variables[].reason` should use `code` and `pointer` instead. A
  callback's inactive-setting `value` is now a count such as `1 callback URL
  expression(s)`.
- `report.scripts[]` no longer has `source`, and `owner` is now one of
  `collection`, `folder`, `request` or `test_suite` rather than a name. `event`
  is one of `prerequest`, `test`, `after_response`, `unit_test` or `other`.
  `language` is `javascript` or `other`. `bytes` and `lines` are new. Read a
  script's body from the source file at the entry's `pointer`.
- Placeholders an import makes for a redacted credential are now bound to the
  secret they replaced (a credential the source never supplied, such as an
  OpenAPI security scheme's key, keeps its scheme-derived name): `{{secret_<16 hex digits>}}` for header, query, form, body, path and
  environment values, `{{auth_<16 hex digits>_<field>}}` for auth secrets and
  URL userinfo, and `{{url_<16 hex digits>}}` for quarantined URLs. They replace
  field-named placeholders (`{{Authorization}}`, `{{api_key}}`), owner-named
  ones (`{{<collection>_password}}`), `{{username}}` / `{{password}}` and
  `{{url-needs-review}}`. The report lists the `secret_` and `auth_` names
  under required variables and a quarantined URL's `url_` name in
  `redactions[].placeholder`.
- The first reimport after upgrading moves requests imported by an earlier build
  to the new names, so their credentials are asked for again once. After that, a
  credential you fill stays with the secret it replaced across reimports, and a
  secret that changed in the source gets a new variable to fill in.
- The names are keyed by your profile. Reimporting in another profile, or after
  restoring a backup into a new profile, asks for every credential again.
  Library callers of `anvil_import::import` should pass a stable
  `ImportOptions::credential_key` (`CredentialKey::derive` of a secret they keep
  outside workspace files) if they want names to survive reimports. Without one,
  every import makes new names.
- An empty secret in the source is no longer replaced by a placeholder; fill it
  in on the request.
- A source that uses a variable named like these placeholders (`auth_`,
  `secret_` or `url_` followed by 16 hex digits) is refused; rename the variable
  in the source.
- `ReimportChange` and `ScopeChange` are unchanged; no reimport change is held
  for credential review.
- These names also apply to the URL userinfo and quarantined URLs described
  under "Import behaviour changes" below.

### Import report redaction to end of text (GHSA-84pr-239v-mv8x)

- Report text and imported names are redacted from the first credential
  indicator (a credential name with a separator, or `Bearer`, `Basic`, `Token`
  or `Digest`) to the end of the text. Names such as `Basic auth` now read
  `Basic <redacted>`; rename them after import if you want them back.
- An operation key or external reference that redaction changes now ends in
  `#<16 hex digits>`, keyed by your profile's credential key. Requests imported
  by an earlier build whose operation keys held a credential indicator get new
  keys on the first reimport after upgrading, so the reimport plan shows them
  as removed and added. Review that plan before applying it.

### Load runs: exit codes and CSV (#565, #566)

`anvil load run` now decides its exit code from the send ledger. A chained
plan in which one step failed an assertion exits 2 even if a later step timed
out or failed at transport; scripts that treated such runs as exit 1 should
treat 2 as "assertion failure". The summary line now reads `<completion>:
iterations N started, …` followed by a `sends:` line. In the summary and
timeline CSVs, values with no measurement behind them are empty instead of
`0`: the latency rows of a distribution without samples (except `count`),
`timeouts_censored,elapsed_max_us` without timeouts, and the start-lag cells
of closed and iteration runs. Spreadsheets should treat an empty cell as "not
measured".

### Gateway profile console links (#567)

Saving a gateway profile now refuses a `console_url` that is not an absolute
`https` or `http` URL with a host and no user name or password. Fix or clear
such a link before saving the profile again. An imported profile keeps its
link, but the desktop will not open an invalid one, and `anvil gateway list`
reports it as refused.

### gRPC diagnostics (#570)

`app.grpc_status` names owner `unknown` when no message arrived before the
status. On a trusted Ferrum profile, such a status may add
`ferrum.grpc_status_outcomes`. On gRPC requests, `ferrum.marker.inconsistent`
now fires for a token on a 4xx, beside grpc-status 0, or
`overload`/`config_stale` on a gRPC error over HTTP/1.1 or HTTP/2.
`ferrum.marker.absent` now fires for an unmarked 5xx. Tooling that filters
findings by owner or code should account for these. The findings catalog
version is `2026.11.17-1`.

### Import behaviour changes (#563, #564, #575, #583, GHSA-c236-7r9g-c9p2)

- Imports from Postman, Insomnia, cURL and HAR can produce different requests
  than before:
  - A URL with `user:password@` imports with Basic auth. A userinfo of exactly
    variable references is kept; anything else, a literal user name included,
    becomes required `{{auth_<16 hex digits>_<field>}}` variables (see above).
  - A URL with a template before the end of its host part and an `@` anywhere
    (`https://{{tenant}}.example.com/x?to=a@b`) imports as
    `{{url_<16 hex digits>}}` (listed in `redactions[].placeholder`) with a
    `url_quarantined` warning: re-enter it. With
    credentials included it is kept as written. `{{baseUrl}}/x?email=a@b` is
    kept as written.
  - An OAuth 2 token or authorization URL with credentials in it (Postman,
    Insomnia, OpenAPI, Swagger) imports without them; supply them as the
    client credentials.
  - A cURL `-u`, or a request's own or disabled auth, wins over URL userinfo.
  - Credential-named path variables and credential members of Insomnia
    environment arrays become required `{{placeholders}}` unless credentials
    are included.
  - Postman and Insomnia query values with exactly re-encodable escapes are
    stored decoded.
  - cURL `-d @file` imports as POST.
- Import report messages no longer quote source values, and report pointers
  and imported names redact recognised credential patterns:
  tooling that reads report pointers, external references or imported names sees
  `<redacted>`, `<url redacted>` or `{{…}}` there, and a pointer token that
  was redacted ends in `#` and a digest. cURL diagnostics no longer quote the
  ignored URL, option value or command tail; use the pointer.
- Share-safely and encrypted-transfer exports extract a URL field (`url`,
  `token_url`, `authorization_url`, any `*_url`) whose userinfo is not exactly
  references or whose host part mixes a template with an `@`: share-safely
  recipients see `{{secret_url}}` (or `{{secret_<field>}}`) and supply the
  URL; an encrypted-transfer import restores it.
- Requests imported by an earlier build are not changed. Re-import a
  collection to pick these up; **Reimport a changed spec…** / `anvil
  reimport-spec` shows the differences before applying them.

## 0.1.7

### Before you upgrade

If you may want to go back to 0.1.5 or earlier, keep a copy of each profile
with your current build before opening it with 0.1.7. An earlier build cannot
open the profile once 0.1.7 has enrolled it, and the checkpoint 0.1.7 takes
before it migrates the database is deleted when enrollment rotates the data
key (below), so it is not a way back. Use one of these:

- **Full backup** (any profile): in the desktop, **Export** → **Whole app
  backup**; in the CLI (omit `--passphrase-stdin` for an OS-keychain profile):

  ```sh
  ANVIL_EXPORT_PASSPHRASE='<export passphrase>' \
    anvil --profile PROFILE --passphrase-stdin export --mode backup --out profile.anvilbak
  ```

  It keeps everything in the profile: workspaces with their vault secrets,
  attachments, history, load reports, app settings and API standards
  rulesets. Everything after a short readable header (format version, cipher,
  and the key-derivation costs and salt) is encrypted and authenticated with
  the export passphrase. Restoring it needs only that passphrase, not the
  profile's passphrase, recovery key or OS keychain entry. See
  [Full backups](storage-and-recovery.md#full-backups).
- **Encrypted-transfer bundle** (any profile): in the desktop, **Export** →
  **This workspace** → **Encrypted transfer**, one workspace at a time; in the
  CLI, `--mode encrypted --out workspaces.anvil` in the command above (every
  workspace, or one with `--workspace`). It keeps the workspaces but not app
  settings, load reports or spec-import records. Only its vault is encrypted
  with the export passphrase: the vault secrets and the literal secrets Anvil
  took out of sensitive fields. The workspace objects (names, URLs, header and
  body text), attachments and history are ordinary ZIP entries that anyone
  holding the file can read, and a credential typed into a body or URL is
  exported as written. Store the bundle as sensitive. A bundle exported by
  0.1.7 still imports into an earlier build, so this one can also be made
  after upgrading. See [Export and import](storage-and-recovery.md#export-and-import).
- **Copy of the profile directory** (passphrase profiles only): close every
  copy of Anvil and copy the profile directory somewhere outside the data
  directory. The copy keeps the old passphrase and recovery-key wraps, so the
  earlier build unlocks it with the old passphrase or recovery key, with
  nothing lost. This does not work for an OS-keychain profile: it has no
  passphrase or recovery-key wrap, only its OS keychain entry, and enrollment
  deletes that entry (or overwrites it with a keyless marker), so the copy can
  no longer be unlocked.

Do not rely on a **Share safely** export, the default mode of `anvil export`:
it leaves out vault secrets and turns literal secrets into placeholders. A
restored backup or imported bundle names linked local files by path only, so
choose those files again, and a workspace written by an import or restore does
not use this device's workload identity until you allow it again in the
workspace's settings.

To go back, restore the backup or bundle with the earlier build into a new,
empty profile, with the **Replace** policy. `anvil import` writes into an
existing profile (the one `--profile` names, or the first one), and its
default policy, Merge, keeps the target profile's app settings instead of the
backup's. With the 0.1.5 CLI:

```sh
# Create the recovery profile: its new passphrase on stdin; save the recovery key it prints.
anvil --passphrase-stdin profile create rollback
# Preview, then restore. Each command reads the recovery profile's passphrase on stdin.
ANVIL_EXPORT_PASSPHRASE='<export passphrase>' \
  anvil --profile rollback --passphrase-stdin import profile.anvilbak --dry-run
ANVIL_EXPORT_PASSPHRASE='<export passphrase>' \
  anvil --profile rollback --passphrase-stdin import profile.anvilbak --policy replace
```

Replace restores a full backup's app settings only into a profile that holds
no other workspace. In the desktop, create a new profile, then **Import** the
file with **Replace existing**; the desktop adds an empty "My workspace" to a
new profile, so it keeps that profile's app settings, and the CLI restore above
is the way to bring back the backup's app settings too.

### Policy enrollment

0.1.7 does not unlock a profile created by an earlier build until you enroll
it, and a recovery-key unlock does not skip this step. Enrollment rotates the
data key and re-encrypts the profile's active data:

- **Desktop:** the lock screen shows **Enroll legacy policy**. Enter the
  current passphrase (an OS-keychain profile asks for none), enter a new
  passphrase twice, confirm the native prompt and save the replacement recovery
  key it shows before confirming. For a profile linked with a fresh-login
  requirement, choose **Use recovery key** on the lock screen first and enter
  the current recovery key: the desktop does not sign in to the provider during
  enrollment, so it refuses the passphrase for such a profile.
- **CLI:** supply the current passphrase, the new passphrase and the saved
  replacement recovery key on consecutive stdin lines:

  ```sh
  anvil --profile PROFILE --passphrase-stdin profile enroll-policy \
    --confirm-replace-unknown-policy --new-passphrase-stdin
  ```

  For an OS-keychain profile omit `--passphrase-stdin`. To enroll with the
  recovery key, leave out the global `--passphrase-stdin` and pass
  `--recovery-key-stdin` to `enroll-policy`; the first stdin line is then the
  current recovery key:

  ```sh
  anvil --profile PROFILE profile enroll-policy --recovery-key-stdin \
    --confirm-replace-unknown-policy --new-passphrase-stdin
  ```

After enrollment only the new passphrase and the new recovery key unlock the
profile, and an OS-keychain profile becomes a passphrase profile. A verified
linked identity is kept; a profile linked with a fresh-login requirement
enrolls with its current recovery key. With no surviving identity policy, you
confirm replacing it with an unlinked one. Details:
[Deliberate local key rotation](storage-and-recovery.md#deliberate-local-key-rotation)
and [Where the binding is stored](identity.md#where-the-binding-is-stored).

### Database schema 6

Enrollment moves the profile database from schema 3 to schema 6. Earlier
builds then refuse that database, and any full backup made by 0.1.7, as
written by a newer version. Portable bundles keep their format, so a bundle
exported by 0.1.7 still imports into an earlier build.

- Close every earlier build before upgrading.
- Before migrating, 0.1.7 copies the database into the profile's
  `checkpoints` folder as `<time>-before-schema-<version>.db`. If that copy
  cannot be written, enrollment fails until space is freed. The copy is sealed
  with the old key, so enrollment's key rotation deletes it, with any older
  checkpoint.
- To go back to an earlier build, close every copy of Anvil and either
  restore the full backup or the encrypted-transfer bundle into a new, empty
  profile of the earlier build with the Replace policy, or put back a
  passphrase profile's directory copy and unlock it with the old passphrase or
  recovery key (see [Before you upgrade](#before-you-upgrade)). Everything
  changed since the copy was made is lost.

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
- Windows 7 is no longer supported (Tauri 2.12 builds with `windows` 0.62 and
  `webview2-com` 0.39).
- `anvil send --trust-ferrum HOST` trusts the host for that send only; add
  `--save-trust` to save a Ferrum gateway profile. A profile an earlier build
  saved this way is still trusted; list and remove it with `anvil gateway list`
  and `anvil gateway remove`, or **Remove gateway** in the desktop app.
- Rust code: `SecretResolver` methods no longer have default
  implementations, so a wrapping resolver must forward each one.

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
