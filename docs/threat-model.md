# Threat model

Scope: the Anvil desktop app, the `anvil` CLI, the load worker and their local
data. Out of scope: the security of the APIs being tested, and malware already
running as the user inside an unlocked Anvil process (we do not claim protection
against it).

## Assets

1. Credentials: vault secrets, auth material (API keys, passwords, tokens, HMAC
   secrets, private keys, PKCS#12 bundles), OAuth tokens in memory.
2. Workspace data: URLs, headers, bodies, history, datasets — often sensitive.
3. The data-encryption key and its wrappings (passphrase, recovery key, keychain).
4. Integrity of diagnostics: users act on them; false *confirmed* attribution is
   a defect class of its own.
5. Other people's systems: Anvil can generate load; it must not do so by
   accident.

## Trust boundaries

| Boundary | Untrusted side | Controls |
|---|---|---|
| Network responses → app | Response bytes, headers, TLS peers, stream messages | Rendered as inert text/hex only; strict CSP (no remote script/frame/fetch); bounded buffering and decompression; typed parsing; no response can call IPC or change settings |
| Imported files → app | Bundles, OpenAPI/WSDL/Postman/Insomnia/cURL/HAR | Size/node/ref limits, no external `$ref`/DTD fetching, XXE disabled, zip traversal/symlink/bomb checks, checksums, preview before apply, trust normalisation, nothing executes on import, scripts kept as inert notes; a spec import into an existing workspace lands under an import root that keeps the source's own auth (explicitly none when it has none), variables and settings, and its requests resolve no variable, environment or auth of the destination workspace, no value extracted during a run or load chain by a request outside that root, no dataset row and no JWT-SVID of this device (Workload API or token file), and the request's selected TLS profile is refused when its client identity is bound to no host (a proxy's own TLS profile still applies to the connection to that proxy), until the user opens that root on this device (desktop control pending); cookies and cached OAuth tokens are per workspace, not per import root; cookies follow host rules, and imported OAuth profiles are cached under their own folder; imported linked local files stay inert until bound on this device for the request or dataset that names them (desktop control pending); a bundle or backup writes into a workspace stored here only once the user approves that workspace for the exact file that was previewed (its SHA-256); an OAuth profile imported from a bundle never keeps the bundle's token-cache id |
| Webview → Rust backend | A compromised renderer | Narrow typed commands; lock enforced in backend; secrets returned only as references; file access only through the backend's own native dialogs: file commands take an opaque, purpose-bound grant instead of a path (grants expire, are revoked on lock, a choice in progress when the app locks grants nothing, and a read is refused if the file or a folder on its path was replaced); a request spec from the webview may not name a linked local file; a JWT-SVID token file is read only if it was bound in the vault through the dialog; capability allowlist (`capabilities/default.json`: no open or save dialog, no filesystem plugin). A linked local file that a saved request, gRPC schema or dataset names (for example one from an imported bundle) is read only once that exact file was bound on this device through the dialog (purpose `linked_file`) for that request or dataset; the desktop control that opens this dialog is pending, so the app does not yet offer a way to bind one |
| Anvil → destinations | User mistakes, redirects | TLS verification on by default; bypass scoped to a profile with persistent warnings; client certs bound to hosts; credentials stripped on cross-origin redirects; load runs need explicit acknowledgement; imported plans untrusted |
| Disk | Other local users, backups, forensic reads | Everything sealed with AEAD; key wrapping with Argon2id or OS keychain; leak audit covers WAL/journal/blobs |
| Worker process | — | Job over stdin (not argv/env), only referenced secrets, killed with the parent, no inherited UI state |
| Remote diagnostics text | Server-authored explanations | Never used as instructions; findings come from local rules and catalog wording only |

## Threats and mitigations (STRIDE-style highlights)

- **Spoofed gateway markers** (a backend injects `X-Gateway-Error`): markers only
  count for declared gateways, capped at *likely*; lookalike tests in the lab.
  After redirects, attribution comes from the origin that produced the final
  response (its own profile and TLS requirement), never the original request's.
- **Credential leakage via redirects or logs:** cross-origin credential stripping;
  redaction by name and by exact secret value across records, history, reports,
  exports and support bundles; query-string key warning. Headers, query
  parameters and form fields the user marks sensitive are redacted by name and
  by value. URL path segments, query names and values and fragments are
  compared after percent-decoding, and a component that hides a secret is
  replaced whole, so no reversible encoding of it is kept; a URL that still
  reveals one once decoded keeps only its scheme and authority. Userinfo is
  always replaced, in scheme-relative URLs (`//user:pw@host`) too. URLs inside
  headers (`Location`, `Content-Location`, `Referer`, the `Link` targets and
  `anchor` parameters, the `Refresh` target) and URL-valued diagnostic
  evidence (the authorization endpoint of a login redirect, also where the
  explanation quotes it) get the same URL redaction. A collection
  run drops a content-encoded response body it cannot check for sensitive run
  values.
- **Redirect hops:** every hop is evaluated for its own target. Once a redirect
  leaves the request's origin (scheme, host or port), unless
  `redirects.forward_credentials_cross_origin` is on, configured headers that
  carry credentials are dropped for the rest of the chain: known credential
  names (`Authorization`, a manual `Cookie` header, `X-API-Key`, names
  containing `token`, `secret`, `auth`, ... or ending in `-key` / `_key`),
  headers marked sensitive, and headers whose value holds a secret variable.
  The prepared request notes the names (never the values) of the headers
  withheld. Auth (headers, API-key query parameters and API-key cookies) is no
  longer applied. The workspace cookie jar is separate: on each hop it sends
  the stored cookies that match that hop's target under cookie rules, which
  do not separate ports (nor schemes, for cookies without `Secure`). A
  redirect that would resend a body to another origin is not followed when
  preparing the body substituted a secret variable, whatever the body type
  and its encoding (form fields are percent-encoded, GraphQL variables are
  re-serialized), or when the body holds a resolved secret value byte for
  byte (an attachment, say). This also covers 301/302 redirects that retain
  the body, such as for PUT, PATCH and DELETE. Setting
  `redirects.forward_credentials_cross_origin` lifts this refusal. The TLS
  client identity is never presented to another origin unless a TLS profile
  is bound to it, whatever the redirect policy.
  The TLS settings are prepared for each hop's target; a hop whose route or
  TLS settings cannot be prepared is not followed.
- **Redirects and NO_PROXY:** the proxy route is decided for each hop's host
  and port. A redirect from a NO_PROXY host to any other host goes through the
  proxy, and a redirect to a NO_PROXY host goes direct, so a server can only
  move a request onto or off the proxy within the NO_PROXY list the user
  configured. Each attempt records its own route; the record's proxy and TLS
  summary describe the hop that produced the final response.
- **Replay by the client itself:** HMAC nonce, DPoP proof and JWT regenerated per
  send; no automatic retry of possibly-processed non-idempotent requests.
- **Replay of 0-RTT early data by the network:** data sent before a TLS 1.3 / QUIC
  handshake completes can be captured and replayed to the server by anyone on the
  path (RFC 8446 §8). Early data is off by default and opt-in per settings layer;
  only GET, HEAD, OPTIONS and explicitly listed idempotent methods (PUT, DELETE,
  TRACE) are sent as early data, a policy listing any other method is refused
  before traffic, imports turn the opt-in off, and load runs refuse it. An accepted
  early request carries a finding that says it could be replayed. The retry after
  `425 Too Early` happens once, after the handshake, only for eligible requests.
- **Session tickets:** the tickets early data needs are secrets that let the
  holder resume a session. They are kept in memory only, per workspace, transport,
  host and port, TLS profile and client identity, never persisted or exported, and
  dropped with pooled connections and OAuth tokens when the vault locks.
- **Accidental load against third parties:** explicit preflight acknowledgement,
  destination list, imported plans untrusted, bounded arrivals and abort rules.
- **Malicious bundle trying to enable insecure settings:** import normalisation
  (TLS bypass, plain-HTTP marker trust, credential forwarding, legacy HMAC,
  scenario/plan trust) with warnings in the preview.
- **Imported reference to a local file:** a linked local file
  (`AttachmentRef::LinkedFile`) names a path on the machine that made it. On
  any other device, and on this one until that exact file is bound in the
  native dialog (`file_choose`, purpose `linked_file`) for the request or
  dataset that names it, that request, gRPC schema or dataset is refused
  before anything is read or sent. The desktop control that opens this
  dialog is pending, so the app does not yet offer a way to bind one. A
  binding (`anvil_app::linked_files`) covers one request or dataset and one
  path, so a later import naming the same path cannot use it, and a bundle
  import drops the bindings of every request and dataset it overwrites.
  Bindings live in the vault, are never exported and cannot be created by an
  import. The bundle import preview lists every linked file the bundle names.
  The CLI cannot bind a linked file, but it reads one bound in the desktop
  when it runs that saved request or dataset from the same profile. A load
  run reads each bound file once, in the app, and hands the worker the bytes:
  the worker never opens a local path.
- **Imported collection using the destination's credentials:** a spec import
  into an existing workspace lands under an import root that carries the
  source's own auth, variables and settings (explicitly "no auth" when it has
  none). Its requests never resolve the destination workspace's variables,
  auth or environments, secret or not. In a collection run or load chain
  they never see a value extracted by a request outside the import root, or
  the dataset row, and a value they extract is not visible outside it: each
  prepared request carries its import root (`ExecutionContext::scope`) and
  run-local values are handed only to steps of the same scope. They never
  present this device's JWT-SVID (Workload API or token file), and a TLS
  profile whose client identity (certificate or X.509-SVID) is bound to no
  host is refused for them. All of this holds until the user explicitly
  opens the import root to the workspace on this device
  (`App::set_import_root_workspace_scope`; the desktop control is pending);
  that choice is never imported. TLS trust settings and proxies selected by
  the destination still apply, and a client identity bound to hosts is
  presented only to those hosts.
- **Altering an encrypted bundle:** the vault (secrets and the sensitive
  literals moved out of the objects) is sealed with associated data that
  covers the bundle format version and the SHA-256 of every other entry by
  name: the manifest (kind, mode, placeholders and vault parameters
  included), `workspace/objects.json`, each attachment and the history. A
  change to any other entry, or another entry added or removed, fails the
  vault's authentication, and the import is refused before any secret or
  literal is restored and before anything is written. Recomputing
  `checksums.json` does not help: checksums only detect corruption. Each
  literal is restored only to the field the export recorded (listed in the
  manifest's placeholders), and only while that field still holds its
  placeholder; any other mismatch refuses the whole import. Bundles of
  earlier builds (format 1) sealed the vault with constant associated data
  that bound nothing else in the archive; an encrypted bundle of that format
  is refused, with or without its passphrase, and must be exported again. A
  bundle whose mode and vault disagree (an encrypted-transfer manifest
  without a vault, or a share-safe one with one) is refused. Removing the
  vault, with the manifest relabelled to match, does not fail
  authentication: it turns the bundle into a share-safe one, from which no
  secret or literal is restored. A passphrase given for a share-safe bundle
  is refused rather than accepted as though it verified the bundle.
- **Reading an encrypted bundle:** only the vault is encrypted. The objects
  (names, URLs, header and body text), attachments and history are ordinary
  zip entries that anyone holding the file can read, in either mode. Secrets
  and sensitive literals never appear in them, but credentials typed into
  free text (a body or URL) are only warned about on export. Full backups are
  ANVILBAK files, encrypted as a whole (below).
- **Bundle key-derivation costs:** the Argon2id costs in a bundle manifest are
  read before the vault authenticates, so costs outside documented bounds
  (memory, passes, lanes, memory × passes, salt length; see
  [storage-and-recovery.md](storage-and-recovery.md#export-and-import)) are
  refused before any derivation.
- **Bundle identities:** bundle secrets and every workspace-scoped object
  must belong to a workspace in the bundle, and references between objects
  must stay within their workspace; object ids must be unique, and a Duplicate
  import gives every object, revision and secret a new id. A Replace import
  never overwrites or re-owns a secret that a workspace outside the bundle
  owns, nor overwrites an object stored in another workspace; it is refused
  instead.
- **Attachments named without their bytes:** stored attachments are found by
  content hash alone, so a reference whose bytes a bundle or full backup does
  not carry would resolve to content already stored on this device, possibly
  another workspace's. Such a file is refused when content with that hash is
  stored here. Otherwise it is accepted, and the preview and report name each
  request or dataset that will fail until its file is attached again: the
  reference is legitimate after a stored blob was lost, or for a request
  created without its file. If content with that hash is stored later, the
  reference resolves to it.
- **Bundle writing into an existing workspace:** workspace ids are not
  secret, so any bundle can claim a workspace already stored here. Merge and
  Replace into a stored workspace assume the bundle is trusted: what they write
  there can use that workspace's vault secrets. The preview lists each such
  workspace as an error and the import is refused unless the user confirms each
  one after the preview. Encryption proves nothing about who wrote a bundle;
  for an encrypted bundle whose vault opened, it only shows the bundle was not
  altered after it was exported (see "Altering an encrypted bundle"). A
  share-safe bundle has no passphrase at all, and nothing shows it was not
  altered. Duplicate never writes into a stored workspace and is the safe
  choice for untrusted bundles.
- **Secret scope:** a request resolves only secrets its own workspace owns; a
  reference to any other stored secret fails before anything is sent. A saved
  request is prepared only in its own workspace and with folders of that
  workspace, and a scenario or load plan runs only requests and a dataset of
  its own workspace. A Merge import keeps a stored object whose id a bundle
  reuses in another workspace, and imported items never use it; imported
  requests and datasets use only attachment bytes their bundle carried. This
  scope is the workspace boundary: it does not separate items inside one
  workspace, so anything imported into a workspace (see above) can use its
  secrets.
- **Lock bypass:** backend refuses privileged commands while locked; key dropped;
  sessions/executions/load runs stopped.
- **Reading or altering a full backup:** the whole payload (objects, bodies,
  settings, history, attachments and secrets) is one AEAD envelope under the
  export passphrase, with the header as associated data, so a copy of the file
  reveals nothing and any change to it is refused before anything is restored.
  Only the header (at most 4 KiB of JSON) is parsed before authentication, to
  bound its key-derivation costs before derivation. Authentic contents are
  still type-checked; every workspace-scoped object, workspace secret and
  load report must belong to one of the backup's own workspaces (revisions to
  their request's), and history records of any other workspace are left out
  with a warning; stored attachments named without their bytes are checked as
  above.
  The import trust normalisation applies to the backup's app settings as to
  workspace, folder and request settings: cross-origin credential forwarding
  and 0-RTT early data are turned off, like TLS bypasses, plain-HTTP marker
  trust, legacy HMAC and scenario and load plan trust.
- **App settings from a backup:** app settings are the lowest settings layer
  of every workspace's requests, and their DNS overrides, resolver and other
  defaults are not something normalisation can judge. Replace therefore
  restores the backup's app settings only when every workspace stored here
  is one the backup claims (each of which the user must approve); while the
  profile holds any other workspace, Replace keeps this profile's app
  settings and says so in the preview and the report. Merge always keeps
  them.
- **Restoring into existing workspaces:** a full backup must be your own or
  otherwise trusted. Its passphrase proves only that the file was not
  altered, not who made it, and a restore writes every item under its own
  id. Restoring into a workspace already stored here (Merge or Replace) is
  refused unless the user approves each such workspace after the preview,
  as for bundles (desktop checkbox, `anvil import --into-existing`), because
  what it writes there can use that workspace's vault secrets. Replace also
  refuses a backup that would overwrite an object, history record or load
  report stored in another workspace, or a secret stored here under another
  owner.
- **Legacy full backups:** full backups written as zip bundles by earlier
  builds, whose vault authenticated nothing else in the archive, are
  refused on import: as a legacy full backup when the manifest names kind
  `backup` or mode `full_backup` or the archive carries app settings, and
  otherwise (relabelled as an encrypted workspace bundle) because its vault
  is format 1; a manifest claiming the current format fails the vault's
  authentication. No secret or sensitive literal from such a vault is ever
  restored, and bundle exports never produce them. Their other entries were
  never encrypted: a copy of one exposes its objects, attachments, settings
  and history, and a copy stripped of its vault is only a share-safe bundle
  of whatever it now contains, as anyone could write.
- **Test backdoors shipped:** E2E WebDriver and env unlock only under the `e2e`
  feature; release check fails if present (ADR 0009).
- **Supply chain:** pinned dependencies with lockfiles, `cargo deny` (licenses,
  advisories, sources), SBOMs, secret scanning in CI.

## Residual risks

- An encrypted bundle's objects, attachments and history are readable by
  anyone holding the file; only its vault is encrypted (see "Reading an
  encrypted bundle"). Share one only with people who may read its
  contents; a full backup encrypts everything.
- An encrypted bundle's passphrase shows only that the bundle is one some
  export sealed with it: an older, authentic bundle exported with the same
  passphrase still opens. Use a new passphrase for each export when it
  matters which one is imported.
- A bundle the user confirms writing into an existing workspace is trusted
  with that workspace's secrets (see "Bundle writing into an existing
  workspace").
- A secret's owning workspace is stored as plaintext metadata next to the
  encrypted record and is not authenticated with it; changing it needs local
  write access to the database.
- Keychain-protected profiles are as strong as the OS session.
- Memory of the running unlocked process can contain secrets; zeroization is
  best-effort.
- Unsigned development builds cannot prove provenance; release signing is blocked
  on owner credentials (see `docs/release.md`).
