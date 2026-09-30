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
| Imported files → app | Bundles, OpenAPI/WSDL/Postman/Insomnia/cURL/HAR, API-standards rulesets | Size, node, string-byte, reference and sample-generation limits; no external `$ref`/DTD fetching (XXE disabled); zip traversal/symlink/bomb checks; checksums; preview before apply; trust normalisation; nothing executes on import (scripts kept as inert notes). Spec imports into an existing workspace are sealed under an import root; bundle imports and restores seal this device's workload identity; writing into a stored workspace needs approval for the exact previewed file. See the import threats below. |
| Webview → Rust backend | A compromised renderer | Narrow typed commands; lock enforced in the backend; secrets returned only as references. File access only through the backend's own native dialogs: file commands take an opaque, purpose-bound grant instead of a path (grants expire and are revoked on lock, a choice in progress when the app locks grants nothing, and a read is refused if the file or a folder on its path was replaced). A request spec from the webview may not name a linked local file (a linked path is written into a saved request or dataset only by a relocation, from the backend's own dialog), and a JWT-SVID token file is read only if it was bound in the vault through the dialog. Capability allowlist (`capabilities/default.json`): no open or save dialog, no filesystem plugin. |
| Anvil → destinations | User mistakes, redirects | TLS verification on by default; bypass scoped to a profile with persistent warnings; client certs bound to hosts; credentials stripped on cross-origin redirects; load runs need explicit acknowledgement; imported plans untrusted |
| Disk | Other local users, backups, forensic reads | Everything sealed with AEAD; key wrapping with Argon2id or OS keychain; leak audit covers WAL/journal/blobs |
| Worker process | — | Job over stdin (not argv/env); only referenced secrets; killed when the controller drops it and cancels itself when its parent goes away (stdin EOF); no inherited UI state |
| Remote diagnostics text | Server-authored explanations | Never used as instructions; findings come from local rules and catalog wording only |

## Threats and mitigations (STRIDE-style highlights)

### Diagnostics

- **Spoofed gateway markers** (a backend injects `X-Gateway-Error`): markers
  only count for declared gateways and are capped at *likely*; the lab tests
  lookalikes. After redirects, attribution comes from the origin that
  produced the final response (its own profile and TLS requirement), never
  the original request's. See [diagnostics.md](diagnostics.md).

### Requests and redirects

- **Credential leakage via redirects or logs:** cross-origin credential
  stripping; redaction by name and by exact secret value across records,
  history, reports, exports and support bundles; a warning for keys in query
  strings.
  - Headers, query parameters and form fields the user marks sensitive are
    redacted by name and by value.
  - URL path segments, query names and values, and fragments are compared
    after percent-decoding, and a component that hides a secret is replaced
    whole, so no reversible encoding of it is kept. A URL that still reveals
    one once decoded keeps only its scheme and authority. Userinfo is always
    replaced, in scheme-relative URLs (`//user:pw@host`) too.
  - URLs inside headers (`Location`, `Content-Location`, `Referer`, `Link`
    targets and `anchor` parameters, the `Refresh` target) and URL-valued
    diagnostic evidence (the authorization endpoint of a login redirect, also
    where the explanation quotes it) get the same URL redaction.
  - A collection run drops a content-encoded response body it cannot check
    for sensitive run values.
- **Redirect hops:** every hop is evaluated for its own target. Unless
  `redirects.forward_credentials_cross_origin` is on, once a redirect leaves
  the request's origin (scheme, host or port):
  - configured headers that carry credentials are dropped for the rest of the
    chain: known credential names (`Authorization`, a manual `Cookie` header,
    `X-API-Key`, names containing `token`, `secret`, `auth`, … or ending in
    `-key` / `_key`), headers marked sensitive, and headers whose value holds
    a secret variable. The prepared request notes the names (never the
    values) of the headers withheld;
  - auth (headers, API-key query parameters and API-key cookies) is no longer
    applied;
  - a redirect that would resend a body to another origin is not followed
    when preparing the body substituted a secret variable (whatever the body
    type and encoding: form fields are percent-encoded, GraphQL variables are
    re-serialized), or when the body holds a resolved secret value byte for
    byte (an attachment, say). This covers 301/302 redirects that keep the
    body, such as for PUT, PATCH and DELETE.

  The workspace cookie jar is separate: on each hop it sends the stored
  cookies that match that hop's target under cookie rules, which do not
  separate ports (nor schemes, for cookies without `Secure`). The TLS client
  identity is never presented to another origin unless a TLS profile is bound
  to it, whatever the redirect policy. TLS settings are prepared for each
  hop's target, and a hop whose route or TLS settings cannot be prepared is
  not followed.

  SSE and WebSocket handshakes and gRPC calls use the same jar, with the
  same rules and workspace isolation (a `ws://` or `grpc://` URL counts as
  `http://`, `wss://` or `grpcs://` as `https://`). A handshake's (or a gRPC
  call's) `Set-Cookie` is stored when the session ends, and not at all when
  the profile was locked or the session's workspace deleted since the
  session started (the same fences as for HTTP responses, below).
- **Redirects and NO_PROXY:** the proxy route is decided for each hop's host
  and port. A redirect from a NO_PROXY host to any other host goes through
  the proxy, and a redirect to a NO_PROXY host goes direct, so a server can
  only move a request onto or off the proxy within the NO_PROXY list the user
  configured. Each attempt records its own route; the record's proxy and TLS
  summary describe the hop that produced the final response.
- **Replay by the client itself:** HMAC nonce, DPoP proof and JWT regenerated
  per send; no automatic retry of possibly-processed non-idempotent requests.
- **Replay of 0-RTT early data by the network:** data sent before a TLS 1.3 /
  QUIC handshake completes can be captured and replayed to the server by
  anyone on the path (RFC 8446 §8). Early data is off by default and opt-in
  per settings layer. Only GET, HEAD, OPTIONS and explicitly listed
  idempotent methods (PUT, DELETE, TRACE) are sent as early data; a policy
  listing any other method is refused before traffic. Imports turn the opt-in
  off and load runs refuse it. An accepted early request carries a finding
  that says it could be replayed. The retry after `425 Too Early` happens
  once, after the handshake, only for eligible requests.
- **Session tickets:** the tickets early data needs are secrets that let the
  holder resume a session. They are kept in memory only, per workspace,
  transport, host and port, TLS profile and client identity, never persisted
  or exported, and dropped with pooled connections and OAuth tokens when the
  vault locks. A connection of an execution that began before the lock keeps
  none of the tickets it receives afterwards. Outside the early-data opt-in
  no ticket and no TLS 1.2 session is kept at all (such a connection could
  never resume one): only the key-exchange group each server chose.
- **Accidental load against third parties:** explicit preflight
  acknowledgement, destination list, imported plans untrusted, bounded
  arrivals and abort rules.

### Imports, bundles and backups

The mechanics are in [import.md](import.md#persisting-an-import-anvil-app)
and [storage-and-recovery.md](storage-and-recovery.md#export-and-import).

- **Hostile ruleset or spec given to the linter:** a ruleset is data, never
  code: rules name built-in functions only, regular expressions (in rules
  and in schema patterns) use the linear-time `regex` crate with a size
  limit, `extends` names built-in rulesets only and nothing is fetched or
  read; specs are parsed under the import bounds plus a member-name budget,
  `$ref` resolution is internal and depth-capped, and every walk is linear
  ([contract.md](contract.md#guarantees)). Text output escapes control
  characters, so a spec cannot inject CI workflow commands or terminal
  escape sequences.
- **Malicious bundle trying to enable insecure settings:** import
  normalisation (TLS bypass, plain-HTTP marker trust, credential forwarding,
  0-RTT early data, legacy HMAC, scenario/plan trust) with warnings in the
  preview.
- **Imported collection using the destination's credentials:** a spec import
  into an existing workspace lands under an import root that carries the
  source's own auth, variables and settings (explicitly "no auth" when it has
  none). Until the user opens the root to the workspace on this device, its
  requests never resolve the destination's variables, auth or environments;
  never see run values extracted outside the root or the dataset row (and
  values they extract stay inside it); never present this device's JWT-SVID
  (Workload API or token file); and are refused a TLS profile whose client
  identity (certificate or X.509-SVID) is bound to no host, including the
  proxy's. Opening a root (`App::set_import_root_workspace_scope`, the
  desktop's **Workspace scope** tab after a confirmation) is never imported.
  TLS trust
  settings and proxies selected by the destination still apply, and a client
  identity bound to hosts is presented only to those hosts. Cookies and
  cached OAuth tokens are per workspace, not per import root; cookies follow
  host rules, and imported OAuth profiles are cached apart from the
  workspace's own.
- **Imported bundle using this device's workload identity:** a bundle import
  or full-backup restore seals every workspace it writes into, on this device
  only and whatever the conflict policy. Its requests are refused a JWT-SVID
  from the Workload API or a token file, and a TLS profile (the request's own
  or its proxy's) presenting an X.509-SVID from the Workload API, until the
  user lifts the seal on this device. Seals are never exported or backed up.
  See [identity.md](identity.md#8-target-api-workload-identity-the-spiffe-workload-api).
- **Imported reference to a local file:** a linked local file
  (`AttachmentRef::LinkedFile`) names a path on the machine that made it. On
  any other device, and on this one until that exact file is bound in the
  native dialog (`file_choose`, purpose `linked_file`) for the request or
  dataset that names it, that request, gRPC schema or dataset is refused
  before anything is read or sent. The desktop offers **Choose file…** (or
  **Rebind…**) beside each linked file and shows whether it is bound; the
  backend binds only the exact file the request or dataset names, and its
  status query (`linked_file_status`) reads no file and never looks at a
  path that was not chosen.
  - A binding (`anvil_app::linked_files`) covers one request or dataset and
    one path, so a later import naming the same path cannot use it, and a
    bundle import drops the bindings of every request and dataset it
    overwrites.
  - Bindings live in the vault, are never exported and cannot be created by
    an import. The bundle import preview lists every linked file the bundle
    names.
  - The CLI cannot bind a linked file, but it reads one bound in the desktop
    when it runs that saved request or dataset from the same profile. A load
    run reads each bound file once, in the app, and hands the worker the
    bytes: the worker never opens a local path.
  - A reference whose file is now elsewhere on this device is repointed only
    with the user's pick in the native dialog (`file_choose`, purpose
    `linked_file_relocate`, for one request or dataset and the path it
    names). The webview names only which reference to repoint, never the new
    path, and that old path is never looked at on disk. The picked file must
    be a regular file, and its canonical path replaces the old one in that
    request or dataset only, in one transaction that also moves its binding.
    Other requests or datasets naming the old path stay unbound. A dialog
    open when the app locks, or another profile opens, relocates nothing.
  - **Privacy:** a relocated path is a path on this device, and it is saved
    in the request or dataset, so a later export carries it (as it carries
    any linked path, in every export mode). The export preview warns that
    requests or datasets name linked local files and lists each one with
    its path and the request or dataset that names it, as the receiving
    device's import preview does. Attach a copy instead to keep a local
    path out of a bundle.
- **Small spec or collection that expands during preview:** the expansions
  known to multiply work after parsing are charged before they run, against
  the import limits in [import.md](import.md#trust-and-safety-policy).
  JSON/YAML parsing charges nodes and the string bytes it keeps (YAML aliases
  included). OpenAPI `allOf` merging charges the payload budget and the
  `$ref` depth, and copied examples, defaults and merged schemas share a byte
  budget for the whole import. WSDL envelopes charge the schema nodes they
  look at and the bytes they generate (per envelope and per import) and cut
  recursive groups. An Insomnia v4 export with a repeated workspace, group or
  environment id is refused, and each resource is walked once. These are
  budgets, not a proof that every code path is linear: a preview can still
  take time and memory proportional to those limits.
- **Altering an encrypted bundle:** the vault is sealed with associated data
  covering the format version and the SHA-256 of every other entry
  (manifest, `workspace/objects.json`, each attachment, the history). Any
  change, addition or removal fails the vault's authentication before
  anything is restored or written; recomputing `checksums.json` does not help
  (checksums only detect corruption). Each literal is restored only to the
  field the export recorded, and only while it still holds its placeholder.
  Encrypted bundles of format 1 (earlier builds), which bound nothing else,
  are refused. A bundle whose mode and vault disagree is refused. Stripping
  the vault and relabelling the manifest yields a share-safe bundle from
  which nothing secret is restored, and a passphrase given for a share-safe
  bundle is refused.
- **Reading an encrypted bundle:** only the vault is encrypted. The objects
  (names, URLs, header and body text), attachments and history are ordinary
  zip entries that anyone holding the file can read, in either mode. Secrets
  and sensitive literals never appear in them, but credentials typed into
  free text (a body or URL) are only warned about on export. Full backups are
  encrypted as a whole.
- **Bundle key-derivation costs:** the Argon2id costs in a bundle manifest or
  backup header are read before anything authenticates, so costs outside the
  [documented bounds](storage-and-recovery.md#key-derivation-bounds) are
  refused before any derivation.
- **Bundle identities:** bundle secrets and every workspace-scoped object must
  belong to a workspace in the bundle, references between objects must stay
  within their workspace, and object ids must be unique. A Duplicate import
  gives every object, revision and secret a new id. A Replace import never
  overwrites or re-owns a secret that a workspace outside the bundle owns,
  nor overwrites an object stored in another workspace; it is refused
  instead.
- **Attachments named without their bytes:** stored attachments are found by
  content hash alone, so a reference whose bytes a bundle or backup does not
  carry would resolve to content already stored here, possibly another
  workspace's. Such a file is refused when content with that hash is stored
  here. Otherwise it is accepted, and the preview and report name each
  request or dataset that will fail until its file is attached again (the
  reference is legitimate after a stored blob was lost, or for a request
  created without its file). If content with that hash is stored later, the
  reference resolves to it.
- **Bundle or backup writing into an existing workspace:** workspace ids are
  not secret, so any bundle or backup can claim a workspace already stored
  here, and what Merge or Replace writes there can use that workspace's vault
  secrets. The preview lists each such workspace, and the import is refused
  unless the user confirms each one after the preview, for the exact file
  previewed (its SHA-256). A passphrase only shows that the file was not
  altered after export, not who wrote it; a share-safe bundle has no
  passphrase at all. Duplicate never writes into a stored workspace and is
  the safe choice for untrusted bundles. Replace also refuses a backup that
  would overwrite an object, history record or load report stored in another
  workspace, or a secret stored under another owner.
- **Reading or altering a full backup:** the whole payload (objects, bodies,
  settings, history, attachments and secrets) is one AEAD envelope under the
  export passphrase, with the header as associated data, so a copy reveals
  nothing and any change is refused before anything is restored. Only the
  header (at most 4 KiB of JSON) is parsed before authentication. Authentic
  contents are still type-checked and must belong to the backup's own
  workspaces, and the import trust normalisation applies to the backup's app
  settings too.
- **App settings from a backup:** app settings are the lowest settings layer
  of every workspace's requests, and normalisation cannot judge their DNS
  overrides, resolver and other defaults. Replace therefore restores them
  only when every workspace stored here is one the backup claims (each of
  which the user must approve). Otherwise Replace keeps this profile's app
  settings and says so; Merge always keeps them.
- **Legacy full backups:** zip-format full backups from early builds, whose
  vault authenticated nothing else in the archive, are refused, and no
  secret from such a vault is ever restored. Their other entries were never
  encrypted: a copy exposes its objects, attachments, settings and history.
- **An OAuth profile imported from a bundle** never keeps the bundle's
  token-cache id, so it cannot share a token with a profile stored here.

### Local data and the app

- **Secret scope:** a request resolves only secrets its own workspace owns; a
  reference to any other stored secret fails before anything is sent. A saved
  request is prepared only in its own workspace and with folders of that
  workspace, and a scenario or load plan runs only requests and a dataset of
  its own workspace. A Merge import keeps a stored object whose id a bundle
  reuses in another workspace, and imported items never use it; imported
  requests and datasets use only attachment bytes their bundle carried. This
  scope is the workspace boundary: it does not separate items inside one
  workspace, so anything imported into a workspace can use its secrets.
- **Lock bypass:** the backend refuses privileged commands while locked; the
  key is dropped; sessions, executions and load runs are stopped. Work still
  in flight at the lock cannot refill what it cleared, even if it is not
  canceled: each cache the lock clears is fenced by the generation the work
  started in, checked under the cache's own lock. A Workload API answer or
  an OAuth token that arrives after the lock to a call made before it is
  never cached. For an execution that began before the lock, nothing of the
  following is kept after it: its responses' cookies, the TLS
  configurations it prepares (which hold a client identity's private key),
  its connections (HTTP/1.1, HTTP/2 or HTTP/3) and the session tickets they
  receive. Session tickets are kept only by the 0-RTT ticket caches, which
  the lock check counts: a connection outside the early-data opt-in never
  resumes (rustls resumes a ticket only with the verifier instance that
  obtained it, and each such connection has its own), so its prepared TLS
  configuration's session store keeps neither TLS 1.3 tickets nor TLS 1.2
  sessions, only each server's key-exchange group. Prepared TLS
  configurations are kept per workspace, and a connection under the opt-in
  resumes only its own workspace's tickets. A workspace delete
  (`Engine::clear_isolation`) fences that workspace's caches the same way,
  with a generation of its own, so other workspaces' work is not affected:
  it drops the workspace's cookies, OAuth tokens, prepared TLS
  configurations, connections and session tickets, and for a request,
  session, gRPC call or token request of that workspace that started
  before the delete, none of those it prepares or receives afterwards is
  kept, even on a later redirect or retry, so they cannot reappear in a
  workspace restored with the same id.
  An execution takes the lock epoch and all of these generations between
  the same two points, with no lock or delete of its workspace started in
  between, so a snapshot never takes a transport or channel generation
  newer than its jar generation; a snapshot taken during a delete is
  post-delete for cookies and TLS material and keeps no connection, ticket
  or channel. For a context the app builds from storage
  (`App::build_context`), the snapshot is taken when the build starts,
  before anything is read for the workspace, and carried by the context
  (`ExecutionContext::epoch`, bound to the engine that took it and to the
  context's workspace): an execution whose context was built before a
  delete is fenced even when it starts executing after it (`App::send`, for
  example, builds the context off the runtime first), and a delete that
  lands before the snapshot leaves the build nothing to read. A workspace
  restored with the same id is not refused: its contexts are built after
  the delete. An execution of a context without a snapshot (a standalone
  request) or on another engine than the one that took it (a load run's
  engines) takes its snapshot when it starts.
  Pooled gRPC channels exist only on a load run's own engines
  (one per virtual-user slot); a call that began before a clear of its
  engine's channels does not return its connection to them. Neither the
  lock nor a workspace delete reaches into those engines; each stops the
  run instead, and the run's engines, with everything they hold, end with
  its worker process. Every load run is registered with its profile, by
  workspace, before its job is prepared (`App::register_load_run`):
  `App::lock` stops every registered run and a workspace delete stops that
  workspace's, and a lock or delete that landed before the registration is
  seen by it, so the job is never handed to a worker. A run stopped by its
  workspace's delete keeps no report, and a report of a deleted workspace is
  refused.
- **Test backdoors shipped:** E2E WebDriver and env unlock exist only under
  the `e2e` feature; the release check fails if they are present
  ([ADR 0009](adr/0009-test-hooks-excluded-from-release.md)).
- **Supply chain:** pinned dependencies with lockfiles, `cargo deny`
  (licenses, advisories, sources), SBOMs, secret scanning in CI.

## Residual risks

- An encrypted bundle's objects, attachments and history are readable by
  anyone holding the file; only its vault is encrypted. Share one only with
  people who may read its contents; a full backup encrypts everything.
- An encrypted bundle's passphrase shows only that some export sealed the
  bundle with it: an older, authentic bundle exported with the same
  passphrase still opens. Use a new passphrase for each export when it
  matters which one is imported.
- A bundle the user confirms writing into an existing workspace is trusted
  with that workspace's secrets.
- Someone with write access to the database can make records unreadable, or
  replace the whole database with an older copy; that rollback cannot be
  detected without state kept outside the database (see
  [storage-and-recovery.md](storage-and-recovery.md#schema-versions-and-migration)).
- Keychain-protected profiles are as strong as the OS session.
- Memory of the running unlocked process can contain secrets; zeroization is
  best-effort.
- Unsigned development builds cannot prove provenance; release signing is
  blocked on owner credentials (see [release.md](release.md)).
