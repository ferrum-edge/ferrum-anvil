# Changelog

## [Unreleased]

### Added

- API standards: check OpenAPI descriptions against a team's own rules.
  A ruleset (YAML or JSON, `anvil_ruleset: 1`) targets version-neutral
  objects (operations, parameters, responses, media types, schemas,
  properties, servers, tags, security schemes, or any node by JSONPath) with
  checks such as `pattern`, `casing`, `enumeration`, `includes`, `length`
  and `schema`, so one standard applies to Swagger 2.0 and OpenAPI 3.0, 3.1
  and 3.2 alike. Rulesets layer in order, may extend the built-in
  `anvil:recommended` rules and change or turn off inherited ones, and are
  checked when loaded. Each finding names the rule, the JSON Pointer and the
  line and column to edit, and how to fix it; body examples are validated
  against their schemas. New crate `anvil-contract`; see
  `docs/contract.md` and `samples/api-standards/`.
- CLI: `anvil lint-spec <spec> [--ruleset FILE]...` prints text, JSON or
  SARIF 2.1.0 (for code scanning) and exits with 2 when a finding reaches
  `--fail-on` (default `error`), and with 3 on a local error, including a
  description too large to lint completely unless `--allow-incomplete` is
  passed. It needs no profile.
- Desktop: a **Contract** view checks the workspace's imported OpenAPI
  descriptions, or a chosen file, against the profile's API standards,
  filters findings by severity and exports JSON or SARIF. Rulesets are kept
  in the app settings (new `api_standards`), added from a file (file purpose
  `ruleset`), replaced, enabled and removed there; a change that would not
  load with the others is refused. The settings dialog never changes them.

- Desktop: a linked local file that a saved request names (for example one
  imported from another machine) can be repointed to where the file is on
  this device. When the file is not chosen yet, or is missing or changed,
  **Choose new location…** opens the native dialog for that request and
  reference (`file_choose` with the new purpose `linked_file_relocate`,
  the referrer and `old_path`). The backend rewrites every reference to the
  old path in that request only (filing a new revision) to the canonical
  path of the regular file picked there, moves the request's binding to it
  in the same transaction, and never looks at the old path. Other requests
  naming the old path stay unbound. The editor then reloads the saved
  request. The new path is saved in the request, so a later export carries
  it; the export preview warns that linked local files are named. A load
  plan's linked-file dataset offers the same **Choose new location…**: the
  backend rewrites that dataset only, and the load view then reloads its
  datasets.
- Desktop: an imported collection's root folder has a **Workspace scope** tab
  in its folder settings. It shows whether the collection is isolated from
  its workspace (the default) or opened to it on this device, and which
  variables, environments, auth, run values and identities its requests
  resolve either way. **Open to workspace…** asks for confirmation first;
  **Isolate again** does not. Ordinary folders have no such tab, and an
  import still never opens a collection.
- CLI: `anvil storage-cleanup` prints the profile's last storage cleanup:
  when it ran, how many orphaned revisions it removed and stored files it
  released, and the kind and id of each stored object that did not decode
  (which keeps every stored file until it is repaired or deleted).
  `--json` prints it as JSON; `--now` runs a pass first. The desktop exposes
  the same record through the `storage_cleanup_last` command
  (`api.storageCleanupLast()`); it has no screen for it yet.
- Desktop: a linked local file that a saved request or dataset names (for
  example one from an imported bundle) can now be chosen on this device. The
  request's binary body or multipart part, its gRPC schema, and a load
  plan's dataset show the file with its binding state: chosen on this
  device, not chosen, or chosen but missing or changed since. **Choose
  file…** or **Rebind…** opens the native dialog for that request or
  dataset. The backend still binds only the exact file the reference names
  (canonical path, regular file, and that request or dataset), and the new
  read-only `linked_file_status` command reads no file and never looks at a
  path that was not chosen. The import preview points to where linked files
  are chosen, and the refusal of an unchosen linked file names Choose file…
  instead of saying the chooser is not available.
- Diagnostics: a `ferrum-edge-0.9.8` compatibility catalog for Ferrum Edge
  v0.9.8 (540 source-audited outcomes, `docs/audit/gateway-0.9.8-delta.md`).
  It knows the new `X-Gateway-Error: request_timeout` token: a route's total
  request timeout that expired before any backend held the request. Anvil
  reports it as a gateway-side timeout, not a slow backend, and on v0.9.8 a
  route-timeout 504 with `backend_timeout` means a backend held the request.
  Profiles declaring an older release report the new token as unknown.
- Load testing covers every gRPC call mode: client-streaming and
  bidirectional calls are load units of their own (`grpc_client_stream`,
  `grpc_bidi_stream`). Each unit is one call: the request's scripted
  messages, a half-close, and reading until the terminal status, on the same
  pooled channels as unary calls. Reports add the messages sent to the gRPC
  and stream counts; no round trip is claimed.
- Load testing covers UDP and DTLS through a MASQUE (CONNECT-UDP) proxy or a
  mesh HBONE datagram tunnel. Every exchange opens its own tunnel, and the
  report counts them (attempted, established, refused by the proxy, failed,
  timed out, canceled when the run stopped) with the tunnel setup time. An
  exchange whose tunnel did not open is incomplete, never "no response
  observed". The preflight names the proxy the traffic goes to (with
  variables resolved), and warns that traffic leaves this machine when
  either the target or the proxy is not local. Runs over different datagram
  paths are not compared. A plan that mixes direct and tunneled exchanges,
  or two kinds of tunnel, is refused (`mixed_tunnels`), and so is UDP
  through a MASQUE proxy while a proxy profile routes the request
  (`masque_through_proxy`), which the engine would refuse on every send.
  A target the HBONE profile's `NO_PROXY` list bypasses is sent directly,
  as the engine does: it counts as a direct exchange, and HTTP or gRPC to it
  is not refused in persistent mode (`hbone_persistent`).
- Load plan checks refuse a gRPC call the engine would refuse on every send,
  such as gRPC-Web with client or bidirectional streaming
  (`grpc_unsupported_combination`, quoting the engine's reason).

### Changed

- CI: Dependabot now covers GitHub composite actions, keeps patched vendored
  crates pinned, and leaves coordinated Tauri updates for a manual bump.
  Dependabot dependency PRs may require manual license and generated-contract
  updates before the required CI checks pass.
- New Ferrum gateway profiles default to `ferrum-edge-0.9.8` (desktop dialog
  and CLI), and the failure lab's default pin is Ferrum Edge v0.9.8
  (`lab/gateway/RELEASE.lock`, the release's published sha256 for every
  asset). v0.9.7 and v0.9.5 stay supported with `--release`; the nightly lab
  runs all three. Lab scenarios whose public signal changed in v0.9.8 (HBONE
  relay-synthesis refusals are now 403, an injected
  `X-Gateway-Upstream-Status` is stripped) expect the running release's
  signal.
- Encrypted-transfer bundles now use bundle format 2: the encrypted vault is
  bound to every other entry of the bundle, so a bundle changed after export
  is refused before any secret is restored. Encrypted bundles exported by
  earlier builds (format 1), including whole-profile zip backups from early
  development builds, are refused on import; export them again with this
  version. Share-safe bundles of either format still import, but only
  without a passphrase: one given for a bundle that is not encrypted is
  refused, since it would verify nothing.
- Desktop: opening another profile now locks the previous one and stops its
  runs, sends, sessions and load runs. Each records only into the profile it
  started under, and a load report that finished while its profile was
  locked is saved when that profile is next unlocked, never into another.
  Progress of a closed profile's work no longer reaches the new profile's
  window, and its sessions cannot be driven from there. A JWT-SVID token
  file is read through links (such as a Kubernetes projected token), but
  the file opened must be a regular file of at most 16 KiB.
- A bundle import or full-backup restore now seals, on this device only,
  every workspace it writes into, including Duplicate copies and new
  workspaces: its requests are refused this device's workload identity
  (JWT-SVID or X.509-SVID), that is a JWT-SVID from the Workload API or a
  token file, and a TLS profile, the request's own or its proxy's, whose
  client identity is an X.509-SVID from the Workload API, until you allow it
  with **Allow on this device** in the workspace settings' Auth tab or
  `anvil workspace allow-device-identity <workspace>` (a workspace id, or an
  exact name no other workspace has). A JWT-SVID from a vault or variable
  value is unaffected. Seals are never exported or backed up, so after
  restoring your own backup on a new device, allow each workspace you trust.
  The desktop now binds a token file by the path you chose rather than the
  file it resolved to, so a Kubernetes projected token keeps working after
  it rotates; a projected token file bound by an earlier build names the
  file of one rotation, so choose it again. A run or load run of a closed
  profile ends with a generic message in the new profile's window.
- Bundle imports now store the load plans and history records a bundle
  carries (exports include load plans, and list a plan left out because it
  names a deleted object among the excluded items), and a Duplicate import
  gives them new ids. A history record that is not a valid execution record
  is left out with a warning instead of refusing the bundle, one dated after
  the import is stored with the import time, and a record overwritten under
  Replace no longer leaves its old response body behind. Approving an import or restore into an existing workspace now names
  the previewed file's `bundle_sha256`, and a file that changed since the
  preview is refused (CLI: `--bundle-sha256`, which a `--dry-run` checks
  too). Imported OAuth 2 profiles no
  longer keep a token-cache id, a Duplicate preview no longer lists foreign
  secrets, and profile headers with key-derivation costs outside the bundle
  bounds are refused before unlocking. The CLI treats an empty
  `ANVIL_EXPORT_PASSPHRASE` as unset and says to unset it when importing a
  bundle that is not encrypted.
- A vault secret is now sealed together with the workspace that owns it, so
  a secret whose owner is changed in the database file no longer decrypts.
  Database schema 2 re-seals existing secrets once, in one transaction, when
  a profile is opened or unlocked, trusting the owner each row names at that
  time. A secret that already failed to decrypt is left as it is (it still
  fails and can be deleted) and counted in the log; a secret already sealed
  for its owner in a database still marked schema 1 fails the unlock and
  nothing is written. Earlier builds refuse a
  schema 2 database, and a full backup made from one, as newer. Restoring a
  checkpoint refuses a newer or foreign one before touching the profile. The
  desktop reads an imported bundle or backup and derives its key on a worker
  thread, one import at a time. The key a preview derives is not kept for the
  import that follows.
- Full-backup restore: the preview now says when Replace restores the
  backup's app settings, which then apply to every workspace in the profile.
  A load report of a workspace that is not in the backup is left out with a
  warning, as a history record already was, instead of refusing the
  restore, and a restored history record dated after the restore is stored
  with the restore time.
- Profile headers now carry a MAC, under a key derived from the data key,
  over their protection mode, checked at every unlock and before a
  passphrase change or conversion rewrites the header, so a header edited to
  claim keychain mode (or stripped of the MAC) no longer opens a profile
  converted to a passphrase from its old keychain entry. A conversion tags
  the keychain entry before it writes the passphrase header, and stops with
  nothing changed if the credential store refuses; an old entry the store
  refuses to delete is overwritten with a marker that opens nothing. Headers
  and keychain entries from earlier builds still open, are trusted as found
  at their first unlock on this build, and are upgraded then; a keychain
  header without a MAC that carries passphrase or recovery wraps is refused.
  An old entry left by a conversion done in an earlier build stays usable
  by a header edited back to keychain mode (MAC and wraps removed) only if
  the store refuses both to delete and to overwrite it, and a copy of the
  header saved before a conversion opens from that entry until it is removed
  or overwritten. Keychain entries
  written by this build are not readable by earlier development builds.
  Header writes use a temporary file per writer under an advisory lock
  (`profile.lock`), and a writer holding the lock removes temporary files
  older than ten minutes. Settings lists a keychain entry whose removal is
  still pending, offers neither converting nor changing the passphrase until
  the profile's mode is known, and stays open until a new recovery key is
  confirmed stored. A conversion reports the old entry as removed whenever
  the delete succeeded.
- A spec reimport now also compares the settings of the folders inside the
  import: a folder's name, description, settings, variables and auth (a
  Postman folder's auth or variables, an OpenAPI tag's description), by the
  same rules as the import's own scope (keys `folders/<id>/…`). A folder
  only the source or only your workspace has is not compared: a new one
  still arrives with the requests added in it, and one gone from the source
  is left in place. An apply is refused, with nothing written, when one of
  these folders changed after the diff was made.
- A reimport no longer overwrites a request you renamed. A request's name,
  description and tags are each compared on their own, like its spec: a
  request you renamed keeps your name when only its spec changed upstream
  (the spec is still updated), and one the source renamed too is a conflict
  kept until you approve overwriting it. A declined conflict keeps only the
  parts you edited: the rest of what changed upstream is still applied, so a
  request whose name conflicts gets the source's new spec and keeps your
  name (`ReimportChange::conflicting_fields` lists the parts that conflict).
  A rename by the source alone is now applied; before, it was ignored unless
  the spec changed as well. For an import made by an earlier build, this
  works from its stored original file unless it was reimported since; then
  a name that differs from the source's awaits approval.
- A reimport now refreshes the import's source record in the same
  transaction: it then holds the file just applied as the stored original,
  with its name, hash, size and import time, instead of the first import's.
  The file it replaces is released from the attachment store in that
  transaction unless something else still references it (another import of
  the same file, or a saved request body or dataset) or you attached the
  same file yourself, even to a request or dataset not saved yet.
- **Breaking (API):** `App::spec_reimport_apply` takes the name of the file
  it applies: `spec_reimport_apply(import_id, bytes, file_name, approval)`.
- **API:** `App::register_load_run` registers a load run with its profile
  before its job is prepared; the returned guard's tokens are canceled when
  the profile locks or the run's workspace is deleted (the desktop stops the
  worker then). It fails, registering nothing, when whether the workspace
  exists cannot be read. `App::save_load_report` now fails with
  `AppError::NotFound` once the report's workspace is deleted.
  `App::clean_up_storage` runs a storage cleanup pass now and returns what it
  removed and which stored objects did not decode;
  `App::clean_up_storage_if_due` runs one only when opening a profile would
  (`cleanup::CLEANUP_INTERVAL`), and `App::last_storage_cleanup` returns the
  last pass. `anvil_app::logging` installs the log the desktop and the CLI
  write to (`log_to_file`, `log_to_stderr`).
- **Breaking (API):** `App::release_attachment` keeps a file a user attached
  (`App::put_attachment`) and returns `false` for it, even when nothing
  references it. `App::save_request`, `App::create_request` and
  `App::save_dataset` can now fail with `AppError::Invalid` ("an attached
  file ... is no longer stored; attach it again, then save") when they name a
  stored file the item did not hold before and that is not stored.
- **Breaking (API):** `anvil_load::RefusalCode` no longer has
  `grpc_client_streaming`, `grpc_bidirectional`, `udp_masque` and
  `udp_hbone` (those plans are now load tested), and adds `mixed_tunnels`,
  `grpc_unsupported_combination` and `masque_through_proxy`.
- The export preview now lists each linked local file path the bundle will
  carry, with the request or dataset that names it (`linked_files`, as
  `request 'Upload': /path/to/file`), beside the existing warning that
  linked local files are named. A path repointed with **Choose new
  location…** is a path on this device, so the preview shows which ones
  leave with the export. The bundle's manifest does not repeat them. The
  desktop export dialog lists them under its rebinding warning (Windows
  paths without the `\\?\` verbatim prefix), and `anvil export --preview`
  prints them.

### Fixed

- The failure lab's EARLY-001 and EARLY-002 no longer fail when the gateway
  handles the 0-RTT request after its own handshake completed. Ferrum Edge
  classifies each HTTP/3 stream when it accepts it and handles a 0-RTT
  stream accepted after its handshake as 1-RTT (RFC 8470 section 6.4), so
  the client's "offered and accepted" evidence does not prove the gateway
  saw the request early; lab run 36557709775 got one 200 for EARLY-002's PUT
  and failed. A round is now judged strictly only once the gateway's side
  shows it saw the stream while its handshake was pending (a `425` on the
  first attempt, its refusal log, or the request forwarded with
  `Early-Data: 1`): EARLY-001 still requires the admitted GET with
  `Early-Data: 1`, EARLY-002 still requires `425`, the one retry on the same
  connection, `request.too_early` and the refusal log. A round of exactly
  the permitted shape (one 200, no retry, one backend request without
  `Early-Data`, no refusal logged) is a missed window and the next round is
  tried; if every round that sent the request as early data was one, the
  scenario is skipped with a reason starting `window not observed: `, never
  passed. Any other shape still fails. Because a gateway that processes the
  request early but forwards it unmarked looks like the permitted shape, a
  scenario skipped this way in both the trusted and the untrusted pass of
  one run fails both results. Lab scenarios can now report such a skip
  (`Checks::skip`) (#221).
- UDP load-scenario silence coverage keeps its non-responding target socket
  bound for the whole sub-case, then checks ICMP-unreachable counts on a
  released port with up to five fresh-port retries for parallel UDP replies.
  PROTO-020 uses the same bounded retry for its ICMP-unreachable assertion;
  both tests fail clearly if every attempt receives foreign traffic.
- The effective-request preview reports a multi-auth as varying per send
  when any of its profiles is HMAC, DPoP, JWT, WS-Security or JWT-SVID
  (nested sets included), and an SSE preview with such a multi-auth says
  each send is signed again. It used to report, say, an API key with HMAC
  as not varying, with no note, although the HMAC signature changes on
  every send. A multi-auth of static credentials (bearer, Basic, API key,
  a cached OAuth2 token) is still shown as sent.
- Creating or duplicating a request (`create_request`, `duplicate_request`)
  checks that its workspace and folder exist and belong together in the
  write transaction that stores it, not before. A workspace or folder
  delete that committed in between used to leave the new request, with its
  first revision, under the deleted workspace or folder; the create is now
  refused and nothing is stored.
- HTTP/1.1 and HTTP/2: a request on a reused pooled connection that the
  server closed just as the request went out no longer fails with "closed
  before response" when resending it is safe. When none of it was written,
  the transport sends it once more on a new connection. When it may have
  been written and its method is idempotent, the engine signs it again (a
  new HMAC nonce, DPoP proof and JWT time claims, since the server may
  already have seen the first ones) and sends it once more on a new
  connection. The resend happens at most once per execution, never on a
  pooled connection or the one kept after `425 Too Early`, and is not a
  retry: it happens with retries set to 0 and does not count toward them.
  Both attempts are recorded, the second with the new attempt reason
  `reused_connection_closed` and the failure kind that preceded it. A
  written non-idempotent request, such as a `POST`, is never resent, even as
  the retry after `425 Too Early`; its message now says why. This also
  fixes an intermittent failure of the retry after `425 Too Early` when the
  server had just closed the kept connection.
- HTTP/3 with fallback to TCP: the fallback no longer sends a request over
  TCP that may already have been received over HTTP/3 unless its method is
  idempotent. It falls back when nothing of the request was sent over
  HTTP/3 (the QUIC connection or handshake failed before the request stream
  was written, or the server refused its 0-RTT early data unread and the
  resend after the handshake never started), whatever
  the method, or when the method is idempotent. A written non-idempotent
  request, such as a `POST` whose HTTP/3 stream was reset before a response,
  used to be sent a second time over TCP; it is now not sent again, and its
  HTTP/3 attempt's message says why. The fallback is now a new attempt of
  the engine, signed again (a new HMAC nonce, DPoP proof and JWT time
  claims): it used to repeat the HTTP/3 attempt's signature, which a server
  that checks for replays rejects. Both attempts are still recorded, the
  second with reason `protocol_fallback{from: h3}`.
- Server-sent events: each send of a stream is now signed afresh (a new
  HMAC nonce, DPoP proof and JWT time claims): the initial send, the TCP
  fallback after HTTP/3 and each reconnection. A stream used to be signed
  once, when it was prepared, and the fallback and every reconnection
  repeated that signature, which a server that checks for replays rejects,
  so such a server refused every reconnection. A reconnection is signed once
  its `retry:` delay is over and still sends `Last-Event-ID`; when the
  fallback is made is unchanged. A JWT's only per-send claim is `iat`, in
  whole seconds, so two sends within the same second can carry the same JWT
  (as can legacy Ferrum HMAC v1). The record's prepared request and auth
  facts are the last send's. A fallback or reconnection that auth cannot
  sign again is not made, and the session notes why; it is never sent with
  an earlier send's signature.
- Server-sent events: a send is now signed just before it is made, after
  the HTTP/3 checks, so an HTTP/3 attempt refused before any traffic (the
  automatic policy with an `http://` URL or through a proxy, which then
  falls back to TCP) is no longer signed. A send whose auth would add other query
  parameters than it did when the stream was prepared is not made
  (`unsupported_combination`): only headers are signed again for each send,
  and the URL is fixed. No current auth does this; an API key in the query
  is the same on every send. The effective-request preview of a stream with
  auth now notes that each send (the initial one, the TCP fallback and each
  reconnection) is signed again when it is sent, not with the signature
  shown.
- HTTP/3: a request on a reused pooled QUIC connection that the server
  closed (or let time out) just as the request went out is now sent once
  more on a new connection when that is safe, as over HTTP/1.1 and HTTP/2:
  at once by the transport when none of it left, else by the engine, signed
  again, for an idempotent method. A request the server rejected with
  `H3_REQUEST_REJECTED`, or whose HEADERS the closing connection cut short,
  was not processed: it is now reported `not_dispatched` and, on a reused
  connection, signed again and sent once more whatever its method (on a new
  connection the TCP fallback may now take it, whatever its method). A
  written `POST` whose connection closed under it is still not sent again,
  and its message says why. A pooled connection whose server sent `GOAWAY`
  is no longer handed out: its next request used to fail on it. The resend
  has reason `reused_connection_closed`, happens with retries set to 0 and
  does not count toward them.
- HTTP/2: a request on a reused pooled connection that the server refused
  unprocessed, with `REFUSED_STREAM` or by a graceful `GOAWAY` whose
  last-stream-id is below its stream (RFC 9113 §8.7), is now signed again
  and sent once more on a new connection whatever its method, a `POST`
  included; it used to fail. A stream above such a `GOAWAY` is now reported
  `not_dispatched`; a `GOAWAY` carrying an error code proves nothing and
  keeps the previous rules. Only an `RST_STREAM` with `REFUSED_STREAM` is
  now classified `h2_refused_stream`; a `GOAWAY` whose error code happens to
  be `REFUSED_STREAM` is `h2_go_away`.
- Saving a request (`save_request`) keeps the workspace, folder and position
  it has in storage, read in the save's write transaction, whatever the
  saved copy names; the name, description, tags and spec are saved as
  before. An editor's copy loaded before the request was moved used to write
  back its old folder and position, so the save silently undid the move.
  Only a new request is placed by a save; moving one takes `move_request`.
- Saving a request that is no longer stored (`save_request`, the desktop
  **Save**) is refused with "request (it was deleted) not found". An editor
  tab left open after its request, folder or workspace was deleted used to
  recreate the request on save, possibly under a deleted folder or another
  workspace's folder. New requests are made only by creating or duplicating
  one.
- Desktop Load: Discard is disabled while a new plan's save or Run… is on its
  way and disappears as soon as the save is acknowledged, before the list
  reload finishes. A save that lands after another plan or report was
  selected keeps that selection instead of reopening the saved plan. The
  discarded-plan guard is cleared on workspace switch.
- Desktop linked files: Choose new location… now names the hosts the file is
  used for (the request's saved URL, or a dataset's plan requests; host and
  port only, never the path or query; template variables are omitted), and
  asks before discarding a request tab's unsaved edits, which the relocation
  replaces with the saved request.
  Windows paths are shown without the `\\?\` verbatim prefix (`\\?\UNC\`
  as `\\`); the stored path is unchanged.
- Moving a request (`move_request`) reads and writes it in one write
  transaction and changes only its folder and position. It used to read the
  request first and save that copy afterwards, so a save or a linked-file
  relocation that landed in between could be undone, leaving the request
  naming its old, unbound path. A move never files a revision.
- Desktop Load: switching workspaces now clears the selected plan or report
  and closes a pending run confirmation, so the Load view never shows, saves,
  runs or deletes the previous workspace's plan; the plan editor also refuses
  to save or start a plan that belongs to another workspace. A live run's
  Stop control is kept. Unsaved plan edits and unsaved new plans are kept per
  workspace for the session (not written to disk): they are hidden while
  another workspace is shown, marked **unsaved** on return, and an edit is
  dropped once its plan is no longer in its workspace. A new plan is kept
  only once it has been edited: an untouched one is dropped when something
  else is selected or the workspace switches. An unsaved new plan has
  **Discard** instead of Delete, which removes it without asking the backend
  to delete a plan that was never saved. The sidebar row shows an edited
  plan's unsaved name. The previous workspace's plans and reports leave the
  sidebar at once instead of staying until the new workspace's lists arrive,
  and a report delete that completes after a switch no longer clears the new
  workspace's selection.
- The load preflight's "Traffic leaves this machine" warning now compares
  each destination's whole host: a host that only contains `localhost` or
  `127.0.0.1` (such as `localhost.example.com`) no longer counts as this
  machine, and a tunnel's proxy is judged apart from its target.
- The load preflight now judges the proxy profile a request is actually sent
  through, whatever its kind: a loopback target behind a remote HTTP, HTTPS
  or SOCKS5 proxy (as well as MASQUE or HBONE) warns that traffic leaves
  this machine, and each destination names that proxy. The profile's
  `NO_PROXY` list is applied as the engine applies it, so a bypassed target
  (including a UDP target under an HBONE profile, which was labelled "via
  HBONE proxy") is shown as direct and the proxy's host is not judged.
- The effective-request preview now shows what a WebSocket, SSE or gRPC
  request sends. A `ws://`, `wss://`, `grpc://` or `grpcs://` URL is
  previewed (before, it was refused, and a URL without a scheme was
  previewed as `https://`). A WebSocket over HTTP/2 or HTTP/3 shows its
  `CONNECT`, a gRPC or gRPC-Web call shows `POST` to the method's path with
  its request message as redacted JSON (and the size of the framed message
  sent), and each shows the headers the session transport adds or leaves
  out. The preview and the session build the request with the same code. An HMAC or DPoP signature in the preview
  covers the same method, path, authority and body as the one sent, with a
  `ws`/`grpc` URL signed as its `http` counterpart. An auth profile the
  session refuses (one that rewrites the body, or adds query parameters to
  a gRPC call) is shown as a request that would not be sent. Raw TCP and UDP
  say the preview is not supported for them.
- CLI: `anvil load create --rate N` and `--vus N` now hold `N` for
  `--duration` from the start, as their help says. Before, they built a
  single stage that ramped linearly from 0 to `N`, so `--rate 100
  --duration 20` planned 1,000 arrivals instead of 2,000. The plan is now a
  zero-duration step to `N` followed by a hold of `N` for `--duration`.
- The failure lab's `h3x`, `proxyproto` and `mesh` profiles declared the
  Ferrum Edge 0.9.5 catalog whatever release ran, so on the default pin their
  diagnoses used another release's catalog. Every lab profile now declares
  the running release's own catalog, and `anvil-lab run` and `up` refuse a
  release Anvil has no catalog for, or only one audited at another commit
  (#137).
  The `early` profile's ground-truth checks on 1-RTT HTTP/3 requests now
  accept `Early-Data: 1` (and EARLY-005 a 425 and its retry) on gateway
  releases before 0.9.8, which can mark such a request as early data
  (ferrum-edge#5775), and name that in the check detail; 0.9.8 and later
  stay strict.
- WebSocket over HTTP/2 and HTTP/3, SSE over HTTP/2 and gRPC (native and
  gRPC-Web, every HTTP version) now send an explicit `Host` header as the
  request's authority (`:authority`, or `Host` over HTTP/1.1), as HTTP
  requests do. Before, they sent the URL's authority while an HMAC or DPoP
  signature covered the explicit `Host`, so the server's signature check
  failed. A WebSocket over extended CONNECT is now signed, and recorded,
  with the method it is sent with (`CONNECT`) instead of `GET`. A DPoP
  proof for a WebSocket or native gRPC session is now bound (`htu`) to the
  `http` or `https` counterpart of its `ws`, `wss`, `grpc` or `grpcs` URL,
  the HTTP URL the request is sent to. Before, DPoP refused those sessions
  before sending anything.
- gRPC calls now use the workspace cookie jar as HTTP requests and SSE and
  WebSocket handshakes do: with the Cookies setting on, they send the
  stored cookies that match their URL (a `grpc://` or `grpcs://` URL counts
  as its `http://` or `https://` counterpart, so `Secure` cookies stay on
  TLS), within the workspace only, and the `Set-Cookie` of their response
  headers is stored when the call ends, unless the profile was locked or
  the workspace deleted since the call started. The server reflection
  requests of a call send the jar's cookies too, but their `Set-Cookie` is
  not stored. Before, gRPC ignored the jar as if Cookies were off.
- An SSE stream set to reconnect is no longer reconnected without
  `Last-Event-ID` when the id the server sent is not a valid header value
  (it holds a control character other than a tab), which would have asked
  the server to start the stream over. The session ends with a note that
  says why and never holds the id. Before, the reconnection silently left
  the header out.
- The effective-request preview now resolves the `Host` / `:authority` the
  way Send does: an explicit `Host` header wins over the URL's authority, and
  an HMAC or DPoP signature shown in the preview covers that value. Before,
  the preview signed for the URL's authority, so for a request with an
  explicit `Host` it did not match what was sent. The preview also shows the
  `Host` / `:authority` that will be sent (including a `Host` an auth
  profile sets) and the non-secret facts of the generated credential (for
  example the DPoP proof's `htu`), and when the auth profile cannot be
  applied (for example an HMAC request with a manual `Content-Digest`
  header, also beside a JWT-SVID the preview does not fetch) it says the
  request would not be sent, instead of showing it without its credentials.
- The effective-request preview now shows the body an auth profile rewrites
  as it is sent: a WS-Security request's body includes its `wsse:Security`
  header block (with the password redacted), and the body size is that of
  the body sent. Before, the preview showed the body without the header
  block and its size.
- A file you attach (a request body or multipart file, a gRPC schema file, a
  dataset) can no longer be deleted before the request or dataset that uses
  it is saved. Before, a release in between, such as a reimport releasing
  the source file it replaces while that same file was attached as a body,
  left the saved request naming content that was gone. An attached file is
  now marked in the attachment index and is released only when a request or
  dataset that held it is deleted or replaced (a request's revisions are
  deleted with it), never automatically. A save of a request or dataset that
  names a stored file it did not hold before, and that is not stored, is
  refused with a message to attach the file again. `App::delete_request` and
  `App::delete_dataset` now also release, in the same transaction, the files
  their item held that nothing else references; attachment index entries
  written by earlier builds read as not marked. A marked entry records when
  the file was attached. A duplicate of a request whose file is no longer
  stored still saves.
- A header an auth profile produces that is not valid on the wire (for
  example a token pasted with a trailing line break, or an API-key or JWT
  header name with a space) now fails the request before anything is sent,
  with an invalid-header error that names the header and never its value.
  Before, the header was left out and the request was sent without the
  credential. This applies to HTTP requests and to WebSocket, SSE, gRPC and
  MASQUE handshakes alike.
- SSE and WebSocket handshakes now use the workspace cookie jar as HTTP
  requests do: with the Cookies setting on, they send the stored cookies
  that match their URL (a `ws://` or `wss://` URL counts as its `http://` or
  `https://` counterpart, so `Secure` and `HttpOnly` cookies apply), within
  the workspace only, and the `Set-Cookie` of their handshake responses is
  stored when the session ends, unless the profile was locked or the
  workspace deleted since the session started. With Cookies off they
  neither send nor store cookies.
- A request or session still in flight when its workspace is deleted no
  longer recreates that workspace's cookie jar with the cookies it
  receives, so a workspace restored from a backup with the same id does not
  send them.
- An SSE `Last-Event-ID` that resolves to a value that is not a valid header
  value now fails the request before anything is sent, with an
  invalid-header error naming `sse.last_event_id`. Before, the header was
  left out and the stream was opened without it.
- The effective-request preview now says a request would not be sent when
  its auth profile produces a header that is not valid on the wire, instead
  of showing it. A redirect or retry whose freshly applied auth is refused
  is noted in the prepared request.
- A stored cookie with the same name as a cookie the request sends itself
  (a `Cookie` header or a cookie API key) is no longer sent as well: the
  request's own cookie wins, and the jar's other cookies follow it.
- Work still in flight when a profile locks no longer refills what the lock
  cleared. The desktop lock cancels a SPIFFE Workload API call in flight,
  and an answer that arrives after the lock anyway (an X.509-SVID, a
  JWT-SVID or JWT bundles) is never cached; before, a JWT-SVID fetched
  across a lock could stay in memory after it. Likewise, for an execution
  that began before the lock, even one that is not canceled: the cookies of
  its responses are not stored, the TLS configuration it prepares (which
  holds a client identity's private key) is not cached, its connections
  (HTTP/1.1, HTTP/2 and HTTP/3) are closed instead of pooled, and its TLS or
  QUIC connections keep none of the session tickets they receive.
- Work still in flight when its workspace is deleted no longer refills that
  workspace's caches: a request, session or gRPC call of the deleted
  workspace closes its connections instead of pooling them, caches none of
  the TLS configurations it prepares and keeps none of the session tickets
  it receives, even on a later redirect or retry. Other workspaces' work in
  flight at the same time is not affected. An execution that starts while
  its workspace is being deleted is now fenced on one side of the delete
  for all of its caches: before, it could keep its connections and session
  tickets while its cookies were refused. A send, interactive session or
  collection run step whose context the app prepared from storage before
  the delete is fenced too, even when it starts executing after the delete:
  it takes the workspace's generations when the context is built, not when
  it executes. Before, it could keep cookies, a prepared TLS
  configuration (with a client identity's private key), pooled connections
  and session tickets under the deleted workspace, where a workspace
  restored with the same id would find them. Requests of the restored
  workspace, built after the delete, are not affected.
- `Engine::execute` now runs each protocol's execution boxed, so the future
  a caller awaits is small. Before, a caller that awaited several gRPC
  calls inline could overflow its thread's stack in a debug build.
- Prepared TLS configurations are now kept per workspace (every workspace
  without a TLS profile shared one configuration), and a workspace delete
  drops them. Connections without the early-data opt-in still never resume
  a session, and they no longer keep the TLS 1.3 session tickets and TLS 1.2
  sessions servers send: only the key-exchange group each server chose is
  kept, so the next handshake still needs no HelloRetryRequest. Under the
  opt-in, a connection resumes only its own workspace's tickets.
- Pooled gRPC channels, which only a load run's virtual users keep, are no
  longer shared between workspaces, and a call that began before its
  engine's channels were cleared no longer returns its connection to them.
  Deleting a workspace now stops that workspace's running load runs, and
  `App::lock` stops every load run, so a run's engines no longer keep a
  deleted workspace's pooled connections, session tickets, cookies, prepared
  TLS configurations and gRPC channels until the run ends. The desktop ends
  the worker of a run stopped by its workspace's delete at once, and keeps
  no report of it; only the window of the run's profile is told why.
- Deleting a workspace now also releases the stored files (request bodies,
  multipart and gRPC schema files, datasets, imported spec sources) its
  items held, unless an item of another workspace still references them or
  you attached the file within the last 30 days (a draft not saved yet may
  hold it; the 30-day cleanup below decides it). Before, their encrypted
  content and pins stayed in the profile for good.
- A file you attached to a request or dataset that was never saved is now
  released by the storage cleanup, 30 days after it was last attached,
  unless a saved item references it. Saving an item that names such a file
  is refused with "attach it again", as for any released file.
- The storage cleanup also removes request revisions whose request no
  longer exists (earlier builds left them behind when a request was
  deleted) and releases the stored files only they referenced, except one
  you attached again within the last 30 days.
- Opening a profile runs the storage cleanup at most once a day. It reads
  without taking the database write lock and writes in a short transaction
  only if nothing changed meanwhile. While a stored object that does not
  decode blocks it, the cleanup at open is skipped until something it reads
  changes.
- A stored object that does not decode, which keeps every stored file from
  being released, is now logged as a warning naming its kind and id (never
  its content), and the cleanup keeps it in its last pass, which
  `anvil storage-cleanup` prints, so the damaged row can be found and
  repaired or deleted. Warnings now reach a log: before, none was installed,
  so they were dropped. The desktop writes `anvil.log` in its log directory
  (on macOS `~/Library/Logs/com.ferrumedge.anvil/`) at level `info`,
  rotated to `anvil.log.1` at 5 MiB; the CLI writes warnings and errors to
  stderr. `ANVIL_LOG` (`off`, `error`, `warn`, `info`, `debug`, `trace`)
  sets another level for Anvil's own crates.
- Deleting a request, a folder with its requests or a dataset, or replacing
  a dataset's file, no longer releases a file you attached within the last
  30 days, as a workspace delete already did not: a draft of another request
  or dataset may have attached the same file moments before, and its save
  was then refused with "attach it again". The 30-day cleanup decides it
  instead.
- A file attached by a build that did not record when (a mark with no
  `attached_at`) now ages from the first storage cleanup that sees it, which
  records the time. Before, it counted as recently attached for good, so an
  unsaved one was never released.
- A spec reimport now compares the import's scoped configuration too, not
  only its requests: the source's own variables, auth, settings and
  description (on the new workspace, or on the import root in an existing
  workspace) and its environments. An OpenAPI server change, which leaves
  every `{{baseUrl}}/…` request as it was, is now listed as a change to its
  environment's `baseUrl` and applied, so requests are sent to the new
  server. The same rules as for requests apply: a value you edited is a
  conflict kept until you approve overwriting it (`overwrite_scope`), a
  variable or environment gone from the source is kept until you approve
  deleting it (`delete_scope`), your own variables stay, and a new server
  arrives as a new environment. An environment you deleted is a conflict
  when the source changed any of it, and one gone from the source is marked
  as edited when you changed any of its variables. An approved deletion of
  the active environment leaves none active, as deleting it yourself does.
  Imports made by earlier builds work this out from their stored original
  file, unless they were reimported since or that file cannot be read; then
  every difference awaits approval, and a removal you decline is kept as
  your own from then on. A reimport of an import root that was deleted is
  refused, and so is an apply when the import's requests, scope or
  environments changed after the diff was made; nothing is written then.
- A reimport that changes a saved request now records a new revision for
  it, in the same transaction, and points the request at it, so a send, run
  or history record names the spec that was actually sent. The revision of
  its old spec stays as it was; a request the reimport leaves unchanged
  keeps its revision and gains none.
- Desktop Runner: **Run folder** and **Run** start one run at a time. A
  second click while the start is still pending no longer starts another
  run, and a run that finishes before the start answers (an empty folder,
  for example) is no longer shown as running with a Stop control that does
  nothing. **Stop run** pressed while a run is starting stops it as soon as
  it starts, and a run the backend no longer has is cleared when stopped.
  Switching workspaces now clears the Runner's selected scenario, report,
  folder choice and pending confirmation, so the Runner never offers to run
  the previous workspace's scenario; a live run's Stop control is kept.
  Unsaved edits to a scenario's run options are kept per workspace for the
  session (not written to disk): they are hidden while another workspace is
  shown, marked **unsaved** again on return, and dropped once the scenario is
  no longer in its workspace.
- Deleting an environment clears its active workspace selection in the same
  transaction. Older profiles with a missing workspace-default environment
  now prepare requests without an environment, and collection run reports say
  when that fallback was used; an explicitly selected missing environment
  still fails clearly.
- Server-sent events: an event whose data (its `data:` lines joined with
  newlines) passes the parser's event bound, four times the line bound
  (`min(max_response_bytes, 1 MiB)`, at least 1 KiB), now stops the attempt
  with `response_too_large_local` instead of being dispatched with the
  extra data lines silently dropped. Events completed earlier in the same
  read are still recorded.
- Server-sent events: a leading UTF-8 byte order mark is now stripped even
  when its three bytes arrive in separate reads; the stream's first event
  was lost when the transport split it. A BOM later in the stream is still
  not stripped.
- A load run now hands its worker every vault secret the plan's requests
  resolve: the datagram PROXY-protocol authentication secret of a UDP
  request, and the client identity of the selected proxy's own TLS profile
  (which also travels to the worker now), were missing, so those requests
  failed preparation in the worker ("the datagram secret is not available",
  or the proxy's TLS profile "no longer exists"). A request of another
  protocol with a leftover UDP section ships no datagram secret.
- Desktop: long store work no longer holds the async runtime. Spec imports
  and re-imports, folder and workspace deletes, profile creation, unlock and
  passphrase changes (their key derivation), history lists, views and
  clears, export previews, and reading an attachment, a PEM/PKCS#12 file or
  a dataset now run on a worker thread. A send, session open, collection
  run, load run and OAuth sign-in prepare the request, look up the vault
  secrets its spec, effective auth and selected profiles name, and record
  their history or report on a worker thread, so they no longer hold the
  runtime while an import holds the database. A send, session open or
  collection run canceled while it waits for that returns at once, with
  nothing sent or recorded. A synchronous store command issued during a
  long import still waits for the database connection until the import
  ends.
- Desktop: a lock now wins over an unlock or profile creation whose key
  derivation it overlaps: the profile stays locked, and is never usable in
  between (a new profile is still created, and its recovery key still
  shown). A command that runs on a worker thread and returns what it read
  from the store (a history list or entry, an export or spec preview, a
  re-import plan, a request preview) returns `LOCKED` instead when a lock or
  a profile switch overlaps it; one that only writes (a folder or workspace
  delete, a history clear, a spec import or re-import, an attachment)
  reports its own outcome. A history list that meets the lock midway fails
  as locked instead of returning the records read so far, and a load run
  whose preparation overlaps a lock is not handed to a worker.
- History records are indexed by their response body, so releasing a
  replaced body and history retention no longer scan whole tables. The index
  is created, as a best effort, when a profile is opened or unlocked (one
  that cannot be created is logged and only slows those lookups, and never
  keeps the profile from opening); it changes no stored data,
  so the database schema version stays 2, and earlier builds still read the
  database and its full backups. Restoring a checkpoint whose recorded
  version was set back below schema 2 after its secrets were re-sealed is
  now refused before the profile is touched, instead of leaving it locked.
  Deleting an attachment's last use checks for other references and deletes
  it in one transaction, and the pins re-applied when a profile opens are
  written in one transaction. Deletes, blob pins and releases, and history
  and load-report clean-up check the lock only once they hold the database,
  so one that raced a failed checkpoint restore fails as locked.
- Desktop: canceling an import or a full-backup restore now works from the
  import dialog (Cancel while it runs; closing the dialog cancels it too),
  and a restore can be canceled until its key is derived and its contents
  checked instead of only before it starts; a canceled one writes nothing,
  not even its checkpoint. A lock or a profile switch during an import's key
  derivation ends it without writing even when it was started without an
  `attempt` id and the profile is unlocked again before the derivation ends,
  and a preview that a lock overlaps returns `LOCKED`. A preview or import
  refused because an earlier one is still finishing returns `IMPORT_BUSY`,
  which the dialog explains, instead of a sentence.
- Desktop: OAuth sign-in attempts are canceled from their own registry, so
  `oauth_cancel` never cancels a request execution with the same id, nor
  `cancel_execution` a sign-in; a lock still cancels both.
- An unlock refused by its gate (a lock that landed during the key
  derivation) no longer locks the store itself: the lock that caused the
  refusal clears the key itself, and locking again could undo a newer unlock
  that completed meanwhile.
- A request under an import root that is not opened to its workspace is now
  also refused when the selected proxy's own TLS profile has a client
  identity bound to no host, whatever the proxy's kind or `no_proxy`, as it
  already was for the request's own TLS profile. This applies to a send, a
  session, a collection run and a load run.
- Multi auth now applies each profile to the request as it will be sent
  after the earlier profiles' changes. Cookie API keys from several profiles
  all reach the one `Cookie` header, after the request's own cookies (from
  every `Cookie` header it has); earlier builds sent only the last profile's
  cookie. A profile's cookie replaces a cookie of the same name already in
  the request, as a header API key replaces a header of the same name. An
  HMAC profile signs the query, body and `Host` the earlier profiles
  produced (a query API key, a WS-Security header), where it signed the
  request before them and the gateway refused the signature. Before anything
  is sent, a multi-auth set is now refused when two profiles would set the
  same header, cookie or query parameter (including inside a nested set),
  or when a profile would change what an earlier signature covers: after
  HMAC, the query, the body or the `Host`, `Date`, `Digest` or
  `Content-Digest` header; after DPoP, the `Host` header. Put such a profile
  before the signing one. A multi-auth set can hold one HMAC profile and one
  DPoP profile.
- A cookie API key whose name is not an RFC 6265 cookie name (a token) or
  whose value is not made of cookie octets (optionally in double quotes) is
  refused before anything is sent, so its value cannot add or change another
  cookie (for example a value `a; x=y`). The message names the cookie, never
  its value.
- HMAC evidence no longer records `hmac.signing_string_sha256`. With multi
  auth the signing string can include an earlier profile's query API key,
  and its hash could be checked against guesses of that key offline. The
  nonce is still recorded.
- An explicit `Host` header must now be a host with an optional port
  (`uri-host[:port]`: a host name, an IPv4 address or an IPv6 address in
  brackets). A value with userinfo, a path, a query, a fragment or
  whitespace, or an IPv6 address without brackets, is refused before
  anything is sent, for HTTP/1.1, HTTP/2 and HTTP/3 requests, WebSocket,
  SSE and gRPC, and so is such a `Host` set by an auth profile. An empty
  `Host` is refused too; before, it was sent empty (leave the header out to
  send the URL's host and port). The message names the reason, never the
  value. Before, a `Host` such as
  `a.test/admin` changed the path an HTTP/2 or HTTP/3 request was sent
  with, while the signature covered the original path.
- A gRPC URL with a query, or a gRPC request with query parameters, is now
  refused before anything is sent (`unsupported_combination`, field `url`),
  by a send, an interactive session and the preview. The call is sent to the
  method's path without a query, so the query was signed but never sent and
  an HMAC signature always failed verification.
- A gRPC call whose schema comes from server reflection is now signed over
  the framed request message it sends, once reflection has resolved the
  schema and the message is encoded, as a call with a `.proto` file or a
  descriptor set is. Before, the message was encoded after signing, so an
  HMAC `Content-Digest` and signature covered an empty body and a gateway
  that checks the digest refused the call. The record's prepared request is
  the one signed and sent. The effective-request preview shows the request
  message as redacted JSON and says that a digest or signature it shows
  covers an empty body, since the call is signed when it is sent.
- gRPC: a unary or server-streaming call with a local schema and no request
  message is now signed over the empty message it sends (a 5-byte frame,
  base64-encoded for gRPC-Web text). Before, an HMAC `Content-Digest` and
  signature covered an empty body, so a gateway that verifies the digest
  refused the call. The prepared request and the effective-request preview
  show the empty message `{}` and the size of that frame.
- gRPC: each server reflection request is now signed for its own path and
  message when auth is set: an HMAC signature and `Content-Digest` of its
  own (and a fresh nonce with Ferrum HMAC v2), or a fresh DPoP proof bound
  to the reflection URL. Before, reflection requests reused the headers
  signed for the call's method path, so a gateway that verifies HMAC or
  DPoP refused them and reflection failed. docs/protocols.md explains why
  reflection is signed rather than sent without those headers. A token
  minted for a reflection request (a JWT) is redacted in the record and
  history, including where the server echoes it in its refusal. A
  reflection request that auth cannot sign is not sent, and
  `grpc.reflection_unavailable` says that auth preparation failed for it
  instead of reporting a transport failure and advising the operator to
  allow reflection.

### Security

- A redirect that would resend a request body to another origin is no
  longer followed when the body has a form field marked sensitive, even
  when its value is a literal rather than a secret variable. Before, only
  secret variables marked the body structurally, and a literal whose form
  encoding changed its bytes (such as one holding `@` or a space) was
  resent by a 307 or 308 redirect. Allowing credentials to be forwarded
  cross-origin in the redirect policy still lifts the refusal.
  (GHSA-c8jq-hq57-v523)
- The workspace cookie jar no longer stores a cookie whose `Domain` is a
  public suffix, such as `com`, `co.uk` or a private-section suffix like
  `github.io`, so one site can no longer set a cookie that Anvil then sends
  to unrelated sites under that suffix. When the suffix is the responding
  host itself, the cookie is kept for that host only. Cookies scoped to a
  registrable parent domain and host-only cookies are unchanged. The Public
  Suffix List is compiled in (the `psl` crate). (GHSA-vv3h-gm7f-3hm7)
- Fixed GHSA-6g2g-2mvw-7h7v and GHSA-x6q9-gx98-c5wc: gRPC reflection now
  has a 30-second absolute deadline, shortened by the call's total deadline,
  including interactive sessions. Its cumulative budget counts wire and
  decoded response bytes across every reflection request, and it accepts only
  one response message per request. gRPC-Web percent decoding reads escape
  digits as bytes, preserving malformed escapes without panicking on
  multibyte UTF-8.
- Full backup restores now reject spec provenance whose root is missing,
  belongs to another workspace, or is not an import root. Import roots may be
  nested in their workspace and remain valid for restore and reimport; a
  deleted root retains the guidance to import the source again. Restore rejects
  an imported spec namespace already used in another workspace, and reimport
  refuses generated IDs owned by another workspace before writing. This keeps
  restored provenance from changing unrelated objects. Fixes
  GHSA-2c97-mfx4-3g7r.
- Desktop development dependencies now override Mocha's vulnerable
  `serialize-javascript` dependency with patched version 7.0.5.
- A secret variable used only in what a session sends once it is open (a
  WebSocket message or subprotocol, a gRPC message, method or metadata
  value, an SSE `Last-Event-ID`, a raw TCP or UDP payload) is now redacted
  in the live transcript events and in the stored history, like a secret
  used in the URL or a header. The session's redactor was built before
  those values were resolved; it now takes them in once they are, before
  anything is redacted with it, and the stored transcript is redacted again
  with the record's redactor. Hex previews (binary messages, pings and
  payloads that are not printable text) are now redacted too, live and
  stored: a secret's lowercase hex is recognised. An SSE event type is now
  redacted in live events, as it was in the stored record. A secret in a
  hex- or base64-encoded field (a WebSocket binary message or ping, a TCP
  payload, a UDP datagram, a PROXY header TLV) is also redacted as the bytes
  it decodes to, as text and as hex, when they are at least 4 bytes long.
  The secrets a gRPC call signs with once server reflection resolves its
  schema (such as a freshly minted token) are now redacted in live events
  too, not only in the stored record.
- Follow-up to the session redaction above: a secret in a hex- or
  base64-encoded field that decodes to only 2 or 3 bytes is now redacted in
  hex previews, since the 4-character minimum applies to each redacted form
  rather than to the decoded byte count. A secret split across the
  encoding's alignment no longer makes the whole decoded field (up to
  8 MiB) a redaction pattern: only the bytes it covers, widened to whole
  bytes or base64 groups, are, so it is also recognised in the truncated
  preview of a field longer than the preview limit. The run history's
  scrub of a stored transcript now redacts event ids and event types as
  well as previews.
- Deleting a workspace now also forgets the OAuth tokens (access and
  refresh tokens, including interactive sign-ins) cached for it. Before, they
  stayed in memory until the lock, and a workspace restored with the same id
  sent them without a new sign-in. A token request or refresh of that
  workspace in flight across the delete, and a sign-in completed after it,
  no longer caches its token, and a send or sign-in whose context was built
  before the delete caches nothing for the workspace: a client-credentials
  token is acquired for that send only, and an interactive grant needs a new
  sign-in. Workload API SVIDs are not kept per workspace and are still
  cleared on lock.
