# Read-only shared diagnostic import

Anvil's desktop **Import → Diagnostic preview** accepts pasted JSON or a browser
`File` selection. It previews `ferrum.diagnostic_report` 1.x, a standalone
`DiagnosticFinding`, `ferrum.diagnostic_ref.v1`, and the exact Alloy
`diagnose --format json` envelope (`report`, `warnings`, `claimed_verification`).
Alloy `diagnose --write-report` writes the report directly. There is no apply
operation; closing or clearing the preview drops its in-memory contents.

The dedicated `diagnostic_import_preview` command accepts only
`input: { text: string }`. Its input DTO rejects additional keys, null and other
types. The command has no `DesktopState`, profile, workspace, grant or request
arguments. Neither it nor the parser accesses storage, history, the vault,
native filesystem, URLs, network clients or gateway lookups. Selecting a file
uses the renderer's existing browser File interface; no capability changes or
backend path parameters are involved.

## Contract and producer pins

The coherent additive pin is `contracts-edge-0.9.9-r2`, full commit
`591c73a3f965fdab440c3a76b2707accdf491ba5`. Every vendored byte is covered by
`contracts/ferrum-contracts/PIN`. All previously vendored files retain their
hashes from `25c4e9e00033d7941a1dd0ab733fa74e735546ae`; the report schema, all
12 report fixtures and the full canonical invalid-expectations manifest are
additions. Existing file-presence scans, catalog parity and reference-reader
qualification remain in place.

Alloy is unreleased (`publish = false`). The producer inspected is immutable
commit `0c260f5379939ff46d681666bfbcd65b8518b08d`. Tests pin its exact CLI
`diagnose.rs` and report schema, and compare the schema with the canonical copy
after removing only contract metadata and restoring the producer `$id`.

The producer golden is real hosted exporter output, copied without modification
from `e2e/diagnosis.json` in artifact `11305688717`,
`edge-e2e-evidence-v0.9.10`, from
[Alloy run 37208769030](https://github.com/ferrum-edge/ferrum-alloy/actions/runs/37208769030).
GitHub identifies that artifact's head as the exact producer commit above. Its
archive SHA-256 is
`159bef8a6b7b021b8498a93a12172ba8cd2dd227172ced4659af6902bd3965d9`.
The immutable Edge E2E driver serializes the assembled report and findings with
`serde_json::to_string_pretty`, the report representation the CLI exporter also
uses. The golden's SHA-256 and source copies are pinned in
`crates/anvil-diagnostics/tests/fixtures/alloy/PIN`. This is an actual exported
report, not a captured CLI stdout envelope; the envelope test uses the exact
shape from the pinned CLI source around those real facts.

## Bounds and schema semantics

The frontend checks a selected file's declared size before reading and reads at
most 4 MiB plus one byte through `File.slice`. It decodes UTF-8 with fatal errors
and checks pasted UTF-8 byte length before IPC. Preview requests and file reads
have attempt identifiers so clearing or closing cannot restore a stale preview.
Successful paste previews remove the raw paste from the textarea.

The Rust parser checks 4 MiB and UTF-8 before JSON decoding. A lexical scan
respects string escapes, rejects nesting beyond 32, bounds encoded strings and
tokens before allocating a JSON tree. A serde visitor rejects duplicate keys
(including escaped aliases), strings and keys over 2,048 decoded UTF-8 bytes,
arrays over 5,000 elements, objects over 128 members and trees over 200,000
values. The schema additionally caps findings at 1,000, attributes at 32 and
reference attempts at eight. Schema and semantic validation complete before
redaction, so masking a credential cannot repair invalid JSON or invalid schema
values. Redaction discovery is bounded to 128 nonempty registrations and 64 KiB
of credential bytes; exceeding either rejects the preview. Repeated values and
decoded layers count toward both budgets even though the scrubber deduplicates
them. Each component has at most three strict, shrinking UTF-8 percent-decoding
rounds. Invalid percent escapes or UTF-8 stop decoding without a lossy substitute.
These limits apply to unknown fields and extensions as well.

The consumer uses a fail-closed interpreter of the assertions in the three
embedded immutable schemas, with independent `jsonschema` fixture parity tests.
A new schema assertion fails during schema compilation instead of being ignored.
The canonical schemas allow additional fields; the consumer preserves them as
uninterpreted claims. Report vocabularies are open strings; standalone findings
and reference vocabularies are closed. Numeric probabilities fail. Null is
accepted only where the relevant schema permits it, including finding evidence
attempts and reference nullable fields. Unknown attribute values still must be
strings. Input never selects a schema URL or causes remote reference resolution.

Additional consumer semantic checks require RFC 3339 `generated_at` when supplied,
unique observation IDs, valid nonzero trace/span IDs, ordered integer intervals,
measured measurement values and units, and existing supporting-observation
references. The schema validates reference RFC 3339 timestamps, lowercase IDs,
required presence and nullable fields. None of these checks authenticates a claim.

## Trust and presentation

The ephemeral `ImportedDiagnosticPreview` DTO cannot substitute for an
execution record, `DiagnosticFinding`, `GatewayDetail` or confirmed client
diagnosis. Its assessment is always **unverified**, confidence **unknown**.
Original reported verification, observation trust, confidence and authenticated
booleans stay visible as claims, after redaction. Supplied conclusions are never
inputs to Anvil's rules; no automatic diagnosis or Edge lookup follows an import.

The command uses Anvil's existing credential-name classification and `Redactor`
for exact values, encoded echoes and URL credentials. Credential-named subtrees
and evidence/header `key`/`name`/`header` plus `value` pairs are masked. Recognized
Bearer/Basic tokens and private-key text are scrubbed across the whole preview.
Before global scrubbing, discovery extracts individual Cookie values, the first
Set-Cookie pair (including quoted values, excluding attributes), and username and
password components from structurally parsed URLs. Cookie header arrays and
evidence/header pairs retain their context. URL fields and whitespace-delimited
URLs in text contribute credentials, as do recognized credential query/fragment
values. Raw and bounded valid percent-decoded components are registered, so
matching echoes elsewhere are scrubbed. Overlapping values are scrubbed longest
first. Values shorter than four UTF-8 bytes are masked in their credential
structure but are deliberately not scrubbed from arbitrary text, which would
otherwise shred ordinary words. URLs embedded without recognizable delimiters,
other encodings and unrecognized free-form secrets can remain.
The command does not resolve vault secrets. Unrecognized secrets in arbitrary
free text can remain, so the preview retains a review-before-sharing notice.
Errors contain fixed text, never attacker keys or JSON excerpts.

Rust serializes the redacted tree to `reported_json` text before native IPC. The
DTO transports bounded observation/finding counts plus kind, trust, confidence,
fixed warnings and this string; it carries no JSON numeric tree to JavaScript.
The domain DTO participates in JSON schema and TypeScript binding generation.
The UI uses this text directly, without `JSON.parse` or `JSON.stringify`, retaining
exact integer values such as the exporter's `1791123618658684620` nanoseconds.
The UI renders up to 64 KiB of the redacted report as React text inside a `pre`,
escaping bidirectional control characters and showing a truncation notice when
needed, with fixed trust wording outside it. No Markdown, HTML, executable instructions or external links
are created from imported content. Rendering tests exercise forged claims,
HTML, `javascript:` and `file:` strings, browser file bounds, malformed Unicode,
stale replies, the real import-dialog entry point and zero mutation/lookup calls.

All canonical positive and negative fixtures exercise both the production parser
and dedicated IPC DTO/command. Independent schema tests check each canonical
negative's expected location and keyword, as well as exact fixture presence.
The real hosted golden preserves all reported facts and both telemetry source
families without granting trust. The existing native WDIO runner launches the
actual Tauri E2E app for the diagnostic spec: all 27 shared fixtures, the actual
Alloy report and source-derived CLI envelope cross native IPC. The golden's
timestamp lexemes are compared as strings through IPC and the real dialog. The
spec also covers forged provenance/authentication, credential echoes, truncated
input, discovery count/byte caps, duplicate keys, invalid credential attributes,
extra capabilities, presentation truncation, bidi escaping and clearing. It
compares profile/workspace/history/settings state and hashes the throw-away
profile's persisted bytes (including vault/database/WAL), without decrypting
secrets. A loopback fixture observes no fetches to the supplied credential and
markup URLs; this is a targeted network control, not a capture of all OS traffic.
Native qualification at code commit `925e96253d36ea69a5f52a83a9c21602bb7557e4`,
against main `4254ea84c101bdc9231a4c6f455421e22468d0ec`, passed all fourteen
cases of the diagnostic-import spec on Linux, macOS and Windows. Root read the
actual logs for [Linux job 111471676088](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37214333011/job/111471676088),
[macOS job 111471675865](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37214333011/job/111471675865)
and [Windows job 111471676069](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37214333011/job/111471676069).
Each runner completed all eleven native spec files. The duplicate-key cases use
an otherwise valid report, including an escaped alias, and require the fixed JSON
error; caps, schema failures, oversized real IPC input and rejected capabilities
are independent cases. The shared-fixture, real golden timestamp and credential
no-effect cases also passed. Root separately verified the downloaded producer
archive and its GitHub source identity, every golden/source digest and the
canonical contract pins. This is native fixture and producer evidence; final
landing still requires all fresh hosted checks for the final documentation head.
The cross-repository qualification below remains PROPOSED.

Local validation is static only; formatting, compile, lint and execution gates
belong to GitHub-hosted CI.

This implements Anvil's consumer portion of
[ferrum-alloy#27](https://github.com/ferrum-edge/ferrum-alloy/issues/27).
That issue remains open for Nexus consumption and cross-repository qualification.
The shared-contract qualification remains **PROPOSED** pending that evidence.
