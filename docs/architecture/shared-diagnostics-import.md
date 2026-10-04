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
reference attempts at eight. Redaction discovery is bounded to 128 credential
strings and 64 KiB of credential bytes; exceeding it rejects the preview.
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

The private, ephemeral `ImportedDiagnosticPreview` DTO cannot substitute for an
execution record, `DiagnosticFinding`, `GatewayDetail` or confirmed client
diagnosis. Its assessment is always **unverified**, confidence **unknown**.
Original reported verification, observation trust, confidence and authenticated
booleans stay visible as claims, after redaction. Supplied conclusions are never
inputs to Anvil's rules; no automatic diagnosis or Edge lookup follows an import.

The command uses Anvil's existing credential-name classification and `Redactor`
for exact values, encoded echoes and URL credentials. Credential-named subtrees
and evidence/header `key`/`name`/`header` plus `value` pairs are masked. Recognized
Bearer/Basic tokens and private-key text are scrubbed across the whole preview.
The command does not resolve vault secrets. Unrecognized secrets in arbitrary
free text can remain, so the preview retains a review-before-sharing notice.
Errors contain fixed text, never attacker keys or JSON excerpts.

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
families without granting trust. Local validation is static only; formatting,
compile, lint and execution gates belong to GitHub-hosted CI.

This implements Anvil's consumer portion of
[ferrum-alloy#27](https://github.com/ferrum-edge/ferrum-alloy/issues/27).
That issue remains open for Nexus consumption and cross-repository qualification.
