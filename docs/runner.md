# Collection runner (`anvil-runner`)

Implements the collection-test part of build plan §6 (assertions, extraction,
chained requests, CSV/JSON rows), the variable chain of §5.3 and the
shared-prepared-request rule of §14.1 for collection runs. Relevant matrix
cases: LOAD-008 (same request via Send/collection/load), DATA-020 (redaction
across artifacts, datasets included) and the universal assertions
(transport/application/assertion separation, no unsafe replay, bounded
resources).

## Parity with manual Send

Every step is one call to `Engine::execute(&ctx, EventCtx::none(), cancel)` —
the same preparation, variable resolution, body serialization, per-send auth
(fresh HMAC nonces, DPoP proofs, JWT time claims), TLS policy, connection
pool, cookie jar, redaction, diagnostics and assertion evaluation as the
request editor. The runner does not read storage: a `StepProvider`
(implemented by `anvil-app`) yields the frozen `ExecutionContext` of each
saved request, built by the same `App::build_context` a manual Send uses.

The app snapshots every request of the run once, at run start, so a run
uses a frozen environment and request state (§5.3) even if either is edited
while it runs. The exact request revision executed is recorded per step.

The runner never retries a step. Retries remain the engine's decision under
the request's retry policy, and the engine never replays a request that may
have been processed unless the method is idempotent.

## What can be run

* **Scenario** — a saved `Scenario`: ordered `steps` (request, enabled,
  `delay_ms` think time before the step), optional `dataset_id`,
  `iterations`, `stop_on_failure`.
* **Folder** — every request of a folder subtree (or the whole workspace) in
  sidebar order: at each level subfolders first, then requests, each by
  `sort_key`. Folder runs default to `stop_on_failure = false`.

### Trust

Imported scenarios arrive with `trusted = false` (the portability layer
clears the flag; nothing runs on import). The runner refuses an untrusted
scenario with `RunError::Untrusted` before any traffic unless the caller sets
`allow_untrusted`, which UIs set only after the user confirmed that specific
run. The override is recorded in the report (`source.untrusted_override`,
a note, and a banner in the HTML summary) and does not trust the scenario
for later runs. `App::trust_scenario` / `anvil scenario trust` marks a
reviewed scenario trusted. Scenarios created locally (`App::create_scenario`,
`anvil scenario create`) are trusted. Folder runs are an explicit user
action over the user's own saved requests.

## Variables and precedence

The provider's context carries the normal chain (low → high): app defaults →
workspace → selected environment → ancestor folders. The runner appends the
run-local layers, which therefore always win:

1. `run` — `{{anvil.iteration}}` (0-based) and `{{anvil.step}}` (0-based
   position in the scenario). Treat the `anvil.` prefix as reserved.
2. `dataset '<name>' row N` — the iteration's dataset row.
3. `extracted (this iteration)` — values extracted by earlier steps of the
   same iteration (a later extraction of the same name replaces the earlier
   one). Extracted values never cross iterations and are never persisted.

Unresolved variables still fail preparation (`unresolved_variable`, nothing
sent) — for example when an earlier extraction matched nothing. The step
then fails on the transport dimension and its record says which variable
and which scopes were searched; extraction misses are also surfaced in the
step's `message`.

When the context has a seed, each step gets a seed derived from it, the
iteration and the step, so `{{$randomInt}}` / `{{$randomFrom}}` are
reproducible per step and still differ between iterations.

## Datasets

CSV (header row, then records) or a JSON array of flat objects — parsed by
the same code as the load engine. JSON strings are used as-is, other scalars
use their JSON text, `null` becomes an empty string, and a key missing from
a row leaves that variable *undefined* for that row (not empty).

Bounds (errors are clear and never quote cell values): 16 MiB, 100 000
rows, 256 columns; empty, duplicate or brace-containing column names are
rejected; a dataset must have at least one row.

Iterations: the explicit run override, else the scenario's `iterations`
when non-zero, else one per dataset row, else 1 (at most 10 000). Iteration
*i* uses row *i mod rows* — rows are reused in order when there are more
iterations than rows, and later rows are unused when there are fewer; both
cases are noted in the report.

`sensitive_columns` values are secrets: they enter the engine as secret
variables (redacted by the engine wherever it substitutes them), are added
to the run's exact-value redactor, and the column names are added to the
redaction name list for that run. Only the dataset's name, format, SHA-256,
row count and column names appear in the report. A sensitive column that is
not in the dataset is reported (and rejected by `App::create_dataset` and the
CLI) rather than silently ignored.

## Step outcome and "failed"

Each executed step keeps the engine's three independent dimensions:

| Dimension | Failed when |
|---|---|
| transport | `outcome.transport` is not `completed` (failed before a response, incomplete body, local preparation failure, unknown) |
| application | `outcome.application` is `failure` (HTTP ≥ 400, gRPC non-OK, SOAP fault, GraphQL errors, WebSocket error close) |
| assertions | `outcome.assertions` is `fail` (an enabled assertion failed or could not be evaluated) |

`failed_dimensions` lists every dimension that failed. `FailOn { transport,
application, assertions }` decides which of them make the step **failed**;
the default counts all three. Counting is independent of reporting: a
dimension that is not counted is still listed and still counted in the
per-dimension totals.

Step statuses:

| Status | Meaning |
|---|---|
| `passed` | executed; no counted dimension failed |
| `failed` | executed; at least one counted dimension failed |
| `error` | not sent: the provider could not supply the request (deleted, belongs to another workspace, a referenced secret is missing). Always counts as failed |
| `skipped` | not sent: disabled in the scenario, or the iteration stopped at an earlier failure |
| `canceled` | canceled in flight (has a record; `dispatch` says whether the peer may have processed it) or not started because the run was canceled/aborted |

`stop_on_failure` ends the **iteration** at its first failed/error step; the
remaining steps of that iteration are `skipped` and the next iteration runs.
An iteration is `passed`, `failed` (any failed/error step) or `incomplete`
(the run was canceled or aborted during it).

## Cancellation, lock and abort

The run's `CancellationToken` is passed to every engine execution and to the
think-time wait, so a cancel takes effect promptly. The in-flight step
finishes as `canceled` with its record; the remaining steps of the iteration
are reported as `canceled` (not started); no further iteration starts. If
the canceled request may have reached the peer (`sent`, `may_have_been_sent`,
`unknown`), a note says so — it is not retried.

A provider may report a fatal condition (`StepError::Fatal`); the app does so
when the vault is locked (runs stop on lock). The run ends `aborted` with
`abort_reason`, the rest of the iteration is `canceled`, and the partial
report is returned (the app adds a note if it could not be saved because the
store is locked). `completion` is `completed`, `canceled` or `aborted`;
`partial` is true for the latter two.

## Live events

`RunEvent` (contract schema `RunEvent.schema.json`): `run_started`,
`iteration_started`, `step_started`, `step_finished`, `iteration_finished`,
`run_finished`. The sink must not block. Delivery is bounded:

* `run_started` and `run_finished` are always delivered;
* events about failed/error steps and non-passing iterations are delivered up
  to 1 000 per run regardless of rate;
* everything else passes a token bucket (burst 200, then 20 events/s).

Dropped events are counted in `run_finished.dropped_events`. Every
`step_finished` / `iteration_finished` / `run_finished` carries a
`RunProgress` snapshot (steps done/total/failed, iterations done/total), so
coalescing loses detail, never totals. The final report is authoritative.

## Report (`RunReport`, contract schema `RunReport.schema.json`)

Versioned by `report_version` (currently 1) plus the object `schema_version`
and `runner_version`. It records the source (scenario id/name and override,
or folder id/path), environment, dataset identity, `fail_on`,
`stop_on_failure`, timings (`started_at`, `finished_at`, `duration_ms`),
`completion`, `partial`, `abort_reason`, totals, notes and per iteration:
index, dataset row, start, duration, status, `stopped_at_step`, steps.

Per step: position, request id, **revision id**, name, protocol, method,
redacted URL, status, `failed_dimensions`, **execution record id** (the
history entry), transport/application/assertion states, dispatch state,
HTTP (or handshake) status, gRPC status, redacted summary and message,
wall-clock `duration_ms`, `exchange_ms` (sum of attempt durations),
`delay_ms`, assertion results (redacted, ≤ 50), top findings (code, title,
confidence, severity; highest severity first, ≤ 5) and the names of
extracted variables. Never response bodies or extracted values.

Totals balance: `steps_executed = steps_passed + steps_failed +
steps_canceled_in_flight`, and every planned step of a started iteration is
exactly one of executed, `steps_errored`, `steps_skipped`, `steps_canceled`.
`transport_failures`, `application_failures` and `assertion_failures` count
executed steps per failed dimension (independent, may overlap);
`assertions_passed/failed` count individual results.

Memory is bounded: the runner keeps summaries only (each execution's body is
dropped after the step), strings are clipped, and at most 10 000 step
summaries are kept — beyond that passing and skipped summaries are omitted
(`steps_omitted` per iteration plus a note) while failed, error and canceled
ones get 2 000 more. Totals always count everything.

The app stores reports encrypted as `run_report` objects (newest 100 per
workspace; deleted with the workspace) and records each executed step in
history exactly like a Send (subject to the history policy).

### Exports

* **JSON** — `anvil_runner::to_json`: the report itself.
* **JUnit XML** — `anvil_runner::to_junit`: one `<testsuite>` per iteration
  (named with the dataset row), one `<testcase>` per retained step.
  Counted transport failures and `error` steps are `<error>` (the test
  could not be carried out); failures only on application status and/or
  assertions are `<failure>` with `type` naming the dimensions; skipped and
  canceled steps are `<skipped>`. Run facts (run id, completion, partial,
  runner version) are suite properties. Every value is escaped and
  characters XML 1.0 cannot carry are replaced with U+FFFD.
* **HTML** — `anvil_runner::to_html`: one standalone file, inline CSS only,
  no scripts, no external requests (an embedded
  `Content-Security-Policy: default-src 'none'` enforces this), every value
  escaped — response-derived text such as assertion values is untrusted.
  Iterations are `<details>` elements, failed ones open.

## Redaction

The engine already redacts sensitive names and the secret variable values it
substituted. The runner adds a run-level exact-value redactor fed by
sensitive dataset values and by values extracted with `sensitive: true` —
which first appear in the response of the step that extracts them, before
any variable carries them. Before a step is recorded in history, its record
(URLs, headers, trailers, failure messages, assertion values, findings,
warnings, stream previews) is scrubbed, and so is the captured response body.
Compressed bytes cannot be scrubbed in place, so while the run holds any such
value a content-encoded body is kept in history only when it was decoded
completely and the decoded content does not contain one; a body whose
decoding was truncated, failed or unsupported, or that was not decoded
because decompression is off, is dropped (raw and decoded) and a run note
says so. Every report string is scrubbed again. The redactor
remembers at most 4 096 values (oldest first out; the current iteration's
values are always present).

## Application and CLI

```rust
app.run_scenario(&scenario_id, RunSettings { .. }, cancel).await? -> RunReport
app.run_folder(&workspace_id, Some(folder_id) /* None = root */, settings, cancel).await?
app.run_plan(plan, settings, cancel).await?
app.run_reports(&ws)? / run_report(&id)? / delete_run_report(&id)?
app.create_scenario / update_scenario / find_scenario / trust_scenario / delete_scenario
app.create_dataset(&ws, name, DatasetFormat::Csv, bytes, sensitive_columns)? / run_dataset(&dataset)?
app.find_folder(&ws, "Orders/Refunds")? / folder_run_requests(&ws, folder)?
```

`RunSettings`: `environment`, `iterations`, `stop_on_failure`, `fail_on`,
`allow_untrusted`, `dataset` (overrides the scenario's), `record_history`
(default true), `persist_report` (default true), `seed`, `events`, `run_id`.

```
anvil run <workspace> (--scenario <name|id> | --folder <path>) [--env <name>]
          [--dataset <file.csv|file.json> [--dataset-format csv|json] [--sensitive-column NAME]...]
          [--iterations N] [--stop-on-failure | --continue-on-failure]
          [--fail-on transport,application,assertions] [--allow-untrusted] [--no-history]
          [--json FILE] [--junit FILE] [--html FILE] [-q]
anvil scenario create <workspace> <name> --step <request>... [--iterations N] [--stop-on-failure]
          [--delay-ms MS] [--dataset FILE [--sensitive-column NAME]...]
anvil scenario list <workspace>
anvil scenario show <workspace> <scenario>
anvil scenario trust <workspace> <scenario>
```

Exit codes follow the CLI convention (0 success · 1 transport/application
failure · 2 assertion failure · 3 local/usage error): `anvil run` exits 2
when any step failed an assertion (and assertions are counted), otherwise 1
when any step failed or was not sent or the run was canceled/aborted, 0 when
everything passed, and 3 when the run could not start (untrusted scenario,
invalid scenario, dataset or folder, locked profile, usage error). Usage
errors now exit 3 as documented, rather than clap's default 2. Ctrl-C
cancels and still writes the partial report files. Live progress goes to
stderr (`-q` silences it); the summary and failing steps go to stdout.

## Tests

`cargo test -p anvil-runner -p anvil-app -p anvil-cli -p anvil-domain` —
real fixture sockets and the real engine throughout:

* `crates/anvil-runner/tests/runner.rs` — chaining (a JSON-extracted token is
  seen by the fixture in the next step's header; `anvil.*` builtins), CSV and
  JSON dataset iterations with a sensitive column absent from JSON, JUnit,
  HTML and history, sensitive extraction redacted everywhere (the engine
  could not know the value), `stop_on_failure` stopping only the iteration
  (the fixture never sees the skipped step) and a configurable `FailOn`,
  assertion vs transport failure (distinct dimensions, JUnit `<failure>` vs
  `<error>`), untrusted refusal with no traffic, cancellation mid-run with a
  partial report, well-formed JUnit with hostile names, HTML escaping of an
  injected `<script>` from a response, report/event bounds, provider errors
  and fatal aborts, and plan validation.
* `crates/anvil-app/tests/runner.rs` — scenario run through the store
  (history records linked from the report, report saved and encrypted at
  rest), export → import → refused until trusted or explicitly allowed,
  folder tree order, stored datasets, and a lock mid-run aborting with a
  partial report and nothing sent afterwards.
* `crates/anvil-cli/tests/cli_run.rs` — the real `anvil` binary: scenario
  create/list/show/trust, all exports, exit codes 0/1/2/3, `--fail-on`,
  `--allow-untrusted`, stored and file datasets.

## Limitations

* Steps run sequentially; there is no concurrency within a run (use the load
  engine for concurrent traffic).
* No scripting: extraction and assertions are the declarative ones of §6.
  There are no conditional steps, loops or step-level retries.
* Session protocols (WebSocket, gRPC streams, SSE, TCP, UDP) run exactly as
  a Send of the saved request runs them (its saved messages and stop
  conditions); there is no interactive session step.
* Only "matched nothing" extraction misses are surfaced in a step's
  `message`; other extraction errors (for example a body that is not JSON)
  are in the step's execution record warnings.
* Exact-value redaction ignores values shorter than 4 characters (the
  engine's rule, to avoid shredding ordinary text); name-based redaction
  still applies. Like every detector, it cannot recognize secrets that were
  never marked as secret.
* Response bodies are not part of any report; they live only in history,
  subject to the history policy.
* The TypeScript bindings in `apps/desktop/src/generated/contracts.ts` must
  be regenerated from the new schemas by the desktop owner
  (`npm run contracts`).
