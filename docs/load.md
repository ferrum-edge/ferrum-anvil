# Native load engine (`anvil-load`)

Implements build plan §14 (load testing) and the worker boundary of §4.3.
Matrix cases LOAD-001…LOAD-014 are mapped to tests at the end of this page.

## Parity with manual Send

Every send in a load run is one call to
`Engine::execute(&ctx, EventCtx::none(), cancel)` — the same preparation,
variable resolution, body serialization, auth application, TLS policy,
transport, diagnostics and outcome classifier as the request editor. So
HMAC nonces, DPoP proofs and JWT time claims are regenerated for every actual
send, and trust settings cannot drift (LOAD-005, LOAD-008).

The load engine adds exactly one settings layer, `run:load`, on top of the
request's own layers:

| Field | Value | Why |
|---|---|---|
| `keepalive` | `true` for `persistent`, `false` for `fresh` | the plan's connection mode |
| `limits.capture_bytes` | `min(request setting, 1 MiB)` | bounded memory per in-flight send; the full body is still read and counted |

It also appends iteration-scoped variable layers (lowest to highest
precedence): `load` (`{{anvil.iteration}}`, `{{anvil.vu}}`), the dataset row,
and values extracted by earlier chain steps. Each send gets a seed derived
from the plan seed, the iteration and the step, so `{{$randomInt}}` /
`{{$randomFrom}}` are reproducible per iteration.

### Slots, connections and tokens

A *slot* is a virtual user (closed), a concurrency lane (iterations) or an
in-flight slot (open). Each slot lazily gets its own `Engine`, so connection
pools and cookie jars are per slot (like per-VU state in other tools), while
all slots share **one** OAuth `TokenCache`. Token refresh is therefore
single-flight across the whole run (LOAD-006). Open-workload slots are reused
LIFO, so only as many engines exist as the peak concurrency actually needed.

## Workloads

Stages ramp linearly from the previous stage's target (0 before the first
stage). A zero-duration stage is an instantaneous step, so a constant load is
`[{0 s → R}, {D s → R}]` and a spike is a step up, a hold and a step down.

* **Closed (`closed_virtual_users`)** — each VU runs iterations back to back
  plus `think_time_ms`. A VU waits for its response before its next
  iteration, so **slowing responses reduce the offered rate**; every report
  carries that label, has no offered rate, and never claims a sustained
  arrival rate (LOAD-002). Inactive VUs sleep until the ramp reaches them
  (activation time is computed, not polled).
* **Open (`open_arrival_rate`)** — arrival *k* is scheduled when the
  integral of the rate reaches *k*, independently of response time. At its
  scheduled time an arrival is started if fewer than `max_in_flight`
  iterations are running; otherwise it is **dropped and counted** — never
  queued. Late timers catch up (they are not skipped), and the start lag
  (scheduled → actually running) is measured per arrival (LOAD-001).
* **Iterations** — a fixed count over `min(concurrency, iterations)` lanes.
  Slowing responses lengthen the run instead of dropping work.

Per iteration: a **weighted mix** picks one request with a deterministic,
seeded function of `(seed, iteration)` (reproducible regardless of
scheduling); otherwise the **chain** runs in order, feeding
`ExecutionOutput.extracted` into later steps. A chain continues after an
application or assertion failure (a complete response exists) and stops at a
transport failure, timeout or cancellation. **Datasets** (CSV with header row,
or a JSON array of flat objects; ≤ 64 MiB, ≤ 1 M rows, ≤ 256 columns) supply
row `iteration mod rows`; the SHA-256 of the exact bytes goes into the report.

**Warmup**: iterations that start (closed/iterations) or are scheduled (open)
in the first `warmup_secs` are excluded from every summary metric. They stay
in the timeline, flagged, and are counted in `warmup_*_excluded`. A run whose
warmup swallowed every iteration says "Nothing was measured".

**Abort rule**: once per progress tick the failure ratio of sends finished in
the trailing `window_secs` is compared with `max_failure_permille` (evaluated
only with ≥ 10 sends in the window; warmup sends count, because the rule
protects the target). Aborting stops scheduling and chains, drains, and marks
the report `aborted_by_rule` and partial.

Every run requires `RunOptions.acknowledged = true` — the UI's explicit start
after showing destination, planned rate/concurrency/duration and the
ownership reminder. Imported plans are never auto-started.

## Accounting

Two ledgers, both balanced at every progress snapshot and in every report
(checked by `report::check_balance` / `check_request_balance` in every
scenario test):

* **Iterations** (`counts`): `scheduled = started + dropped` and
  `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`.
* **Sends** (`requests`, one per `Engine::execute`):
  `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`.

The terminal classes are disjoint. `completed` means a complete response was
received (any status). `application_failures` and `assertion_failures` are
subsets of `completed` and may overlap. `in_flight_at_end` is work whose
outcome is unknown: sends in flight when a crashed worker's last snapshot was
taken, or tasks that ignored cancellation past the drain window. For a
single-request iteration the two ledgers are identical.

Datagram and stream denominators (UDP datagrams, WebSocket/gRPC stream
messages) are **not implemented** (LOAD-013): non-HTTP requests are refused at
validation with an `Unsupported` error, so no count can imply delivery.

## Metrics

* **Latency** is the sum of attempt durations recorded by the engine
  (connect … last body byte, including redirects/retries). Local work around
  it — preparation, token acquisition, retry backoff, record assembly — is the
  separate **setup** distribution, so a token refresh stall is visible without
  polluting request latency.
* **Success** (complete response, application success, assertions passed or
  not run) and **failure** (transport, application or assertion failure, to
  the failure point) are separate HDR histograms.
* **Timeouts are censored.** A send that hits a deadline is counted in
  `timeouts`, excluded from both distributions, and summarised in
  `timeouts_censored` (count, deadlines that elapsed, elapsed-at-abandonment)
  with the label *"a lower bound on the latency the target would have
  produced"* (LOAD-004). Canceled sends have no latency.
* **Histograms are merged, never averaged.** Each shard (≤ 8, slots mapped
  round-robin) owns HDR histograms (1 µs – 1 h; 3 significant figures for
  success/failure, 2 for setup/lag/censored). Aggregation adds histograms and
  only then computes percentiles; the success and failure histograms are
  exported as base64 V2+DEFLATE so saved reports can be merged again.
  LOAD-003 checks merged percentiles against a brute-force sorted array
  (within 0.1 %) and shows averaging per-worker p99s would be off by > 100×.
  Min/max/mean are exact; percentiles are clamped to the exact min/max.
* **Timeline**: one bucket per second (wider if the plan exceeds 3,600 s),
  capped at 3,600 buckets. Sends are bucketed by start (`started`) and by
  completion (`completed`, `failures`, success p50/p99 at 2 significant
  figures); `dropped` counts arrivals; `in_flight` is the peak; `warmup` and
  p99 start lag per bucket. Buckets are finalized one bucket late so their
  percentiles are complete.
* **Bytes** are logical header + body sizes per attempt (HTTP/2 header sizes
  are estimates), not wire bytes. Connections opened vs. reused come from
  engine evidence and match fixture ground truth in the tests.
* **Failure samples**: category = class + top diagnostic finding code (or
  failure kind / status / assertion label), ≤ 32 categories (overflow is
  counted under "other"), ≤ 5 examples of ≤ 400 characters each, built only
  from the engine's redacted record (method, redacted URL, outcome summary,
  failure message, failed-assertion message). Response bodies are never
  retained (LOAD-010).

## Generator health and "target not achieved"

The worker samples its own process: peak CPU (user+system time over wall
time; 100 % = one core), peak RSS (`getrusage(RUSAGE_SELF)`), peak open
descriptors (`/dev/fd`, `/proc/self/fd` on Linux), and start-lag p99/max
(open workloads). On non-Unix platforms these are `None` and the report says
the measurement is unavailable.

For open workloads `target_not_achieved` is set, with the reasons, when any
of these hold:

1. achieved/offered < 0.9 (e.g. arrivals dropped at `max_in_flight`);
2. start lag grows: mean per-bucket p99 lag of the last quarter > 50 ms and
   > 2× the first quarter;
3. p99 start lag over the measured window > 50 ms — every arrival may have
   started, but late, so the offered arrival process was not honoured.

The note states that the run does not establish the target's capacity
(LOAD-007). Local port/address exhaustion (`client.connect.address_unavailable`)
gets its own generator note because it is a generator-side limit. Closed and
iteration workloads have no target rate, and say so.

## Worker process and IPC

`anvil-load-worker` takes **no arguments** (it exits with 64 if given any).

* **stdin, line 1**: one JSON `WorkerJob` (≤ 256 MiB): plan, run options,
  per-request specs and settings/auth/variable layers, the selected TLS and
  proxy profiles, Ferrum trust profiles with their diagnostic-detail
  credentials removed, a map of **scoped secret values**, stored attachment
  bytes (base64, digest-verified) and the dataset bytes.
* **stdin, afterwards**: a `{"cancel":true}` line **or EOF** cancels the run.
  EOF means the parent went away, so a worker never keeps generating traffic
  for a dead app.
* **stdout**: NDJSON `WorkerMessage`s — `started` (run metadata), `progress`
  (≤ 4/s; lossy under backpressure; carries a balanced snapshot plus only the
  timeline buckets finalized since the last delivered progress) and exactly one
  `report`. A refused job yields `error` and exit code 2, and the error text
  never quotes job content (serde messages can echo values).

**Secret handling.** `WorkerJob::from_load_job` resolves only the secrets the
plan's requests actually reference — the effective auth profile, the selected
TLS profile's client identity and the selected proxy password — through each
context's own resolver. Values travel only over the stdin pipe (never argv or
the environment, which other local users can read), are held in zeroizing
buffers, redact in `Debug`, and are rebuilt in the worker as `MemorySecrets` /
`MemoryAttachments`. The LOAD-009 test checks the process table shows no job
content and that a scoped secret was used by every send but never appears in
the report.

**Cancel, drain and crash.** Cancel stops scheduling and further chain steps,
gives in-flight sends `cancel_drain_ms` (default 2 s), then cancels them and
waits 2 s more; anything still running is abandoned and reported as
`in_flight_at_end`. At the normal end of a schedule, in-flight iterations get
`graceful_stop_ms` (default 5 s) before the same sequence, and the report
notes how many were canceled. `LoadController` forwards cancel, kills the
worker if it has not finished within its drain window plus 5 s, and — if the
worker dies without a report — rebuilds a **partial `worker_crashed` report**
from the last progress snapshot and the accumulated timeline, stating that
later sends and the outcome of the in-flight ones are unknown (LOAD-009).
Dropping the controller closes stdin (graceful cancel) and kills the worker
after the same bound. The worker path always comes from the host app, never
from an imported plan.

## Reports

* **JSON** (`report::to_json` / `open_json`): the domain `LoadReport`, sealed
  with `integrity_sha256` (SHA-256 of the canonical JSON with that field
  unset). Reopening verifies the hash, so metrics, configuration, engine
  version and dataset hash are proven unchanged (LOAD-011).
* **CSV**: `summary_csv` (`section,metric,value`) and `timeline_csv`. Cells
  starting with `= + - @` or control characters are prefixed with `'` to
  neutralise spreadsheet formula injection.
* **HTML** (`html::to_html`): one self-contained file — inline CSS and inline
  SVG only, no JavaScript, no external fonts/images/stylesheets, and an
  embedded CSP (`default-src 'none'`). Every dynamic string is escaped;
  response-derived text (e.g. a header value quoted by a failed assertion) is
  rendered inert (LOAD-011). Charts: sends completed/failed and arrivals
  dropped per second, success p50/p99 per second, status distribution; native
  SVG `<title>` hover and a timeline table as the accessible data view; light
  and dark themes. Partial runs and unmet targets carry banners.

## Comparison

`compare(a, b)` lists semantic differences. **Blocking** (latency deltas are
withheld and the reasons returned instead): engine, engine version, workload
model, warmup handling, observed protocol set, connection mode, dataset hash,
request set. **Caution** (deltas shown): request revisions, load level,
completeness/partial, generator saturation, report schema (LOAD-014).

## Measured on this hardware (not product claims)

Apple M4, 10 cores, 16 GB, macOS 26.6.1, release build. The fixture HTTP
server ran in the benchmark process on the same machine; the load engine ran
in a separate `anvil-load-worker` process, whose own CPU/RSS is reported.
The host was shared with other builds (1-minute load average 9–26 during
runs), so these are observations of a contended laptop, not baselines.
Reproduce with `cargo build --release -p anvil-load --bins --examples` and
`target/release/examples/loopback_bench` (1 s warmup on timed runs).

| Scenario (5–6 s) | Observed | Worker CPU (mean / peak, % of one core) | Worker peak RSS |
|---|---|---|---|
| Closed, 32 VUs, persistent, `GET /` | 91,169 / 100,569 / 107,343 iterations/s (three runs); success p50 232–261 µs, p99 0.6–1.0 ms; 0 new connections after warmup | 513–667 % / 591–729 % | 28–29 MiB |
| Open 2,000/s, `max_in_flight` 256, `GET /` | 2,000/s achieved in every run; p99 start lag 1.8 ms and 5.4 ms, but 55 ms (max 88 ms) in a run where host load spiked to 26 | ~28 % / 27–40 % | 26–37 MiB |
| Open 500/s, 20 ms backend | 500/s achieved; success p50 21.2–21.6 ms; p99 start lag 1.5–2.1 ms, but 221 ms (max 269 ms) in the contended run | 8–12 % / 13 % | 27–35 MiB |
| 3,000 iterations × 8, fresh connections | 23,141–29,767 iterations/s; 3,000 connections opened, 0 reused | 227–287 % peak | 24 MiB |

Observations that shaped the implementation:

* The contended runs kept the achieved/offered ratio at 100 % while arrivals
  started up to ~270 ms late. That is why a p99 start lag above 50 ms now marks
  the target as not achieved.
* An unbounded fresh-connection run (8 VUs for several seconds) exhausted the
  machine's ephemeral ports: 16,359 sockets in `TIME_WAIT` against a range of
  16,384 (49152–65535). Every later connection failed with
  `address_unavailable` until they drained. With `net.inet.tcp.msl` = 15 s
  (TIME_WAIT 30 s), one source address sustains at most ~16,384 / 30 s ≈ 546
  new connections/s on this OS. Reports now call this out as a
  generator-side limit.
* One worker process used ~5–7 cores at 91–107k iterations/s for a trivial
  response. Each send runs the full engine path (preparation, diagnostics,
  record assembly) that buys parity with manual Send; the per-send cost has
  not been profiled yet.

## Bounds

| Bound | Value |
|---|---|
| Virtual users / concurrency / `max_in_flight` | ≤ 5,000 / ≤ 5,000 / ≤ 10,000 |
| Arrival rate / duration / iterations | ≤ 100,000/s / ≤ 24 h / ≤ 100 M |
| Chain length | ≤ 64 steps |
| In-memory response capture per send | ≤ 1 MiB (never above the request's setting) |
| Metric shards | ≤ 8 |
| Timeline | ≤ 3,600 buckets |
| Failure categories / examples / example length | 32 / 5 / 400 chars |
| Destinations / protocols listed | 16 / 8 |
| Progress events | ≤ 4/s, worker stdout queue of 8 (lossy for progress only) |
| Job size / controller message size | 256 MiB / 64 MiB |
| Drain windows | graceful stop 5 s, cancel drain 2 s, hard-cancel grace 2 s, controller kill margin 5 s |

## Limitations

* **LOAD-012** (optional JMeter adapter) is not implemented.
* **LOAD-013**: datagram/stream load is refused (see Accounting); there are no
  sent/received denominators yet.
* HTTP/3 goes through the same engine path but has not been exercised under
  load here.
* One worker process per run; there is no multi-process or multi-host
  distribution yet, although `Metrics` and the exported histograms merge.
* Cookie jars are per slot and persist across that slot's iterations.
* `{{$counter}}` restarts for every send (the engine creates a resolver per
  send); use `{{anvil.iteration}}`, dataset rows or `{{$uuid}}` for unique
  values.
* Timeline percentiles are success-only, at 2 significant figures; a record
  that lands after its bucket was finalized updates counts but not
  percentiles.
* Peak CPU is sampled at the progress cadence (≥ 250 ms), so short bursts are
  averaged. Generator health is unavailable on non-Unix platforms.
* `cargo clippy -p anvil-load --tests -- -D warnings` also lints workspace
  path dependencies; with clippy 1.98 it currently fails on 42 pre-existing
  findings in `anvil-transport`, `anvil-engine`, `anvil-auth`,
  `anvil-diagnostics` and `anvil-fixtures` (mostly `result_large_err`).
  `anvil-load` itself is clean (`--no-deps`).

## Matrix coverage

| Case | Test(s) |
|---|---|
| LOAD-001 | `load_001_open_arrivals_balance_with_drops_and_lag` |
| LOAD-002 | `load_002_closed_vus_rate_falls_with_slow_backend` |
| LOAD-003 | `metrics::tests::load_003_merge_histograms_before_percentiles` |
| LOAD-004 | `load_004_timeouts_are_censored_and_counted_separately`, `metrics::tests::load_004_…` |
| LOAD-005 | `load_005_fresh_hmac_nonce_and_valid_signature_per_send` |
| LOAD-006 | `load_006_oauth_refresh_is_single_flight_under_load` |
| LOAD-007 | `load_007_generator_saturation_is_reported_not_blamed_on_target`, `report::tests::load_007_late_starts_…` |
| LOAD-008 | `load_008_load_sends_the_same_request_as_manual_send` (headers, auth, strict TLS failure, TLS profile) |
| LOAD-009 | `load_009_worker_crash_…`, `load_009_cancel_through_controller_…`, `load_009_stdin_eof_cancels_worker_…` |
| LOAD-010 | `load_010_bounded_samples_under_sustained_failures_and_large_bodies`, `metrics::tests::load_010_…` |
| LOAD-011 | `load_011_report_roundtrip_and_html_escape_response_content`, `report::tests::load_011_…`, `html::tests::load_011_…` |
| LOAD-012 | not implemented |
| LOAD-013 | `load_013_datagram_requests_are_refused_not_counted_as_delivered` (refusal only) |
| LOAD-014 | `compare::tests::load_014_incompatible_runs_withhold_latency_deltas` |
