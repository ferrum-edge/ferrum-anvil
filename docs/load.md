# Native load engine (`anvil-load`)

Implements build plan §14 (load testing), the per-protocol load actions of §7
(ADR 0011) and the worker boundary of §4.3. Matrix cases LOAD-001…LOAD-014 are
mapped to tests at the end of this page.

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
| `keepalive` | `true` for `persistent`, `false` for `fresh` | the plan's connection mode (HTTP pools and gRPC channels) |
| `limits.capture_bytes` | `min(request setting, 1 MiB)` | bounded memory per in-flight send; the full body is still read and counted |

It also appends iteration-scoped variable layers (lowest to highest
precedence): `load` (`{{anvil.iteration}}`, `{{anvil.vu}}`), the dataset row,
and values extracted by earlier chain steps. A request under an unopened
import root (see [import.md](import.md#persisting-an-import-anvil-app)) gets no
dataset row and only values extracted by chain steps under the same root;
values it extracts reach only those steps (`ExecutionContext::scope`, carried
to the worker). Each send gets a seed derived
from the plan seed, the iteration and the step, so `{{$randomInt}}` /
`{{$randomFrom}}` are reproducible per iteration.

### Slots, connections and tokens

A *slot* is a virtual user (closed), a concurrency lane (iterations) or an
in-flight slot (open). Each slot lazily gets its own `Engine`, so connection
pools, gRPC channels and cookie jars are per slot (like per-VU state in other
tools), while all slots share **one** OAuth `TokenCache`. Token refresh is
therefore single-flight across the whole run (LOAD-006). Open-workload slots
are reused LIFO, so only as many engines exist as the peak concurrency
actually needed. A slot's pools keep as many idle connections as the plan has
distinct requests (at least 4, at most 64), so a persistent chain reuses each
step's connection across iterations (see `docs/architecture.md`).

## Load units per protocol (LOAD-013)

Every step of a plan is one `Engine::execute` call — the same preparation,
variables, auth, TLS profile and trust, proxy, DNS and timeout settings as a
manual Send, through the same session adapter — and produces one **unit**.
What a unit is depends on the request's protocol (`anvil_load::protocol`):

| Unit (`LoadUnitKind`) | Requests | One unit is | Completed means | Success means | Latency (`latency_success`/`_failure`) | Protocol denominators |
|---|---|---|---|---|---|---|
| `http_request` | HTTP/1.1, HTTP/2, HTTP/3 (forced or automatic) | one request/response; redirects, retries and an HTTP/3 → TCP fallback are attempts inside it | complete response (any status) | status < 400, no SOAP fault / GraphQL error, assertions pass | sum of attempt durations, fallback attempt included | fallback attempts, requests with a fallback, requests over HTTP/3 |
| `grpc_call` | unary gRPC (native over HTTP/2 or HTTP/3, gRPC-Web) | one call = one send | a terminal `grpc-status` with complete framing (any code) | status 0 and assertions pass; HTTP 200 alone never | sum of attempt durations (channel checkout … status) | status codes (code → count), OK, non-OK, **missing status**, fallback attempts |
| `grpc_stream` | server-streaming gRPC / gRPC-Web | one stream | the server ended it with a terminal status and complete framing | status 0 and assertions pass | stream duration (call start … status) | streams opened, messages received, streams with messages, **time to first message**, plus the gRPC block |
| `sse_stream` | SSE | one stream | the stream ended without a failure: the server ended it, or the request's `max_events` / idle timeout stopped it; an error status completes as an application failure | a 2xx event stream and assertions pass | stream duration | streams opened, events received, streams with events, **time to first event**, how streams ended (peer / client / timeout / abnormal) |
| `websocket_session` | WebSocket (HTTP/1.1 Upgrade, HTTP/2 or HTTP/3 extended CONNECT) | one session: handshake, scripted messages, close | handshake answered and the session ended without a failure (close by either side, `expect_messages`, idle close); a rejected handshake completes as an application failure | accepted handshake, close 1000/1001/none, assertions pass | session duration (connect … close) | opened, handshake rejected, not opened, closed cleanly, messages sent/received, close codes by who closed, **round-trip time only when `expect_messages` is set** |
| `tcp_exchange` | raw TCP / TLS | one connection carrying the request's frames | connected, frames sent, reading stopped on a stop condition (expected frames, max bytes, read-idle, peer close) without a failure | completed, the expected frames arrived (when `expect_frames` is set with a framing preset), assertions pass; fewer frames = application failure | exchange duration (connect … end of reading; includes the read-idle wait when the exchange ends on idle) | connections, frames sent/received, payload bytes, partial trailing frames, peer closes, expectation met/short |
| `udp_exchange` / `dtls_exchange` | UDP / DTLS | the request's datagrams, then its response window (DTLS: after a handshake) | the window elapsed (or `max_datagrams` arrived) without a local failure — says nothing about delivery | at least one datagram received and assertions pass; **a completed exchange with nothing received is "no response observed": neither success nor failure, and it has no latency** | time to first response (first datagram sent → first received in the same exchange; not attributed to a specific datagram) | datagrams sent, datagrams received (separate counts), exchanges with a response / with no response observed, repeated payloads, echoed / other payloads, ICMP-unreachable exchanges, DTLS handshakes (attempted, completed, failed, timed out, duration) |

A plan has **exactly one unit kind**, so every count, rate and percentile in
its report has one denominator. The editor (`load_plan_check`), the preflight
and `anvil load check` name the unit and its definitions before a run.

**Refused before any traffic** (`LoadError::Refused`, a typed `Refusal`
with a `RefusalCode`; the editor shows it and cannot start the run):

| Code | Why |
|---|---|
| `mixed_unit_kinds` | A chain or mix whose requests produce different units (e.g. an HTTP login followed by a WebSocket session). Their counts and latencies have different denominators; split the plan per protocol. |
| `grpc_client_streaming`, `grpc_bidirectional` | A long-lived client or two-way stream has no single completion or per-message denominator yet. |
| `grpc_reflection` | With server reflection every call would first run a reflection RPC, so a unit would not be one call. Import the `.proto` files or a descriptor set. |
| `sse_reconnect` | Automatic reconnection turns one stream into several connections with server-chosen delays. |
| `udp_masque` | UDP through a MASQUE (CONNECT-UDP) proxy would open a QUIC connection and tunnel per exchange; there are no tunnel denominators. |
| `udp_hbone` | UDP or DTLS through a mesh HBONE datagram tunnel would open an mTLS connection and tunnel per exchange; there are no tunnel denominators. |
| `hbone_persistent` | HTTP or gRPC through a mesh HBONE proxy in persistent mode: tunnels carry one execution's identity and are never pooled, so persistent mode could not be honoured. Fresh mode is allowed (it is what would happen). |
| `early_data` | The request enables 0-RTT early data: handshakes that share session tickets are serialized (their evidence is per connection) and the report has no early-data denominators. |
| `incomplete_request` | A gRPC request without a service, method or schema. |

Interactive sessions (`Engine::open_session`) are never used by a load run:
each unit runs the automation path, so the request's script, stop conditions,
idle close and total deadline apply, and interactive commands (send, ping,
half-close typed into a live session) have no load equivalent. No request
setting is interactive-only; the gRPC call modes that exist mainly for
interactive use (client streaming, bidirectional) are refused above.

Combinations the engine itself refuses (e.g. native gRPC with HTTP/1.1-only,
gRPC over HTTP/3 with a cleartext URL, UDP through an HTTP proxy) keep failing
per send with `unsupported_combination` before any bytes are written; they
are local failures in the ledger, never successes. An abort rule stops such a
run early.

**Connection modes per unit.** For HTTP requests and gRPC calls/streams,
*persistent* keeps pooled connections per virtual user: HTTP keep-alive and
one multiplexed HTTP/2 or HTTP/3 connection per origin, and for gRPC one
pooled **channel** per destination (`anvil_transport::grpc::Channels`, set on
each slot's engine): a multiplexed HTTP/2 or HTTP/3 connection, or an HTTP/1.1
connection used by one gRPC-Web call at a time. A channel is returned only
while it is open (HTTP/2) or after a clean call (HTTP/3, HTTP/1.1); a canceled
HTTP/3 stream closes its connection instead. *Fresh* opens a connection per
unit. Manual Send never uses channels (each call opens its own connection so
its evidence covers the whole setup). SSE streams, WebSocket sessions, TCP
exchanges and UDP/DTLS exchanges always open their own connection or socket;
the connection mode does not apply to them, and the preflight, report and
comparison say so.

**What is never claimed.** Sent datagrams are never counted as delivered,
received datagrams are never attributed to sent ones, silence is never a
failure or a loss, a WebSocket round trip is never reported without a defined
pairing, a gRPC deadline that elapsed locally is never reported as
`DEADLINE_EXCEEDED`, and HTTP 200 is never a gRPC success.

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
* **Units** (`requests`, one per `Engine::execute`, i.e. one request, call,
  stream, session or exchange):
  `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`.

The terminal classes are disjoint. `completed` follows the unit's definition
(table above). `application_failures` and `assertion_failures` are subsets of
`completed` and may overlap. `in_flight_at_end` is work whose outcome is
unknown: units in flight when a crashed worker's last snapshot was taken, or
tasks that ignored cancellation past the drain window. For a single-request
iteration the two ledgers are identical.

**Protocol denominators** (`protocol_metrics`) balance against the unit
ledger; `report::check_protocol_balance` checks them in every scenario test,
and the HTML report says "WARNING: counts do not balance" otherwise. With
`settled = started − in_flight_at_end`:

* gRPC: `Σ status_codes = ok + non_ok = completed`, `non_ok = application_failures`,
  `missing_status ≤ transport_failures + timeouts` (a missing status is
  incomplete, never completed).
* Streams: `opened ≤ settled`, `with_messages ≤ opened`; SSE `Σ ended_by = opened`.
* WebSocket: `opened + handshake_rejected + not_opened = settled`,
  `closed_cleanly ≤ opened`, `Σ close_codes = opened`, and no RTT pairs
  unless a pairing is defined.
* TCP: `connected ≤ settled`; `expectation_met + expectation_short = completed`
  when the request expects frames; short exchanges are application failures.
* UDP/DTLS: `exchanges_with_response + exchanges_silent = completed`;
  echoed and repeated payloads ≤ datagrams received; DTLS
  `completed + failed + timed_out ≤ attempted ≤ settled`.

Progress snapshots are **one consistent cut**: a finished unit updates its
shard (metrics) and the ledger under the shard lock, and a snapshot locks
every shard before reading the ledger, so the identities above also hold in
live progress and in a crash report rebuilt from the last snapshot.

## Metrics

* **Latency** is the sum of attempt durations recorded by the engine
  (connect … last body byte, including redirects/retries; for streams and
  sessions, until the stream or session ended). For UDP/DTLS exchanges it is
  the time to first response instead, because an exchange's duration includes
  its fixed response window. Local work around it — preparation, token
  acquisition, retry backoff, record assembly — is the separate **setup**
  distribution, so a token refresh stall is visible without polluting unit
  latency.
* **Success** (the unit's success definition) and **failure** (transport,
  application or assertion failure, to the failure point) are separate HDR
  histograms. Percentiles exist only over units in them: with no successful
  unit, reports show "—", never 0 µs. A UDP exchange with no response
  observed is in neither.
* **Protocol distributions** — time to first message/event (streams),
  WebSocket round trips, UDP time to first response and DTLS handshake
  duration — are HDR histograms too (2 significant figures), merged across
  shards before percentiles, reported as summaries.
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
  bytes (base64, digest-verified: request bodies and the `.proto` files or
  descriptor set a gRPC request's schema needs) and the dataset bytes.
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
from an imported plan. A worker exits the process right after writing its
report, without dropping its runtime: the runtime's blocking stdin reader
would otherwise keep a finished worker alive (the `anvil` CLI's worker mode
had exactly that bug until the protocol-load CLI test exposed it). A crash
report carries the plan's unit kind, taken from the job's first request when
the worker never announced its run.

## Reports

* **JSON** (`report::to_json` / `open_json`): the domain `LoadReport`, sealed
  with `integrity_sha256` (SHA-256 of the canonical JSON with that field
  unset). Reopening verifies the hash, so metrics, configuration, engine
  version and dataset hash are proven unchanged (LOAD-011). The typed
  `protocol_metrics` block (`ProtocolLoadMetrics`: `version` =
  `PROTOCOL_METRICS_VERSION` 1, `unit`, `semantics`, and one family block —
  `http`, `grpc` (+ `stream` for server streaming), `stream` (SSE),
  `websocket`, `tcp` or `datagram`) is part of the sealed content: changing a
  denominator breaks the seal. Reports written before protocol load reopen
  unchanged (`protocol_metrics` absent means HTTP requests).
* **CSV**: `summary_csv` (`section,metric,value`) and `timeline_csv`. Cells
  starting with `= + - @` or control characters are prefixed with `'` to
  neutralise spreadsheet formula injection. The summary adds `unit,*` rows
  (kind, version, definitions) and one section per family (`grpc`,
  `grpc_status`, `stream`, `websocket`, `websocket_close`, `tcp`, `datagram`,
  `dtls_handshake`); `datagram,observed_received_per_sent` is labelled an
  observation, and empty distributions have empty values, not zeros.
* **HTML** (`html::to_html`): one self-contained file — inline CSS and inline
  SVG only, no JavaScript, no external fonts/images/stylesheets, and an
  embedded CSP (`default-src 'none'`). Every dynamic string is escaped;
  response-derived text (e.g. a header value quoted by a failed assertion) is
  rendered inert (LOAD-011). Charts: sends completed/failed and arrivals
  dropped per second, success p50/p99 per second, status distribution; native
  SVG `<title>` hover and a timeline table as the accessible data view; light
  and dark themes. Partial runs and unmet targets carry banners. A
  **Protocol** section shows the unit's definitions and its denominators
  (gRPC codes with their names, stream and session counts, close codes by who
  closed, round trips or "not defined", frames, datagrams with the observed
  ratio labelled "not a delivery rate", DTLS handshakes); labels use the
  unit's own nouns ("Successful sessions", "Failed exchanges").

The desktop report view and live panel show the same unit counts and a
protocol panel; the CLI prints one line per family after a run.

## Comparison

`compare(a, b)` first compares the **load unit**: runs of different units
(e.g. HTTP requests vs WebSocket sessions vs UDP exchanges) are **refused**
outright — `compatible = false`, one blocking difference (`load unit`), no
deltas, summary "Refused: …" (LOAD-013). Otherwise it lists semantic
differences. **Blocking** (latency deltas are withheld and the reasons
returned instead): engine, engine version, workload model, warmup handling,
observed protocol set, connection mode (only a *caution* for units that open
their own connection in either mode), dataset hash, request set. **Caution**
(deltas shown): request revisions, load level, completeness/partial,
generator saturation, report schema (LOAD-014). Comparable runs get
success-latency deltas only when both have successful units, the achieved
rate, the **failed-unit ratio**, censored timeouts and dropped arrivals, plus
per-protocol ratios (non-OK and missing-status ratios, messages per opened
stream or session, time-to-first-message and round-trip percentiles, frames
per exchange, the observed received/sent datagram ratio and the
no-response ratio).

The failed-unit ratio is failed units over finished units (completed,
transport failures and timeouts; canceled and in-flight units are excluded).
A unit counts once however many ways it failed: a completed unit with an
application failure, a failed assertion or both is one failed unit, exactly
as `SendObservation::is_failure` decides per unit. Because
`application_failures` and `assertion_failures` may overlap, neither their
maximum nor their sum is that count; the ratio uses the failure-latency
distribution (one entry per failed non-timeout unit) plus the ledger's
timeouts, kept within the bounds the two counters imply.

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
* **Refused protocol combinations** (table above): client-streaming and
  bidirectional gRPC, gRPC with server reflection, SSE with reconnection,
  UDP through MASQUE, HTTP/gRPC through HBONE in persistent mode, and
  mixed-protocol plans. There is no "long-lived stream" load action yet
  (sessions held open while messages are sent at a rate); a WebSocket session
  unit is connect → scripted messages → close.
* WebSocket round trips pair the i-th scripted data message with the i-th
  data message received (the adapter sends the whole script, then reads), so
  they fit echo-style exchanges; a session whose reply arrives before its
  message, or whose transcript exceeded the 2,000-entry bound, is counted as
  unpaired and contributes no round trip.
* UDP payload observations compare bytes within one exchange only: "echoed"
  means byte-identical to a datagram sent in that exchange, "repeated" means
  identical to an earlier received one. Neither is a delivery or duplication
  claim.
* A pooled gRPC channel that the peer closes between the pool's liveness
  check and the next call fails that call like any call (it is not retried);
  the channel is then replaced.
* Per-unit distributions of message counts (messages per stream or session)
  are reported as totals and means, not percentiles.
* HTTP/3 with the automatic policy re-attempts QUIC for every request (there
  is no "QUIC broken" memory); each failed attempt is counted and its time is
  part of the request's latency.
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
| LOAD-013 | `load_013_udp_sends_more_than_it_receives_and_never_claims_delivery` (lossy, silent, duplicating and closed-port UDP: sent and received separate, silence neither success nor failure, no latency without a response); `load_protocols.rs` (HTTP/3 forced and fallback, unary gRPC codes/missing status/channel reuse over HTTP/2, HTTP/3 and gRPC-Web HTTP/1.1, server streams and deadlines, SSE stop conditions, WebSocket sessions/RTT/rejections/abnormal ends, TCP expectations/partial frames/peer closes, DTLS handshakes, typed refusals, acknowledgement and lock-stops-run through the worker for every protocol, cross-protocol comparison refused, integrity over protocol metrics); `cli_load.rs` (CLI parity); `specs_load.rs::load_plan_check_…` (app preflight); `LoadView.test.tsx` (renderer); lab `LOAD-013-grpc`, `LOAD-013-ws`, `LOAD-013-udp` (streams profile, real gateway) |
| LOAD-014 | `compare::tests::load_014_incompatible_runs_withhold_latency_deltas` |

### Live lab check (real gateway)

The `streams` lab profile runs three short, low-rate load plans through the
real Ferrum Edge gateway (loopback only) and compares Anvil's counts with
independent ground truth:

* `LOAD-013-grpc` — 30 unary calls over h2c (3 virtual users, persistent),
  dataset rows choosing OK or PERMISSION_DENIED: Anvil reports
  `status_codes = [(0, 20), (7, 10)]`, 20 success samples, ≤ 3 connections;
  the backend received exactly 30 calls and the gateway's transaction log
  holds 30 `/anvil.lab.v1.Echo/Unary` lines with `grpc_status` 0 × 20 and
  7 × 10.
* `LOAD-013-ws` — 10 WebSocket sessions (2 messages each, `expect_messages`
  2): 10 opened and closed cleanly by Anvil with 1000, 20 messages each way,
  20 round trips; the backend received exactly 20 messages and the gateway
  logged 10 upgrades and 10 session ends.
* `LOAD-013-udp` — 5 exchanges of 4 datagrams to the lossy backend: Anvil
  reports 20 sent and 10 received as separate counts with no delivery claim,
  while the backend's own log shows all 20 arrived.

Each runs in the trusted and untrusted passes, on v0.9.7 and v0.9.5.
