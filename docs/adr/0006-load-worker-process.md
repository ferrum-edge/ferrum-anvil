# ADR 0006: Native load engine in a worker process

## Decision
- The load engine (`anvil-load`) drives `Engine::execute` for every send.
  Auth, TLS, redaction and diagnostics are therefore identical to a manual
  Send, and every iteration gets a fresh nonce, proof and JWT.
- Workloads are open (arrival rate), closed (virtual users) or a fixed
  iteration count. Arrivals are bounded: late or over-cap arrivals are
  dropped and counted, never queued without limit.
- Latency is recorded in mergeable HDR histograms. The ledgers balance, so
  `started = completed + failures + timeouts + canceled + in_flight_at_end`.
  Timeouts are censored. Load-generator limits (schedule lag, port
  exhaustion) are reported as generator problems, not target failures.
- The desktop and CLI re-launch their own executable with
  `--anvil-load-worker` and pass the job over stdin. The job contains only
  the secrets its requests use. A worker crash still produces a partial
  report built from the last progress update.
- A run needs an explicit acknowledgement of its destinations and planned
  load, and imported plans must be reviewed before they can run.

## Consequences
- An unresponsive or crashing worker cannot freeze or corrupt the UI.
- Load of non-HTTP protocols was refused at validation until per-protocol
  denominators existed; ADR 0011 adds them (one load unit per protocol).
