# Samples

Real output of the `anvil` CLI against the core lab gateway on
`127.0.0.1:18080`. `SOURCE.txt` records the Ferrum Edge release, commit,
platform and time the files were made. `crates/anvil-app/tests/samples.rs`
checks that the workspace still imports and the reports still parse.

| File | What it is |
|---|---|
| `workspaces/anvil-samples.anvil` | A workspace exported in "share" mode (no secrets). Six saved requests in three folders: one healthy call, three gateway-to-backend failures (connection refused, unresolvable name, body ended early) and two application errors that only look like gateway problems (a 500, and a 403 that is not a WAF). Import it with **Import → Anvil bundle / backup** or `anvil import samples/workspaces/anvil-samples.anvil`. |
| `reports/collection-run.{json,junit.xml,html}` | A collection run over every request in that workspace: one pass and five diagnosed failures. |
| `reports/load-report.{json,html,csv}` | A 200-iteration fixed load run (concurrency 4) over the healthy request, run in the load worker. It is a smoke run on one machine, not a benchmark. |

The requests point at `http://127.0.0.1:18080`, so they only behave as
described while `anvil-lab up core` is running.

The sample workspace does not declare the lab gateway as a Ferrum gateway
profile, on purpose. The reports show how Anvil treats an undeclared
destination: `X-Gateway-Error` is reported as an unverified marker
(`ferrum.marker.unverified`) and nothing is attributed to a gateway. Declare
the gateway (**Profiles → Ferrum gateways**) and the same requests get
gateway-attributed findings, capped at "likely" (see
[diagnostics.md](../docs/diagnostics.md#confidence-ceilings-why-most-gateway-findings-say-likely)).

## Regenerating

```bash
cargo build -p anvil-cli -p anvil-lab
target/debug/anvil-lab up core &   # lab gateway on 127.0.0.1:18080
scripts/make-samples.sh
```

The script uses a throw-away profile in a temporary data directory and
deletes it afterwards.
