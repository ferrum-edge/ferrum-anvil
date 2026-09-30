# Failure lab

The failure lab (`crates/anvil-lab`) runs failure-matrix scenarios through Anvil's engine against a
**real, pinned Ferrum Edge release binary** and controllable local fixtures, all on loopback. No
gateway response is mocked. Each scenario checks Anvil's conclusion against independent ground
truth (fixture logs, the gateway's operator log, admin endpoints) that the engine never sees.

Supported releases: **v0.9.8** (default, `lab/gateway/RELEASE.lock`), **v0.9.7**
(`lab/gateway/releases/v0.9.7.lock`) and **v0.9.5** (`lab/gateway/releases/v0.9.5.lock`).

## Running

```sh
lab/scripts/fetch-gateway.sh              # download + verify the default pin into lab/bin/<release>/
lab/scripts/fetch-gateway.sh v0.9.5       # an earlier supported release
ulimit -n 4096

cargo run -p anvil-lab -- verify                          # print the verified binary's identity
cargo run -p anvil-lab -- list                            # profiles and scenario counts
cargo run -p anvil-lab -- list <profile>                  # scenario ids of one profile
cargo run -p anvil-lab -- run <profile> --untrusted-pass  # or `run all`
cargo run -p anvil-lab -- run <profile> --scenario <ID>   # repeatable
cargo run -p anvil-lab -- up <profile>                    # keep fixtures + gateway up until Ctrl-C
cargo run -p anvil-lab -- --release v0.9.5 run <profile> --untrusted-pass
```

`fetch-gateway.sh` needs an authenticated `gh`. CI usage is described in
[ci.md § Lab gateway on CI](../ci.md#lab-gateway-on-ci).

- **Release.** `--release <tag>` (or `$ANVIL_LAB_RELEASE`) selects
  `lab/gateway/releases/<tag>.lock`; otherwise the lab uses `lab/gateway/RELEASE.lock`. The trusted
  Ferrum profile of every profile declares that release's compatibility id (`ferrum-edge-0.9.8`,
  `ferrum-edge-0.9.7` or `ferrum-edge-0.9.5`), so diagnoses use its catalog. `run` and `up` refuse to
  start a release Anvil has no catalog for (or only one audited at another commit).
- **Binary lookup.** `$ANVIL_LAB_FERRUM_BIN`, then `lab/bin/<release>/<asset>`, then
  `../lab-bin/<release>/<asset>`, then the legacy unversioned `lab/bin/<asset>` and
  `../lab-bin/<asset>` (`crates/anvil-lab/src/gateway.rs` `candidates`). A binary whose sha256
  differs from the lock is refused; one in a legacy location is skipped instead, since it may belong
  to another release. A git worktree without its own `lab/bin/` should set `ANVIL_LAB_FERRUM_BIN`.
- **Ports.** Every profile uses fixed loopback ports, so two runs of the same profile collide. Stop
  any other lab run first.
- **Results.** Each run writes `results/lab/<stamp>-<profile>/`: `summary.json`, `<ID>.json` (checks,
  observed and recovery summaries, operator-log evidence), `<ID>.record.json` (the full execution
  record) and `gateway-operator*.log`. Per-run state (rendered configs, PKI, sockets, logs) lives in
  `lab/.run/`.
- **Two passes.** `--untrusted-pass` repeats every scenario (as `<ID>-untrusted`) with the destination
  *not* declared as a trusted Ferrum profile. In that pass no `ferrum.token*` or `ferrum.outcome*`
  finding may appear (`crates/anvil-lab/src/harness.rs`). A skip is never counted as a pass.
- **Skips.** A scenario is skipped when it cannot run in this environment, or when the condition it
  tests was not observed within its bounded attempts (`Checks::skip`, for example EARLY-001 and
  EARLY-002 in [early.md](early.md), whose reasons start `window not observed: `). The result names
  the reason; a failed check still fails the scenario.

## Profiles

| Profile | What it covers | Gateway listeners | Fixtures | Doc |
|---|---|---|---|---|
| `core` | Upstream failures, gateway admission, response ownership | HTTP 18080, admin 18090 | 19000–19099 | — |
| `policy` | WAF/bot, OPA, IP, validators, rate/AI limits, concurrency, breaker, header ownership | HTTP 18280, admin 18290 | 19200–19299 | [policy-admission.md](policy-admission.md) |
| `admission` | Overload, retained-buffer capacity, connection ceiling | HTTP 18580, admin 18590; mesh egress 18589 | 19500–19599 | [policy-admission.md](policy-admission.md) |
| `drain` | Graceful shutdown: drain refusal and in-flight completion | HTTP 18680, admin 18690 | 19600–19699 | [policy-admission.md](policy-admission.md) |
| `tls` | Frontend TLS/mTLS, TCP+TLS, DTLS, gateway-to-backend TLS | HTTPS 18343/18344, TCP+TLS 18302, DTLS 18301, HTTP 18380 | 19300–19399 | [auth-tls.md](auth-tls.md) |
| `auth` | Authentication families, IdP/LDAP dependencies, multi-auth, ACL | HTTP 18180, admin 18190 | 19100–19199 | [auth-tls.md](auth-tls.md) |
| `streams` | H1/H2/h2c/H3, WebSocket, gRPC, SSE, TCP/TLS, UDP/DTLS | HTTP 18480, HTTPS+QUIC 18443 | 19400–19499 | [streams-cpdp.md](streams-cpdp.md) |
| `cpdp` | Control plane + data planes: stale-configuration fences | DP 18780, orphan DP 18770, CP admin 18790 | 19700–19799 | [streams-cpdp.md](streams-cpdp.md) |
| `h3x` | SSE over HTTP/3, CONNECT-UDP, DTLS in the tunnel | HTTPS+QUIC 18843/18844/18845 | 19800–19899 | [h3x.md](h3x.md) |
| `mesh` | Mesh client: sidecar mTLS, HBONE ambient, UDP/DTLS | sidecar 17606 (STRICT) / 17626 (PERMISSIVE), HBONE ambient 17618 | 17801–17899 | [mesh.md](mesh.md) |
| `proxyproto` | PROXY protocol v1/v2 and the datagram envelope | streams 18901–18923 | 19901–19930 | [proxyproto.md](proxyproto.md) |
| `workload` | SPIFFE Workload API: X.509-SVID and JWT-SVID | mesh inbound 17406, HTTP 17480 | 17501–17503 | [workload.md](workload.md) |
| `early` | TLS 1.3 / QUIC 0-RTT early data | HTTPS+QUIC 17243/17244 | 17300–17399 | [early.md](early.md) |

`cargo run -p anvil-lab -- list` prints the same list from the profile registry
(`crates/anvil-lab/src/profiles.rs`). Gateway settings and routes are in `lab/gateway/<profile>*`;
the port plan and config citations are in [../audit/gateway-lab-config.md](../audit/gateway-lab-config.md).
