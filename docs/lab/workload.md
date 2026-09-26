# Failure lab: `workload` profile (SPIFFE Workload API)

Anvil as a client of the **real** Ferrum Edge SPIFFE Workload API (gRPC over a Unix socket), using what it
issues — an X.509-SVID as the TLS client identity and a JWT-SVID as the bearer token — against the same
release's mesh inbound listener and a `jwks_auth` route. Pinned releases: **v0.9.7** (`lab/gateway/RELEASE.lock`)
and **v0.9.5** (`lab/gateway/releases/v0.9.5.lock`); the Workload API code is identical in both
(`src/identity/workload_api/server.rs`, `src/identity/jwt_svid/`). No SPIRE, no Kubernetes, no control plane.

Protocol behaviour and findings: [protocols.md §3.11](../protocols.md), [diagnostics.md](../diagnostics.md)
("SPIFFE Workload API and JWT-SVIDs").

**Independent ground truth**, never passed to the engine: the echo fixtures' request logs, each gateway's
operator log — transaction lines (`consumer_username`, `auth_method`, status), the Workload API's debug lines
`workload attested` (with the SPIFFE ID and attestor) and `minted JWT-SVID` (SPIFFE ID, key id, audiences,
lifetime), and its warning `workload attestation failed` — and the lookalike fixture's log.

## 1. Running

```sh
export PATH=/opt/homebrew/opt/rustup/bin:$PATH    # macOS/Homebrew rustup
export ANVIL_LAB_FERRUM_BIN=/path/to/ferrum-edge-macos-aarch64   # checked against the lock
ulimit -n 4096
cargo run -p anvil-lab -- run workload --untrusted-pass
cargo run -p anvil-lab -- --release v0.9.5 run workload --untrusted-pass
cargo run -p anvil-lab -- up workload        # keep everything up; prints the socket and listeners
anvil workload probe --endpoint unix:///private/tmp/anvil-lab-wl-$(id -u)/mesh.sock --audience spiffe://anvil.lab/api/orders
```

Results go to `results/lab/<stamp>-workload/` (`summary.json`, `<ID>.json`, `<ID>.record.json`,
`gateway-operator*.log`, `sockets.txt`). Every gateway configuration is validated by the real binary
(`ferrum-edge validate`) before it starts. The profile needs Unix domain sockets (macOS, Linux).

### Identity and attestation

Ferrum Edge's Workload API is off by default (`FERRUM_MESH_WORKLOAD_API_ENABLED`, `src/config/env_config.rs:4647-4658`)
and can only be served with `FERRUM_MESH_CA_BACKEND=internal` and the dev-only self-signed root
(`FERRUM_MESH_CA_BOOTSTRAP_DEV=true`); it is refused under `FERRUM_MESH_PRODUCTION_MODE=true` (docs/mesh.md
"Workload API JWT-SVID", ~line 4906). It attests a caller only by the kernel peer credentials of the socket:
`FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES=uid:<uid>=<spiffe-id>` (`src/identity/attestation/unix.rs`; the
server reads `SO_PEERCRED` / `getpeereid` through tonic's `UdsConnectInfo`, `server.rs:397-415`). The lab writes a
rule for **the uid Anvil runs as** (read from a directory it just created), so the gateway attests the lab
process itself as `spiffe://anvil.lab/ns/lab/sa/anvil-client`. A second instance maps the uid + 1, so it refuses
Anvil. Every call must carry `workload.spiffe.io: true` (`server.rs:145`, `validate_workload_metadata`).

The JWT signing key is a per-run ES256 (P-256) key passed as `FERRUM_MESH_JWT_SIGNING_KEY_PEM` (read from the
environment, `src/identity/mod.rs:160`), so the published `kid` (the RFC 7638 thumbprint) and JWKS are stable
for the run. JWT-SVIDs live 5 s here (`FERRUM_MESH_JWT_SVID_TTL_SECONDS=5`; default 300 s,
`src/identity/jwt_svid/mod.rs:96`; the authority clamps to [1, 3600]) so a token the Workload API issued can
expire during the run.

### Socket placement

The socket must meet Ferrum's contract (`src/identity/workload_api/listener.rs`,
`WorkloadApiSocketConfig::validate`): an absolute path whose parent is at most **74 bytes** (the socket is bound
in a staging directory inside `sun_path`) and whose **every** ancestor is a real directory owned by this user or
root and not group/world-writable without the sticky bit. The lab uses `lab/.run/workload/wapi` when it
qualifies, else a private `0700` directory `anvil-lab-wl-<uid>` under `/private/tmp` (macOS, where `/tmp` is a
symlink the contract refuses) or `/tmp` (Linux), and records the choice and the reason in `sockets.txt`. On the
development machine the worktree path is 119 bytes and `/Volumes/JustusStorage` is group-writable, so the
sockets live in `/private/tmp/anvil-lab-wl-501/`: `mesh.sock`, `foreign.sock`, and `disabled.sock` (never bound).

### Instances and ports

Gateway listeners use 17400–17499, fixtures 17500–17599; everything binds `127.0.0.1`, and every mesh listener is
remapped (a unit test in `crates/anvil-lab/src/workload.rs` checks the configuration files).

| Instance | Config | Role | Listeners | Admin |
|---|---|---|---|---|
| `workload-mesh` | `lab/gateway/workload-mesh.{conf,json}` | mesh sidecar (STRICT), internal CA, Workload API attesting Anvil's uid, JWT-SVIDs 5 s | inbound mTLS `17406` → echo `17501`; outbound 17401, HBONE 17408, egress 17409, DNS 17453 (off) | 17490 |
| `workload-foreign` | same files | the same, attestation rule for another uid | 17426/17421/17428/17429/17455 | 17492 |
| `workload-proxy` | `lab/gateway/workload-proxy.{conf,yaml}` | file mode; `/wl/jwt` → echo `17502` behind `jwks_auth` with the **JWKS the workload-mesh Workload API returned** (`FetchJWTBundles`, fetched by Anvil's own client after workload-mesh is up and rendered inline) and audience `spiffe://anvil.lab/api/orders` | HTTP `17480` | 17491 |
| fixtures | `anvil_fixtures::http` | mesh workload echo 17501, API echo 17502, lookalike 17503 | | |

Ferrum Edge has no data-path JWT-SVID verifier; `jwks_auth` validates a JWT-SVID as an ES256 JWT: JWT-SVIDs
carry no `iss`, so the provider names none (`jwks_auth.rs` then tries every provider), and it validates
`exp`/`nbf` with a **0-second** leeway (`jwks_auth.rs:2049`).

## 2. Scenarios

Every scenario also runs untrusted (the gateway listeners not declared as Ferrum) and must then make no
gateway attribution.

| ID | Stimulus | Anvil's conclusion (public evidence) | Ground truth |
|---|---|---|---|
| WL-001 | HTTPS to the STRICT mesh inbound with a TLS profile whose identity is the **Workload API X.509-SVID** and whose trust is the SVID's bundle; server verified by SPIFFE ID `…/sa/workload-svc` | success; `FetchX509SVID` OK at the socket (or reused from the cache until half-life); client SVID `…/sa/anvil-client` presented; server verified by exact SPIFFE ID; no key material in the record | echo got `/echo`; operator 200 inbound transaction; `workload attested spiffe_id=…/anvil-client attestor=unix` |
| WL-002 | JWT-SVID from the Workload API (`FetchJWTSVID`, audience `…/api/orders`, bundle verification on) to `/wl/jwt/echo` | success; subject, audience, expiry and bundle-signature checks passed; ES256; the token never in the record | API echo got `/echo`; operator 200 with `auth_method=jwks_auth`, `consumer_username=…/anvil-client`; `minted JWT-SVID` |
| WL-003 | JWT-SVID for `…/api/billing` (not the route's audience) | 401 `{"error":"Invalid or unrecognized JWT"}`; Anvil's audience and signature checks **passed** (it got the audience it asked for); `auth.jwt_svid_rejected` (unknown, scope unknown) quoting the body with `jwt_svid.aud` as evidence and "expects a different audience" as an alternative; no audience-mismatch claim | API echo got nothing; operator 401 transaction |
| WL-004 | a JWT-SVID the Workload API issued, 6 s later (expired), as a variable | refused before sending: `jwt_svid_rejected_locally`, `auth.jwt_svid_expired` (confirmed, local), signature still verified; `not_dispatched`; no destination/gateway finding | API echo and proxy log: nothing |
| WL-005 | the same token with **send despite failed checks** | sent; 401 with the jwks_auth body; `auth.jwt_svid_expired` kept as a warning; `auth.jwt_svid_rejected` (unknown) lists the failed expiry check only as an alternative; evidence marks the send | operator 401 transaction; API echo nothing |
| WL-006 | JWT-SVID with the endpoint `unix:///…/disabled.sock` (where a Workload API with the default `FERRUM_MESH_WORKLOAD_API_ENABLED=false` binds nothing) | `workload_api_unavailable`, `local.workload_api_unavailable` (confirmed, local) naming the socket and "no Workload API socket exists"; `not_dispatched` | no socket at the path; proxy log and API echo: nothing |
| WL-007 | X.509-SVID from `workload-foreign` (rule for another uid) | `workload_api_denied`, `local.workload_api_denied` (confirmed) with `grpc.status 7 (PERMISSION_DENIED)`, the server's message and Anvil's `process.uid`; `not_dispatched` | workload-foreign: `workload attestation failed … no unix attestor rule matched the peer`; mesh echo and inbound log: nothing |
| WL-008 | an ES256 token with the trust domain's `kid` but signed by another key, bundle verification on | refused before sending: `auth.jwt_svid_invalid` (signature does not verify with the `anvil.lab` bundle from `FetchJWTBundles`); expiry passed | proxy log and API echo: nothing |
| WL-009 | lookalike: the JWT-SVID sent to a backend fixture answering the jwks_auth body byte for byte | 401; `auth.jwt_svid_rejected` (unknown, scope unknown); no `ferrum.token`/`ferrum.outcome`, no confirmed gateway claim | the lookalike fixture answered |

## 3. What the lab found

- **v0.9.5 serves the same Workload API.** `src/identity/workload_api/` and `src/identity/jwt_svid/` are
  unchanged between v0.9.5 and v0.9.7 (only `ca/internal.rs`, `spiffe/id.rs` and `spiffe/trust_domain.rs` differ,
  in PEM parsing and error-message quoting), and all nine scenarios pass on both releases. No release-aware skip
  is needed.
- **The socket contract rules out most repository paths.** A worktree path longer than 74 bytes or any
  group-writable ancestor (a shared volume) makes `ferrum-edge validate` refuse the configuration; the lab
  therefore checks the contract itself before starting and falls back to a private temporary directory.
- **Attestation is by uid only, and it works on macOS.** The `workload attested … attestor=unix` debug line
  shows the rule matched Anvil's uid through the socket's peer credentials on macOS too (the attestor module's
  comment expects non-Linux platforms to decline; the uid from tokio's `getpeereid` path is enough for a
  uid-only rule). A uid without a rule gets the fixed
  `PERMISSION_DENIED "workload attestation failed"` — the reason (`no unix attestor rule matched the peer`) is
  only in the operator log, which is why Anvil's finding names the uid and lists the causes as alternatives.
- **jwks_auth authenticates the SPIFFE ID.** A JWT-SVID accepted by `jwks_auth` appears in the transaction log
  with `consumer_username` = the SPIFFE ID and `auth_method=jwks_auth` — useful operator evidence, and the reason
  WL-002 can check whose identity reached the API.
- **One public answer for every rejected token.** Wrong audience, an expired token and a foreign key all give
  `401 {"error":"Invalid or unrecognized JWT"}` (`jwks_auth.rs:1100,1130`), and with a 0-second leeway an
  expired token is rejected at once. Anvil's local checks are the only place the difference shows; they are
  evidence, never the verifier's stated reason.
- **The trusted pass adds only the Ferrum catalog's generic plugin outcome** (`ferrum.outcome`, likely,
  `gateway_admission`) next to `auth.jwt_svid_rejected`; the untrusted pass has no `ferrum.*` gateway
  attribution.

## 4. Stability

Three consecutive `anvil-lab run workload --untrusted-pass` runs on v0.9.7 and one on v0.9.5, on 2026-09-26 on
the final code (macOS arm64; binaries `ferrum-edge-macos-aarch64`, sha256 from the lock files):

| Run | Release | Result |
|---|---|---|
| 1 (`results/lab/20260926T045317Z-workload`) | v0.9.7 | 18 passed, 0 failed, 0 skipped |
| 2 (`results/lab/20260926T045327Z-workload`) | v0.9.7 | 18 passed, 0 failed, 0 skipped |
| 3 (`results/lab/20260926T045336Z-workload`) | v0.9.7 | 18 passed, 0 failed, 0 skipped |
| 4 (`results/lab/20260926T045345Z-workload`) | v0.9.5 | 18 passed, 0 failed, 0 skipped |

18 = 9 scenarios × (trusted + untrusted pass). No untrusted run produced a `ferrum.token.*` or `ferrum.outcome*`
finding. In every run the untrusted WL-001 reused the X.509-SVID the trusted pass had fetched (Anvil's cache
holds it until half its 1-hour lifetime), which the evidence records as a cached call; its attestation line is
the earlier fetch's.

## 5. Limitations

- No SPIRE agent in the lab: SPIRE serves the same standard `SpiffeWorkloadAPI`, which the independent fixture
  (`anvil_fixtures::workload_api`, SPIRE-style `spiffe://` bundle keys) and Ferrum Edge's server exercise here.
- Ferrum Edge's Workload API is dev/test-only (internal CA bootstrap), so the lab cannot show a production-mode
  posture; production deployments use a SPIRE agent's socket.
- Federated trust domains, `ValidateJWTSVID` and Windows named pipes are not driven live (see
  protocols.md §5, item 9).
