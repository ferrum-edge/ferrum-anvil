# Failure lab: `mesh` profile (Ferrum Mesh client)

Anvil tested as a **mesh client** against the real, pinned Ferrum Edge **v0.9.7** release binary
(`lab/gateway/RELEASE.lock`) in **mesh mode**. There is no Kubernetes, no control plane and no
traffic capture: every gateway runs the documented localized file source
(`FERRUM_MESH_CONFIG_PROTOCOL=file`, docs/mesh.md "Localized file source (no control plane)") with
file-based SVIDs (`FERRUM_GATEWAY_SVID_*`, "File-Based SVIDs: Two-Process Local Mesh"), and Anvil
dials the mesh listeners directly. Anvil verifies every listener by **SPIFFE ID** (no verification
bypass) and presents the lab client SVID.

The profile exercises the client features added for mesh testing (`docs/protocols.md` §3.9):
the HBONE proxy profile, SPIFFE server-identity verification, the SNI override, and UDP through an HBONE
tunnel (Ferrum Mesh datagram-over-HBONE, MESH-018 to MESH-028).

**Independent ground truth**, never passed to the engine: the echo fixture's request log (did the
workload receive the request?), the UDP fixtures' datagram logs (sizes, in order), and each gateway's
operator log (transaction lines, TLS handshake warnings, the HBONE gate warnings, the debug-level
relay-synthesis refusal with its reason and the debug-level `HBONE UDP tunnel relay completed` line with
the relayed byte counts).

## 1. Running

```sh
export PATH=/opt/homebrew/opt/rustup/bin:$PATH    # macOS/Homebrew rustup
export ANVIL_LAB_FERRUM_BIN=/path/to/ferrum-edge-macos-aarch64   # checked against RELEASE.lock
ulimit -n 4096
cargo run -p anvil-lab -- run mesh --untrusted-pass
cargo run -p anvil-lab -- run mesh --scenario MESH-008     # one scenario
cargo run -p anvil-lab -- up mesh                          # keep everything up for manual use
```

Results go to `results/lab/<stamp>-mesh/` (`summary.json`, `<ID>.json`, `<ID>.record.json`,
`gateway-operator*.log`). The per-run SPIFFE PKI is generated into `lab/.run/mesh/pki/`
(`ca.pem`, `svc.pem`/`.key`, `ztunnel.pem`/`.key`, `client.pem`/`.key`, `foreign-client.pem`/`.key`,
`foreign-ca.pem`); CA private keys are never written, nothing is committed and nothing is added to a
system trust store. `up mesh` prints the listeners and the client SVID paths for desktop use.

Every gateway configuration is validated by the real binary (`ferrum-edge validate -m mesh -s … -c …`)
before it starts.

### Instances and ports

Gateway listeners use the 176xx/177xx block, fixtures 178xx; everything binds `127.0.0.1`. Every mesh
listener (inbound, outbound, HBONE, egress, DNS) is remapped explicitly, so no default `150xx` port is
ever bound (a unit test in `crates/anvil-lab/src/mesh.rs` checks the configuration files).

| Instance | Config | Topology / PeerAuthentication | Listener Anvil drives | Other listeners | Admin |
|---|---|---|---|---|---|
| `mesh-sidecar` | `lab/gateway/mesh-sidecar.{conf,json}` | Sidecar, STRICT | inbound mTLS `17606` (15006-equivalent) | outbound 17601, HBONE 17608, egress 17609, DNS 17653 (disabled) | 17690 |
| `mesh-sidecar-permissive` | same files | Sidecar, PERMISSIVE | inbound mTLS `17626` | 17621, 17628, 17629, 17655 | 17692 |
| `mesh-ambient` | `lab/gateway/mesh-ambient.{conf,json}` | Ambient, STRICT | HBONE `17618` (15008-equivalent) | inbound 17616, outbound 17611, egress 17619, DNS 17654 | 17691 |
| workload | `anvil_fixtures::http` echo | — | `127.0.0.1:17801` | — | — |
| workload UDP | `anvil_fixtures::streams::udp` | echo / silent / closes after its first reply (bound per scenario) / declared, nothing listening | `127.0.0.1:17802` / `17803` / `17804` / `17805` | — | — |

The mesh documents declare the local workload (`spiffe://cluster.local/ns/ferrum/sa/anvil-lab-svc`,
or `…/sa/anvil-lab-ztunnel` for Ambient) at `127.0.0.1:17801`, service `svc`, the PeerAuthentication,
and (sidecar) one MeshPolicy that **denies** the lab client identity on `/denied/*`. The sidecars
materialize an inbound loopback route for `svc` (Host `svc.ferrum.svc.cluster.local`) and relay an
authenticated bare HTTP/2 CONNECT to the workload's declared address:port. The sidecar workload also
declares the `udp` ports 17802-17805, so a CONNECT with `x-ferrum-mesh-protocol: udp` to one of them is
relayed as datagram records to a local UDP socket. The Ambient workload also declares two names and the
`udp` port 17802: `udp-loopback.anvil-lab.test` (resolved to `127.0.0.1` by the Ambient instance's
`FERRUM_DNS_OVERRIDES`) and `udp-unresolvable.anvil-lab.invalid` (RFC 6761 `.invalid`, never resolves).
The Ambient instance clears `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR`: with the default directory and
no node agent, the absent registry is authoritative and refuses every declared name at relay synthesis
(`denial = unresolvable_authority`, seen in the first lab run), so the names could never reach the UDP
relay's own checks.

Ambient on macOS: the Ambient UDP placement guard withholds `/health` readiness on a host without the
node-agent netns producer, while every TCP listener serves. The lab waits on `/live` for that instance.
The relay-synthesis refusal reason is only logged at debug level, so the lab starts the gateways with
`RUST_LOG=info,ferrum_edge::proxy=debug`.

## 2. Scenarios

Every scenario also runs untrusted (the listeners not declared as a Ferrum gateway) and must then make
no gateway attribution.

| ID | Stimulus | Anvil's conclusion (public evidence) | Ground truth |
|---|---|---|---|
| MESH-001 | HTTPS to the STRICT sidecar inbound with the client SVID, server verified by exact SPIFFE ID | success; `identity_check = spiffe_id`, `peer_spiffe_id = …/sa/anvil-lab-svc`, client SVID presented | echo got `/echo`; operator 200 transaction on `__mesh-inbound-ferrum-svc-17801` |
| MESH-002 | expected server SPIFFE ID `…/sa/anvil-lab-other` | `tls_spiffe_id_mismatch`, `client.tls.spiffe_id_mismatch` (confirmed, `client_to_peer`), dispatch `not_dispatched` | echo got nothing; no transaction line |
| MESH-003 | SNI override `outbound_.17801_._.svc.ferrum.svc.cluster.local` + SPIFFE ID | success; `tls.sni` = the override, `server_name_overridden`, SPIFFE check; `client.tls.sni_override` (info) | echo got `/echo` |
| MESH-004 | plaintext `http://` to the STRICT inbound | not a success, no response accepted, no `http.*` finding | echo got nothing; operator `Frontend TLS handshake failed … InvalidContentType` |
| MESH-005 | no client SVID (STRICT) | `client.tls.client_cert_required` or the lost-alert `client.tls.closed_after_certificate_request` | echo got nothing; operator `peer sent no certificates` |
| MESH-006 | client SVID from `partner.example` (untrusted root) | `client.tls.client_cert_rejected` (likely; `handshake_failure` after Anvil's TLS 1.3 Finished) or the lost-alert `client.tls.closed_after_certificate_request` | echo got nothing; operator `Frontend TLS handshake failed` |
| MESH-007 | `/denied/x` (MeshPolicy DENY for the client identity) | HTTP 403 `{"error":"Mesh authorization denied"}`, not a success, no TLS or backend claim | echo got nothing; operator 403 transaction |
| MESH-008 | **HBONE proxy** at the sidecar inbound, `CONNECT 127.0.0.1:17801`, then GET `/echo` in the tunnel | success; tunnel evidence: `CONNECT` 200, endpoint verified by SPIFFE ID, client SVID presented, outer phases separate from the inner ones | echo got `/echo`; operator `CONNECT` transaction on `__mesh-inbound-hbone-relay` (200, `tcp://127.0.0.1:17801`) |
| MESH-009 | HBONE to the sidecar, `CONNECT 127.0.0.1:17899` (no workload declares that port) | `hbone_connect_refused`, `hbone.tunnel_refused` (`forward_proxy`) quoting the 404 body, dispatch `not_dispatched`, destination not blamed | debug: relay synthesis refused, `denial = port_not_declared` |
| MESH-010 | HBONE to the Ambient listener with the client SVID, `CONNECT 127.0.0.1:17801` | mTLS succeeded (endpoint verified), then `hbone.tunnel_refused` (404) | debug: `denial = address_not_terminated_here` (Ambient never relays to loopback) |
| MESH-011 | HBONE to Ambient, `CONNECT 192.0.2.10:17801` (TEST-NET) | `hbone.tunnel_refused` (404); Anvil's inner `dns`/`connect` are `not_applicable` | debug: `denial = address_not_terminated_here`, nothing dialed |
| MESH-012 | HBONE to Ambient without a client SVID | tunnel-leg failure and `hbone.client_svid_required` (or the lost-alert `hbone.closed_after_certificate_request`), `forward_proxy` | operator `peer sent no certificates`; no `CONNECT` transaction |
| MESH-013 | HBONE to Ambient with the `partner.example` SVID | `hbone.client_svid_rejected` (likely; the gateway sends `handshake_failure` after Anvil's TLS 1.3 Finished) or the lost-alert `hbone.closed_after_certificate_request` | operator `SPIFFE inbound verify: no trust bundle for peer's trust domain 'partner.example'` |
| MESH-014 | HBONE to Ambient expecting endpoint `…/sa/anvil-lab-other` | `hbone.endpoint_identity_rejected` (Anvil's decision), tunnel failure `tls_spiffe_id_mismatch` | no `CONNECT` reached the gateway |
| MESH-015 | HBONE to the PERMISSIVE sidecar, TLS without a client certificate, marker `x-ferrum-mesh-protocol: hbone` | `hbone.tunnel_refused` quoting `{"error":"HBONE tunnel requires an authenticated mesh peer"}`; no policy cause claimed | echo got nothing; operator `Rejected HBONE CONNECT with no authenticated peer identity` + 403 transaction |
| MESH-018 | **UDP** through HBONE at the sidecar inbound: `CONNECT 127.0.0.1:17802` with `x-ferrum-mesh-protocol: udp`, datagrams `mesh-udp-1`, an empty one, `mesh-udp-three` | 3 sent, 3 received, per-datagram boundaries (the empty datagram too), no warning; tunnel `CONNECT` 200 with the `udp` marker, endpoint verified by SPIFFE ID, client SVID presented; channel 3/3 records, `closed_by = client`; no inner TLS | UDP echo got 10, 0 and 14 bytes in order; operator transaction on `__mesh-inbound-hbone-relay` with `backend_target` `udp://127.0.0.1:17802`, `bytes_sent` and `bytes_received` 24 |
| MESH-019 | UDP through HBONE to the silent workload (17803) | only `udp.no_response` (with "the relay gives no acknowledgement" as an alternative), no `hbone.*` finding, dispatch `may_have_been_sent` | the silent workload got the 13-byte datagram |
| MESH-020 | UDP through HBONE, no client SVID (STRICT sidecar) | tunnel-leg failure, `hbone.client_svid_required` or the lost-alert `hbone.closed_after_certificate_request`; nothing sent, the UDP destination not reported on | UDP workload got nothing; operator `peer sent no certificates` |
| MESH-021 | UDP through HBONE with the `partner.example` SVID | `hbone.client_svid_rejected` or the lost-alert finding; never `hbone.endpoint_identity_rejected` | UDP workload got nothing; operator `TLS handshake failed`, no transaction |
| MESH-022 | UDP through HBONE at the PERMISSIVE sidecar, TLS without a client certificate | `hbone.tunnel_refused` quoting `{"error":"HBONE UDP tunnel requires an authenticated mesh peer"}` with the UDP-tunnel alternatives; no policy cause claimed | UDP workload got nothing; operator `Rejected datagram-over-HBONE CONNECT with no authenticated peer identity`, `hbone_udp_unauthenticated_peer` |
| MESH-023 | UDP `CONNECT 127.0.0.1:17899` at the sidecar (no workload declares the port) | `hbone.tunnel_refused` (404 `Not Found`), nothing sent | debug: relay synthesis refused, `denial = port_not_declared` |
| MESH-024 | UDP `CONNECT udp-loopback.anvil-lab.test:17802` at Ambient (a declared name whose DNS answer is loopback) | `hbone.tunnel_refused` quoting 403 `{"error":"HBONE UDP relay destination not allowed"}`; no policy cause claimed | operator `Rejected datagram-over-HBONE CONNECT whose resolved destination is not one this proxy terminates for`, `hbone_udp_relay_destination_denied` |
| MESH-025 | UDP `CONNECT udp-unresolvable.anvil-lab.invalid:17802` at Ambient | `hbone.tunnel_unavailable` quoting 502 `{"error":"HBONE UDP destination DNS resolution failed"}`; no leg claim | operator `HBONE UDP backend resolution failed` |
| MESH-026 | UDP through HBONE, interactive: the workload (17804) answers `first`, closes its socket, then Anvil sends `second` | the session ends without Anvil closing it: `hbone.udp_tunnel_ended` (the endpoint's `END_STREAM`; ICMP at the endpoint's socket stays an alternative; the destination is not called down), 1 reply kept, no `exchange.*` | the workload got only the 5-byte datagram and closed; debug `HBONE UDP tunnel relay completed` with `bytes_in` 11, `bytes_out` 5 |
| MESH-027 | UDP through HBONE to the declared port 17805, where nothing listens | `udp.no_response` and `hbone.udp_tunnel_ended`; never `udp.icmp_port_unreachable` (the ICMP reaches the gateway's socket, not Anvil) | the port could be bound (nothing listened); debug `HBONE UDP tunnel relay completed` with `bytes_in` 6, `bytes_out` 0 |
| MESH-028 | UDP `CONNECT 127.0.0.1:17802` at Ambient | `hbone.tunnel_refused` (404) | debug: `denial = address_not_terminated_here` (Ambient never relays to loopback) |

### Skipped (never counted as passes)

| ID | Why |
|---|---|
| MESH-016 — HBONE through the **Ambient** HBONE listener reaches a workload | Ferrum Edge 0.9.7's Ambient inbound relay guard categorically refuses loopback destinations and admits only a non-loopback accepted pod address or node-agent-enrolled pod IPs (docs/mesh.md "Inbound Relay Destination Guard"; `inbound_relay_destination_decision`). The lab binds only `127.0.0.1` and has no node agent or pod network namespace. MESH-010/011 verify the Ambient guard live, and MESH-008 drives the same transparent CONNECT relay to a workload on the Sidecar inbound listener. |
| MESH-029 — UDP through the **Ambient** HBONE listener reaches a workload | Infeasible for the MESH-016 reason: Ambient refuses loopback authorities (MESH-028) and the UDP relay also drops loopback DNS answers for a declared name (MESH-024, `screen_ordinary_inbound_hbone_relay_dns_candidates`). MESH-018 drives the same datagram relay on the Sidecar inbound listener. |
| MESH-030 — EgressGateway: allow-listed external UDP and its `503` session cap | Needs a fourth, EgressGateway-topology instance with a `MESH_EXTERNAL` ServiceEntry UDP port and `FERRUM_MESH_EGRESS_STREAM_ENABLED` (`mesh_egress_udp_destination_dial_endpoint`); the cap is `FERRUM_UDP_MAX_SESSIONS` (`503 {"error":"UDP egress relay session capacity exhausted"}`). The 503 refusal shape is covered by `crates/anvil-engine/tests/mesh_hbone_udp.rs`. |
| MESH-017 — relay destination guard `403 hbone_relay_destination_denied` | Not reachable without a control plane: 0.9.7 refuses an authority the terminator does not own **at relay synthesis** with a generic `404 {"error":"Not Found"}` and a debug line (`build_inbound_hbone_relay_proxy`, MESH-009/010/011). The documented 403 comes only from the re-check after a `before_proxy` route override (`mesh_route_dispatch` from a VirtualService) moved the effective destination, and the localized file source carries no VirtualService. The 403 refusal contract is covered by the HBONE fixture tests. |

## 3. What the lab found

- **UDP through HBONE interoperates with the real relay on both releases.** The `udp`-marked bare
  HTTP/2 `CONNECT` (no `:protocol`), `[u16 length][payload]` records both ways and a zero-length datagram
  all pass through Ferrum Edge 0.9.7 and 0.9.5 unchanged (MESH-018); the transaction line names
  `udp://<authority>` and the payload bytes each way.
- **Ferrum ends a UDP relay with `END_STREAM`, whatever ended it.** `relay_hbone_udp` either shuts its
  write half down or drops the upgraded stream, and hyper turns a dropped upgrade into `END_STREAM`.
  When the relay's connected UDP socket gets an ICMP port-unreachable (the workload closed, MESH-026, or
  nothing listens, MESH-027), the relay ends and the client sees a clean `END_STREAM` right after its
  datagram. Anvil reports that as the endpoint ending the tunnel (`closed_by = peer`,
  `hbone.udp_tunnel_ended`) and keeps the ICMP as an alternative: the ICMP reaches the gateway, never
  Anvil, so `udp.icmp_port_unreachable` cannot appear through a tunnel.
- **The UDP destination 403 is reachable, unlike the byte-stream one.** A declared Ambient name passes
  relay synthesis without being resolved; the datagram relay then resolves it and drops loopback answers
  (Ambient), answering `403 {"error":"HBONE UDP relay destination not allowed"}` (MESH-024). The byte
  tunnel's 403 still needs a route override (MESH-017).
- **An absent node-agent registry is authoritative on Ambient.** With the default
  `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR` and no node agent, every declared name was refused at
  relay synthesis (`unresolvable_authority`); the lab clears the directory for the Ambient instance.
- **Failed DNS is retried in the background.** After MESH-025 the gateway keeps logging `DNS failed
  retry` warnings for the `.invalid` name (its failed-lookup retry); the public answer stays 502.

- **Relay-guard refusals are 404, not 403, on 0.9.7.** docs/mesh.md says an inbound CONNECT to a
  destination the terminator does not own is refused `403` with
  `mesh_authz.deny_policy=hbone_relay_destination_denied`. At relay synthesis the code returns `None`
  and the caller answers the generic route-miss `404 {"error":"Not Found"}`, logging the reason only at
  debug level. The public signal is therefore identical to "no route". Anvil reports the refusal with
  its status and body and lists "no route or relay for this authority" among the alternatives; it never
  claims the guard as the cause.
- **The unauthenticated-peer gate runs after relay synthesis.** On Ambient over loopback every CONNECT is
  refused at synthesis first, so `hbone_unauthenticated_peer` is reachable only where synthesis admits
  the authority: MESH-015 uses a PERMISSIVE **sidecar** (same `handle_hbone_request` gate).
- **An untrusted-trust-domain SVID is refused with `handshake_failure` after the client's TLS 1.3
  Finished** (operator: `SPIFFE inbound verify: no trust bundle for peer's trust domain`). Anvil used to
  report that alert as a generic peer alert. After its own Finished, with a client certificate
  presented, the peer's only remaining handshake decision is the client certificate, so Anvil now
  reports `client.tls.client_cert_rejected` / `hbone.client_svid_rejected` (likely), for direct TLS and
  for the HBONE endpoint alike. The same alert *during* the handshake stays generic.
- **Lost TLS 1.3 alerts.** The gateway's `certificate_required` alert follows Anvil's finished handshake,
  and its reset sometimes discards it (MESH-005/006/012/013 each saw both shapes across runs). The tunnel then fails
  with a broken pipe on the `CONNECT`; Anvil explains that shape as
  `hbone.closed_after_certificate_request` (likely without an SVID, unknown with one), mirroring
  `client.tls.closed_after_certificate_request`.
- **Plaintext on STRICT** (MESH-004): the listener answers the plaintext request bytes with a TLS alert
  record, which Anvil's HTTP/1.1 parser reports as a protocol error with dispatch `may_have_been_sent`
  (bytes were written). That is honest but generic; a dedicated "the peer answered with TLS" explanation
  is a possible follow-up.

## 4. Stability

Three consecutive `anvil-lab run mesh --untrusted-pass` runs on 2026-09-26 on the final code
(macOS arm64, Ferrum Edge v0.9.7 `ferrum-edge-macos-aarch64`, sha256 from `lab/gateway/RELEASE.lock`):

| Run | Result |
|---|---|
| 1 (`results/lab/20260926T023532Z-mesh`) | 30 passed, 0 failed, 2 skipped |
| 2 (`results/lab/20260926T023540Z-mesh`) | 30 passed, 0 failed, 2 skipped |
| 3 (`results/lab/20260926T023547Z-mesh`) | 30 passed, 0 failed, 2 skipped |
| after the merge, `run all` on v0.9.7 | 30 passed, 0 failed, 2 skipped |
| after the merge, `--release v0.9.5 run all` (v0.9.5 in mesh mode) | 30 passed, 0 failed, 2 skipped |

30 = 15 scenarios × (trusted + untrusted pass). No untrusted run produced a `ferrum.token.*` or
`ferrum.outcome*` finding. The lost-alert shapes appeared in every run (MESH-006 in run 1, MESH-013 in
runs 2 and 3) and were explained by the lost-alert findings, as designed; the other runs of the same
scenarios read the alert.

With UDP through HBONE (MESH-018 to MESH-028, commit "UDP through HBONE tunnels"), on 2026-09-26 on the
final code (macOS arm64, `ferrum-edge-macos-aarch64` pinned by `lab/gateway/RELEASE.lock` and
`lab/gateway/releases/v0.9.5.lock`):

| Run | Result |
|---|---|
| v0.9.7 run 1 (`results/lab/20260926T043340Z-mesh`) | 52 passed, 0 failed, 4 skipped |
| v0.9.7 run 2 (`results/lab/20260926T043354Z-mesh`) | 52 passed, 0 failed, 4 skipped |
| v0.9.7 run 3 (`results/lab/20260926T043404Z-mesh`) | 52 passed, 0 failed, 4 skipped |
| v0.9.5 (`--release v0.9.5`, `results/lab/20260926T043415Z-mesh`) | 52 passed, 0 failed, 4 skipped |

52 = 26 scenarios × (trusted + untrusted pass); the skips are MESH-016, 017, 029 and 030. No untrusted
run produced a `ferrum.token.*` or `ferrum.outcome*` finding. In every run and pass, MESH-026 and MESH-027
saw the endpoint's `END_STREAM` (`closed_by = peer`), never a reset. The lost-alert shapes appeared in runs
2 and 3 (MESH-012) and on v0.9.5 (MESH-006, MESH-013), explained by the lost-alert findings.

## 5. Limitations

- No Kubernetes, CNI, eBPF or node agent: captured (transparent) traffic, NodeWaypoint and the Ambient
  positive relay (TCP and UDP) are out of reach on a loopback-only host (MESH-016, MESH-029).
- No EgressGateway instance: the allow-listed external UDP relay and its session cap are not driven
  live (MESH-030).
- DTLS through an HBONE tunnel is refused by Anvil before traffic (not implemented yet), so no DTLS
  scenario runs here; Ferrum's relay would carry DTLS records opaquely as datagrams.
- No control plane: VirtualService-driven route overrides, and so the post-plugin `403` relay refusal,
  are out of reach (MESH-017).
- The Ferrum compatibility catalog is still 0.9.5 (`ferrum-edge-0.9.5`); mesh-mode public bodies are
  not in it, and the `hbone.*` findings make no Ferrum-specific attribution by design.
