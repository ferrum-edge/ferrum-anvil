# Failure lab: `early` profile

This profile drives Anvil's TLS 1.3 / QUIC **0-RTT early data** ([protocols.md §3.12](../protocols.md))
against the **real, pinned Ferrum Edge release binary** (v0.9.8 by default, v0.9.7 or v0.9.5 with
`--release`). There are no gateway mocks.

The gateway behaviour under test is Ferrum Edge `docs/http3.md` ("0-RTT (TLS 1.3 early data)"),
`docs/frontend_tls.md` and its source (v0.9.7 `8fed134` lines; the early-data code of v0.9.5
`20e7603` is identical apart from log formatting):

- `FERRUM_TLS_EARLY_DATA_METHODS` (comma-separated, uppercased; `src/config/env_config.rs`
  5076–5120) enables early data on the **HTTP/3 listener** when frontend mTLS is off
  (`src/http3/peer_identity.rs` `zero_rtt_admitted`, `quic_max_early_data_size`). The QUIC TLS
  config then advertises `max_early_data_size = u32::MAX` and uses a stateful session cache
  (`FERRUM_TLS_SESSION_CACHE_SIZE`, default 4096) instead of the stateless ticketer
  (`src/http3/server.rs` 700–745): rustls tickets from that cache are single-use, valid 24 hours,
  and admit early data only within a 60-second ticket-age window.
- A request stream accepted before the handshake completed is early data (`src/http3/server.rs`
  1731–1790, accept loop biased ahead of the completion signal at 1973–1979). Because every
  connection starts flagged as early, a 1-RTT request that becomes ready in the same turn as handshake
  completion can also be classified as early (ferrum-edge/ferrum-edge#5761, fixed in v0.9.8 by
  #5775; observed on v0.9.7 in lab run 36345042003 on macOS, see §3). A method outside the list gets `425 {"error":"Method not allowed in 0-RTT early data"}` before routing (2805–2825);
  an admitted one is forwarded with `Early-Data: 1` (`src/http3/cross_protocol.rs` 1171–1178,
  5439–5440).
- The **HTTPS (TCP) listener never accepts early data** (`src/tls/mod.rs` `enable_early_data`,
  2178–2195: "Ignoring HTTPS 0-RTT enablement"); it answers 425 only to a request that *carries*
  `Early-Data: 1` with a method outside the list (`src/proxy/mod.rs` 30953–30988).

Each scenario records the stimulus, what Anvil concluded, and **independent ground truth** that is
never passed to the engine:

- the HTTP/1.1 echo **backend's request log**: which requests arrived, and whether the gateway
  marked them `Early-Data: 1`;
- the **gateway's own log**: the warnings `Rejected HTTP/3 0-RTT request: method PUT not in allowed
  early data methods` (HTTP/3) and `Rejected 0-RTT request: …` (HTTPS header path).

Profile code: `crates/anvil-lab/src/early.rs`. Gateway configuration:
`lab/gateway/early{,-off}.conf`, `lab/gateway/early.yaml`.

## 1. Running

```sh
cargo run -p anvil-lab -- list early
cargo run -p anvil-lab -- run early --untrusted-pass                     # ~3 s
cargo run -p anvil-lab -- --release v0.9.5 run early --untrusted-pass
cargo run -p anvil-lab -- up early                                       # manual/desktop use
```

Setup, binary lookup, results layout and the two passes: [README.md](README.md).

## 2. Instances and ports

Port block: gateway 172xx, fixtures 173xx, everything on loopback.

| Instance | Settings | Listeners | Fixture |
|---|---|---|---|
| `early` | `FERRUM_TLS_EARLY_DATA_METHODS = GET`, HTTP/3 on | HTTP 17280, HTTPS + QUIC 17243, admin 17290 | 17301: HTTP/1.1 echo backend |
| `early-off` | the same without early data | HTTP 17281, HTTPS + QUIC 17244, admin 17291 | 17301 |

Route `/early/echo` → `127.0.0.1:17301` (`strip_listen_path`, methods GET, HEAD, PUT, POST, DELETE),
global `stdout_logging`. Anvil trusts the per-run lab CA with verification on, and turns connection
reuse off (0-RTT is a property of a new connection). Every scenario starts from an empty ticket
cache (the vault-lock path), so the trusted and untrusted passes behave alike.

## 3. Scenarios

| ID | Stimulus | Anvil must conclude | Ground truth |
|---|---|---|---|
| CTRL-EARLY | GET over HTTP/3, no opt-in | success; no early-data evidence; no ticket kept | backend saw the GET without `Early-Data` |
| EARLY-001 | GET (fetches tickets), then GET with the opt-in | first: `no_ticket`, 2 tickets, `max_early_data_size` 4294967295; second: resumed, 0-RTT offered and **accepted** (154 bytes), `early_data.accepted` (confirmed, `client_to_peer`, replay note) | backend saw the 0-RTT GET with **`Early-Data: 1`**, the ticket GET without |
| EARLY-002 | GET, then PUT in 0-RTT (Anvil's policy lists PUT; the gateway's only GET) | once the gateway saw the PUT while its handshake was pending: attempt 0: 0-RTT accepted by QUIC, answered **425**; attempt 1 `too_early_retry` on the **same connection**, not early, **200**; `request.too_early` (confirmed, scope unknown, names "HTTP 200"). A round the gateway handled after its handshake is a missed window (see *Gateway window*) | backend saw exactly one PUT (the retry) without `Early-Data`; gateway log `Rejected HTTP/3 0-RTT request: method PUT …` |
| EARLY-003 | the same GET pair against `early-off` | tickets with `max_early_data_size` 0; second GET resumed, not offered (`ticket_without_early_data`), delivered after the handshake; `early_data.ticket_without_early_data` | backend saw both GETs, neither marked |
| EARLY-004 | GET pair over TLS 1.3 / TCP (HTTP/1.1-only) to the HTTPS listener | resumed TLS 1.3 session (`resumed`, verification from the ticket's handshake), tickets never allow early data; `early_data.ticket_without_early_data` | backend saw both GETs, neither marked |
| EARLY-005 | GET, then POST with the opt-in | POST not eligible: resumed, sent after the handshake (`method_not_eligible`), no 425 | backend saw the POST without `Early-Data` |
| EARLY-006 | lookalike: PUT over TCP with a user-set `Early-Data: 1` header, opt-in with PUT | nothing sent as early data; 425, **one** retry, 425 again, final; `request.too_early` says the request was not sent as early data and lists the header; trusted: `ferrum.outcome` (`gateway.admission.early_data_rejected`) capped at likely | backend received nothing; gateway log `Rejected 0-RTT request: method PUT …` twice |
| EARLY-007 | GET (tickets), vault lock (`clear_sensitive_state`), GET | the lock empties the ticket cache; the next GET is a full handshake (`no_ticket`), nothing early | backend saw the GET without `Early-Data` |

Every scenario runs twice: with the gateway declared as a trusted Ferrum profile, and untrusted, where
no `ferrum.token*`/`ferrum.outcome*` finding may appear.

**Loopback race.** On loopback the resumed handshake completes in about 0.3 ms. EARLY-001/002 need
the request itself inside the 0-RTT window, so they try up to 6 rounds (each from an empty ticket
cache); a round that missed the window must be reported as `handshake_completed_first`, never as
early data, and the backend must agree. In the recorded runs no round was missed (HTTP/3 setup
~20 µs, request written ~0.1 ms after `connect`).

**Gateway window (EARLY-002).** The client's evidence (0-RTT offered and accepted by QUIC) does not
show where the gateway checked the request. The gateway classifies each HTTP/3 stream from its own
handshake state when it accepts it, and a 0-RTT stream it accepts after its handshake completed is
handled as 1-RTT (v0.9.8 `src/http3/server.rs` 2130–2165 and `src/http3/peer_identity.rs` 130–142;
RFC 8470 §6.4; the catalog note on `gateway.admission.early_data_rejected`). Lab run 36557709775 saw
this on Ubuntu: one 200 for the 0-RTT PUT, which reached the backend once without `Early-Data`. So
EARLY-002 requires 425 and the retry only once the gateway saw the PUT while its handshake was
pending, which the first attempt's 425 or the gateway's refusal log shows; the strict checks
(425, one retry on the same connection, 200, one backend PUT, `request.too_early`, the refusal log)
then all apply. A round of exactly the permitted shape (one 200, no retry, no `request.too_early`,
exactly one backend PUT without `Early-Data`, no refusal logged) is recorded as a missed window and
the next round is tried. Any other shape, such as a PUT that reached the backend with `Early-Data: 1`,
goes to the strict checks and fails. When the gateway handled the PUT after its handshake in every
round that sent it as early data, EARLY-002 is **skipped** with that reason: the refusal was not
exercised, which is neither a pass nor a failure. No round sending the PUT as early data at all still
fails.

**Gateway race before v0.9.8.** v0.9.5 and v0.9.7 can classify an HTTP/3 stream accepted before the
gateway's own handshake-complete signal as early data (ferrum-edge/ferrum-edge#5761, fixed in v0.9.8
by #5775), so a request Anvil sent as ordinary 1-RTT data reaches the backend with `Early-Data: 1`,
or draws 425 when its method is not GET. Lab run 36345042003 saw it on macOS for CTRL-EARLY and
EARLY-001's ticket GET. On releases before v0.9.8 the ground-truth checks on 1-RTT requests through
the early-data listener (CTRL-EARLY, EARLY-001's ticket GET, EARLY-005, EARLY-007 and missed 0-RTT
rounds) therefore accept `Early-Data: 1`, and EARLY-005 accepts a 425 followed by its one retry; the
check detail names the misclassification. Anvil's own evidence must still say nothing was sent
early. On v0.9.8 and later these checks stay strict. EARLY-002's retry is sent a round trip after the
handshake, outside the race.

## 4. Results

| Release | Runs | Result |
|---|---|---|
| v0.9.7 | 3 consecutive, trusted + untrusted | 16 passed, 0 failed, 0 skipped each (`results/lab/20260926T045920Z-early`, `…045921Z-early`, `…045923Z-early`) |
| v0.9.5 | 1, trusted + untrusted | 16 passed, 0 failed, 0 skipped (`results/lab/20260926T045925Z-early`) |

Observed on both releases: 2 session tickets per handshake on every listener; `max_early_data_size`
4294967295 on the early-data HTTP/3 listener and 0 on the other HTTP/3 listener and on the HTTPS
listener; the admitted 0-RTT GET reaches the backend with `Early-Data: 1`; the 425 body is the
same on the HTTP/3 and HTTPS paths and carries no `X-Gateway-Error`.

Behaviour these runs pin in Anvil:

- Ferrum answers 425 as soon as it has the HEADERS and does not read the rest of the request
  (`src/http3/server.rs` 2808–2825), so Anvil's write of the body can fail after the answer exists
  (seen once in six early runs). Anvil reads the response after a stopped HTTP/3 write instead of
  reporting a write failure.
- A request written after the handshake completed is recorded as `handshake_completed_first`, never
  as early data, even when the ticket allowed it. When the handshake watch ran in its own task, one
  run in three lost this race on loopback and was wrongly reported as accepted early data with 0
  early bytes.
