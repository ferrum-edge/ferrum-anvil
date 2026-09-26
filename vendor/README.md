# Vendored crates

## `h3-0.0.8-rfc9220/`

`h3` 0.0.8 exactly as published on crates.io (checksum
`10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be`, built from
hyperium/h3 `22c1aa3f44d1463cd7644c8f654fffc9a6da305c`), with one change:
`patches/h3-0.0.8-rfc9220-websocket.patch`.

The patch is the upstream commit
[`154ff8d`](https://github.com/hyperium/h3/commit/154ff8d4eb939cddf8136e45cfb757d7f9e55866)
("Add WebSocket :protocol extension per RFC 9220", hyperium/h3#236, merged
2026-01-04), backported to 0.0.8. It adds `Protocol::WEBSOCKET`, the
`:protocol = websocket` value of an RFC 9220 Extended CONNECT. The upstream
commit also touches a `CONNECT_IP` variant that 0.0.8 does not have; only the
WebSocket lines are applied. No other file differs from the published crate.

The workspace uses it through `[patch.crates-io]` in `Cargo.toml` (so
`h3-quinn` 0.0.10 links against it too), and `vendor/` is excluded from the
workspace so the crate is not linted or tested as Anvil code. The license is
upstream's MIT license (`h3-0.0.8-rfc9220/LICENSE`).

**Retire it** when an `h3` release after 0.0.8 includes `Protocol::WEBSOCKET`:
bump `h3` (and `h3-quinn`) in `Cargo.toml`, delete the `[patch.crates-io]`
entry, this directory and the patch, and regenerate `THIRD_PARTY_LICENSES.md`.

To check the vendored copy against crates.io:

```bash
cargo download h3@0.0.8   # or unpack ~/.cargo/registry/src/*/h3-0.0.8
diff -ru <unpacked h3-0.0.8> vendor/h3-0.0.8-rfc9220   # only src/ext.rs differs
```

## `h3-quinn-0.0.10-stop-sending/`

`h3-quinn` 0.0.10 exactly as published on crates.io (checksum
`8b2e732c8d91a74731663ac8479ab505042fbf547b9a207213ab7fbcbfc4f8b4`, built
from hyperium/h3 `2dc3412bdf6083451920d5bfd7a9484d054c1859`), without the
published `Cargo.lock` and `.cargo_vcs_info.json`, and with one change:
`patches/h3-quinn-0.0.10-stop-sending.patch`, confined to `RecvStream` in
`src/lib.rs`.

`RecvStream::poll_data` moves the `quinn::RecvStream` into the read future
while a read is outstanding, and 0.0.10's `stop_sending` and `recv_id` then
`unwrap()` the empty slot and panic. That is the ordinary cancel path: a
request waiting for response data is canceled (a deadline, the user, a local
failure), and Anvil stops the response half with `H3_REQUEST_CANCELLED`. The
patch:

* `stop_sending` with no read outstanding stops the stream at once, as
  before. With one outstanding, it hands the code to the read future and polls
  it once with a no-op waker; the future sees the code before polling quinn,
  drops the unfinished read (no data is consumed), stops the stream with that
  code, and returns the stream. The requested code goes on the wire straight
  away.
* `recv_id` returns the ID captured when the stream was created.

Upstream fixed the panics after 0.0.10 (hyperium/h3#331 for `stop_sending`,
#357 for `recv_id`), but that `stop_sending` only records the code and applies
it when the outstanding read completes. After a cancel the peer may never
send again, so the stream is dropped first and quinn stops it with code 0,
which is not an HTTP/3 error code (hyperium/h3#361, open). Anvil reports the
code it sends, so the patch applies it immediately instead.

The workspace uses it through `[patch.crates-io]` in `Cargo.toml`, like `h3`
above. The license is upstream's MIT license (`h3-quinn-0.0.10-stop-sending/LICENSE`).

**Retire it** when an `h3-quinn` release applies `stop_sending` while a read is
outstanding (hyperium/h3#361): bump `h3-quinn` in `Cargo.toml`, delete the
`[patch.crates-io]` entry, this directory and the patch, and regenerate
`THIRD_PARTY_LICENSES.md`.

To check the vendored copy against crates.io:

```bash
cargo download h3-quinn@0.0.10   # or unpack ~/.cargo/registry/src/*/h3-quinn-0.0.10
cd <unpacked h3-quinn-0.0.10> && patch -p1 < vendor/patches/h3-quinn-0.0.10-stop-sending.patch
diff -r <unpacked h3-quinn-0.0.10> vendor/h3-quinn-0.0.10-stop-sending   # only Cargo.lock and .cargo_vcs_info.json differ
```

## `tungstenite-0.30.0-deflate/`

`tungstenite` 0.30.0 exactly as published on crates.io (checksum
`e48ac77174b19c110a50ab2128b24215ac9cb40e0e12e093fb602d175c569d22`, built
from snapview/tungstenite-rs `7f4aeaf0944992c5664c8fb8e0d54577c7e18020`),
without the published `Cargo.lock` and the registry's `.cargo-ok` marker, and
with one change: `patches/tungstenite-0.30.0-permessage-deflate.patch`. It
adds an RFC 7692 `permessage-deflate` codec behind a new, off-by-default
`deflate` feature (about 330 added lines):

* `src/protocol/deflate.rs` (new): the per-message codec for parameters that
  were already negotiated (`DeflateConfig`: compress or not, the compressor's
  window, context takeover each way). Outgoing Text/Binary messages are
  compressed with a sync flush and the `0x00 0x00 0xff 0xff` tail removed;
  an empty message becomes the single `0x00` octet (§7.2.3.6). Incoming
  compressed messages are inflated fragment by fragment with the tail
  appended; `max_message_size` limits the *decompressed* size, and inflation
  stops as soon as it is passed. A BFINAL block ends the stream for that
  message. The decompressor keeps a 2^15 window (it decodes any peer window).
* `src/protocol/mod.rs`: `WebSocketConfig::deflate` (default `None`); RSV1 is
  accepted only on the first frame of a data message when a codec is
  configured, as RFC 7692 §6 requires (RSV1 on a control or continuation
  frame is still `NonZeroReservedBits`).
* `src/error.rs`: `ProtocolError::CompressedMessageNotNegotiated` (RSV1 on a
  data message without a codec; before, `NonZeroReservedBits`),
  `ProtocolError::InvalidCompressedMessage` and
  `CapacityError::DecompressedMessageTooLong`, so the adapter can attribute
  each case exactly.
* `Cargo.toml` (and `Cargo.toml.orig`): the `deflate` feature and an optional
  `flate2` dependency with its `zlib-rs` backend.

Negotiation (the offer and the validation of the server's answer) is not in
tungstenite: Anvil does its own handshakes for all three bootstraps, and it
lives in `crates/anvil-transport/src/ws_deflate.rs`. Without the feature, or
with `deflate: None`, tungstenite behaves as published except for the new
error variant above.

**Why vendor, and why this patch.** No tungstenite release has
permessage-deflate, and nothing is merged upstream to backport:
snapview/tungstenite-rs#426 ("Add permessage-deflate support, again", open
since 2024-05) and #561 ("Opt-in permessage-deflate support", open since
2026-08, about 1,100 lines of production code and 1,900 of tests) are open,
and earlier attempts (#144, #235, #328) were closed unmerged. Taking
either open PR would vendor unreviewed code several times this size, with
its own negotiation that Anvil's handshakes do not use. Switching WebSocket
crates would rewrite the session adapter and its evidence for all three
bootstraps. The codec here is small, and it is tested as Anvil code: the RFC
7692 §7.2.3 examples and codec edge cases
(`crates/anvil-transport/tests/ws_deflate_codec.rs`), real sockets against an
independent fixture peer (`crates/anvil-engine/tests/ws_deflate.rs`), and an
interop run against Python `websockets`
(`crates/anvil-engine/tests/ws_deflate_interop.rs`).

**Why `zlib-rs`.** It is the pure-Rust zlib that `flate2` already uses in
this workspace (the `zip` dependency enables it, and feature unification
makes it the backend of every `flate2` user). flate2's `miniz_oxide` backend
cannot limit the LZ77 window, so it could not honour a server's
`client_max_window_bits`. zlib cannot compress within a 2^8 window either;
for that answer Anvil sends its messages uncompressed (RSV1 clear), which
RFC 7692 §6 allows.

The workspace uses it through `[patch.crates-io]` (so `tokio-tungstenite`
0.30.0 links against it too) and a direct `tungstenite` dependency that turns
the feature on. The license is upstream's MIT OR Apache-2.0
(`LICENSE-MIT`, `LICENSE-APACHE`).

**Retire it** when a tungstenite release ships permessage-deflate: bump
`tungstenite`/`tokio-tungstenite`, map the adapter's use of `DeflateConfig`,
the three error variants and the RSV1 rules onto the upstream API (keeping
the negotiation in `ws_deflate.rs`, or moving to upstream's if it validates
answers as strictly), delete the `[patch.crates-io]` entry, this directory and
the patch, and regenerate `THIRD_PARTY_LICENSES.md`.

To check the vendored copy against crates.io:

```bash
cargo download tungstenite@0.30.0   # or unpack ~/.cargo/registry/src/*/tungstenite-0.30.0
cd <unpacked tungstenite-0.30.0> && patch -p1 < vendor/patches/tungstenite-0.30.0-permessage-deflate.patch
diff -r <unpacked tungstenite-0.30.0> vendor/tungstenite-0.30.0-deflate   # only Cargo.lock and .cargo-ok differ
```
