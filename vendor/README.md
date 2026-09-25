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
