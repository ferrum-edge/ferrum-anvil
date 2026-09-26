# ADR 0008: Licensing and dependencies

- Anvil is dual-licensed under PolyForm Noncommercial 1.0.0 and a commercial
  licence, following the suite convention (`LICENSE`,
  `LICENSE-COMMERCIAL.md`).
- No gateway source is copied into Anvil. The gateway was audited read-only
  and is referenced by `path:line` citations only
  (`docs/audit/gateway-source-audit.md`). The lab runs the unmodified
  published release binary.
- Dependencies must be permissively licensed (MIT, Apache-2.0, BSD, ISC,
  Zlib, Unicode-3.0, CDLA-Permissive-2.0 and similar). `cargo deny` enforces
  this, together with advisories and sources, in CI.
- Crypto comes from audited libraries only: rustls (ring provider),
  RustCrypto AEADs/hashes, argon2, p256/rsa, and dimpl for DTLS. No
  primitives are implemented here.
- Native libraries:
  - SQLite is bundled via rusqlite.
  - WebKitGTK is required on Linux, WebView2 on Windows and WKWebView on
    macOS.
  - The OS keychain is used through `keyring` 4 (Keychain, Credential
    Manager, Secret Service). On Linux without a Secret Service, the
    passphrase vault is used, never plaintext.
- wrk and JMeter are not bundled; the JMeter adapter is not implemented (see
  `docs/load.md`). wrk's modified Apache licence was noted and wrk is not
  used.
