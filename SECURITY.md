# Security policy

This policy covers Ferrum Anvil: the desktop app, the `anvil` CLI, their
release artifacts and this repository's build and release workflows. It
follows the [ferrum-edge organization policy](https://github.com/ferrum-edge/.github/blob/main/SECURITY.md)
and takes precedence over it for this repository. A problem in the Ferrum Edge
gateway itself belongs to
[ferrum-edge/ferrum-edge](https://github.com/ferrum-edge/ferrum-edge/security).

## Reporting a vulnerability

Please do not report a security problem in a public issue, discussion or pull
request, and don't disclose it publicly before a fix is available.

Report it privately:

1. **GitHub private vulnerability reporting** (preferred):
   [Report a vulnerability](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/new)
   on this repository's **Security** tab.
2. **Email** **contact@ferrumedge.com** with "Security" in the subject line,
   if you cannot use private reporting.

Please include the Anvil version (`anvil --version`, or Settings → About in
the desktop app), the operating system and package (DMG, MSI, NSIS, `.deb`,
`.rpm`, AppImage, CLI archive or a source build), steps to reproduce or a
minimal proof of concept, and the impact you believe it has. Don't include
live credentials, private keys, tokens or real workspace exports in a report.

We aim to acknowledge a report within **5 business days** and keep you
informed through triage, the fix and its release. Fixes are published as
[GitHub Security Advisories](https://github.com/ferrum-edge/ferrum-anvil/security/advisories)
on this repository, and the release notes of the fixing release carry a
Security line. We credit reporters unless you ask us not to.

## Supported versions

From 1.0.0 onward, security fixes ship in a new release of the newest Anvil
version line (a patch release of the newest `1.Y`, tagged `anvil-v1.Y.Z`).
Older releases don't receive backports: upgrade to the newest release to get
a fix. The opt-in update check (Settings) tells you when a newer release is
published.

| Version | Security fixes |
| --- | --- |
| Newest release from 1.0.0 onward | Yes |
| Older 1.x releases | No; upgrade to the newest release |
| 0.x preview releases (`anvil-v0.1.0` to `anvil-v0.1.9`) | No once 1.0.0 is published; until then, fixes ship in the next release from `main` |

## Release integrity

- **Checksums and evidence.** Every release publishes `SHA256SUMS`,
  `release-evidence.json` (each artifact's hash, platform, release check,
  signing status and the CI runs for the commit), CycloneDX SBOMs and a
  license report. Check a download against `SHA256SUMS` before running it.
- **In-app updates are signed.** Update detection is off by default; when on,
  the app asks `api.github.com` for the latest published release and contacts
  nothing else. An in-app install verifies the update's minisign signature
  against the public key compiled into the app, and requires the signed
  version to be the version the manifest announces (`requireSignedVersion`),
  before it replaces anything. An update signed by another key, with a
  corrupted signature or altered after signing is refused; this is tested on
  built bundles in `updater-e2e.yml`. Published releases so far use updater
  key id `BFE08514FEC0E65A`. `.deb` and `.rpm` installs update from the
  release page.
- **Platform code signing.** The release workflow supports Apple Developer
  ID signing with notarization and Windows Azure Artifact Signing, and
  records a platform as signed only after verifying the signature on the
  build runner. The 0.1.x releases' installers are not code-signed, so macOS
  Gatekeeper and Windows SmartScreen warn for them
  ([#2](https://github.com/ferrum-edge/ferrum-anvil/issues/2)). Whether a
  given release's installers are signed is stated, per platform, in that
  release's notes and `release-evidence.json`. Linux packages have no
  platform code signing.

Details: [docs/release.md](docs/release.md) and
[docs/threat-model.md](docs/threat-model.md).

## Known issues

- **glib 0.18 `VariantStrIter` unsoundness (RUSTSEC-2024-0429,
  GHSA-wrw7-89jp-8q8g), Linux only.** Tauri's Linux GTK stack (gtk-rs 0.18)
  pins `glib` 0.18.5 into Anvil's dependency graph. Neither Anvil nor the
  Tauri crates call the affected `VariantStrIter` API. The advisory is the
  one reviewed exception in `deny.toml`; its exit condition is a published
  Tauri release whose Linux stack uses gtk 0.19 or later (glib 0.20 or
  later), after which Anvil updates, qualifies every platform and removes the
  exception. Upstream status is tracked in
  [#233](https://github.com/ferrum-edge/ferrum-anvil/issues/233). macOS and
  Windows builds do not contain this code.
