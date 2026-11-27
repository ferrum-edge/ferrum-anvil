#!/usr/bin/env bash
# Sign the release's updater files with the owner's updater key.
#
#   VERSION=<x.y.z> PUBKEY=<updater public key> TAURI_SIGNING_PRIVATE_KEY=<key> \
#   TAURI_SIGNING_PRIVATE_KEY_PASSWORD=<password> scripts/release/sign-updater.sh <dist> <out>
#
# <dist> holds one release-<target> folder per build target, as the release
# workflow downloads them. Every updater file there (the macOS
# "*.app.tar.gz", the AppImage, the NSIS "*-setup.exe" and the MSI) is signed
# with `tauri signer sign --app-version <VERSION>` (the version goes into the
# signature's trusted comment, which the app's requireSignedVersion checks),
# the signature is verified against PUBKEY (the key compiled into the app) and
# must record VERSION, and it is written to <out>/release-<target>/<file>.sig.
# Run by the release workflow's sign-updater job, which runs no bundler.
set -euo pipefail

dist="${1:?usage: sign-updater.sh <dist> <out>}"
out="${2:?usage: sign-updater.sh <dist> <out>}"
: "${VERSION:?}" "${PUBKEY:?}" "${TAURI_SIGNING_PRIVATE_KEY:?}"
dist="$(cd "$dist" && pwd)"
mkdir -p "$out" && out="$(cd "$out" && pwd)"
here="$(cd "$(dirname "$0")/../.." && pwd)"
shopt -s nullglob
count=0
for dir in "$dist"/release-*/; do
  target="$(basename "$dir")"
  for f in "$dir"*.app.tar.gz "$dir"*.AppImage "$dir"*-setup.exe "$dir"*.msi; do
    [ -f "$f.sig" ] && { echo "::error::$f already has a signature; only sign-updater signs updater files"; exit 1; }
    (cd "$here/apps/desktop" && npx tauri signer sign --app-version "$VERSION" "$f" > /dev/null)
    [ -s "$f.sig" ] || { echo "::error::tauri signer sign wrote no signature for $f"; exit 1; }
    # shellcheck disable=SC2016 # JavaScript source, not shell
    node --input-type=module -e '
      import { readFileSync } from "node:fs";
      import { pathToFileURL } from "node:url";
      const { checkSignedVersion, verifyUpdaterSignature } = await import(pathToFileURL(process.argv[1]).href);
      const [file, version, pubkey] = process.argv.slice(2);
      checkSignedVersion(verifyUpdaterSignature(readFileSync(file), readFileSync(`${file}.sig`, "utf8").trim(), pubkey), version);
    ' "$here/scripts/updater-manifest.mjs" "$f" "$VERSION" "$PUBKEY"
    mkdir -p "$out/$target"
    mv "$f.sig" "$out/$target/$(basename "$f").sig"
    echo "signed $target/$(basename "$f")"
    count=$((count + 1))
  done
done
[ "$count" -gt 0 ] || { echo "::error::no updater files under $dist/release-*"; exit 1; }
echo "$count updater files signed"
