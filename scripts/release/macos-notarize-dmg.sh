#!/usr/bin/env bash
# Notarize and staple every DMG of a macOS release build.
#
#   MACOS_ROUTE=api-key|apple-id scripts/release/macos-notarize-dmg.sh <bundle dir>
#
# `tauri bundle` signs the DMG with the Developer ID and notarizes and staples
# only the .app inside it, so the disk image users download has no ticket of
# its own. This submits each DMG to Apple's notary service, waits for the
# result, requires "Accepted" and staples the ticket to the DMG.
# Credentials come from the environment of the bundle step that calls it:
#   api-key:  APPLE_API_KEY_PATH, APPLE_API_KEY, APPLE_API_ISSUER
#   apple-id: APPLE_ID, APPLE_PASSWORD, APPLE_TEAM_ID
# No credential is printed; notarytool's JSON result (submission id, status)
# is.
set -euo pipefail

dir="${1:?usage: macos-notarize-dmg.sh <bundle dir>}"
shopt -s nullglob
dmgs=("$dir"/dmg/*.dmg)
[ "${#dmgs[@]}" -gt 0 ] || { echo "::error::no DMG under $dir/dmg to notarize"; exit 1; }

case "${MACOS_ROUTE:-}" in
  api-key) auth=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER") ;;
  apple-id) auth=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID") ;;
  *) echo "::error::macos-notarize-dmg.sh needs MACOS_ROUTE api-key or apple-id"; exit 1 ;;
esac

for dmg in "${dmgs[@]}"; do
  echo "Notarizing $(basename "$dmg")"
  result="$(xcrun notarytool submit "$dmg" "${auth[@]}" --wait --timeout 2h --output-format json)" || {
    echo "::error::notarytool submit failed for $(basename "$dmg")"; echo "$result"; exit 1
  }
  echo "$result"
  status="$(node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).status||"")}catch{console.log("")}})' <<<"$result")"
  [ "$status" = "Accepted" ] || { echo "::error::notarization of $(basename "$dmg") ended with status '${status:-unknown}'"; exit 1; }
  xcrun stapler staple "$dmg"
  xcrun stapler validate "$dmg"
done
