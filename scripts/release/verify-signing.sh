#!/usr/bin/env bash
# Verify a release target's platform signatures and write its build-info.json.
#
#   TARGET=<triple> RUNNER_LABEL=<runner> APP=<raw binary> ROUTE=<route> \
#   UPDATER=true|false UPDATER_PUBKEY=<key> [PFX_THUMBPRINT=<sha1>] [PROFILE_EKU=<oid>] \
#   scripts/release/verify-signing.sh
#
# A target is recorded as signed only after its signatures verify here:
#   macOS    the .app (codesign --deep --strict, a Team ID, no ad-hoc
#            signature) and every DMG (codesign --strict, the same Team ID)
#            are Developer ID signed, and both carry a stapled notarization
#            ticket (stapler validate).
#   Windows  every MSI and NSIS installer is Authenticode Valid with the
#            route's signer identity (scripts/release/authenticode-status.ps1).
#   Linux    no platform code signing (not applicable).
# When signing credentials were configured for this platform (ROUTE is not
# "none"), anything less fails the job: a release never ships unsigned once
# signing is configured.
set -euo pipefail

out="dist/$TARGET"
ROUTE="${ROUTE:-none}"
# Evidence that the updater public key is compiled into the app binary.
if [ "${UPDATER:-false}" = "true" ]; then
  [ -n "${UPDATER_PUBKEY:-}" ] || { echo "::error::updater configured without a public key"; exit 1; }
  LC_ALL=C grep -aqF "$UPDATER_PUBKEY" "$APP" || { echo "::error::the updater public key is not in $APP"; exit 1; }
fi

signed=false; applicable=true; notarized=false; method="none"; detail="unsigned — owner credentials not configured"
team_of() { codesign -dv --verbose=2 "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -1; }
case "$RUNNER_OS" in
  macOS)
    app="$(find "target/$TARGET/release/bundle/macos" -maxdepth 1 -name "*.app" | head -1)"
    info="$(codesign -dv --verbose=2 "$app" 2>&1 || true)"
    team="$(team_of "$app" || true)"
    shopt -s nullglob
    dmgs=("$out"/*.dmg)
    if codesign --verify --deep --strict "$app" 2>/dev/null && ! grep -q "Signature=adhoc" <<<"$info" && [[ "$team" =~ ^[A-Z0-9]+$ ]] && [ "${#dmgs[@]}" -gt 0 ]; then
      dmg_ok=true; dmg_stapled=true
      for d in "${dmgs[@]}"; do
        if ! codesign --verify --strict "$d" 2>/dev/null || [ "$(team_of "$d" || true)" != "$team" ]; then dmg_ok=false; fi
        xcrun stapler validate "$d" >/dev/null 2>&1 || dmg_stapled=false
      done
      if [ "$dmg_ok" = "true" ]; then
        signed=true; method="Developer ID codesign (app and DMG)"
        detail="$(grep -E '^Authority=' <<<"$info" | head -1) TeamIdentifier=$team"
        if xcrun stapler validate "$app" >/dev/null 2>&1 && [ "$dmg_stapled" = "true" ]; then
          notarized=true; method="$method + notarized (app and DMG stapled)"
        else
          method="$method (not notarized: app stapled $(xcrun stapler validate "$app" >/dev/null 2>&1 && echo yes || echo no), DMG stapled $dmg_stapled)"
        fi
        # Informational: Gatekeeper's own reading on the runner.
        detail="$detail; spctl app: $(spctl -a -t exec -vv "$app" 2>&1 | grep -o 'source=.*' | head -1 || true)"
      else
        detail="the .app is Developer ID signed but a DMG is not signed by the same team"
      fi
    elif grep -q "Signature=adhoc" <<<"$info"; then
      detail="unsigned — owner credentials not configured (ad-hoc signature only, not a Developer ID)"
    fi ;;
  Windows)
    status=""; subject=""; identity=""
    IFS=$'\t' read -r status subject identity < <(pwsh -NoProfile -File scripts/release/authenticode-status.ps1 -Dir "$out" -Route "$ROUTE" -Thumbprint "${PFX_THUMBPRINT:-}" -ProfileEku "${PROFILE_EKU:-}") || true
    identity="${identity%$'\r'}"; subject="${subject%$'\r'}"
    if [ "$status" = "Valid" ]; then
      signed=true; method="Authenticode"; detail="all installers: Valid; signer: $subject; $identity"
    elif [ "$ROUTE" != "none" ]; then
      detail="installers not validly signed by the configured identity: $subject"
    fi ;;
  Linux)
    applicable=false
    detail="unsigned — owner credentials not configured (no platform code signing for .deb/.rpm/.AppImage; verify with SHA256SUMS)" ;;
esac
# The route that produced a verified signature is part of the method.
if [ "$signed" = "true" ]; then
  case "$ROUTE" in
    api-key) method="$method (App Store Connect API key)" ;;
    apple-id) method="$method (Apple ID)" ;;
    pfx) method="$method (imported .pfx certificate)" ;;
    artifact-signing-*) method="$method (Azure Artifact Signing)" ;;
  esac
fi
echo "route=$ROUTE signed=$signed method=$method detail=$detail"
if [ "$ROUTE" != "none" ]; then
  [ "$signed" = "true" ] || { echo "::error::signing is configured for $RUNNER_OS (route $ROUTE) but $TARGET is not signed: $detail"; exit 1; }
  if [ "$RUNNER_OS" = "macOS" ] && [ "$notarized" != "true" ]; then
    echo "::error::$TARGET is Developer ID signed but not notarized and stapled (route $ROUTE): $method"; exit 1
  fi
fi
# shellcheck disable=SC2016 # JavaScript source, not shell
node -e '
  const [target, os, arch, runner, signed, method, detail, updater, pubkey, applicable, route] = process.argv.slice(1);
  const { execSync } = require("node:child_process");
  const v = (c) => { try { return execSync(c, { encoding: "utf8" }).trim(); } catch { return null; } };
  const info = {
    target, os, arch, runner,
    toolchain: { rustc: v("rustc -V"), cargo: v("cargo -V"), node: process.version, tauri_cli: v("node apps/desktop/node_modules/@tauri-apps/cli/tauri.js -V") },
    signing: { signed: signed === "true", applicable: applicable === "true", route, method, detail },
    // Built with the owner updater key: the public key compiled into the
    // app (found in the binary above), which the publish job verifies
    // every signature against.
    updater: updater === "true" ? { configured: true, pubkey, embedded: true } : { configured: false },
  };
  require("node:fs").writeFileSync(`dist/${target}/build-info.json`, JSON.stringify(info, null, 2) + "\n");
' "$TARGET" "$RUNNER_OS" "${TARGET%%-*}" "${RUNNER_LABEL:-}" "$signed" "$method" "$detail" "${UPDATER:-false}" "${UPDATER_PUBKEY:-}" "$applicable" "$ROUTE"
