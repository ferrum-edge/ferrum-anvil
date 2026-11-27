#!/usr/bin/env bash
# Choose each platform's signing route for a release build job.
#
#   TAG=<tag or empty> HAS_<NAME>=true|false ... scripts/release/signing-route.sh
#
# Reads only whether each signing secret or variable is set (HAS_<NAME>, from
# `secrets.NAME != ''` in the workflow), never a value. Every platform's
# configuration is checked on every job, so a half-configured route fails the
# whole run before anything is built. Writes to $GITHUB_OUTPUT:
#
#   route=<this runner's route>   macos=<route or none>   windows=<route or none>
#
# macos and windows are "none" on a runner of another OS, so a later step can
# gate a credential on them and it never reaches another platform's job.
# Routes: macOS api-key | apple-id | none; Windows artifact-signing-oidc |
# artifact-signing-secret | pfx | none. A dry run (no TAG) is always none.
set -euo pipefail

present() { local n v out=(); for n in "$@"; do v="HAS_$n"; [ "${!v:-}" = "true" ] && out+=("$n"); done; echo "${out[*]-}"; }
missing() { local n v out=(); for n in "$@"; do v="HAS_$n"; [ "${!v:-}" = "true" ] || out+=("$n"); done; echo "${out[*]-}"; }
fail() { echo "::error::$1"; exit 1; }

macos=none
windows=none
if [ -z "${TAG:-}" ]; then
  echo "Dry run: no signing credential is read; every target builds unsigned."
else
  apple_cert=(APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD)
  apple_api=(APPLE_API_ISSUER APPLE_API_KEY APPLE_API_KEY_P8)
  apple_id=(APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID)
  any="$(present "${apple_cert[@]}" APPLE_SIGNING_IDENTITY "${apple_api[@]}" "${apple_id[@]}")"
  if [ -n "$any" ]; then
    m="$(missing "${apple_cert[@]}")"; [ -z "$m" ] || fail "macOS signing is partly configured (set: $any); missing: $m"
    api="$(present "${apple_api[@]}")"; m="$(missing "${apple_api[@]}")"
    [ -z "$api" ] || [ -z "$m" ] || fail "App Store Connect API-key notarization is partly configured (set: $api); missing: $m"
    idp="$(present APPLE_ID APPLE_PASSWORD)"; m="$(missing "${apple_id[@]}")"
    [ -z "$idp" ] || [ -z "$m" ] || fail "Apple ID notarization is partly configured (set: $idp); missing: $m"
    if [ -n "$api" ]; then
      macos="api-key"
      [ -z "$idp" ] || echo "::notice::both notarization credentials are configured; using the App Store Connect API key, not the Apple ID"
    elif [ -n "$idp" ]; then
      macos="apple-id"
    else
      fail "macOS signing needs notarization credentials too: APPLE_API_ISSUER, APPLE_API_KEY and APPLE_API_KEY_P8 (recommended), or APPLE_ID, APPLE_PASSWORD and APPLE_TEAM_ID"
    fi
  fi

  # Both Windows credential sets are checked for completeness before either
  # is chosen: a half-set .pfx fails even when Artifact Signing is complete.
  ats=(AZURE_TENANT_ID AZURE_CLIENT_ID ARTIFACT_SIGNING_ENDPOINT ARTIFACT_SIGNING_ACCOUNT ARTIFACT_SIGNING_CERTIFICATE_PROFILE)
  pfx=(WINDOWS_CERTIFICATE WINDOWS_CERTIFICATE_PASSWORD)
  any_ats="$(present "${ats[@]}" AZURE_SUBSCRIPTION_ID AZURE_CLIENT_SECRET ARTIFACT_SIGNING_PROFILE_EKU)"
  any_pfx="$(present "${pfx[@]}")"
  if [ -n "$any_ats" ]; then
    m="$(missing "${ats[@]}")"; [ -z "$m" ] || fail "Azure Artifact Signing is partly configured (set: $any_ats); missing: $m"
  fi
  if [ -n "$any_pfx" ]; then
    m="$(missing "${pfx[@]}")"; [ -z "$m" ] || fail "Windows .pfx signing is partly configured (set: $any_pfx); missing: $m"
  fi
  if [ -n "$any_ats" ]; then
    if [ "${HAS_AZURE_CLIENT_SECRET:-}" = "true" ]; then windows="artifact-signing-secret"; else windows="artifact-signing-oidc"; fi
    [ -z "$any_pfx" ] || echo "::notice::both Windows routes are configured; using Azure Artifact Signing, not the .pfx"
  elif [ -n "$any_pfx" ]; then
    windows="pfx"
  fi
  echo "Signing routes: macOS $macos, Windows $windows, Linux none (no platform code signing)."
fi

route=none
case "${RUNNER_OS:-}" in
  macOS) route="$macos" ;;
  Windows) route="$windows" ;;
esac
if [ "$route" = "none" ] && [ -n "${TAG:-}" ] && [ "${RUNNER_OS:-}" != "Linux" ]; then
  echo "::notice::no ${RUNNER_OS:-} signing credentials configured; ${TARGET:-this target} builds unsigned"
fi
[ "${RUNNER_OS:-}" = "macOS" ] || macos=none
[ "${RUNNER_OS:-}" = "Windows" ] || windows=none
{ echo "route=$route"; echo "macos=$macos"; echo "windows=$windows"; } >> "${GITHUB_OUTPUT:-/dev/stdout}"
