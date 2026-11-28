#!/usr/bin/env bash
# Tauri updater config for a release build or bundle job.
#
#   TAG=<tag or empty> HAS_KEY=true|false ANVIL_UPDATER_PUBKEY=<pub> scripts/release/updater-config.sh
#
# Signed updater artifacts need both halves of the owner's updater key and a
# real tag: dry runs never sign updates. The config carries only the public
# key, which is compiled into the app (the compile and the bundle steps both
# get it); the bundle step creates no updater artifact and never sees the
# private key. The sign-updater job signs the updater files afterwards with
# `tauri signer sign`. One normalized key (all whitespace stripped) is
# compiled in and recorded.
# Writes updater=true|false, config=<file or empty>, pubkey=<key or empty> to
# $GITHUB_OUTPUT. HAS_KEY says whether TAURI_SIGNING_PRIVATE_KEY exists, never
# the key itself.
set -euo pipefail

pubkey="$(tr -d '[:space:]' <<<"${ANVIL_UPDATER_PUBKEY:-}")"
out="${GITHUB_OUTPUT:-/dev/stdout}"
if [ -n "${TAG:-}" ] && [ "${HAS_KEY:-}" = "true" ] && [ -n "$pubkey" ]; then
  cfg="$RUNNER_TEMP/anvil-updater.conf.json"
  PUBKEY="$pubkey" node -e 'require("node:fs").writeFileSync(process.argv[1], JSON.stringify({ plugins: { updater: { pubkey: process.env.PUBKEY } } }))' "$cfg"
  { echo "updater=true"; echo "config=$cfg"; echo "pubkey=$pubkey"; } >> "$out"
  echo "Updater key configured; creating signed updater artifacts."
else
  if [ -z "${TAG:-}" ]; then
    echo "Dry run: no updater artifacts."
  elif [ "${HAS_KEY:-}" = "true" ] || [ -n "$pubkey" ]; then
    echo "::warning::only one of TAURI_SIGNING_PRIVATE_KEY / ANVIL_UPDATER_PUBKEY is set; building without updater artifacts"
  fi
  { echo "updater=false"; echo "config="; echo "pubkey="; } >> "$out"
fi
