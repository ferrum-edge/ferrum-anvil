#!/usr/bin/env bash
# Run the release check over a target's collected files and raw app binary.
#
#   TARGET=<triple> VERSION=<x.y.z> APP=<binary> PROBE=true|false scripts/release/check-artifacts.sh
#
# Writes dist/<target>/release-check-<version>-<target>.json. Runs before the
# SBOMs are placed in dist/<target> (they are not artifacts the checker reads).
set -euo pipefail

out="dist/$TARGET"
args=(--report "$out/release-check-$VERSION-$TARGET.json")
[ "${PROBE:-false}" = "true" ] && args+=(--runtime-probe)
shopt -s nullglob
files=("$out"/*.dmg "$out"/*.deb "$out"/*.rpm "$out"/*.AppImage "$out"/*.msi "$out"/*-setup.exe "$out"/*.app.tar.gz "$out"/anvil-cli-*.tar.gz "$out"/anvil-cli-*.zip "$APP")
if [ "$RUNNER_OS" = "Linux" ]; then
  xvfb-run -a scripts/release-check.sh "${args[@]}" "${files[@]}"
else
  scripts/release-check.sh "${args[@]}" "${files[@]}"
fi
