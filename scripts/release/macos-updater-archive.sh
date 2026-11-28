#!/usr/bin/env bash
# Archive a macOS .app as the in-app updater's payload.
#
#   scripts/release/macos-updater-archive.sh <path/to/Product.app> <out.app.tar.gz>
#
# The format Tauri's bundler makes (tauri-bundler 2.x updater_bundle.rs
# create_tar): a gzipped tar whose one top-level entry is the .app folder,
# with symlinks stored as links, not followed. macOS tar is told to add no
# AppleDouble or extended-attribute entries. Used by the release workflow's
# collect step and by the macOS updater E2E, so the archive the updater
# installs in the E2E is the one releases ship.
set -euo pipefail
app="${1:?usage: macos-updater-archive.sh <app> <out>}"
out="${2:?usage: macos-updater-archive.sh <app> <out>}"
[ -d "$app" ] && [[ "$app" == *.app ]] || { echo "::error::$app is not a .app folder"; exit 1; }
parent="$(cd "$(dirname "$app")" && pwd)"
COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$out" -C "$parent" "$(basename "$app")"
# The archive holds exactly the .app at its top level.
top="$(tar -tzf "$out" | sed 's#/.*##' | sort -u)"
[ "$top" = "$(basename "$app")" ] || { echo "::error::$out has top-level entries other than $(basename "$app"): $top"; exit 1; }
