#!/usr/bin/env bash
# Collect a release target's shipped files into dist/<target>.
#
#   TARGET=<triple> VERSION=<x.y.z> scripts/release/collect.sh
#
# Copies the installers from target/<triple>/release/bundle and packages the
# CLI with the license files. With the owner's updater key (UPDATER=true) on
# macOS it also makes the updater archive, "<Product>_<version>_<arch>.app.tar.gz":
# the .app in a gzipped tar, as Tauri's bundler makes it (the .app as the
# archive's one top-level folder, symlinks kept). The updater files are signed
# later, by the sign-updater job. Writes app=<path of the raw desktop binary>
# to $GITHUB_OUTPUT for the release check.
set -euo pipefail

out="dist/$TARGET"
mkdir -p "$out"
b="target/$TARGET/release/bundle"
shopt -s nullglob
for f in "$b"/dmg/*.dmg "$b"/deb/*.deb "$b"/rpm/*.rpm "$b"/appimage/*.AppImage "$b"/msi/*.msi "$b"/nsis/*-setup.exe; do
  name="$(basename "$f" | tr ' ' '-')"
  cp "$f" "$out/$name"
done
# The macOS updater archive (only with the updater key). Both macOS targets
# produce "<Product>.app"; name the archive like the DMGs.
if [ "${UPDATER:-false}" = "true" ] && [ "$RUNNER_OS" = "macOS" ]; then
  apps=("$b"/macos/*.app)
  [ "${#apps[@]}" = 1 ] || { echo "::error::expected one .app under $b/macos, found ${#apps[@]}"; exit 1; }
  arch="${TARGET%%-*}"; [ "$arch" = "x86_64" ] && arch=x64
  name="$(basename "${apps[0]}" .app | tr ' ' '-')_${VERSION}_${arch}.app.tar.gz"
  COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$out/$name" -C "$b/macos" "$(basename "${apps[0]}")"
fi
stage="$RUNNER_TEMP/anvil-cli-$VERSION-$TARGET"
mkdir -p "$stage"
cp LICENSE LICENSE-COMMERCIAL.md THIRD_PARTY_LICENSES.md "$stage/"
if [ "$RUNNER_OS" = "Windows" ]; then
  cp "target/$TARGET/release/anvil.exe" "$stage/"
  (cd "$RUNNER_TEMP" && 7z a -tzip -bso0 "anvil-cli-$VERSION-$TARGET.zip" "anvil-cli-$VERSION-$TARGET")
  mv "$RUNNER_TEMP/anvil-cli-$VERSION-$TARGET.zip" "$out/"
  echo "app=target/$TARGET/release/anvil-desktop.exe" >> "$GITHUB_OUTPUT"
else
  cp "target/$TARGET/release/anvil" "$stage/"
  tar -C "$RUNNER_TEMP" -czf "$out/anvil-cli-$VERSION-$TARGET.tar.gz" "anvil-cli-$VERSION-$TARGET"
  echo "app=target/$TARGET/release/anvil-desktop" >> "$GITHUB_OUTPUT"
fi
ls -la "$out"
