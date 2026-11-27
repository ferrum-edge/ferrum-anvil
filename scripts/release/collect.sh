#!/usr/bin/env bash
# Collect a release target's shipped files into dist/<target>.
#
#   TARGET=<triple> VERSION=<x.y.z> scripts/release/collect.sh
#
# Copies the installers (and, with the updater key, their updater signatures
# and the macOS updater archives) from target/<triple>/release/bundle, and
# packages the CLI with the license files. Writes app=<path of the raw desktop
# binary> to $GITHUB_OUTPUT for the release check.
set -euo pipefail

out="dist/$TARGET"
mkdir -p "$out"
b="target/$TARGET/release/bundle"
shopt -s nullglob
for f in "$b"/dmg/*.dmg "$b"/deb/*.deb "$b"/rpm/*.rpm "$b"/appimage/*.AppImage "$b"/msi/*.msi "$b"/nsis/*-setup.exe \
         "$b"/appimage/*.AppImage.sig "$b"/msi/*.msi.sig "$b"/nsis/*-setup.exe.sig; do
  name="$(basename "$f" | tr ' ' '-')"
  cp "$f" "$out/$name"
done
# Updater archives (only with the updater key). Both macOS targets
# produce "<Product>.app.tar.gz"; name them like the DMGs.
for f in "$b"/macos/*.app.tar.gz; do
  [ -f "$f.sig" ] || { echo "::error::$f has no updater signature"; exit 1; }
  arch="${TARGET%%-*}"; [ "$arch" = "x86_64" ] && arch=x64
  name="$(basename "$f" .app.tar.gz | tr ' ' '-')_${VERSION}_${arch}.app.tar.gz"
  cp "$f" "$out/$name"
  cp "$f.sig" "$out/$name.sig"
done
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
