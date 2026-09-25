#!/usr/bin/env bash
# Download the pinned Ferrum Edge release binary for this platform and verify
# it against lab/gateway/RELEASE.lock. Never runs an unverified binary.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
lock="$root/lab/gateway/RELEASE.lock"
release="$(awk '$1=="release"{print $2}' "$lock")"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) asset=ferrum-edge-macos-aarch64 ;;
  Darwin-x86_64) asset=ferrum-edge-macos-x86_64 ;;
  Linux-aarch64) asset=ferrum-edge-linux-aarch64 ;;
  Linux-x86_64) asset=ferrum-edge-linux-x86_64 ;;
  MINGW*|MSYS*|CYGWIN*) asset=ferrum-edge-windows-x86_64.exe ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
want="$(awk -v a="$asset" '$1==a{print $2}' "$lock")"
mkdir -p "$root/lab/bin"
out="$root/lab/bin/$asset"
if [ ! -f "$out" ]; then
  gh release download "$release" --repo ferrum-edge/ferrum-edge --pattern "$asset" --dir "$root/lab/bin" --clobber
fi
got="$( (shasum -a 256 "$out" 2>/dev/null || sha256sum "$out") | awk '{print $1}')"
if [ "$got" != "$want" ]; then
  echo "checksum mismatch for $asset: got $got want $want" >&2
  rm -f "$out"
  exit 1
fi
chmod +x "$out"
xattr -d com.apple.quarantine "$out" 2>/dev/null || true
echo "verified $asset ($release) sha256 $got"
