#!/usr/bin/env bash
# Download a supported Ferrum Edge release binary for this platform and verify
# it against its lock. Never keeps (or runs) an unverified binary.
#
#   lab/scripts/fetch-gateway.sh            # the default pin, lab/gateway/RELEASE.lock
#   lab/scripts/fetch-gateway.sh v0.9.5     # lab/gateway/releases/v0.9.5.lock
#   ANVIL_LAB_RELEASE=v0.9.5 lab/scripts/fetch-gateway.sh
#
# The binary lands in lab/bin/<release>/<asset>, where `anvil-lab --release
# <release>` looks for it (after $ANVIL_LAB_FERRUM_BIN).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
selected="${1:-${ANVIL_LAB_RELEASE:-}}"
if [ -n "$selected" ]; then
  case "$selected" in v*) ;; *) selected="v$selected" ;; esac
  lock="$root/lab/gateway/releases/$selected.lock"
  if [ ! -f "$lock" ]; then
    echo "no lock for Ferrum Edge $selected ($lock); supported: $(cd "$root/lab/gateway/releases" && ls -1 ./*.lock | sed 's#^\./##; s#\.lock$##' | tr '\n' ' ')" >&2
    exit 2
  fi
else
  lock="$root/lab/gateway/RELEASE.lock"
fi
release="$(awk '$1=="release"{print $2}' "$lock")"
if [ -n "$selected" ] && [ "$release" != "$selected" ]; then
  echo "$lock pins $release, not $selected" >&2
  exit 2
fi
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) asset=ferrum-edge-macos-aarch64 ;;
  Darwin-x86_64) asset=ferrum-edge-macos-x86_64 ;;
  Linux-aarch64) asset=ferrum-edge-linux-aarch64 ;;
  Linux-x86_64) asset=ferrum-edge-linux-x86_64 ;;
  MINGW*|MSYS*|CYGWIN*) asset=ferrum-edge-windows-x86_64.exe ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
want="$(awk -v a="$asset" '$1==a{print $2}' "$lock")"
if [ -z "$want" ]; then
  echo "no pinned checksum for $asset in $lock" >&2
  exit 2
fi
dir="$root/lab/bin/$release"
mkdir -p "$dir"
out="$dir/$asset"
if [ ! -f "$out" ]; then
  gh release download "$release" --repo ferrum-edge/ferrum-edge --pattern "$asset" --dir "$dir" --clobber
fi
got="$( (shasum -a 256 "$out" 2>/dev/null || sha256sum "$out") | awk '{print $1}')"
if [ "$got" != "$want" ]; then
  echo "checksum mismatch for $asset ($release): got $got want $want" >&2
  rm -f "$out"
  exit 1
fi
chmod +x "$out"
xattr -d com.apple.quarantine "$out" 2>/dev/null || true
echo "verified $asset ($release) sha256 $got -> ${out#"$root"/}"
