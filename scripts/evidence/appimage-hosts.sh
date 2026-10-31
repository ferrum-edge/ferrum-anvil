#!/usr/bin/env bash
# TEMPORARY evidence driver for the AppImage EGL fix (dropped before merge).
# Extract each AppImage given as LABEL=FILE, optionally derive variants of the
# published 0.1.5 AppImage with bundled libwayland files removed, launch each
# AppDir with appimage-probe.sh under Xvfb, record which bundled
# libwayland/libEGL files each carries and whether the host's Mesa EGL driver
# loads against each AppDir's usr/lib, then check EXPECT (LABEL=pass|fail ...).
#
# usage: OUT=dir EXPECT="fix=pass ..." appimage-hosts.sh LABEL=FILE...
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${OUT:?}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/appimage-hosts.XXXXXX")"

{
  # shellcheck source=/dev/null
  . /etc/os-release && echo "host: $PRETTY_NAME"
  uname -a
  if command -v dpkg-query >/dev/null; then
    dpkg-query -W libwayland-client0 libwayland-server0 libwayland-cursor0 libwayland-egl1 libegl1 libegl-mesa0 libgl1-mesa-dri 2>&1 || true
  else
    rpm -q libwayland-client libwayland-server libwayland-cursor libwayland-egl mesa-libEGL mesa-dri-drivers libglvnd-egl glibc 2>&1 || true
  fi
  { ldd --version 2>&1 || true; } | head -1
} >"$OUT/host.txt"
cat "$OUT/host.txt"

labels=()
for spec in "$@"; do
  label="${spec%%=*}" file="${spec#*=}"
  mkdir -p "$work/$label"
  cp "$file" "$work/$label/app.AppImage"
  chmod +x "$work/$label/app.AppImage"
  (cd "$work/$label" && ./app.AppImage --appimage-extract >/dev/null)
  sha256sum "$file" | sed "s|  .*|  $label $(basename "$file")|" >>"$OUT/inputs.sha256"
  labels+=("$label")
  if [ "$label" = v015 ]; then
    cp -a "$work/v015" "$work/v015-noclient"
    rm "$work/v015-noclient/squashfs-root/usr/lib/libwayland-client.so.0"
    labels+=(v015-noclient)
    cp -a "$work/v015" "$work/v015-nowayland"
    rm "$work/v015-nowayland/squashfs-root/usr/lib/"libwayland-*.so*
    labels+=(v015-nowayland)
  fi
done

egl_mesa="$(find /usr/lib /usr/lib64 -name 'libEGL_mesa.so.0' 2>/dev/null | head -1)"
for label in "${labels[@]}"; do
  lib="$work/$label/squashfs-root/usr/lib"
  {
    echo "== $label"
    echo "bundled wayland/EGL/epoxy/gbm/drm files:"
    (cd "$lib" && ls -1 | grep -E '^lib(wayland|EGL|GL|gbm|drm|epoxy|xkbcommon)' || echo "  (none)")
    echo "host Mesa EGL driver ($egl_mesa) loaded with LD_LIBRARY_PATH=AppDir/usr/lib:"
    LD_LIBRARY_PATH="$lib" python3 -I -c 'import ctypes, sys; ctypes.CDLL(sys.argv[1]); print("  loads")' "$egl_mesa" 2>&1 | sed 's/^/  /' || true
    if [ -f "$lib/libwayland-client.so.0" ]; then
      missing="$(comm -23 \
        <(objdump -T "$egl_mesa" $(find /usr/lib /usr/lib64 -name 'libgbm.so.1' 2>/dev/null | head -1) 2>/dev/null | awk '$4 == "*UND*" && $NF ~ /^wl_/ {print $NF}' | sort -u) \
        <(objdump -T "$lib/libwayland-client.so.0" | awk '$4 != "*UND*" && $NF ~ /^wl_/ {print $NF}' | sort -u) | tr '\n' ' ')"
      echo "wl_* symbols the host's libEGL_mesa/libgbm import that the bundled libwayland-client lacks (some may come from libwayland-server): ${missing:-none}"
    fi
  } >>"$OUT/libraries.txt" 2>&1
done
cat "$OUT/libraries.txt"

export XDG_RUNTIME_DIR="$work/xdg-runtime"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
Xvfb :99 -screen 0 1600x1000x24 -nolisten tcp >"$OUT/xvfb.log" 2>&1 &
export DISPLAY=:99
for _ in $(seq 1 20); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.5; done

for label in "${labels[@]}"; do
  "$here/appimage-probe.sh" "$OUT" "$label" "$work/$label/squashfs-root"
done

status=0
for e in ${EXPECT:-}; do
  label="${e%%=*}" want="${e#*=}"
  got="$(python3 -I -c 'import json,sys
for l in open(sys.argv[1]):
    r = json.loads(l)
    if r["label"] == sys.argv[2]: print("pass" if r["pass"] else "fail")' "$OUT/results.jsonl" "$label")"
  if [ "$got" = "$want" ]; then echo "expected $label=$want: ok"; else echo "::error::expected $label=$want, got ${got:-no result}"; status=1; fi
done
exit "$status"
