#!/usr/bin/env bash
# Release artifact safety check: prove that release artifacts contain no
# test-only WebDriver server and no E2E test hooks.
#
#   scripts/release-check.sh [options] <artifact>...
#
# <artifact> may be a raw executable, a macOS .app directory or .dmg, a Linux
# .deb/.rpm/.AppImage, a Windows .msi or NSIS *-setup.exe, a .tar.gz/.tgz/.zip
# archive, or a directory. Installers/archives are unpacked and every
# executable image inside (ELF, Mach-O, PE: programs and shared libraries) is
# scanned. Type 2 AppImages require trusted python3 and unsquashfs tools on
# PATH (unsquashfs >= 4.5.1); inspection reads their ELF/SquashFS bytes without
# executing the image.
#
# Checks
#   1. graph    `cargo tree` for anvil-desktop with the release feature set
#               (targets: all) must not contain tauri-plugin-wdio-webdriver or
#               the `e2e` feature.                       (skip with --no-graph)
#   2. content  no executable may contain strings unique to the embedded
#               WebDriver plugin or to the E2E profile unlock; each artifact
#               must contain at least one Anvil marker string, so a
#               compressed or foreign file can never pass by accident.
#   3. runtime  (--runtime-probe) launch each desktop executable with
#               TAURI_WEBDRIVER_PORT=<free port> and E2E unlock variables set:
#               nothing may answer WebDriver /status on that port, and no
#               profile may be created in the throw-away data directory.
#               Needs a display (use xvfb-run on Linux CI).
#
# Options
#   --features <list>   features the release was built with (default: none)
#   --no-graph          skip check 1 (e.g. for downloaded artifacts)
#   --runtime-probe     run check 3 on desktop executables
#   --probe-seconds N   how long the probe watches the port (default 20)
#   --report <file>     write a JSON report
#
# Exit status: 0 = all checks passed, 1 = a check failed (test hooks found),
# 2 = usage error or an artifact could not be inspected (never a pass).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
features=""
graph=1
probe=0
probe_seconds=20
report=""
artifacts=()

usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --features) features="${2:-}"; shift 2 ;;
    --no-graph) graph=0; shift ;;
    --runtime-probe) probe=1; shift ;;
    --probe-seconds) probe_seconds="${2:-20}"; shift 2 ;;
    --report) report="${2:-}"; shift 2 ;;
    --) shift; artifacts+=("$@"); break ;;
    -h|--help) usage ;;
    -*) echo "unknown option $1" >&2; usage ;;
    *) artifacts+=("$1"); shift ;;
  esac
done
[ ${#artifacts[@]} -gt 0 ] || [ "$graph" = 1 ] || usage

# Strings that exist only in builds with the embedded WebDriver plugin or the
# E2E unlock (see apps/desktop/src-tauri/src/lib.rs and the plugin sources).
NEEDLES=(
  "tauri-plugin-wdio-webdriver"      # crate path in panic locations
  "tauri_plugin_wdio_webdriver"      # crate/symbol name
  "TAURI_WEBDRIVER_PORT"             # plugin port variable
  "/session/{session_id}/element"    # W3C WebDriver route table
  "/wdio/eval"                       # plugin's direct-eval endpoint
  "wdio-webdriver"                   # Tauri plugin name
  "ANVIL_E2E_PASSPHRASE"             # E2E profile unlock
  "ANVIL_E2E_PROFILE"
  "e2e: create profile failed"
  "e2e: unlock failed"
  "e2e_unlock"                       # function symbol (unstripped builds)
)
# At least one must be present in every artifact, proving the scan read real
# Anvil code rather than compressed or unrelated bytes.
MARKERS=("com.ferrumedge.anvil" "ANVIL_DATA_DIR" "anvil-domain" "anvil_domain")

work="$(mktemp -d "${TMPDIR:-/tmp}/anvil-release-check.XXXXXX")"
cleanup() {
  for m in ${mounts[@]+"${mounts[@]}"}; do
    hdiutil detach -quiet "$m" >/dev/null 2>&1 || { sleep 2; hdiutil detach -quiet -force "$m" >/dev/null 2>&1; } || true
  done
  rm -rf "$work"
}
mounts=()
trap cleanup EXIT

failures=0
inconclusive=0
json_items=()
say() { printf '%s\n' "$*"; }
fail() { say "FAIL  $*"; failures=$((failures + 1)); }
bad_input() { say "ERROR $*"; inconclusive=$((inconclusive + 1)); }
json_str() {
  local value="$1" char i LC_ALL=C
  for ((i = 0; i < ${#value}; i++)); do
    char="${value:i:1}"
    case "$char" in
      \\) printf '%s' '\\' ;;
      '"') printf '%s' '\"' ;;
      [[:cntrl:]]) printf '\\u%04x' "'$char" ;;
      *) printf '%s' "$char" ;;
    esac
  done
}

# ------------------------------------------------------------ 1. graph
graph_result="skipped"
if [ "$graph" = 1 ]; then
  say "== dependency graph (anvil-desktop, features: ${features:-<default>})"
  feat_args=()
  [ -n "$features" ] && feat_args=(--features "$features")
  tree="$work/tree.txt"
  if (cd "$root" && cargo tree --locked -p anvil-desktop --target all -e normal,build,features --prefix none ${feat_args[@]+"${feat_args[@]}"}) >"$tree" 2>"$work/tree.err"; then
    if grep -q "tauri-plugin-wdio-webdriver" "$tree" || grep -q 'anvil-desktop feature "e2e"' "$tree"; then
      fail "graph: tauri-plugin-wdio-webdriver / feature e2e is in the release dependency graph"
      graph_result="fail"
    else
      say "ok    graph: $(sort -u "$tree" | wc -l | tr -d ' ') tree entries, no WebDriver plugin, no e2e feature"
      graph_result="pass"
    fi
  else
    cat "$work/tree.err" >&2
    bad_input "graph: cargo tree failed"
    graph_result="error"
  fi
fi

# ------------------------------------------------------------ helpers
is_exe() { # ELF, Mach-O (thin/fat, both endians), PE
  local magic
  magic="$(LC_ALL=C od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n')"
  case "$magic" in
    7f454c46|cffaedfe|cefaedfe|feedfacf|feedface|cafebabe|bebafeca) return 0 ;;
    4d5a*) return 0 ;;
  esac
  return 1
}

# Read the Type 2 filesystem offset as data, matching AppImage's runtime:
# max(end of section-header table, end of last section). Never ask the input
# runtime for its offset. Validate all file-backed ranges before extracting.
# https://github.com/AppImage/type2-runtime/blob/main/src/runtime/runtime.c
appimage_offset() {
  python3 -I - "$1" <<'PY'
import os
import struct
import sys

try:
    with open(sys.argv[1], "rb") as image:
        size = os.fstat(image.fileno()).st_size

        def read_at(offset, length):
            if offset < 0 or length < 0 or offset + length > size:
                raise ValueError("ELF/SquashFS range outside the image")
            image.seek(offset)
            data = image.read(length)
            if len(data) != length:
                raise ValueError("truncated AppImage")
            return data

        ident = read_at(0, 16)
        if ident[:4] != b"\x7fELF" or ident[8:11] != b"AI\x02":
            raise ValueError("expected a Type 2 ELF AppImage")
        if ident[4] not in (1, 2) or ident[5] not in (1, 2) or ident[6] != 1:
            raise ValueError("unsupported ELF class, byte order or version")
        endian = "<" if ident[5] == 1 else ">"
        elf64 = ident[4] == 2
        header = struct.Struct(endian + ("HHIQQQIHHHHHH" if elf64 else "HHIIIIIHHHHHH"))
        section = struct.Struct(endian + ("IIQQQQIIQQ" if elf64 else "IIIIIIIIII"))
        program = struct.Struct(endian + ("IIQQQQQQ" if elf64 else "IIIIIIII"))
        fields = header.unpack(read_at(16, header.size))
        kind, _, version, _, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, shstr = fields
        if kind not in (2, 3) or version != 1 or ehsize != 16 + header.size:
            raise ValueError("invalid ELF executable header")
        if not shnum or shsize != section.size or shoff < ehsize or shstr >= shnum:
            raise ValueError("missing or unsupported ELF section table")
        if not phnum or phnum == 65535 or phsize != program.size or phoff < ehsize:
            raise ValueError("missing or unsupported ELF program table")
        table_end = shoff + shsize * shnum
        read_at(shoff, shsize * shnum)
        last = section.unpack(read_at(table_end - shsize, shsize))
        offset = max(table_end, last[4] + last[5])
        if offset >= size or offset >= 1 << 63 or phoff + phsize * phnum > offset:
            raise ValueError("invalid filesystem offset")
        for index in range(shnum):
            entry = section.unpack(read_at(shoff + index * shsize, shsize))
            # SHT_NULL and SHT_NOBITS do not occupy bytes in the file.
            if entry[1] not in (0, 8) and entry[4] + entry[5] > offset:
                raise ValueError("ELF section overlaps the filesystem")
        for index in range(phnum):
            entry = program.unpack(read_at(phoff + index * phsize, phsize))
            start, length = (entry[2], entry[5]) if elf64 else (entry[1], entry[4])
            if start + length > offset:
                raise ValueError("ELF segment overlaps the filesystem")
        superblock = read_at(offset, 96)
        if superblock[:4] != b"hsqs" or struct.unpack_from("<HH", superblock, 28) != (4, 0):
            raise ValueError("expected a SquashFS 4.0 filesystem at the ELF boundary")
        used = struct.unpack_from("<Q", superblock, 40)[0]
        if used < 96 or offset + used > size:
            raise ValueError("truncated SquashFS filesystem")
        print(offset)
except (OSError, ValueError, struct.error) as error:
    print(f"AppImage metadata: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

# 4.5.1 fixes extraction outside the destination (CVE-2021-41072).
# https://github.com/plougher/squashfs-tools/blob/master/CHANGES.md
# Require a release version banner from the trusted tool; never infer a version
# from extraction success or accept an unknown/pre-release version.
appimage_extractor_version() {
  local banner rc=0
  # 4.5.1's parse_options exits 1 when -version has no filesystem argument.
  # https://github.com/plougher/squashfs-tools/blob/4.5.1/squashfs-tools/unsquashfs.c
  banner="$(LC_ALL=C unsquashfs -version 2>/dev/null)" || rc=$?
  case "$rc" in
    0|1) ;;
    *) echo "trusted unsquashfs >= 4.5.1 required: version query failed" >&2; return 1 ;;
  esac
  python3 -I - "$banner" <<'PY'
import re
import sys

lines = sys.argv[1].splitlines()
number = r"(0|[1-9][0-9]{0,3})"
match = re.fullmatch(
    rf"unsquashfs version {number}\.{number}(?:\.{number})? \([^()]+\)",
    lines[0] if lines else "",
)
if match is None or tuple(int(part or 0) for part in match.groups()) < (4, 5, 1):
    print("trusted unsquashfs >= 4.5.1 required: unsupported or unparseable version", file=sys.stderr)
    sys.exit(1)
PY
}

# find -P never follows extracted links. Also reject escaping links, including
# AppRun, before a file test or an explicit probe could follow one onto the host.
appimage_tree_safe() {
  python3 -I - "$1" <<'PY'
import os
from pathlib import Path
import sys

try:
    root = Path(sys.argv[1]).resolve(strict=True)

    def walk_error(error):
        raise error

    for directory, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in directories + files:
            path = Path(directory) / name
            if path.is_symlink():
                target = path.resolve()
                if os.path.commonpath((root, target)) != str(root):
                    raise ValueError("symlink escapes the extraction directory")
    if not (root / "AppRun").is_file():
        raise ValueError("AppImage has no AppRun")
except (OSError, RuntimeError, ValueError) as error:
    print(f"AppImage extraction: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

# Unpack an artifact into $2 (a directory); print nothing on success.
unpack() {
  local a="$1" out="$2"
  # Prefix relative arguments without command substitution, which would strip
  # trailing newlines from directory names. Absolute paths cannot become options.
  case "$a" in /*) ;; *) a="$PWD/$a" ;; esac
  mkdir -p "$out"
  case "$a" in
    *.dmg)
      command -v hdiutil >/dev/null || { echo "hdiutil (macOS) required for $a" >&2; return 1; }
      local mp="$work/mnt.$RANDOM"
      mkdir -p "$mp"
      # Our DMGs carry the Anvil license as a software license agreement
      # (bundle.licenseFile); hdiutil cancels a non-interactive attach unless
      # the prompt is answered. Only Anvil's own artifacts are attached here.
      # `yes` ends with SIGPIPE; only hdiutil's status matters (pipefail).
      mounts+=("$mp")
      { yes 2>/dev/null || true; } | hdiutil attach -nobrowse -readonly -mountpoint "$mp" "$a" >/dev/null || return 1
      cp -R "$mp"/. "$out/" 2>/dev/null || true ;;
    *.deb)
      if command -v dpkg-deb >/dev/null; then dpkg-deb -x "$a" "$out"
      else (cd "$out" && ar x "$a" && for d in data.tar.*; do tar -xf "$d"; done); fi ;;
    *.rpm)
      # rpm2cpio | cpio first; bsdtar (libarchive) reads the RPM payload
      # itself. A failure says why instead of only "could not unpack".
      local err="$work/unpack.$RANDOM.err"
      : >"$err"
      if command -v rpm2cpio >/dev/null && (cd "$out" && rpm2cpio "$a" 2>>"$err" | cpio -idm --quiet 2>>"$err"); then
        :
      elif command -v bsdtar >/dev/null && bsdtar -xf "$a" -C "$out" 2>>"$err"; then
        say "      unpack: rpm2cpio/cpio failed ($(tr '\n' ' ' <"$err" | cut -c1-300)); read with bsdtar"
      else
        say "      unpack: $(command -v rpm2cpio >/dev/null || printf 'no rpm2cpio; ')$(command -v bsdtar >/dev/null || printf 'no bsdtar; ')$(tr '\n' ' ' <"$err" | cut -c1-300)"
        return 1
      fi ;;
    *.AppImage)
      command -v python3 >/dev/null || { echo "trusted python3 required for $a" >&2; return 1; }
      command -v unsquashfs >/dev/null || { echo "trusted unsquashfs (squashfs-tools) required for $a" >&2; return 1; }
      appimage_extractor_version || return 1
      local offset
      offset="$(appimage_offset "$a")" || return 1
      unsquashfs -no-progress -no-xattrs -strict-errors -d "$out/squashfs-root" \
        -o "$offset" "$a" >/dev/null || return 1
      appimage_tree_safe "$out/squashfs-root" || return 1 ;;
    *.msi)
      command -v powershell >/dev/null || command -v pwsh >/dev/null || { echo "Windows msiexec required for $a" >&2; return 1; }
      local ps; ps="$(command -v pwsh || command -v powershell)"
      local wa wo; wa="$(cygpath -w "$a")"; wo="$(cygpath -w "$out")"
      "$ps" -NoProfile -Command "\$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/a', '\"$wa\"', '/qn', 'TARGETDIR=\"$wo\"'); exit \$p.ExitCode" ;;
    *-setup.exe|*_setup.exe|*.nsis.exe)
      command -v 7z >/dev/null || { echo "7z required to unpack NSIS installer $a" >&2; return 1; }
      7z x -y -o"$out" "$a" >/dev/null ;;
    *.tar.gz|*.tgz|*.tar.xz|*.tar) tar -xf "$a" -C "$out" ;;
    *.zip) (command -v unzip >/dev/null && unzip -q "$a" -d "$out") || tar -xf "$a" -C "$out" ;;
    *) return 2 ;;
  esac
}

scan_file() { # prints needle hits, one per line
  local f="$1" n
  for n in "${NEEDLES[@]}"; do
    if LC_ALL=C grep -a -q -F -- "$n" "$f"; then printf '%s\n' "$n"; fi
  done
}
has_marker() {
  local f="$1" m
  for m in "${MARKERS[@]}"; do
    if LC_ALL=C grep -a -q -F -- "$m" "$f"; then return 0; fi
  done
  return 1
}

free_port() {
  local p i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    p=$((20000 + (RANDOM * 7 + i) % 40000))
    if [ "$(curl -s -m 1 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/status" 2>/dev/null || true)" = "000" ]; then
      echo "$p"; return 0
    fi
  done
  return 1
}

runtime_probe() { # $1 = executable, $2 = optional directory whose leftover processes are stopped; returns 0 pass, 1 fail, 2 inconclusive
  local exe="$1" tree="${2:-}" port data pid code i alive=1 served=""
  port="$(free_port)" || { say "ERROR probe: no free port"; return 2; }
  data="$work/probe-data.$RANDOM"
  mkdir -p "$data"
  say "      probe: launching $(basename "$exe") with TAURI_WEBDRIVER_PORT=$port for ${probe_seconds}s"
  TAURI_WEBDRIVER_PORT="$port" ANVIL_DATA_DIR="$data" ANVIL_E2E_PROFILE="release-check-probe" \
    ANVIL_E2E_PASSPHRASE="probe-$RANDOM-$RANDOM-$RANDOM" "$exe" >"$work/probe.log" 2>&1 &
  pid=$!
  for i in $(seq 1 "$probe_seconds"); do
    sleep 1
    code="$(curl -s -m 1 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/status" 2>/dev/null || true)"
    if [ "$code" != "000" ] && [ -n "$code" ]; then served="$code"; break; fi
    if ! kill -0 "$pid" 2>/dev/null; then alive=0; break; fi
  done
  if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; sleep 1; kill -9 "$pid" 2>/dev/null || true; fi
  wait "$pid" 2>/dev/null || true
  # A launcher that did not exec the app leaves it running from $tree (the probe's own unpack directory).
  if [ -n "$tree" ] && command -v pkill >/dev/null; then pkill -KILL -f -- "$tree/" 2>/dev/null || true; fi
  local profiles=0 profile
  if [ -d "$data/profiles" ]; then
    while IFS= read -r -d '' profile; do
      profiles=$((profiles + 1))
    done < <(find -P "$data/profiles" -mindepth 1 -maxdepth 1 -print0)
  fi
  if [ -n "$served" ]; then
    say "FAIL  probe: WebDriver endpoint answered HTTP $served on 127.0.0.1:$port"; return 1
  fi
  if [ "$profiles" != "0" ]; then
    say "FAIL  probe: the E2E unlock created $profiles profile(s) from environment variables"; return 1
  fi
  if [ "$alive" = 0 ]; then
    say "ERROR probe: the app exited early; result inconclusive (log: $(tail -3 "$work/probe.log" | tr '\n' ' '))"; return 2
  fi
  say "ok    probe: no WebDriver listener, no environment-driven profile unlock"
  return 0
}

# ------------------------------------------------------------ 2/3. artifacts
idx=0
for a in ${artifacts[@]+"${artifacts[@]}"}; do
  idx=$((idx + 1))
  say "== artifact: $a"
  path="$a"
  case "$path" in /*) ;; *) path="$PWD/$path" ;; esac
  if [ ! -e "$path" ]; then bad_input "$a does not exist"; continue; fi
  dir="$work/a$idx"
  files=()
  # Installers that are themselves executables (NSIS, and an AppImage, whose
  # ELF runtime carries the app in a squashfs payload) are unpacked instead.
  if [ -f "$path" ] && is_exe "$path" && case "$a" in *-setup.exe|*_setup.exe|*.nsis.exe|*.AppImage) false ;; *) true ;; esac; then
    files=("$path")
  else
    if [ -d "$path" ]; then
      dir="$path" # a directory or an .app bundle: scan in place
    else
      rc=0; unpack "$path" "$dir" || rc=$?
      if [ "$rc" = 2 ]; then bad_input "$a: unsupported artifact type"; continue; fi
      if [ "$rc" != 0 ]; then bad_input "$a: could not unpack"; continue; fi
    fi
    while IFS= read -r -d '' f; do
      if is_exe "$f"; then files+=("$f"); fi
    done < <(find -P "$dir" -type f -print0 2>/dev/null)
  fi
  if [ ${#files[@]} -eq 0 ]; then bad_input "$a: no executable images found"; continue; fi

  art_hits=0; art_marker=0; hit_list=""
  for f in "${files[@]}"; do
    hits="$(scan_file "$f")"
    if has_marker "$f"; then art_marker=1; fi
    if [ -n "$hits" ]; then
      art_hits=1
      fail "$(basename "$f"): contains test-only strings: $(printf '%s' "$hits" | tr '\n' ',' | sed 's/,$//; s/,/, /g')"
      hit_list="$hit_list$(printf '%s' "$hits" | tr '\n' '|')"
    fi
  done
  if [ "$art_marker" = 0 ]; then
    bad_input "$a: no Anvil marker string found in ${#files[@]} executable(s) — refusing to pass an artifact whose contents could not be read"
    status="error"
  elif [ "$art_hits" = 1 ]; then
    status="fail"
  else
    say "ok    content: ${#files[@]} executable image(s) scanned, no WebDriver or E2E hook strings"
    status="pass"
  fi

  probe_status="skipped"
  if [ "$probe" = 1 ]; then
    # Probe the desktop app: the executable carrying both the app identifier
    # and the Tauri runtime (the CLI also contains the identifier).
    target=""
    for f in "${files[@]}"; do
      case "$f" in *.dll|*.so|*.so.*|*.dylib) continue ;; esac
      if LC_ALL=C grep -a -q -F "com.ferrumedge.anvil" "$f" && LC_ALL=C grep -a -q -F "__TAURI_INTERNALS__" "$f"; then
        target="$f"; break
      fi
    done
    if [ -z "$target" ]; then
      say "      probe: no desktop executable in this artifact (skipped)"
    else
      [ -x "$target" ] || chmod +x "$target" 2>/dev/null || true
      tree=""
      # An AppImage's bundled WebKit finds its helper processes only when the
      # app starts through the image's AppRun (environment, working directory).
      case "$a" in *.AppImage) if [ -x "$dir/squashfs-root/AppRun" ]; then target="$dir/squashfs-root/AppRun"; tree="$dir/squashfs-root"; fi ;; esac
      prc=0; runtime_probe "$target" "$tree" || prc=$?
      case "$prc" in
        0) probe_status="pass" ;;
        1) probe_status="fail"; failures=$((failures + 1)); status="fail" ;;
        *) probe_status="error"; inconclusive=$((inconclusive + 1)); [ "$status" = "pass" ] && status="error" ;;
      esac
    fi
  fi
  json_items+=("{\"artifact\":\"$(json_str "$a")\",\"executables\":${#files[@]},\"status\":\"$status\",\"hits\":\"$(json_str "${hit_list%|}")\",\"runtime_probe\":\"$probe_status\"}")
done

overall="pass"
[ "$inconclusive" -gt 0 ] && overall="error"
[ "$failures" -gt 0 ] && overall="fail"
if [ -n "$report" ]; then
  {
    printf '{"format":"anvil-release-check","version":1,"result":"%s","features":"%s","graph":"%s","artifacts":[' "$overall" "$(json_str "$features")" "$graph_result"
    sep=""
    for j in ${json_items[@]+"${json_items[@]}"}; do printf '%s%s' "$sep" "$j"; sep=","; done
    printf ']}\n'
  } >"$report"
fi
say "== release-check: $overall (failures: $failures, inconclusive: $inconclusive)"
case "$overall" in pass) exit 0 ;; fail) exit 1 ;; *) exit 2 ;; esac
