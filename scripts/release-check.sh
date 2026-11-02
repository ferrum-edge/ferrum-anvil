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
#               The app and the processes it started (on Windows its
#               WebView2 msedgewebview2.exe processes) are then stopped. A
#               WebDriver answer or a created profile is still a failure,
#               which takes precedence; otherwise, if they are not gone
#               within about 30 s the probe is inconclusive. A probe
#               launches only once the previous probe's processes are gone
#               and, on Windows, the WebView2 user data folder is unlocked,
#               waiting about 30 s for each; otherwise it is skipped as
#               inconclusive.
#               Needs a display (use xvfb-run on Linux CI).
#
# Options
#   --features <list>   features the release was built with (default: none)
#   --no-graph          skip check 1 (e.g. for downloaded artifacts)
#   --runtime-probe     run check 3 on desktop executables
#   --probe-seconds N   how long the probe watches the port (default 20)
#   --report <file>     write a JSON report
#   --list-appimage <f> run no checks; print every file and empty directory in
#                       the Type 2 AppImage <f>, one per line relative to its
#                       root (`unsquashfs -lc`), read the same way as check 2
#                       (trusted python3 and unsquashfs >= 4.5.1, never
#                       executed). Takes no other artifact or option. Exit 2
#                       if it cannot be read.
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
list_appimage=""
check_options=0
artifacts=()

usage() { sed -n '2,52p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --features) features="${2:-}"; check_options=1; shift 2 ;;
    --no-graph) graph=0; check_options=1; shift ;;
    --runtime-probe) probe=1; check_options=1; shift ;;
    --probe-seconds) probe_seconds="${2:-20}"; check_options=1; shift 2 ;;
    --report) report="${2:-}"; check_options=1; shift 2 ;;
    --list-appimage) list_appimage="${2:-}"; [ -n "$list_appimage" ] || usage; shift 2 ;;
    --) shift; artifacts+=("$@"); break ;;
    -h|--help) usage ;;
    -*) echo "unknown option $1" >&2; usage ;;
    *) artifacts+=("$1"); shift ;;
  esac
done
if [ -n "$list_appimage" ]; then
  if [ ${#artifacts[@]} -gt 0 ] || [ "$check_options" = 1 ]; then
    echo "--list-appimage runs no checks and takes no other artifact or option" >&2
    exit 2
  fi
  graph=0
fi
[ ${#artifacts[@]} -gt 0 ] || [ "$graph" = 1 ] || [ -n "$list_appimage" ] || usage

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
is_exe() { # ELF, Mach-O (thin/fat, both endians), PE; 2 = read error
  local magic
  [ -f "$1" ] && [ -r "$1" ] || return 2
  magic="$(LC_ALL=C od -An -tx1 -N4 "$1" | tr -d ' \n')" || return 2
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

# --list-appimage: list the filesystem without extracting or running anything.
if [ -n "$list_appimage" ]; then
  [ -f "$list_appimage" ] && [ -r "$list_appimage" ] || { echo "cannot read AppImage $list_appimage" >&2; exit 2; }
  command -v python3 >/dev/null || { echo "trusted python3 required for $list_appimage" >&2; exit 2; }
  command -v unsquashfs >/dev/null || { echo "trusted unsquashfs (squashfs-tools) required for $list_appimage" >&2; exit 2; }
  appimage_extractor_version || exit 2
  list_offset="$(appimage_offset "$list_appimage")" || exit 2
  if ! LC_ALL=C unsquashfs -no-progress -lc -o "$list_offset" "$list_appimage" >"$work/appimage-list" 2>"$work/appimage-list.err"; then
    echo "could not list $list_appimage: $(tr '\n' ' ' <"$work/appimage-list.err" | cut -c1-300)" >&2
    exit 2
  fi
  # unsquashfs prefixes every path with its default destination directory.
  grep -q '^squashfs-root/' "$work/appimage-list" || { echo "could not list $list_appimage: empty filesystem listing" >&2; exit 2; }
  sed 's|^squashfs-root/||' "$work/appimage-list"
  exit 0
fi

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

# Classify and scan each AppImage file through one descriptor, opened relative
# to directory descriptors without following links. A readability precheck alone
# cannot protect a later od/grep open from replacement or an I/O error. Read all
# regular files to EOF and reject changes; emit NUL-separated scan records only
# after the entire tree succeeds. The input runtime and payload are never run.
appimage_scan() {
  python3 -I - "$1" "${#NEEDLES[@]}" "${NEEDLES[@]}" "${MARKERS[@]}" <<'PY'
import os
from pathlib import Path
import stat
import sys

try:
    root = os.path.abspath(sys.argv[1])
    # Trusted TMPDIR ancestors may be aliases. Resolve only the containment
    # boundary; keep the supplied root for O_NOFOLLOW opens and identity checks.
    containment_root = str(Path(root).resolve(strict=True))
    count = int(sys.argv[2])
    needles = [value.encode() for value in sys.argv[3:3 + count]]
    markers = [value.encode() for value in sys.argv[3 + count:]]
    desktop = [b"com.ferrumedge.anvil", b"__TAURI_INTERNALS__"]
    patterns = needles + markers + desktop
    overlap = max(map(len, patterns)) - 1
    records = []
    seen = {}
    directory_names = {}
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)

    def unchanged(before, after, path):
        if identity(before) != identity(after):
            raise ValueError(f"file changed during inspection: {path!r}")

    def walk(directory, directory_fd, verify=False):
        before_directory = os.fstat(directory_fd)
        names = os.listdir(directory_fd)
        if verify:
            unchanged(seen[directory], before_directory, directory)
            if set(names) != directory_names[directory]:
                raise ValueError(f"directory changed during inspection: {directory!r}")
        else:
            seen[directory] = before_directory
            directory_names[directory] = set(names)
        for name in names:
            path = os.path.join(directory, name)
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if verify:
                unchanged(seen[path], before, path)
            else:
                seen[path] = before
            if stat.S_ISLNK(before.st_mode):
                target = Path(path).resolve()
                if os.path.commonpath((containment_root, target)) != containment_root:
                    raise ValueError("symlink escapes the extraction directory")
            elif stat.S_ISDIR(before.st_mode):
                child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                try:
                    unchanged(before, os.fstat(child_fd), path)
                    walk(path, child_fd, verify)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(before.st_mode) and not verify:
                file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                with os.fdopen(file_fd, "rb") as image:
                    unchanged(before, os.fstat(image.fileno()), path)
                    magic = image.read(4)
                    executable = (magic.hex() in (
                        "7f454c46", "cffaedfe", "cefaedfe", "feedfacf", "feedface",
                        "cafebabe", "bebafeca",
                    ) or magic.startswith(b"MZ"))
                    found = set()
                    total = len(magic)
                    tail = magic
                    while True:
                        chunk = image.read(1024 * 1024)
                        data = tail + chunk
                        if executable:
                            found.update(pattern for pattern in patterns if pattern in data)
                        total += len(chunk)
                        if not chunk:
                            break
                        tail = data[-overlap:]
                    unchanged(before, os.fstat(image.fileno()), path)
                    if total != before.st_size:
                        raise ValueError(f"short read during inspection: {path!r}")
                if executable:
                    records.append((
                        os.fsencode(path),
                        b"\n".join(needle for needle in needles if needle in found),
                        b"1" if any(marker in found for marker in markers) else b"0",
                        b"1" if all(marker in found for marker in desktop) else b"0",
                    ))
            unchanged(before, os.stat(name, dir_fd=directory_fd, follow_symlinks=False), path)
        unchanged(before_directory, os.fstat(directory_fd), directory)

    root_fd = os.open(root, directory_flags)
    try:
        before_root = os.fstat(root_fd)
        unchanged(before_root, os.stat(containment_root, follow_symlinks=False), containment_root)
        walk(root, root_fd)
        # Recheck earlier files after later candidates have been read, too.
        walk(root, root_fd, verify=True)
        unchanged(before_root, os.stat(containment_root, follow_symlinks=False), containment_root)
        unchanged(before_root, os.stat(root, follow_symlinks=False), root)
    finally:
        os.close(root_fd)
    for record in records:
        for field in record:
            sys.stdout.buffer.write(field + b"\0")
except (OSError, RuntimeError, ValueError) as error:
    print(f"AppImage content: could not read a stable extraction tree: {error}", file=sys.stderr)
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

contains_string() { # 0 = match, 1 = no match, 2 = read error
  local rc=0
  [ -f "$2" ] && [ -r "$2" ] || return 2
  # -q may return success after a match even when a read error also occurs.
  LC_ALL=C grep -a -F -- "$1" "$2" >/dev/null || rc=$?
  case "$rc" in 0|1) return "$rc" ;; *) return 2 ;; esac
}
scan_file() { # prints needle hits, one per line; 2 = read error
  local f="$1" n
  for n in "${NEEDLES[@]}"; do
    local rc=0
    contains_string "$n" "$f" || rc=$?
    case "$rc" in 0) printf '%s\n' "$n" ;; 1) ;; *) return 2 ;; esac
  done
  return 0
}
has_marker() {
  local f="$1" m
  for m in "${MARKERS[@]}"; do
    local rc=0
    contains_string "$m" "$f" || rc=$?
    case "$rc" in 0) return 0 ;; 1) ;; *) return 2 ;; esac
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

# The probed app is stopped together with every process it started, and a
# probe starts only once the previous probe's processes are gone: a helper
# that outlives the app keeps holding what the app holds. On Windows the
# app's WebView2 browser process (msedgewebview2.exe, a child of the app)
# locks the user data folder %LOCALAPPDATA%\com.ferrumedge.anvil\EBWebView
# that every launch of the app shares, and a launch while another browser
# process still holds that lock fails with WebView2 0x800700AA ("The requested
# resource is in use"), which says nothing about the artifact under test.
# Git Bash's `kill` ends the app in a way that leaves its browser process
# exiting for 30 s or more (it then also outlasts TerminateProcess), so on
# Windows the app's process tree is ended with TerminateProcess only
# (Stop-Process), after which the browser process is gone within a second.
# Every wait on the probe's processes is bounded; what is still running at
# the deadline makes the probe inconclusive.
probe_settle_seconds=30
probe_windows=0
case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*) probe_windows=1 ;; esac
# The current probe: its background job (on Linux and macOS also the ID of
# the process group the job leads), the AppImage extraction directory, the
# WebView2 lock file it took, and what identifies its processes (Linux/macOS:
# an environment token; Windows: this shell's process id, the executable and
# the launch time). probe_pending=1 while they are not all gone.
pt_pid="" pt_tree="" pt_lock="" pt_token="" pt_shell="" pt_exe="" pt_since="" pt_watch="" pt_files=""
probe_pending=0
probe_count=0

# Windows helper, by PROBE_MODE:
#   wait-lock  wait (bounded) until the WebView2 user data folder is not
#              locked; prints "free", or "held" and the WebView2 processes
#              using that folder.
#   watch      from launch until PROBE_STOPFILE appears (bounded): identify
#              the app and record its process tree in PROBE_KNOWN every 250 ms.
#   stop       stop the recorded tree (identifying the app now if the watch
#              did not) and wait (bounded) until none of it is left and the
#              user data folder lock is released. Exit 0 = settled, 1 = not.
#   library    define the functions only (for tests).
# The app is the process running the probed executable, started no earlier
# than the probe, whose parent chain (each parent running and no younger than
# its child) reaches this checker's own shell, which is running, so its id is
# its own; another launch of the same executable is not taken for it. Its
# tree is the app and every process descending from it by parent id, each
# created no earlier than its parent and, when another process now holds that
# parent's id, before that process; processes are remembered by id and
# creation time as they are seen, so a child whose parent has since exited is
# still found, and a process that merely reuses an id is not. Limits: the
# app is looked for at most four parents below this checker's shell (on
# hosted runners it is two: the app, then its Git Bash job); a process
# whose parent started and exited between two looks (250 ms apart) is not
# found; and a process whose id was reused while a child of its first holder
# still ran, by a process that has itself exited, cannot be told apart from
# that first holder. Each of these fails closed: an app that is not found is
# not stopped, and its still-running job or a leftover that keeps the
# WebView2 folder locked makes the probe inconclusive and holds the next
# probe back.
probe_windows_ps() {
  cat <<'PS1'
$ErrorActionPreference = 'Stop'
function Select-ProbeTree($all, $known) {
  # $all: processes as {Id, ParentId, Ticks, Name, Path}; $known: id -> creation
  # ticks of the verified app and of every descendant seen so far (kept after exit).
  $byId = @{}
  foreach ($p in $all) { $byId[[int]$p.Id] = $p }
  do {
    $added = $false
    foreach ($p in $all) {
      $id = [int]$p.Id; $parent = [int]$p.ParentId
      if ($known.ContainsKey($id) -or -not $known.ContainsKey($parent)) { continue }
      if ([long]$p.Ticks -lt [long]$known[$parent]) { continue }
      $holder = $byId[$parent]
      if ($holder -and [long]$holder.Ticks -ne [long]$known[$parent] -and [long]$p.Ticks -ge [long]$holder.Ticks) { continue }
      $known[$id] = [long]$p.Ticks; $added = $true
    }
  } while ($added)
  return @($all | Where-Object { $known.ContainsKey([int]$_.Id) -and [long]$known[[int]$_.Id] -eq [long]$_.Ticks })
}
function Find-ProbeApp($all, $shell, $sinceTicks, $name, $isExe) {
  $byId = @{}
  foreach ($p in $all) { $byId[[int]$p.Id] = $p }
  foreach ($p in @($all | Where-Object { $_.Name -ieq $name -and [long]$_.Ticks -ge $sinceTicks } | Sort-Object { [long]$_.Ticks })) {
    $c = $p; $ours = $false
    for ($i = 0; $i -lt 4; $i++) {
      $parent = $byId[[int]$c.ParentId]
      if (-not $parent -or [long]$parent.Ticks -gt [long]$c.Ticks) { break }
      if ([int]$parent.Id -eq $shell) { $ours = $true; break }
      $c = $parent
    }
    if ($ours -and $p.Path -and (& $isExe $p.Path)) { return $p }
  }
  return $null
}
function New-ExeTest($exe) {
  # Compare as 8.3 paths: %TEMP% on hosted runners is itself an 8.3 path.
  $fso = New-Object -ComObject Scripting.FileSystemObject
  $want = $fso.GetFile($exe).ShortPath
  return { param($path) try { $fso.GetFile($path).ShortPath -ieq $want } catch { $false } }.GetNewClosure()
}
function Get-AllProcesses {
  @(Get-CimInstance Win32_Process | Where-Object { $_.CreationDate } | ForEach-Object {
    [pscustomobject]@{ Id = [int]$_.ProcessId; ParentId = [int]$_.ParentProcessId
      Ticks = $_.CreationDate.ToUniversalTime().Ticks; Name = $_.Name; Path = $_.ExecutablePath }
  })
}
function Test-LockHeld($lock) {
  if (-not $lock -or -not (Test-Path -LiteralPath $lock)) { return $false }
  try { $f = [IO.File]::Open($lock, 'Open', 'Write', 'ReadWrite, Delete'); $f.Close(); return $false }
  catch { return $true }
}
if ($env:PROBE_MODE -eq 'library') { return }
$lock = $env:PROBE_LOCK
$deadline = (Get-Date).AddSeconds([int]$env:PROBE_SETTLE)
if ($env:PROBE_MODE -eq 'wait-lock') {
  while (Test-LockHeld $lock) {
    if ((Get-Date) -ge $deadline) {
      $folder = Split-Path -Parent $lock
      $users = @(Get-CimInstance Win32_Process -Filter "Name = 'msedgewebview2.exe'" |
        Where-Object { ([string]$_.CommandLine).IndexOf($folder, [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
        ForEach-Object { 'pid ' + $_.ProcessId + ' started ' + $_.CreationDate.ToString('HH:mm:ss') }) -join ', '
      if (-not $users) { $users = 'no msedgewebview2.exe names it' }
      'held (' + $users + ')'
      exit 0
    }
    Start-Sleep -Milliseconds 500
  }
  'free'
  exit 0
}
$since = [datetime]::Parse($env:PROBE_SINCE, [Globalization.CultureInfo]::InvariantCulture,
  [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal')
$shell = [int]$env:PROBE_SHELL
$name = Split-Path -Leaf $env:PROBE_EXE
$isExe = New-ExeTest $env:PROBE_EXE
$known = @{}
$root = $null
if (Test-Path -LiteralPath $env:PROBE_KNOWN) {
  foreach ($line in @(Get-Content -LiteralPath $env:PROBE_KNOWN)) {
    $f = $line -split ' '
    if ($f.Count -eq 2) { if (-not $root) { $root = $line }; $known[[int]$f[0]] = [long]$f[1] }
  }
}
function Update-Known($all) {
  if (-not $script:root) {
    $app = Find-ProbeApp $all $shell $since.Ticks $name $isExe
    if ($app) { $script:root = '{0} {1}' -f $app.Id, $app.Ticks; $known[[int]$app.Id] = [long]$app.Ticks }
  }
  if ($script:root) { return @(Select-ProbeTree $all $known) }
  return @()
}
if ($env:PROBE_MODE -eq 'watch') {
  while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $env:PROBE_STOPFILE)) {
    $null = Update-Known (Get-AllProcesses)
    if ($root) {
      $lines = @($root) + @($known.Keys | ForEach-Object { '{0} {1}' -f $_, $known[$_] })
      Set-Content -LiteralPath ($env:PROBE_KNOWN + '.new') -Value $lines
      Move-Item -Force -LiteralPath ($env:PROBE_KNOWN + '.new') -Destination $env:PROBE_KNOWN
    }
    Start-Sleep -Milliseconds 250
  }
  exit 0
}
$stopped = @{}
while ($true) {
  $tree = @(Update-Known (Get-AllProcesses))
  foreach ($p in $tree) {
    $stopped[[int]$p.Id] = $p.Name
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  }
  $held = Test-LockHeld $lock
  if ($tree.Count -eq 0 -and -not $held) {
    $names = @($stopped.Values | Group-Object | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', '
    if (-not $root) { $names = 'nothing (the app process was not found running)' }
    elseif (-not $names) { $names = 'none left' }
    'stopped: ' + $names + '; WebView2 user data folder free'
    exit 0
  }
  if ((Get-Date) -ge $deadline) {
    $left = @($tree | ForEach-Object { '{0} (pid {1})' -f $_.Name, $_.Id }) -join ', '
    if (-not $left) { $left = 'no process of the app' }
    'still running: ' + $left + '; WebView2 user data folder lock ' + $(if ($held) { 'held' } else { 'free' })
    exit 1
  }
  Start-Sleep -Milliseconds 500
}
PS1
}
probe_windows_run() { # env PROBE_* set by the caller; prints the script's output
  local ps script
  ps="$(command -v powershell || command -v pwsh)" || { echo "PowerShell not found"; return 2; }
  script="$work/probe-tree.ps1"
  [ -f "$script" ] || probe_windows_ps >"$script"
  "$ps" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w "$script")" 2>&1 | tr -d '\r'
  return "${PIPESTATUS[0]}"
}

# Linux/macOS. The probe's job runs in its own process group (the group's ID
# is the job's pid), which keeps helpers that the app leaves behind findable;
# neither system reuses a process id while a process group with that ID still
# has members. The app is also started with a random RELEASE_CHECK_PROBE_ID,
# which every process it starts inherits, also after `setsid` and after the
# app exits: on Linux every process whose environment carries it is the
# probe's (/proc/<pid>/environ), and on macOS where `ps -E` shows it. Helpers
# that leave the group are also remembered by pid and start time from launch
# on (every 100 ms for the first second, then every second) and are
# signalled only while that pid still has that start time.
probe_ps() { # pid ppid pgid stat start, start with spaces as "_"
  ps -A -o pid= -o ppid= -o pgid= -o stat= -o lstart= 2>/dev/null |
    awk '{ s = $5; for (i = 6; i <= NF; i++) s = s "_" $i; print $1, $2, $3, $4, s }'
}
probe_token_pids() { # processes whose environment carries this probe's token
  if [ -r /proc/self/environ ]; then
    grep -lzxF -- "RELEASE_CHECK_PROBE_ID=$pt_token" /proc/[0-9]*/environ 2>/dev/null |
      sed -n 's|^/proc/\([0-9]*\)/environ$|\1|p' || true
  else
    # The token is passed to awk in pieces so that awk's own line never matches.
    ps -A -E -ww -o pid= -o command= 2>/dev/null |
      PROBE_TOKEN="$pt_token" awk 'index($0, "RELEASE_CHECK_PROBE_ID=" ENVIRON["PROBE_TOKEN"]) { print $1 }' || true
  fi
}
probe_remember_helpers() { # the app's descendants (and theirs) outside its process group
  probe_ps | awk -v root="$pt_pid" -v helpers="$pt_files.helpers" '
    BEGIN { while ((getline line < helpers) > 0) { split(line, f, " "); seen[f[1] " " f[2]] = 1 } }
    { parent[$1] = $2; group[$1] = $3; start[$1] = $5; if (($1 " " $5) in seen) found[$1] = 1 }
    END {
      if (group[root] == root) found[root] = 1
      do {
        added = 0
        for (p in parent) if (!(p in found) && (parent[p] in found)) { found[p] = 1; added = 1 }
      } while (added)
      for (p in found) if ((p in group) && group[p] != root && !((p " " start[p]) in seen)) print p, start[p]
    }' >>"$pt_files.helpers"
}
probe_posix_left() { # live (non-zombie) processes of the probe
  { probe_token_pids; probe_ps | awk -v root="$pt_pid" -v helpers="$pt_files.helpers" '
      BEGIN { while ((getline line < helpers) > 0) { split(line, f, " "); seen[f[1] " " f[2]] = 1 } }
      $4 !~ /^Z/ && ($3 == root || (($1 " " $5) in seen)) { print $1 }'; } | sort -un
}
probe_posix_signal() { # $1 = signal
  local p
  kill -s "$1" -- "-$pt_pid" 2>/dev/null || true
  for p in $(probe_posix_left); do kill -s "$1" "$p" 2>/dev/null || true; done
}
probe_job_gone() { # $1 = seconds; 0 once the probe's background job has exited (then reaped), 1 at the deadline
  local end=$((SECONDS + $1)) state
  while :; do
    if ! kill -0 "$pt_pid" 2>/dev/null; then break; fi
    if [ "$probe_windows" = 0 ]; then
      state="$(ps -o stat= -p "$pt_pid" 2>/dev/null || true)"
      case "$state" in Z*) break ;; esac
    fi
    [ "$SECONDS" -lt "$end" ] || return 1
    sleep 0.2
  done
  wait "$pt_pid" 2>/dev/null || true # it has exited: this returns at once
  return 0
}
probe_windows_watch_end() { # ask the Windows watcher to stop; bounded
  local i
  [ -n "$pt_watch" ] || return 0
  : >"$pt_files.watch-stop"
  for i in $(seq 1 50); do
    if ! kill -0 "$pt_watch" 2>/dev/null; then wait "$pt_watch" 2>/dev/null || true; pt_watch=""; return 0; fi
    sleep 0.2
  done
  say "      probe: note: the process-tree watcher is still running; it stops by itself"
  pt_watch=""
}

# Stop the current probe's processes and wait until they are gone, at most
# about probe_settle_seconds; 0 = nothing of them left (and the probe's job
# has exited), 1 = something still running (or, on Windows, the WebView2 user
# data folder still locked).
stop_probe_tree() {
  local rc=0 summary left deadline
  deadline=$((SECONDS + probe_settle_seconds))
  if [ "$probe_windows" = 1 ]; then
    probe_windows_watch_end
    summary="$(PROBE_MODE=stop PROBE_SHELL="$pt_shell" PROBE_EXE="$(cygpath -w "$pt_exe")" PROBE_SINCE="$pt_since" \
      PROBE_KNOWN="$(cygpath -w "$pt_files.known")" PROBE_LOCK="$pt_lock" PROBE_SETTLE="$probe_settle_seconds" \
      probe_windows_run)" || rc=$?
    if [ "$rc" != 0 ]; then say "      probe: ${summary:-could not stop the probed app}"; return 1; fi
    # The app is never signalled through Git Bash (see above): once it is gone
    # the background job ends by itself.
    left=$((deadline - SECONDS)); [ "$left" -gt 2 ] || left=2
    if ! probe_job_gone "$left"; then say "      probe: $summary, but the probe's job is still running"; return 1; fi
    say "      probe: $summary"
    return 0
  fi
  probe_remember_helpers
  probe_posix_signal TERM
  sleep 1
  probe_posix_signal KILL
  # A launcher that did not exec the app leaves it running from $tree (the probe's own unpack directory).
  if [ -n "$pt_tree" ] && command -v pkill >/dev/null; then pkill -KILL -f -- "$pt_tree/" 2>/dev/null || true; fi
  while :; do
    left="$(probe_posix_left | tr '\n' ' ')"
    if [ -z "$left" ]; then
      rc=$((deadline - SECONDS)); [ "$rc" -gt 1 ] || rc=1
      probe_job_gone "$rc" && return 0
      left="the probe's job ($pt_pid)"
      break
    fi
    [ "$SECONDS" -lt "$deadline" ] || break
    sleep 1
    probe_posix_signal KILL
  done
  say "      probe: still running: $left"
  return 1
}

runtime_probe() { # $1 = executable, $2 = optional directory whose leftover processes are stopped; returns 0 pass, 1 fail, 2 inconclusive
  local exe="$1" tree="${2:-}" port data code i alive=1 served="" state="" settled=1
  if [ "$probe_pending" = 1 ]; then
    say "      probe: the previous probe's processes were still running; stopping them again (up to ${probe_settle_seconds}s)"
    if ! stop_probe_tree; then
      say "ERROR probe: skipped, inconclusive: the previous probe's processes are still running, so this one could not start clean"
      return 2
    fi
    probe_pending=0
  fi
  port="$(free_port)" || { say "ERROR probe: no free port"; return 2; }
  data="$work/probe-data.$RANDOM"
  mkdir -p "$data"
  probe_count=$((probe_count + 1))
  pt_pid="" pt_tree="$tree" pt_lock="" pt_token="" pt_shell="" pt_exe="$exe" pt_since="" pt_watch=""
  pt_files="$work/probe-$probe_count" # per probe, so nothing of an earlier probe can mix in
  : >"$pt_files.helpers"
  if [ "$probe_windows" = 1 ]; then
    # Git Bash always sets LOCALAPPDATA and /proc/<pid>/winpid; without them
    # the lock cannot be checked or the app identified.
    pt_shell="$(cat "/proc/$$/winpid" 2>/dev/null || true)"
    if [ -z "${LOCALAPPDATA:-}" ] || [ -z "$pt_shell" ]; then
      say "ERROR probe: skipped, inconclusive: LOCALAPPDATA or this shell's Windows process id is unavailable"
      return 2
    fi
    # Launch only once the WebView2 user data folder is free (bounded wait).
    pt_lock="$LOCALAPPDATA\\com.ferrumedge.anvil\\EBWebView\\lockfile"
    state="$(PROBE_MODE=wait-lock PROBE_LOCK="$pt_lock" PROBE_SETTLE="$probe_settle_seconds" probe_windows_run)" || state=""
    case "$state" in
      free) ;;
      held*)
        say "ERROR probe: skipped, inconclusive: the WebView2 user data folder is still locked after ${probe_settle_seconds}s ${state#held } (is Anvil open outside this check?)"
        return 2 ;;
      *) say "ERROR probe: could not read the WebView2 user data folder state (${state:-no output})"; return 2 ;;
    esac
  else
    pt_token="$(od -An -N12 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
    [ -n "$pt_token" ] || pt_token="$$-$RANDOM$RANDOM$RANDOM-$SECONDS"
  fi
  pt_since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  say "      probe: launching $(basename "$exe") with TAURI_WEBDRIVER_PORT=$port for ${probe_seconds}s"
  if [ "$probe_windows" = 1 ]; then
    TAURI_WEBDRIVER_PORT="$port" ANVIL_DATA_DIR="$data" ANVIL_E2E_PROFILE="release-check-probe" \
      ANVIL_E2E_PASSPHRASE="probe-$RANDOM-$RANDOM-$RANDOM" "$exe" >"$work/probe.log" 2>&1 &
    pt_pid=$!
    # Identify the app and record its process tree from launch on.
    PROBE_MODE=watch PROBE_SHELL="$pt_shell" PROBE_EXE="$(cygpath -w "$exe")" PROBE_SINCE="$pt_since" \
      PROBE_KNOWN="$(cygpath -w "$pt_files.known")" PROBE_STOPFILE="$(cygpath -w "$pt_files.watch-stop")" \
      PROBE_SETTLE=$((probe_seconds + 60)) probe_windows_run >"$pt_files.watch-log" 2>&1 &
    pt_watch=$!
  else
    set -m # the job gets its own process group
    RELEASE_CHECK_PROBE_ID="$pt_token" TAURI_WEBDRIVER_PORT="$port" ANVIL_DATA_DIR="$data" \
      ANVIL_E2E_PROFILE="release-check-probe" ANVIL_E2E_PASSPHRASE="probe-$RANDOM-$RANDOM-$RANDOM" \
      "$exe" </dev/null >"$work/probe.log" 2>&1 &
    pt_pid=$!
    set +m
    for i in 1 2 3 4 5 6 7 8 9 10; do probe_remember_helpers; sleep 0.1; done
  fi
  for i in $(seq 1 "$probe_seconds"); do
    sleep 1
    [ "$probe_windows" = 1 ] || probe_remember_helpers
    code="$(curl -s -m 1 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/status" 2>/dev/null || true)"
    if [ "$code" != "000" ] && [ -n "$code" ]; then served="$code"; break; fi
    if ! kill -0 "$pt_pid" 2>/dev/null; then alive=0; break; fi
  done
  stop_probe_tree || { settled=0; probe_pending=1; }
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
  if [ "$settled" = 0 ]; then
    say "ERROR probe: the probed app's processes did not all exit within ${probe_settle_seconds}s of being stopped; inconclusive, and the next probe starts only once they are gone"; return 2
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
  appimage=0; scanned=0; scan_hits=(); scan_markers=(); scan_desktops=()
  rc=1
  if [ -f "$path" ]; then rc=0; is_exe "$path" || rc=$?; fi
  if [ "$rc" -gt 1 ]; then bad_input "$a: could not read file for classification"; continue; fi
  # Installers that are themselves executables (NSIS, and an AppImage, whose
  # ELF runtime carries the app in a squashfs payload) are unpacked instead.
  if [ "$rc" = 0 ] && case "$a" in *-setup.exe|*_setup.exe|*.nsis.exe|*.AppImage) false ;; *) true ;; esac; then
    files=("$path")
  else
    if [ -d "$path" ]; then
      dir="$path" # a directory or an .app bundle: scan in place
    else
      rc=0; unpack "$path" "$dir" || rc=$?
      if [ "$rc" = 2 ]; then bad_input "$a: unsupported artifact type"; continue; fi
      if [ "$rc" != 0 ]; then bad_input "$a: could not unpack"; continue; fi
      case "$a" in *.AppImage) appimage=1 ;; esac
    fi
    candidates="$work/candidates.$idx"
    case "$appimage" in
      1)
        if ! appimage_scan "$dir/squashfs-root" >"$candidates"; then
          bad_input "$a: could not inspect AppImage contents"; continue
        fi
        scanned=1
        while IFS= read -r -d '' f && IFS= read -r -d '' hits && \
          IFS= read -r -d '' marker && IFS= read -r -d '' desktop; do
          files+=("$f"); scan_hits+=("$hits"); scan_markers+=("$marker"); scan_desktops+=("$desktop")
        done <"$candidates" ;;
      *)
        if ! find -P "$dir" -type f -print0 >"$candidates"; then
          bad_input "$a: could not enumerate regular files"; continue
        fi
        classification_error=0
        while IFS= read -r -d '' f; do
          rc=0; is_exe "$f" || rc=$?
          case "$rc" in
            0) files+=("$f") ;;
            1) ;;
            *) bad_input "$f: could not read file for classification"; classification_error=1; break ;;
          esac
        done <"$candidates"
        [ "$classification_error" = 0 ] || continue ;;
    esac
  fi
  if [ ${#files[@]} -eq 0 ]; then bad_input "$a: no executable images found"; continue; fi

  art_hits=0; art_marker=0; hit_list=""; content_error=0
  for ((file_index = 0; file_index < ${#files[@]}; file_index++)); do
    f="${files[$file_index]}"
    if [ "$scanned" = 1 ]; then
      hits="${scan_hits[$file_index]}"
      [ "${scan_markers[$file_index]}" = 0 ] || art_marker=1
    else
      if ! hits="$(scan_file "$f")"; then
        bad_input "$f: could not read file for hook scan"; content_error=1; break
      fi
      rc=0; has_marker "$f" || rc=$?
      case "$rc" in
        0) art_marker=1 ;;
        1) ;;
        *) bad_input "$f: could not read file for marker scan"; content_error=1; break ;;
      esac
    fi
    if [ -n "$hits" ]; then
      art_hits=1
      fail "$(basename "$f"): contains test-only strings: $(printf '%s' "$hits" | tr '\n' ',' | sed 's/,$//; s/,/, /g')"
      hit_list="$hit_list$(printf '%s' "$hits" | tr '\n' '|')"
    fi
  done
  if [ "$content_error" = 1 ]; then
    status="error"
  elif [ "$art_marker" = 0 ]; then
    bad_input "$a: no Anvil marker string found in ${#files[@]} executable(s) — refusing to pass an artifact whose contents could not be read"
    status="error"
  elif [ "$art_hits" = 1 ]; then
    status="fail"
  else
    say "ok    content: ${#files[@]} executable image(s) scanned, no WebDriver or E2E hook strings"
    status="pass"
  fi

  probe_status="skipped"
  if [ "$probe" = 1 ] && [ "$status" != "error" ]; then
    # Probe the desktop app: the executable carrying both the app identifier
    # and the Tauri runtime (the CLI also contains the identifier).
    target=""
    for ((file_index = 0; file_index < ${#files[@]}; file_index++)); do
      f="${files[$file_index]}"
      case "$f" in *.dll|*.so|*.so.*|*.dylib) continue ;; esac
      if [ "$scanned" = 1 ]; then
        if [ "${scan_desktops[$file_index]}" = 1 ]; then target="$f"; break; fi
      else
        rc=0; contains_string "com.ferrumedge.anvil" "$f" || rc=$?
        if [ "$rc" = 0 ]; then contains_string "__TAURI_INTERNALS__" "$f" || rc=$?; fi
        case "$rc" in
          0) target="$f"; break ;;
          1) ;;
          *) bad_input "$f: could not read file for probe selection"; status="error"; break ;;
        esac
      fi
    done
    if [ "$status" = "error" ]; then
      probe_status="error"
    elif [ -z "$target" ]; then
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
