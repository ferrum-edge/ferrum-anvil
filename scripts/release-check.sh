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
# scanned.
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
  for m in ${mounts[@]+"${mounts[@]}"}; do hdiutil detach -quiet "$m" >/dev/null 2>&1 || true; done
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
json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

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

# Unpack an artifact into $2 (a directory); print nothing on success.
unpack() {
  local a="$1" out="$2"
  mkdir -p "$out"
  case "$a" in
    *.dmg)
      command -v hdiutil >/dev/null || { echo "hdiutil (macOS) required for $a" >&2; return 1; }
      local mp="$work/mnt.$RANDOM"
      mkdir -p "$mp"
      hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mp" "$a" || return 1
      mounts+=("$mp")
      cp -R "$mp"/. "$out/" 2>/dev/null || true ;;
    *.deb)
      if command -v dpkg-deb >/dev/null; then dpkg-deb -x "$a" "$out"
      else (cd "$out" && ar x "$a" && for d in data.tar.*; do tar -xf "$d"; done); fi ;;
    *.rpm)
      command -v rpm2cpio >/dev/null || { echo "rpm2cpio required for $a" >&2; return 1; }
      (cd "$out" && rpm2cpio "$a" | cpio -idm --quiet) ;;
    *.AppImage)
      local abs; abs="$(cd "$(dirname "$a")" && pwd)/$(basename "$a")"
      chmod +x "$abs"
      (cd "$out" && "$abs" --appimage-extract >/dev/null) ;;
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

runtime_probe() { # $1 = executable; returns 0 pass, 1 fail, 2 inconclusive
  local exe="$1" port data pid code i alive=1 served=""
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
  local profiles=0
  if [ -d "$data/profiles" ]; then profiles="$(find "$data/profiles" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"; fi
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
  if [ ! -e "$a" ]; then bad_input "$a does not exist"; continue; fi
  dir="$work/a$idx"
  files=()
  if [ -f "$a" ] && is_exe "$a" && case "$a" in *-setup.exe|*_setup.exe|*.nsis.exe) false ;; *) true ;; esac; then
    files=("$a")
  else
    if [ -d "$a" ]; then
      dir="$a" # a directory or an .app bundle: scan in place
    else
      rc=0; unpack "$a" "$dir" || rc=$?
      if [ "$rc" = 2 ]; then bad_input "$a: unsupported artifact type"; continue; fi
      if [ "$rc" != 0 ]; then bad_input "$a: could not unpack"; continue; fi
    fi
    while IFS= read -r f; do
      if is_exe "$f"; then files+=("$f"); fi
    done < <(find "$dir" -type f 2>/dev/null)
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
    # Probe the desktop app: the executable carrying the Tauri identifier.
    target=""
    for f in "${files[@]}"; do
      case "$f" in *.dll|*.so|*.so.*|*.dylib) continue ;; esac
      if LC_ALL=C grep -a -q -F "com.ferrumedge.anvil" "$f"; then target="$f"; break; fi
    done
    if [ -z "$target" ]; then
      say "      probe: no desktop executable in this artifact (skipped)"
    else
      [ -x "$target" ] || chmod +x "$target" 2>/dev/null || true
      prc=0; runtime_probe "$target" || prc=$?
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
