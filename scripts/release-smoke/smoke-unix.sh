#!/usr/bin/env bash
# Clean-install release smoke (REL-001) on a GitHub-hosted macOS or Linux
# runner. Installs one published, unsigned release package the way a user
# would, launches the installed app (twice: on an empty store and after the
# example import), and imports the sample workspace and makes a loopback call
# with the release CLI archive of the same release and target.
#
# Run by .github/workflows/release-smoke.yml; every step, the exact surface
# driven and every OS protection that was not exercised are recorded with
# record.py into $OUT (finalized into $OUT/result.json by the workflow).
#
# Environment:
#   TARGET_ID     result name, e.g. macos-arm64-dmg
#   PACKAGE       dmg | deb | rpm | appimage
#   EXPECT_ARCH   arm64 | x86_64 (the runner and the installed binary must match)
#   RUST_TARGET   release target triple (names the CLI archive directory)
#   ASSET         desktop package file name in $INPUTS
#   CLI_ASSET     CLI archive file name in $INPUTS
#   INPUTS        directory with the release assets, SHA256SUMS, release.json,
#                 example.json and the example bundle (from the fetch job)
#   OUT           result directory
#   VERSION       release version (X.Y.Z)
#   ALIVE_SECONDS how long each launch must stay up (default 30)
#   STARTUP_LIMIT how long a launch may take to show its window and webview
#                 (default 90)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${TARGET_ID:?}" "${PACKAGE:?}" "${EXPECT_ARCH:?}" "${RUST_TARGET:?}" "${ASSET:?}" "${CLI_ASSET:?}" "${INPUTS:?}" "${OUT:?}" "${VERSION:?}"
ALIVE_SECONDS="${ALIVE_SECONDS:-30}"
STARTUP_LIMIT="${STARTUP_LIMIT:-90}"
INPUTS="$(cd "$INPUTS" && pwd)"
mkdir -p "$OUT/logs" "$OUT/screenshots"
OUT="$(cd "$OUT" && pwd)"
logs="$OUT/logs"
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/rel001.XXXXXX")"
os="$(uname -s)"
SUDO=""
[ "$(id -u)" = 0 ] || SUDO="sudo"
WS="Anvil samples (lab core)"
SAMPLE_REQUESTS=("OK" "Backend refuses connections" "Backend name does not resolve" "Backend ends the body early" "Application 500 (not the gateway)" "Application 403 (not a WAF)")

py() { python3 -I "$here/record.py" "$@"; }
step() { py step --dir "$OUT" --name "$1" --result "$2" --detail "$3"; }
pass() { step "$1" pass "$2"; }
info() { step "$1" info "$2"; }
# Every failure is classified (record.py FAILURE_CLASSES): `fail` when the
# shipped asset is at fault (checksum, install, launch, import, local call),
# `hfail` when the harness is (runner, test tools, package mirrors, artifact
# fetch). Only a package failure is grounds to act on a published asset.
fail_as() { # $1 class, $2 step, $3 detail
  py step --dir "$OUT" --name "$2" --result fail --failure-class "$1" --detail "$3"
  echo "::error title=$TARGET_ID $2 ($1 failure)::$3"
  exit 1
}
fail() { fail_as package "$1" "$2"; }
hfail() { fail_as harness "$1" "$2"; }
# A package-manager install of the shipped package failed: a mirror or network
# error is the harness's, anything else (unmet dependencies, a broken package)
# is the package's. $1 step, $2 log, $3 detail.
fail_pkg_install() {
  if grep -qiE "Temporary failure resolving|Could not resolve|Failed to fetch|Unable to fetch|Could not connect|Connection (timed out|refused|reset)|Hash Sum mismatch|Curl error|Cannot download|Failed to download|Status code: 5[0-9][0-9]|Network is unreachable|Connection timed out|Operation timed out|Timeout was reached" "$2"; then
    hfail "$1" "$3 (package mirror or network error)"
  fi
  fail "$1" "$3"
}
bypass() { py bypass --dir "$OUT" --protection "$1" --what "$2"; }
meta() { py meta --dir "$OUT" "$@"; }
metaj() { py meta --dir "$OUT" --json "$@"; }
oneline() { tr '\n' ' ' | sed 's/  */ /g; s/ $//'; }

server_pid=""
app_pids=""
cleanup() {
  for p in $app_pids; do
    if [ "$os" = Darwin ]; then kill -KILL "$p" 2>/dev/null || true; else kill -KILL -- "-$p" 2>/dev/null || kill -KILL "$p" 2>/dev/null || true; fi
  done
  [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT

# --- inputs and runner ---------------------------------------------------

metaj "release=$(cat "$INPUTS/release.json")" "example=$(cat "$INPUTS/example.json")"
meta target_triple="$RUST_TARGET" package="$PACKAGE"

check_asset() { # $1 file name, $2 meta key
  local f="$INPUTS/$1" fetched status detail want got size
  # The fetch job checked the published asset against SHA256SUMS (fetch.sh):
  # a problem it found is the published release's, a package failure.
  fetched="$(py fetch-asset --fetch "$INPUTS/fetch.json" --name "$1")"
  status="${fetched%%$'\t'*}"
  detail="${fetched#*$'\t'}"
  [ "$status" != missing ] || hfail asset_integrity "$1: $detail"
  [ "$status" = ok ] || fail asset_integrity "published asset $1: $detail (fetch status $status)"
  # Here the check is of the hand-over between jobs: a difference now is a
  # transfer error, a harness failure.
  [ -f "$f" ] || hfail asset_integrity "$1 did not arrive from the fetch job"
  want="$(py sums --sums "$INPUTS/SHA256SUMS" --name "$1")" || hfail asset_integrity "SHA256SUMS from the fetch job does not list $1"
  got="$(py sha256 "$f")"
  [ "$want" = "$got" ] || hfail asset_integrity "$1 changed between the fetch job and this one (sha256 $got, SHA256SUMS $want)"
  size="$(wc -c <"$f" | tr -d ' ')"
  meta "$2.name=$1" "$2.sha256=$got"
  metaj "$2.size=$size" "$2.sha256sums_match=true"
}
check_asset "$ASSET" asset
check_asset "$CLI_ASSET" cli_asset
example_sha="$(py sha256 "$INPUTS/anvil-samples.anvil")"
want_example="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$INPUTS/example.json")"
[ "$example_sha" = "$want_example" ] || hfail asset_integrity "the example bundle changed after it was fetched ($example_sha, expected $want_example)"
pass asset_integrity "$ASSET and $CLI_ASSET match the release's SHA256SUMS; example bundle sha256 $example_sha"

machine="$(uname -m)"
translated=0
if [ "$os" = Darwin ]; then
  osver="macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  translated="$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)"
  cpu="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
else
  # shellcheck source=/dev/null
  osver="$(. /etc/os-release && echo "$PRETTY_NAME")"
  cpu="$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //' || echo unknown)"
fi
meta runner.label="${RUNNER_LABEL:-unknown}" runner.os="$osver" runner.kernel="$(uname -sr)" runner.machine="$machine" \
  runner.cpu="$cpu" runner.image="${ImageOS:-container}/${ImageVersion:-n/a}" runner.container="${SMOKE_CONTAINER:-none}"
metaj "runner.rosetta_translated=$([ "$translated" = 1 ] && echo true || echo false)"
[ "$machine" = "$EXPECT_ARCH" ] || hfail native_arch "runner machine is $machine, expected $EXPECT_ARCH"
[ "$translated" = 0 ] || hfail native_arch "this shell runs under Rosetta translation"
pass native_arch "$osver on $machine ($cpu), not translated"

# --- install ---------------------------------------------------------------

bin=""
app=""
install_dmg() {
  local xq xq2 mp src dest exe ver archs sp
  xq="$(xattr -p com.apple.quarantine "$INPUTS/$ASSET" 2>/dev/null || true)"
  mp="$work/dmg"
  mkdir -p "$mp"
  # The DMG shows the license agreement (bundle.licenseFile); hdiutil cancels
  # a non-interactive attach unless it is answered.
  if ! { yes 2>/dev/null || true; } | hdiutil attach -nobrowse -readonly -mountpoint "$mp" "$INPUTS/$ASSET" >"$logs/hdiutil-attach.log" 2>&1; then
    fail install "hdiutil attach failed: $(tail -3 "$logs/hdiutil-attach.log" | oneline)"
  fi
  bypass dmg_license_prompt "The DMG's license agreement was accepted non-interactively (yes piped into hdiutil attach); no person read or clicked it."
  ls -la "$mp" >"$logs/dmg-contents.txt" 2>&1 || true
  src="$(find "$mp" -maxdepth 1 -name '*.app' -type d | head -1)"
  [ -n "$src" ] || fail install "no .app at the top level of the DMG"
  dest="/Applications/$(basename "$src")"
  [ ! -e "$dest" ] || hfail install "$dest already exists on this runner; it is not clean"
  ditto "$src" "$dest" || fail install "ditto to /Applications failed"
  hdiutil detach "$mp" -quiet || hdiutil detach "$mp" -force -quiet || true
  app="$dest"
  exe="$(plutil -extract CFBundleExecutable raw "$app/Contents/Info.plist" 2>&1)" || fail install "the app's Info.plist has no CFBundleExecutable: $exe"
  ver="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist" 2>&1)" || fail install "the app's Info.plist has no CFBundleShortVersionString: $ver"
  bin="$app/Contents/MacOS/$exe"
  [ -x "$bin" ] || fail install "$bin is missing or not executable"
  [ "$ver" = "$VERSION" ] || fail install "installed app version $ver, expected $VERSION"
  archs="$(lipo -archs "$bin" 2>&1)" || fail install "lipo cannot read $bin: $archs"
  case " $archs " in *" $EXPECT_ARCH "*) ;; *) fail install "the installed binary is built for '$archs', not $EXPECT_ARCH" ;; esac
  xq2="$(xattr -p com.apple.quarantine "$app" 2>/dev/null || true)"
  meta install.method="hdiutil attach, then ditto of the .app to /Applications (the drag-to-Applications install)" \
    install.path="$app" install.executable="$bin" install.binary_archs="$archs" install.version="$ver"
  pass install "copied $(basename "$src") from the DMG to /Applications; version $ver; executable $exe ($archs)"

  codesign -dv --verbose=2 "$app" >"$logs/codesign.txt" 2>&1 || true
  sp=0
  spctl --assess --type execute -vv "$app" >"$logs/spctl-assess.txt" 2>&1 || sp=$?
  local sig spl
  sig="$(grep -E '^(Signature|TeamIdentifier|Authority)=' "$logs/codesign.txt" | oneline || true)"
  spl="$(oneline <"$logs/spctl-assess.txt")"
  meta signing.codesign="${sig:-no signature}" signing.spctl_assess="$spl (exit $sp)"
  info signing "codesign: ${sig:-no signature}; spctl --assess --type execute: $spl (exit $sp)"
  info quarantine "com.apple.quarantine on the DMG: ${xq:-absent}; on the installed app: ${xq2:-absent}"
  bypass gatekeeper "Gatekeeper's first-launch check never ran: the DMG and the installed app carried no com.apple.quarantine attribute (DMG: ${xq:-absent}; app: ${xq2:-absent}) because the asset was fetched through the GitHub API and an Actions artifact, not a browser. No xattr removal, Open Anyway override or spctl change was used. spctl --assess on the installed app: $spl (exit $sp)."
}

install_deb() {
  local f="$INPUTS/$ASSET" pkg dver darch st n
  pkg="$(dpkg-deb -f "$f" Package 2>&1)" || fail install "dpkg-deb cannot read $ASSET: $pkg"
  dver="$(dpkg-deb -f "$f" Version)"
  darch="$(dpkg-deb -f "$f" Architecture)"
  dpkg-deb -f "$f" Depends >"$logs/deb-depends.txt" || true
  dpkg-query -W -f '${Package}\n' | sort >"$work/pkgs-before"
  $SUDO apt-get update -qq >"$logs/apt-update.log" 2>&1 || hfail install "apt-get update failed"
  if ! $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$f" >"$logs/apt-install.log" 2>&1; then
    fail_pkg_install install "$logs/apt-install.log" "apt-get install of $ASSET failed: $(tail -5 "$logs/apt-install.log" | oneline)"
  fi
  dpkg-query -W -f '${Package}\n' | sort >"$work/pkgs-after"
  comm -13 "$work/pkgs-before" "$work/pkgs-after" >"$logs/apt-new-packages.txt"
  n="$(wc -l <"$logs/apt-new-packages.txt" | tr -d ' ')"
  st="$(dpkg-query -W -f '${Status} ${Version}' "$pkg")"
  case "$st" in "install ok installed $VERSION"*) ;; *) fail install "dpkg reports '$st' for $pkg" ;; esac
  bin="$(dpkg -L "$pkg" | grep -E '^/usr/bin/[^/]+$' | head -1 || true)"
  [ -n "$bin" ] && [ -x "$bin" ] || fail install "package $pkg installed no executable under /usr/bin"
  file -L "$bin" >"$logs/binary-file.txt"
  grep -q 'x86-64' "$logs/binary-file.txt" || fail install "$bin is not an x86-64 executable: $(cat "$logs/binary-file.txt")"
  meta install.method="apt-get install of the local .deb file" install.package="$pkg" install.version="$dver" \
    install.package_arch="$darch" install.executable="$bin"
  metaj "install.new_packages=$n"
  pass install "apt-get installed $pkg $dver ($darch) with $n new packages from the distribution archive; executable $bin"
  info signing "the .deb has no package signature and Linux has no platform code signing; integrity was checked against SHA256SUMS only"
  bypass package_signature "apt installs a local .deb without any signature check (repository signatures do not apply to a local file); the only integrity check was the release's SHA256SUMS."
}

install_rpm() {
  local f="$INPUTS/$ASSET" name rver n
  name="$(rpm -qp --qf '%{NAME}' "$f" 2>/dev/null)" || fail install "rpm cannot read $ASSET"
  rver="$(rpm -qp --qf '%{VERSION}-%{RELEASE}.%{ARCH}' "$f" 2>/dev/null)"
  rpm -qpR "$f" >"$logs/rpm-requires.txt" 2>&1 || true
  rpm -Kv "$f" >"$logs/rpm-checksig.txt" 2>&1 || true
  rpm -qa --qf '%{NAME}\n' | sort >"$work/pkgs-before"
  if dnf -y install "$f" >"$logs/dnf-install.log" 2>&1; then
    :
  elif grep -qiE 'gpg|openpgp|signature|not signed' "$logs/dnf-install.log"; then
    bypass rpm_signature "dnf refused the unsigned local RPM; it was installed with --nogpgcheck."
    dnf -y install --nogpgcheck "$f" >>"$logs/dnf-install.log" 2>&1 || fail_pkg_install install "$logs/dnf-install.log" "dnf install --nogpgcheck failed: $(tail -5 "$logs/dnf-install.log" | oneline)"
  else
    fail_pkg_install install "$logs/dnf-install.log" "dnf install of $ASSET failed: $(tail -5 "$logs/dnf-install.log" | oneline)"
  fi
  rpm -qa --qf '%{NAME}\n' | sort >"$work/pkgs-after"
  comm -13 "$work/pkgs-before" "$work/pkgs-after" >"$logs/dnf-new-packages.txt"
  n="$(wc -l <"$logs/dnf-new-packages.txt" | tr -d ' ')"
  rpm -q "$name" >/dev/null || fail install "rpm -q $name: not installed"
  bin="$(rpm -ql "$name" | grep -E '^/usr/bin/[^/]+$' | head -1 || true)"
  [ -n "$bin" ] && [ -x "$bin" ] || fail install "package $name installed no executable under /usr/bin"
  file -L "$bin" >"$logs/binary-file.txt"
  grep -q 'x86-64' "$logs/binary-file.txt" || fail install "$bin is not an x86-64 executable: $(cat "$logs/binary-file.txt")"
  meta install.method="dnf install of the local .rpm file" install.package="$name" install.version="$rver" install.executable="$bin"
  metaj "install.new_packages=$n"
  pass install "dnf installed $name $rver with $n new packages from the Fedora repositories; executable $bin"
  info signing "rpm -K: $(oneline <"$logs/rpm-checksig.txt"); Linux has no platform code signing; integrity was checked against SHA256SUMS"
  grep -q 'rpm_signature' "$OUT/bypasses.jsonl" 2>/dev/null ||
    bypass package_signature "dnf accepted the local RPM without a package signature check (local packages are not GPG-checked by default); the only integrity check was the release's SHA256SUMS."
}

install_appimage() {
  local dest prereq="none"
  if ! command -v fusermount3 >/dev/null && ! command -v fusermount >/dev/null; then
    $SUDO apt-get update -qq >"$logs/apt-update.log" 2>&1 || true
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y fuse3 >"$logs/apt-fuse.log" 2>&1 || hfail install "could not install fuse3 (fusermount) for the AppImage"
    prereq="fuse3 (fusermount3), installed because the runner had no fusermount"
  fi
  [ -e /dev/fuse ] || hfail install "/dev/fuse is not available on this runner"
  # AppImages leave the graphics driver stack (libEGL and its Mesa vendor
  # library and drivers) to the host, as the AppImage excludelist requires;
  # every desktop install has it, a bare runner may not.
  if ! /sbin/ldconfig -p | grep 'libEGL\.so\.1 ' >/dev/null || ! ls /usr/share/glvnd/egl_vendor.d/*mesa*.json >/dev/null 2>&1; then
    $SUDO apt-get update -qq >"$logs/apt-update.log" 2>&1 || true
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y libegl1 libegl-mesa0 libgl1-mesa-dri >"$logs/apt-egl.log" 2>&1 ||
      hfail install "could not install the host EGL stack for the AppImage"
    if [ "$prereq" = none ]; then prereq=""; else prereq="$prereq; "; fi
    prereq="${prereq}libegl1 libegl-mesa0 libgl1-mesa-dri (the host EGL/Mesa stack, which AppImages do not bundle), installed because the runner had no libEGL.so.1 or no Mesa EGL vendor"
  fi
  dest="$HOME/Applications"
  mkdir -p "$dest"
  cp "$INPUTS/$ASSET" "$dest/$ASSET"
  chmod +x "$dest/$ASSET"
  bin="$dest/$ASSET"
  file -L "$bin" >"$logs/binary-file.txt"
  grep -q 'ELF 64-bit.*x86-64' "$logs/binary-file.txt" || fail install "$ASSET is not an x86-64 ELF executable: $(cat "$logs/binary-file.txt")"
  meta install.method="copied to ~/Applications and marked executable (chmod +x)" install.executable="$bin" install.prerequisites="$prereq"
  pass install "copied $ASSET to ~/Applications and marked it executable; host prerequisites installed: $prereq"
  info signing "the .AppImage.sig asset is the in-app updater (minisign) signature, which the OS does not check; Linux has no platform code signing; integrity was checked against SHA256SUMS"
  bypass package_signature "the AppImage is run directly: nothing checks a signature at launch (the .AppImage.sig asset is the in-app updater's minisign signature, not checked by the OS); the only integrity check was the release's SHA256SUMS."
}

case "$PACKAGE" in
  dmg) install_dmg ;;
  deb) install_deb ;;
  rpm) install_rpm ;;
  appimage) install_appimage ;;
  *) hfail install "unknown package kind $PACKAGE" ;;
esac

# --- test harness (Linux display) -------------------------------------------
# Installed only after the package, so the package's own dependencies are
# resolved on the clean system first. Not part of the product install.

if [ "$os" = Linux ]; then
  if command -v apt-get >/dev/null; then
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends xvfb xauth xdotool imagemagick dbus >"$logs/harness-install.log" 2>&1 ||
      hfail harness_setup "could not install the Xvfb test harness"
  else
    dnf -y install xorg-x11-server-Xvfb xdotool dbus-daemon >"$logs/harness-install.log" 2>&1 || hfail harness_setup "could not install the Xvfb test harness"
  fi
  if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
    export XDG_RUNTIME_DIR="$work/xdg-runtime"
    mkdir -p "$XDG_RUNTIME_DIR"
    chmod 700 "$XDG_RUNTIME_DIR"
  fi
  Xvfb :99 -screen 0 1600x1000x24 -nolisten tcp >"$logs/xvfb.log" 2>&1 &
  export DISPLAY=:99
  for _ in $(seq 1 20); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.5; done
  xdotool getdisplaygeometry >/dev/null 2>&1 || hfail harness_setup "Xvfb did not start"
  # A desktop session always has a session bus; without one, GTK and the
  # portals wait for D-Bus timeouts before the window appears.
  command -v dbus-run-session >/dev/null || hfail harness_setup "dbus-run-session is not available"
  meta harness.display="Xvfb :99 1600x1000x24 (no window manager)" harness.session_bus="a private session bus per launch (dbus-run-session)"
fi

# --- release CLI ---------------------------------------------------------------

mkdir -p "$work/cli"
tar -xzf "$INPUTS/$CLI_ASSET" -C "$work/cli" || fail cli_ready "could not extract $CLI_ASSET"
cli="$work/cli/anvil-cli-$VERSION-$RUST_TARGET/anvil"
[ -x "$cli" ] || fail cli_ready "$CLI_ASSET has no executable anvil-cli-$VERSION-$RUST_TARGET/anvil"
cli_version="$("$cli" --version 2>&1 || true)"
case "$cli_version" in *"$VERSION"*) ;; *) fail cli_ready "anvil --version printed '$cli_version', expected $VERSION" ;; esac
"$cli" doctor >"$logs/cli-doctor-before.txt" 2>&1 || true
data_dir="$(sed -n 's/^data dir: //p' "$logs/cli-doctor-before.txt" | head -1)"
data_state="absent"
[ -d "$data_dir" ] && data_state="present ($(find "$data_dir" -mindepth 1 | wc -l | tr -d ' ') entries)"
meta cli.version="$cli_version" cli.data_dir="${data_dir:-unknown}" cli.data_dir_before_first_launch="$data_state"
pass cli_ready "release CLI archive $CLI_ASSET extracted ($cli_version); default data dir ${data_dir:-unknown}: $data_state"

meta surfaces.install="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["install"]["method"])' "$OUT/meta.json")"
meta surfaces.launch="$([ "$os" = Darwin ] && echo "open -n on the installed .app (LaunchServices), as a user's double-click" || echo "the installed executable started under Xvfb with a private session bus (dbus-run-session)")" \
  surfaces.import_and_call="release CLI archive $CLI_ASSET from the same release (the CLI is a separate release asset, not inside the desktop package), on the app's default data directory" \
  surfaces.gui_driven="no: the installed app was launched and observed (process, top-level window, webview processes), but no UI automation clicked or typed in it"

# --- launch ------------------------------------------------------------------

app_log_dir() {
  if [ "$os" = Darwin ]; then echo "$HOME/Library/Logs/com.ferrumedge.anvil"; else echo "${XDG_DATA_HOME:-$HOME/.local/share}/com.ferrumedge.anvil/logs"; fi
}

window_count() { # $1 = app pid
  if [ "$os" = Darwin ]; then
    local w
    w="$(osascript -l JavaScript "$here/mac-windows.js" "$1" 2>>"$logs/window-probe.err" || echo '[]')"
    python3 -I -c 'import json,sys; print(len(json.loads(sys.argv[1] or "[]")))' "$w" 2>/dev/null || echo 0
  else
    # xdotool exits 1 when nothing matches yet.
    { xdotool search --onlyvisible --name '^Ferrum Anvil$' 2>/dev/null || true; } | wc -l | tr -d ' '
  fi
}

webview_count() {
  if [ "$os" = Darwin ]; then
    { pgrep -f 'com.apple.WebKit.WebContent' || true; } | wc -l | tr -d ' '
  else
    { pgrep -f 'WebKitWebProcess' || true; } | wc -l | tr -d ' '
  fi
}

launch() { # $1 = step name
  local name="$1" pid="" i=0 win=0 web=0 web_before first_window="" first_webview="" shot="none"
  web_before="$(webview_count)"
  if [ "$os" = Darwin ]; then
    open -n --stdout "$logs/$name.stdout.log" --stderr "$logs/$name.stdout.log" "$app" 2>>"$logs/$name.open.log" ||
      open -n "$app" 2>>"$logs/$name.open.log" || fail "$name" "open -n '$app' failed: $(oneline <"$logs/$name.open.log")"
    for _ in $(seq 1 20); do
      pid="$(pgrep -nf "$bin" || true)"
      [ -n "$pid" ] && break
      sleep 1
    done
  else
    setsid dbus-run-session -- "$bin" >"$logs/$name.stdout.log" 2>&1 </dev/null &
    pid=$!
  fi
  [ -n "$pid" ] || fail "$name" "no app process appeared within 20 s of launching $bin"
  app_pids="$app_pids $pid"
  # Up for at least ALIVE_SECONDS, and until both the window and a webview
  # content process have appeared (at most STARTUP_LIMIT seconds).
  while [ "$i" -lt "$ALIVE_SECONDS" ] || { [ "$i" -lt "$STARTUP_LIMIT" ] && { [ -z "$first_window" ] || [ -z "$first_webview" ]; }; }; do
    sleep 1
    i=$((i + 1))
    kill -0 "$pid" 2>/dev/null || fail "$name" "the app exited ${i}s after launch (output: $(tail -5 "$logs/$name.stdout.log" 2>/dev/null | oneline))"
    if [ -z "$first_window" ] && [ "$(window_count "$pid")" != 0 ]; then first_window="${i}s"; fi
    if [ -z "$first_webview" ] && [ "$(($(webview_count) - web_before))" -gt 0 ]; then first_webview="${i}s"; fi
  done
  win="$(window_count "$pid")"
  web="$(($(webview_count) - web_before))"
  if [ "$os" = Darwin ]; then
    screencapture -x "$OUT/screenshots/$name.png" 2>/dev/null && shot="screenshots/$name.png" || true
  elif command -v import >/dev/null; then
    import -display "$DISPLAY" -window root "$OUT/screenshots/$name.png" 2>/dev/null && shot="screenshots/$name.png" || true
  fi
  ps -ef >"$logs/$name.ps.txt" 2>&1 || true
  # Stop the app (and, on Linux, its process group: AppImage runtime, webview processes).
  if [ "$os" = Darwin ]; then kill -TERM "$pid" 2>/dev/null || true; else kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true; fi
  for _ in $(seq 1 10); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  if [ "$os" = Darwin ]; then
    kill -KILL "$pid" 2>/dev/null || true
  else
    kill -KILL -- "-$pid" 2>/dev/null || true
  fi
  # Webview processes can outlive the app (macOS WebContent XPC services);
  # clear them so the next launch counts only its own. On this single-purpose
  # runner no other app uses WebKit.
  for _ in $(seq 1 10); do [ "$(webview_count)" -le "$web_before" ] && break; sleep 1; done
  if [ "$os" = Darwin ]; then
    pkill -KILL -f 'com.apple.WebKit.WebContent' 2>/dev/null || true
  else
    pkill -KILL -f 'WebKit(Web|Network)Process' 2>/dev/null || true
  fi
  local ld
  ld="$(app_log_dir)"
  if [ -d "$ld" ]; then mkdir -p "$logs/app-log-$name" && cp -R "$ld/." "$logs/app-log-$name/" 2>/dev/null || true; fi
  metaj "launches.$name={\"pid\":$pid,\"alive_seconds\":$i,\"top_level_windows\":$win,\"webview_processes\":$web,\"webview_processes_before_launch\":$web_before,\"app_log_dir_exists\":$([ -d "$ld" ] && echo true || echo false)}"
  meta "launches.$name.first_window_after=${first_window:-never}" "launches.$name.first_webview_after=${first_webview:-never}" "launches.$name.screenshot=$shot"
  local wanted="a top-level window titled 'Ferrum Anvil'"
  [ "$os" = Darwin ] && wanted="an on-screen window owned by the app process"
  # No window found because the probe itself failed says nothing about the app.
  if [ "$win" = 0 ] && [ "$os" = Darwin ] && [ -s "$logs/window-probe.err" ]; then
    hfail "$name" "the window probe (osascript) failed: $(tail -2 "$logs/window-probe.err" | oneline)"
  fi
  [ "$win" != 0 ] || fail "$name" "the app stayed up ${i}s but showed no $wanted (first seen: ${first_window:-never})"
  [ "$web" -gt 0 ] || fail "$name" "the app stayed up ${i}s but has no webview content process (WebKit; first seen: ${first_webview:-never}; $web_before were running before the launch)"
  pass "$name" "installed app stayed up ${i}s (pid $pid); $win top-level window(s), first after $first_window; $web webview content process(es), first after $first_webview; screenshot: $shot"
}

launch launch_first_run

# --- example import and a local call through the release CLI -------------------

ANVIL_PASSPHRASE="rel001-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export ANVIL_PASSPHRASE
if ! "$cli" profile create rel001-smoke 2>&1 | sed 's/RECOVERY KEY.*/RECOVERY KEY (withheld from the log)/' >"$logs/profile-create.log"; then
  fail profile_create "anvil profile create failed: $(oneline <"$logs/profile-create.log")"
fi
"$cli" profile list >"$logs/profile-list.txt" 2>&1 || fail profile_create "anvil profile list failed"
pass profile_create "passphrase profile created with the release CLI in ${data_dir:-the default data dir}: $(head -1 "$logs/profile-create.log")"

"$cli" import "$INPUTS/anvil-samples.anvil" >"$logs/import-report.json" 2>"$logs/import.stderr" ||
  fail example_import "anvil import failed: $(tail -5 "$logs/import.stderr" | oneline)"
"$cli" workspace tree "$WS" >"$logs/workspace-tree.txt" 2>&1 || fail example_import "anvil workspace tree '$WS' failed: $(oneline <"$logs/workspace-tree.txt")"
for r in "${SAMPLE_REQUESTS[@]}"; do
  grep -qF -- "$r" "$logs/workspace-tree.txt" || fail example_import "the imported workspace has no request '$r'"
done
pass example_import "imported the sample bundle samples/workspaces/anvil-samples.anvil (sha256 $example_sha) with the release CLI; workspace '$WS' holds all ${#SAMPLE_REQUESTS[@]} sample requests"

python3 -I "$here/local-server.py" --port 18080 --log "$logs/local-server-requests.jsonl" >"$logs/local-server.log" 2>&1 &
server_pid=$!
ready() { python3 -I -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18080/__ready", timeout=1).read()' 2>/dev/null; }
for _ in $(seq 1 30); do ready && break; sleep 0.5; done
ready || hfail local_call "the loopback listener on 127.0.0.1:18080 did not start"
before="$(py requests --log "$logs/local-server-requests.jsonl" --method GET --path /ok/echo)"
rc=0
"$cli" send "Healthy/OK" --workspace "$WS" --json >"$logs/send.json" 2>"$logs/send.stderr" || rc=$?
after="$(py requests --log "$logs/local-server-requests.jsonl" --method GET --path /ok/echo)"
statuses="$(py statuses "$logs/send.json" 2>/dev/null || true)"
"$cli" history -n 5 --workspace "$WS" >"$logs/history.txt" 2>&1 || true
kill "$server_pid" 2>/dev/null || true
server_pid=""
[ "$rc" = 0 ] || fail local_call "anvil send exited $rc: $(tail -5 "$logs/send.stderr" | oneline)"
[ "$after" -gt "$before" ] || fail local_call "the loopback listener logged no GET /ok/echo"
case " $statuses " in *" 200 "*) ;; *) fail local_call "the execution record shows no HTTP 200 (statuses found: ${statuses:-none})" ;; esac
ua="$(python3 -I -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1]) if "/ok/echo" in l][-1].get("user_agent"))' "$logs/local-server-requests.jsonl")"
meta local_call.request="Healthy/OK in '$WS'" local_call.url="http://127.0.0.1:18080/ok/echo" local_call.user_agent="$ua"
metaj "local_call.exit_code=$rc" "local_call.listener_requests=$((after - before))"
pass local_call "anvil send 'Healthy/OK' made GET http://127.0.0.1:18080/ok/echo; the loopback listener logged $((after - before)) request(s) (User-Agent: $ua) and answered 200; exit 0"

launch launch_with_example

echo "REL-001 smoke for $TARGET_ID finished; finalize with record.py."
