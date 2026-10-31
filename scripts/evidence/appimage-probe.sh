#!/usr/bin/env bash
# TEMPORARY evidence helper for the AppImage EGL fix (dropped before merge).
# Launch one extracted AppDir's AppRun under the current $DISPLAY with a
# private session bus, watch it for 30 s, and append a JSON line to
# $OUT/results.jsonl: app alive, a visible "Ferrum Anvil" window, a live
# WebKitWebProcess at 30 s, and whether the EGL abort was logged.
#
# usage: appimage-probe.sh OUT LABEL APPDIR
set -uo pipefail
out="$1" label="$2" dir="$3"
log="$out/$label.log"
mkdir -p "$out"
pkill -KILL -f 'WebKit(Web|Network)Process' 2>/dev/null || true
sleep 1
webcount() { { pgrep -f 'WebKitWebProcess' || true; } | wc -l | tr -d ' '; }
wincount() { { xdotool search --onlyvisible --name '^Ferrum Anvil$' 2>/dev/null || true; } | wc -l | tr -d ' '; }
setsid dbus-run-session -- "$dir/AppRun" >"$log" 2>&1 </dev/null &
pid=$!
first_web="never" first_win="never" exited="no"
for i in $(seq 1 30); do
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null; then exited="${i}s"; break; fi
  if [ "$first_web" = never ] && [ "$(webcount)" -gt 0 ]; then first_web="${i}s"; fi
  if [ "$first_win" = never ] && [ "$(wincount)" -gt 0 ]; then first_win="${i}s"; fi
done
alive=false
kill -0 "$pid" 2>/dev/null && alive=true
web="$(webcount)"
win="$(wincount)"
egl="$(grep -c 'EGL_BAD_PARAMETER' "$log" || true)"
ps -ef >"$out/$label.ps.txt" 2>&1 || true
if command -v import >/dev/null; then import -display "$DISPLAY" -window root "$out/$label.png" 2>/dev/null || true; fi
kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
sleep 3
kill -KILL -- "-$pid" 2>/dev/null || true
pkill -KILL -f 'WebKit(Web|Network)Process' 2>/dev/null || true
pass=false
if [ "$alive" = true ] && [ "$web" -gt 0 ] && [ "$win" -gt 0 ] && [ "$egl" = 0 ]; then pass=true; fi
printf '{"label":"%s","pass":%s,"app_alive_30s":%s,"exited_after":"%s","windows_at_30s":%s,"first_window":"%s","webprocesses_at_30s":%s,"first_webprocess":"%s","egl_bad_parameter_lines":%s,"last_output":"%s"}\n' \
  "$label" "$pass" "$alive" "$exited" "$win" "$first_win" "$web" "$first_web" "$egl" \
  "$(tail -3 "$log" | tr '\n"\\' '   ' | tr -cd '[:print:]')" >>"$out/results.jsonl"
echo "$label: pass=$pass alive=$alive exited=$exited windows=$win (first $first_win) webprocesses=$web (first $first_web) egl_abort_lines=$egl"
tail -5 "$log" | sed "s/^/  [$label] /"
