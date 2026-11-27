#!/usr/bin/env python3
"""Measure the desktop app's launch time and webview helper memory.

    python3 -I scripts/perf/measure_desktop.py --app <binary> --runs 5 --idle 10 --out result.json

Standard library only; run by .github/workflows/perf.yml on macOS, Linux
(under Xvfb) and Windows against the release-profile app (default features,
no test hooks). Each run:

1. starts the app with a fresh, empty ANVIL_DATA_DIR (the first-run screen);
2. times, from just before the process is started, until the app's log file
   gains a `startup milestone milestone="ui_ready" pid=<pid>` line carrying
   the pid of the process it started (another instance's line never counts).
   The UI reports ready once its first usable screen is shown: here, the
   first-run form, after the profile list was read. The line's own
   `startup_ms` (measured inside the process from its start) is recorded too;
3. waits --idle seconds at that screen, then reads the resident memory of the
   app process and of its webview processes, identified by name and owner:
   - Linux: WebKitWebProcess, WebKitNetworkProcess and WebKitGPUProcess that
     descend from the app (sandbox wrappers such as bwrap are not counted);
   - Windows: msedgewebview2.exe processes that descend from the app
     (working set, and private bytes);
   - macOS: WebKit's com.apple.WebKit.* XPC services, started by launchd, so
     attributed by `launchctl procinfo`'s "responsible pid". If procinfo gives
     no responsible pid for any of them, the services not running before the
     launch are taken (recorded as the weaker "pid delta" attribution), never
     one that procinfo names another owner for.
   A launch whose app process or webview content process (WebKitWebProcess,
   com.apple.WebKit.WebContent, msedgewebview2.exe) cannot be found records an
   error, not a number;
4. stops the app and its attributed processes and waits until they are gone.
   A process that outlives the wait is stopped by force only if it is the
   app's own (attributed above); the launch then records an error, and if
   any of them is still running no further launch starts.

The first launch of a job follows the artifact's extraction on the same VM,
so its file cache state is not controlled: it is reported as the first
launch, not as a cold-cache start. Resident sizes count shared pages in every
process that maps them, so a total over processes overstates what the system
as a whole uses.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IDENTIFIER = "com.ferrumedge.anvil"
LOG_FILE = "anvil.log"
READY_RE = re.compile(r'startup milestone milestone="ui_ready" pid=(\d+) startup_ms=(\d+)')
# Webview processes per OS (process image names; Linux comm is cut at 15 bytes, so
# the full argv[0] is used).
LINUX_WEBVIEW = {"WebKitWebProcess", "WebKitNetworkProcess", "WebKitGPUProcess"}
CONTENT = {"Linux": "WebKitWebProcess", "Windows": "msedgewebview2.exe", "Darwin": "com.apple.WebKit.WebContent"}
SYSTEM = platform.system()
MIB = 1024 * 1024


def log_dirs() -> list[Path]:
    """Where Tauri's app_log_dir is for the app's identifier on this OS."""
    home = Path.home()
    if SYSTEM == "Darwin":
        return [home / "Library" / "Logs" / IDENTIFIER]
    if SYSTEM == "Windows":
        base = os.environ.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
        return [Path(base) / IDENTIFIER / "logs"]
    data = os.environ.get("XDG_DATA_HOME") or str(home / ".local" / "share")
    return [Path(data) / IDENTIFIER / "logs"]


def log_size() -> dict[Path, int]:
    sizes = {}
    for d in log_dirs():
        p = d / LOG_FILE
        sizes[p] = p.stat().st_size if p.exists() else 0
    return sizes


def ready_in(text: str, pid: int) -> int | None:
    """startup_ms of the ui_ready line `pid` wrote in `text`, if any."""
    for m in READY_RE.finditer(text):
        if int(m.group(1)) == pid:
            return int(m.group(2))
    return None


def ready_line(start_sizes: dict[Path, int], pid: int) -> int | None:
    """startup_ms of a ui_ready line by `pid` written since start_sizes, if any."""
    for p, offset in start_sizes.items():
        if not p.exists():
            continue
        size = p.stat().st_size
        if size < offset:  # rotated
            offset = 0
        with open(p, "rb") as f:
            f.seek(offset)
            found = ready_in(f.read().decode("utf-8", "replace"), pid)
        if found is not None:
            return found
    return None


# ------------------------------------------------------------- processes
def processes() -> list[dict]:
    """Every process: pid, ppid, name, rss (bytes), and on Windows private bytes."""
    if SYSTEM == "Windows":
        ps = (
            "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,WorkingSetSize,PrivatePageCount"
            " | ConvertTo-Json -Compress"
        )
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, check=True).stdout
        rows = json.loads(out)
        return [
            {
                "pid": int(r["ProcessId"]),
                "ppid": int(r["ParentProcessId"] or 0),
                "name": r["Name"] or "",
                "rss": int(r["WorkingSetSize"] or 0),
                "private": int(r["PrivatePageCount"] or 0),
            }
            for r in rows
        ]
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,rss=,args="], capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        # The image name: argv[0]'s basename (comm is truncated on Linux).
        argv0 = parts[3].strip().split(" ")[0]
        rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "rss": int(parts[2]) * 1024, "name": os.path.basename(argv0)})
    return rows


def descendants(rows: list[dict], root: int) -> list[dict]:
    children: dict[int, list[dict]] = {}
    for r in rows:
        children.setdefault(r["ppid"], []).append(r)
    found, todo = [], [root]
    while todo:
        for c in children.get(todo.pop(), []):
            if c["pid"] != root and c not in found:
                found.append(c)
                todo.append(c["pid"])
    return found


def responsible_pid(pid: int) -> int | None:
    try:
        out = subprocess.run(["sudo", "-n", "launchctl", "procinfo", str(pid)], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"^\s*responsible pid = (\d+)", out, re.M)
    return int(m.group(1)) if m else None


def is_mac_webkit(name: str) -> bool:
    return name.startswith("com.apple.WebKit.")


def helpers(rows: list[dict], app_pid: int, before: set[int]) -> tuple[list[dict], str]:
    """The app's webview processes and how they were attributed."""
    if SYSTEM == "Darwin":
        webkit = [r for r in rows if is_mac_webkit(r["name"])]
        owners = {r["pid"]: responsible_pid(r["pid"]) for r in webkit}
        attributed = [r for r in webkit if owners[r["pid"]] == app_pid]
        if attributed:
            return attributed, "launchctl procinfo responsible pid"
        if any(o is not None for o in owners.values()):
            # procinfo works here but names no WebKit service of this app.
            return [], "launchctl procinfo responsible pid"
        # procinfo gives no owner on this runner: new services, never one with another owner.
        return [r for r in webkit if r["pid"] not in before], "pid delta (WebKit services not running before the launch; weaker)"
    tree = descendants(rows, app_pid)
    if SYSTEM == "Windows":
        return [r for r in tree if r["name"].lower() == "msedgewebview2.exe"], "process tree (msedgewebview2.exe descendants of the app)"
    return [r for r in tree if r["name"] in LINUX_WEBVIEW], "process tree (WebKitGTK processes descending from the app)"


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if SYSTEM == "Windows":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        if SYSTEM != "Windows":
            os.killpg(proc.pid, signal.SIGKILL)
        proc.kill()
        proc.wait(timeout=15)


def alive(pids: set[int]) -> set[int]:
    return {r["pid"] for r in processes()} & pids


def wait_gone(pids: set[int], timeout: float = 30) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not alive(pids):
            return True
        time.sleep(0.5)
    return False


def force_stop(pids: set[int]) -> None:
    """Stop processes this launch owns (the app and its attributed webview processes)."""
    for pid in pids:
        try:
            if SYSTEM == "Windows":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
            else:
                os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


# ------------------------------------------------------------- runs
def one_run(app: str, idle: float, timeout: float, index: int) -> dict:
    data_dir = tempfile.mkdtemp(prefix="anvil-perf-")
    env = dict(os.environ, ANVIL_DATA_DIR=data_dir)
    before = {r["pid"] for r in processes()}
    sizes = log_size()
    kwargs = {"env": env, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if SYSTEM == "Windows":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    t0 = time.monotonic()
    proc = subprocess.Popen([app], **kwargs)
    result: dict = {"run": index, "pid": proc.pid}
    owned: set[int] = {proc.pid}
    try:
        startup_ms = None
        while time.monotonic() - t0 < timeout:
            startup_ms = ready_line(sizes, proc.pid)
            if startup_ms is not None or proc.poll() is not None:
                break
            time.sleep(0.02)
        ready_s = time.monotonic() - t0
        if startup_ms is None:
            result["error"] = "the app exited before its UI was ready" if proc.poll() is not None else f"no ui_ready line from pid {proc.pid} within {timeout:.0f} s"
            return result
        result["ready_ms"] = round(ready_s * 1000)
        result["startup_ms_in_process"] = startup_ms
        time.sleep(idle)
        if proc.poll() is not None:
            result["error"] = "the app exited while idle"
            return result
        rows = processes()
        app_row = next((r for r in rows if r["pid"] == proc.pid), None)
        found, method = helpers(rows, proc.pid, before)
        owned |= {h["pid"] for h in found}
        result["attribution"] = method
        if app_row is None:
            result["error"] = "the app process was not found in the process list"
            return result
        if not any(h["name"] == CONTENT[SYSTEM] for h in found):
            result["error"] = f"no {CONTENT[SYSTEM]} process could be attributed to the app ({method}); memory not reported"
            return result
        result["app_rss_mib"] = round(app_row["rss"] / MIB, 1)
        result["helpers"] = [{"name": h["name"], "pid": h["pid"], "rss_mib": round(h["rss"] / MIB, 1), **({"private_mib": round(h["private"] / MIB, 1)} if "private" in h else {})} for h in found]
        result["helpers_rss_mib"] = round(sum(h["rss"] for h in found) / MIB, 1)
        if SYSTEM == "Windows":
            result["app_private_mib"] = round((app_row or {}).get("private", 0) / MIB, 1)
            result["helpers_private_mib"] = round(sum(h.get("private", 0) for h in found) / MIB, 1)
        result["total_rss_mib"] = round(result["app_rss_mib"] + result["helpers_rss_mib"], 1)
        return result
    finally:
        # Webview processes that appeared after the sample are the app's too
        # if they descend from it (Linux, Windows) or name it as owner (macOS).
        if proc.poll() is None:
            later, _ = helpers(processes(), proc.pid, before)
            owned |= {h["pid"] for h in later}
        stop(proc)
        result["stopped_cleanly"] = wait_gone(owned)
        if not result["stopped_cleanly"]:
            left = alive(owned)
            force_stop(left)
            result["error"] = result.get("error") or f"processes {sorted(left)} outlived the app's stop (stopped by force)"
            result["left_running"] = sorted(alive(owned)) if not wait_gone(owned, 15) else []
        shutil.rmtree(data_dir, ignore_errors=True)


def summarize(runs: list[dict]) -> dict:
    ok = [r for r in runs if "error" not in r]
    first = next((r for r in ok if r["run"] == 1), None)
    warm = [r for r in ok if r["run"] > 1]

    def stat(key: str, rs: list[dict]) -> dict | None:
        vals = [r[key] for r in rs if key in r]
        if not vals:
            return None
        return {"median": statistics.median(vals), "min": min(vals), "max": max(vals), "n": len(vals)}

    keys = ["ready_ms", "startup_ms_in_process", "app_rss_mib", "helpers_rss_mib", "total_rss_mib", "app_private_mib", "helpers_private_mib"]
    return {
        "runs_ok": len(ok),
        "runs_failed": len(runs) - len(ok),
        # Launch 1 only (empty if it failed), then every valid later launch.
        "first_run": {k: first[k] for k in keys if first and k in first},
        "first_run_attribution": (first or {}).get("attribution"),
        "warm_runs": {k: s for k in keys if (s := stat(k, warm))},
        "warm_attributions": sorted({r["attribution"] for r in warm if r.get("attribution")}),
        "all_runs": {k: s for k in keys if (s := stat(k, ok))},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--app", required=True)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--idle", type=float, default=10)
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    args = ap.parse_args()
    runs = []
    for i in range(1, args.runs + 1):
        r = one_run(args.app, args.idle, args.timeout, i)
        print(json.dumps(r), flush=True)
        runs.append(r)
        if r.get("left_running"):
            # A process of this launch still runs: a further launch would share it.
            print(f"stopping: processes {r['left_running']} of launch {i} are still running", flush=True)
            break
    result = {
        "format": "anvil-desktop-perf",
        "version": 1,
        "label": args.label,
        "os": SYSTEM,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "runner": os.environ.get("RUNNER_NAME"),
        "image": os.environ.get("ImageOS"),
        "image_version": os.environ.get("ImageVersion"),
        "commit": os.environ.get("GITHUB_SHA"),
        "app": args.app,
        "idle_seconds": args.idle,
        "runs": runs,
        "summary": summarize(runs),
    }
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))
    return 0 if result["summary"]["runs_failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
