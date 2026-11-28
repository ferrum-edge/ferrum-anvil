#!/usr/bin/env python3
"""Measure the desktop app's launch time and webview helper memory.

    python3 -I scripts/perf/measure_desktop.py --app <binary> --runs 5 --idle 10 --out result.json

Standard library only; run by .github/workflows/perf.yml on macOS, Linux
(under Xvfb) and Windows against the release-profile app (default features,
no test hooks). Each run:

1. starts the app with a fresh, empty ANVIL_DATA_DIR (the first-run screen)
   and, on Windows, a fresh temporary WEBVIEW2_USER_DATA_FOLDER so each launch
   owns an isolated WebView2 browser session (later launches do not reuse a
   warm WebView2 disk cache; on Linux, WebKitGTK retains the runner's normal
   XDG disk state);
2. times, from just before the process is started, until the app's log file
   gains a `startup milestone milestone="ui_ready" pid=<pid>` line carrying
   the pid of the process it started (another instance's line never counts).
   The UI reports ready once its first usable screen is shown: here, the
   first-run form, after the profile list was read. The line's own
   `startup_ms` (measured inside the process from its start) is recorded too;
3. waits --idle seconds at that screen, then reads the resident memory of the
   app process and of its webview processes, identified by name and owner:
   - Linux: WebKitWebProcess, WebKitNetworkProcess and WebKitGPUProcess that
     descend from the app (verified per-launch process tree; sandbox wrappers
     such as bwrap are not counted);
   - Windows: msedgewebview2.exe processes that descend from the app
     (verified per-launch process tree inside the isolated WebView2 session;
     working set and private bytes);
   - macOS: WebKit's com.apple.WebKit.* XPC services, started by launchd:
     first attributed by `launchctl procinfo`'s `responsible pid == app_pid`
     (verified per-launch ownership). When the binary is spawned directly
     rather than through LaunchServices, macOS assigns both the app and its
     XPC helpers the spawning shell/runner as their responsible pid; the
     harness then falls back to provisional attribution (new WebKit services
     sharing the app's responsible pid, or pid delta when procinfo returns no
     owners). Provisional attribution is reported explicitly and is never used
     to authorize SIGKILL.
   A launch whose app process or webview content process (WebKitWebProcess,
   com.apple.WebKit.WebContent, msedgewebview2.exe) cannot be found records an
   error, not a number;
4. stops the app process tree/group (even after an early app exit or a failed
   process listing) and verifies by (pid, start_time, name) identity that every
   attributed process exited. Only verified per-launch processes whose identity
   still matches are ever force-stopped. If cleanup cannot be confirmed (a
   verified or provisional helper still runs, or process enumeration fails),
   the launch records an error and no further launch starts.

The first launch of a job follows the artifact's extraction on the same VM,
so its file cache state is not controlled: it is reported as the first
launch, not as a cold-cache start. Resident sizes count shared pages in every
process that maps them, so a total over processes overstates what the system
as a whole uses.
"""

from __future__ import annotations

import argparse
import ctypes
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

ProcId = tuple[int, str, str]  # (pid, start_time, image_name)


def proc_identity(row: dict) -> ProcId:
    return (int(row["pid"]), str(row.get("start") or ""), str(row.get("name") or ""))


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
    """Every process: pid, ppid, start, name, rss (bytes), and on Windows private bytes."""
    if SYSTEM == "Windows":
        ps = (
            "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,"
            "WorkingSetSize,PrivatePageCount,@{Name='Start';Expression={if ($_.CreationDate) {$_.CreationDate.ToUniversalTime().ToString('o')} else {''}}}"
            " | ConvertTo-Json -Compress"
        )
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, check=True).stdout
        rows = json.loads(out)
        if isinstance(rows, dict):
            rows = [rows]
        return [
            {
                "pid": int(r["ProcessId"]),
                "ppid": int(r["ParentProcessId"] or 0),
                "start": str(r.get("Start") or ""),
                "name": r["Name"] or "",
                "rss": int(r["WorkingSetSize"] or 0),
                "private": int(r["PrivatePageCount"] or 0),
            }
            for r in rows
        ]
    if SYSTEM == "Linux":
        rows = []
        page_size = os.sysconf("SC_PAGE_SIZE")
        try:
            entries = os.listdir("/proc")
        except OSError as exc:
            raise RuntimeError(f"failed to list /proc: {exc}") from exc
        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                stat = Path(f"/proc/{pid}/stat").read_text()
                lparen = stat.index("(")
                rparen = stat.rindex(")")
                comm = stat[lparen + 1 : rparen]
                after = stat[rparen + 2 :].split()
                ppid = int(after[1])
                start_ticks = after[19]
                rss_pages = int(after[21])
            except (OSError, ValueError, IndexError):
                continue
            name = comm
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
                if cmdline:
                    argv0 = cmdline.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    if argv0:
                        name = os.path.basename(argv0)
            except OSError:
                pass
            rows.append({
                "pid": pid,
                "ppid": ppid,
                "rss": rss_pages * page_size,
                "start": f"ticks:{start_ticks}",
                "name": name,
            })
        return rows
    env = dict(os.environ, LC_ALL="C")
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,rss=,lstart=,args="], capture_output=True, text=True, check=True, env=env).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        # lstart is 5 fixed tokens under LC_ALL=C: Dow Mon DD HH:MM:SS YYYY.
        start = " ".join(parts[3:8])
        # The image name: argv[0]'s basename (comm is truncated on Linux).
        argv0 = parts[8].strip().split(" ")[0]
        rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "rss": int(parts[2]) * 1024, "start": start, "name": os.path.basename(argv0)})
    return rows


def _parse_start(start: str) -> tuple[int, float | str] | None:
    if not start:
        return None
    if start.startswith("ticks:"):
        try:
            return (2, float(int(start[6:])))
        except ValueError:
            return None
    if "T" in start and start.endswith("Z"):
        # Windows Win32_Process CreationDate serialized as UTC ISO-8601 ("o").
        return (1, start)
    try:
        return (0, float(time.mktime(time.strptime(start, "%a %b %d %H:%M:%S %Y"))))
    except ValueError:
        return None


def _start_not_earlier(child_start: str, parent_start: str) -> bool:
    c = _parse_start(child_start)
    p = _parse_start(parent_start)
    if c is None or p is None or c[0] != p[0]:
        return False
    return c[1] >= p[1]


class _WinProcess:
    """Minimal Popen-compatible handle wrapper for a suspended-then-job-assigned Windows process."""

    STILL_ACTIVE = 259
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102

    def __init__(self, k32, h_process: int, pid: int) -> None:
        self._k32 = k32
        self._handle: int | None = h_process
        self.pid: int = pid
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        if not self._handle:
            return self.returncode
        code = ctypes.c_uint32(0)
        if self._k32.GetExitCodeProcess(self._handle, ctypes.byref(code)):
            if code.value != self.STILL_ACTIVE:
                self.returncode = int(code.value)
                self._close()
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        if not self._handle:
            return 0
        ms = 0xFFFFFFFF if timeout is None else max(0, int(timeout * 1000))
        res = self._k32.WaitForSingleObject(self._handle, ms)
        if res == self.WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(cmd="anvil-desktop", timeout=timeout or 0)
        rc = self.poll()
        return 0 if rc is None else rc

    def kill(self) -> None:
        if self._handle and self.returncode is None:
            self._k32.TerminateProcess(self._handle, 1)

    def _close(self) -> None:
        if self._handle:
            self._k32.CloseHandle(self._handle)
            self._handle = None


class _WinJob:
    """Kernel-enforced Windows Job Object for creation-time launch ownership and tree teardown."""

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFO = 9
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    CREATE_SUSPENDED = 0x00000004
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_UNICODE_ENVIRONMENT = 0x00000400

    def __init__(self) -> None:
        self.handle: int | None = None
        self.assigned: bool = False
        self.last_error: int = 0
        self._kernel32 = None
        if SYSTEM != "Windows" or not hasattr(ctypes, "WinDLL"):
            return
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        k32.CreateJobObjectW.restype = ctypes.c_void_p
        k32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        k32.SetInformationJobObject.restype = ctypes.c_int
        k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k32.AssignProcessToJobObject.restype = ctypes.c_int
        k32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        k32.TerminateJobObject.restype = ctypes.c_int
        k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        k32.IsProcessInJob.restype = ctypes.c_int
        k32.CreateProcessW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        k32.CreateProcessW.restype = ctypes.c_int
        k32.ResumeThread.argtypes = [ctypes.c_void_p]
        k32.ResumeThread.restype = ctypes.c_uint32
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        k32.GetExitCodeProcess.restype = ctypes.c_int
        k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        k32.WaitForSingleObject.restype = ctypes.c_uint32
        k32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        k32.TerminateProcess.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.restype = ctypes.c_int

        class _BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class _ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimit),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        h = k32.CreateJobObjectW(None, None)
        if not h:
            self.last_error = ctypes.get_last_error()
            return
        info = _ExtendedLimit()
        info.BasicLimitInformation.LimitFlags = self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not k32.SetInformationJobObject(
            h, self.JOB_OBJECT_EXTENDED_LIMIT_INFO, ctypes.byref(info), ctypes.sizeof(info)
        ):
            self.last_error = ctypes.get_last_error()
            k32.CloseHandle(h)
            return
        self.handle = h
        self._kernel32 = k32

    def spawn_suspended_and_assign(self, app: str, env: dict[str, str]) -> _WinProcess | None:
        """Start `app` suspended, assign it to the Job Object before any thread runs, then resume."""
        if not self.handle or self._kernel32 is None:
            return None

        class _StartupInfoW(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32),
                ("lpReserved", ctypes.c_wchar_p),
                ("lpDesktop", ctypes.c_wchar_p),
                ("lpTitle", ctypes.c_wchar_p),
                ("dwX", ctypes.c_uint32),
                ("dwY", ctypes.c_uint32),
                ("dwXSize", ctypes.c_uint32),
                ("dwYSize", ctypes.c_uint32),
                ("dwXCountChars", ctypes.c_uint32),
                ("dwYCountChars", ctypes.c_uint32),
                ("dwFillAttribute", ctypes.c_uint32),
                ("dwFlags", ctypes.c_uint32),
                ("wShowWindow", ctypes.c_uint16),
                ("cbReserved2", ctypes.c_uint16),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", ctypes.c_void_p),
                ("hStdOutput", ctypes.c_void_p),
                ("hStdError", ctypes.c_void_p),
            ]

        class _ProcessInformation(ctypes.Structure):
            _fields_ = [
                ("hProcess", ctypes.c_void_p),
                ("hThread", ctypes.c_void_p),
                ("dwProcessId", ctypes.c_uint32),
                ("dwThreadId", ctypes.c_uint32),
            ]

        si = _StartupInfoW()
        si.cb = ctypes.sizeof(si)
        pi = _ProcessInformation()
        env_block = "\0".join(f"{k}={v}" for k, v in env.items()) + "\0\0"
        env_buf = ctypes.create_unicode_buffer(env_block)
        cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline([app]))
        flags = self.CREATE_SUSPENDED | self.CREATE_NEW_PROCESS_GROUP | self.CREATE_UNICODE_ENVIRONMENT
        ok = self._kernel32.CreateProcessW(
            app,
            cmdline,
            None,
            None,
            0,
            flags,
            ctypes.byref(env_buf),
            None,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            self.last_error = ctypes.get_last_error()
            return None
        assigned = bool(self._kernel32.AssignProcessToJobObject(self.handle, pi.hProcess))
        if not assigned:
            self.last_error = ctypes.get_last_error()
            self._kernel32.TerminateProcess(pi.hProcess, 1)
            self._kernel32.CloseHandle(pi.hThread)
            self._kernel32.CloseHandle(pi.hProcess)
            return None
        self.assigned = True
        if self._kernel32.ResumeThread(pi.hThread) == 0xFFFFFFFF:
            self.last_error = ctypes.get_last_error()
            self._kernel32.TerminateJobObject(self.handle, 1)
            self._kernel32.CloseHandle(pi.hThread)
            self._kernel32.CloseHandle(pi.hProcess)
            self.assigned = False
            return None
        self._kernel32.CloseHandle(pi.hThread)
        return _WinProcess(self._kernel32, int(pi.hProcess), int(pi.dwProcessId))

    def assign(self, proc: subprocess.Popen) -> bool:
        if not self.handle or self._kernel32 is None:
            return False
        proc_handle = getattr(proc, "_handle", None)
        if not proc_handle:
            return False
        ok = bool(self._kernel32.AssignProcessToJobObject(self.handle, ctypes.c_void_p(int(proc_handle))))
        self.assigned = ok
        return ok

    def contains(self, pid: int) -> bool | None:
        if not self.handle or not self.assigned or self._kernel32 is None:
            return None
        hproc = self._kernel32.OpenProcess(self.PROCESS_QUERY_LIMITED_INFORMATION, 0, int(pid))
        if not hproc:
            return None
        try:
            res = ctypes.c_int(0)
            if not self._kernel32.IsProcessInJob(hproc, self.handle, ctypes.byref(res)):
                return None
            return bool(res.value)
        finally:
            self._kernel32.CloseHandle(hproc)

    def terminate(self) -> bool:
        if not self.handle or not self.assigned or self._kernel32 is None:
            return False
        return bool(self._kernel32.TerminateJobObject(self.handle, 1))

    def close(self) -> None:
        if self.handle and self._kernel32 is not None:
            self._kernel32.CloseHandle(self.handle)
            self.handle = None
            self.assigned = False


def descendants(
    rows: list[dict],
    root: int,
    before: set[ProcId] | None = None,
    require_creation_order: bool = False,
) -> list[dict]:
    """Descendants of `root`, excluding prelaunch identities and invalid creation-time edges."""
    by_pid = {r["pid"]: r for r in rows}
    root_row = by_pid.get(root)
    if require_creation_order and (root_row is None or _parse_start(str(root_row.get("start") or "")) is None):
        return []
    children: dict[int, list[dict]] = {}
    for r in rows:
        children.setdefault(r["ppid"], []).append(r)
    found: list[dict] = []
    seen_pids: set[int] = {root}
    todo: list[tuple[int, str]] = [(root, str((root_row or {}).get("start") or ""))]
    while todo:
        parent_pid, parent_start = todo.pop()
        for c in children.get(parent_pid, []):
            cid = c["pid"]
            if cid in seen_pids:
                continue
            if before is not None and proc_identity(c) in before:
                continue
            child_start = str(c.get("start") or "")
            if require_creation_order and not _start_not_earlier(child_start, parent_start):
                continue
            seen_pids.add(cid)
            found.append(c)
            todo.append((cid, child_start))
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


def helpers(
    rows: list[dict],
    app_pid: int,
    before: set[ProcId],
    known_app_owner: int | None = None,
    win_job: _WinJob | None = None,
    provisional_out: set[ProcId] | None = None,
    root_exited: bool = False,
) -> tuple[list[dict], str, bool]:
    """The app's webview processes, attribution label, and whether ownership is verified per-launch.

    When `provisional_out` is supplied, any newly observed helper whose ownership
    could not be verified (e.g. a macOS WebKit service whose `procinfo` query
    returned None, or a Linux WebKitGTK orphan after an early app exit) is added
    there so cleanup never falsely succeeds while it is still running.
    """
    if SYSTEM == "Darwin":
        webkit = [r for r in rows if is_mac_webkit(r["name"])]
        owners = {r["pid"]: responsible_pid(r["pid"]) for r in webkit}
        unresolved = [r for r in webkit if owners[r["pid"]] is None and proc_identity(r) not in before]
        if provisional_out is not None:
            provisional_out |= {proc_identity(r) for r in unresolved}
        attributed = [r for r in webkit if owners[r["pid"]] == app_pid and proc_identity(r) not in before]
        if attributed:
            return attributed, "launchctl procinfo responsible pid", True
        app_owner = known_app_owner if known_app_owner is not None else responsible_pid(app_pid)
        if app_owner is not None and app_owner != app_pid:
            # When the binary is spawned directly (not through LaunchServices),
            # macOS gives both the app and its XPC WebKit helpers the spawning
            # runner/shell as their responsible pid. Mark this provisional so it
            # is never used to authorize SIGKILL.
            shared = [r for r in webkit if owners[r["pid"]] == app_owner and proc_identity(r) not in before]
            if shared:
                return shared, "launchctl procinfo shared responsible pid + pid delta (provisional)", False
        if app_owner is not None and not unresolved and any(o is not None for o in owners.values()):
            # procinfo succeeded for the app and every WebKit service, and none belong to this app.
            return [], "launchctl procinfo responsible pid", True
        if unresolved and app_owner is not None:
            return (
                unresolved,
                "pid delta (provisional; WebKit ownership partially unavailable)",
                False,
            )
        # App ownership could not be queried (e.g. early exit) or procinfo gave no owner:
        # fall back to provisional pid-delta so surviving helpers are detected without authorizing SIGKILL.
        return (
            [r for r in webkit if proc_identity(r) not in before],
            "pid delta (provisional; WebKit services not running before the launch)",
            False,
        )
    if SYSTEM == "Windows":
        if win_job is not None and win_job.assigned:
            in_job = [
                r
                for r in rows
                if r["name"].lower() == "msedgewebview2.exe"
                and proc_identity(r) not in before
                and win_job.contains(r["pid"]) is True
            ]
            return in_job, "Windows job object (msedgewebview2.exe inside the launch job)", True
        tree = descendants(rows, app_pid, before=before, require_creation_order=True)
        return (
            [r for r in tree if r["name"].lower() == "msedgewebview2.exe"],
            "process tree (msedgewebview2.exe descendants verified by creation time and prelaunch baseline)",
            True,
        )
    if root_exited or not any(r["pid"] == app_pid for r in rows):
        # App already exited (possibly still visible as a zombie or reaped and
        # recycled) so Linux has reparented surviving children: never trust
        # descendants of `app_pid`, and track newly observed WebKitGTK helpers
        # provisionally so cleanup cannot report success while an orphan runs.
        if provisional_out is not None:
            provisional_out |= {
                proc_identity(r) for r in rows if r["name"] in LINUX_WEBVIEW and proc_identity(r) not in before
            }
        return [], "process tree (app exited; WebKitGTK ancestry unavailable)", False
    tree = descendants(rows, app_pid, before=before, require_creation_order=True)
    found = [r for r in tree if r["name"] in LINUX_WEBVIEW]
    return found, "process tree (WebKitGTK processes descending from the app)", True


def stop(proc: subprocess.Popen, win_job: _WinJob | None = None) -> tuple[bool, str | None]:
    """Stop the app and its launch containment group/job without signaling a reaped numeric PID."""
    if SYSTEM == "Windows":
        if win_job is not None and win_job.assigned:
            ok = win_job.terminate()
            if proc.poll() is None:
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=15)
            win_job.close()
            return (True, None) if ok else (False, "TerminateJobObject failed")
        if proc.returncode is None and proc.poll() is None:
            res = subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, text=True)
            if proc.poll() is None:
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=15)
            if res.returncode != 0 and proc.poll() is None:
                return False, f"taskkill exited {res.returncode}"
            return (True, None) if res.returncode == 0 else (False, f"taskkill exited {res.returncode} without a Windows job object")
        return False, "app exited before stop without a Windows job object"
    # Unix: only signal the session process group while the leader has not been reaped.
    if getattr(proc, "returncode", None) is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            if getattr(proc, "returncode", None) is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.kill()
                proc.wait(timeout=15)
    return True, None


def alive(expected: set[ProcId]) -> set[ProcId]:
    """Return identities from `expected` that still match a live process by (pid, start, name)."""
    if not expected:
        return set()
    current = {proc_identity(r) for r in processes()}
    return current & expected


UNIX_QUIET_CONFIRM_SECONDS = 0.5


def _survey_teardown(
    before: set[ProcId],
    verified_owned: set[ProcId],
    provisional_owned: set[ProcId],
) -> tuple[set[ProcId], set[ProcId]]:
    """Single-survey discovery + liveness check for teardown confirmation.

    Uses one `processes()` snapshot to both discover any newly visible
    Linux/macOS webview helpers and intersect live identities against
    `verified_owned` and `provisional_owned`, so a helper observed during the
    final survey can never slip between discovery and liveness checking.
    """
    rows = processes()
    current = {proc_identity(r) for r in rows}
    if SYSTEM in ("Linux", "Darwin"):
        for r in rows:
            rid = proc_identity(r)
            if rid in before or rid in verified_owned or rid in provisional_owned:
                continue
            if (SYSTEM == "Linux" and r["name"] in LINUX_WEBVIEW) or (
                SYSTEM == "Darwin" and is_mac_webkit(r["name"])
            ):
                provisional_owned.add(rid)
    return current & verified_owned, current & provisional_owned


def _wait_teardown_quiet(
    before: set[ProcId],
    verified_owned: set[ProcId],
    provisional_owned: set[ProcId],
    timeout: float = 30,
    quiet_seconds: float | None = None,
) -> tuple[set[ProcId], set[ProcId], bool]:
    """Wait until verified and provisional sets are empty across a quiet window.

    On Unix, requires `quiet_seconds` (default `UNIX_QUIET_CONFIRM_SECONDS`)
    of consecutive empty single-survey checks before confirming teardown so a
    pending WebKit XPC helper cannot appear right after the first empty poll
    and slip past cleanup. Returns `(live_verified, live_provisional, quiet_confirmed)`.
    """
    if quiet_seconds is None:
        quiet_seconds = UNIX_QUIET_CONFIRM_SECONDS if SYSTEM in ("Linux", "Darwin") else 0.0
    end = time.monotonic() + timeout
    quiet_since: float | None = None
    while True:
        live_v, live_p = _survey_teardown(before, verified_owned, provisional_owned)
        now = time.monotonic()
        if not live_v and not live_p:
            if quiet_seconds <= 0:
                return set(), set(), True
            if quiet_since is None:
                quiet_since = now
            if now <= end and (now - quiet_since) >= quiet_seconds:
                return set(), set(), True
            if now >= end:
                return set(), set(), False
            time.sleep(min(0.1, quiet_seconds, max(0.0, end - now)))
            continue
        quiet_since = None
        if now >= end:
            return live_v, live_p, False
        time.sleep(min(0.5, max(0.0, end - now)))


def _linux_proc_starttime(pid: int) -> str | None:
    """Kernel-tick start time from /proc/<pid>/stat (field 22), or None outside Linux."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        after_comm = stat.rsplit(")", 1)[1].split()
        return after_comm[19]  # field 22 (1-indexed) minus 3 (pid, comm, state-index)
    except (OSError, IndexError, ValueError):
        return None


def pin_linux_pidfd(proc_id: ProcId, pinned: dict[ProcId, int]) -> None:
    """Open and retain a Linux pidfd ONLY if it binds to the exact /proc starttime tick observed during ancestry verification."""
    if SYSTEM != "Linux" or proc_id in pinned:
        return
    pidfd_open = getattr(os, "pidfd_open", None)
    if pidfd_open is None:
        return
    pid, start_token, _ = proc_id
    if not start_token.startswith("ticks:"):
        return
    expected_ticks = start_token[6:]
    if not expected_ticks:
        return
    fd = None
    try:
        fd = pidfd_open(pid, 0)
        after_ticks = _linux_proc_starttime(pid)
        if after_ticks == expected_ticks:
            pinned[proc_id] = fd
            fd = None
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def force_stop(verified_expected: set[ProcId], pinned_pidfds: dict[ProcId, int] | None = None) -> bool:
    """Force-stop ONLY verified processes already bound to a pinned Linux pidfd.

    Never opens a fresh pidfd or signals a numeric PID after teardown begins.
    Returns True only when every surviving verified identity had a pinned fd
    and was signaled through `pidfd_send_signal`. Any unbound survivor causes
    teardown to mark `cleanup_unconfirmed=True` instead of risking PID reuse.
    """
    still_live = alive(verified_expected)
    if not still_live:
        return True
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if SYSTEM != "Linux" or pidfd_send_signal is None or not pinned_pidfds:
        return False
    all_bound = True
    for expected_id in sorted(still_live):
        fd = pinned_pidfds.get(expected_id)
        if fd is None:
            all_bound = False
            continue
        try:
            pidfd_send_signal(fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            all_bound = False
    return all_bound


# ------------------------------------------------------------- runs
def one_run(app: str, idle: float, timeout: float, index: int) -> dict:
    data_dir = tempfile.mkdtemp(prefix="anvil-perf-")
    env = dict(os.environ, ANVIL_DATA_DIR=data_dir)
    if SYSTEM == "Windows":
        env["WEBVIEW2_USER_DATA_FOLDER"] = os.path.join(data_dir, "webview2")
    before = {proc_identity(r) for r in processes()}
    sizes = log_size()
    kwargs: dict = {"env": env, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if SYSTEM != "Windows":
        kwargs["start_new_session"] = True
    win_job = _WinJob() if SYSTEM == "Windows" else None
    t0 = time.monotonic()
    proc: subprocess.Popen | _WinProcess | None = None
    if win_job is not None:
        if win_job.handle is None:
            shutil.rmtree(data_dir, ignore_errors=True)
            return {
                "run": index,
                "error": f"failed to create Windows Job Object (win32 error {win_job.last_error})",
                "stopped_cleanly": False,
                "cleanup_unconfirmed": True,
            }
        proc = win_job.spawn_suspended_and_assign(app, env)
        if proc is None:
            err_code = win_job.last_error
            win_job.close()
            shutil.rmtree(data_dir, ignore_errors=True)
            return {
                "run": index,
                "error": f"failed to launch app suspended inside Windows Job Object (win32 error {err_code})",
                "stopped_cleanly": False,
                "cleanup_unconfirmed": True,
            }
    else:
        proc = subprocess.Popen([app], **kwargs)
    result: dict = {"run": index, "pid": proc.pid}
    verified_owned: set[ProcId] = set()
    provisional_owned: set[ProcId] = set()
    pinned_pidfds: dict[ProcId, int] = {}
    app_responsible_pid: int | None = None
    try:
        try:
            # Poll only the log file and process exit so process enumeration never
            # blocks or inflates the ui_ready startup measurement.
            startup_ms = None
            while time.monotonic() - t0 < timeout:
                startup_ms = ready_line(sizes, proc.pid)
                if startup_ms is not None or proc.poll() is not None:
                    break
                time.sleep(0.02)
            ready_s = time.monotonic() - t0
            if startup_ms is None:
                result["error"] = (
                    "the app exited before its UI was ready"
                    if proc.poll() is not None
                    else f"no ui_ready line from pid {proc.pid} within {timeout:.0f} s"
                )
                return result
            result["ready_ms"] = round(ready_s * 1000)
            result["startup_ms_in_process"] = startup_ms
            # Capture the app's stable identity and macOS responsible pid while
            # it is live (unreaped), after readiness has already been timed.
            if proc.poll() is None:
                try:
                    post_ready_rows = processes()
                    if proc.poll() is None:
                        app_row = next((r for r in post_ready_rows if r["pid"] == proc.pid), None)
                        if app_row is not None and proc_identity(app_row) not in before:
                            app_id = proc_identity(app_row)
                            verified_owned.add(app_id)
                            pin_linux_pidfd(app_id, pinned_pidfds)
                except Exception:
                    pass
                if SYSTEM == "Darwin" and proc.poll() is None:
                    app_responsible_pid = responsible_pid(proc.pid)
            time.sleep(idle)
            if proc.poll() is not None:
                result["error"] = "the app exited while idle"
                return result
            rows = processes()
            root_exited = proc.poll() is not None
            app_row = None if root_exited else next((r for r in rows if r["pid"] == proc.pid), None)
            if SYSTEM == "Darwin" and app_responsible_pid is None and not root_exited:
                app_responsible_pid = responsible_pid(proc.pid)
            found, method, verified = helpers(
                rows,
                proc.pid,
                before,
                known_app_owner=app_responsible_pid,
                win_job=win_job,
                provisional_out=provisional_owned,
                root_exited=root_exited,
            )
            if app_row is not None and proc_identity(app_row) not in before:
                app_id = proc_identity(app_row)
                verified_owned.add(app_id)
                pin_linux_pidfd(app_id, pinned_pidfds)
            if verified:
                for h in found:
                    hid = proc_identity(h)
                    verified_owned.add(hid)
                    if not root_exited:
                        pin_linux_pidfd(hid, pinned_pidfds)
            else:
                provisional_owned |= {proc_identity(h) for h in found}
            result["attribution"] = method
            result["attribution_verified"] = verified
            if app_row is None:
                result["error"] = "the app process was not found in the process list"
                return result
            if not any(h["name"] == CONTENT[SYSTEM] for h in found):
                result["error"] = f"no {CONTENT[SYSTEM]} process could be attributed to the app ({method}); memory not reported"
                return result
            result["app_rss_mib"] = round(app_row["rss"] / MIB, 1)
            result["helpers"] = [
                {
                    "name": h["name"],
                    "pid": h["pid"],
                    "rss_mib": round(h["rss"] / MIB, 1),
                    **({"private_mib": round(h["private"] / MIB, 1)} if "private" in h else {}),
                }
                for h in found
            ]
            result["helpers_rss_mib"] = round(sum(h["rss"] for h in found) / MIB, 1)
            if SYSTEM == "Windows":
                result["app_private_mib"] = round((app_row or {}).get("private", 0) / MIB, 1)
                result["helpers_private_mib"] = round(sum(h.get("private", 0) for h in found) / MIB, 1)
            result["total_rss_mib"] = round(result["app_rss_mib"] + result["helpers_rss_mib"], 1)
            return result
        except Exception as exc:
            result["error"] = result.get("error") or f"unexpected harness error: {exc}"
            result["cleanup_unconfirmed"] = True
            return result
    finally:
        cleanup_error = None
        # Discover any additional helpers before stopping, without adopting a
        # recycled PID if the app already exited and without letting a listing
        # error block stopping the app.
        try:
            pre_stop_rows = processes()
            root_exited = getattr(proc, "returncode", None) is not None or proc.poll() is not None
            if not root_exited:
                app_row = next((r for r in pre_stop_rows if r["pid"] == proc.pid), None)
                if app_row is not None and proc_identity(app_row) not in before:
                    app_id = proc_identity(app_row)
                    verified_owned.add(app_id)
                    pin_linux_pidfd(app_id, pinned_pidfds)
                if SYSTEM == "Darwin" and app_responsible_pid is None:
                    app_responsible_pid = responsible_pid(proc.pid)
            later, _method, verified = helpers(
                pre_stop_rows,
                proc.pid,
                before,
                known_app_owner=app_responsible_pid,
                win_job=win_job,
                provisional_out=provisional_owned,
                root_exited=root_exited,
            )
            if verified and not root_exited:
                for h in later:
                    hid = proc_identity(h)
                    verified_owned.add(hid)
                    pin_linux_pidfd(hid, pinned_pidfds)
            else:
                provisional_owned |= {proc_identity(h) for h in later}
        except Exception as exc:
            cleanup_error = f"process listing failed during teardown: {exc}"
        try:
            stop_res = stop(proc, win_job) if win_job is not None else stop(proc)
            if isinstance(stop_res, tuple):
                stop_ok, stop_err = stop_res
                if not stop_ok:
                    cleanup_error = cleanup_error or stop_err or "stop failed"
        except Exception as exc:
            cleanup_error = cleanup_error or f"failed to stop app process: {exc}"
        finally:
            if win_job is not None:
                win_job.close()

        try:
            # Wait for all verified and provisional processes using single-survey
            # discovery + liveness checks across a bounded Unix quiet interval so
            # helpers appearing during shutdown or pending macOS XPC launches
            # cannot slip between discovery and liveness checks.
            live_v, live_p, quiet_ok = _wait_teardown_quiet(before, verified_owned, provisional_owned, timeout=30)
            if live_v:
                initial_survivors = sorted(pid for pid, _, _ in live_v)
                bound = force_stop(live_v, pinned_pidfds)
                live_v, live_p, quiet_ok = _wait_teardown_quiet(before, verified_owned, provisional_owned, timeout=15)
                still_verified = sorted(pid for pid, _, _ in live_v)
                if bound and not still_verified:
                    result["error"] = result.get("error") or f"verified processes {initial_survivors} outlived the app's stop (exited during forced teardown)"
                elif bound:
                    result["cleanup_unconfirmed"] = True
                    result["error"] = result.get("error") or f"verified processes {initial_survivors} outlived the app's stop (still running after force-stop: {still_verified})"
                else:
                    result["cleanup_unconfirmed"] = True
                    result["error"] = result.get("error") or f"verified processes {initial_survivors} outlived the app's stop without a safe termination handle"
                if still_verified:
                    result["left_running"] = still_verified
            result["stopped_cleanly"] = quiet_ok and not live_v and not live_p and cleanup_error is None
            if live_p:
                still_provisional = sorted(pid for pid, _, _ in live_p)
                # Never SIGKILL heuristically attributed processes; abort further launches instead.
                result["stopped_cleanly"] = False
                result["cleanup_unconfirmed"] = True
                result["provisional_left_running"] = still_provisional
                result["error"] = result.get("error") or (
                    f"provisional helpers {still_provisional} were still running after stop "
                    "(not force-stopped; aborting further launches)"
                )
            elif not quiet_ok and not live_v and cleanup_error is None:
                result["stopped_cleanly"] = False
                result["cleanup_unconfirmed"] = True
                quiet_msg = "teardown deadline elapsed before Unix quiet confirmation completed"
                result["error"] = f"{result['error']}; {quiet_msg}" if result.get("error") else quiet_msg
        except Exception as exc:
            cleanup_error = cleanup_error or f"process listing failed while confirming teardown: {exc}"
        finally:
            for fd in pinned_pidfds.values():
                try:
                    os.close(fd)
                except OSError:
                    pass
            pinned_pidfds.clear()

        if cleanup_error is not None:
            result["stopped_cleanly"] = False
            result["cleanup_unconfirmed"] = True
            result["cleanup_error"] = cleanup_error
            result["error"] = result.get("error") or cleanup_error
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
    runs: list[dict] = []
    aborted_error: str | None = None
    try:
        for i in range(1, args.runs + 1):
            try:
                r = one_run(args.app, args.idle, args.timeout, i)
            except Exception as exc:
                r = {"run": i, "error": f"unexpected harness error: {exc}", "cleanup_unconfirmed": True}
                runs.append(r)
                print(json.dumps(r), flush=True)
                aborted_error = str(exc)
                break
            print(json.dumps(r), flush=True)
            runs.append(r)
            if r.get("left_running") or r.get("cleanup_unconfirmed"):
                # Cleanup could not be confirmed: a further launch could share state or helpers.
                print(f"stopping: cleanup unconfirmed after launch {i}", flush=True)
                break
    finally:
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
        if aborted_error is not None:
            result["aborted_error"] = aborted_error
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result["summary"], indent=2))
    return 0 if result["summary"]["runs_failed"] == 0 and len(runs) == args.runs else 1


if __name__ == "__main__":
    sys.exit(main())
