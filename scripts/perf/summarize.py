#!/usr/bin/env python3
"""Summarize desktop performance results from several jobs.

    python3 -I scripts/perf/summarize.py <result.json>... > summary.md

Reads the `anvil-desktop-perf` files measure_desktop.py writes (one per OS and
runner) and prints a Markdown table: per job, the first (coldest) run and the
median of the warm runs, then per OS the spread of the warm medians across
runners, which is what a regression threshold would have to absorb.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

COLUMNS = [
    ("ready_ms", "UI ready (ms)"),
    ("app_rss_mib", "app RSS (MiB)"),
    ("helpers_rss_mib", "webview helpers RSS (MiB)"),
    ("helpers_private_mib", "helpers private (MiB, Windows)"),
]


def fmt(v) -> str:
    if v is None:
        return "–"
    return f"{v:g}" if isinstance(v, (int, float)) else str(v)


def main(paths: list[str]) -> int:
    results = []
    for p in paths:
        d = json.loads(Path(p).read_text())
        if d.get("format") != "anvil-desktop-perf":
            raise SystemExit(f"{p}: not an anvil-desktop-perf result")
        results.append(d)
    results.sort(key=lambda d: (d["os"], d.get("label", "")))
    print("| Job | Runs | " + " | ".join(f"{t}: first / warm median" for _, t in COLUMNS) + " | Helpers (last run) | Attribution |")
    print("|---|---|" + "---|" * len(COLUMNS) + "---|---|")
    for d in results:
        s = d["summary"]
        cells = []
        for key, _ in COLUMNS:
            first = s["first_run"].get(key)
            warm = (s["warm_runs"].get(key) or {}).get("median")
            cells.append(f"{fmt(first)} / {fmt(warm)}")
        last = next((r for r in reversed(d["runs"]) if "error" not in r), {})
        names = sorted({h["name"] for h in last.get("helpers", [])})
        print(f"| {d['os']} {d.get('label', '')} | {s['runs_ok']} ok, {s['runs_failed']} failed | " + " | ".join(cells) + f" | {len(last.get('helpers', []))}: {', '.join(names)} | {last.get('attribution', '–')} |")
    print()
    print("Spread of the warm medians across runners, per OS (max − min, and as a share of the smallest):")
    print()
    print("| OS | " + " | ".join(t for _, t in COLUMNS) + " |")
    print("|---|" + "---|" * len(COLUMNS))
    by_os: dict[str, list[dict]] = {}
    for d in results:
        by_os.setdefault(d["os"], []).append(d)
    for os_name, ds in sorted(by_os.items()):
        cells = []
        for key, _ in COLUMNS:
            meds = [m for d in ds if (m := (d["summary"]["warm_runs"].get(key) or {}).get("median")) is not None]
            if len(meds) < 2:
                cells.append("–")
                continue
            lo, hi = min(meds), max(meds)
            cells.append(f"{hi - lo:g} ({(hi - lo) / lo * 100:.0f}%)" if lo else f"{hi - lo:g}")
        print(f"| {os_name} ({len(ds)} runners) | " + " | ".join(cells) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
