#!/usr/bin/env python3
"""Summarize desktop performance results from several jobs.

    python3 -I scripts/perf/summarize.py <result.json>... > summary.md

Reads the `anvil-desktop-perf` files measure_desktop.py writes (one per OS and
runner) and prints a Markdown table: per job, launch 1 (the first launch
after the artifact's extraction; its file cache state is not controlled) and
the median of the later launches, then per OS the spread of those medians
across runners, which is what a regression threshold would have to absorb.
A value that could not be measured or attributed is shown as "–", never as 0.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

COLUMNS = [
    ("ready_ms", "first screen usable (ms)"),
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
    print("| Job | Runs | " + " | ".join(f"{t}: launch 1 / later median" for _, t in COLUMNS) + " | Webview processes (last valid launch) | Attribution: launch 1 / later |")
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
        attribution = f"{s.get('first_run_attribution') or '–'} / {'; '.join(s.get('warm_attributions') or []) or '–'}"
        errors = sorted({r["error"] for r in d["runs"] if "error" in r})
        print(f"| {d['os']} {d.get('label', '')} | {s['runs_ok']} ok, {s['runs_failed']} failed | " + " | ".join(cells) + f" | {len(last.get('helpers', []))}: {', '.join(names) or '–'} | {attribution} |")
        for e in errors:
            print(f"|  | error: {e} |" + " |" * (len(COLUMNS) + 2))
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
