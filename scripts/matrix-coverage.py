#!/usr/bin/env python3
"""Map the 182 seed scenarios of FERRUM_ANVIL_FAILURE_MATRIX.json to evidence.

Evidence is discovered, not declared:
  * test functions / lab scenario ids / E2E specs that name the scenario id
    (forms: UP-001, up_001, up001) under crates/, apps/desktop/e2e/ and
    apps/desktop/src/**/*.test.*;
  * the latest real-gateway lab results (results/lab/*/<ID>.json);
  * explicit, reasoned statuses in docs/verification/matrix-status.json for
    cases that are blocked or not applicable (never counted as passed).

Outputs docs/verification/matrix-coverage.{json,md}. Exit code 1 if any case
has no evidence and no reasoned status (use --allow-gaps to report only).
"""

import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MATRIX = os.path.join(ROOT, "docs/handoff/FERRUM_ANVIL_FAILURE_MATRIX.json")
STATUS = os.path.join(ROOT, "docs/verification/matrix-status.json")
OUT_DIR = os.path.join(ROOT, "docs/verification")

SCAN_GLOBS = [
    "crates/**/*.rs",
    "apps/desktop/e2e/**/*.ts",
    "apps/desktop/e2e/**/*.js",
    "apps/desktop/src/**/*.test.ts",
    "apps/desktop/src/**/*.test.tsx",
]


def kind_for(path: str) -> str:
    if path.startswith("crates/anvil-lab/"):
        return "lab"
    if path.startswith("apps/desktop/e2e/"):
        return "native_e2e"
    if path.startswith("apps/desktop/src/"):
        return "renderer_test"
    if "/tests/" in path:
        return "integration_test"
    return "unit_test"


def id_patterns(case_id: str):
    fam, num = case_id.split("-", 1)
    lo = fam.lower()
    # Word-ish boundaries so UP-01 does not match UP-010.
    return [
        re.compile(rf"(?<![A-Za-z0-9]){re.escape(case_id)}(?![0-9])"),
        re.compile(rf"(?<![A-Za-z0-9]){lo}_{num}(?![0-9])"),
        re.compile(rf"(?<![A-Za-z0-9_]){lo}{num}(?![0-9])"),
    ]


def scan(cases):
    files = []
    for g in SCAN_GLOBS:
        files.extend(glob.glob(os.path.join(ROOT, g), recursive=True))
    refs = {c["id"]: [] for c in cases}
    pats = {c["id"]: id_patterns(c["id"]) for c in cases}
    for f in sorted(set(files)):
        rel = os.path.relpath(f, ROOT)
        if "/target/" in rel or "node_modules" in rel:
            continue
        try:
            lines = open(f, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        kind = kind_for(rel)
        for i, line in enumerate(lines, 1):
            # Outside test files, only test function names and lab scenario
            # definitions count as evidence (not comments in product code).
            if kind == "unit_test" and not re.search(r"\bfn\s+\w+", line):
                continue
            if kind == "lab" and not re.search(r'id:\s*"|fn\s+\w+|skipped\(', line):
                continue
            for cid, ps in pats.items():
                if any(p.search(line) for p in ps):
                    refs[cid].append({"path": rel, "line": i, "kind": kind})
    return refs


BASE_ID = re.compile(r"^([A-Z]+-\d+)(?:$|[.\-])")


def latest_lab_results():
    """base id -> {runs, variants: {scenario id: {profile, passes}}} from the
    newest run per profile. Scenario variants (`UP-004.expired`,
    `GW-013-TIMEOUT`, `UP-002-tcp`) count toward their base case."""
    out = {}
    runs = sorted(glob.glob(os.path.join(ROOT, "results/lab/*")))
    newest = {}
    for r in runs:
        name = os.path.basename(r)
        if "-" not in name:
            continue
        profile = name.split("-", 1)[1]
        newest[profile] = r  # sorted by timestamp prefix
    for profile, r in sorted(newest.items()):
        for f in glob.glob(os.path.join(r, "*.json")):
            base = os.path.basename(f)
            if base == "summary.json" or base.endswith(".record.json"):
                continue
            try:
                d = json.load(open(f))
            except (OSError, ValueError):
                continue
            rid = d.get("id", "")
            untrusted = rid.endswith("-untrusted")
            sid = rid[: -len("-untrusted")] if untrusted else rid
            m = BASE_ID.match(sid)
            if not m:
                continue
            entry = out.setdefault(m.group(1), {"runs": [], "variants": {}})
            run = os.path.relpath(r, ROOT)
            if run not in entry["runs"]:
                entry["runs"].append(run)
            var = entry["variants"].setdefault(f"{profile}:{sid}", {"profile": profile, "scenario": sid, "passes": {}})
            var["passes"]["untrusted" if untrusted else "trusted"] = {
                "status": d.get("status"),
                "skip_reason": d.get("skip_reason"),
            }
    return out


def classify(case, refs, lab, overrides):
    cid = case["id"]
    ov = overrides.get(cid)
    kinds = sorted({r["kind"] for r in refs})
    labres = lab.get(cid)
    lab_statuses = [p["status"] for v in (labres or {}).get("variants", {}).values() for p in v["passes"].values()]
    if any(s == "failed" for s in lab_statuses):
        status = "failing_live"
    elif any(s == "passed" for s in lab_statuses):
        # Skipped variants (a documented infeasible half) are listed in the
        # lab block; they never turn into passes.
        status = "verified_live"
    elif lab_statuses and not any(k != "lab" for k in kinds):
        status = "skipped_live"
    elif any(k in ("integration_test", "unit_test", "native_e2e", "renderer_test") for k in kinds):
        status = "verified_test"
    elif ov:
        status = ov["status"]
    else:
        status = "not_covered"
    if ov and status in ("not_covered", "skipped_live"):
        status = ov["status"]
    return {
        "id": cid,
        "category": case.get("category"),
        "title": case.get("title"),
        "status": status,
        "evidence_kinds": kinds,
        "references": refs[:12],
        "lab": labres,
        "note": (ov or {}).get("reason"),
    }


LABELS = {
    "verified_live": "✅ live (real gateway)",
    "verified_test": "✅ automated test",
    "failing_live": "❌ failing (live)",
    "skipped_live": "⏭ skipped (live) — see reason",
    "blocked": "⛔ blocked — see reason",
    "not_applicable": "➖ not applicable — see reason",
    "partial": "◐ partial — see reason",
    "not_covered": "⚠ not covered",
}


def main():
    allow_gaps = "--allow-gaps" in sys.argv
    matrix = json.load(open(MATRIX))
    cases = matrix["cases"]
    overrides = {}
    if os.path.exists(STATUS):
        overrides = {k: v for k, v in json.load(open(STATUS)).items() if not k.startswith("_")}
    refs = scan(cases)
    lab = latest_lab_results()
    rows = [classify(c, refs[c["id"]], lab, overrides) for c in cases]
    os.makedirs(OUT_DIR, exist_ok=True)
    totals = {}
    for r in rows:
        totals[r["status"]] = totals.get(r["status"], 0) + 1
    json.dump({"source": os.path.relpath(MATRIX, ROOT), "total": len(rows), "totals": totals, "cases": rows},
              open(os.path.join(OUT_DIR, "matrix-coverage.json"), "w"), indent=1)
    md = ["# Failure-matrix coverage", "",
          "Generated by `scripts/matrix-coverage.py` from test/lab references and the newest lab results.",
          "A skip or block is never counted as a pass.", "",
          "| Status | Cases |", "|---|---|"]
    for k in LABELS:
        if totals.get(k):
            md.append(f"| {LABELS[k]} | {totals[k]} |")
    md.append(f"| **Total** | **{len(rows)}** |")
    cat = None
    for r in rows:
        if r["category"] != cat:
            cat = r["category"]
            md += ["", f"## {cat}", "", "| ID | Scenario | Status | Evidence |", "|---|---|---|---|"]
        ev = ", ".join(sorted({f"`{x['path']}`" for x in r["references"]})[:3]) or "—"
        if r["lab"]:
            variants = r["lab"]["variants"].values()
            passed = sorted({v["scenario"] for v in variants if any(p["status"] == "passed" for p in v["passes"].values())})
            skipped = sorted({v["scenario"] for v in variants if any(p["status"] == "skipped" for p in v["passes"].values())})
            lab_ev = "lab " + ", ".join(f"`{x}`" for x in r["lab"]["runs"])
            if passed:
                lab_ev += f" — passed {', '.join(passed)}"
            if skipped:
                lab_ev += f" — skipped {', '.join(skipped)}"
            ev = lab_ev if ev == "—" else f"{lab_ev}; {ev}"
        note = f" — {r['note']}" if r["note"] else ""
        md.append(f"| {r['id']} | {r['title']} | {LABELS.get(r['status'], r['status'])}{note} | {ev} |")
    open(os.path.join(OUT_DIR, "matrix-coverage.md"), "w").write("\n".join(md) + "\n")
    print(json.dumps(totals, indent=1))
    gaps = [r["id"] for r in rows if r["status"] == "not_covered"]
    failing = [r["id"] for r in rows if r["status"] == "failing_live"]
    if failing:
        print("failing live:", " ".join(failing))
    if gaps:
        print("not covered:", " ".join(gaps))
    if (gaps and not allow_gaps) or failing:
        sys.exit(1)


if __name__ == "__main__":
    main()
