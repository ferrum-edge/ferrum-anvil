#!/usr/bin/env python3
"""Result recorder for the clean-install release smoke (REL-001).

Used by .github/workflows/release-smoke.yml through smoke-unix.sh and
smoke-windows.ps1. Each target keeps its record in one directory:

  steps.jsonl     one line per step: name, result (pass/fail/info), detail
                  and, for a failure, its class (see FAILURE_CLASSES)
  bypasses.jsonl  every OS protection that was not exercised or was overridden
  meta.json       asset, runner, surfaces and other facts about the run

`finalize` turns that directory into result.json; `summarize` merges the
result.json files of every target. Standard library only; run with `-I`.
"""

import argparse
import datetime
import hashlib
import json
import os
import sys

SCHEMA = "anvil.release-smoke.v1"

# Why a step failed. Only a `package` failure says something about the
# shipped asset; a `harness` failure (runner setup, test tools, package
# mirrors, artifact fetch) says nothing about it and is re-run first. The
# full command-by-command mapping is in docs/release.md. `unclassified` is
# recorded only by the scripts' safety nets for an error no mapping
# anticipated (with the step, line and command), or by `finalize` when a job
# stopped before its script recorded anything; it is handled like a harness
# failure until a person has read the log.
FAILURE_CLASSES = {
    "package": "the shipped asset failed its checksum, install, launch, import or local call",
    "harness": "runner setup, a test tool, a package mirror or the artifact fetch failed; says nothing about the asset",
    "unclassified": "an error no mapping anticipated, or a job that stopped before recording; read the log",
}

# A target passes only if every one of these steps ran and passed.
REQUIRED_STEPS = [
    "asset_integrity",
    "native_arch",
    "install",
    "cli_ready",
    "launch_first_run",
    "profile_create",
    "example_import",
    "local_call",
    "launch_with_example",
]


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def read_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def set_path(obj, dotted, value):
    keys = dotted.split(".")
    for k in keys[:-1]:
        obj = obj.setdefault(k, {})
    obj[keys[-1]] = value


def cmd_step(a):
    os.makedirs(a.dir, exist_ok=True)
    if (a.result == "fail") != (a.failure_class is not None):
        sys.exit("step: --failure-class is required for a failed step and only for one")
    entry = {"name": a.name, "result": a.result, "detail": a.detail, "at": now()}
    if a.failure_class:
        entry["failure_class"] = a.failure_class
    append(os.path.join(a.dir, "steps.jsonl"), entry)
    print(f"[{a.result}{'/' + a.failure_class if a.failure_class else ''}] {a.name}: {a.detail}")


def cmd_bypass(a):
    os.makedirs(a.dir, exist_ok=True)
    append(os.path.join(a.dir, "bypasses.jsonl"), {"protection": a.protection, "what": a.what})
    print(f"[bypass] {a.protection}: {a.what}")


def cmd_meta(a):
    os.makedirs(a.dir, exist_ok=True)
    path = os.path.join(a.dir, "meta.json")
    meta = read_json(path, {})
    for kv in a.pairs:
        key, sep, value = kv.partition("=")
        if not sep:
            sys.exit(f"meta: expected key=value, got {kv!r}")
        if a.json:
            value = json.loads(value)
        set_path(meta, key, value)
    write_json(path, meta)


def cmd_sha256(a):
    h = hashlib.sha256()
    with open(a.file, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    print(h.hexdigest())


def cmd_sums(a):
    """Print the SHA256SUMS digest recorded for one file name (exit 1 if none)."""
    with open(a.sums, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == a.name:
                print(parts[0].lower())
                return
    sys.exit(1)


def statuses(obj, out):
    """Integer values of keys named like an HTTP status anywhere in obj."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, int) and not isinstance(v, bool) and k.lower() in ("status", "status_code", "http_status"):
                out.append(v)
            else:
                statuses(v, out)
    elif isinstance(obj, list):
        for v in obj:
            statuses(v, out)
    return out


def cmd_statuses(a):
    with open(a.file, encoding="utf-8-sig") as f:
        print(" ".join(str(s) for s in statuses(json.load(f), [])))


def cmd_requests(a):
    """Count requests the local server logged for a method and path."""
    n = 0
    for r in read_lines(a.log):
        if r.get("method") == a.method and r.get("path") == a.path:
            n += 1
    print(n)


def cmd_finalize(a):
    steps = read_lines(os.path.join(a.dir, "steps.jsonl"))
    meta = read_json(os.path.join(a.dir, "meta.json"), {})
    bypasses = read_lines(os.path.join(a.dir, "bypasses.jsonl"))
    by_name = {}
    for s in steps:
        by_name.setdefault(s["name"], []).append(s["result"])
    missing = [n for n in REQUIRED_STEPS if n not in by_name]
    failed = sorted({s["name"] for s in steps if s["result"] == "fail"})
    not_passed = [n for n in REQUIRED_STEPS if n in by_name and "pass" not in by_name[n]]
    result = "pass" if not missing and not failed and not not_passed else "fail"
    classes = {s.get("failure_class") for s in steps if s["result"] == "fail"}
    if result == "pass":
        failure_class = None
    elif "package" in classes:
        failure_class = "package"
    elif "harness" in classes:
        failure_class = "harness"
    else:
        failure_class = "unclassified"  # recorded as such, or no failure recorded at all
    env = os.environ
    doc = {
        "schema": SCHEMA,
        "case": "REL-001",
        "target": a.target,
        "result": result,
        "failure_class": failure_class,
        "failure_classes": FAILURE_CLASSES,
        "missing_required_steps": missing,
        "failed_steps": failed,
        "required_steps": REQUIRED_STEPS,
        **meta,
        "bypasses": bypasses,
        "steps": steps,
        "workflow_run": {
            "repository": env.get("GITHUB_REPOSITORY"),
            "workflow": env.get("GITHUB_WORKFLOW"),
            "event": env.get("GITHUB_EVENT_NAME"),
            "run_id": env.get("GITHUB_RUN_ID"),
            "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
            "job": env.get("GITHUB_JOB"),
            "workflow_sha": env.get("GITHUB_SHA"),
            "url": f"{env.get('GITHUB_SERVER_URL')}/{env.get('GITHUB_REPOSITORY')}/actions/runs/{env.get('GITHUB_RUN_ID')}",
        },
        "finalized_at": now(),
    }
    write_json(a.out, doc)
    print(f"{a.target}: {result}" + (f" [{failure_class}]" if failure_class else "") + (f" (missing: {', '.join(missing)})" if missing else "") + (f" (failed: {', '.join(failed)})" if failed else ""))
    if result != "pass":
        sys.exit(1)


def cmd_fetch_asset(a):
    """Print the fetch job's status and detail for one asset, tab-separated
    (`missing` when fetch.json does not name it)."""
    for e in read_json(a.fetch, {}).get("assets", []):
        if e.get("name") == a.name:
            print(f"{e.get('status')}\t{e.get('detail')}")
            return
    print("missing\tthe fetch result does not name this asset")


def cmd_summarize(a):
    fetch = read_json(a.fetch, None) if a.fetch else None
    fetch_ok = a.fetch_job_result in (None, "success")
    if fetch is None and not fetch_ok:
        # The fetch job stopped before writing its result (for example while
        # resolving the release): nothing about the assets is known.
        fetch = {"failure_class": "harness", "harness_error": f"the fetch job ended '{a.fetch_job_result}' without a result", "package_failures": []}
    if fetch is not None and not fetch_ok and not fetch.get("failure_class"):
        # The asset check passed, then a later fetch step failed (the example
        # bundle from the repository, or the upload): not a shipped asset.
        fetch = {**fetch, "failure_class": "harness", "harness_error": f"the fetch job ended '{a.fetch_job_result}' after its asset check passed"}
    fetch_class = (fetch or {}).get("failure_class")
    results = []
    for root, _dirs, files in os.walk(a.input):
        if "result.json" in files:
            results.append(read_json(os.path.join(root, "result.json"), {}))
    results.sort(key=lambda r: r.get("target", ""))
    seen = {r.get("target") for r in results}
    absent = [t for t in a.expect if t not in seen]
    overall = "pass" if fetch_ok and not fetch_class and results and not absent and all(r.get("result") == "pass" for r in results) else "fail"
    summary = {
        "schema": SCHEMA + ".summary",
        "case": "REL-001",
        "result": overall,
        "targets_expected": a.expect,
        "targets_without_result": absent,
        "fetch": {
            "job_result": a.fetch_job_result,
            "failure_class": fetch_class,
            "harness_error": (fetch or {}).get("harness_error"),
            "package_failures": (fetch or {}).get("package_failures", []),
            "assets": (fetch or {}).get("assets", []),
        },
        "package_failures": [f"fetch:{n}" for n in (fetch or {}).get("package_failures", [])]
        + [r.get("target") for r in results if r.get("failure_class") == "package"],
        "harness_or_unclassified_failures": (["fetch"] if fetch_class == "harness" else [])
        + [r.get("target") for r in results if r.get("failure_class") in ("harness", "unclassified")]
        + absent,
        "targets": [
            {
                "target": r.get("target"),
                "result": r.get("result"),
                "failure_class": r.get("failure_class"),
                "asset": (r.get("asset") or {}).get("name"),
                "sha256": (r.get("asset") or {}).get("sha256"),
                "runner": r.get("runner"),
                "failed_steps": r.get("failed_steps"),
                "missing_required_steps": r.get("missing_required_steps"),
            }
            for r in results
        ],
        "generated_at": now(),
    }
    write_json(a.out, summary)
    lines = [
        "## REL-001 clean-install smoke",
        "",
        f"Overall: **{overall}**" + (f" (no result from: {', '.join(absent)})" if absent else ""),
        "",
        "Fetch: "
        + (
            f"**harness** failure, no target ran: {summary['fetch']['harness_error']}"
            if fetch_class == "harness"
            else f"**package** problems with published assets: {', '.join(summary['fetch']['package_failures'])}"
            if fetch_class == "package"
            else "every asset matched SHA256SUMS"
            if fetch
            else "no result"
        ),
        "",
        "| Target | Result | Failure class | Asset | sha256 | Runner | Failed / missing steps |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for t in summary["targets"]:
        run = t.get("runner") or {}
        bad = ", ".join((t.get("failed_steps") or []) + (t.get("missing_required_steps") or [])) or "none"
        lines.append(
            f"| {t['target']} | {t['result']} | {t.get('failure_class') or '-'} | `{t['asset']}` | `{(t['sha256'] or '')[:16]}…` | {run.get('label')} ({run.get('os')} {run.get('machine')}) | {bad} |"
        )
    lines += [
        "",
        "A `package` failure concerns the shipped asset. A `harness` or `unclassified` failure says nothing about it:",
        "re-run the failed jobs first (docs/release.md, After publishing).",
    ]
    text = "\n".join(lines) + "\n"
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    if overall != "pass":
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("step")
    s.add_argument("--dir", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--result", required=True, choices=["pass", "fail", "info"])
    s.add_argument("--detail", required=True)
    s.add_argument("--failure-class", choices=sorted(FAILURE_CLASSES))
    s.set_defaults(fn=cmd_step)

    s = sub.add_parser("bypass")
    s.add_argument("--dir", required=True)
    s.add_argument("--protection", required=True)
    s.add_argument("--what", required=True)
    s.set_defaults(fn=cmd_bypass)

    s = sub.add_parser("meta")
    s.add_argument("--dir", required=True)
    s.add_argument("--json", action="store_true", help="values are JSON")
    s.add_argument("pairs", nargs="+", metavar="key.path=value")
    s.set_defaults(fn=cmd_meta)

    s = sub.add_parser("sha256")
    s.add_argument("file")
    s.set_defaults(fn=cmd_sha256)

    s = sub.add_parser("sums")
    s.add_argument("--sums", required=True)
    s.add_argument("--name", required=True)
    s.set_defaults(fn=cmd_sums)

    s = sub.add_parser("statuses")
    s.add_argument("file")
    s.set_defaults(fn=cmd_statuses)

    s = sub.add_parser("requests")
    s.add_argument("--log", required=True)
    s.add_argument("--method", required=True)
    s.add_argument("--path", required=True)
    s.set_defaults(fn=cmd_requests)

    s = sub.add_parser("fetch-asset")
    s.add_argument("--fetch", required=True)
    s.add_argument("--name", required=True)
    s.set_defaults(fn=cmd_fetch_asset)

    s = sub.add_parser("finalize")
    s.add_argument("--dir", required=True)
    s.add_argument("--target", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_finalize)

    s = sub.add_parser("summarize")
    s.add_argument("--input", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--expect", nargs="*", default=[])
    s.add_argument("--fetch", help="fetch.json written by fetch.sh")
    s.add_argument("--fetch-job-result", help="the fetch job's result (success, failure, ...)")
    s.set_defaults(fn=cmd_summarize)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
