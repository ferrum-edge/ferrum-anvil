"""Tests of scripts/release-smoke/record.py, the clean-install release smoke's
(REL-001) recorder: step recording, per-target failure classification
(`finalize`) and the merged summary (`summarize`), run the way the workflow
runs them (a subprocess, `python3 -I`). Standard library only.

    python3 -I scripts/tests/test_release_smoke_record.py
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

RECORD = Path(__file__).resolve().parents[1] / "release-smoke" / "record.py"
REQUIRED = [
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


def rec(*args, check=True):
    p = subprocess.run([sys.executable, "-I", str(RECORD), *map(str, args)], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise AssertionError(f"record.py {args[0]} exited {p.returncode}: {p.stderr}")
    return p


class RecorderTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.out = self.tmp / "rel001-result"

    def tearDown(self):
        self._tmp.cleanup()

    def step(self, name, result, cls=None, out=None):
        args = ["step", "--dir", out or self.out, "--name", name, "--result", result, "--detail", f"{name} {result}"]
        if cls:
            args += ["--failure-class", cls]
        rec(*args)

    def finalize(self, target="t", out=None, result_path=None):
        out = out or self.out
        result_path = result_path or (out / "result.json")
        p = rec("finalize", "--dir", out, "--target", target, "--out", result_path, check=False)
        return p.returncode, json.loads(Path(result_path).read_text())

    # --- step -----------------------------------------------------------------

    def test_a_failed_step_needs_a_class_and_a_passing_one_takes_none(self):
        p = rec("step", "--dir", self.out, "--name", "install", "--result", "fail", "--detail", "x", check=False)
        self.assertNotEqual(p.returncode, 0)
        p = rec("step", "--dir", self.out, "--name", "install", "--result", "pass", "--detail", "x", "--failure-class", "package", check=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.out / "steps.jsonl").exists())

    # --- finalize -------------------------------------------------------------

    def test_every_required_step_passed_is_a_pass(self):
        for s in REQUIRED:
            self.step(s, "pass")
        code, r = self.finalize()
        self.assertEqual(code, 0)
        self.assertEqual(r["result"], "pass")
        self.assertIsNone(r["failure_class"])
        self.assertEqual(r["missing_required_steps"], [])

    def test_a_package_failure_outranks_a_harness_failure(self):
        self.step("asset_integrity", "pass")
        self.step("install", "fail", "harness")
        self.step("launch_first_run", "fail", "package")
        code, r = self.finalize()
        self.assertEqual(code, 1)
        self.assertEqual(r["failure_class"], "package")
        self.assertEqual(r["failed_steps"], ["install", "launch_first_run"])

    def test_only_harness_failures_are_harness(self):
        self.step("asset_integrity", "pass")
        self.step("install", "fail", "harness")
        _, r = self.finalize()
        self.assertEqual(r["failure_class"], "harness")

    def test_a_recorded_unclassified_failure_stays_unclassified(self):
        self.step("install", "fail", "unclassified")
        _, r = self.finalize()
        self.assertEqual(r["failure_class"], "unclassified")

    def test_steps_missing_without_a_failure_are_unclassified(self):
        # The job was killed or timed out after some steps passed.
        for s in REQUIRED[:4]:
            self.step(s, "pass")
        code, r = self.finalize()
        self.assertEqual(code, 1)
        self.assertEqual(r["result"], "fail")
        self.assertEqual(r["failure_class"], "unclassified")
        self.assertEqual(r["missing_required_steps"], REQUIRED[4:])

    def test_finalize_writes_a_result_when_the_script_never_created_its_directory(self):
        # The job stopped before the script ran (e.g. the artifact download).
        out = self.tmp / "never-created"
        result = self.tmp / "also-missing" / "result.json"
        code, r = self.finalize(out=out, result_path=result)
        self.assertEqual(code, 1)
        self.assertTrue(result.is_file())
        self.assertEqual(r["failure_class"], "unclassified")
        self.assertEqual(r["missing_required_steps"], REQUIRED)

    # --- statuses -------------------------------------------------------------

    def test_statuses_exit_3_only_for_a_missing_or_invalid_execution_record(self):
        bad = self.tmp / "send.json"
        bad.write_text("not json")
        self.assertEqual(rec("statuses", bad, check=False).returncode, 3)
        self.assertEqual(rec("statuses", self.tmp / "absent.json", check=False).returncode, 3)
        empty = self.tmp / "empty.json"
        empty.write_text('{"response": {}}')
        p = rec("statuses", empty, check=False)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, ""))
        ok = self.tmp / "ok.json"
        ok.write_text('{"response": {"status": 200}}')
        self.assertEqual(rec("statuses", ok).stdout.strip(), "200")


class SummaryTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.results = self.tmp / "rel001-results"
        self.results.mkdir()
        self.env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}

    def tearDown(self):
        self._tmp.cleanup()

    def result(self, target, result, cls=None):
        d = self.results / f"rel001-result-{target}"
        d.mkdir()
        (d / "result.json").write_text(json.dumps({"target": target, "result": result, "failure_class": cls, "asset": {"name": target, "sha256": "0" * 64}, "runner": {}}))

    def fetch(self, doc):
        p = self.tmp / "fetch.json"
        p.write_text(json.dumps(doc))
        return p

    def summarize(self, expect, fetch=None, fetch_job="success"):
        args = [sys.executable, "-I", str(RECORD), "summarize", "--input", str(self.results), "--out", str(self.tmp / "summary.json"),
                "--fetch-job-result", fetch_job]
        if fetch:
            args += ["--fetch", str(fetch)]
        args += ["--expect", *expect]
        p = subprocess.run(args, capture_output=True, text=True, env=self.env)
        return p.returncode, json.loads((self.tmp / "summary.json").read_text())

    def test_package_and_harness_failures_are_listed_apart(self):
        self.result("a", "pass")
        self.result("b", "fail", "package")
        self.result("c", "fail", "harness")
        code, s = self.summarize(["a", "b", "c", "d"], self.fetch({"failure_class": None, "package_failures": [], "assets": []}))
        self.assertEqual(code, 1)
        self.assertEqual(s["package_failures"], ["b"])
        # A target with no result (e.g. its checkout failed) is never a package failure.
        self.assertEqual(s["harness_or_unclassified_failures"], ["c", "d"])

    def test_a_fetch_package_problem_is_a_package_failure(self):
        self.result("a", "fail", "package")
        _, s = self.summarize(["a"], self.fetch({"failure_class": "package", "package_failures": ["x.dmg"], "assets": []}))
        self.assertEqual(s["package_failures"], ["fetch:x.dmg", "a"])
        self.assertEqual(s["fetch"]["failure_class"], "package")

    def test_a_fetch_job_that_failed_without_a_result_is_harness(self):
        code, s = self.summarize(["a", "b"], fetch=None, fetch_job="failure")
        self.assertEqual(code, 1)
        self.assertEqual(s["fetch"]["failure_class"], "harness")
        self.assertEqual(s["package_failures"], [])
        self.assertEqual(s["harness_or_unclassified_failures"], ["fetch", "a", "b"])

    def test_a_fetch_job_that_failed_after_a_clean_asset_check_is_harness(self):
        code, s = self.summarize(["a"], self.fetch({"failure_class": None, "package_failures": [], "assets": []}), fetch_job="failure")
        self.assertEqual(code, 1)
        self.assertEqual(s["fetch"]["failure_class"], "harness")
        self.assertEqual(s["package_failures"], [])

    def test_all_passing_with_a_clean_fetch_is_a_pass(self):
        self.result("a", "pass")
        code, s = self.summarize(["a"], self.fetch({"failure_class": None, "package_failures": [], "assets": []}))
        self.assertEqual((code, s["result"]), (0, "pass"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
