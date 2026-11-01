"""Tests of scripts/matrix-coverage.py's classifier (`classify`): reasoned
statuses in docs/verification/matrix-status.json against discovered
evidence. Covers the `pinned` cap (a pinned case is never promoted by
discovered tests or lab passes; a failing lab result still shows) and the
`requires` gate (only a test definition of a required kind promotes).
Standard library only; the classifier is loaded from its file.

    python3 -I scripts/tests/test_matrix_coverage.py
"""

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("matrix_coverage", ROOT / "scripts" / "matrix-coverage.py")
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)

CASE = {"id": "REL-001", "category": "Installer, updater and website release", "title": "Clean native installs"}


def ref(kind, definition=True):
    r = {"path": "crates/x/tests/t.rs", "line": 1, "kind": kind}
    if definition:
        r["_definition"] = True
    return r


def lab(status):
    return {"REL-001": {"runs": ["results/lab/x"], "variants": {"core:REL-001": {"profile": "core", "scenario": "REL-001", "passes": {"trusted": {"status": status, "skip_reason": None}}}}}}


class ClassifyTest(unittest.TestCase):
    def status(self, override, refs=(), labres=None):
        return mc.classify(CASE, list(refs), labres or {}, {"REL-001": override} if override else {})["status"]

    def test_a_pinned_status_is_not_promoted_by_a_discovered_test(self):
        pinned = {"status": "partial", "pinned": True, "reason": "r"}
        self.assertEqual(self.status(pinned, [ref("integration_test")]), "partial")
        self.assertEqual(self.status(pinned, [ref("native_e2e")]), "partial")

    def test_the_same_status_unpinned_is_promoted(self):
        self.assertEqual(self.status({"status": "partial", "reason": "r"}, [ref("integration_test")]), "verified_test")

    def test_a_pinned_status_is_not_promoted_by_a_lab_pass(self):
        self.assertEqual(self.status({"status": "partial", "pinned": True, "reason": "r"}, labres=lab("passed")), "partial")

    def test_a_failing_lab_result_still_shows_on_a_pinned_case(self):
        self.assertEqual(self.status({"status": "partial", "pinned": True, "reason": "r"}, labres=lab("failed")), "failing_live")

    def test_pinned_references_are_still_listed(self):
        out = mc.classify(CASE, [ref("integration_test")], {}, {"REL-001": {"status": "partial", "pinned": True, "reason": "r"}})
        self.assertEqual(out["evidence_kinds"], ["integration_test"])
        self.assertEqual(len(out["references"]), 1)
        self.assertNotIn("_definition", out["references"][0])

    def test_requires_promotes_only_on_a_definition_of_a_required_kind(self):
        gated = {"status": "partial", "requires": ["native_e2e"], "reason": "r"}
        self.assertEqual(self.status(gated, [ref("integration_test")]), "partial")
        self.assertEqual(self.status(gated, [ref("native_e2e", definition=False)]), "partial")
        self.assertEqual(self.status(gated, [ref("native_e2e")]), "verified_test")

    def test_no_evidence_keeps_the_reasoned_status(self):
        self.assertEqual(self.status({"status": "blocked", "reason": "r"}), "blocked")
        self.assertEqual(self.status(None), "not_covered")


class StatusFileTest(unittest.TestCase):
    def test_rel_001_is_pinned_partial(self):
        # Its evidence is the hosted release smoke, outside the scanned paths.
        rel = json.loads((ROOT / "docs" / "verification" / "matrix-status.json").read_text())["REL-001"]
        self.assertEqual(rel["status"], "partial")
        self.assertIs(rel.get("pinned"), True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
