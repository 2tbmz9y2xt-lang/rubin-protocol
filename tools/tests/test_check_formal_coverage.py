from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_formal_coverage as m  # noqa: E402


def source_rebind_doc() -> dict:
    source_rebind = dict(m.EXPECTED_SOURCE_REBIND_SCALARS)
    for key, paths in m.EXPECTED_SOURCE_REBIND_PATHS.items():
        source_rebind[key] = sorted(paths)
    return {"source_rebind": source_rebind}


class SourceRebindTests(unittest.TestCase):
    def test_accepts_exact_manifest(self) -> None:
        self.assertEqual(m.validate_source_rebind(source_rebind_doc()), [])

    def test_rejects_path_set_and_count_drift(self) -> None:
        doc = source_rebind_doc()
        doc["source_rebind"]["reconcile_current_protocol_paths"].pop()

        errors = m.validate_source_rebind(doc)

        self.assertTrue(any("reconcile_current_protocol_paths set drift" in error for error in errors))
        self.assertTrue(any("reconcile_current_protocol_path_count does not match" in error for error in errors))

    def test_rejects_partition_arithmetic_drift(self) -> None:
        doc = source_rebind_doc()
        doc["source_rebind"]["byte_exact_path_count"] = 78

        errors = m.validate_source_rebind(doc)

        self.assertTrue(any("byte_exact_path_count drift" in error for error in errors))
        self.assertTrue(any("active partition drift" in error for error in errors))


class FormalCoverageSummaryTests(unittest.TestCase):
    def test_summary_accepts_exact_counts(self) -> None:
        rows = [
            {"status": "proved", "theorems": ["A", "B"]},
            {"status": "stated", "theorems": ["A"]},
            {"status": "deferred", "theorems": []},
        ]
        coverage = {
            "coverage_summary": {
                "section_rows": 3,
                "proved_rows": 1,
                "stated_rows": 1,
                "deferred_rows": 1,
                "theorem_references": 3,
                "unique_theorem_names": 2,
                "reused_theorem_names": ["A"],
                "counting_rule": "unique_theorem_names is deduplicated",
            }
        }

        self.assertEqual(m.validate_coverage_summary(coverage, rows), [])

    def test_summary_rejects_drift(self) -> None:
        rows = [{"status": "proved", "theorems": ["A", "A"]}]
        coverage = {
            "coverage_summary": {
                "section_rows": 1,
                "proved_rows": 1,
                "stated_rows": 0,
                "deferred_rows": 0,
                "theorem_references": 1,
                "unique_theorem_names": 1,
                "reused_theorem_names": [],
                "counting_rule": "unique_theorem_names is deduplicated",
            }
        }

        errors = m.validate_coverage_summary(coverage, rows)

        self.assertIn("coverage_summary.theorem_references drift: expected 2, got 1", errors)
        self.assertIn("coverage_summary.reused_theorem_names drift: expected ['A'], got []", errors)

    def test_summary_rejects_non_object_rows_without_traceback(self) -> None:
        coverage = {"coverage_summary": {}}

        self.assertEqual(m.validate_coverage_summary(coverage, ["bad"]), ["coverage_summary cannot inspect non-object coverage[0]"])

    def test_declared_lean_theorems_collects_theorem_declarations_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "Example.lean"
            source.write_text(
                (
                    "namespace RubinFormal.Example\n"
                    "theorem present_theorem : True := by trivial\n"
                    "def helper_definition : Nat := 1\n"
                    "end RubinFormal.Example\n"
                ),
                encoding="utf-8",
            )

            names = m.declared_lean_theorems(root)

        self.assertIn("RubinFormal.Example.present_theorem", names)
        self.assertNotIn("present_theorem", names)
        self.assertNotIn("helper_definition", names)


if __name__ == "__main__":
    unittest.main()
