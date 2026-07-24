from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_formal_coverage as m  # noqa: E402
import check_formal_refinement_bridge as bridge_checker  # noqa: E402
from check_formal_risk_gate import check_profile  # noqa: E402
from formal_risk_score import RiskSummary  # noqa: E402


def source_rebind_doc() -> dict:
    source_rebind = dict(m.EXPECTED_SOURCE_REBIND_SCALARS)
    for key, paths in m.EXPECTED_SOURCE_REBIND_PATHS.items():
        source_rebind[key] = sorted(paths)
    return {"source_rebind": source_rebind}


class ConformanceIndexImportTests(unittest.TestCase):
    def test_requires_canonical_import_line(self) -> None:
        expected = "import RubinFormal.Conformance.CVParseReplay"

        self.assertTrue(m.has_canonical_import(f"{expected}\n", expected))
        self.assertFalse(m.has_canonical_import(f"-- {expected}\n", expected))
        self.assertFalse(m.has_canonical_import(f"/- {expected} -/\n", expected))

    def test_string_comment_markers_preserve_following_import_and_theorem(self) -> None:
        expected = "import RubinFormal.Conformance.CVParseReplay"
        source = 'def marker := "-- /- not a comment -/"\n' + expected + "\nnamespace RubinFormal\ntheorem retained : True := by trivial\n"

        self.assertTrue(m.has_canonical_import(source, expected))
        self.assertEqual(m.declared_lean_theorems_in_text(source), {"RubinFormal.retained"})


class FormalRiskMaturityTests(unittest.TestCase):
    def test_only_phase0_and_devnet_pass_pending_maturity(self) -> None:
        summary = RiskSummary("refinement", "refined", "experimental_pending_reverification", 31, 28, 3, 0, 0, 0, "LOW", [], [], [])
        self.assertTrue(check_profile("phase0", summary)[0])
        self.assertTrue(check_profile("devnet", summary)[0])
        self.assertFalse(check_profile("audit", summary)[0])
        self.assertFalse(check_profile("freeze", summary)[0])


class SourceRebindTests(unittest.TestCase):
    @staticmethod
    def active_manifest_doc(root: Path) -> dict:
        manifest = {}
        for path, disposition in m.expected_active_source_dispositions().items():
            candidate = root / "rubin-formal" / path
            candidate.parent.mkdir(parents=True, exist_ok=True); candidate.write_text(path, encoding="utf-8")
            candidate_hash = hashlib.sha256(candidate.read_bytes()).hexdigest()
            manifest[path] = {"disposition": disposition, "source_sha256": candidate_hash if disposition == "BYTE_EXACT" else "0" * 64, "candidate_sha256": candidate_hash}
        return {"source_rebind": {"active_path_manifest": manifest}}

    def test_accepts_exact_manifest(self) -> None:
        self.assertEqual(m.validate_source_rebind(source_rebind_doc()), [])

    def test_rejects_path_set_and_count_drift(self) -> None:
        doc = source_rebind_doc()
        doc["source_rebind"]["reconcile_current_protocol_paths"].remove(
            "RubinFormal/ThresholdSpendSuiteGateBridge.lean"
        )

        errors = m.validate_source_rebind(doc)

        self.assertTrue(any("reconcile_current_protocol_paths set drift" in error for error in errors))
        self.assertTrue(any("reconcile_current_protocol_path_count does not match" in error for error in errors))

    def test_active_manifest_rejects_candidate_and_metadata_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); doc = self.active_manifest_doc(root)
            self.assertEqual(m.validate_active_path_manifest(root, doc), [])
            path = "RubinFormal/BlockHeaderRoundtrip.lean"
            (root / "rubin-formal" / path).write_text("one-byte-drift", encoding="utf-8")
            self.assertTrue(any("candidate hash drift" in error for error in m.validate_active_path_manifest(root, doc)))
            doc = self.active_manifest_doc(root)
            doc["source_rebind"]["active_path_manifest"][path]["disposition"] = "RECONCILE_CURRENT_PROTOCOL"
            self.assertTrue(any("disposition drift" in error for error in m.validate_active_path_manifest(root, doc)))
            doc = self.active_manifest_doc(root)
            doc["source_rebind"]["active_path_manifest"][path]["candidate_sha256"] = "0" * 64
            self.assertTrue(any("candidate hash drift" in error for error in m.validate_active_path_manifest(root, doc)))

    def test_rejects_partition_arithmetic_drift(self) -> None:
        doc = source_rebind_doc()
        doc["source_rebind"]["byte_exact_path_count"] = 78

        errors = m.validate_source_rebind(doc)

        self.assertTrue(any("byte_exact_path_count drift" in error for error in errors))
        self.assertTrue(any("active partition drift" in error for error in errors))

    def test_retired_paths_must_be_absent_and_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root, formal = Path(td), Path(td) / "rubin-formal"
            (formal / "RubinFormal").mkdir(parents=True)
            (formal / "RubinFormal.lean").write_text("import RubinFormal.Active\n", encoding="utf-8")
            (formal / "RubinFormal" / "Active.lean").write_text("", encoding="utf-8")
            doc = source_rebind_doc(); self.assertEqual(m.validate_retired_source_paths(root, doc), [])
            retired = "RubinFormal/CoreExtRefinement.lean"; (formal / retired).write_text("", encoding="utf-8")
            (formal / "RubinFormal.lean").write_text("import RubinFormal.CoreExtRefinement\n", encoding="utf-8")
            errors = m.validate_retired_source_paths(root, doc)
        self.assertTrue(all(any(token in error for error in errors) for token in ("candidate tree", "reachable")))

    def test_rejects_boolean_for_every_numeric_count(self) -> None:
        for key in sorted(m.SOURCE_REBIND_COUNT_KEYS):
            with self.subTest(key=key):
                doc = source_rebind_doc()
                doc["source_rebind"][key] = True

                errors = m.validate_source_rebind(doc)

                self.assertIn(
                    f"source_rebind.{key} must be an exact integer, got True",
                    errors,
                )

    def test_both_entrypoints_reject_boolean_count_positions(self) -> None:
        keys = (
            "import_adapt_single_owner_path_count",
            "transplant_check_logic_path_count",
            "drop_retired_source_path_count",
            "byte_exact_path_count",
        )
        entrypoints = (
            (m, "check_formal_coverage.py"),
            (bridge_checker, "check_formal_refinement_bridge.py"),
        )
        for module, filename in entrypoints:
            for key in keys:
                with self.subTest(entrypoint=filename, key=key):
                    with tempfile.TemporaryDirectory() as td:
                        root = Path(td)
                        (root / "tools").mkdir()
                        (root / "conformance" / "fixtures").mkdir(parents=True)
                        (root / "conformance" / "MATRIX.md").write_text(
                            "# matrix\n",
                            encoding="utf-8",
                        )
                        conformance = (
                            root / "rubin-formal" / "RubinFormal" / "Conformance"
                        )
                        conformance.mkdir(parents=True)
                        (conformance / "Index.lean").write_text(
                            "-- fixture\n",
                            encoding="utf-8",
                        )
                        doc = source_rebind_doc()
                        doc["source_rebind"][key] = True
                        payload = json.dumps(doc)
                        (root / "rubin-formal" / "proof_coverage.json").write_text(
                            payload,
                            encoding="utf-8",
                        )
                        (root / "rubin-formal" / "refinement_bridge.json").write_text(
                            payload,
                            encoding="utf-8",
                        )
                        stderr = io.StringIO()
                        fake_file = root / "tools" / filename
                        with (
                            mock.patch.object(module, "__file__", str(fake_file)),
                            mock.patch("sys.stderr", stderr),
                        ):
                            result = module.main()

                    self.assertEqual(result, 1)
                    self.assertIn(
                        f"source_rebind.{key} must be an exact integer",
                        stderr.getvalue(),
                    )


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
