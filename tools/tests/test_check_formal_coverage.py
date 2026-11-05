from __future__ import annotations

import hashlib
import contextlib
import io
import json
import sys
import tempfile
import unittest
import unittest.mock as mock
from collections import Counter
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

    def test_reachability_ignores_quoted_and_raw_string_imports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root, formal = Path(td), Path(td) / "rubin-formal"
            lean_root = formal / "RubinFormal"
            lean_root.mkdir(parents=True)
            (lean_root / "Live.lean").touch()
            (formal / "RubinFormal.lean").write_text(
                'def o := "import RubinFormal.HiddenOrdinary"\n'
                'def r := r"import RubinFormal.HiddenRaw"\n'
                'def h := r###"\nimport RubinFormal.HiddenHashed\n"###\n'
                'import RubinFormal.Live\n',
                encoding="utf-8",
            )
            hidden = [f"RubinFormal/{name}.lean" for name in ("HiddenOrdinary", "HiddenRaw", "HiddenHashed")]
            doc = {"source_rebind": {"drop_retired_source_paths": [*hidden, "RubinFormal/Live.lean"]}}
            errors = m.validate_retired_source_paths(root, doc)

        self.assertEqual([e for e in errors if "reachable from" in e], ["retired source path remains reachable from RubinFormal.lean: RubinFormal/Live.lean"])


class FormalRiskMaturityTests(unittest.TestCase):
    def test_only_phase0_and_devnet_pass_pending_maturity(self) -> None:
        summary = RiskSummary("refinement", "refined", "experimental_pending_reverification", 31, 28, 3, 0, 0, 0, "LOW", [], [], [])
        self.assertTrue(check_profile("phase0", summary)[0])
        self.assertTrue(check_profile("devnet", summary)[0])
        self.assertFalse(check_profile("audit", summary)[0])
        self.assertFalse(check_profile("freeze", summary)[0])


class SourceRebindTests(unittest.TestCase):
    @staticmethod
    def active_manifest_doc() -> dict:
        coverage = json.loads(
            (TOOLS_DIR.parent / "rubin-formal" / "proof_coverage.json").read_text(
                encoding="utf-8"
            )
        )
        return {"source_rebind": coverage["source_rebind"]}

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
        root = TOOLS_DIR.parent
        doc = self.active_manifest_doc()
        self.assertEqual(m.validate_active_path_manifest(root, doc), [])
        for path, expected_disposition, wrong_disposition in (
            ("RubinFormal/BlockHeaderRoundtrip.lean", "BYTE_EXACT", "RECONCILE_CURRENT_PROTOCOL"),
            ("RubinFormal/LegacySunset.lean", "RECONCILE_CURRENT_PROTOCOL", "BYTE_EXACT"),
            ("tests/test_covenant_registry_disposition.py", "IMPORT_PACKAGE_CHECK_OR_TEST", "BYTE_EXACT"),
        ):
            with self.subTest(path=path):
                doc = self.active_manifest_doc()
                doc["source_rebind"]["active_path_manifest"][path]["disposition"] = wrong_disposition
                self.assertIn(
                    f"source_rebind.active_path_manifest[{path}].disposition drift: "
                    f"expected {expected_disposition!r}, "
                    f"got {wrong_disposition!r}",
                    m.validate_active_path_manifest(root, doc),
                )
        path = "RubinFormal/BlockHeaderRoundtrip.lean"
        doc = self.active_manifest_doc()
        doc["source_rebind"]["active_path_manifest"][path]["candidate_sha256"] = "0" * 64
        self.assertTrue(any("candidate hash drift" in error for error in m.validate_active_path_manifest(root, doc)))

    def test_active_manifest_rejects_simultaneous_source_and_candidate_hash_tampering(self) -> None:
        doc = self.active_manifest_doc()
        record = doc["source_rebind"]["active_path_manifest"]["RubinFormal/BlockHeaderRoundtrip.lean"]
        tampered_hash = hashlib.sha256(b"tampered-source-record").hexdigest()
        record["source_sha256"] = tampered_hash
        record["candidate_sha256"] = tampered_hash

        errors = m.validate_active_path_manifest(TOOLS_DIR.parent, doc)

        self.assertTrue(any("source digest drift" in error for error in errors))

    def test_rejects_partition_arithmetic_drift(self) -> None:
        doc = source_rebind_doc()
        doc["source_rebind"]["byte_exact_path_count"] = 78

        errors = m.validate_source_rebind(doc)

        self.assertTrue(any("byte_exact_path_count drift" in error for error in errors))
        self.assertTrue(any("active partition drift" in error for error in errors))

    def test_claim_boundary_evidence_requires_non_empty_limitations(self) -> None:
        for limitations in (None, [], "not-a-list", [""], [1]):
            self.assertIsNotNone(
                m.claim_boundary_limitations_error(
                    "covenant_registry", "machine_checked_model", limitations
                )
            )
        self.assertIsNone(
            m.claim_boundary_limitations_error(
                "covenant_registry", "machine_checked_model", ["bounded model only"]
            )
        )
        self.assertIsNone(
            m.claim_boundary_limitations_error(
                "fork_choice", "machine_checked_universal", None
            )
        )

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


class StateModelRegistrationTests(unittest.TestCase):
    def test_public_entrypoint_accepts_model_and_retains_independent_refusals(self) -> None:
        original = json.loads((TOOLS_DIR.parent / "rubin-formal" / "proof_coverage.json").read_text())

        def check(doc: dict) -> tuple[int, str]:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "tools").mkdir()
                (root / "conformance").symlink_to(TOOLS_DIR.parent / "conformance", target_is_directory=True)
                formal = root / "rubin-formal"
                formal.mkdir()
                for path in (TOOLS_DIR.parent / "rubin-formal").iterdir():
                    if path.name != "proof_coverage.json":
                        (formal / path.name).symlink_to(path, target_is_directory=path.is_dir())
                (formal / "proof_coverage.json").write_text(json.dumps(doc), encoding="utf-8")
                stderr = io.StringIO()
                with mock.patch.object(m, "__file__", str(root / "tools" / "check_formal_coverage.py")), contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                    result = m.main()
                return result, stderr.getvalue()

        self.assertEqual(check(original), (0, ""))
        for key, defect in (
            (key, defect)
            for key, defects in (
                ("canonical_utxo_state_model", ("unknown", "duplicate", "missing", "evidence", "theorem", "summary", "candidate_hash", "source_hash")),
                ("compact_size", ("unknown", "duplicate", "missing", "evidence", "theorem")),
                ("primitive_encodings", ("unknown", "duplicate", "missing", "evidence", "theorem")),
                ("deterministic_parse_error_mapping", ("unknown", "duplicate", "missing", "evidence", "theorem")),
            )
            for defect in defects
        ):
            with self.subTest(key=key, defect=defect):
                doc = json.loads(json.dumps(original))
                rows = doc["coverage"]
                row = next(r for r in rows if r["section_key"] == key)
                if defect == "unknown":
                    row["section_key"] = "unrelated_state_model"
                    expected = (f"ERROR: unknown section_key in coverage[{rows.index(row)}]: unrelated_state_model\n"
                                f"ERROR: missing section keys in proof coverage:\n  - {key}\n")
                elif defect == "duplicate":
                    rows.append(json.loads(json.dumps(row)))
                    expected = f"ERROR: duplicate section_key in coverage: {key}\n"
                elif defect == "missing":
                    rows.remove(row)
                    expected = f"ERROR: missing section keys in proof coverage:\n  - {key}\n"
                elif defect == "evidence":
                    row["evidence_level"] = "machine_checked_universal"
                    expected = f"ERROR: evidence_level drift for {key}: expected machine_checked_model, got machine_checked_universal\n"
                elif defect == "theorem":
                    theorem = row["theorems"][0]
                    absent = "RubinFormal.StateConsensusV1.absent_contract"
                    row["theorems"][0] = absent
                    row["theorem_files"][absent] = row["theorem_files"].pop(theorem)
                    expected = f"ERROR: {key} references missing Lean theorem declaration: RubinFormal.StateConsensusV1.absent_contract\n"
                elif defect == "summary":
                    doc["coverage_summary"]["section_rows"] = 34
                    expected = "ERROR: coverage_summary.section_rows drift: expected 35, got 34\n"
                else:
                    path = "tools/check_formal_registry_truth.py"
                    record = doc["source_rebind"]["active_path_manifest"][path]
                    record["candidate_sha256" if defect == "candidate_hash" else "source_sha256"] = "0" * 64
                    expected = (f"ERROR: source_rebind.active_path_manifest candidate hash drift: {path}\n"
                                if defect == "candidate_hash" else "ERROR: source_rebind.active_path_manifest source digest drift\n")
                if defect in {"duplicate", "missing", "theorem"}:
                    # Keep the unrelated summary valid so the intended refusal is reached.
                    refs = Counter(t for r in rows for t in r["theorems"])
                    statuses = Counter(r["status"] for r in rows)
                    doc["coverage_summary"].update(
                        section_rows=len(rows), theorem_references=sum(refs.values()),
                        unique_theorem_names=len(refs), reused_theorem_names=sorted(t for t, n in refs.items() if n > 1),
                        **{f"{status}_rows": statuses[status] for status in ("proved", "proved_with_axiom", "stated", "deferred")},
                    )
                result, stderr = check(doc)
                self.assertEqual(result, 1)
                self.assertEqual(stderr, expected)


if __name__ == "__main__":
    unittest.main()
