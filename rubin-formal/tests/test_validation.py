"""Tests for validation functions in check_formal_registry_truth."""
from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_formal_registry_truth import (
    fail,
    theorem_lookup_error,
    validate_registered_paths,
    validate_shared_op_parity,
    validate_single_theorem_ref,
    validate_theorem_refs,
)


class FailTests(unittest.TestCase):
    def test_returns_1(self) -> None:
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            result = fail("test error")
            self.assertEqual(result, 1)
        finally:
            sys.stderr = old_stderr

    def test_prints_error_to_stderr(self) -> None:
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            fail("something broke")
            output = sys.stderr.getvalue()
            self.assertIn("ERROR:", output)
            self.assertIn("something broke", output)
        finally:
            sys.stderr = old_stderr


class TheoremLookupErrorTests(unittest.TestCase):
    def test_proof_coverage_with_path(self) -> None:
        msg = theorem_lookup_error("proof_coverage", "Foo.bar", "rubin-formal/RubinFormal/Foo.lean")
        self.assertIn("proof_coverage", msg)
        self.assertIn("Foo.bar", msg)
        self.assertIn("rubin-formal/RubinFormal/Foo.lean", msg)

    def test_proof_coverage_without_path(self) -> None:
        msg = theorem_lookup_error("proof_coverage", "Foo.bar", None)
        self.assertIn("Foo.bar", msg)
        self.assertIn("RubinFormal/", msg)

    def test_bridge_label_with_path(self) -> None:
        msg = theorem_lookup_error("refinement_bridge", "M.thm", "rubin-formal/RubinFormal/M.lean")
        self.assertIn("refinement_bridge", msg)
        self.assertIn("M.thm", msg)
        self.assertIn("rubin-formal/RubinFormal/M.lean", msg)

    def test_bridge_label_without_path(self) -> None:
        msg = theorem_lookup_error("refinement_bridge", "M.thm", None)
        self.assertIn("M.thm", msg)
        self.assertIn("RubinFormal/", msg)


class ValidateSingleTheoremRefTests(unittest.TestCase):
    def _make_lookups(
        self,
        in_file_results: dict[tuple[str, str], Optional[bool]],
        anywhere_results: dict[str, bool],
    ):
        def exists_in_file(theorem: str, path: str) -> Optional[bool]:
            return in_file_results.get((theorem, path))

        def exists_anywhere(theorem: str) -> bool:
            return anywhere_results.get(theorem, False)

        return exists_in_file, exists_anywhere

    def test_found_in_declared_file(self) -> None:
        eif, ea = self._make_lookups(
            {("Foo.bar", "f.lean"): True}, {"Foo.bar": True}
        )
        result = validate_single_theorem_ref(
            "Foo.bar", "f.lean", eif, ea, label="test", allow_global_fallback=False
        )
        self.assertIsNone(result)

    def test_not_found_anywhere(self) -> None:
        eif, ea = self._make_lookups({("Foo.bar", "f.lean"): False}, {})
        result = validate_single_theorem_ref(
            "Foo.bar", "f.lean", eif, ea, label="test", allow_global_fallback=False
        )
        self.assertIsNotNone(result)

    def test_global_fallback_allowed(self) -> None:
        eif, ea = self._make_lookups(
            {("Foo.bar", "f.lean"): False}, {"Foo.bar": True}
        )
        result = validate_single_theorem_ref(
            "Foo.bar", "f.lean", eif, ea, label="test", allow_global_fallback=True
        )
        self.assertIsNone(result)

    def test_global_fallback_disallowed(self) -> None:
        eif, ea = self._make_lookups(
            {("Foo.bar", "f.lean"): False}, {"Foo.bar": True}
        )
        result = validate_single_theorem_ref(
            "Foo.bar", "f.lean", eif, ea, label="proof_coverage", allow_global_fallback=False
        )
        self.assertIsNotNone(result)

    def test_no_declared_path_found_anywhere(self) -> None:
        eif, ea = self._make_lookups({}, {"Foo.bar": True})
        result = validate_single_theorem_ref(
            "Foo.bar", None, eif, ea, label="test", allow_global_fallback=False
        )
        self.assertIsNone(result)

    def test_no_declared_path_not_found(self) -> None:
        eif, ea = self._make_lookups({}, {})
        result = validate_single_theorem_ref(
            "Foo.bar", None, eif, ea, label="test", allow_global_fallback=False
        )
        self.assertIsNotNone(result)

    def test_file_lookup_returns_none_treated_as_ok(self) -> None:
        """When file path can't be resolved (returns None), theorem is accepted."""
        eif, ea = self._make_lookups(
            {("Foo.bar", "f.lean"): None}, {}
        )
        result = validate_single_theorem_ref(
            "Foo.bar", "f.lean", eif, ea, label="test", allow_global_fallback=False
        )
        self.assertIsNone(result)


class ValidateTheoremRefsTests(unittest.TestCase):
    def _noop_lookups(self):
        def eif(theorem: str, path: str) -> Optional[bool]:
            return True

        def ea(theorem: str) -> bool:
            return True

        return eif, ea

    def _failing_lookups(self):
        def eif(theorem: str, path: str) -> Optional[bool]:
            return False

        def ea(theorem: str) -> bool:
            return False

        return eif, ea

    def test_all_found(self) -> None:
        eif, ea = self._noop_lookups()
        errors = validate_theorem_refs(
            [("A.b", "f.lean"), ("C.d", "g.lean")],
            eif, ea,
            label="test",
            allow_global_fallback=False,
        )
        self.assertEqual(errors, [])

    def test_some_missing(self) -> None:
        eif, ea = self._failing_lookups()
        errors = validate_theorem_refs(
            [("A.b", "f.lean"), ("C.d", "g.lean")],
            eif, ea,
            label="test",
            allow_global_fallback=False,
        )
        self.assertEqual(len(errors), 2)

    def test_empty_refs(self) -> None:
        eif, ea = self._noop_lookups()
        errors = validate_theorem_refs(
            [], eif, ea, label="test", allow_global_fallback=False
        )
        self.assertEqual(errors, [])


class ValidateSharedOpParityTests(unittest.TestCase):
    def test_matching_evidence_levels(self) -> None:
        coverage_rows = {
            "sighash_v1": {"evidence_level": "machine_checked_universal"},
            "da_set_integrity": {"evidence_level": "machine_checked_universal"},
            "weight_accounting": {"evidence_level": "machine_checked_universal"},
        }
        bridge_rows = {
            "sighash_v1": {"evidence_level": "machine_checked_universal"},
            "da_set_integrity": {"evidence_level": "machine_checked_universal"},
            "weight_accounting": {"evidence_level": "machine_checked_universal"},
        }
        errors = validate_shared_op_parity(coverage_rows, bridge_rows)
        self.assertEqual(errors, [])

    def test_drift_detected(self) -> None:
        coverage_rows = {
            "sighash_v1": {"evidence_level": "machine_checked_universal"},
            "da_set_integrity": {"evidence_level": "machine_checked_universal"},
            "weight_accounting": {"evidence_level": "machine_checked_universal"},
        }
        bridge_rows = {
            "sighash_v1": {"evidence_level": "different_level"},
            "da_set_integrity": {"evidence_level": "machine_checked_universal"},
            "weight_accounting": {"evidence_level": "machine_checked_universal"},
        }
        errors = validate_shared_op_parity(coverage_rows, bridge_rows)
        self.assertEqual(len(errors), 1)
        self.assertIn("drift", errors[0])
        self.assertIn("sighash_v1", errors[0])

    def test_missing_bridge_row(self) -> None:
        coverage_rows = {
            "sighash_v1": {"evidence_level": "a"},
            "da_set_integrity": {"evidence_level": "a"},
            "weight_accounting": {"evidence_level": "a"},
        }
        bridge_rows = {
            "da_set_integrity": {"evidence_level": "a"},
            "weight_accounting": {"evidence_level": "a"},
        }
        errors = validate_shared_op_parity(coverage_rows, bridge_rows)
        self.assertEqual(len(errors), 1)
        self.assertIn("missing in refinement_bridge", errors[0])

    def test_missing_coverage_row(self) -> None:
        coverage_rows = {
            "da_set_integrity": {"evidence_level": "a"},
            "weight_accounting": {"evidence_level": "a"},
        }
        bridge_rows = {
            "sighash_v1": {"evidence_level": "a"},
            "da_set_integrity": {"evidence_level": "a"},
            "weight_accounting": {"evidence_level": "a"},
        }
        errors = validate_shared_op_parity(coverage_rows, bridge_rows)
        self.assertEqual(len(errors), 1)
        self.assertIn("missing in proof_coverage", errors[0])

    def test_both_missing(self) -> None:
        errors = validate_shared_op_parity({}, {})
        # All 3 SHARED_OP_PARITY items should be flagged
        self.assertEqual(len(errors), 3)


class ValidateRegisteredPathsTests(unittest.TestCase):
    def test_all_valid(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            (lean_dir / "Foo.lean").write_text("theorem a : True := by trivial")
            lake_dir = root / ".lake" / "build" / "lib" / "RubinFormal"
            lake_dir.mkdir(parents=True)
            (lake_dir / "Foo.olean").write_text("")

            paths = {"rubin-formal/RubinFormal/Foo.lean"}
            errors = validate_registered_paths(root, paths)
            self.assertEqual(errors, [])

    def test_lean_file_missing(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "RubinFormal").mkdir()
            paths = {"rubin-formal/RubinFormal/Missing.lean"}
            errors = validate_registered_paths(root, paths)
            self.assertEqual(len(errors), 1)
            self.assertIn("does not exist", errors[0])

    def test_olean_missing(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            (lean_dir / "Foo.lean").write_text("code")
            paths = {"rubin-formal/RubinFormal/Foo.lean"}
            errors = validate_registered_paths(root, paths)
            self.assertEqual(len(errors), 1)
            self.assertIn("outside the default build graph or failed to build", errors[0])

    def test_non_canonical_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {"wrong-prefix/Foo.lean"}
            errors = validate_registered_paths(root, paths)
            self.assertEqual(len(errors), 1)
            self.assertIn("unsupported non-repo path", errors[0])


if __name__ == "__main__":
    unittest.main()
