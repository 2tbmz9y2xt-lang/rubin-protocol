"""Tests for registry path and theorem extraction functions."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_formal_registry_truth import (
    bridge_paths,
    bridge_theorems,
    coverage_paths,
    coverage_theorems,
    indexed_rows,
    iter_registered_theorems,
    iter_registry_paths,
)


class CoveragePathsTests(unittest.TestCase):
    def test_file_only(self) -> None:
        row = {"file": "rubin-formal/RubinFormal/Foo.lean"}
        self.assertEqual(coverage_paths(row), {"rubin-formal/RubinFormal/Foo.lean"})

    def test_theorem_files(self) -> None:
        row = {
            "theorem_files": {
                "Foo.bar": "rubin-formal/RubinFormal/Foo.lean",
                "Baz.qux": "rubin-formal/RubinFormal/Baz.lean",
            }
        }
        result = coverage_paths(row)
        self.assertEqual(
            result,
            {
                "rubin-formal/RubinFormal/Foo.lean",
                "rubin-formal/RubinFormal/Baz.lean",
            },
        )

    def test_file_and_theorem_files(self) -> None:
        row = {
            "file": "rubin-formal/RubinFormal/Main.lean",
            "theorem_files": {"Th.a": "rubin-formal/RubinFormal/A.lean"},
        }
        result = coverage_paths(row)
        self.assertIn("rubin-formal/RubinFormal/Main.lean", result)
        self.assertIn("rubin-formal/RubinFormal/A.lean", result)

    def test_empty_row(self) -> None:
        self.assertEqual(coverage_paths({}), set())

    def test_non_string_file(self) -> None:
        row = {"file": 42}
        self.assertEqual(coverage_paths(row), set())

    def test_non_dict_theorem_files(self) -> None:
        row = {"theorem_files": "not-a-dict"}
        self.assertEqual(coverage_paths(row), set())

    def test_non_string_values_in_theorem_files(self) -> None:
        row = {"theorem_files": {"a": 42, "b": "rubin-formal/RubinFormal/B.lean"}}
        result = coverage_paths(row)
        self.assertEqual(result, {"rubin-formal/RubinFormal/B.lean"})


class BridgePathsTests(unittest.TestCase):
    def test_lean_file_only(self) -> None:
        row = {"lean_file": "rubin-formal/RubinFormal/Foo.lean"}
        self.assertEqual(bridge_paths(row), {"rubin-formal/RubinFormal/Foo.lean"})

    def test_theorem_file_only(self) -> None:
        row = {"theorem_file": "rubin-formal/RubinFormal/Bar.lean"}
        self.assertEqual(bridge_paths(row), {"rubin-formal/RubinFormal/Bar.lean"})

    def test_both_files(self) -> None:
        row = {
            "lean_file": "rubin-formal/RubinFormal/A.lean",
            "theorem_file": "rubin-formal/RubinFormal/B.lean",
        }
        result = bridge_paths(row)
        self.assertEqual(len(result), 2)
        self.assertIn("rubin-formal/RubinFormal/A.lean", result)
        self.assertIn("rubin-formal/RubinFormal/B.lean", result)

    def test_empty_row(self) -> None:
        self.assertEqual(bridge_paths({}), set())

    def test_non_string_values(self) -> None:
        row = {"lean_file": 42, "theorem_file": None}
        self.assertEqual(bridge_paths(row), set())


class IterRegistryPathsTests(unittest.TestCase):
    def test_combines_coverage_and_bridge(self) -> None:
        coverage = {
            "coverage": [{"file": "rubin-formal/RubinFormal/A.lean"}]
        }
        bridge = {
            "critical_ops": [{"lean_file": "rubin-formal/RubinFormal/B.lean"}]
        }
        result = iter_registry_paths(coverage, bridge)
        self.assertIn("rubin-formal/RubinFormal/A.lean", result)
        self.assertIn("rubin-formal/RubinFormal/B.lean", result)

    def test_empty_registries(self) -> None:
        self.assertEqual(iter_registry_paths({}, {}), set())

    def test_non_dict_rows_skipped(self) -> None:
        coverage = {"coverage": ["not-a-dict", 42]}
        bridge = {"critical_ops": [None]}
        result = iter_registry_paths(coverage, bridge)
        self.assertEqual(result, set())

    def test_deduplication(self) -> None:
        path = "rubin-formal/RubinFormal/Same.lean"
        coverage = {"coverage": [{"file": path}]}
        bridge = {"critical_ops": [{"lean_file": path}]}
        result = iter_registry_paths(coverage, bridge)
        self.assertEqual(result, {path})


class CoverageTheoremsTests(unittest.TestCase):
    def test_theorems_with_files(self) -> None:
        row = {
            "theorems": ["Foo.bar", "Baz.qux"],
            "theorem_files": {
                "Foo.bar": "rubin-formal/RubinFormal/Foo.lean",
                "Baz.qux": "rubin-formal/RubinFormal/Baz.lean",
            },
        }
        refs = coverage_theorems(row)
        self.assertEqual(len(refs), 2)
        self.assertEqual(refs[0], ("Foo.bar", "rubin-formal/RubinFormal/Foo.lean"))
        self.assertEqual(refs[1], ("Baz.qux", "rubin-formal/RubinFormal/Baz.lean"))

    def test_theorems_without_files(self) -> None:
        row = {"theorems": ["A.b"]}
        refs = coverage_theorems(row)
        self.assertEqual(refs, [("A.b", None)])

    def test_empty_row(self) -> None:
        self.assertEqual(coverage_theorems({}), [])

    def test_non_string_theorem_skipped(self) -> None:
        row = {"theorems": [42, "Valid.thm"]}
        refs = coverage_theorems(row)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0][0], "Valid.thm")

    def test_theorem_files_not_dict(self) -> None:
        row = {"theorems": ["A.b"], "theorem_files": "invalid"}
        refs = coverage_theorems(row)
        self.assertEqual(refs, [("A.b", None)])


class BridgeTheoremsTests(unittest.TestCase):
    def test_model_theorem_with_lean_file(self) -> None:
        row = {
            "model_theorem": "Model.thm",
            "lean_file": "rubin-formal/RubinFormal/Model.lean",
        }
        refs = bridge_theorems(row)
        self.assertEqual(refs, [("Model.thm", "rubin-formal/RubinFormal/Model.lean")])

    def test_supporting_theorems(self) -> None:
        row = {
            "supporting_theorems": ["S.a", "S.b"],
            "theorem_file": "rubin-formal/RubinFormal/Support.lean",
        }
        refs = bridge_theorems(row)
        self.assertEqual(len(refs), 2)
        self.assertEqual(refs[0], ("S.a", "rubin-formal/RubinFormal/Support.lean"))
        self.assertEqual(refs[1], ("S.b", "rubin-formal/RubinFormal/Support.lean"))

    def test_model_and_supporting(self) -> None:
        row = {
            "model_theorem": "Model.thm",
            "lean_file": "rubin-formal/RubinFormal/Model.lean",
            "supporting_theorems": ["S.a"],
            "theorem_file": "rubin-formal/RubinFormal/Support.lean",
        }
        refs = bridge_theorems(row)
        self.assertEqual(len(refs), 2)
        self.assertEqual(refs[0][0], "Model.thm")
        self.assertEqual(refs[1][0], "S.a")

    def test_empty_row(self) -> None:
        self.assertEqual(bridge_theorems({}), [])

    def test_non_string_model_theorem(self) -> None:
        row = {"model_theorem": 42}
        self.assertEqual(bridge_theorems(row), [])

    def test_non_string_lean_file(self) -> None:
        row = {"model_theorem": "M.thm", "lean_file": 42}
        refs = bridge_theorems(row)
        self.assertEqual(refs, [("M.thm", None)])


class IterRegisteredTheoremsTests(unittest.TestCase):
    def test_combines_coverage_and_bridge(self) -> None:
        coverage = {
            "coverage": [{"theorems": ["C.a"], "theorem_files": {"C.a": "rubin-formal/RubinFormal/C.lean"}}]
        }
        bridge = {
            "critical_ops": [{"model_theorem": "B.m", "lean_file": "rubin-formal/RubinFormal/B.lean"}]
        }
        cov_refs, br_refs = iter_registered_theorems(coverage, bridge)
        self.assertEqual(len(cov_refs), 1)
        self.assertEqual(len(br_refs), 1)
        self.assertEqual(cov_refs[0][0], "C.a")
        self.assertEqual(br_refs[0][0], "B.m")

    def test_empty(self) -> None:
        cov, br = iter_registered_theorems({}, {})
        self.assertEqual(cov, [])
        self.assertEqual(br, [])


class IndexedRowsTests(unittest.TestCase):
    def test_indexes_by_key(self) -> None:
        rows = [
            {"op": "sighash_v1", "data": 1},
            {"op": "weight_accounting", "data": 2},
        ]
        result = indexed_rows(rows, "op")
        self.assertEqual(len(result), 2)
        self.assertEqual(result["sighash_v1"]["data"], 1)
        self.assertEqual(result["weight_accounting"]["data"], 2)

    def test_missing_key_skipped(self) -> None:
        rows = [
            {"op": "a", "data": 1},
            {"no_op": "b", "data": 2},
        ]
        result = indexed_rows(rows, "op")
        self.assertEqual(len(result), 1)
        self.assertIn("a", result)

    def test_non_dict_rows_skipped(self) -> None:
        rows = [42, "string", {"op": "valid"}]
        result = indexed_rows(rows, "op")
        self.assertEqual(len(result), 1)

    def test_non_string_value_skipped(self) -> None:
        rows = [{"op": 42}, {"op": "valid"}]
        result = indexed_rows(rows, "op")
        self.assertEqual(len(result), 1)

    def test_empty_rows(self) -> None:
        self.assertEqual(indexed_rows([], "key"), {})

    def test_duplicate_key_last_wins(self) -> None:
        rows = [
            {"op": "dup", "val": 1},
            {"op": "dup", "val": 2},
        ]
        result = indexed_rows(rows, "op")
        self.assertEqual(result["dup"]["val"], 2)


if __name__ == "__main__":
    unittest.main()
