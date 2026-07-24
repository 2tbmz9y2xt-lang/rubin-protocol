"""Tests for high-level orchestration functions and end-to-end integration."""
from __future__ import annotations

import io
import json
import sys
import unittest
import unittest.mock as mock
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tools.check_formal_registry_truth as registry_truth
from tools.check_formal_registry_truth import (
    collect_registry_errors,
    load_registry_inputs,
    theorem_lookups,
)


class LoadRegistryInputsTests(unittest.TestCase):
    def test_missing_coverage_json(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "refinement_bridge.json").write_text("{}")
            (root / "RubinFormal").mkdir()
            (root / "RubinFormal" / "Test.lean").write_text("-- content")
            with self.assertRaises(FileNotFoundError) as ctx:
                load_registry_inputs(root)
            self.assertIn("proof_coverage.json", str(ctx.exception))

    def test_missing_bridge_json(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "proof_coverage.json").write_text("{}")
            (root / "RubinFormal").mkdir()
            (root / "RubinFormal" / "Test.lean").write_text("-- content")
            with self.assertRaises(FileNotFoundError) as ctx:
                load_registry_inputs(root)
            self.assertIn("refinement_bridge.json", str(ctx.exception))

    def test_no_lean_files(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "proof_coverage.json").write_text("{}")
            (root / "refinement_bridge.json").write_text("{}")
            (root / "RubinFormal").mkdir()
            with self.assertRaises(FileNotFoundError) as ctx:
                load_registry_inputs(root)
            self.assertIn("no Lean files", str(ctx.exception))

    def test_successful_load(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            coverage_data: dict[str, list[dict[str, Any]]] = {"coverage": []}
            bridge_data: dict[str, list[dict[str, Any]]] = {"critical_ops": []}
            (root / "proof_coverage.json").write_text(
                json.dumps(coverage_data), encoding="utf-8"
            )
            (root / "refinement_bridge.json").write_text(
                json.dumps(bridge_data), encoding="utf-8"
            )
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            (lean_dir / "Test.lean").write_text("theorem t : True := by trivial")

            coverage, bridge, lean_files = load_registry_inputs(root)
            self.assertEqual(coverage, coverage_data)
            self.assertEqual(bridge, bridge_data)
            self.assertEqual(len(lean_files), 1)
            self.assertTrue(lean_files[0].name.endswith(".lean"))


class TheoremLookupsTests(unittest.TestCase):
    """Extended tests for theorem_lookups beyond the existing test."""

    def test_theorem_in_nested_namespace(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "Deep.lean"
            sample.write_text(
                """
namespace RubinFormal.Deep
namespace Inner
theorem nested_thm : True := by trivial
end Inner
end RubinFormal.Deep
""",
                encoding="utf-8",
            )
            ea, _ = theorem_lookups(root, [sample])
            self.assertTrue(ea("RubinFormal.Deep.Inner.nested_thm"))
            self.assertFalse(ea("RubinFormal.Deep.nested_thm"))

    def test_theorem_not_in_any_file(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "Empty.lean"
            sample.write_text("-- no theorems", encoding="utf-8")
            ea, eif = theorem_lookups(root, [sample])
            self.assertFalse(ea("NonExistent.theorem"))

    def test_theorem_in_specific_file(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            file_a = lean_dir / "A.lean"
            file_a.write_text(
                "namespace RubinFormal.A\ntheorem a_thm : True := by trivial\nend RubinFormal.A",
                encoding="utf-8",
            )
            file_b = lean_dir / "B.lean"
            file_b.write_text(
                "namespace RubinFormal.B\ntheorem b_thm : True := by trivial\nend RubinFormal.B",
                encoding="utf-8",
            )

            _, eif = theorem_lookups(root, [file_a, file_b])
            self.assertTrue(eif("RubinFormal.A.a_thm", "rubin-formal/RubinFormal/A.lean"))
            self.assertFalse(eif("RubinFormal.A.a_thm", "rubin-formal/RubinFormal/B.lean"))

    def test_exists_in_file_nonexistent_file(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "X.lean"
            sample.write_text("-- content", encoding="utf-8")
            ea, eif = theorem_lookups(root, [sample])
            # File that doesn't exist on disk
            result = eif("Foo.bar", "rubin-formal/RubinFormal/NonExistent.lean")
            self.assertFalse(result)

    def test_exists_in_file_bad_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "X.lean"
            sample.write_text("-- content", encoding="utf-8")
            ea, eif = theorem_lookups(root, [sample])
            # Path with wrong prefix returns None
            result = eif("Foo.bar", "wrong-prefix/Foo.lean")
            self.assertIsNone(result)


class CollectRegistryErrorsTests(unittest.TestCase):
    def test_no_errors_on_valid_registry(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "Foo.lean"
            sample.write_text(
                "namespace RubinFormal.Foo\ntheorem bar : True := by trivial\nend RubinFormal.Foo",
                encoding="utf-8",
            )
            (root / "RubinFormal.lean").write_text("import RubinFormal.Foo", encoding="utf-8")
            lake_dir = root / ".lake" / "build" / "lib" / "RubinFormal"
            lake_dir.mkdir(parents=True)
            (lake_dir / "Foo.olean").write_text("")

            coverage = {
                "coverage": [
                    {
                        "section_key": "test_section",
                        "file": "rubin-formal/RubinFormal/Foo.lean",
                        "theorems": ["RubinFormal.Foo.bar"],
                        "theorem_files": {
                            "RubinFormal.Foo.bar": "rubin-formal/RubinFormal/Foo.lean"
                        },
                        "evidence_level": "machine_checked_universal",
                    }
                ]
            }
            bridge = {"critical_ops": []}
            ea, eif = theorem_lookups(root, [sample])
            paths, cov_refs, br_refs, errors = collect_registry_errors(
                root, coverage, bridge, ea, eif
            )
            # Shared-op parity will produce errors for all 3 missing ops
            # but no file/theorem errors expected
            file_errors = [e for e in errors if "shared-op" not in e]
            self.assertEqual(file_errors, [])

    def test_missing_theorem_produces_error(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "Foo.lean"
            sample.write_text("namespace RubinFormal.Foo\ntheorem present : True := by trivial\nend RubinFormal.Foo", encoding="utf-8")
            lake_dir = root / ".lake" / "build" / "lib" / "RubinFormal"
            lake_dir.mkdir(parents=True)
            (lake_dir / "Foo.olean").write_text("")

            coverage = {
                "coverage": [
                    {
                        "section_key": "test_section",
                        "file": "rubin-formal/RubinFormal/Foo.lean",
                        "theorems": ["RubinFormal.Foo.present"],
                    }
                ]
            }
            bridge = {"critical_ops": []}
            ea, eif = theorem_lookups(root, [sample])
            _, _, _, errors = collect_registry_errors(root, coverage, bridge, ea, eif)
            theorem_errors = [e for e in errors if "theorem" in e.lower() and "shared-op" not in e]
            self.assertGreater(len(theorem_errors), 0)
            self.assertIn("no exact theorem_files mapping", theorem_errors[0])

    def test_private_theorem_cannot_satisfy_registry_reference(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "Foo.lean"
            sample.write_text(
                "namespace RubinFormal.Foo\n"
                "private theorem hidden : True := by trivial\n"
                "end RubinFormal.Foo",
                encoding="utf-8",
            )
            lake_dir = root / ".lake" / "build" / "lib" / "RubinFormal"
            lake_dir.mkdir(parents=True)
            (lake_dir / "Foo.olean").write_text("")

            path = "rubin-formal/RubinFormal/Foo.lean"
            coverage = {
                "coverage": [
                    {
                        "section_key": "test_section",
                        "file": path,
                        "theorems": ["RubinFormal.Foo.hidden"],
                        "theorem_files": {"RubinFormal.Foo.hidden": path},
                    }
                ]
            }
            bridge = {"critical_ops": []}
            ea, eif = theorem_lookups(root, [sample])

            _, _, _, errors = collect_registry_errors(root, coverage, bridge, ea, eif)

            self.assertTrue(
                any("RubinFormal.Foo.hidden" in error for error in errors),
                errors,
            )

    def test_registry_path_traversal_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "Safe.lean"
            sample.write_text(
                "namespace RubinFormal.Safe\n"
                "theorem kept : True := by trivial\n"
                "end RubinFormal.Safe",
                encoding="utf-8",
            )
            traversal = "rubin-formal/RubinFormal/../../outside.lean"
            coverage = {"coverage": [{"file": traversal}]}
            bridge = {"critical_ops": []}
            ea, eif = theorem_lookups(root, [sample])

            _, _, _, errors = collect_registry_errors(root, coverage, bridge, ea, eif)

            self.assertIn(
                f"unsupported non-repo path in registry: {traversal}",
                errors,
            )

    def test_returns_registered_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            sample = lean_dir / "Foo.lean"
            sample.write_text("-- content", encoding="utf-8")
            lake_dir = root / ".lake" / "build" / "lib" / "RubinFormal"
            lake_dir.mkdir(parents=True)
            (lake_dir / "Foo.olean").write_text("")

            path = "rubin-formal/RubinFormal/Foo.lean"
            coverage = {"coverage": [{"file": path}]}
            bridge: dict[str, list[dict[str, Any]]] = {"critical_ops": []}
            ea, eif = theorem_lookups(root, [sample])
            registered_paths, _, _, _ = collect_registry_errors(root, coverage, bridge, ea, eif)
            self.assertIn(path, registered_paths)

    def test_bridge_model_theorem_does_not_fallback_globally(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_dir = root / "RubinFormal"
            lean_dir.mkdir()
            file_a = lean_dir / "A.lean"
            file_a.write_text(
                "namespace RubinFormal.A\ntheorem bridge_thm : True := by trivial\nend RubinFormal.A",
                encoding="utf-8",
            )
            file_b = lean_dir / "B.lean"
            file_b.write_text("-- empty", encoding="utf-8")
            lake_dir = root / ".lake" / "build" / "lib" / "RubinFormal"
            lake_dir.mkdir(parents=True)
            (lake_dir / "A.olean").write_text("")
            (lake_dir / "B.olean").write_text("")

            coverage = {"coverage": []}
            bridge = {
                "critical_ops": [
                    {
                        "op": "test_op",
                        "model_theorem": "RubinFormal.A.bridge_thm",
                        "lean_file": "rubin-formal/RubinFormal/B.lean",  # wrong file!
                    }
                ]
            }
            ea, eif = theorem_lookups(root, [file_a, file_b])
            _, _, _, errors = collect_registry_errors(root, coverage, bridge, ea, eif)
            theorem_errors = [e for e in errors if "bridge_thm" in e]
            self.assertTrue(theorem_errors)


class MainFunctionTests(unittest.TestCase):
    """Tests for the main() entry point."""

    @staticmethod
    def _write_minimal_valid_registry(root: Path) -> None:
        lean_dir = root / "RubinFormal"
        lean_dir.mkdir()

        lean_file = lean_dir / "Ops.lean"
        lean_file.write_text(
            "namespace RubinFormal.Ops\n"
            "theorem sighash_ok : True := by trivial\n"
            "theorem da_ok : True := by trivial\n"
            "theorem weight_ok : True := by trivial\n"
            "end RubinFormal.Ops\n",
            encoding="utf-8",
        )
        (root / "RubinFormal.lean").write_text("import RubinFormal.Ops", encoding="utf-8")

        lake_dir = root / ".lake" / "build" / "lib" / "RubinFormal"
        lake_dir.mkdir(parents=True)
        (lake_dir / "Ops.olean").write_text("", encoding="utf-8")

        lean_path = "rubin-formal/RubinFormal/Ops.lean"
        evidence = "machine_checked_universal"
        coverage: dict[str, list[dict[str, Any]]] = {
            "coverage": [
                {
                    "section_key": "sighash_v1",
                    "file": lean_path,
                    "theorems": ["RubinFormal.Ops.sighash_ok"],
                    "theorem_files": {"RubinFormal.Ops.sighash_ok": lean_path},
                    "evidence_level": evidence,
                },
                {
                    "section_key": "da_set_integrity",
                    "file": lean_path,
                    "theorems": ["RubinFormal.Ops.da_ok"],
                    "theorem_files": {"RubinFormal.Ops.da_ok": lean_path},
                    "evidence_level": evidence,
                },
                {
                    "section_key": "weight_accounting",
                    "file": lean_path,
                    "theorems": ["RubinFormal.Ops.weight_ok"],
                    "theorem_files": {"RubinFormal.Ops.weight_ok": lean_path},
                    "evidence_level": evidence,
                },
            ]
        }
        bridge: dict[str, list[dict[str, Any]]] = {
            "critical_ops": [
                {"op": "sighash_v1", "evidence_level": evidence},
                {"op": "da_set_integrity", "evidence_level": evidence},
                {"op": "weight_accounting", "evidence_level": evidence},
            ]
        }
        (root / "proof_coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
        (root / "refinement_bridge.json").write_text(json.dumps(bridge), encoding="utf-8")

    @staticmethod
    def _patched_main_file(root: Path):
        fake_tool_path = root / "tools" / "check_formal_registry_truth.py"
        fake_tool_path.parent.mkdir()
        fake_tool_path.write_text("# patched by tests\n", encoding="utf-8")
        return mock.patch.object(registry_truth, "__file__", str(fake_tool_path))

    def test_main_import(self) -> None:
        """Verify main can be imported without side effects."""
        self.assertTrue(callable(registry_truth.main))

    def test_main_returns_1_on_missing_files(self) -> None:
        """main() returns 1 and emits the file-not-found error for an invalid repo root."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            stderr = io.StringIO()
            with self._patched_main_file(root), mock.patch("sys.stderr", stderr):
                result = registry_truth.main()
            self.assertEqual(result, 1)
            self.assertIn("proof_coverage.json not found", stderr.getvalue())

    def test_main_succeeds_with_valid_registry(self) -> None:
        """main() returns 0 with a fully valid minimal registry."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_minimal_valid_registry(root)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with self._patched_main_file(root), mock.patch.object(registry_truth, "classify_registered_theorems", return_value=({}, [])), mock.patch.object(registry_truth, "validate_compiled_proof_trust", return_value=[]), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                result = registry_truth.main()
            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertIn("OK: formal registry truth passed", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
