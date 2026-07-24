import contextlib
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import check_formal_registry_truth as registry
from tools.check_formal_registry_truth import extract_declared_names, parse_axiom_output, theorem_lookups


class RegistryTruthCheckerTests(unittest.TestCase):
    def test_malformed_registry_json_fails_closed(self) -> None:
        for name in ("proof_coverage.json", "refinement_bridge.json"):
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                root = Path(tmp); (root / "tools").mkdir()
                for path in ("proof_coverage.json", "refinement_bridge.json"):
                    (root / path).write_text("{" if path == name else "{}", encoding="utf-8")
                stderr = io.StringIO()
                with mock.patch.object(registry, "__file__", str(root / "tools" / "check_formal_registry_truth.py")), contextlib.redirect_stderr(stderr):
                    self.assertEqual(registry.main(), 1)
                self.assertEqual(stderr.getvalue(), f"ERROR: {name}: invalid JSON\n")

    def test_non_utf8_registry_json_fails_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "tools").mkdir()
            (root / "proof_coverage.json").write_bytes(b"\xff")
            (root / "refinement_bridge.json").write_text("{}", encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch.object(registry, "__file__", str(root / "tools" / "check_formal_registry_truth.py")), contextlib.redirect_stderr(stderr):
                self.assertEqual(registry.main(), 1)
            self.assertEqual(stderr.getvalue(), "ERROR: proof_coverage.json: invalid UTF-8\n")

    def test_axiom_output_classifies_and_fails_closed(self) -> None:
        trust, errors = parse_axiom_output("'A.ok' depends on axioms: [propext, Lean.ofReduceBool]\n'B.ok' depends on axioms: [propext, Quot.sound, Classical.choice]\n", ["A.ok", "B.ok"])
        self.assertEqual(errors, [])
        self.assertEqual(trust, {"A.ok": "compiler_trusted", "B.ok": "kernel_checked"})
        self.assertTrue(parse_axiom_output("unexpected", ["A.ok"])[1])
        self.assertTrue(
            parse_axiom_output(
                "'A.ok' depends on axioms: [ExternalAssumption]\n", ["A.ok"]
            )[1]
        )

    def test_supporting_theorems_require_exact_file_bindings(self) -> None:
        theorem = "RubinFormal.Model.ok"
        coverage = {"coverage": [{"theorems": [theorem], "theorem_files": {theorem: "rubin-formal/RubinFormal/Model.lean"}}]}
        paths = registry.coverage_theorem_file_paths(coverage)
        bindings, errors = registry.bridge_supporting_theorem_bindings({"op": "demo", "supporting_theorems": [theorem]}, paths)
        self.assertEqual((bindings, errors), ({theorem: "rubin-formal/RubinFormal/Model.lean"}, []))
        _, errors = registry.bridge_supporting_theorem_bindings(
            {
                "op": "demo",
                "supporting_theorems": [theorem],
                "supporting_theorem_files": {theorem: "rubin-formal/RubinFormal/Model.lean"},
            },
            paths,
        )
        self.assertEqual(
            errors,
            [
                f"refinement_bridge `demo` supporting theorem `{theorem}` has direct binding but "
                "proof_coverage already binds it to `rubin-formal/RubinFormal/Model.lean`"
            ],
        )

    def test_extract_declared_names_ignores_comments(self) -> None:
        text = """
namespace RubinFormal.Real
theorem kept : True := by trivial
-- theorem fake_line : True := by trivial
/- nested block comment
namespace RubinFormal.Fake
theorem fake_block : True := by trivial
/- theorem fake_nested : True := by trivial -/
end RubinFormal.Fake
-/
end RubinFormal.Real
"""
        names = extract_declared_names(text)
        self.assertIn("RubinFormal.Real.kept", names)
        self.assertNotIn("RubinFormal.Real.fake_line", names)
        self.assertNotIn("RubinFormal.Fake.fake_block", names)
        self.assertNotIn("RubinFormal.Fake.fake_nested", names)

    def test_source_import_reachability_ignores_quoted_and_raw_string_imports(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_root = root / "RubinFormal"
            lean_root.mkdir()
            hidden_modules = ("HiddenOrdinary", "HiddenRaw", "HiddenHashed")
            hidden_paths = []
            for module in (*hidden_modules, "Live"):
                path = lean_root / f"{module}.lean"
                path.write_text("", encoding="utf-8")
                if module != "Live":
                    hidden_paths.append(path.resolve())
            (root / "RubinFormal.lean").write_text(
                'def ordinary := "import RubinFormal.HiddenOrdinary"\n'
                'def raw := r"import RubinFormal.HiddenRaw"\n'
                'def hashed := r###"\n'
                'import RubinFormal.HiddenHashed\n'
                '"###\n'
                'import RubinFormal.Live\n',
                encoding="utf-8",
            )

            reachable, errors = registry.source_import_reachability(root)

            self.assertEqual(errors, [])
            self.assertIn((lean_root / "Live.lean").resolve(), reachable)
            self.assertTrue(all(path not in reachable for path in hidden_paths))

    def test_extract_declared_names_respects_relative_namespace_names(self) -> None:
        text = """
namespace RubinFormal
theorem Wire.roundtrip_ok : True := by trivial
theorem listFind?_ok! : True := by trivial
theorem universe_ok.{u, v} : True := by trivial
end RubinFormal
"""
        names = extract_declared_names(text)
        self.assertIn("RubinFormal.Wire.roundtrip_ok", names)
        self.assertIn("RubinFormal.listFind?_ok!", names)
        self.assertIn("RubinFormal.universe_ok", names)

    def test_theorem_exists_in_file_requires_exact_qualified_name(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            lean_root = repo_root / "RubinFormal"
            lean_root.mkdir()
            sample = lean_root / "Sample.lean"
            sample.write_text(
                """
namespace RubinFormal.Real
theorem bridge_ok : True := by trivial
end RubinFormal.Real

namespace RubinFormal.Other
theorem bridge_ok : True := by trivial
end RubinFormal.Other
""",
                encoding="utf-8",
            )

            theorem_exists_anywhere, theorem_exists_in_file = theorem_lookups(repo_root, [sample])
            rel_path = "rubin-formal/RubinFormal/Sample.lean"

            self.assertTrue(theorem_exists_in_file("RubinFormal.Real.bridge_ok", rel_path))
            self.assertTrue(theorem_exists_anywhere("RubinFormal.Real.bridge_ok"))
            self.assertFalse(theorem_exists_in_file("RubinFormal.Wrong.bridge_ok", rel_path))
            self.assertFalse(theorem_exists_anywhere("RubinFormal.Wrong.bridge_ok"))


if __name__ == "__main__":
    unittest.main()
