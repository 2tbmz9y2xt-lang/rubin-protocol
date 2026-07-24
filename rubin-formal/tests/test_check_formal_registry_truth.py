from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_formal_registry_truth import extract_declared_names, theorem_lookups


class RegistryTruthCheckerTests(unittest.TestCase):
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
