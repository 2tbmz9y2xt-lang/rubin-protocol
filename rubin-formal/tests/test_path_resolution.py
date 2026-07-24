"""Tests for path resolution and olean path functions."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_formal_registry_truth import (
    lean_repo_path,
    olean_path,
    rel_repo_path,
    try_lean_repo_path,
)


class LeanRepoPathTests(unittest.TestCase):
    def test_valid_prefixed_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = lean_repo_path(root, "rubin-formal/RubinFormal/Foo.lean")
            self.assertEqual(result, root / "RubinFormal" / "Foo.lean")

    def test_nested_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = lean_repo_path(root, "rubin-formal/RubinFormal/Sub/Deep.lean")
            self.assertEqual(result, root / "RubinFormal" / "Sub" / "Deep.lean")

    def test_invalid_prefix_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError) as ctx:
                lean_repo_path(root, "wrong-prefix/RubinFormal/Foo.lean")
            self.assertIn("non-canonical", str(ctx.exception))
            self.assertIn("rubin-formal/", str(ctx.exception))

    def test_no_prefix_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                lean_repo_path(root, "RubinFormal/Foo.lean")


class TryLeanRepoPathTests(unittest.TestCase):
    def test_valid_path_returns_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = try_lean_repo_path(root, "rubin-formal/RubinFormal/Foo.lean")
            self.assertIsNotNone(result)
            self.assertEqual(result, root / "RubinFormal" / "Foo.lean")

    def test_invalid_path_returns_none(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = try_lean_repo_path(root, "wrong/path")
            self.assertIsNone(result)


class OleanPathTests(unittest.TestCase):
    def test_valid_lean_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = olean_path(root, "rubin-formal/RubinFormal/Foo.lean")
            expected = root / ".lake" / "build" / "lib" / "RubinFormal" / "Foo.olean"
            self.assertEqual(result, expected)

    def test_nested_lean_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = olean_path(root, "rubin-formal/RubinFormal/Sub/Bar.lean")
            expected = root / ".lake" / "build" / "lib" / "RubinFormal" / "Sub" / "Bar.olean"
            self.assertEqual(result, expected)

    def test_wrong_prefix_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError) as ctx:
                olean_path(root, "wrong/RubinFormal/Foo.lean")
            self.assertIn("non-canonical", str(ctx.exception))

    def test_outside_rubin_formal_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError) as ctx:
                olean_path(root, "rubin-formal/scripts/check.sh")
            self.assertIn("outside RubinFormal build graph", str(ctx.exception))

    def test_non_lean_extension_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError) as ctx:
                olean_path(root, "rubin-formal/RubinFormal/Foo.py")
            self.assertIn("outside RubinFormal build graph", str(ctx.exception))


class RelRepoPathTests(unittest.TestCase):
    def test_relative_to_root(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sub = root / "RubinFormal" / "Foo.lean"
            sub.parent.mkdir(parents=True)
            sub.touch()
            result = rel_repo_path(root, sub)
            self.assertEqual(result, "RubinFormal/Foo.lean")

    def test_nested_relative(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sub = root / "a" / "b" / "c.lean"
            sub.parent.mkdir(parents=True)
            sub.touch()
            result = rel_repo_path(root, sub)
            self.assertEqual(result, "a/b/c.lean")


if __name__ == "__main__":
    unittest.main()
