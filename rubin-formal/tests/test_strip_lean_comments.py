"""Tests for comment and string stripping in check_formal_registry_truth."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_formal_registry_truth import strip_lean_comments


class StripLeanCommentsTests(unittest.TestCase):
    # ── line comments ──────────────────────────────────────────────
    def test_line_comment_is_blanked(self) -> None:
        text = "theorem foo -- this is a comment\ntheorem bar"
        result = strip_lean_comments(text)
        self.assertNotIn("this is a comment", result)
        self.assertIn("theorem foo", result)
        self.assertIn("theorem bar", result)

    def test_line_comment_preserves_newline(self) -> None:
        text = "a -- comment\nb"
        result = strip_lean_comments(text)
        self.assertIn("\n", result)
        self.assertIn("b", result)

    def test_only_line_comment(self) -> None:
        text = "-- entire line is a comment"
        result = strip_lean_comments(text)
        self.assertNotIn("entire", result)

    # ── block comments ─────────────────────────────────────────────
    def test_simple_block_comment(self) -> None:
        text = "before /- block comment -/ after"
        result = strip_lean_comments(text)
        self.assertIn("before", result)
        self.assertIn("after", result)
        self.assertNotIn("block comment", result)

    def test_nested_block_comment(self) -> None:
        text = "before /- outer /- inner -/ still outer -/ after"
        result = strip_lean_comments(text)
        self.assertIn("before", result)
        self.assertIn("after", result)
        self.assertNotIn("inner", result)
        self.assertNotIn("outer", result)

    def test_block_comment_preserves_newlines(self) -> None:
        text = "a /- comment\nacross\nlines -/ b"
        result = strip_lean_comments(text)
        lines = result.split("\n")
        self.assertEqual(len(lines), 3)  # newlines inside block preserved as \n

    def test_multiline_block_comment(self) -> None:
        text = "/- multi\nline\ncomment -/\ncode"
        result = strip_lean_comments(text)
        self.assertIn("code", result)
        self.assertNotIn("multi", result)

    # ── string literals ────────────────────────────────────────────
    def test_string_preserved_even_with_comment_like_content(self) -> None:
        text = 'let s := "-- not a comment"'
        result = strip_lean_comments(text)
        self.assertIn("-- not a comment", result)

    def test_string_with_escaped_quote(self) -> None:
        text = r'let s := "escaped \" quote"'
        result = strip_lean_comments(text)
        self.assertIn("escaped", result)

    def test_string_with_block_comment_syntax(self) -> None:
        text = 'let s := "/- not a comment -/"'
        result = strip_lean_comments(text)
        self.assertIn("/- not a comment -/", result)

    # ── edge cases ─────────────────────────────────────────────────
    def test_empty_string(self) -> None:
        self.assertEqual(strip_lean_comments(""), "")

    def test_no_comments(self) -> None:
        text = "theorem foo : True := by trivial"
        self.assertEqual(strip_lean_comments(text), text)

    def test_only_block_comment(self) -> None:
        text = "/- only a comment -/"
        result = strip_lean_comments(text)
        self.assertNotIn("only", result)

    def test_adjacent_line_comments(self) -> None:
        text = "-- first\n-- second\ncode"
        result = strip_lean_comments(text)
        self.assertNotIn("first", result)
        self.assertNotIn("second", result)
        self.assertIn("code", result)

    def test_line_length_preserved(self) -> None:
        """strip_lean_comments replaces comment chars with spaces to preserve column positions."""
        text = "a -- bc\nd"
        result = strip_lean_comments(text)
        lines = result.split("\n")
        self.assertEqual(len(lines[0]), len("a -- bc"))


if __name__ == "__main__":
    unittest.main()
