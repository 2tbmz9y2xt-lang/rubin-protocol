#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_codacy_coverage", REPO_ROOT / "tools/check_codacy_coverage.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class CodacyCoverageDecisionTests(unittest.TestCase):
    def parse_args(self, *thresholds: str):
        argv = [
            "check_codacy_coverage.py",
            "--summary-title",
            "Test coverage summary",
            "--repo-root",
            "/repo",
            "--base-ref",
            "855db0709967350e6236c185578a44f2fddfdab6",
            "--base-go",
            "/coverage/base-go.out",
            "--base-rust",
            "/coverage/base-rust.info",
            "--head-go",
            "/coverage/head-go.out",
            "--head-rust",
            "/coverage/head-rust.info",
            *thresholds,
        ]
        with mock.patch.object(sys, "argv", argv):
            return CHECKER.parse_args()

    def test_clean_variation_only_diff_only_and_both(self):
        args = self.parse_args()
        self.assertEqual((args.min_variation, args.min_diff_coverage), (-0.10, 85.0))
        explicit = self.parse_args(
            "--min-variation", "-1.25", "--min-diff-coverage", "91.5"
        )
        self.assertEqual((explicit.min_variation, explicit.min_diff_coverage), (-1.25, 91.5))

        cases = (
            ("clean", (1000, 1), (1000, 0), 85, 0, False, False),
            ("variation-only", (100, 90), (100, 89), 85, 0, True, False),
            ("diff-only", (100, 90), (100, 90), 84, 1, False, True),
            ("both", (100, 90), (100, 89), 84, 1, True, True),
        )
        changed_file = args.repo_root / "clients/go/example.go"
        for name, base, head, diff_covered, returncode, warns, fails in cases:
            with self.subTest(name=name):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(CHECKER, "parse_args", return_value=args),
                    mock.patch.object(CHECKER, "read_go_module_prefix", return_value="example"),
                    mock.patch.object(CHECKER, "parse_go_cover", return_value={}),
                    mock.patch.object(CHECKER, "parse_lcov", return_value={}),
                    mock.patch.object(CHECKER, "coverage_totals", side_effect=(base, head)),
                    mock.patch.object(CHECKER, "changed_lines", return_value={}),
                    mock.patch.object(
                        CHECKER,
                        "diff_coverage",
                        return_value=(100, diff_covered, [f"{changed_file}:7"]),
                    ),
                    mock.patch.object(
                        CHECKER,
                        "diff_coverage_by_file",
                        return_value={changed_file: (100, diff_covered, [7])},
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(CHECKER.main(), returncode)

                output = stdout.getvalue()
                diagnostic = stderr.getvalue()
                variation = CHECKER.coverage_percent(*head) - CHECKER.coverage_percent(*base)
                expected_diagnostic = ""
                if warns:
                    expected_diagnostic += (
                        f"WARN: coverage variation {variation:+.2f}% is below advisory threshold -0.10%\n"
                    )
                if fails:
                    expected_diagnostic += (
                        f"FAIL: diff coverage {diff_covered:.2f}% is below hard threshold 85.00%\n"
                    )
                self.assertIn("Test coverage summary", output)
                self.assertIn(f"  variation:      {variation:+.2f}%", output)
                self.assertIn(
                    "variation advisory >= -0.10%, diff coverage hard >= 85.00%", output
                )
                self.assertIn(f"diff coverage:  {diff_covered:.2f}% ({diff_covered}/100)", output)
                self.assertIn("clients/go/example.go", output)
                self.assertIn(f"{changed_file}:7", output)
                self.assertEqual(diagnostic, expected_diagnostic)
                self.assertEqual(
                    output.endswith(
                        "PASS: hard diff coverage threshold satisfied; coverage variation is advisory\n"
                    ),
                    returncode == 0,
                )


if __name__ == "__main__":
    unittest.main()
