#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import validate_prepush_summary_contract as m


class ValidatePrepushSummaryContractTests(unittest.TestCase):
    def test_validate_contract_passes_for_valid_summary(self):
        summary = (
            "CHECK_TYPE=diff_only|ACTIVE_LENSES=code-review,diff-scan|"
            "LENSES_COVERED=code-review:ok;diff-scan:ok|"
            "NO_FINDINGS=true|RATIONALE=code-review ok; diff-scan ok"
        )
        errors = m.validate_contract(
            summary=summary,
            findings=[],
            expected_check_type="diff_only",
            expected_active_lenses=["code-review", "diff-scan"],
        )
        self.assertEqual(errors, [])

    def test_validate_contract_rejects_missing_lens_coverage(self):
        summary = (
            "CHECK_TYPE=diff_only|ACTIVE_LENSES=code-review,diff-scan|"
            "LENSES_COVERED=code-review:ok|NO_FINDINGS=true|"
            "RATIONALE=code-review ok; diff-scan ok"
        )
        errors = m.validate_contract(
            summary=summary,
            findings=[],
            expected_check_type="diff_only",
            expected_active_lenses=["code-review", "diff-scan"],
        )
        self.assertTrue(any("missing ok status for lens='diff-scan'" in err for err in errors))

    def test_validate_contract_rejects_no_findings_mismatch(self):
        summary = (
            "CHECK_TYPE=code_noncritical|ACTIVE_LENSES=code-review,diff-scan|"
            "LENSES_COVERED=code-review:ok;diff-scan:ok|NO_FINDINGS=false|"
            "RATIONALE=code-review ok; diff-scan ok"
        )
        errors = m.validate_contract(
            summary=summary,
            findings=[],
            expected_check_type="code_noncritical",
            expected_active_lenses=["code-review", "diff-scan"],
        )
        self.assertTrue(any("NO_FINDINGS mismatch" in err for err in errors))

    def test_validate_contract_rejects_multiline_summary(self):
        summary = "CHECK_TYPE=diff_only|ACTIVE_LENSES=code-review\na|LENSES_COVERED=code-review:ok|NO_FINDINGS=true|RATIONALE=x"
        errors = m.validate_contract(
            summary=summary,
            findings=[],
            expected_check_type="diff_only",
            expected_active_lenses=["code-review"],
        )
        self.assertTrue(any("single-line" in err for err in errors))


if __name__ == "__main__":
    unittest.main()
