#!/usr/bin/env python3
from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_pv_doc_compliance as m


class PvSelectorLiteralTests(unittest.TestCase):
    # Expected values are stated literals, never read back from the module under
    # test: a pin sourced from the constant it guards moves with any edit to it.

    def test_touch_needles_are_exactly_the_retained_six(self):
        self.assertEqual(
            m.PV_TOUCH_NEEDLES,
            (
                "parallel",
                "connect_block_parallel",
                "tx_dep_graph",
                "utxo_snapshot",
                "pv-",
                "cv-pv",
            ),
        )

    def test_touch_prefixes_are_exactly_the_retained_six(self):
        self.assertEqual(
            m.PV_TOUCH_PREFIXES,
            (
                "clients/go/consensus/",
                "clients/go/node/",
                "clients/rust/crates/rubin-consensus/",
                "clients/rust/crates/rubin-node/",
                "conformance/fixtures/",
                "conformance/runner/",
            ),
        )

    def test_required_pr_body_markers_are_unchanged(self):
        self.assertEqual(
            m.REQ_MARKERS,
            [
                r"(?im)^\s*Refs:\s*Q-[A-Z0-9-]+\s*$",
                r"(?im)^\s*##\s*Summary\s*$",
                r"(?im)^\s*##\s*Scope\s*$",
            ],
        )


class PvSelectionTests(unittest.TestCase):
    def test_selects_sensitive_path_matching_a_single_needle(self):
        self.assertTrue(m.touches_pv(["clients/go/consensus/da_verify_parallel.go"]))

    def test_selects_fixture_under_retained_prefix(self):
        self.assertTrue(m.touches_pv(["conformance/fixtures/CV-PV-ERR.json"]))

    def test_skips_sensitive_path_matching_no_needle(self):
        self.assertFalse(m.touches_pv(["clients/go/node/mempool.go"]))

    def test_skips_path_outside_every_sensitive_prefix(self):
        self.assertFalse(m.touches_pv(["tools/check_pv_doc_compliance.py"]))


class PvDeclarationTests(unittest.TestCase):
    def test_main_declaration_outcomes(self):
        consensus = "Consensus rules unchanged: "
        hashes = "SECTION_HASHES.json unchanged: "
        missing_consensus = (
            "- missing line: 'Consensus rules unchanged: YES' or 'Consensus rules unchanged: NO'"
        )
        uppercase = "- Consensus declaration must be uppercase YES or NO"
        missing_hashes = "- missing line: 'SECTION_HASHES.json unchanged: YES'"
        invalid_hashes = (
            "- SECTION_HASHES.json boundary must be explicitly affirmed: 'SECTION_HASHES.json unchanged: YES'"
        )
        cases = [
            ("A1", consensus + "YES", hashes + "YES", "", 0, "PV_DOC_COMPLIANCE: PASS"),
            ("A2", "- " + consensus + "NO", "- `SECTION_HASHES.json` unchanged: YES", "", 0, "PV_DOC_COMPLIANCE: PASS"),
            ("R1", "", hashes + "YES", "", 1, missing_consensus),
            ("R2", consensus, hashes + "YES", "", 1, missing_consensus),
            ("R3", consensus + "MAYBE", hashes + "YES", "", 1, missing_consensus),
            ("R4-yes", consensus + "yes", hashes + "YES", "", 1, uppercase),
            ("R4-no", consensus + "no", hashes + "YES", "", 1, uppercase),
            ("R5", consensus + "NO", "", "", 1, missing_hashes),
            ("R6", consensus + "YES", hashes + "NO", "", 1, invalid_hashes),
            ("R6-lowercase", consensus + "NO", hashes + "yes", "", 1, invalid_hashes),
            ("R7", consensus + "NO", hashes + "YES", "Refs: Q-1715", 1, r"- (?im)^\s*Refs:\s*Q-[A-Z0-9-]+\s*$"),
            ("R8", consensus + "NO", hashes + "YES", "## Summary", 1, r"- (?im)^\s*##\s*Summary\s*$"),
            ("R9", consensus + "NO", hashes + "YES", "## Scope", 1, r"- (?im)^\s*##\s*Scope\s*$"),
            ("H1", consensus + "NO", hashes + "NO", "", 1, invalid_hashes),
        ]
        with (
            patch.object(sys, "argv", ["check_pv_doc_compliance.py", "--repo", "owner/repo"]),
            patch.object(m, "detect_range_from_github_event", return_value=("a" * 40, "b" * 40, True)),
            patch.object(m, "run_git", return_value="M\0clients/go/consensus/parallel.go\0"),
            patch.object(m, "pr_number_from_event", return_value=1715),
        ):
            for name, cons, sh, omitted, expected, diagnostic in cases:
                with self.subTest(case=name):
                    lines = ["Refs: Q-1715", "## Summary", "## Scope", cons, sh]
                    body = "\n".join(line for line in lines if line != omitted)
                    output = io.StringIO()
                    with patch.object(m, "fetch_pr_body", return_value=body), redirect_stdout(output):
                        result = m.main()
                    observed = output.getvalue()
                    self.assertEqual(result, expected)
                    self.assertIn(diagnostic, observed.splitlines())
                    self.assertIn("PV_DOC_COMPLIANCE: PASS" if expected == 0 else "PV_DOC_COMPLIANCE: FAIL", observed.splitlines())
                    self.assertNotIn("PV_DOC_COMPLIANCE: FAIL" if expected == 0 else "PV_DOC_COMPLIANCE: PASS", observed)
                    self.assertNotIn("PV_DOC_COMPLIANCE: SKIP", observed)
                    if omitted:
                        self.assertIn("Missing structural markers (regex):", observed.splitlines())


if __name__ == "__main__":
    unittest.main()
