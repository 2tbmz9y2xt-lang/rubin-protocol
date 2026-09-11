#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
