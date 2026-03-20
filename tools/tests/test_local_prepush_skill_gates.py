#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_local_prepush_skill_gates as m


class LocalPrepushSkillGateTests(unittest.TestCase):
    def test_build_plan_activates_fullscan_lenses_for_go_fixture_and_tooling_changes(self):
        changed = {
            "clients/go/consensus/verify_sig_openssl.go",
            "conformance/fixtures/CV-TEST.json",
            "tools/check_consensus_openssl_isolation.py",
        }

        checks, focuses, lenses = m.build_plan(changed)
        check_names = {name for name, _cmd in checks}
        active_lenses = {lens.name for lens in lenses if lens.active}

        self.assertIn("conformance_fixtures_policy", check_names)
        self.assertIn("conformance_matrix", check_names)
        self.assertIn("formal_refinement_bridge", check_names)
        self.assertIn("consensus_openssl_source_policy", check_names)
        self.assertIn("go_verify_sig_smoke", check_names)
        self.assertIn("rust_verify_sig_smoke", check_names)
        self.assertTrue(any("OpenSSL isolation" in focus for focus in focuses))
        self.assertIn("code-review", active_lenses)
        self.assertIn("diff-scan", active_lenses)
        self.assertIn("combined-security-scan", active_lenses)
        self.assertIn("semgrep-scan", active_lenses)
        self.assertIn("gosec-scan", active_lenses)
        self.assertIn("rubin-coverage", active_lenses)
        self.assertIn("internal-tools", active_lenses)
        self.assertNotIn("cargo-audit-scan", active_lenses)

    def test_render_fullscan_reports_active_and_standby_lenses(self):
        changed = {"docs/README.md"}
        checks, focuses, lenses = m.build_plan(changed)
        self.assertEqual(checks, [])
        self.assertEqual(focuses, [])

        rendered = m.render_fullscan(changed, checks, lenses)
        self.assertIn("ACTIVE review lenses", rendered)
        self.assertIn("code-review", rendered)
        self.assertIn("diff-scan", rendered)
        self.assertIn("STANDBY review lenses", rendered)
        self.assertIn("cargo-audit-scan", rendered)
        self.assertIn("No Rust dependency manifest or lockfile changed", rendered)


if __name__ == "__main__":
    unittest.main()
