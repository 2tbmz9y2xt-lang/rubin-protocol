#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
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

        checks, focuses, lenses, profile = m.build_plan(changed)
        check_names = {name for name, _cmd in checks}
        active_lenses = {lens.name for lens in lenses if lens.active}

        self.assertEqual(profile.name, "consensus_critical")
        self.assertEqual(profile.check_type, "consensus_critical")
        self.assertIn("conformance_fixtures_policy", check_names)
        self.assertIn("conformance_matrix", check_names)
        self.assertIn("formal_refinement_bridge", check_names)
        self.assertIn("consensus_openssl_source_policy", check_names)
        self.assertIn("go_verify_sig_smoke", check_names)
        self.assertIn("rust_verify_sig_smoke", check_names)
        self.assertTrue(any("OpenSSL isolation" in focus for focus in focuses))
        self.assertEqual(profile.model, "gpt-5.4")
        self.assertEqual(profile.model_reasoning_effort, "xhigh")
        self.assertEqual(profile.combine_review_units_when_at_most, 4)
        self.assertEqual(
            profile.required_lenses,
            ("code-review", "diff-scan", "combined-security-scan", "semgrep-scan", "rubin-coverage"),
        )
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
        checks, focuses, lenses, profile = m.build_plan(changed)
        self.assertEqual(checks, [])
        self.assertEqual(focuses, [])
        self.assertEqual(profile.name, "diff_only")

        rendered = m.render_fullscan(changed, checks, lenses, profile)
        self.assertIn("Selected review profile: diff_only", rendered)
        self.assertIn("Check type: diff_only", rendered)
        self.assertIn("PROFILE-REQUIRED review lenses", rendered)
        self.assertIn("PROFILE-CONDITIONAL active review lenses", rendered)
        self.assertIn("code-review", rendered)
        self.assertIn("diff-scan", rendered)
        self.assertIn("Model route: gpt-5.4-mini (xhigh), combine-if-paths<=6", rendered)
        self.assertIn("STANDBY review lenses", rendered)
        self.assertIn("cargo-audit-scan", rendered)
        self.assertIn("No Rust dependency manifest or lockfile changed", rendered)

    def test_read_changed_files_supports_nul_delimited_payload_and_render_sanitizes_paths(self):
        with tempfile.TemporaryDirectory() as td:
            changed_path = Path(td) / "changed.txt"
            changed_path.write_text("safe.py\0evil\nname.py\0", encoding="utf-8")
            changed = m.read_changed_files(changed_path)

        self.assertIn("safe.py", changed)
        self.assertIn("evil\nname.py", changed)

        rendered = m.render_fullscan(
            changed,
            [],
            [],
            m.ReviewProfile(name="diff_only", check_type="diff_only", why="test"),
        )
        self.assertIn("evil\\nname.py", rendered)
        self.assertNotIn("evil\nname.py", rendered)

    def test_render_fullscan_caps_changed_file_listing(self):
        changed = {f"path-{idx}.py" for idx in range(m.MAX_RENDERED_CHANGED_PATHS + 3)}
        rendered = m.render_fullscan(
            changed,
            [],
            [],
            m.ReviewProfile(name="diff_only", check_type="diff_only", why="test"),
        )

        self.assertIn("+3 more files omitted from the supplement", rendered)

    def test_build_plan_selects_code_noncritical_profile_for_non_consensus_rust(self):
        changed = {"clients/rust/crates/rubin-node/src/txpool.rs"}
        checks, focuses, lenses, profile = m.build_plan(changed)

        self.assertEqual(checks, [])
        self.assertEqual(focuses, [])
        self.assertEqual(profile.name, "code_noncritical")
        self.assertEqual(profile.check_type, "code_noncritical")
        self.assertEqual(profile.model, "gpt-5.4-mini")
        self.assertEqual(profile.model_reasoning_effort, "xhigh")
        self.assertEqual(
            profile.required_lenses,
            ("code-review", "diff-scan", "combined-security-scan", "semgrep-scan"),
        )
        self.assertTrue(any(lens.name == "combined-security-scan" and lens.active for lens in lenses))

    def test_build_plan_selects_diff_only_profile_for_tooling_only(self):
        changed = {"tools/check_local_prepush_skill_gates.py", "tools/tests/test_local_prepush_skill_gates.py"}
        checks, focuses, lenses, profile = m.build_plan(changed)

        self.assertEqual(profile.name, "diff_only")
        self.assertEqual(profile.check_type, "diff_only")
        self.assertEqual(profile.model, "gpt-5.4-mini")
        self.assertEqual(profile.model_reasoning_effort, "xhigh")
        self.assertEqual(profile.required_lenses, ("code-review", "diff-scan"))
        self.assertTrue(any(lens.name == "internal-tools" and lens.active for lens in lenses))

    def test_build_plan_override_formal_lean(self):
        changed = {"clients/rust/crates/rubin-node/src/txpool.rs"}
        checks, focuses, _lenses, profile = m.build_plan(changed, check_type_override="formal_lean")

        self.assertEqual(checks, [])
        self.assertEqual(focuses, [])
        self.assertEqual(profile.check_type, "formal_lean")
        self.assertEqual(profile.model, "gpt-5.4")
        self.assertEqual(profile.model_reasoning_effort, "xhigh")

    def test_build_plan_auto_selects_formal_lean_for_lean_only_changes(self):
        changed = {"rubin-formal/RubinFormal/Conformance/CVUtxoBasicVectors.lean"}
        checks, focuses, _lenses, profile = m.build_plan(changed)

        self.assertIn("lean_conformance_staleness", {name for name, _cmd in checks})
        self.assertIn("formal_refinement_bridge", {name for name, _cmd in checks})
        self.assertTrue(any("Formal bridge sync" in focus for focus in focuses))
        self.assertEqual(profile.name, "formal_lean")
        self.assertEqual(profile.check_type, "formal_lean")
        self.assertEqual(profile.model, "gpt-5.4")
        self.assertEqual(profile.model_reasoning_effort, "xhigh")

    def test_build_plan_auto_keeps_consensus_critical_for_mixed_lean_and_runtime_consensus(self):
        changed = {
            "rubin-formal/RubinFormal/Conformance/CVUtxoBasicVectors.lean",
            "clients/go/consensus/verify_sig_openssl.go",
        }
        checks, focuses, _lenses, profile = m.build_plan(changed)

        self.assertIn("go_verify_sig_smoke", {name for name, _cmd in checks})
        self.assertTrue(any("OpenSSL isolation" in focus for focus in focuses))
        self.assertEqual(profile.name, "consensus_critical")
        self.assertEqual(profile.check_type, "consensus_critical")

    def test_build_plan_rejects_unsupported_check_type(self):
        with self.assertRaisesRegex(ValueError, "unsupported check_type"):
            m.build_plan({"README.md"}, check_type_override="not-a-check")

    def test_unknown_profile_lens_fails_closed(self):
        profile = m.ReviewProfile(
            name="diff_only",
            check_type="diff_only",
            why="test",
            required_lenses=("code-review", "missing-lens"),
        )
        lenses = [m.ScanLens(name="code-review", active=True, why="test", guidance="test")]

        with self.assertRaisesRegex(ValueError, "unknown review lenses"):
            m.ensure_known_profile_lenses(profile, lenses)

    def test_missing_contract_fails_closed(self):
        missing = Path(tempfile.mkdtemp()) / "missing-contract.json"

        with self.assertRaisesRegex(ValueError, "is missing"):
            m.load_profile_contract("diff_only", path=missing)

    def test_empty_conditional_lenses_are_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            contract_path = Path(td) / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "schema_version": 4,
                        "default_profile": "diff_only",
                        "profiles": {
                            "diff_only": {
                                "model": "gpt-5.4-mini",
                                "model_reasoning_effort": "xhigh",
                                "stall_seconds": 60,
                                "combine_review_units_when_at_most": 6,
                                "required_lenses": ["code-review", "diff-scan"],
                                "conditional_lenses": [],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            profile = m.load_profile_contract("diff_only", path=contract_path)

        self.assertEqual(profile.conditional_lenses, ())

    def test_zero_combine_threshold_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            contract_path = Path(td) / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "schema_version": 4,
                        "default_profile": "diff_only",
                        "profiles": {
                            "diff_only": {
                                "model": "gpt-5.4-mini",
                                "model_reasoning_effort": "xhigh",
                                "stall_seconds": 60,
                                "combine_review_units_when_at_most": 0,
                                "required_lenses": ["code-review", "diff-scan"],
                                "conditional_lenses": [],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "expected >= 1"):
                m.load_profile_contract("diff_only", path=contract_path)


if __name__ == "__main__":
    unittest.main()
