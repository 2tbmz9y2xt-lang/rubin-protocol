#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import self_audit_prompt_pack as m


class SelfAuditPromptPackTests(unittest.TestCase):
    def test_compose_prompt_includes_pattern_replay(self):
        contract = {
            "prompt_pack_version": "self-audit-v1",
            "required_pattern_families": [
                {
                    "id": "exact-native-suite-params",
                    "title": "Exact native-suite parameter binding",
                    "checks": [
                        "Reject empty alias strings.",
                        "Enforce exact ML-DSA-87 lengths.",
                    ],
                }
            ],
        }
        prompt = m.compose_prompt(
            contract=contract,
            bundle_text="--- STAGED PATCH ---\n+new line",
        )
        self.assertIn("Prompt Pack: self-audit-v1", prompt)
        self.assertIn("Required pattern replay:", prompt)
        self.assertIn("Exact native-suite parameter binding [exact-native-suite-params]", prompt)
        self.assertIn("Reject empty alias strings.", prompt)
        self.assertIn("Mandatory self-audit output before receipt refresh:", prompt)
        self.assertIn("Staged diff bundle follows.", prompt)

    def test_load_contract_reads_self_audit_section(self):
        contract = m.load_self_audit_contract()
        self.assertEqual(contract["prompt_pack_version"], "self-audit-v1")
        self.assertTrue(contract["required_pattern_families"])

    def test_normalize_repo_root_requires_git_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                m.normalize_repo_root(Path(tmp))

    def test_reviewable_paths_include_native_extensions(self):
        for pattern in ("*.proto", "*.cpp", "*.h"):
            self.assertIn(pattern, m.REVIEWABLE_PATHS)

    def test_staged_bundle_falls_back_to_head_bundle(self):
        with mock.patch.object(m, "staged_changed_files", return_value=[]), mock.patch.object(
            m, "head_changed_files", return_value=["tools/self_audit_prompt_pack.py"]
        ), mock.patch.object(m, "run_git") as run_git:
            run_git.side_effect = [
                "stat-output",
                "patch-output",
                "03b3e85",
            ]
            bundle = m.staged_bundle(Path("/tmp/repo"))
        self.assertIn("MODE=head", bundle)
        self.assertIn("--- REVIEW CHANGED FILES ---", bundle)
        self.assertIn("tools/self_audit_prompt_pack.py", bundle)


if __name__ == "__main__":
    unittest.main()
