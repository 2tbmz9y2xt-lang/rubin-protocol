#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
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
        for pattern in (":(glob)**/*.proto", ":(glob)**/*.cpp", ":(glob)**/*.h"):
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

    def test_staged_changed_files_captures_subdirectory_paths(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            subprocess.run(["git", "init", "-b", "main"], cwd=repo_root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_root, check=True)
            nested = repo_root / "clients" / "go" / "node"
            nested.mkdir(parents=True)
            tracked = nested / "config.go"
            tracked.write_text("package node\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo_root, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=repo_root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tracked.write_text("package node\n\nconst x = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", str(tracked.relative_to(repo_root))], cwd=repo_root, check=True)
            files = m.staged_changed_files(repo_root)
            self.assertEqual(files, ["clients/go/node/config.go"])
            bundle = m.staged_bundle(repo_root)
            self.assertIn("clients/go/node/config.go", bundle)
            self.assertIn("+const x = 1", bundle)

    def test_load_contract_rejects_non_string_family_fields(self):
        with tempfile.TemporaryDirectory() as td:
            contract_path = Path(td) / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "self_audit": {
                            "prompt_pack_version": "self-audit-v1",
                            "required_pattern_families": [
                                {
                                    "id": 7,
                                    "title": "Family",
                                    "checks": ["ok"],
                                }
                            ],
                        }
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                m.load_self_audit_contract(contract_path)

    def test_load_contract_rejects_non_string_checks(self):
        with tempfile.TemporaryDirectory() as td:
            contract_path = Path(td) / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "self_audit": {
                            "prompt_pack_version": "self-audit-v1",
                            "required_pattern_families": [
                                {
                                    "id": "family",
                                    "title": "Family",
                                    "checks": ["ok", {"bad": True}],
                                }
                            ],
                        }
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                m.load_self_audit_contract(contract_path)


if __name__ == "__main__":
    unittest.main()
