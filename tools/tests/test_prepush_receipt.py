#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import prepush_receipt as m


class PrepushReceiptTests(unittest.TestCase):
    def init_repo(self, root: Path) -> None:
        subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        (root / "README.md").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        subprocess.run(["git", "remote", "add", "origin", str(root)], cwd=root, check=True)
        subprocess.run(["git", "update-ref", "refs/remotes/origin/main", "HEAD"], cwd=root, check=True)

    def test_write_and_check_fresh_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            result = m.write_receipt(repo_root, base_ref="origin/main", source="test")
            self.assertTrue(result["fresh"])
            checked = m.check_receipt(repo_root, base_ref="origin/main")
            self.assertTrue(checked["fresh"])
            self.assertEqual(checked["reason"], "fresh")

    def test_check_detects_dirty_worktree(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            m.write_receipt(repo_root, base_ref="origin/main", source="test")
            (repo_root / "README.md").write_text("dirty\n", encoding="utf-8")
            checked = m.check_receipt(repo_root, base_ref="origin/main")
            self.assertFalse(checked["fresh"])
            self.assertEqual(checked["reason"], "dirty-worktree")

    def test_check_detects_head_change(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            m.write_receipt(repo_root, base_ref="origin/main", source="test")
            (repo_root / "NEXT.md").write_text("next\n", encoding="utf-8")
            subprocess.run(["git", "add", "NEXT.md"], cwd=repo_root, check=True)
            subprocess.run(["git", "commit", "-m", "next"], cwd=repo_root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            checked = m.check_receipt(repo_root, base_ref="origin/main")
            self.assertFalse(checked["fresh"])
            self.assertEqual(checked["reason"], "head-mismatch")

    def test_check_detects_base_ref_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            m.write_receipt(repo_root, base_ref="origin/main", source="test")
            checked = m.check_receipt(repo_root, base_ref="origin/master")
            self.assertFalse(checked["fresh"])
            self.assertEqual(checked["reason"], "base-ref-mismatch")

    def test_check_handles_non_numeric_schema_version_as_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            payload = m.write_receipt(repo_root, base_ref="origin/main", source="test")
            receipt_path = Path(payload["receipt_path"])
            data = json.loads(receipt_path.read_text(encoding="utf-8"))
            data["schema_version"] = "broken"
            receipt_path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            checked = m.check_receipt(repo_root, base_ref="origin/main")
            self.assertFalse(checked["fresh"])
            self.assertEqual(checked["reason"], "schema-malformed")

    def test_write_outputs_json_serializable_payload(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            payload = m.write_receipt(repo_root, base_ref="origin/main", source="test")
            json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
