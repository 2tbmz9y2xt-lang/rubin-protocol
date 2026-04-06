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

import self_audit_receipt as m


class SelfAuditReceiptTests(unittest.TestCase):
    def init_repo(self, root: Path) -> None:
        subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        (root / "tools").mkdir()
        (root / "tools" / "prepush_review_contract.json").write_text(
            json.dumps(
                {
                    "self_audit": {
                        "prompt_pack_version": "self-audit-v1",
                        "required_pattern_families": [
                            {
                                "id": "family",
                                "title": "Family",
                                "checks": ["check one"],
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
        (root / "tools" / "self_audit_prompt_pack.py").write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "import argparse\n"
            "ap = argparse.ArgumentParser()\n"
            "ap.add_argument('--repo-root', required=True)\n"
            "ap.add_argument('--output', required=True)\n"
            "args = ap.parse_args()\n"
            "Path(args.output).write_text('prompt', encoding='utf-8')\n",
            encoding="utf-8",
        )
        (root / "README.md").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_write_and_check_fresh_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            result = m.write_receipt(repo_root, source="test")
            self.assertTrue(result["fresh"])
            checked = m.check_commit(repo_root)
            self.assertTrue(checked["fresh"])
            self.assertEqual(checked["reason"], "fresh")

    def test_check_detects_contract_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            m.write_receipt(repo_root, source="test")
            (repo_root / "tools" / "prepush_review_contract.json").write_text(
                json.dumps(
                    {
                        "self_audit": {
                            "prompt_pack_version": "self-audit-v2",
                            "required_pattern_families": [{"id": "family", "title": "Family", "checks": ["changed"]}],
                        }
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            checked = m.check_commit(repo_root)
            self.assertFalse(checked["fresh"])
            self.assertEqual(checked["reason"], "review-contract-mismatch")

    def test_check_detects_prompt_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            payload = m.write_receipt(repo_root, source="test")
            Path(payload["receipt"]["prompt_path"]).write_text("different", encoding="utf-8")
            checked = m.check_commit(repo_root)
            self.assertFalse(checked["fresh"])
            self.assertEqual(checked["reason"], "self-audit-prompt-mismatch")

    def test_check_rejects_schema_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            self.init_repo(repo_root)
            payload = m.write_receipt(repo_root, source="test")
            receipt_path = Path(payload["receipt_path"])
            data = json.loads(receipt_path.read_text(encoding="utf-8"))
            data["schema_version"] = 999
            receipt_path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            checked = m.check_commit(repo_root)
            self.assertFalse(checked["fresh"])
            self.assertEqual(checked["reason"], "schema-mismatch")


if __name__ == "__main__":
    unittest.main()
