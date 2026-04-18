#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
PREFLIGHT = TOOLS_DIR / "rubin_q_preflight.sh"


def run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=check,
    )


def init_repo() -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    run(["git", "init"], root)
    run(["git", "config", "user.name", "Test User"], root)
    run(["git", "config", "user.email", "test@example.com"], root)
    run(["git", "branch", "-M", "main"], root)
    (root / "tools" / "agent_tasks").mkdir(parents=True, exist_ok=True)
    (root / "clients" / "go" / "node").mkdir(parents=True, exist_ok=True)
    (root / "clients" / "go" / "node" / "sync.go").write_text("package node\n", encoding="utf-8")
    run(["git", "add", "."], root)
    run(["git", "commit", "-m", "baseline"], root)
    head = run(["git", "rev-parse", "HEAD"], root).stdout.strip()
    run(["git", "update-ref", "refs/remotes/origin/main", head], root)
    manifest_path = root / "tools" / "agent_tasks" / "Q-TEST.json"
    return td, root, manifest_path


class QPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td, self.repo_root, self.manifest_path = init_repo()
        self.addCleanup(self._td.cleanup)

    def write_manifest(self, required_tests: list[str]) -> None:
        payload = {
            "q_id": "Q-IMPL-NODE-TEST-01",
            "owner_area": "node",
            "allowed_files": ["clients/go/node/sync.go"],
            "allowed_globs": [],
            "forbidden_globs": [],
            "required_tests": required_tests,
            "hard_production_loc": 250,
            "required_invariants": [
                "scope",
                "state_ownership",
                "lock_io",
                "failure_atomicity",
                "go_rust_parity",
                "caller_fuzz_test_sweep",
                "test_stability"
            ],
        }
        self.manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    def test_preflight_fails_when_required_test_fails(self):
        self.write_manifest(["printf ok", "exit 1"])

        result = run(
            [str(PREFLIGHT), str(self.manifest_path)],
            self.repo_root,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BLOCKED: q preflight", result.stdout)

    def test_preflight_passes_on_clean_manifest(self):
        self.write_manifest(["printf ok"])
        target = self.repo_root / "clients" / "go" / "node" / "sync.go"
        target.write_text("package node\n\nfunc Sync() {}\n", encoding="utf-8")

        result = run(
            [str(PREFLIGHT), str(self.manifest_path)],
            self.repo_root,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("PASS: q preflight", result.stdout)


if __name__ == "__main__":
    unittest.main()
