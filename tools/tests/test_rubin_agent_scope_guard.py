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

import rubin_agent_scope_guard as m
from rubin_agent_contract import CANONICAL_INVARIANTS, GitCommandError


def run(cmd: list[str], cwd: Path) -> str:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def init_repo() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    run(["git", "init"], root)
    run(["git", "config", "user.name", "Test User"], root)
    run(["git", "config", "user.email", "test@example.com"], root)
    run(["git", "config", "commit.gpgsign", "false"], root)
    run(["git", "branch", "-M", "main"], root)
    (root / "tools" / "agent_tasks").mkdir(parents=True, exist_ok=True)
    (root / "clients" / "go" / "node").mkdir(parents=True, exist_ok=True)
    (root / "clients" / "rust" / "crates" / "rubin-node" / "src").mkdir(parents=True, exist_ok=True)
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "clients" / "go" / "node" / "sync.go").write_text("package node\n", encoding="utf-8")
    (root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "p2p_runtime.rs").write_text(
        "pub fn relay() {}\n",
        encoding="utf-8",
    )
    (root / "docs" / "note.md").write_text("baseline\n", encoding="utf-8")
    run(["git", "add", "."], root)
    run(["git", "commit", "-m", "baseline"], root)
    head = run(["git", "rev-parse", "HEAD"], root)
    run(["git", "update-ref", "refs/remotes/origin/main", head], root)
    return td, root


class ScopeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td, self.repo_root = init_repo()
        self.addCleanup(self._td.cleanup)

    def write_manifest(self, payload: dict[str, object]) -> Path:
        path = self.repo_root / "tools" / "agent_tasks" / "Q-TEST.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def runtime_manifest(self) -> dict[str, object]:
        return {
            "q_id": "Q-IMPL-NODE-TEST-01",
            "owner_area": "node",
            "allowed_files": ["clients/go/node/sync.go"],
            "allowed_globs": [],
            "forbidden_globs": [
                ".cursor/**",
                ".claude/**",
                ".github/workflows/**",
                "tools/**",
                "docs/**",
            ],
            "required_tests": ["printf ok"],
            "target_production_loc": 10,
            "hard_production_loc": 20,
            "required_invariants": list(CANONICAL_INVARIANTS),
        }

    def test_fails_on_file_outside_allowed_files(self):
        manifest = self.write_manifest(self.runtime_manifest())
        extra = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "p2p_runtime.rs"
        extra.write_text("pub fn drift() {\n    let _x = 1;\n}\n", encoding="utf-8")

        blockers, warnings = m.evaluate_scope(manifest, "HEAD")

        self.assertFalse(warnings)
        self.assertTrue(any("outside allowed_files/allowed_globs" in item for item in blockers))

    def test_fails_on_default_forbidden_glob_touch(self):
        manifest = self.write_manifest(self.runtime_manifest())
        touched = self.repo_root / "docs" / "note.md"
        touched.write_text("drift\nmore drift\n", encoding="utf-8")

        blockers, warnings = m.evaluate_scope(manifest, "HEAD")

        self.assertFalse(warnings)
        self.assertTrue(any("forbidden surface" in item for item in blockers))

    def test_warns_over_target_loc_and_fails_over_hard_loc(self):
        manifest = self.write_manifest(self.runtime_manifest())
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["target_production_loc"] = 3
        payload["hard_production_loc"] = 5
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        target = self.repo_root / "clients" / "go" / "node" / "sync.go"
        target.write_text(
            "package node\n\nfunc A() {}\nfunc B() {}\nfunc C() {}\nfunc D() {}\nfunc E() {}\n",
            encoding="utf-8",
        )

        blockers, warnings = m.evaluate_scope(manifest, "HEAD")

        self.assertTrue(any("above target_production_loc" in item for item in warnings))
        self.assertTrue(any("above hard_production_loc" in item for item in blockers))

    def test_fails_when_origin_main_missing_for_default_diff_range(self):
        manifest = self.write_manifest(self.runtime_manifest())
        run(["git", "update-ref", "-d", "refs/remotes/origin/main"], self.repo_root)

        with self.assertRaises(GitCommandError) as ctx:
            m.evaluate_scope(manifest, None)

        self.assertIn("origin/main", str(ctx.exception))

    def test_default_diff_catches_untracked_file_outside_scope(self):
        manifest = self.write_manifest(self.runtime_manifest())
        extra = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "new_sync.rs"
        extra.write_text("pub fn drift() {}\n", encoding="utf-8")

        blockers, warnings = m.evaluate_scope(manifest, None)

        self.assertFalse(warnings)
        self.assertTrue(any("outside allowed_files/allowed_globs" in item for item in blockers))

    def test_runtime_defaults_enforce_forbidden_globs_when_manifest_omits_them(self):
        payload = self.runtime_manifest()
        payload.pop("forbidden_globs")
        manifest = self.write_manifest(payload)
        touched = self.repo_root / "docs" / "note.md"
        touched.write_text("runtime drift\n", encoding="utf-8")

        blockers, warnings = m.evaluate_scope(manifest, None)

        self.assertFalse(warnings)
        self.assertTrue(any("forbidden surface" in item for item in blockers))

    def test_runtime_defaults_allow_manifest_control_plane_artifact(self):
        payload = self.runtime_manifest()
        payload.pop("forbidden_globs")
        manifest = self.write_manifest(payload)

        blockers, warnings = m.evaluate_scope(manifest, None)

        self.assertFalse(warnings)
        self.assertFalse(blockers)

    def test_fails_on_rename_from_forbidden_source_path(self):
        payload = self.runtime_manifest()
        payload["allowed_globs"] = ["clients/go/node/**"]
        manifest = self.write_manifest(payload)
        run(
            ["git", "mv", "docs/note.md", "clients/go/node/note.md"],
            self.repo_root,
        )
        changed_files = m.list_changed_files(self.repo_root, "HEAD")

        blockers, warnings = m.evaluate_scope(manifest, "HEAD")

        self.assertFalse(warnings)
        self.assertIn("docs/note.md", changed_files)
        self.assertIn("clients/go/node/note.md", changed_files)
        self.assertTrue(
            any("docs/note.md: touched forbidden surface" == item for item in blockers),
            msg=blockers,
        )
        self.assertFalse(
            any("clients/go/node/note.md" in item for item in blockers),
            msg=blockers,
        )


if __name__ == "__main__":
    unittest.main()
