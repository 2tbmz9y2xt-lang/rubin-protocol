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

import rubin_invariant_scan as m
from rubin_agent_contract import CANONICAL_INVARIANTS


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
    (root / "clients" / "go" / "node" / "tests").mkdir(parents=True, exist_ok=True)
    (root / "clients" / "rust" / "crates" / "rubin-node" / "src").mkdir(parents=True, exist_ok=True)
    (root / "clients" / "rust" / "crates" / "rubin-node" / "tests").mkdir(parents=True, exist_ok=True)
    (root / "clients" / "go" / "node" / "sync.go").write_text("package node\n", encoding="utf-8")
    (root / "clients" / "go" / "node" / "tests" / "sync_test.go").write_text(
        "package tests\n",
        encoding="utf-8",
    )
    (root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "p2p_runtime.rs").write_text(
        "pub fn relay() {}\n",
        encoding="utf-8",
    )
    (root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "dropper.rs").write_text(
        "struct Dropper;\n",
        encoding="utf-8",
    )
    (root / "clients" / "rust" / "crates" / "rubin-node" / "tests" / "cwd.rs").write_text(
        "#[test]\nfn t() {}\n",
        encoding="utf-8",
    )
    (root / "clients" / "rust" / "crates" / "rubin-node" / "tests" / "safe.rs").write_text(
        "#[test]\nfn ok() {}\n",
        encoding="utf-8",
    )
    run(["git", "add", "."], root)
    run(["git", "commit", "-m", "baseline"], root)
    head = run(["git", "rev-parse", "HEAD"], root)
    run(["git", "update-ref", "refs/remotes/origin/main", head], root)
    return td, root


class InvariantScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td, self.repo_root = init_repo()
        self.addCleanup(self._td.cleanup)
        manifest_path = self.repo_root / "tools" / "agent_tasks" / "Q-TEST.json"
        manifest = {
            "q_id": "Q-IMPL-NODE-TEST-01",
            "owner_area": "node",
            "allowed_files": ["clients/go/node/sync.go"],
            "allowed_globs": ["clients/**"],
            "forbidden_globs": [],
            "required_tests": ["printf ok"],
            "hard_production_loc": 250,
            "required_invariants": list(CANONICAL_INVARIANTS),
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.manifest_path = manifest_path

    def scan(self) -> list[str]:
        return m.scan_invariants(self.manifest_path, "HEAD")

    def test_fails_on_hidden_test_knob_in_production_file(self):
        target = self.repo_root / "clients" / "go" / "node" / "sync.go"
        target.write_text("package node\nconst knob = \"RUBIN_TEST_ONLY\"\n", encoding="utf-8")

        blockers = self.scan()

        self.assertTrue(any("hidden test knob" in item for item in blockers))

    def test_fails_on_file_line_anchor_comment(self):
        target = self.repo_root / "clients" / "go" / "node" / "sync.go"
        target.write_text("package node\n// see p2p_runtime.rs:123 before editing\n", encoding="utf-8")

        blockers = self.scan()

        self.assertTrue(any("file:line anchor" in item for item in blockers))

    def test_fails_on_inline_file_line_anchor_comment(self):
        target = self.repo_root / "clients" / "go" / "node" / "sync.go"
        target.write_text(
            "package node\nfunc sync() { doWork() // see p2p_runtime.rs:123 before editing\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("file:line anchor" in item for item in blockers))

    def test_fails_on_block_comment_interior_file_line_anchor(self):
        target = self.repo_root / "clients" / "go" / "node" / "sync.go"
        target.write_text(
            "package node\n/*\n * see p2p_runtime.rs:123 before editing\n */\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("file:line anchor" in item for item in blockers))

    def test_fails_on_set_current_dir_in_test(self):
        target = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "tests" / "cwd.rs"
        target.write_text(
            "#[test]\nfn t() {\n    std::env::set_current_dir(\"/\").unwrap();\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("CWD mutation" in item for item in blockers))

    def test_fails_on_brittle_test_path_pattern(self):
        target = self.repo_root / "clients" / "go" / "node" / "tests" / "sync_test.go"
        target.write_text(
            "package tests\n\nfunc T() {\n    _ = \"/nonexistent\"\n    chmod(0)\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("brittle test path or OS-string match" in item for item in blockers))

    def test_fails_on_unwrap_in_runtime_sensitive_path(self):
        target = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "p2p_runtime.rs"
        target.write_text(
            "pub fn relay() {\n    let _value = Some(1).unwrap();\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("unwrap/expect added in runtime-sensitive" in item for item in blockers))

    def test_fails_on_dereference_line_with_unwrap(self):
        target = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "p2p_runtime.rs"
        target.write_text(
            "pub fn relay(slot: &mut Option<i32>) {\n    *slot = Some(1).unwrap();\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("unwrap/expect added in runtime-sensitive" in item for item in blockers))

    def test_fails_on_ufcs_unwrap_in_runtime_sensitive_path(self):
        target = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "p2p_runtime.rs"
        target.write_text(
            "pub fn relay(value: Option<i32>) {\n    let _value = Option::unwrap(value);\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("unwrap/expect added in runtime-sensitive" in item for item in blockers))

    def test_fails_on_panic_in_drop(self):
        target = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "dropper.rs"
        target.write_text(
            "struct Dropper;\n\nimpl Drop for Dropper {\n    fn drop(&mut self) {\n        panic!(\"boom\");\n    }\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("panic-like cleanup added inside impl Drop" in item for item in blockers))

    def test_fails_on_ufcs_expect_in_multiline_drop_impl(self):
        target = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "dropper.rs"
        target.write_text(
            "struct Dropper;\n\nimpl Drop\nfor Dropper\n{\n    fn drop(&mut self) {\n        let _value = Result::<i32, &str>::expect(Err(\"boom\"), \"boom\");\n    }\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("panic-like cleanup added inside impl Drop" in item for item in blockers))

    def test_does_not_flag_test_only_unwrap_in_non_runtime_sensitive_path(self):
        target = self.repo_root / "clients" / "rust" / "crates" / "rubin-node" / "tests" / "safe.rs"
        target.write_text(
            "#[test]\nfn ok() {\n    let _value = Some(1).unwrap();\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertFalse(blockers)

    def test_fails_on_untracked_test_with_brittle_pattern(self):
        target = self.repo_root / "clients" / "go" / "node" / "tests" / "new_sync_test.go"
        target.write_text(
            "package tests\n\nfunc T() {\n    _ = \"Permission denied\"\n}\n",
            encoding="utf-8",
        )

        blockers = self.scan()

        self.assertTrue(any("brittle test path or OS-string match" in item for item in blockers))


if __name__ == "__main__":
    unittest.main()
