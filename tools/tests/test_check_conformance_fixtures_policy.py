#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOL = Path(__file__).resolve().parents[1] / "check_conformance_fixtures_policy.py"
CHANGELOG = "conformance/fixtures/CHANGELOG.md"
DASH = "—"
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def git(repo: Path, *args: str, check: bool = True, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603
        ["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, *args],
        cwd=repo, text=True, capture_output=True, check=check, input=stdin,
    )


def commit(repo: Path, msg: str, **files: str) -> str:
    for rel, text in files.items():
        path = repo / rel.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def new_repo(root: Path, branch: str = "main") -> Path:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", branch)
    return repo


def seed(repo: Path) -> str:
    return commit(
        repo, "c0",
        **{
            ".github__workflows__ci.yml": "name: ci\n",
            "conformance__fixtures__CHANGELOG.md": "# Changelog\n",
            "conformance__fixtures__CV-Y.json": "{}\n",
            "conformance__fixtures__CV-X.json": "{}\n",
            "README": "r\n",
        },
    )


def set_origin_main(repo: Path, sha: str) -> None:
    git(repo, "update-ref", "refs/remotes/origin/main", sha)


def unrelated_commit(repo: Path) -> str:
    tree = git(repo, "mktree", stdin="").stdout.strip()
    return git(repo, "commit-tree", tree, "-m", "unrelated").stdout.strip()


def load_tool():
    spec = importlib.util.spec_from_file_location("policy_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PolicyBase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k != "GITHUB_BASE_REF"}
        env = mock.patch.dict(os.environ, {**clean, **GIT_ENV}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.repo = new_repo(self.root)

    def run_tool(self) -> subprocess.CompletedProcess[str]:
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_BASE_REF"}
        return subprocess.run(  # nosec B603
            [sys.executable, str(TOOL)], cwd=self.repo, env=env, text=True, capture_output=True, check=False
        )

    def in_repo(self, fn):
        old = os.getcwd()
        os.chdir(self.repo)
        try:
            return fn()
        finally:
            os.chdir(old)

    def run_main_in_process(self, wrap=None) -> tuple[int, str, list[list[str]]]:
        mod = load_tool()
        calls: list[list[str]] = []
        real = mod.run

        def spy(cmd, **kw):
            calls.append(list(cmd))
            return wrap(real, cmd, kw) if wrap else real(cmd, **kw)

        mod.run = spy
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = self.in_repo(mod.main)
        return rc, err.getvalue(), calls

    def policy_lines(self, stderr: str) -> list[str]:
        return [l for l in stderr.splitlines() if l.startswith("policy:")]

    def ab_repo(self) -> None:
        """c0 on main, c1 on main, feat branch with c2 (fixture + CHANGELOG entry); origin/main = c0."""
        c0 = seed(self.repo)
        commit(self.repo, "c1", README="1\n")
        git(self.repo, "checkout", "-q", "-b", "feat")
        (self.repo / "conformance/fixtures/CV-Y.json").write_text('{"v":2}\n', encoding="utf-8")
        (self.repo / CHANGELOG).write_text("# Changelog\n- CV-Y.json updated\n", encoding="utf-8")
        commit(self.repo, "c2", README="2\n")
        set_origin_main(self.repo, c0)

    def assert_no_merge_base(self, ref: str) -> None:
        self.assertNotEqual(git(self.repo, "diff", "--name-only", f"{ref}...HEAD", check=False).returncode, 0)


class ProbeTests(PolicyBase):
    def test_a1_probe_resolves_existing_refs(self):
        c0 = seed(self.repo)
        set_origin_main(self.repo, c0)
        mod = load_tool()
        for ref in ("HEAD", "main", "origin/main", c0):
            with self.subTest(ref=ref):
                self.assertTrue(self.in_repo(lambda: mod.git_ref_exists(ref)))

    def test_r2_probe_rejects_missing_ref(self):
        seed(self.repo)
        mod = load_tool()
        self.assertFalse(self.in_repo(lambda: mod.git_ref_exists("nope")))

    def test_r3_old_probe_form_recorded_only(self):
        seed(self.repo)
        p = git(self.repo, "rev-parse", "--verify", "--quiet", "--", "HEAD", check=False)
        print(f"R3 informational: old probe form rc={p.returncode}", file=sys.stderr)


class SelectionTests(PolicyBase):
    def test_a2_origin_main_selected_once(self):
        self.ab_repo()
        mod = load_tool()
        self.assertEqual(self.in_repo(mod.select_diff_ref), "origin/main...HEAD")
        p = self.run_tool()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.policy_lines(p.stderr), ["policy: diff range = origin/main...HEAD"])

    def test_a3_main_selected_without_origin(self):
        self.ab_repo()
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/main")
        mod = load_tool()
        self.assertEqual(self.in_repo(mod.select_diff_ref), "main...HEAD")
        p = self.run_tool()
        self.assertEqual(self.policy_lines(p.stderr), ["policy: diff range = main...HEAD"])

    def test_h1_neither_ref_falls_back_visibly(self):
        git(self.repo, "checkout", "-q", "-b", "trunk")
        seed(self.repo)
        commit(self.repo, "c1", README="1\n")
        self.assertNotEqual(git(self.repo, "rev-parse", "--verify", "--quiet", "main^{commit}", check=False).returncode, 0)
        p = self.run_tool()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(
            self.policy_lines(p.stderr),
            [f"policy: origin/main and main unresolved {DASH} falling back to HEAD~1..HEAD",
             "policy: diff range = HEAD~1..HEAD"],
        )
        mod = load_tool()
        eff: list[str] = []
        self.assertIn("README", self.in_repo(lambda: mod.changed_files("HEAD~1..HEAD", eff)))
        self.assertEqual(eff, ["HEAD~1..HEAD"])

    def test_h2_unsafe_base_ref_never_reaches_git(self):
        self.ab_repo()
        with mock.patch.dict(os.environ, {"GITHUB_BASE_REF": "-x"}):
            rc, err, calls = self.run_main_in_process()
        self.assertEqual(rc, 0, err)
        self.assertIn("WARN: ignoring unsafe GITHUB_BASE_REF='-x'", err)
        self.assertEqual(self.policy_lines(err), ["policy: diff range = origin/main...HEAD"])
        self.assertFalse([c for c in calls if any("-x" in part for part in c)])
        self.assertFalse([c for c in calls if c[:2] == ["git", "fetch"]])


class RangeTests(PolicyBase):
    def test_a4_merge_commit_ignores_base_fixture_changes(self):
        c0 = seed(self.repo)
        git(self.repo, "checkout", "-q", "-b", "feat")
        commit(self.repo, "b1", README="b\n")
        git(self.repo, "checkout", "-q", "main")
        (self.repo / "conformance/fixtures/CV-X.json").write_text('{"v":2}\n', encoding="utf-8")
        (self.repo / CHANGELOG).write_text("# Changelog\n- CV-X updated\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "m1")
        tip = git(self.repo, "rev-parse", "HEAD").stdout.strip()
        set_origin_main(self.repo, tip)
        git(self.repo, "checkout", "-q", "feat")
        git(self.repo, "merge", "-q", "--no-ff", "-m", "merge", "main")
        self.assertEqual(git(self.repo, "rev-parse", "HEAD^2").stdout.strip(), tip)
        self.assertNotEqual(c0, tip)
        p = self.run_tool()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("OK:", p.stdout)
        self.assertEqual(self.policy_lines(p.stderr), ["policy: diff range = origin/main...HEAD"])
        mod = load_tool()
        eff: list[str] = []
        changed = self.in_repo(lambda: mod.changed_files("origin/main...HEAD", eff))
        self.assertNotIn("conformance/fixtures/CV-X.json", changed)

    def test_a5_changelog_in_earlier_commit_is_seen(self):
        c0 = seed(self.repo)
        set_origin_main(self.repo, c0)
        (self.repo / CHANGELOG).write_text("# Changelog\n- CV-Y.json updated\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "log")
        (self.repo / "conformance/fixtures/CV-Y.json").write_text('{"v":2}\n', encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "fixture")
        p = self.run_tool()
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_r1_fixture_change_in_earlier_commit_is_seen(self):
        c0 = seed(self.repo)
        set_origin_main(self.repo, c0)
        (self.repo / "conformance/fixtures/CV-Y.json").write_text('{"v":2}\n', encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "fixture")
        commit(self.repo, "other", README="o\n")
        p = self.run_tool()
        self.assertEqual(p.returncode, 1)
        self.assertIn("ERROR: fixture JSON changed but conformance/fixtures/CHANGELOG.md not updated", p.stderr)

    def _h3_repo(self) -> None:
        seed(self.repo)
        set_origin_main(self.repo, unrelated_commit(self.repo))
        (self.repo / "conformance/fixtures/CV-Y.json").write_text('{"v":2}\n', encoding="utf-8")
        (self.repo / CHANGELOG).write_text("# Changelog\n- CV-Y.json updated\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "fixture and log")
        self.assert_no_merge_base("origin/main")

    def test_h3_failing_range_falls_back_for_both_consumers(self):
        self._h3_repo()
        p = self.run_tool()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(
            self.policy_lines(p.stderr),
            [f"policy: git diff origin/main...HEAD failed {DASH} falling back to HEAD~1..HEAD",
             "policy: diff range = HEAD~1..HEAD"],
        )
        mod = load_tool()
        eff: list[str] = []
        changed = self.in_repo(lambda: mod.changed_files("origin/main...HEAD", eff))
        self.assertIn("conformance/fixtures/CV-Y.json", changed)
        self.assertIn(CHANGELOG, changed)
        self.assertEqual(eff, ["HEAD~1..HEAD"])

    def test_h3_changelog_hunk_outside_fallback_range_is_rejected(self):
        seed(self.repo)
        set_origin_main(self.repo, unrelated_commit(self.repo))
        commit(self.repo, "log", **{"conformance__fixtures__CHANGELOG.md": "# Changelog\n- CV-Y.json updated\n"})
        (self.repo / "conformance/fixtures/CV-Y.json").write_text('{"v":2}\n', encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "fixture only")
        self.assert_no_merge_base("origin/main")
        p = self.run_tool()
        self.assertEqual(p.returncode, 1)
        self.assertIn("ERROR: fixture JSON changed but conformance/fixtures/CHANGELOG.md not updated", p.stderr)

    def _no_commit_lines(self, first: list[str]) -> list[str]:
        return first + [f"policy: git diff HEAD~1..HEAD failed {DASH} no committed changes inspected",
                        "policy: diff range = none"]

    def _untracked_fixture_stays_ignored(self, diff_ref: str) -> None:
        (self.repo / "conformance/fixtures/CV-Z.json").write_text("{}\n", encoding="utf-8")
        mod = load_tool()
        eff: list[str] = []
        self.assertEqual(self.in_repo(lambda: mod.changed_files(diff_ref, eff)), [])
        self.assertEqual(eff, ["none"])

    def test_h5_single_commit_no_refs(self):
        git(self.repo, "checkout", "-q", "-b", "trunk")
        seed(self.repo)
        self.assertNotEqual(git(self.repo, "rev-parse", "HEAD~1", check=False).returncode, 0)
        p = self.run_tool()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(
            self.policy_lines(p.stderr),
            self._no_commit_lines([f"policy: origin/main and main unresolved {DASH} falling back to HEAD~1..HEAD"]),
        )
        self._untracked_fixture_stays_ignored("HEAD~1..HEAD")

    def test_h7_both_ranges_fail(self):
        seed(self.repo)
        set_origin_main(self.repo, unrelated_commit(self.repo))
        self.assert_no_merge_base("origin/main")
        self.assertNotEqual(git(self.repo, "rev-parse", "HEAD~1", check=False).returncode, 0)
        p = self.run_tool()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(
            self.policy_lines(p.stderr),
            self._no_commit_lines([f"policy: git diff origin/main...HEAD failed {DASH} falling back to HEAD~1..HEAD"]),
        )
        self._untracked_fixture_stays_ignored("origin/main...HEAD")

    def test_h6_committed_changelog_diff_failure_is_visible(self):
        c0 = seed(self.repo)
        set_origin_main(self.repo, c0)
        (self.repo / CHANGELOG).write_text("# Changelog\n- CV-Y.json updated\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "log")
        (self.repo / "conformance/fixtures/CV-Y.json").write_text('{"v":2}\n', encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "fixture")
        failing = ["git", "diff", "--unified=0", "origin/main...HEAD", "--", CHANGELOG]

        def wrap(real, cmd, kw):
            if list(cmd) == failing:
                return subprocess.CompletedProcess(cmd, 1, "", "injected")
            return real(cmd, **kw)

        rc, err, calls = self.run_main_in_process(wrap)
        self.assertEqual(rc, 1)
        self.assertIn(f"policy: git diff origin/main...HEAD -- {CHANGELOG} failed {DASH} committed CHANGELOG text not inspected", err)
        self.assertIn("ERROR: CHANGELOG.md missing fresh entry for changed fixture CV-Y.json", err)
        self.assertIn(["git", "diff", "--unified=0", "--", CHANGELOG], calls)
        self.assertIn(["git", "diff", "--cached", "--unified=0", "--", CHANGELOG], calls)


if __name__ == "__main__":
    unittest.main()
