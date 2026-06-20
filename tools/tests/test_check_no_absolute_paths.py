from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_no_absolute_paths as m  # noqa: E402


def _init_repo(root: Path) -> None:
    subprocess.run([_git(), "init", "-q"], cwd=root, check=True)  # nosec B603


def _track(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    subprocess.run([_git(), "add", rel], cwd=root, check=True)  # nosec B603


def _git() -> str:
    git = shutil.which("git")
    if git is None:
        raise unittest.SkipTest("git executable not found")
    return git


class CheckNoAbsolutePathsTests(unittest.TestCase):
    def test_repo_root_argument_scans_selected_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _init_repo(root)
            _track(root, "README.md", "repo-relative path only\n")

            self.assertEqual(m.main(["--repo-root", str(root)]), 0)

    def test_disallowed_home_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _init_repo(root)
            path = "/" + "Users" + "/example/project\n"
            _track(root, "README.md", f"local path: {path}")

            self.assertEqual(m.main(["--repo-root", str(root)]), 1)

    def test_default_from_subdir_scans_repo_toplevel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _init_repo(root)
            path = "/" + "Users" + "/example/project\n"
            _track(root, "README.md", f"local path: {path}")
            subdir = root / ".github"
            subdir.mkdir()

            old_cwd = Path.cwd()
            try:
                os.chdir(subdir)
                rc = m.main([])
            finally:
                os.chdir(old_cwd)

        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
