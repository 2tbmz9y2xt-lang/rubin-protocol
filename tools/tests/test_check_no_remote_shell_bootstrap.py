#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_no_remote_shell_bootstrap as m


class RemoteShellBootstrapTests(unittest.TestCase):
    def write_workflow(self, root: Path, name: str, body: str) -> Path:
        workflow_dir = root / ".github" / "workflows"
        workflow_dir.mkdir(parents=True, exist_ok=True)
        path = workflow_dir / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_rejects_process_substitution_bootstrap(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: bash <(curl -fsSL https://coverage.codacy.com/get.sh) report\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_pipe_to_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_shell_across_lines(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: |\n          curl -fsSL https://example.com/install.sh |\n            bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_eval_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: eval "$(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("eval command substitution", violations[0])

    def test_allows_pinned_download_to_file(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "ok.yml",
                "jobs:\n  cov:\n    steps:\n      - run: curl -fsSL https://example.com/reporter -o /tmp/reporter\n      - run: bash ./scripts/codacy-coverage-reporter.sh report --partial\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
