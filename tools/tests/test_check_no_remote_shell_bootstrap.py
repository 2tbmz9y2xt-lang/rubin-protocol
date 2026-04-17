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
        self.assertTrue(violations[0].startswith(".github/workflows/bad.yml:"))

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

    def test_rejects_pipe_with_quoted_curl_command_word(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: 'curl' -fsSL https://example.com/install.sh | bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_dash(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | dash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_assignment_prefixed_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | FOO=1 bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_absolute_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | /bin/bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_env_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | /usr/bin/env bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_env_shell_with_flags(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | env -i bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_env_shell_with_assignments(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | env FOO=bar bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_env_split_string_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | env -S "bash -e"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_env_split_string_shell_without_space_after_pipe(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh |env -S "bash -e"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_env_split_string_long_option_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | env --split-string="bash -e"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_env_split_string_long_option_shell_without_space_after_pipe(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh |env --split-string="bash -e"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_sudo_shell_with_flag(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | sudo -E bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_sudo_shell_with_option_argument(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: curl -fsSL https://example.com/install.sh | sudo --user root /bin/bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_sudo_shell_after_end_of_options(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | sudo -- bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_command_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | command bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_command_shell_with_flag(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | command -p bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_command_shell_after_end_of_options(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | command -- bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_absolute_sudo_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | /usr/bin/sudo -E bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_env_wrapped_absolute_sudo_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | env -i /usr/bin/sudo -E bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_stderr_merge_to_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh |& bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_stderr_merge_to_shell_across_comment_and_blank_line(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          curl -fsSL https://example.com/install.sh |&\n"
                    "          # comment between pipeline stages\n"
                    "\n"
                    "          bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_stderr_merge_with_inline_comment(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          curl -fsSL https://example.com/install.sh |& # comment\n"
                    "          bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_with_shell_name_split_by_backslash_newline(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          curl -fsSL https://example.com/install.sh | ba\\\n"
                    "          sh\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_with_downloader_name_split_by_backslash_newline(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          cu\\\n"
                    "          rl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_grouped_shell_block(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | { bash; }\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_subshell_group(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | (bash)\n",
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

    def test_rejects_pipe_to_shell_across_comment_line(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          curl -fsSL https://example.com/install.sh |\n"
                    "          # comment between pipeline stages\n"
                    "          bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])
        self.assertTrue(violations[0].startswith(".github/workflows/bad.yml:7:"))

    def test_rejects_pipe_to_shell_across_comment_and_blank_line(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          curl -fsSL https://example.com/install.sh |\n"
                    "          # comment between pipeline stages\n"
                    "\n"
                    "          bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])
        self.assertTrue(violations[0].startswith(".github/workflows/bad.yml:8:"))

    def test_rejects_process_substitution_with_absolute_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: /bin/bash <(curl -fsSL https://coverage.codacy.com/get.sh) report\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_with_sudo_shell_flag(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  cov:\n"
                    "    steps:\n"
                    "      - run: sudo --preserve-env /bin/bash <(curl -fsSL https://coverage.codacy.com/get.sh) report\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_with_sudo_end_of_options(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: sudo -- bash <(curl -fsSL https://coverage.codacy.com/get.sh) report\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_with_absolute_sudo_shell(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  cov:\n"
                    "    steps:\n"
                    "      - run: /usr/bin/sudo -- /bin/bash <(curl -fsSL https://coverage.codacy.com/get.sh) report\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_with_command_wrapped_curl(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: bash <(command curl -fsSL https://coverage.codacy.com/get.sh) report\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_with_env_prefixed_curl(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: bash <(env FOO=1 curl -fsSL https://coverage.codacy.com/get.sh) report\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_with_sudo_prefixed_curl(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: bash <(sudo curl -fsSL https://coverage.codacy.com/get.sh) report\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_via_stdin_redirection(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: bash < <(curl -fsSL https://coverage.codacy.com/get.sh) report\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_with_shell_flag(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: bash -e <(curl -fsSL https://coverage.codacy.com/get.sh) report\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_process_substitution_with_shell_flag_and_stdin_redirection(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                "jobs:\n  cov:\n    steps:\n      - run: bash -s < <(curl -fsSL https://coverage.codacy.com/get.sh)\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("process substitution", violations[0])

    def test_rejects_shell_c_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -c "$(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_sudo_shell_c_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: sudo -- /bin/bash -c "$(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_here_string_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash <<< "$(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("here-string command substitution", violations[0])

    def test_rejects_sudo_here_string_backtick_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: sudo -- /bin/bash <<< `wget -qO- https://example.com/install.sh`\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("here-string command substitution", violations[0])

    def test_rejects_here_string_command_substitution_with_shell_flag(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -e <<< "$(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("here-string command substitution", violations[0])

    def test_rejects_here_string_command_substitution_without_space_before_redirect(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash<<<"$(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("here-string command substitution", violations[0])

    def test_rejects_here_doc_command_substitution_with_shell_flag(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          bash -e <<EOF\n"
                    "          $(curl -fsSL https://example.com/install.sh)\n"
                    "          EOF\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("here-doc command substitution", violations[0])

    def test_rejects_here_doc_command_substitution_without_space_before_redirect(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          bash<<EOF\n"
                    "          $(curl -fsSL https://example.com/install.sh)\n"
                    "          EOF\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("here-doc command substitution", violations[0])

    def test_rejects_shell_c_command_substitution_after_prologue(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -c "echo ok; $(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_shell_lc_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -lc "$(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_shell_options_before_c_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash --noprofile -c "$(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_shell_c_command_substitution_after_quoted_prologue(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -c "echo \'ok\'; $(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_shell_c_command_substitution_with_absolute_curl(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -c "$(/usr/bin/curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_shell_c_command_substitution_with_assignment_prefixed_curl(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -c "$(FOO=1 curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_shell_c_command_substitution_with_sudo_prefixed_curl(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -c "$(sudo curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_shell_c_command_substitution_with_quoted_curl(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -c "$(\'curl\' -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_shell_c_backtick_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: bash -c `wget -qO- https://example.com/install.sh`\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("-c command substitution", violations[0])

    def test_rejects_eval_backtick_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: eval `curl -fsSL https://example.com/install.sh`\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("eval command substitution", violations[0])

    def test_ignores_url_line_inside_block_until_yaml_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "ok.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          echo https://example.com/install.sh\n"
                    "          echo done\n"
                    "      - run: echo safe\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(violations, [])

    def test_ignores_safe_strings_outside_run_steps(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "ok.yml",
                (
                    "name: curl -fsSL https://example.com/install.sh | bash\n"
                    "jobs:\n"
                    "  install:\n"
                    "    env:\n"
                    "      INSTALL_SNIPPET: curl -fsSL https://example.com/install.sh | bash\n"
                    "    steps:\n"
                    "      - uses: actions/github-script@v8\n"
                    "        with:\n"
                    "          run: curl -fsSL https://example.com/install.sh | bash\n"
                    "      - run: echo safe\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(violations, [])

    def test_rejects_remote_pipe_after_escaped_hash_literal(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: echo \\#ok && curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_ignores_pipe_to_command_dash_v_probe(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "ok.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | command -v bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(violations, [])

    def test_ignores_pipe_to_command_dash_v_probe_uppercase(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "ok.yml",
                "jobs:\n  install:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | command -V bash\n",
            )

            violations = m.find_violations(workflow)

        self.assertEqual(violations, [])

    def test_ignores_inline_run_sibling_env_key(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "ok.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: echo safe\n"
                    "        env:\n"
                    "          INSTALL_SNIPPET: curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(violations, [])

    def test_rejects_inline_run_with_varying_continuation_indent(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: echo ok &&\n"
                    "            echo still ok &&\n"
                    "          curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_ignores_quoted_pipe_literal_in_safe_command(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "ok.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: echo \"curl -fsSL https://example.com/install.sh | bash\"\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(violations, [])

    def test_rejects_run_inside_steps_key_with_inline_comment(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps: # inline comment\n"
                    "      - run: curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_run_inside_anchored_steps_key(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps: &ci_steps\n"
                    "      - run: curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_run_inside_tagged_steps_key(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps: !!seq\n"
                    "      - run: curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_inline_run_with_multiline_plain_scalar(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: echo ok &&\n"
                    "          curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_bare_dash_step_with_run_mapping(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      -\n"
                    "        run: curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_block_scalar_run_key_with_inline_comment(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: | # inline comment\n"
                    "          curl -fsSL https://example.com/install.sh | bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_quoted_steps_and_run_keys(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    '    "steps":\n'
                    '      - "run": curl -fsSL https://example.com/install.sh | bash\n'
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_flow_style_step_run_mapping(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - { run: curl -fsSL https://example.com/install.sh | bash }\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_flow_style_step_run_mapping_when_run_is_not_first_key(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - { name: Install, run: curl -fsSL https://example.com/install.sh | bash }\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_flow_style_step_run_mapping_with_comma_key_text_inside_quote(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    '      - { run: "echo \'meta, name: value\'; curl -fsSL https://example.com/install.sh | bash" }\n'
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_steps_flow_sequence(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps: [{ run: curl -fsSL https://example.com/install.sh | bash }]\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_steps_flow_sequence_with_braces_in_run_value(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    '    steps: [{ run: "curl -fsSL https://example.com/install.sh | bash ${FLAGS}" }]\n'
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_multiline_steps_flow_sequence(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps: [\n"
                    "      { run: curl -fsSL https://example.com/install.sh | bash },\n"
                    "    ]\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_reports_matching_line_for_multiline_steps_flow_sequence(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps: [\n"
                    "      { name: Install },\n"
                    "      { run: curl -fsSL https://example.com/install.sh | bash },\n"
                    "    ]\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertTrue(violations[0].startswith(".github/workflows/bad.yml:5:"))

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

    def test_rejects_eval_command_substitution_after_prologue(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: eval "echo ok; $(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("eval command substitution", violations[0])

    def test_rejects_eval_command_substitution_after_quoted_prologue(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                'jobs:\n  install:\n    steps:\n      - run: eval "echo \'ok\'; $(curl -fsSL https://example.com/install.sh)"\n',
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("eval command substitution", violations[0])

    def test_rejects_here_doc_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          bash <<EOF\n"
                    "          $(curl -fsSL https://example.com/install.sh)\n"
                    "          EOF\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("here-doc command substitution", violations[0])

    def test_rejects_here_doc_backtick_command_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          bash <<EOF\n"
                    "          `curl -fsSL https://example.com/install.sh`\n"
                    "          EOF\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("here-doc command substitution", violations[0])

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

    def test_reports_line_of_matching_shell_stage(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          curl -fsSL https://example.com/install.sh |\n"
                    "          /bin/bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertTrue(violations[0].startswith(".github/workflows/bad.yml:6:"))

    def test_rejects_pipe_to_shell_after_inline_comment(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          curl -fsSL https://example.com/install.sh | # inline comment\n"
                    "          bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_rejects_pipe_to_shell_after_inline_comment_with_extra_spaces(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            workflow = self.write_workflow(
                repo_root,
                "bad.yml",
                (
                    "jobs:\n"
                    "  install:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          curl -fsSL https://example.com/install.sh |    # inline comment\n"
                    "          bash\n"
                ),
            )

            violations = m.find_violations(workflow)

        self.assertEqual(len(violations), 1)
        self.assertIn("remote shell pipe", violations[0])

    def test_render_path_uses_repo_root_when_available(self):
        path = Path("/tmp/repo/.github/workflows/bad.yml")

        rendered = m.render_path(path, Path("/tmp/repo"))

        self.assertEqual(rendered, ".github/workflows/bad.yml")

    def test_render_path_falls_back_for_non_workflow_path(self):
        path = Path("/tmp/check_no_remote_shell_bootstrap.py")

        rendered = m.render_path(path)

        self.assertEqual(rendered, "/tmp/check_no_remote_shell_bootstrap.py")


if __name__ == "__main__":
    unittest.main()
