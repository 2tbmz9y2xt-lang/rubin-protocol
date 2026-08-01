#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import list_workflow_shell_targets as m


class WorkflowShellTargetTests(unittest.TestCase):
    def test_collect_targets_matches_current_workflow_references(self):
        repo_root = TOOLS_DIR.parents[0]
        targets = m.collect_targets(repo_root)

        self.assertEqual(
            targets,
            [
                "scripts/benchmarks/run_combined_load_benchmark.sh",
                "scripts/ci/run_fuzz_stage2.sh",
                "scripts/codacy-coverage-reporter.sh",
                "scripts/crypto/openssl/build-openssl-bundle.sh",
                "scripts/crypto/openssl/fips-preflight.sh",
                "scripts/dev-env.sh",
                "scripts/node-runtime-total-parity-gate.sh",
                "scripts/run-codacy-coverage.sh",
                "scripts/runtime_perf/run_runtime_perf_suite.sh",
                "scripts/rust-consensus-total-parity-gate.sh",
                "scripts/security/precheck.sh",
            ],
        )

    def test_collect_targets_are_unique_and_exist(self):
        repo_root = TOOLS_DIR.parents[0]
        targets = m.collect_targets(repo_root)

        self.assertEqual(targets, sorted(set(targets)))
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue((repo_root / target).is_file())

    def test_collect_targets_reads_yaml_workflows_and_composite_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            workflow_dir = repo_root / ".github" / "workflows"
            action_dir = repo_root / ".github" / "actions" / "sample"
            script_path = repo_root / "scripts" / "ci"
            workflow_dir.mkdir(parents=True)
            action_dir.mkdir(parents=True)
            script_path.mkdir(parents=True)
            (script_path / "sample.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            (workflow_dir / "sample.yaml").write_text(
                "jobs:\n  lint:\n    steps:\n      - run: scripts/ci/sample.sh\n",
                encoding="utf-8",
            )
            (action_dir / "action.yml").write_text("runs:\n  steps:\n    - run: scripts/ci/sample.sh\n", encoding="utf-8")
            self.assertEqual(m.collect_targets(repo_root), ["scripts/ci/sample.sh"])

    def test_collect_targets_ignores_longer_suffixes_on_a_sh_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            workflow_dir = repo_root / ".github" / "workflows"
            script_dir = repo_root / "scripts" / "crypto" / "openssl"
            workflow_dir.mkdir(parents=True)
            script_dir.mkdir(parents=True)
            (script_dir / "build-openssl-bundle.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            # source-checksums.sha256 is deliberately absent: an unanchored `.sh`
            # match would read it as a shell target and fail closed on it.
            (workflow_dir / "cache.yml").write_text(
                "jobs:\n  build:\n    steps:\n"
                "      - with:\n"
                "          key: openssl-${{ hashFiles('scripts/crypto/openssl/source-checksums.sha256') }}\n"
                "      - run: scripts/crypto/openssl/build-openssl-bundle.sh\n",
                encoding="utf-8",
            )

            self.assertEqual(
                m.collect_targets(repo_root),
                ["scripts/crypto/openssl/build-openssl-bundle.sh"],
            )

    def test_collect_targets_fail_closed_on_missing_shell_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            workflow_dir = repo_root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "broken.yml").write_text(
                "jobs:\n  lint:\n    steps:\n      - run: scripts/ci/missing.sh\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(FileNotFoundError, "missing shell target"):
                m.collect_targets(repo_root)


if __name__ == "__main__":
    unittest.main()
