#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_workflow_yaml_syntax as m

HAS_PYYAML = m.load_yaml_module() is not None

WORKFLOWS_DIR = TOOLS_DIR.parent / ".github" / "workflows"
ACTION_PATH = TOOLS_DIR.parent / ".github" / "actions" / "openssl-bundle" / "action.yml"
ACTION_REF = "./.github/actions/openssl-bundle"
BUILDER = "scripts/crypto/openssl/build-openssl-bundle.sh"
CHECKSUMS = "scripts/crypto/openssl/source-checksums.sha256"
CALLERS = (
    ("ci.yml", "test", "steps.test_gate.outputs.run_test == 'true'", None, {}),
    ("ci.yml", "go_race_node", None, None, {}),
    ("ci.yml", "formal_refinement", "steps.formal_gate.outputs.run_formal == 'true'", "openssl", {}),
    ("ci.yml", "conformance_fixtures_drift", None, None, {}),
    ("codacy-coverage.yml", "coverage", None, None, {}),
    ("combined-load-nightly.yml", "combined-load", None, "openssl", {}),
    ("fips-only-nightly.yml", "fips-only-smoke", None, "openssl", {}),
    ("fuzz-nightly.yml", "fuzz-stage2", None, None,
     {"cache-key-prefix": "openssl-bundle-mldsa-verified", "cache-revision": "v1"}),
    ("runtime-perf-guardrails.yml", "runtime-perf", None, "openssl", {}),
)


def workflow_files() -> list[Path]:
    return sorted(p for p in WORKFLOWS_DIR.iterdir() if p.suffix in (".yml", ".yaml"))


def job_steps(document: object) -> list[tuple[str, list]]:
    return [(job_id, (job or {}).get("steps") or [])
            for job_id, job in ((document or {}).get("jobs") or {}).items()]

class WorkflowYamlSyntaxTests(unittest.TestCase):
    @unittest.skipUnless(HAS_PYYAML, "PyYAML unavailable")
    def test_validate_paths_accepts_valid_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            workflow = Path(td) / "ok.yml"
            workflow.write_text("name: test\non: [push]\njobs: {}\n", encoding="utf-8")

            ok, message = m.validate_paths([workflow])

        self.assertTrue(ok)
        self.assertIn("OK: parsed 1 workflow file", message)

    @unittest.skipUnless(HAS_PYYAML, "PyYAML unavailable")
    def test_validate_paths_rejects_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            workflow = Path(td) / "bad.yml"
            workflow.write_text("name: [broken\n", encoding="utf-8")

            ok, message = m.validate_paths([workflow])

        self.assertFalse(ok)
        self.assertIn("invalid workflow yaml", message)

    @unittest.skipUnless(HAS_PYYAML, "PyYAML unavailable")
    def test_validate_paths_rejects_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as td:
            workflow = Path(td) / "bad-encoding.yml"
            workflow.write_bytes(b"\xff\xfe\xfd")

            ok, message = m.validate_paths([workflow])

        self.assertFalse(ok)
        self.assertIn("invalid workflow yaml encoding", message)

    def test_validate_paths_rejects_oversized_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            workflow = Path(td) / "huge.yml"
            workflow.write_text("a" * (m.MAX_WORKFLOW_YAML_BYTES + 1), encoding="utf-8")

            ok, message = m.validate_paths([workflow])

        self.assertFalse(ok)
        self.assertIn("workflow yaml too large", message)

    def test_validate_paths_skips_when_pyyaml_missing(self):
        with tempfile.TemporaryDirectory() as td:
            workflow = Path(td) / "ok.yml"
            workflow.write_text("name: test\n", encoding="utf-8")

            with mock.patch.object(m, "load_yaml_module", return_value=None):
                ok, message = m.validate_paths([workflow])

        self.assertTrue(ok)
        self.assertIn("SKIP: PyYAML unavailable", message)


class OpenSSLBundleCacheIdentityTests(unittest.TestCase):
    @unittest.skipUnless(HAS_PYYAML, "PyYAML unavailable")
    def test_composite_action_owns_versioned_cache_and_builder(self):
        yaml = m.load_yaml_module()
        action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
        self.assertEqual(action["runs"]["using"], "composite")
        self.assertEqual(action["inputs"]["cache-key-prefix"]["default"], "openssl-bundle")
        self.assertEqual(action["inputs"]["cache-revision"]["default"], "v3")
        steps = action["runs"]["steps"]
        cache_steps = [step for step in steps if str(step.get("uses", "")).startswith("actions/cache@")]
        self.assertEqual(len(cache_steps), 1)
        self.assertEqual(
            cache_steps[0]["uses"],
            "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        )
        version_step = next(step for step in steps if step.get("id") == "version")
        self.assertLess(steps.index(version_step), steps.index(cache_steps[0]))
        self.assertLess(version_step["run"].index("--check-selection"),
                        version_step["run"].index("GITHUB_OUTPUT"))
        settings = cache_steps[0]["with"]
        self.assertEqual(
            str(settings["path"]).splitlines(),
            [
                "~/.cache/rubin-openssl/bundle-${{ steps.version.outputs.value }}",
                "~/.cache/rubin-openssl/work/openssl-${{ steps.version.outputs.value }}.tar.gz",
            ],
        )
        self.assertEqual(
            settings["key"],
            "${{ inputs.cache-key-prefix }}-${{ runner.os }}-${{ steps.version.outputs.value }}-"
            "${{ inputs.cache-revision }}-${{ hashFiles('scripts/crypto/openssl/source-checksums.sha256') }}",
        )
        self.assertNotIn("restore-keys", settings)
        prepare = next(step for step in steps if step.get("id") == "prepare")
        self.assertEqual(prepare["env"]["OPENSSL_VERSION"], "${{ steps.version.outputs.value }}")
        self.assertIn(BUILDER, prepare["run"])
        expected_outputs = {
            name: {"description": action["outputs"][name]["description"],
                   "value": f"${{{{ steps.prepare.outputs.{name} }}}}"}
            for name in ("openssl_dir", "openssl_modules", "openssl_conf", "pkg_config_path", "ld_library_path")
        }
        self.assertEqual(action["outputs"], expected_outputs)

    @unittest.skipUnless(HAS_PYYAML, "PyYAML unavailable")
    def test_exact_workflow_jobs_use_the_composite_action(self):
        yaml = m.load_yaml_module()
        expected = {(path, job) for path, job, *_ in CALLERS}
        observed = set()

        for path in workflow_files():
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(BUILDER, text, f"{path.name}: direct builder call bypasses the composite action")
            self.assertNotIn("~/.cache/rubin-openssl/", text, f"{path.name}: versioned cache path is duplicated")
            document = yaml.safe_load(text)
            for job_id, steps in job_steps(document):
                calls = [step for step in steps if isinstance(step, dict) and step.get("uses") == ACTION_REF]
                if calls:
                    self.assertEqual(len(calls), 1, f"{path.name}:{job_id}: duplicate OpenSSL action call")
                    observed.add((path.name, job_id))

        self.assertEqual(observed, expected)

        for path_name, job_id, expected_if, expected_id, expected_with in CALLERS:
            document = yaml.safe_load((WORKFLOWS_DIR / path_name).read_text(encoding="utf-8"))
            steps = document["jobs"][job_id]["steps"]
            call = next(step for step in steps if step.get("uses") == ACTION_REF)
            self.assertEqual(call.get("if"), expected_if, f"{path_name}:{job_id}: condition changed")
            self.assertEqual(call.get("id"), expected_id, f"{path_name}:{job_id}: output id changed")
            self.assertEqual(call.get("with") or {}, expected_with, f"{path_name}:{job_id}: cache identity changed")


if __name__ == "__main__":
    unittest.main()
