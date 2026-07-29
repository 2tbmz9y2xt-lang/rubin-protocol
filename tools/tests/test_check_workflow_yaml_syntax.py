#!/usr/bin/env python3
from __future__ import annotations

import re
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
BUILDER = "scripts/crypto/openssl/build-openssl-bundle.sh"
CHECKSUMS = "scripts/crypto/openssl/source-checksums.sha256"
CACHE_ACTION = "actions/cache@"
# The binding must be an evaluated expression: a literal substring or a trailing
# YAML comment carries the text without ever rotating the cache identity.
PIN_BINDING = re.compile(r"\$\{\{[^{}]*hashFiles\(\s*'" + re.escape(CHECKSUMS) + r"'\s*\)[^{}]*\}\}")
BUNDLE_DIR = re.compile(r"~/\.cache/rubin-openssl/bundle-\S+")
SOURCE_ARCHIVE = re.compile(r"~/\.cache/rubin-openssl/work/openssl-\S+\.tar\.gz")


def workflow_files() -> list[Path]:
    return sorted(p for p in WORKFLOWS_DIR.iterdir() if p.suffix in (".yml", ".yaml"))


def is_builder_call(step: object) -> bool:
    return isinstance(step, dict) and BUILDER in str(step.get("run", ""))


def bundle_cache_settings(step: object) -> dict | None:
    """The `with:` block of an OpenSSL bundle cache step, or None for any other step."""
    if not isinstance(step, dict) or CACHE_ACTION not in str(step.get("uses", "")):
        return None
    settings = step.get("with") or {}
    return settings if "rubin-openssl" in str(settings.get("path", "")) else None


def job_steps(document: object) -> list[tuple[str, list]]:
    return [(job_id, (job or {}).get("steps") or [])
            for job_id, job in ((document or {}).get("jobs") or {}).items()]


def builder_jobs(yaml):
    """Yield (label, steps, call_indexes) for every job that builds the OpenSSL bundle."""
    for path in workflow_files():
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, steps in job_steps(document):
            calls = [i for i, step in enumerate(steps) if is_builder_call(step)]
            if calls:
                yield f"{path.name}:{job_id}", steps, calls


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
    def test_bundle_cache_keys_bind_the_pinned_source_digest(self):
        builder_calls = 0
        bound_keys = 0

        for label, steps, calls in builder_jobs(m.load_yaml_module()):
            builder_calls += len(calls)
            caches = [s for s in map(bundle_cache_settings, steps[: calls[0]]) if s]
            with self.subTest(job=label):
                self.assertEqual(len(caches), 1, f"{label}: expected exactly one OpenSSL bundle cache step before the builder call")
                settings = caches[0]
                paths = str(settings.get("path", "")).split()
                self.assertRegex(str(settings.get("key", "")), PIN_BINDING, f"{label}: cache key does not evaluate hashFiles('{CHECKSUMS}')")
                self.assertTrue(any(BUNDLE_DIR.fullmatch(p) for p in paths), f"{label}: cache path no longer covers the installed bundle")
                self.assertTrue(any(SOURCE_ARCHIVE.fullmatch(p) for p in paths), f"{label}: cache path no longer covers the downloaded source archive")
                self.assertIsNone(settings.get("restore-keys"), f"{label}: a prefix fallback restores entries predating the pin binding")
                bound_keys += 1

        self.assertGreater(builder_calls, 0, "no bundle builder call site found; the parse or the builder path is stale")
        self.assertEqual(builder_calls, bound_keys, "every bundle builder call must sit behind a pin-bound cache key")


if __name__ == "__main__":
    unittest.main()
