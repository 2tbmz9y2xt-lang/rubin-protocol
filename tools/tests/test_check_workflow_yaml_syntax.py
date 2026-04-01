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


if __name__ == "__main__":
    unittest.main()
