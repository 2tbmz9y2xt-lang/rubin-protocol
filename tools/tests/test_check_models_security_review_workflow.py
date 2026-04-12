"""Contract tests for tools/check_models_security_review_workflow.py."""

from __future__ import annotations

import sys
import unittest
from unittest import mock
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_models_security_review_workflow as m


class TestCheckModelsSecurityReviewWorkflow(unittest.TestCase):
    def test_main_passes_on_repo_workflow(self) -> None:
        # The contract checker was refactored from a single WORKFLOW constant
        # into one constant per file (shared reusable + two callers).
        self.assertTrue(m.SHARED_WORKFLOW.is_file(), f"missing {m.SHARED_WORKFLOW}")
        self.assertTrue(m.DEEPSEEK_CALLER.is_file(), f"missing {m.DEEPSEEK_CALLER}")
        self.assertTrue(m.QWEN_CALLER.is_file(), f"missing {m.QWEN_CALLER}")
        self.assertEqual(m.main(), 0)

    def test_main_skips_node_syntax_check_when_node_missing(self) -> None:
        with mock.patch.object(m.shutil, "which", return_value=None):
            self.assertEqual(m.main(allow_missing_node=True), 0)


if __name__ == "__main__":
    unittest.main()
