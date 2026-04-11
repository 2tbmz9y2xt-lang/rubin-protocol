"""Contract tests for tools/check_models_security_review_workflow.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_models_security_review_workflow as m


class TestCheckModelsSecurityReviewWorkflow(unittest.TestCase):
    def test_main_passes_on_repo_workflow(self) -> None:
        self.assertTrue(m.WORKFLOW.is_file(), f"missing {m.WORKFLOW}")
        self.assertEqual(m.main(), 0)


if __name__ == "__main__":
    unittest.main()
