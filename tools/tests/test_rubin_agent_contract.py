#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest

from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import rubin_agent_contract as m


class ManifestContractTests(unittest.TestCase):
    def test_runtime_manifest_schema_accepts_runtime_q(self):
        manifest = {
            "q_id": "Q-IMPL-NODE-TEST-01",
            "owner_area": "node",
            "allowed_files": ["clients/go/node/sync.go"],
            "allowed_globs": ["clients/go/node/**"],
            "forbidden_globs": [
                ".cursor/**",
                ".claude/**",
                ".github/workflows/**",
                "tools/**",
                "docs/**",
            ],
            "required_tests": ["printf runtime-ok"],
            "target_production_loc": 200,
            "hard_production_loc": 250,
            "required_invariants": list(m.CANONICAL_INVARIANTS),
        }

        validated = m.validate_manifest_document(manifest)

        self.assertEqual(validated["owner_area"], "node")

    def test_runtime_manifest_schema_accepts_tooling_q(self):
        manifest = {
            "q_id": "Q-TOOLING-LINT-01",
            "owner_area": "tooling",
            "allowed_files": ["tools/check_pre_commit_hygiene.py"],
            "allowed_globs": ["tools/**"],
            "forbidden_globs": [".cursor/**", ".claude/**"],
            "required_tests": ["printf tooling-ok"],
            "hard_production_loc": 80,
            "required_invariants": list(m.CANONICAL_INVARIANTS),
        }

        validated = m.validate_manifest_document(manifest)

        self.assertEqual(validated["owner_area"], "tooling")

    def test_manifest_rejects_missing_canonical_invariant(self):
        manifest = {
            "q_id": "Q-IMPL-NODE-TEST-01",
            "owner_area": "node",
            "allowed_files": ["clients/go/node/sync.go"],
            "required_tests": ["printf ok"],
            "hard_production_loc": 250,
            "required_invariants": list(m.CANONICAL_INVARIANTS[:-1]),
        }

        with self.assertRaises(m.ManifestValidationError) as ctx:
            m.validate_manifest_document(manifest)

        self.assertIn("missing canonical invariant(s)", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
