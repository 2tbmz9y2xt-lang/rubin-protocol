#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import sys
import unittest

from pathlib import Path
from unittest import mock

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

    def test_manifest_rejects_non_object_root(self):
        with self.assertRaises(m.ManifestValidationError) as ctx:
            m.validate_manifest_document(["not", "an", "object"])

        self.assertIn("expected object", str(ctx.exception))

    def test_manifest_rejects_multiline_required_test(self):
        manifest = {
            "q_id": "Q-IMPL-NODE-TEST-01",
            "owner_area": "node",
            "allowed_files": ["clients/go/node/sync.go"],
            "required_tests": ["printf ok\nprintf nope"],
            "hard_production_loc": 250,
            "required_invariants": list(m.CANONICAL_INVARIANTS),
        }

        with self.assertRaises(m.ManifestValidationError) as ctx:
            m.validate_manifest_document(manifest)

        self.assertIn("required test commands must be single-line", str(ctx.exception))

    def test_manifest_rejects_whitespace_only_required_test(self):
        manifest = {
            "q_id": "Q-IMPL-NODE-TEST-01",
            "owner_area": "node",
            "allowed_files": ["clients/go/node/sync.go"],
            "required_tests": ["   "],
            "hard_production_loc": 250,
            "required_invariants": list(m.CANONICAL_INVARIANTS),
        }

        with self.assertRaises(m.ManifestValidationError) as ctx:
            m.validate_manifest_document(manifest)

        self.assertIn(
            "required test commands must contain non-whitespace text",
            str(ctx.exception),
        )

    def test_manifest_rejects_non_string_required_invariant_entries(self):
        manifest = {
            "q_id": "Q-IMPL-NODE-TEST-01",
            "owner_area": "node",
            "allowed_files": ["clients/go/node/sync.go"],
            "required_tests": ["printf ok"],
            "hard_production_loc": 250,
            "required_invariants": list(m.CANONICAL_INVARIANTS[:-1]) + [["bad"]],
        }

        with self.assertRaises(m.ManifestValidationError) as ctx:
            m.validate_manifest_document(manifest)

        self.assertIn("entries must all be strings", str(ctx.exception))

    def test_root_anchored_globs_match_only_from_repo_root(self):
        self.assertTrue(
            m.path_matches_glob("clients/go/node/sync.go", "clients/**")
        )
        self.assertFalse(
            m.path_matches_glob("vendor/clients/go/node/sync.go", "clients/**")
        )

    def test_double_star_slash_glob_matches_repo_root_files(self):
        self.assertTrue(m.path_matches_glob("README.md", "**/*.md"))
        self.assertTrue(m.path_matches_glob("docs/guide.md", "**/*.md"))

    def test_load_json_rejects_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_bytes(b"\xff\xfe\x00")

            with self.assertRaises(m.ManifestValidationError) as ctx:
                m.load_json(path)

        self.assertIn("invalid utf-8", str(ctx.exception))

    def test_list_changed_files_rejects_truncated_name_status_stream(self):
        with mock.patch.object(m, "run_git", return_value="M\0"):
            with mock.patch.object(m, "list_untracked_files", return_value=[]):
                with self.assertRaises(m.GitCommandError) as ctx:
                    m.list_changed_files(Path("/tmp/repo"), "HEAD")

        self.assertIn("malformed changed-path entry", str(ctx.exception))

    def test_find_drop_block_ranges_accepts_qualified_drop_impl(self):
        text = (
            "struct Dropper;\n\n"
            "impl std::ops::Drop for Dropper {\n"
            "    fn drop(&mut self) {\n"
            "        panic!(\"boom\");\n"
            "    }\n"
            "}\n"
        )

        self.assertEqual(m.find_drop_block_ranges(text), [(3, 7)])


if __name__ == "__main__":
    unittest.main()
