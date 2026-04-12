"""Contract tests for tools/gen_conformance_matrix.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import gen_conformance_matrix as m


class GenConformanceMatrixTests(unittest.TestCase):
    def test_load_protocol_artifact_rows_accepts_repo_protocol_artifacts(self) -> None:
        rows = m.load_protocol_artifact_rows()
        self.assertTrue(rows)
        self.assertIn(
            "protocol/live_binding_policy_v1.json",
            {row.path for row in rows},
        )

    def test_load_protocol_artifact_rows_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = Path(tmpdir) / "live_binding_policy_v1.json"
            artifact.write_text(
                '{"version": 1, "version": 2, "entries": []}',
                encoding="utf-8",
            )
            with (
                mock.patch.object(m, "EXPECTED_PROTOCOL_ARTIFACTS", frozenset({artifact.name})),
                mock.patch.object(
                    m,
                    "PROTOCOL_ARTIFACT_META",
                    {artifact.name: ("Canonical live binding policy artifact", "tests")},
                ),
                mock.patch.object(m, "iter_protocol_artifacts", return_value=[artifact]),
            ):
                with self.assertRaisesRegex(RuntimeError, 'duplicate JSON key "version"'):
                    m.load_protocol_artifact_rows()

    def test_load_protocol_artifact_rows_rejects_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = Path(tmpdir) / "live_binding_policy_v1.json"
            artifact.write_text('{"version": 1,', encoding="utf-8")
            with (
                mock.patch.object(m, "EXPECTED_PROTOCOL_ARTIFACTS", frozenset({artifact.name})),
                mock.patch.object(
                    m,
                    "PROTOCOL_ARTIFACT_META",
                    {artifact.name: ("Canonical live binding policy artifact", "tests")},
                ),
                mock.patch.object(m, "iter_protocol_artifacts", return_value=[artifact]),
            ):
                with self.assertRaisesRegex(RuntimeError, "invalid JSON artifact"):
                    m.load_protocol_artifact_rows()


if __name__ == "__main__":
    unittest.main()
