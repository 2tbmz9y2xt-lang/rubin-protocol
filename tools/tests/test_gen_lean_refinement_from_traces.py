from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.formal.gen_lean_refinement_from_traces import _load_fixture_vector_ids, _require_exact_trace_ids


class GoTraceV1GeneratorTests(unittest.TestCase):
    def test_simplicity_exec_trace_ids_must_match_fixture_ids(self) -> None:
        _require_exact_trace_ids(
            [("CV-SE-001", "{ row }"), ("CV-SE-002", "{ row }")],
            ["CV-SE-001", "CV-SE-002"],
            "CV-SIMPLICITY-EXEC",
        )

    def test_simplicity_exec_trace_ids_reject_missing_duplicate_and_extra(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            _require_exact_trace_ids(
                [
                    ("CV-SE-001", "{ row }"),
                    ("CV-SE-001", "{ row }"),
                    ("CV-SE-EXTRA", "{ row }"),
                ],
                ["CV-SE-001", "CV-SE-MISSING"],
                "CV-SIMPLICITY-EXEC",
            )

        message = str(ctx.exception)
        self.assertIn("CV-SIMPLICITY-EXEC trace ID coverage mismatch", message)
        self.assertIn("missing CV-SE-MISSING", message)
        self.assertIn("duplicate CV-SE-001", message)
        self.assertIn("extra CV-SE-EXTRA", message)

    def test_fixture_vector_ids_reject_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "CV-SIMPLICITY-EXEC.json"
            fixture.write_text(
                json.dumps(
                    {
                        "gate": "CV-SIMPLICITY-EXEC",
                        "vectors": [
                            {"id": "CV-SE-001"},
                            {"id": "CV-SE-001"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit) as ctx:
                _load_fixture_vector_ids(fixture, "CV-SIMPLICITY-EXEC")

        self.assertIn("duplicate vector id CV-SE-001", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
