"""Contract tests for tools/check_conformance_edge_pack.py."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_conformance_edge_pack as m  # noqa: E402


@contextlib.contextmanager
def chdir(path: Path):
    old = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_repo(
    root: Path,
    *,
    fuzz_status: str = "deferred",
    formal_status: str = "not_claimed",
    vector_id: str = "V-1",
    proof_vector_ids: list[object] | None = None,
    proof_gates: list[object] | None = None,
) -> None:
    if proof_vector_ids is None:
        proof_vector_ids = ["V-1"]
    if proof_gates is None:
        proof_gates = ["CV-TEST"]
    write_json(
        root / "conformance" / "fixtures" / "CV-TEST.json",
        {"gate": "CV-TEST", "vectors": [{"id": "V-1"}]},
    )
    write_json(
        root / "conformance" / "EDGE_PACK_BASELINE.json",
        {
            "schema_version": 1,
            "domains": [
                {
                    "name": "test_domain",
                    "gates": ["CV-TEST"],
                    "min_vectors_total": 1,
                    "required_vectors_by_gate": {"CV-TEST": [vector_id]},
                    "coverage_accounting": {"proof_coverage_domain": "test_domain"},
                }
            ],
        },
    )
    write_json(
        root / "proof_coverage.json",
        {
            "version": 1,
            "fuzz": {"targets": []},
            "go_fuzz": {"targets": []},
            "edge_property_domains": [
                {
                    "name": "test_domain",
                    "conformance_gates": proof_gates,
                    "vector_ids": proof_vector_ids,
                    "fuzz": {"status": fuzz_status},
                    "formal": {"status": formal_status},
                }
            ],
        },
    )


class EdgePackCheckerTests(unittest.TestCase):
    def test_clean_accounting_passes_with_deferred_fuzz_formal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_missing_required_vector_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, vector_id="V-MISSING")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("missing required vectors: V-MISSING", captured.getvalue())

    def test_fuzz_present_claim_without_target_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, fuzz_status="present")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("claims fuzz=present without committed fuzz target", captured.getvalue())

    def test_formal_present_claim_without_evidence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, formal_status="present")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("claims formal=present without formal_evidence", captured.getvalue())

    def test_proof_coverage_missing_vector_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, proof_vector_ids=["V-MISSING"])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage references missing vector IDs: V-MISSING", captured.getvalue())

    def test_proof_coverage_rejects_non_string_vector_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, proof_vector_ids=["V-1", 7])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage vector_ids entries must be non-empty strings", captured.getvalue())

    def test_proof_coverage_rejects_duplicate_vector_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, proof_vector_ids=["V-1", "V-1"])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage vector_ids entries must be unique", captured.getvalue())

    def test_proof_coverage_rejects_non_string_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, proof_gates=["CV-TEST", 7])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage conformance_gates entries must be non-empty strings", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
