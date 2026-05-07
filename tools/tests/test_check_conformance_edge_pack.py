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
    formal_evidence: list[object] | None = None,
    fuzz_targets: list[dict] | None = None,
    go_fuzz_targets: list[dict] | None = None,
) -> None:
    if proof_vector_ids is None:
        proof_vector_ids = ["V-1"]
    if proof_gates is None:
        proof_gates = ["CV-TEST"]
    if formal_evidence is None:
        formal_evidence = []
    if fuzz_targets is None:
        fuzz_targets = []
    if go_fuzz_targets is None:
        go_fuzz_targets = []
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
            "fuzz": {"path": "clients/rust/fuzz", "targets": fuzz_targets},
            "go_fuzz": {"path": "clients/go/consensus", "targets": go_fuzz_targets},
            "edge_property_domains": [
                {
                    "name": "test_domain",
                    "conformance_gates": proof_gates,
                    "vector_ids": proof_vector_ids,
                    "fuzz": {"status": fuzz_status},
                    "formal": {"status": formal_status},
                    "formal_evidence": formal_evidence,
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

    def test_fuzz_present_claim_with_metadata_only_target_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(
                root,
                fuzz_status="present",
                fuzz_targets=[{"name": "missing_target", "conformance_gate": "CV-TEST"}],
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("claims fuzz=present without committed fuzz target", captured.getvalue())

    def test_fuzz_present_claim_with_existing_rust_target_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rust_target = root / "clients" / "rust" / "fuzz" / "fuzz_targets" / "test_target.rs"
            rust_target.parent.mkdir(parents=True, exist_ok=True)
            rust_target.write_text("fn main() {}\n", encoding="utf-8")
            make_repo(
                root,
                fuzz_status="present",
                fuzz_targets=[{"name": "test_target", "conformance_gate": "CV-TEST"}],
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_go_fuzz_present_claim_with_existing_target_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            go_target = root / "clients" / "go" / "consensus" / "fuzz_test.go"
            go_target.parent.mkdir(parents=True, exist_ok=True)
            go_target.write_text("package consensus\n\nfunc FuzzEdgePack(f *testing.F) {}\n", encoding="utf-8")
            make_repo(
                root,
                fuzz_status="present",
                go_fuzz_targets=[{"name": "FuzzEdgePack", "conformance_gate": "CV-TEST"}],
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_fuzz_present_claim_with_absolute_root_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(
                root,
                fuzz_status="present",
                fuzz_targets=[{"name": "test_target", "conformance_gate": "CV-TEST"}],
            )
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["fuzz"]["path"] = "/tmp"
            write_json(proof_path, proof)
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
        self.assertIn("claims formal=present without committed formal evidence", captured.getvalue())

    def test_formal_present_claim_with_missing_evidence_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, formal_status="present", formal_evidence=[{"path": "rubin-formal/missing.lean"}])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("formal_evidence path does not exist: rubin-formal/missing.lean", captured.getvalue())

    def test_formal_present_claim_with_absolute_evidence_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, formal_status="present", formal_evidence=[{"path": "/tmp/fake.lean"}])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("formal_evidence paths must be repo-relative and contained", captured.getvalue())

    def test_formal_present_claim_with_non_formal_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "README.md"
            evidence.write_text("not formal\n", encoding="utf-8")
            make_repo(root, formal_status="present", formal_evidence=[{"path": "README.md"}])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("formal_evidence paths must reference formal artifacts", captured.getvalue())

    def test_formal_present_claim_with_existing_evidence_path_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "rubin-formal" / "Proof.lean"
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text("-- proof placeholder\n", encoding="utf-8")
            make_repo(root, formal_status="present", formal_evidence=[{"path": "rubin-formal/Proof.lean"}])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

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
