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
) -> None:
    if proof_vector_ids is None:
        proof_vector_ids = ["V-1"]
    if proof_gates is None:
        proof_gates = ["CV-TEST"]
    if formal_evidence is None:
        formal_evidence = []
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
                    "formal_evidence": formal_evidence,
                }
            ],
        },
    )


def add_runtime_evidence(root: Path, tests_by_file: dict[str, list[str]]) -> None:
    baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline["domains"][0]["runtime_evidence"] = {"tests_by_file": tests_by_file}
    write_json(baseline_path, baseline)


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
            stdout = io.StringIO()
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("missing required vectors: V-MISSING", captured.getvalue())
        self.assertNotIn("OK: domain test_domain", stdout.getvalue())

    def test_duplicate_domain_name_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"].append(dict(baseline["domains"][0]))
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("duplicate domain name: test_domain", captured.getvalue())

    def test_domain_name_rejects_whitespace_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["name"] = "   "
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("domain name missing/invalid", captured.getvalue())

    def test_baseline_top_level_array_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline_path.write_text("[]\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("EDGE_PACK_BASELINE.json must be a JSON object", captured.getvalue())
        self.assertNotIn("Traceback", captured.getvalue())

    def test_duplicate_domain_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["gates"] = ["CV-TEST", "CV-TEST"]
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("domain test_domain gates entries must be unique", captured.getvalue())

    def test_domain_gate_rejects_whitespace_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["gates"] = ["   "]
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("domain test_domain gates entries must be non-empty strings", captured.getvalue())

    def test_required_vector_rejects_non_string_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["required_vectors_by_gate"]["CV-TEST"] = ["V-1", 7]
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("required_vectors_by_gate[CV-TEST] entries must be non-empty strings", captured.getvalue())

    def test_required_vector_rejects_duplicate_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["required_vectors_by_gate"]["CV-TEST"] = ["V-1", "V-1"]
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("required_vectors_by_gate[CV-TEST] entries must be unique", captured.getvalue())

    def test_required_vector_rejects_empty_list(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["required_vectors_by_gate"]["CV-TEST"] = []
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("required_vectors_by_gate[CV-TEST] must be non-empty list", captured.getvalue())

    def test_required_vector_gate_key_rejects_whitespace_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["required_vectors_by_gate"] = {"   ": ["V-1"]}
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("required_vectors_by_gate keys must be non-empty strings", captured.getvalue())

    def test_proof_coverage_missing_vector_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, proof_vector_ids=["V-MISSING"])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage references missing vector IDs: V-MISSING", captured.getvalue())

    def test_proof_coverage_top_level_array_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof_path.write_text("[]\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage.json must be a JSON object", captured.getvalue())
        self.assertNotIn("Traceback", captured.getvalue())

    def test_proof_coverage_malformed_json_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof_path.write_text("{not-json\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage.json must contain valid JSON", captured.getvalue())
        self.assertNotIn("Traceback", captured.getvalue())

    def test_fixture_top_level_array_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            fixture_path = root / "conformance" / "fixtures" / "CV-TEST.json"
            fixture_path.write_text("[]\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("conformance/fixtures/CV-TEST.json must be a JSON object", captured.getvalue())
        self.assertNotIn("Traceback", captured.getvalue())

    def test_fixture_gate_rejects_whitespace_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            fixture_path = root / "conformance" / "fixtures" / "CV-TEST.json"
            fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
            fixture["gate"] = "   "
            write_json(fixture_path, fixture)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("conformance/fixtures/CV-TEST.json has invalid gate", captured.getvalue())

    def test_proof_coverage_duplicate_domain_name_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"].append(dict(proof["edge_property_domains"][0]))
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage.json duplicate edge_property_domain: test_domain", captured.getvalue())

    def test_proof_coverage_domain_name_rejects_whitespace_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["name"] = "   "
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage.json edge_property_domains entries need non-empty name", captured.getvalue())

    def test_proof_coverage_missing_required_vector_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["vector_ids"] = []
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage missing vector IDs: V-1", captured.getvalue())

    def test_coverage_accounting_domain_rejects_whitespace_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["coverage_accounting"]["proof_coverage_domain"] = "   "
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("coverage_accounting.proof_coverage_domain must be non-empty string", captured.getvalue())

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

    def test_proof_coverage_rejects_gate_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, proof_gates=["CV-OTHER"])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage gates do not match EDGE baseline gates", captured.getvalue())

    def test_fuzz_present_claim_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, fuzz_status="present")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("committed fuzz evidence validation is not supported", captured.getvalue())

    def test_fuzz_covered_claim_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, fuzz_status="covered")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("claims fuzz=covered", captured.getvalue())

    def test_fuzz_scalar_present_shape_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["fuzz"] = "present"
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage fuzz must be object", captured.getvalue())

    def test_fuzz_non_string_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["fuzz"] = {"status": 7}
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage fuzz.status must be non-empty string", captured.getvalue())

    def test_fuzz_whitespace_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["fuzz"] = {"status": "   "}
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage fuzz.status must be non-empty string", captured.getvalue())

    def test_fuzz_object_missing_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["fuzz"] = {}
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage fuzz.status must be present", captured.getvalue())

    def test_absent_fuzz_formal_fields_are_no_claims(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0].pop("fuzz")
            proof["edge_property_domains"][0].pop("formal")
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_runtime_evidence_requires_declared_go_and_rust_tests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {
                    "clients/go/node/sync_reorg_test.go": ["TestRuntimeReorgCoverage"],
                    "clients/rust/crates/rubin-node/src/sync_reorg.rs": [
                        "runtime_reorg_coverage",
                    ],
                },
            )
            go_test = root / "clients" / "go" / "node" / "sync_reorg_test.go"
            go_test.parent.mkdir(parents=True, exist_ok=True)
            go_test.write_text(
                "package node\n\nfunc TestRuntimeReorgCoverage(t *testing.T) {}\n",
                encoding="utf-8",
            )
            rust_test = root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "sync_reorg.rs"
            rust_test.parent.mkdir(parents=True, exist_ok=True)
            rust_test.write_text(
                "#[test]\nfn runtime_reorg_coverage() {}\n",
                encoding="utf-8",
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_runtime_evidence_missing_declared_test_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/go/node/sync_reorg_test.go": ["TestRuntimeReorgCoverage"]},
            )
            go_test = root / "clients" / "go" / "node" / "sync_reorg_test.go"
            go_test.parent.mkdir(parents=True, exist_ok=True)
            go_test.write_text("package node\n\nfunc TestOtherCoverage(t *testing.T) {}\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn(
            "clients/go/node/sync_reorg_test.go missing runtime tests: TestRuntimeReorgCoverage",
            captured.getvalue(),
        )

    def test_runtime_evidence_rejects_go_helper_without_test_signature(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/go/node/sync_reorg_test.go": ["TestRuntimeReorgCoverage"]},
            )
            go_test = root / "clients" / "go" / "node" / "sync_reorg_test.go"
            go_test.parent.mkdir(parents=True, exist_ok=True)
            go_test.write_text("package node\n\nfunc TestRuntimeReorgCoverage() {}\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime tests: TestRuntimeReorgCoverage", captured.getvalue())

    def test_runtime_evidence_rejects_go_lowercase_test_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/go/node/sync_reorg_test.go": ["Testfoo"]},
            )
            go_test = root / "clients" / "go" / "node" / "sync_reorg_test.go"
            go_test.parent.mkdir(parents=True, exist_ok=True)
            go_test.write_text("package node\n\nfunc Testfoo(t *testing.T) {}\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime tests: Testfoo", captured.getvalue())

    def test_runtime_evidence_rejects_go_test_in_non_test_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/go/node/sync_reorg.go": ["TestRuntimeReorgCoverage"]},
            )
            go_file = root / "clients" / "go" / "node" / "sync_reorg.go"
            go_file.parent.mkdir(parents=True, exist_ok=True)
            go_file.write_text(
                "package node\n\nfunc TestRuntimeReorgCoverage(t *testing.T) {}\n",
                encoding="utf-8",
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime tests: TestRuntimeReorgCoverage", captured.getvalue())

    def test_runtime_evidence_rejects_commented_go_test_signature(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/go/node/sync_reorg_test.go": ["TestRuntimeReorgCoverage"]},
            )
            go_test = root / "clients" / "go" / "node" / "sync_reorg_test.go"
            go_test.parent.mkdir(parents=True, exist_ok=True)
            go_test.write_text(
                "package node\n\n/*\nfunc TestRuntimeReorgCoverage(t *testing.T) {}\n*/\n",
                encoding="utf-8",
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime tests: TestRuntimeReorgCoverage", captured.getvalue())

    def test_runtime_evidence_allows_go_unnamed_test_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/go/node/sync_reorg_test.go": ["TestRuntimeReorgCoverage"]},
            )
            go_test = root / "clients" / "go" / "node" / "sync_reorg_test.go"
            go_test.parent.mkdir(parents=True, exist_ok=True)
            go_test.write_text("package node\n\nfunc TestRuntimeReorgCoverage(*testing.T) {}\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_runtime_evidence_rejects_rust_helper_without_test_attribute(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/rust/crates/rubin-node/src/sync_reorg.rs": ["runtime_reorg_coverage"]},
            )
            rust_test = root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "sync_reorg.rs"
            rust_test.parent.mkdir(parents=True, exist_ok=True)
            rust_test.write_text("fn runtime_reorg_coverage() {}\n", encoding="utf-8")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime tests: runtime_reorg_coverage", captured.getvalue())

    def test_runtime_evidence_allows_rust_test_with_additional_attributes_and_visibility(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/rust/crates/rubin-node/src/sync_reorg.rs": ["runtime_reorg_coverage"]},
            )
            rust_test = root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "sync_reorg.rs"
            rust_test.parent.mkdir(parents=True, exist_ok=True)
            rust_test.write_text(
                "#[test]\n#[should_panic]\npub(crate) fn runtime_reorg_coverage() {}\n",
                encoding="utf-8",
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_runtime_evidence_keeps_line_after_rust_raw_string(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/rust/crates/rubin-node/src/sync_reorg.rs": ["runtime_reorg_coverage"]},
            )
            rust_test = root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "sync_reorg.rs"
            rust_test.parent.mkdir(parents=True, exist_ok=True)
            rust_test.write_text(
                'const TEXT: &str = r#"not code"#;\n#[test]\nfn runtime_reorg_coverage() {}\n',
                encoding="utf-8",
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_runtime_evidence_rejects_commented_rust_test_signature(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(
                root,
                {"clients/rust/crates/rubin-node/src/sync_reorg.rs": ["runtime_reorg_coverage"]},
            )
            rust_test = root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "sync_reorg.rs"
            rust_test.parent.mkdir(parents=True, exist_ok=True)
            rust_test.write_text(
                "/*\n#[test]\nfn runtime_reorg_coverage() {}\n*/\n",
                encoding="utf-8",
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime tests: runtime_reorg_coverage", captured.getvalue())

    def test_runtime_evidence_rejects_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            add_runtime_evidence(root, {str(root / "sync_reorg_test.go"): ["TestRuntimeReorgCoverage"]})
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("must be relative and must not contain '..'", captured.getvalue())

    def test_fuzz_unknown_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, fuzz_status="maybe")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("unknown fuzz coverage status maybe", captured.getvalue())

    def test_formal_present_claim_fails_closed_even_with_evidence_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "rubin-formal" / "Proof.lean"
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text("-- proof placeholder\n", encoding="utf-8")
            make_repo(root, formal_status="present", formal_evidence=[{"path": "rubin-formal/Proof.lean"}])
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("committed formal evidence validation is not supported", captured.getvalue())

    def test_formal_complete_claim_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, formal_status="complete")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("claims formal=complete", captured.getvalue())

    def test_formal_scalar_present_shape_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["formal"] = "covered"
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage formal must be object", captured.getvalue())

    def test_formal_non_string_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["formal"] = {"status": 7}
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage formal.status must be non-empty string", captured.getvalue())

    def test_formal_object_missing_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            proof_path = root / "proof_coverage.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["edge_property_domains"][0]["formal"] = {}
            write_json(proof_path, proof)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("proof_coverage formal.status must be present", captured.getvalue())

    def test_formal_unknown_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, formal_status="maybe")
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("unknown formal coverage status maybe", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
