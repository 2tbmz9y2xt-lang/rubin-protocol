"""Contract tests for tools/check_conformance_edge_pack.py."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess  # nosec B404
import sys
import tempfile
import unittest
import unittest.mock
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


def set_runtime_evidence(root: Path, runtime_evidence: object) -> None:
    baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline["domains"][0]["runtime_evidence"] = runtime_evidence
    write_json(baseline_path, baseline)


def write_runtime_source(root: Path, rel_path: str, text: str = "// test source\n") -> Path:
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def make_runtime_evidence_repo(root: Path, tests_by_file: dict[str, list[str]]) -> None:
    make_repo(root)
    for rel_path in tests_by_file:
        if rel_path.startswith("clients/go/"):
            write_runtime_source(root, rel_path, "package node\n")
        elif rel_path.startswith("clients/rust/"):
            write_runtime_source(root, "clients/rust/crates/rubin-node/Cargo.toml", "[package]\nname = 'rubin-node' # inline comment\n")
            tests = "".join(f"    #[test]\n    fn {name}() {{}}\n" for name in tests_by_file[rel_path])
            write_runtime_source(root, rel_path, f"#[cfg(test)]\nmod tests {{\n{tests}}}\n")
    set_runtime_evidence(root, {"tests_by_file": tests_by_file})


class FakeCommandRunner:
    def __init__(self, outputs: dict[tuple[str, ...], tuple[int, str, str] | BaseException], registered_tests: list[str] | None = None) -> None:
        self.outputs = outputs
        self.registered_tests = ["TestRuntimeReorg"] if registered_tests is None else registered_tests
        self.calls: list[tuple[tuple[str, ...], Path]] = []
        self.envs: list[dict[str, str] | None] = []

    def __call__(
        self,
        cmd: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None,
        text: bool,
        capture_output: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        _ = (text, capture_output, timeout)
        self.calls.append((tuple(cmd), cwd))
        self.envs.append(env)
        output = self.outputs.get(tuple(cmd))
        if output is None:
            output = next((candidate for pattern, candidate in self.outputs.items() if len(pattern) == len(cmd) and all(part == "*" or part == actual for part, actual in zip(pattern, cmd))), (127, "", "unexpected command"))
        if isinstance(output, BaseException):
            raise output
        is_go_compile = len(GO_COMPILE) == len(cmd) and all(part == "*" or part == actual for part, actual in zip(GO_COMPILE, cmd))
        if is_go_compile and env is not None and output[0] == 0:
            work_dir = Path(env["GOTMPDIR"]) / "go-build-fake" / "b001"
            work_dir.mkdir(parents=True)
            entries = "\n".join(f'\t{{"{name}", _test.{name}}},' for name in self.registered_tests)
            (work_dir / "_testmain.go").write_text(f"package main\nvar tests = []testing.InternalTest{{\n{entries}\n}}\n", encoding="utf-8")
            output = (output[0], output[1], output[2] + f"WORK={work_dir.parent}\n")
        rc, stdout, stderr = output
        return subprocess.CompletedProcess(cmd, rc, stdout, stderr)


GO_COMPILE = ("go", "test", "-c", "-work", "-o", "*", "./node")
CARGO_LIST = ("cargo", "test", "--locked", "-p", "rubin-node", "--lib", "--", "--list")
CARGO_IGNORED_LIST = ("cargo", "test", "--locked", "-p", "rubin-node", "--lib", "--", "--ignored", "--list")


def go_objdump_cmd(test_name: str) -> tuple[str, ...]: return ("go", "tool", "objdump", "-s", rf".*\.{test_name}$", "*")


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

    def test_runtime_evidence_schema_path_success_without_test_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            write_runtime_source(root, "clients/go/node/sync_reorg_test.go")
            write_runtime_source(root, "clients/rust/crates/rubin-node/src/sync_reorg.rs")
            set_runtime_evidence(
                root,
                {
                    "tests_by_file": {
                        "clients/go/node/sync_reorg_test.go": ["TestDeclaredButNotScanned"],
                        "clients/rust/crates/rubin-node/src/sync_reorg.rs": ["declared_but_not_scanned"],
                    }
                },
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_runtime_evidence_opt_in_verifies_declared_tests_with_toolchains(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rubin path ") as td:
            root = Path(td)
            make_runtime_evidence_repo(
                root,
                {
                    "clients/go/node/sync_reorg_test.go": ["TestRuntimeReorg"],
                    "clients/rust/crates/rubin-node/src/sync_reorg.rs": ["runtime_reorg_test"],
                },
            )
            runner = FakeCommandRunner(
                {
                    GO_COMPILE: (0, "", ""),
                    go_objdump_cmd("TestRuntimeReorg"): (
                        0,
                        f"TEXT pkg.TestRuntimeReorg(SB) {(root / 'clients/go/node/sync_reorg_test.go').resolve()}\n",
                        "",
                    ),
                }
            )
            with chdir(root):
                rc = m.main(["--verify-runtime-evidence-go"], command_runner=runner)
        self.assertEqual(rc, 0)
        self.assertFalse(any("-list" in call[0] for call in runner.calls))
        self.assertTrue(all(call[0][0] != "cargo" for call in runner.calls))
        go_envs = [env for call, env in zip(runner.calls, runner.envs) if call[0][0] == "go"]
        self.assertTrue(go_envs)
        self.assertTrue(all(env["GOENV"] == "off" for env in go_envs))
        self.assertTrue(all(env["GOFLAGS"] == "-buildvcs=false" for env in go_envs))

    def test_runtime_evidence_rust_opt_in_verifies_declared_tests_with_cargo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_runtime_evidence_repo(
                root,
                {
                    "clients/rust/crates/rubin-node/src/sync_reorg.rs": ["runtime_reorg_test"],
                    "clients/rust/crates/rubin-node/src/txpool.rs": ["txpool_runtime_test"],
                },
            )
            runner = FakeCommandRunner({
                CARGO_LIST: (0, "sync_reorg::tests::runtime_reorg_test: test\ntxpool::tests::txpool_runtime_test: test\n", "warning: wrapper noise is not evidence\n"),
                CARGO_IGNORED_LIST: (0, "", ""),
            })
            forged_env = dict.fromkeys(
                [
                    "CARGO_BUILD_TARGET",
                    "CARGO_BUILD_RUSTC_WRAPPER",
                    "CARGO_BUILD_RUSTFLAGS",
                    "CARGO_ENCODED_RUSTFLAGS",
                    "CARGO_NET_OFFLINE",
                    "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
                    "RUSTC",
                    "RUSTC_WRAPPER",
                    "RUSTFLAGS",
                ],
                "forged",
            ) | {"CARGO_TARGET_DIR": str(root / "forged-target-dir")}
            with unittest.mock.patch.dict(os.environ, forged_env, clear=False):
                with chdir(root):
                    rc = m.main(["--verify-runtime-evidence-rust"], command_runner=runner)
        self.assertEqual(rc, 0)
        self.assertIn((CARGO_LIST, (root / "clients" / "rust").resolve()), runner.calls)
        self.assertEqual(1, [call[0] for call in runner.calls].count(CARGO_LIST))
        self.assertEqual(1, [call[0] for call in runner.calls].count(CARGO_IGNORED_LIST))
        scrubbed = set(forged_env) - {"CARGO_TARGET_DIR"}
        cargo_envs = [env for call, env in zip(runner.calls, runner.envs) if call[0][0] == "cargo"]
        self.assertTrue(cargo_envs)
        for env in cargo_envs:
            if env is None:
                self.fail("cargo discovery env must be set")
            self.assertEqual(env["CARGO_INCREMENTAL"], "0")
            self.assertTrue(all("rubin-rust-test-list-" in env[key] for key in ("CARGO_HOME", "HOME", "CARGO_TARGET_DIR")))
            self.assertNotEqual(env["CARGO_TARGET_DIR"], str(root / "forged-target-dir"))
            self.assertTrue(scrubbed.isdisjoint(env))

    def test_runtime_evidence_rust_package_name_accepts_toml_quotes_and_comments(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            crate_root = root / "clients" / "rust" / "crates" / "rubin-node"
            write_runtime_source(root, "clients/rust/crates/rubin-node/Cargo.toml", "[package]\nname = 'rubin-node' # inline comment\n")
            self.assertEqual(("rubin-node", None), m.rust_package_name(crate_root))
            with unittest.mock.patch.object(m, "toml_parser", None):
                self.assertEqual(("rubin-node", None), m.rust_package_name(crate_root))

    def test_runtime_evidence_rust_opt_in_rejects_wrong_module_and_ignored_tests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_runtime_evidence_repo(
                root,
                {
                    "clients/rust/crates/rubin-node/src/sync_reorg.rs": [
                        "runtime_reorg_test",
                        "ignored_runtime_reorg_test",
                    ]
                },
            )
            runner = FakeCommandRunner({
                CARGO_LIST: (0, "other_module::tests::runtime_reorg_test: test\nsync_reorg::child::tests::runtime_reorg_test: test\nsync_reorg::tests::child::runtime_reorg_test: test\nsync_reorg::tests::ignored_runtime_reorg_test: test\n", ""),
                CARGO_IGNORED_LIST: (0, "sync_reorg::tests::ignored_runtime_reorg_test: test\n", ""),
            })
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main(["--verify-runtime-evidence-rust"], command_runner=runner)
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime evidence tests: runtime_reorg_test, ignored_runtime_reorg_test", captured.getvalue())

    def test_runtime_evidence_rust_opt_in_rejects_unsupported_source_scopes(self) -> None:
        cases = [
            ("clients/rust/crates/rubin-node/src/lib.rs", None),
            ("clients/rust/crates/rubin-node/src/sync_reorg/mod.rs", None),
            ("clients/rust/crates/rubin-node/tests/runtime_reorg.rs", None),
            ("clients/rust/crates/rubin-node/src/sync_reorg.rs", "#[cfg(test)]\nmod tests;\n"),
        ]
        for rel_path, source in cases:
            with self.subTest(rel_path=rel_path), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                make_runtime_evidence_repo(root, {rel_path: ["runtime_reorg_test"]})
                source is not None and write_runtime_source(root, rel_path, source)
                captured = io.StringIO()
                with chdir(root), contextlib.redirect_stderr(captured):
                    rc = m.main(
                        ["--verify-runtime-evidence-rust"],
                        command_runner=FakeCommandRunner({CARGO_LIST: (0, "", ""), CARGO_IGNORED_LIST: (0, "", "")}),
                    )
            self.assertEqual(rc, 1)
            self.assertIn("unsupported Rust runtime evidence source scope", captured.getvalue())

    def test_runtime_evidence_rust_opt_in_rejects_repo_cargo_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_runtime_evidence_repo(root, {"clients/rust/crates/rubin-node/src/sync_reorg.rs": ["runtime_reorg_test"]})
            config = root / "clients" / "rust" / ".cargo" / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text("[build]\nrustflags = [\"--cfg\", \"forged\"]\n", encoding="utf-8")
            with chdir(root), contextlib.redirect_stderr(io.StringIO()) as captured:
                rc = m.main(
                    ["--verify-runtime-evidence-rust"],
                    command_runner=FakeCommandRunner({CARGO_LIST: (0, "sync_reorg::tests::runtime_reorg_test: test\n", ""), CARGO_IGNORED_LIST: (0, "", "")}),
                )
        self.assertEqual(rc, 1)
        self.assertIn("unsupported Rust runtime evidence Cargo config", captured.getvalue())

    def test_runtime_evidence_opt_in_accepts_external_package_go_tests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_runtime_evidence_repo(root, {"clients/go/node/sync_reorg_test.go": ["TestRuntimeReorg"]})
            runner = FakeCommandRunner({GO_COMPILE: (0, "", "")}, registered_tests=[])

            def external_testmain(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                completed = runner(cmd, **kwargs)
                if tuple(cmd[:4]) == ("go", "test", "-c", "-work"):
                    work_root = Path(str(completed.stderr).split("WORK=", 1)[1].strip())
                    (work_root / "b001" / "_testmain.go").write_text(
                        'package main\nvar tests = []testing.InternalTest{\n\t{"TestRuntimeReorg", _xtest.TestRuntimeReorg},\n}\n',
                        encoding="utf-8",
                    )
                return completed

            runner.outputs[go_objdump_cmd("TestRuntimeReorg")] = (
                0,
                f"TEXT pkg.TestRuntimeReorg(SB) {(root / 'clients/go/node/sync_reorg_test.go').resolve()}\n",
                "",
            )
            with chdir(root):
                rc = m.main(["--verify-runtime-evidence-go"], command_runner=external_testmain)
        self.assertEqual(rc, 0)

    def test_runtime_evidence_opt_in_sanitizes_ambient_go_flags(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_runtime_evidence_repo(root, {"clients/go/node/sync_reorg_test.go": ["TestRuntimeReorg"]})
            runner = FakeCommandRunner(
                {
                    GO_COMPILE: (0, "", ""),
                    go_objdump_cmd("TestRuntimeReorg"): (
                        0,
                        f"TEXT pkg.TestRuntimeReorg(SB) {(root / 'clients/go/node/sync_reorg_test.go').resolve()}\n",
                        "",
                    ),
                }
            )
            with unittest.mock.patch.dict(os.environ, {"GOFLAGS": "-tags=forged", "GOENV": str(root / "forged_goenv")}, clear=False):
                with chdir(root):
                    rc = m.main(["--verify-runtime-evidence-go"], command_runner=runner)
        self.assertEqual(rc, 0)
        go_envs = [env for call, env in zip(runner.calls, runner.envs) if call[0][0] == "go"]
        self.assertTrue(go_envs)
        self.assertTrue(all(env["GOENV"] == "off" for env in go_envs))
        self.assertTrue(all(env["GOFLAGS"] == "-buildvcs=false" for env in go_envs))

    def test_go_objdump_source_match_accepts_spaces_and_trimpath(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rubin path ") as td:
            repo_root = Path(td) / "clients/go/wrapper/repo"
            source = repo_root / "clients/go/node/sync_reorg_test.go"
            self.assertTrue(m.go_objdump_matches_source(f"TEXT pkg.TestA(SB) {source}\n", source_path=source, repo_root=repo_root))
            self.assertTrue(
                m.go_objdump_matches_source(
                    "TEXT pkg.TestA(SB) github.com/rubin/clients/go/node/sync_reorg_test.go\n",
                    source_path=source,
                    repo_root=repo_root,
                )
            )

    def test_runtime_evidence_opt_in_rejects_missing_exact_or_wrong_file_names(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_runtime_evidence_repo(
                root,
                {
                    "clients/go/node/sync_reorg_test.go": ["TestRuntimeReorg"],
                    "clients/rust/crates/rubin-node/src/sync_reorg.rs": ["runtime_reorg_test"],
                },
            )
            runner = FakeCommandRunner(
                {
                    GO_COMPILE: (0, "", ""),
                    go_objdump_cmd("TestRuntimeReorg"): (
                        0,
                        f"TEXT pkg.TestRuntimeReorg(SB) {(root / 'clients/go/node/config_test.go').resolve()}\n",
                        "",
                    ),
                }
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main(["--verify-runtime-evidence-go"], command_runner=runner)
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime evidence tests: TestRuntimeReorg", captured.getvalue())

    def test_runtime_evidence_opt_in_rejects_compiled_non_test_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_runtime_evidence_repo(root, {"clients/go/node/sync_reorg_test.go": ["TestRuntimeReorg"]})
            runner = FakeCommandRunner(
                {
                    GO_COMPILE: (0, "", ""),
                    go_objdump_cmd("TestRuntimeReorg"): (
                        0,
                        f"TEXT pkg.TestRuntimeReorg(SB) {(root / 'clients/go/node/sync_reorg_test.go').resolve()}\n",
                        "",
                    ),
                },
                registered_tests=[],
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main(["--verify-runtime-evidence-go"], command_runner=runner)
        self.assertEqual(rc, 1)
        self.assertIn("missing runtime evidence tests: TestRuntimeReorg", captured.getvalue())

    def test_runtime_evidence_opt_in_fails_closed_for_toolchain_error_and_timeout(self) -> None:
        def timeout_runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(["go"], 30)

        for runner, expected in [
            (FakeCommandRunner({GO_COMPILE: (1, "", "go compile failed")}), "failed: go exit 1"),
            (FakeCommandRunner({GO_COMPILE: PermissionError("not executable")}), "failed to start: go: not executable"),
            (timeout_runner, "timed out"),
        ]:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                make_runtime_evidence_repo(root, {"clients/go/node/sync_reorg_test.go": ["TestRuntimeReorg"]})
                captured = io.StringIO()
                with chdir(root), contextlib.redirect_stderr(captured):
                    rc = m.main(["--verify-runtime-evidence-go"], command_runner=runner)
            self.assertEqual(rc, 1)
            self.assertIn(f"runtime_evidence discovery command {expected}", captured.getvalue())

    def test_runtime_evidence_rejects_schema_path_and_source_boundary_errors(self) -> None:
        def base_runtime_evidence(path: str = "clients/go/node/sync_reorg_test.go") -> dict:
            return {"tests_by_file": {path: ["TestRuntimeEvidence"]}}

        cases = [
            ("scalar runtime_evidence", "invalid", None, "runtime_evidence must be object"),
            (
                "missing tests_by_file",
                {},
                None,
                "runtime_evidence.tests_by_file must be present",
            ),
            (
                "empty tests_by_file",
                {"tests_by_file": {}},
                None,
                "runtime_evidence.tests_by_file must be non-empty object",
            ),
            (
                "blank path key",
                {"tests_by_file": {"   ": ["TestRuntimeEvidence"]}},
                None,
                "runtime_evidence.tests_by_file keys must be non-empty repo-relative strings",
            ),
            (
                "empty test list",
                {"tests_by_file": {"clients/go/node/sync_reorg_test.go": []}},
                None,
                "runtime_evidence.tests_by_file[clients/go/node/sync_reorg_test.go] must be non-empty list",
            ),
            (
                "duplicate test names",
                {"tests_by_file": {"clients/go/node/sync_reorg_test.go": ["TestA", "TestA"]}},
                None,
                "runtime_evidence.tests_by_file[clients/go/node/sync_reorg_test.go] entries must be unique",
            ),
            (
                "absolute path",
                base_runtime_evidence("/clients/go/node/sync_reorg_test.go"),
                None,
                "runtime_evidence source path must be repo-relative",
            ),
            (
                "traversal path",
                base_runtime_evidence("clients/go/../node/sync_reorg_test.go"),
                None,
                "runtime_evidence source path must not contain '..'",
            ),
            (
                "unsupported root",
                base_runtime_evidence("scripts/sync_reorg_test.py"),
                lambda root: write_runtime_source(root, "scripts/sync_reorg_test.py"),
                "runtime_evidence source path must be under clients/go or clients/rust",
            ),
            (
                "go wrong suffix",
                base_runtime_evidence("clients/go/node/sync_reorg.go"),
                lambda root: write_runtime_source(root, "clients/go/node/sync_reorg.go"),
                "Go runtime evidence paths must end with _test.go",
            ),
            (
                "rust wrong suffix",
                base_runtime_evidence("clients/rust/crates/rubin-node/src/sync_reorg_test.go"),
                lambda root: write_runtime_source(root, "clients/rust/crates/rubin-node/src/sync_reorg_test.go"),
                "Rust runtime evidence paths must end with .rs",
            ),
            (
                "missing source",
                base_runtime_evidence(),
                lambda root: None,
                "runtime_evidence source path does not exist",
            ),
            (
                "directory source",
                base_runtime_evidence(),
                lambda root: (root / "clients/go/node/sync_reorg_test.go").mkdir(parents=True),
                "runtime_evidence source path must be a regular file",
            ),
            (
                "oversize source",
                base_runtime_evidence(),
                lambda root: write_runtime_source(
                    root,
                    "clients/go/node/sync_reorg_test.go",
                    "x" * (m.RUNTIME_EVIDENCE_MAX_SOURCE_BYTES + 1),
                ),
                "runtime_evidence source file exceeds max size",
            ),
        ]
        for name, runtime_evidence, setup, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                make_repo(root)
                if setup is None:
                    write_runtime_source(root, "clients/go/node/sync_reorg_test.go")
                else:
                    setup(root)
                set_runtime_evidence(root, runtime_evidence)
                captured = io.StringIO()
                with chdir(root), contextlib.redirect_stderr(captured):
                    rc = m.main()
            self.assertEqual(rc, 1)
            self.assertIn(expected, captured.getvalue())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support unavailable")
    def test_runtime_evidence_rejects_symlink_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            target = write_runtime_source(root, "external.go")
            link = root / "clients/go/node/sync_reorg_test.go"
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(target)
            set_runtime_evidence(root, {"tests_by_file": {"clients/go/node/sync_reorg_test.go": ["TestA"]}})
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("runtime_evidence source path must not contain symlinks", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
