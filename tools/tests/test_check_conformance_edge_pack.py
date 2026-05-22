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


def add_runtime_evidence(root: Path, rel_path: str, tests: list[str]) -> None:
    baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline["domains"][0]["runtime_evidence"] = {"tests_by_file": {rel_path: tests}}
    write_json(baseline_path, baseline)


def run_runtime_evidence(root: Path, rel_path: str, source: str, tests: list[str]) -> tuple[int, str]:
    (root / rel_path).parent.mkdir(parents=True, exist_ok=True)
    (root / rel_path).write_text(source, encoding="utf-8")
    add_runtime_evidence(root, rel_path, tests)
    captured = io.StringIO()
    with chdir(root), contextlib.redirect_stderr(captured):
        rc = m.main()
    return rc, captured.getvalue()


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

    def test_runtime_evidence_accepts_go_and_rust_test_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            go_path = "clients/go/node/sync_reorg_test.go"
            rust_path = "clients/rust/crates/rubin-node/src/sync_reorg.rs"
            (root / go_path).parent.mkdir(parents=True, exist_ok=True)
            (root / rust_path).parent.mkdir(parents=True, exist_ok=True)
            go_source = "\ufeffpackage node\n\nimport (\"fmt\"; . `testing`)\n\nvar _ = fmt.Sprintf\nfunc TestRuntimeReorg(t * T) {}\nfunc TestMultiline(\n    t *T,\n) {}\nfunc Test1Bad(t *T) {}\nfunc Test_Bad(t *T) {}\n"
            rust_source = "#[cfg(test)]\nmod tests {\nfn helper<'a>() {}\n#[cfg(any(test, feature = \"x\"))]\n#[test] #[should_panic] fn runtime_reorg_test() { panic!() }\n#[cfg(all(test,))]\n#[test] fn runtime_reorg_cfg_trailing_test() {}\n#[cfg_attr(not(test), ignore)]\n#[test] fn runtime_reorg_cfg_attr_test() {}\n}\n"
            (root / go_path).write_text(go_source, encoding="utf-8")
            (root / rust_path).write_text(rust_source, encoding="utf-8")
            baseline_path = root / "conformance" / "EDGE_PACK_BASELINE.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["domains"][0]["runtime_evidence"] = {
                "tests_by_file": {
                    go_path: ["TestRuntimeReorg", "TestMultiline", "Test1Bad", "Test_Bad"],
                    rust_path: ["runtime_reorg_test", "runtime_reorg_cfg_trailing_test", "runtime_reorg_cfg_attr_test"],
                }
            }
            write_json(baseline_path, baseline)
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stdout(captured):
                rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK: conformance edge-pack baseline satisfied.", captured.getvalue())

    def test_runtime_evidence_ignores_comments_and_raw_strings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            rel_path = "clients/rust/crates/rubin-node/src/sync_reorg.rs"
            rc, stderr = run_runtime_evidence(
                root,
                rel_path,
                '/* #[test] fn fake_comment() {} */\nconst S: &str = r#"#[test]\nfn fake_raw() {}"#;\n',
                ["fake_comment", "fake_raw"],
            )
        self.assertEqual(rc, 1)
        self.assertIn("fake_comment, fake_raw", stderr)

    def test_runtime_evidence_rejects_non_discoverable_go_tests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cases = [
                (
                    "clients/go/node/sync_reorg_test.go",
                    "package node\n\nimport \"testing\"\n\nfunc Testlower() {}\nfunc TestWrong(t string) {}\nfunc TestExtra(t *testing.T, n int) {}\n",
                    ["Testlower", "TestWrong", "TestExtra"],
                    "Testlower, TestWrong, TestExtra",
                ),
                ("clients/go/node/sync_reorg.go", "package node\n\nimport \"testing\"\n\nfunc TestWrongFile(t *testing.T) {}\n", ["TestWrongFile"], "must end with _test.go"),
                ("clients/go/node/sync_reorg_test.go", "package node\n/*\nimport \"testing\"\n*/\nfunc TestCommentImport(t *testing.T) {}\n", ["TestCommentImport"], "TestCommentImport"),
                (
                    "clients/go/node/sync_reorg_test.go",
                    "package node\nvar _ = `\nimport \"testing\"\n`\nvar _ = \"\\nimport \\\"testing\\\"\\n\"\nfunc TestRawImport(t *testing.T) {}\nfunc TestStringImport(t *testing.T) {}\n",
                    ["TestRawImport", "TestStringImport"],
                    "TestRawImport, TestStringImport",
                ),
                ("clients/go/node/sync_reorg_test.go", "/* lead */\n//\t+build never\n\npackage node\n\nimport \"testing\"\n\nfunc TestTaggedOut(t *testing.T) {}\n", ["TestTaggedOut"], "TestTaggedOut"),
                ("clients/go/node/sync_reorg_windows_test.go", "package node\n\nimport \"testing\"\n\nfunc TestTaggedByFileName(t *testing.T) {}\n", ["TestTaggedByFileName"], "must not use GOOS/GOARCH file constraints"),
                ("clients/go/node/sync_reorg_test.go", "package node\n\nfunc TestNoImport(t *testing.T) {}\n", ["TestNoImport"], "TestNoImport"),
            ]
            for rel_path, source, tests, want in cases:
                with self.subTest(want=want):
                    root = Path(td) / want.split()[0].replace(",", "")
                    make_repo(root)
                    rc, stderr = run_runtime_evidence(root, rel_path, source, tests)
                    self.assertEqual(rc, 1)
                    self.assertIn(want, stderr)

    def test_runtime_evidence_rejects_inactive_or_non_plain_rust_tests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root)
            rel_path = "clients/rust/crates/rubin-node/src/sync_reorg.rs"
            (root / rel_path).parent.mkdir(parents=True, exist_ok=True)
            (root / rel_path).write_text(
                "#[test]\n#[ignore]\nfn ignored() {}\n#[ignore]\n#[test]\nfn ignored_before() {}\n"
                "#[test]\n#[cfg(FALSE)]\nfn cfg_disabled() {}\n#[cfg(FALSE)]\n#[test]\nfn cfg_before() {}\n"
                "#[cfg(any(not(test), feature = \"never\"))]\n#[test]\nfn cfg_nested_not_test() {}\n"
                "#[cfg(\nFALSE\n)]\n#[test]\nfn cfg_multiline() {}\n#[cfg_attr(\ntest,\nignore\n)]\n#[test]\nfn cfg_attr_multiline() {}\n"
                "#[cfg(FALSE)]\nmod disabled { #[test]\nfn disabled_module() {} }\n#[cfg(FALSE)]\n#[allow(dead_code)]\nmod disabled_stacked { #[test]\nfn disabled_mod_test() {} }\n"
                "#[cfg(FALSE)]\nmod disabled_brace { const C: char = '}'; #[test]\nfn disabled_brace_module() {} }\n"
                "#[cfg(FALSE)]\nmod disabled_next\n{\n#[test]\nfn disabled_next_line_brace() {}\n}\n#[test]\nconst fn const_test() {}\n#[test]\nunsafe fn unsafe_test() {}\n#[test]\nextern \"C\" fn extern_test() {}\n#[test]\nfn arg_test(x: i32) {}\n"
                "mod inner_disabled {\n#![cfg(FALSE)]\n#[test]\nfn inner_cfg() {}\n}\n",
                encoding="utf-8",
            )
            add_runtime_evidence(
                root,
                rel_path,
                (
                    "ignored ignored_before cfg_disabled cfg_before cfg_nested_not_test cfg_multiline cfg_attr_multiline "
                    "disabled_module disabled_mod_test disabled_brace_module disabled_next_line_brace "
                    "const_test unsafe_test extern_test arg_test inner_cfg"
                ).split(),
            )
            captured = io.StringIO()
            with chdir(root), contextlib.redirect_stderr(captured):
                rc = m.main()
        self.assertEqual(rc, 1)
        self.assertIn("disabled_brace_module, disabled_next_line_brace, const_test", captured.getvalue())

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


if __name__ == "__main__":
    unittest.main()
