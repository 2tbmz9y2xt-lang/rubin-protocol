import subprocess
import unittest
from pathlib import Path

from tools import ci_formal_relevance as subject

def diff(*records: tuple[str, ...]) -> bytes:
    return b"".join(
        b"\0".join(field.encode() for field in record) + b"\0"
        for record in records
    )

def runner(
    payload: bytes = b"M\0tools/format.py\0",
    *,
    verify_code: int = 0,
    diff_code: int = 0,
):
    def run(command, **_kwargs):
        if command[1] == "rev-parse":
            return subprocess.CompletedProcess(command, verify_code, b"base\n", b"")
        return subprocess.CompletedProcess(command, diff_code, payload, b"")

    return run

class FormalRelevanceTests(unittest.TestCase):
    def decision(self, job: str, payload: bytes) -> subject.Decision:
        return subject.decide(job, "pull_request", "main", runner(payload))

    def assert_jobs(self, path: str, formal: bool, refinement: bool):
        payload = diff(("M", path))
        self.assertEqual(self.decision("formal", payload).run_formal, formal, path)
        self.assertEqual(
            self.decision("formal_refinement", payload).run_formal, refinement, path
        )

    def test_input_families_and_exact_exclusions(self):
        cases = {
            ".github/workflows/ci.yml": (True, True),
            "tools/ci_formal_relevance.py": (True, True),
            "rubin-formal/RubinFormal/X.lean": (True, True),
            "conformance/fixtures/CV-X.json": (True, True),
            "README.md": (True, False),
            "conformance/MATRIX.md": (True, False),
            "rubin-formal/tests/test_x.py": (True, False),
            "tools/check_formal_coverage.py": (True, False),
            "clients/go/consensus/x.go": (True, True),
            "clients/go/consensus/sub/x.go": (False, True),
            "clients/rust/crates/rubin-consensus/src/x.rs": (True, False),
            "clients/rust/crates/rubin-consensus/src/x_tests.rs": (True, False),
            "clients/go/go.mod": (False, True),
            "clients/go/cmd/formal-trace/x.go": (False, True),
            "tools/formal/gen_lean_conformance_vectors.py": (False, True),
            ".github/actions/openssl-bundle/action.yml": (False, True),
            "scripts/crypto/openssl/VERSION": (False, True),
            "scripts/crypto/openssl/build-openssl-bundle.sh": (False, True),
            "tools/tests/test_ci_formal_relevance.py": (False, False),
            ".github/PULL_REQUEST_TEMPLATE.md": (False, False),
            "rubin-formal/RISK_MODEL.md": (False, False),
            "rubin-formal/lakefile.toml": (False, False),
            "rubin-formal/traces/schema_v1.json": (False, False),
            "conformance/fixtures/devnet/CV-X.json": (False, False),
            "conformance/fixtures/CHANGELOG.md": (False, False),
            "clients/go/consensus/x_test.go": (False, False),
            "clients/rust/crates/rubin-consensus/src/tests/x.rs": (False, False),
            "clients/rust/crates/rubin-consensus/src/x_test.rs": (False, False),
            "clients/rust/crates/wallet/src/lib.rs": (False, False),
            "tools/ordinary.py": (False, False),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assert_jobs(path, *expected)

    def test_tracked_inventory_counts(self):
        paths = subprocess.run(
            ["git", "ls-files"], check=True, stdout=subprocess.PIPE, text=True
        ).stdout.splitlines()
        formal = {path for path in paths if subject.is_formal_input(path)}
        refinement = {path for path in paths if subject.is_refinement_input(path)}
        self.assertEqual(
            (len(formal), len(refinement), len(formal & refinement), len(formal | refinement)),
            (416, 338, 323, 431),
        )

    def test_every_exact_input_uses_its_job_profile(self):
        for path in subject.FORMAL_EXACT:
            with self.subTest(job="formal", path=path):
                self.assertTrue(subject.is_formal_input(path))
        for path in subject.REFINEMENT_EXACT:
            with self.subTest(job="formal_refinement", path=path):
                self.assertTrue(subject.is_refinement_input(path))

    def test_lake_cache_keys_bind_compatibility_and_formal_sources(self):
        workflow = (
            Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
        ).read_text()
        compatibility = "${{ hashFiles('rubin-formal/lean-toolchain', 'rubin-formal/lakefile.lean', 'rubin-formal/lake-manifest.json') }}"
        sources = "${{ hashFiles('rubin-formal/RubinFormal.lean', 'rubin-formal/RubinFormal/**/*.lean') }}"
        for namespace in ("lake-formal-v2", "lake-refinement-v2"):
            key = f"          key: {namespace}-${{{{ runner.os }}}}-{compatibility}-{sources}\n"
            restore = f"            {namespace}-${{{{ runner.os }}}}-{compatibility}-\n"
            self.assertEqual(workflow.count(key), 1)
            self.assertEqual(workflow.count(restore), 1)
        self.assertNotIn("key: lake-formal-${{", workflow)
        self.assertNotIn("key: lake-refinement-${{", workflow)

    def test_mixed_diff_decides_profiles_independently(self):
        payload = diff(("M", "README.md"), ("M", "clients/go/go.mod"))
        for job in subject.JOBS:
            self.assertTrue(self.decision(job, payload).run_formal)

    def test_add_delete_rename_and_copy_parse_all_paths(self):
        cases = [
            (diff(("A", "tools/a.py"), ("D", "scripts/b.sh")), False, False),
            (diff(("R100", "README.md", "tools/readme.txt")), True, False),
            (diff(("R090", "tools/readme.txt", "clients/go/go.mod")), False, True),
            (diff(("C075", "tools/a.py", "scripts/a.py")), False, False),
            (diff(("C100", "README.md", "docs/readme-copy.md")), True, False),
            (diff(("C100", "tools/a.py", "rubin-formal/RubinFormal/A.lean")), True, True),
        ]
        for payload, formal, refinement in cases:
            with self.subTest(payload=payload):
                self.assertEqual(self.decision("formal", payload).run_formal, formal)
                self.assertEqual(
                    self.decision("formal_refinement", payload).run_formal, refinement
                )

    def test_git_diff_enables_copy_detection_for_unchanged_sources(self):
        commands = []
        subject.decide(
            "formal", "pull_request", "main",
            lambda command, **kwargs: (
                commands.append(command) or runner()(command, **kwargs)
            ),
        )
        self.assertIn("--find-copies", commands[1])
        self.assertIn("--find-copies-harder", commands[1])

    def test_malformed_unknown_and_empty_diffs_run(self):
        for payload in (
            b"",
            b"M\0tools/a.py",
            b"R\0tools/a.py\0scripts/a.py\0",
            *(f"{status}\0tools/a.py\0scripts/a.py\0".encode() for status in ("R1", "R1000", "R101", "Cabc")),
            b"M100\0tools/a.py\0",
            b"Z\0tools/a.py\0",
            b"M\0\0",
            b"M\0\xff\0",
        ):
            with self.subTest(payload=payload):
                for job in subject.JOBS:
                    self.assertTrue(self.decision(job, payload).run_formal)

    def test_environment_and_git_failures_run(self):
        for job in subject.JOBS:
            self.assertTrue(subject.decide(job, "push", "", runner()).run_formal)
            self.assertTrue(subject.decide(job, "pull_request", "", runner()).run_formal)
            self.assertTrue(subject.decide(
                job, "pull_request", "main", runner(verify_code=1)
            ).run_formal)
            self.assertTrue(subject.decide(
                job, "pull_request", "main", runner(diff_code=1)
            ).run_formal)


if __name__ == "__main__":
    unittest.main()
