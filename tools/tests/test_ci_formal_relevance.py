import subprocess
import unittest

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
    def decision(self, payload: bytes) -> subject.Decision:
        return subject.decide("pull_request", "main", runner(payload))

    def test_every_protected_family_runs(self):
        paths = [
            ".github/workflows/ci.yml",
            "rubin-formal/A.lean",
            "conformance/vector.json",
            "clients/go/consensus/a.go",
            "clients/rust/crates/rubin-consensus/src/lib.rs",
            "tools/formal/generate.py",
            "scripts/crypto/openssl/build-openssl-bundle.sh",
            "scripts/crypto/openssl/source-checksums.sha256",
            "README.md",
            "SPEC_LOCATION.md",
            *sorted(path for path in subject.PROTECTED_EXACT if path.startswith("tools/")),
        ]
        for path in paths:
            with self.subTest(path=path):
                decision = self.decision(diff(("M", path)))
                self.assertTrue(decision.run_formal)
                self.assertEqual(decision.reason, f"protected path: {path}")

    def test_every_skippable_family_skips(self):
        paths = [
            "tools/ordinary.py",
            "scripts/ordinary.sh",
            "clients/rust/crates/wallet/src/lib.rs",
            *sorted(subject.SKIPPABLE_EXACT),
        ]
        for path in paths:
            with self.subTest(path=path):
                decision = self.decision(diff(("M", path)))
                self.assertFalse(decision.run_formal)
                self.assertEqual(decision.path_count, 1)

    def test_pr_template_only_skips(self):
        self.assertFalse(
            self.decision(diff(("M", ".github/PULL_REQUEST_TEMPLATE.md"))).run_formal
        )

    def test_protected_precedence_over_broad_allowlists(self):
        for path in (
            "tools/formal/generate.py",
            "tools/check_formal_coverage.py",
            "scripts/crypto/openssl/build-openssl-bundle.sh",
            "clients/rust/crates/rubin-consensus/src/lib.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(self.decision(diff(("M", path))).run_formal)

    def test_unknown_mixed_and_nearest_misses_run(self):
        cases = [
            diff(("A", "docs/new.md")),
            diff(("A", ".github/workflows/new.yml")),
            diff(("M", "tools/ok.py"), ("M", "README.md")),
            diff(("M", "README.markdown")),
            diff(("M", "rubin-formality/file")),
            diff(("M", "client/rust/file")),
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertTrue(self.decision(payload).run_formal)

    def test_add_delete_rename_and_copy_parse_all_paths(self):
        cases = [
            (diff(("A", "tools/a.py"), ("D", "scripts/b.sh")), False),
            (diff(("R100", "README.md", "tools/readme.txt")), True),
            (diff(("R090", "tools/readme.txt", "README.md")), True),
            (diff(("C075", "tools/a.py", "scripts/a.py")), False),
            (diff(("C100", "tools/a.py", "rubin-formal/A.lean")), True),
        ]
        for payload, expected in cases:
            with self.subTest(payload=payload):
                self.assertEqual(self.decision(payload).run_formal, expected)

    def test_fips_preflight_skips_but_bundle_build_runs(self):
        self.assertFalse(
            self.decision(diff(("M", "scripts/crypto/openssl/fips-preflight.sh"))).run_formal
        )
        self.assertTrue(
            self.decision(
                diff(("M", "scripts/crypto/openssl/build-openssl-bundle.sh"))
            ).run_formal
        )

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
                self.assertTrue(self.decision(payload).run_formal)

    def test_environment_and_git_failures_run(self):
        self.assertTrue(subject.decide("push", "", runner()).run_formal)
        self.assertTrue(subject.decide("pull_request", "", runner()).run_formal)
        self.assertTrue(
            subject.decide(
                "pull_request", "main", runner(verify_code=1)
            ).run_formal
        )
        self.assertTrue(
            subject.decide(
                "pull_request", "main", runner(diff_code=1)
            ).run_formal
        )


if __name__ == "__main__":
    unittest.main()
