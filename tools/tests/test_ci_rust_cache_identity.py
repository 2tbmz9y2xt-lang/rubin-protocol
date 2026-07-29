import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPATIBILITY = "${{ hashFiles('clients/rust/Cargo.lock', 'clients/rust/Cargo.toml', 'clients/rust/crates/**/Cargo.toml', 'scripts/crypto/openssl/source-checksums.sha256') }}"
REGISTRY = "${{ hashFiles('clients/rust/Cargo.lock', 'clients/rust/Cargo.toml', 'clients/rust/crates/**/Cargo.toml') }}"
RELEASE = "${{ steps.rust_cache_identity.outputs.release }}"
SOURCES = "${{ hashFiles('clients/rust/**/*.rs') }}"


class RustCacheIdentityTests(unittest.TestCase):
    def workflow(self, name: str) -> str:
        return (ROOT / ".github/workflows" / name).read_text()

    def test_test_and_coverage_targets_have_exact_source_keys(self):
        cases = {
            "ci.yml": "rust-test-v2",
            "codacy-coverage.yml": "rust-coverage-v2",
        }
        for workflow, namespace in cases.items():
            text = self.workflow(workflow)
            with self.subTest(workflow=workflow):
                key = f"          key: {namespace}-${{{{ runner.os }}}}-{RELEASE}-{COMPATIBILITY}-{SOURCES}\n"
                restore = f"            {namespace}-${{{{ runner.os }}}}-{RELEASE}-{COMPATIBILITY}-\n"
                self.assertEqual(text.count(key), 1)
                self.assertEqual(text.count(restore), 1)
                self.assertEqual(text.count("      - name: Resolve Rust cache identity\n"), 1)

    def test_registry_is_separate_and_legacy_target_keys_are_absent(self):
        for workflow in ("ci.yml", "codacy-coverage.yml"):
            text = self.workflow(workflow)
            with self.subTest(workflow=workflow):
                registry = f"          key: cargo-registry-v2-${{{{ runner.os }}}}-{REGISTRY}\n"
                self.assertEqual(text.count(registry), 1)
                self.assertIn("            ~/.cargo/registry/index\n", text)
                self.assertIn("            ~/.cargo/registry/cache\n", text)
                self.assertIn("            ~/.cargo/git/db\n", text)
        self.assertNotIn("key: rust-${{ runner.os }}-", self.workflow("ci.yml"))
        self.assertNotIn(
            "key: rust-coverage-${{ runner.os }}-",
            self.workflow("codacy-coverage.yml"),
        )


if __name__ == "__main__":
    unittest.main()
