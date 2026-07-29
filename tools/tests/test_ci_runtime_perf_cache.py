import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/runtime-perf-guardrails.yml"
SUITE = ROOT / "scripts/runtime_perf/run_runtime_perf_suite.sh"
COMPATIBILITY = "${{ hashFiles('clients/rust/Cargo.lock', 'clients/rust/Cargo.toml', 'clients/rust/crates/**/Cargo.toml', 'scripts/crypto/openssl/source-checksums.sha256') }}"
SOURCES = "${{ hashFiles('clients/rust/**', 'conformance/fixtures/**') }}"
RELEASE = "${{ steps.rust_cache_identity.outputs.release }}"


class RuntimePerfCacheTests(unittest.TestCase):
    def test_workflow_has_one_compatible_shared_target(self):
        text = WORKFLOW.read_text()
        key = (
            "          key: runtime-perf-v2-${{ runner.os }}-"
            f"{RELEASE}-{COMPATIBILITY}-{SOURCES}\n"
        )
        restore = (
            "            runtime-perf-v2-${{ runner.os }}-"
            f"{RELEASE}-{COMPATIBILITY}-\n"
        )
        self.assertEqual(text.count(key), 1)
        self.assertEqual(text.count(restore), 1)
        self.assertEqual(
            text.count("          CARGO_TARGET_DIR: ${{ runner.temp }}/runtime-perf-target\n"),
            2,
        )
        self.assertIn("          path: ${{ runner.temp }}/runtime-perf-target\n", text)

    def test_suite_uses_only_the_explicit_target_for_criterion(self):
        text = SUITE.read_text()
        self.assertIn('CARGO_TARGET_DIR must be an absolute path', text)
        self.assertIn('CRITERION_ROOT="$CARGO_TARGET_DIR/criterion"', text)
        self.assertIn('--criterion-root "$CRITERION_ROOT"', text)
        self.assertNotIn("clients/rust/target/criterion", text)
        clean = "if ! cargo clean --workspace; then"
        self.assertEqual(text.count(clean), 1)
        self.assertLess(text.index(clean), text.index("cargo bench -p rubin-node"))
        self.assertIn('echo "failed to invalidate Rust workspace artifacts" >&2', text)


if __name__ == "__main__":
    unittest.main()
