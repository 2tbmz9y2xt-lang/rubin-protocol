from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.check_openssl_version_consistency import check_repo

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/combined-load-nightly.yml"


class OpenSSLVersionConsistencyTests(unittest.TestCase):
    def fixture(self, tmp: str) -> Path:
        root = Path(tmp)
        for relative in (".github/workflows", "scripts/crypto/openssl", "scripts/dev-env.sh",
                         "tools/tests/test_openssl_bundle_contract.py"):
            source, target = REPO_ROOT / relative, root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, target) if source.is_dir() else shutil.copy2(source, target)
        return root

    def mutate(self, root: Path, relative: str, old: str, new: str) -> None:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def assert_rejected(self, relative: str, old: str, new: str, message: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            self.mutate(root, relative, old, new)
            errors = check_repo(root)
            self.assertTrue(any(message in error for error in errors), errors)

    def test_live_historical_and_complete_bump_are_accepted(self) -> None:
        self.assertEqual(check_repo(REPO_ROOT), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            pin = root / "scripts/crypto/openssl/source-checksums.sha256"
            pin.write_text(pin.read_text(encoding="utf-8") + f"{'a' * 64}  openssl-3.4.0.tar.gz\n", encoding="utf-8")
            self.assertEqual(check_repo(root), [])
            for path in root.rglob("*"):
                if path.is_file():
                    text = path.read_text(encoding="utf-8")
                    updated = text.replace("3.5.5", "3.6.0").replace(r"3\.5\.5", r"3\.6\.0")
                    path.write_text(updated.replace("OpenSSL 3.5", "OpenSSL 3.6"), encoding="utf-8")
            self.assertEqual(check_repo(root), [])

    def test_owned_stale_dynamic_incomplete_and_decoy_cases_are_rejected(self) -> None:
        pin = "b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89  openssl-3.5.5.tar.gz"
        cases = (
            ("scripts/crypto/openssl/build-openssl-bundle.sh", 'OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"', 'OPENSSL_VERSION="${OPENSSL_VERSION:-$NEXT}"\n# OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"', "builder default"),
            ("scripts/crypto/openssl/build-openssl-bundle.sh", "lookup_pinned_sha256() {", "lookup_pinned_sha256() {\n  OPENSSL_VERSION=3.5.5", "one active authority"),
            ("scripts/crypto/openssl/build-openssl-bundle.sh", "lookup_pinned_sha256() {", "lookup_pinned_sha256() {\n  export OPENSSL_VERSION=3.5.5", "one active authority"),
            ("scripts/crypto/openssl/source-checksums.sha256", pin, f"{pin}\n{pin}", "selected checksum"),
            ("scripts/crypto/openssl/source-checksums.sha256", "b28c9153", "NOTHEX00", "malformed"),
            ("scripts/crypto/openssl/README.md", "OPENSSL_VERSION=3.5.5", "OPENSSL_VERSION=3.5.4", "README"),
            ("scripts/dev-env.sh", "bundle-3.5.5", "bundle-3.5.4", "dev-env"),
            ("scripts/crypto/openssl/bench-pq-speed.py", '"bundle-3.5.5"', '"bundle-3.5.4"  # "bundle-3.5.5"', "speed benchmark"),
            ("scripts/crypto/openssl/bench-pq-pkeyutl.py", "bundle-3.5.5", "bundle-3.5.4", "pkeyutl benchmark"),
            ("tools/tests/test_openssl_bundle_contract.py", 'VERSION = "3.5.5"', 'VERSION = "3.5.4"', "bundle contract"),
            (WORKFLOW, "OPENSSL_VERSION=3.5.5", "OPENSSL_VERSION=$DYNAMIC", "unsupported builder"),
            (WORKFLOW, "bash scripts/crypto/openssl/build-openssl-bundle.sh", 'bash scripts/crypto/openssl/build-openssl-"bundle".sh', "unsupported builder"),
            (WORKFLOW, "bash scripts/crypto/openssl/build-openssl-bundle.sh", "command bash scripts/crypto/openssl/build-openssl-bundle.sh", "unsupported builder"),
            (WORKFLOW, "bash scripts/crypto/openssl/build-openssl-bundle.sh", "if true; then bash scripts/crypto/openssl/build-openssl-bundle.sh; fi", "unsupported builder"),
            (WORKFLOW, 'PREFIX="$HOME/.cache/rubin-openssl/bundle-3.5.5"', 'PREFIX="$HOME/.cache/rubin-openssl/bundle-3.5.4"\n          # PREFIX="$HOME/.cache/rubin-openssl/bundle-3.5.5"', "bundle prefix"),
            (WORKFLOW, "openssl-3.5.5.tar.gz", "openssl-3.5.5.tar.gz\n            ~/.cache/rubin-openssl/work/openssl-3.4.0.tar.gz", "cache paths"),
            (WORKFLOW, "-3.5.5-v3-", "-3.5.5-v3-stale-3.4.0-", "cache key"),
            (WORKFLOW, "${{ hashFiles('scripts/crypto/openssl/source-checksums.sha256') }}", "fixed", "checksum hashFiles"),
            (WORKFLOW, "      - name: Build OpenSSL 3.5.5 bundle", "          restore-keys: openssl-\n      - name: Build OpenSSL 3.5.5 bundle", "restore-key"),
            (WORKFLOW, "      - name: Build OpenSSL 3.5.5 bundle", "      - name: Cache OpenSSL spare\n        uses: actions/cache@v5\n        with:\n          path: /tmp/spare\n          key: openssl-bundle-spare\n      - name: Build OpenSSL 3.5.5 bundle", "ambiguous"),
            ("scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md", "completeness; also inspect `git grep -n '3\\.5\\.5'`", "completeness; also inspect `git grep -n '3\\.5\\.4'`", "final grep"),
            ("tools/tests/test_openssl_bundle_contract.py", 'self.assertIn(f"{PUBLISHED_SHA256}', '# decoy self.assertIn(f"{PUBLISHED_SHA256}', "pin binding"),
        )
        for case in cases:
            with self.subTest(case[0], message=case[3]):
                self.assert_rejected(*case)

    def test_shell_and_yaml_non_sites_are_accepted(self) -> None:
        insertions = (
            "          echo unrelated-9.9.9",
            "          echo ok # scripts/crypto/openssl/build-openssl-bundle.sh",
            '          echo "scripts/crypto/openssl/build-openssl-bundle.sh"',
            "          echo $((1 << 2))",
            "          cat <<<EOF",
            "          cat <<EOF\n          scripts/crypto/openssl/build-openssl-bundle.sh\n          EOF",
            "          echo '*artifact'\n          # *artifact",
        )
        for insertion in insertions:
            with self.subTest(insertion), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                self.mutate(root, WORKFLOW, "          set -euo pipefail", f"{insertion}\n          set -euo pipefail")
                self.assertEqual(check_repo(root), [])

    def test_yaml_and_file_boundaries_fail_closed(self) -> None:
        for old, new, message in (
            ("jobs:\n", "jobs:\n  ? [bad, key]\n  : {}\n", "unhashable YAML key"),
            ("jobs:\n", "jobs:\n  duplicate: {}\njobs:\n", "duplicate YAML key"),
        ):
            self.assert_rejected(WORKFLOW, old, new, message)
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            path = root / WORKFLOW
            path.write_text("#" * (2 * 1024 * 1024 + 1), encoding="utf-8")
            self.assertTrue(any("exceeds" in error for error in check_repo(root)))
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            path = root / WORKFLOW
            path.unlink(); path.symlink_to(root / "missing.yml")
            errors = check_repo(root)
            self.assertTrue(any("cannot scan workflow YAML" in error for error in errors), errors)
            proc = subprocess.run([sys.executable, str(REPO_ROOT / "tools/check_openssl_version_consistency.py"), "--repo-root", str(root)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("ERROR:", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            self.mutate(root, WORKFLOW, "jobs:\n", "shared: &shared {value: 1}\ncopy: *shared\njobs:\n")
            self.assertEqual(check_repo(root), [])

    def test_new_workflow_zero_builder_and_cli_error_are_owned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            source = root / WORKFLOW
            (source.parent / "new-site.yml").write_text(source.read_text(encoding="utf-8").replace("OPENSSL_VERSION=3.5.5", "OPENSSL_VERSION=$DYNAMIC"), encoding="utf-8")
            self.assertTrue(any("new-site.yml" in error for error in check_repo(root)))
            for path in source.parent.glob("*.y*ml"):
                path.write_text(path.read_text(encoding="utf-8").replace("scripts/crypto/openssl/build-openssl-bundle.sh", "removed.sh"), encoding="utf-8")
            self.assertIn("no active workflow OpenSSL builder sites found", check_repo(root))
            proc = subprocess.run([sys.executable, str(REPO_ROOT / "tools/check_openssl_version_consistency.py"), "--repo-root", str(root)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("ERROR:", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
