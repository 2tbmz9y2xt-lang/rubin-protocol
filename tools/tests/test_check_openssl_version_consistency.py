from __future__ import annotations
import copy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import yaml
from tools.check_openssl_version_consistency import (
    BUILDER,
    WORKFLOW_OWNERS,
    WorkflowOwner,
    check_repo,
)
REPO_ROOT = Path(__file__).resolve().parents[2]
SIMPLE_WORKFLOW = ".github/workflows/combined-load-nightly.yml"
class OpenSSLVersionConsistencyTests(unittest.TestCase):
    def fixture(self, tmp: str) -> Path:
        root = Path(tmp)
        for relative in (
            ".github/workflows",
            "scripts/crypto/openssl",
            "scripts/dev-env.sh",
            "tools/tests/test_openssl_bundle_contract.py",
        ):
            source, target = REPO_ROOT / relative, root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, target) if source.is_dir() else shutil.copy2(source, target)
        return root
    def mutate(self, root: Path, relative: str, old: str, new: str) -> None:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
    def assert_error(self, root: Path, message: str) -> None:
        errors = check_repo(root)
        self.assertTrue(any(message in error for error in errors), errors)
    def workflow(self, root: Path, owner: WorkflowOwner) -> dict:
        return yaml.safe_load((root / owner.path).read_text(encoding="utf-8"))
    def save_workflow(self, root: Path, owner: WorkflowOwner, workflow: dict) -> None:
        (root / owner.path).write_text(yaml.safe_dump(workflow, sort_keys=False), encoding="utf-8")
    def builder_index(self, workflow: dict, owner: WorkflowOwner) -> int:
        steps = workflow["jobs"][owner.job]["steps"]
        return next(index for index, step in enumerate(steps) if BUILDER in str(step.get("run", "")))
    def test_live_history_repin_complete_propagation_and_nonowners_pass(self) -> None:
        self.assertEqual(check_repo(REPO_ROOT), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            pin = root / "scripts/crypto/openssl/source-checksums.sha256"
            pin.write_text(pin.read_text(encoding="utf-8") + f"{'a' * 64}  openssl-3.4.0.tar.gz\n", encoding="utf-8")
            self.assertEqual(check_repo(root), [])
            pin.write_text(pin.read_text(encoding="utf-8").replace("b28c9153", "c28c9153", 1), encoding="utf-8")
            self.assertEqual(check_repo(root), [])
            readme = root / "scripts/crypto/openssl/README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\nUnrelated Python 3.12.1. `test -x scripts/crypto/openssl/build-openssl-bundle.sh`.\n",
                encoding="utf-8",
            )
            self.assertEqual(check_repo(root), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            for path in root.rglob("*"):
                if path.is_file():
                    text = path.read_text(encoding="utf-8")
                    text = text.replace("3.5.5", "3.6.0").replace(r"3\.5\.5", r"3\.6\.0")
                    if ".github/workflows" in path.as_posix():
                        text = text.replace("OpenSSL 3.5", "OpenSSL 3.6")
                    path.write_text(text, encoding="utf-8")
            self.assertEqual(check_repo(root), [])  # propagation only; digest authenticity is separate
    def test_builder_and_checksum_authorities_fail_closed(self) -> None:
        pin = "b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89  openssl-3.5.5.tar.gz"
        cases = (
            ("scripts/crypto/openssl/build-openssl-bundle.sh", 'OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"', 'OPENSSL_VERSION="${OPENSSL_VERSION:-$NEXT}"', "unsupported or dynamic"),
            ("scripts/crypto/openssl/build-openssl-bundle.sh", "lookup_pinned_sha256() {", "lookup_pinned_sha256() {\n  export OPENSSL_VERSION=3.5.5", "expected one active assignment"),
            ("scripts/crypto/openssl/build-openssl-bundle.sh", "OPENSSL_TAG=", "declare -g -r OPENSSL_VERSION=3.5.4\nOPENSSL_TAG=", "expected one active assignment"),
            ("scripts/crypto/openssl/source-checksums.sha256", pin, f"{pin}\n{pin}", "selected checksum"),
            ("scripts/crypto/openssl/source-checksums.sha256", "b28c9153", "NOTHEX00", "malformed"),
        )
        for relative, old, new, message in cases:
            with self.subTest(message), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                self.mutate(root, relative, old, new)
                self.assert_error(root, message)
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            self.mutate(root, "scripts/crypto/openssl/build-openssl-bundle.sh", 'OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"', "# authority moved")
            self.mutate(root, "scripts/crypto/openssl/build-openssl-bundle.sh", "lookup_pinned_sha256() {", 'lookup_pinned_sha256() {\n  OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"')
            self.assert_error(root, "preamble")
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            self.mutate(root, "scripts/crypto/openssl/build-openssl-bundle.sh", 'OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"', 'prior_helper()\n{\n  :\n}\nOPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"')
            self.assert_error(root, "preamble")
    def test_every_workflow_registry_entry_is_required_and_version_bound(self) -> None:
        for owner in WORKFLOW_OWNERS:
            with self.subTest(owner=owner, case="missing"), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                workflow = self.workflow(root, owner)
                del workflow["jobs"][owner.job]
                self.save_workflow(root, owner, workflow)
                self.assert_error(root, f"{owner.path}:{owner.job}")
            with self.subTest(owner=owner, case="stale"), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                workflow = self.workflow(root, owner)
                index = self.builder_index(workflow, owner)
                step = workflow["jobs"][owner.job]["steps"][index]
                step["run"] = step["run"].replace("OPENSSL_VERSION=3.5.5", "OPENSSL_VERSION=3.5.4")
                self.save_workflow(root, owner, workflow)
                self.assert_error(root, "canonical builder line")
            with self.subTest(owner=owner, case="duplicate"), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                workflow = self.workflow(root, owner)
                index = self.builder_index(workflow, owner)
                workflow["jobs"][owner.job]["steps"].insert(index + 1, copy.deepcopy(workflow["jobs"][owner.job]["steps"][index]))
                self.save_workflow(root, owner, workflow)
                self.assert_error(root, "expected one registered builder step")
    def test_non_workflow_registry_entries_are_version_bound(self) -> None:
        cases = (
            ("scripts/crypto/openssl/README.md", "OPENSSL_VERSION=3.5.5", "OPENSSL_VERSION=3.5.4", "README command"),
            ("scripts/dev-env.sh", "bundle-3.5.5", "bundle-3.5.4", "dev-env example"),
            ("scripts/crypto/openssl/bench-pq-speed.py", '"bundle-3.5.5"', '"bundle-3.5.4"', "speed benchmark"),
            ("scripts/crypto/openssl/bench-pq-pkeyutl.py", '"bundle-3.5.5"', '"bundle-3.5.4"', "pkeyutl benchmark"),
            ("tools/tests/test_openssl_bundle_contract.py", 'VERSION = "3.5.5"', 'VERSION = "3.5.4"', "bundle contract"),
            ("tools/tests/test_openssl_bundle_contract.py", 'self.assertIn(f"{PUBLISHED_SHA256}', 'self.assertEqual(f"{PUBLISHED_SHA256}', "pin binding"),
            ("scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md", "OPENSSL_VERSION=3\\.5\\.5", "OPENSSL_VERSION=3\\.5\\.4", "runbook selector"),
            ("scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md", "bundle-3\\.5\\.5", "bundle-3\\.5\\.4", "runbook cache"),
            ("scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md", "also inspect\n     `git grep -n '3\\.5\\.5'`", "also inspect\n     `git grep -n '3\\.5\\.4'`", "runbook final"),
            ("scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md", "PyYAML==6.0.3", "PyYAML==6.0.2", "PyYAML prerequisite"),
            ("scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md", "--repo-root .` checks", "--repo-root . --extra` checks", "checker command"),
        )
        for relative, old, new, message in cases:
            with self.subTest(message), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                self.mutate(root, relative, old, new)
                self.assert_error(root, message)
    def test_workflow_tuple_structure_is_exact(self) -> None:
        owner = next(item for item in WORKFLOW_OWNERS if item.path == SIMPLE_WORKFLOW)
        def rejected(change, message: str) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                workflow = self.workflow(root, owner)
                index = self.builder_index(workflow, owner)
                change(workflow["jobs"][owner.job]["steps"], index)
                self.save_workflow(root, owner, workflow)
                self.assert_error(root, message)
        rejected(lambda steps, i: steps.insert(i, {"name": "separator", "run": "true"}), "cache with")
        rejected(lambda steps, i: steps[i].__setitem__("if", "always()"), "matching if")
        rejected(lambda steps, i: steps[i - 1].__setitem__("uses", "actions/cache@v4"), "cache action pin")
        rejected(lambda steps, i: steps[i - 1]["with"].__setitem__("path", "/tmp/wrong"), "cache paths")
        rejected(lambda steps, i: steps[i - 1]["with"].__setitem__("key", steps[i - 1]["with"]["key"].replace("-v3-", "-v2-")), "cache key")
        rejected(lambda steps, i: steps[i - 1]["with"].__setitem__("restore-keys", "openssl-"), "restore-key")
        rejected(lambda steps, i: steps.insert(i - 1, copy.deepcopy(steps[i - 1])), "single cache")
        rejected(lambda steps, i: steps.insert(i - 1, {"with": {"key": "openssl-bundle-spare"}}), "single cache")
        rejected(lambda steps, i: steps[i].__setitem__("run", steps[i]["run"] + "\nexport OPENSSL_VERSION=3.5.4"), "single literal selector")
        rejected(lambda steps, i: steps.append({"uses": "example/action@pin", "with": {"run": f"bash {BUILDER}"}}), "unregistered literal builder owner")
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            workflow = self.workflow(root, owner)
            workflow["jobs"][owner.job]["env"] = {"PYTHON_VERSION": "3.12.1"}
            self.save_workflow(root, owner, workflow)
            self.assertEqual(check_repo(root), [])
    def test_registry_closure_rejects_new_supported_owners(self) -> None:
        for suffix in ("yml", "yaml"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                (root / f".github/workflows/new-owner.{suffix}").write_text(
                    "jobs:\n  new:\n    steps:\n      - run: |\n          OPENSSL_VERSION=3.5.5 PREFIX=\"$PREFIX\" bash " + BUILDER + "\n",
                    encoding="utf-8",
                )
                self.assert_error(root, "unregistered literal builder owner")
        additions = (
            ("scripts/crypto/openssl/NEW.md", f"OPENSSL_VERSION=3.5.5 bash {BUILDER}\n", "markdown builder"),
            ("scripts/crypto/openssl/bench-pq-extra.py", "value = Path.home() / '.cache' / 'rubin-openssl' / 'bundle-3.5.5' / 'bin' / 'openssl'\n", "benchmark default"),
            ("tools/tests/test_openssl_bundle_extra.py", 'VERSION = "3.5.5"\n', "bundle-test VERSION"),
        )
        for relative, text, message in additions:
            with self.subTest(relative), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
                self.assert_error(root, message)
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            dev = root / "scripts/dev-env.sh"
            line = '  #   RUBIN_OPENSSL_PREFIX="$HOME/.cache/rubin-openssl/bundle-3.5.5" scripts/dev-env.sh -- openssl version -a\n'
            dev.write_text(dev.read_text(encoding="utf-8") + line, encoding="utf-8")
            self.assert_error(root, "dev-env example")
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            dev = root / "scripts/dev-env.sh"
            dev.write_text(dev.read_text(encoding="utf-8") + '# RUBIN_OPENSSL_PREFIX="$HOME/.cache/rubin-openssl/bundle-3.5.4" scripts/dev-env.sh -- cargo test\n', encoding="utf-8")
            self.assert_error(root, "dev-env registry closure")
    def test_yaml_and_cli_fail_closed_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            self.mutate(root, SIMPLE_WORKFLOW, "jobs:\n", "jobs:\n  duplicate: {}\njobs:\n")
            self.assert_error(root, "duplicate YAML key")
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            (root / SIMPLE_WORKFLOW).write_text("jobs: [not, a, mapping]\n", encoding="utf-8")
            self.assert_error(root, "jobs mapping")
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            owner = root / SIMPLE_WORKFLOW
            owner.unlink()
            owner.symlink_to(REPO_ROOT / SIMPLE_WORKFLOW)
            self.assert_error(root, "regular in-repository path")
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            proc = subprocess.run(
                [sys.executable, "-S", str(REPO_ROOT / "tools/check_openssl_version_consistency.py"), "--repo-root", str(root)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("PyYAML is required", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            self.mutate(root, "scripts/crypto/openssl/README.md", "OPENSSL_VERSION=3.5.5", "OPENSSL_VERSION=3.5.4")
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "tools/check_openssl_version_consistency.py"), "--repo-root", str(root)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("ERROR:", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            lines = proc.stderr.splitlines()
            self.assertEqual(lines, sorted(set(lines)))
if __name__ == "__main__":
    unittest.main()
