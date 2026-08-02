import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/gen_cv_da_integrity.py"
FIXTURE = ROOT / "conformance/fixtures/CV-DA-INTEGRITY.json"
SPEC = importlib.util.spec_from_file_location("gen_cv_da_integrity", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)


class GenCvDaIntegrityTest(unittest.TestCase):
    def snapshot(self, root: Path) -> list[tuple[Path, bool, bytes]]:
        return [
            (path.relative_to(root), path.is_dir(), path.read_bytes() if path.is_file() else b"")
            for path in sorted(root.rglob("*"))
        ]

    def run_script(self, *args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    def run_main_check(self, path: Path) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(GEN, "FIXTURE_PATH", path),
            mock.patch.object(sys, "argv", [str(SCRIPT), "--check"]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit) as stopped,
        ):
            GEN.main()
        return stopped.exception.code, stdout.getvalue(), stderr.getvalue()

    def check_bytes(self, committed: bytes, *, read_only: bool = False) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "fixture.json"
            path.write_bytes(committed)
            if read_only:
                path.chmod(0o444)
            before = self.snapshot(root)
            result = self.run_main_check(path)
            self.assertEqual(self.snapshot(root), before)
            return result

    def test_generated_bytes_exactly_match_fixture_and_are_deterministic(self) -> None:
        expected = FIXTURE.read_bytes()
        self.assertEqual(GEN.generate(), expected)
        self.assertEqual(GEN.generate(), GEN.generate())
        code, stdout, stderr = self.check_bytes(expected, read_only=True)
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("check passed", stdout)
        with tempfile.TemporaryDirectory() as directory:
            results = [self.run_script("--check", cwd=Path(directory)) for _ in range(2)]
        self.assertEqual([(r.returncode, r.stdout, r.stderr) for r in results], [(0, results[0].stdout, b"")] * 2)

    def test_check_detects_byte_alias_and_row_order_drift(self) -> None:
        expected = FIXTURE.read_bytes()
        missing_alias = json.loads(expected)
        missing_alias["vectors"].pop()
        row_order = json.loads(expected)
        row_order["vectors"][0], row_order["vectors"][1] = row_order["vectors"][1], row_order["vectors"][0]
        extra_row = json.loads(expected)
        extra_row["vectors"].append(dict(extra_row["vectors"][0], id="CV-DA-EXTRA"))
        changed_id = json.loads(expected)
        changed_id["vectors"][0]["id"] = "CV-DA-XX"
        variants = [
            ("one-byte", expected[:-1]),
            ("missing-alias", (json.dumps(missing_alias, indent=2) + "\n").encode()),
            ("row-order", (json.dumps(row_order, indent=2) + "\n").encode()),
            ("extra-row", (json.dumps(extra_row, indent=2) + "\n").encode()),
            ("changed-id", (json.dumps(changed_id, indent=2) + "\n").encode()),
        ]
        for case, drifted in variants:
            with self.subTest(case=case):
                code, stdout, stderr = self.check_bytes(drifted)
                self.assertEqual((code, stderr), (1, ""))
                self.assertIn("check failed", stdout)
                self.assertNotIn("Traceback", stdout)

    def test_check_never_mutates_matching_or_drifted_fixture(self) -> None:
        for contents in (FIXTURE.read_bytes(), b"drift"):
            with self.subTest(contents=contents[:5]):
                code, _, _ = self.check_bytes(contents, read_only=True)
                self.assertEqual(code, 0 if contents == FIXTURE.read_bytes() else 1)

    def test_missing_fixture_is_concise_and_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "missing.json"
            before = self.snapshot(root)
            code, stdout, stderr = self.run_main_check(path)
            self.assertEqual((code, stderr), (1, ""))
            self.assertFalse(path.exists())
            self.assertEqual(self.snapshot(root), before)
            self.assertNotIn("Traceback", stdout)
            self.assertIn("check failed", stdout)

            code, stdout, stderr = self.run_main_check(root)
            self.assertEqual((code, stderr), (1, ""))
            self.assertEqual(self.snapshot(root), before)
            self.assertIn("check failed", stdout)
            self.assertNotIn("Traceback", stdout)

    def test_out_and_stdout_are_preserved_and_flags_are_exclusive(self) -> None:
        expected = FIXTURE.read_bytes()
        result = self.run_script()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = self.snapshot(root)
            result = self.run_script("--out", "", cwd=root)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))
            self.assertEqual(self.snapshot(root), before)
            output = root / "generated.json"
            result = self.run_script("--out", str(output))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
            self.assertEqual(output.read_bytes(), expected)
            forbidden = Path(directory) / "forbidden.json"
            result = self.run_script("--check", "--out", str(forbidden))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(forbidden.exists())


if __name__ == "__main__":
    unittest.main()
