#!/usr/bin/env python3
from __future__ import annotations

import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_conformance_fixtures_drift as m


def _populate_committed(root: Path) -> None:
    for rel in m.EXPECTED_FIXTURES:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(rel.as_posix().encode("utf-8"))


def _populate_candidate(
    root: Path,
    *,
    skip: tuple[Path, ...] = (),
    extra: tuple[Path, ...] = (),
    mutate: tuple[Path, ...] = (),
) -> None:
    for rel in m.EXPECTED_FIXTURES:
        if rel in skip:
            continue
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        body = rel.as_posix().encode("utf-8")
        if rel in mutate:
            body = body + b"-MUTATED"
        path.write_bytes(body)
    for rel in extra:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"extra")


class DiffSetTests(unittest.TestCase):
    def test_all_match(self):
        with tempfile.TemporaryDirectory() as td:
            committed = Path(td) / "committed"
            candidate = Path(td) / "candidate"
            committed.mkdir()
            candidate.mkdir()
            _populate_committed(committed)
            _populate_candidate(candidate)
            missing_committed, differing, matching, missing_candidate, extra_candidate = (
                m.diff_set(candidate, committed)
            )
        self.assertEqual(missing_committed, [])
        self.assertEqual(differing, [])
        self.assertEqual(len(matching), len(m.EXPECTED_FIXTURES))
        self.assertEqual(missing_candidate, [])
        self.assertEqual(extra_candidate, [])

    def test_byte_differing(self):
        target = m.EXPECTED_FIXTURES[0]
        with tempfile.TemporaryDirectory() as td:
            committed = Path(td) / "committed"
            candidate = Path(td) / "candidate"
            committed.mkdir()
            candidate.mkdir()
            _populate_committed(committed)
            _populate_candidate(candidate, mutate=(target,))
            _, differing, matching, missing_candidate, extra_candidate = m.diff_set(
                candidate, committed
            )
        self.assertEqual(differing, [target])
        self.assertEqual(len(matching), len(m.EXPECTED_FIXTURES) - 1)
        self.assertEqual(missing_candidate, [])
        self.assertEqual(extra_candidate, [])

    def test_missing_candidate(self):
        target = m.EXPECTED_FIXTURES[2]
        with tempfile.TemporaryDirectory() as td:
            committed = Path(td) / "committed"
            candidate = Path(td) / "candidate"
            committed.mkdir()
            candidate.mkdir()
            _populate_committed(committed)
            _populate_candidate(candidate, skip=(target,))
            _, differing, matching, missing_candidate, extra_candidate = m.diff_set(
                candidate, committed
            )
        self.assertEqual(differing, [])
        self.assertEqual(len(matching), len(m.EXPECTED_FIXTURES) - 1)
        self.assertEqual(missing_candidate, [target])
        self.assertEqual(extra_candidate, [])

    def test_extra_candidate(self):
        extra = Path("CV-NOT-EXPECTED.json")
        with tempfile.TemporaryDirectory() as td:
            committed = Path(td) / "committed"
            candidate = Path(td) / "candidate"
            committed.mkdir()
            candidate.mkdir()
            _populate_committed(committed)
            _populate_candidate(candidate, extra=(extra,))
            missing_committed, _, matching, missing_candidate, extra_candidate = m.diff_set(
                candidate, committed
            )
        self.assertEqual(missing_committed, [extra])
        self.assertEqual(len(matching), len(m.EXPECTED_FIXTURES))
        self.assertEqual(missing_candidate, [])
        self.assertEqual(extra_candidate, [extra])


class MainExitCodeTests(unittest.TestCase):
    def test_main_clean_returns_zero(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def fake_run(_repo_root, out_dir):
                _populate_candidate(out_dir)

            captured = io.StringIO()
            with mock.patch.object(m, "run_generator", side_effect=fake_run):
                with mock.patch("sys.stdout", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 0)
        self.assertIn(
            f"OK: conformance fixture drift check passed ({len(m.EXPECTED_FIXTURES)} generator-owned files match committed)",
            captured.getvalue(),
        )

    def test_main_missing_committed_dir_returns_two(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            captured = io.StringIO()
            with mock.patch("sys.stderr", captured):
                rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 2)
        self.assertIn("ERROR: committed fixtures dir not found", captured.getvalue())

    def test_main_subprocess_filenotfound_returns_two(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def raise_fnf(*_args, **_kwargs):
                raise FileNotFoundError(2, "No such file or directory: 'go'")

            captured = io.StringIO()
            with mock.patch("subprocess.run", side_effect=raise_fnf):
                with mock.patch("sys.stderr", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 2)
        self.assertIn("ERROR:", captured.getvalue())
        self.assertNotIn("Traceback", captured.getvalue())

    def test_main_candidate_inside_committed_root_refused(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            forbidden_root = committed / "candidate"
            forbidden_root.mkdir()

            def fake_mkdtemp(prefix=""):  # noqa: ARG001 - matches stdlib signature
                _ = prefix
                return str(forbidden_root)

            captured = io.StringIO()
            with mock.patch("tempfile.mkdtemp", side_effect=fake_mkdtemp):
                with mock.patch("sys.stderr", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 2)
        self.assertIn(
            "candidate output", captured.getvalue()
        )

    def test_main_drift_detected_returns_one(self):
        target = m.EXPECTED_FIXTURES[1]
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def fake_run(_repo_root, out_dir):
                _populate_candidate(out_dir, mutate=(target,))

            captured = io.StringIO()
            with mock.patch.object(m, "run_generator", side_effect=fake_run):
                with mock.patch("sys.stderr", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 1)
        self.assertIn(f"~ {target}", captured.getvalue())

    def test_main_missing_expected_returns_one(self):
        target = m.EXPECTED_FIXTURES[3]
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def fake_run(_repo_root, out_dir):
                _populate_candidate(out_dir, skip=(target,))

            captured = io.StringIO()
            with mock.patch.object(m, "run_generator", side_effect=fake_run):
                with mock.patch("sys.stderr", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 1)
        self.assertIn(f"- {target}", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
