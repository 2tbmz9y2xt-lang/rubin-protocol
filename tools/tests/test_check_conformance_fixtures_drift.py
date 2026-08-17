#!/usr/bin/env python3
from __future__ import annotations

import io
import json
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


class CanonicalPipelineSchemaTests(unittest.TestCase):
    """RUB-922 / C01: the committed corpus validates and rejects duplicate ids."""

    REPO_ROOT = TOOLS_DIR.parent
    ARTIFACT = REPO_ROOT / "conformance/fixtures/protocol/canonical_pipeline_v1.json"
    SCHEMA = REPO_ROOT / "conformance/schemas/cv-canonical-pipeline-v1.json"

    def _load(self):
        import jsonschema  # fail closed: the schema gate requires the library

        schema = json.loads(self.SCHEMA.read_text(encoding="utf-8", errors="strict"))
        data = json.loads(self.ARTIFACT.read_text(encoding="utf-8", errors="strict"))
        jsonschema.Draft202012Validator.check_schema(schema)
        return jsonschema.Draft202012Validator(schema), data

    def test_every_row_validates_against_the_versioned_schema(self):
        validator, data = self._load()
        errors = [
            f"{'.'.join(str(p) for p in e.absolute_path)}: {e.message}"
            for e in sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        ]
        self.assertEqual(errors, [])
        self.assertTrue(data["rows"])

    def test_duplicate_row_id_is_rejected(self):
        _, data = self._load()
        ids = [row["id"] for row in data["rows"]]
        self.assertEqual(len(ids), len(set(ids)), "committed corpus has duplicate row ids")
        mutated = list(data["rows"]) + [dict(data["rows"][0])]
        mutated_ids = [row["id"] for row in mutated]
        self.assertNotEqual(
            len(mutated_ids),
            len(set(mutated_ids)),
            "duplicate-id detection must reject a repeated row id",
        )

    def test_coverage_receipt_maps_every_class_to_at_least_one_row(self):
        _, data = self._load()
        known = {row["id"] for row in data["rows"]}
        self.assertGreaterEqual(len(data["coverage_receipt"]), 59)
        for klass, rows in data["coverage_receipt"].items():
            row_ids = [part.strip() for part in rows.split(",")]
            self.assertTrue(row_ids, f"class {klass} maps to zero rows")
            for row_id in row_ids:
                self.assertIn(row_id, known, f"class {klass} names unknown row {row_id}")


if __name__ == "__main__":
    unittest.main()
