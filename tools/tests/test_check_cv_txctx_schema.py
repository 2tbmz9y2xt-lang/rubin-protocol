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

import check_cv_txctx_schema as m  # noqa: E402


class CvTxctxSchemaMainTests(unittest.TestCase):
    def test_missing_default_fixture_is_retired_skip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            retired = Path(td) / "CV-TXCTX.json"
            captured = io.StringIO()
            with mock.patch.object(m, "DEFAULT_FIXTURES", retired):
                with mock.patch("sys.stdout", captured):
                    rc = m.main([])
        self.assertEqual(rc, 0)
        self.assertIn("SKIP: default CV-TXCTX fixture retired", captured.getvalue())

    def test_missing_explicit_fixture_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "missing.json"
            captured = io.StringIO()
            with mock.patch("sys.stderr", captured):
                rc = m.main(["--fixtures", str(missing)])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL: fixture file not found", captured.getvalue())

    def test_missing_explicit_fixture_equals_form_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "missing.json"
            captured = io.StringIO()
            with mock.patch("sys.stderr", captured):
                rc = m.main([f"--fixtures={missing}"])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL: fixture file not found", captured.getvalue())

    def test_invalid_schema_returns_deterministic_error(self) -> None:
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest("jsonschema is not installed")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "fixture.json"
            schema = root / "schema.json"
            fixture.write_text(json.dumps({}), encoding="utf-8")
            schema.write_text(json.dumps({"type": 1}), encoding="utf-8")

            errors = m.validate(fixture, schema)

        self.assertTrue(errors)
        self.assertTrue(errors[0].startswith("schema: "))

    def test_jsonschema_path_owns_top_level_type_error(self) -> None:
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest("jsonschema is not installed")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "fixture.json"
            schema = root / "schema.json"
            fixture.write_text(json.dumps([]), encoding="utf-8")
            schema.write_text(json.dumps({"type": "object"}), encoding="utf-8")

            errors = m.validate(fixture, schema)

        self.assertTrue(errors)
        self.assertNotIn(m.ROOT_OBJECT_ERROR, errors)

    def test_permissive_schema_does_not_accept_non_object_root(self) -> None:
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest("jsonschema is not installed")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "fixture.json"
            schema = root / "schema.json"
            fixture.write_text(json.dumps([]), encoding="utf-8")
            schema.write_text(json.dumps({}), encoding="utf-8")

            errors = m.validate(fixture, schema)

        self.assertEqual(errors, [m.ROOT_OBJECT_ERROR])


if __name__ == "__main__":
    unittest.main()
