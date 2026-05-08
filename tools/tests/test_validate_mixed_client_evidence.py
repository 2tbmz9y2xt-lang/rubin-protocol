#!/usr/bin/env python3
"""Tests for scripts/devnet/validate_mixed_client_evidence.py.

The validator design rule is: JSON Schema owns all shape/type/const/
minLength/pattern; the Python cross-field layer runs ONLY after schema
PASS. These tests exercise the layered contract end-to-end via the
public `validate()` and `main()` entrypoints.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = REPO_ROOT / "scripts" / "devnet"
SCHEMA_PATH = SCRIPT_DIR / "schema" / "mixed_client_evidence_v1.json"
TESTDATA_DIR = SCRIPT_DIR / "testdata"

sys.path.insert(0, str(SCRIPT_DIR))
import validate_mixed_client_evidence as validator  # noqa: E402


def _load_committed_valid() -> dict:
    with open(TESTDATA_DIR / "valid_minimal_mixed.json", encoding="utf-8") as f:
        return json.load(f)


def _validate_dict(td: Path, data) -> list[str]:
    fixture = td / "case.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")
    return validator.validate(fixture, SCHEMA_PATH)


def _assert_one(testcase: unittest.TestCase, errors: list[str], *needles: str) -> None:
    testcase.assertTrue(errors, "expected validation errors but got none")
    testcase.assertTrue(
        any(all(n in e for n in needles) for e in errors),
        f"no error matched all needles {needles!r}; got {errors}",
    )


class CommittedFixtureTests(unittest.TestCase):
    def test_committed_valid_minimal_mixed_passes(self):
        errors = validator.validate(
            TESTDATA_DIR / "valid_minimal_mixed.json", SCHEMA_PATH
        )
        self.assertEqual(errors, [], f"committed valid fixture must pass; got {errors}")


class CrossImplTxPathTests(unittest.TestCase):
    """T13 invariant — the core RUB-206 contract."""

    def test_same_impl_tx_path_in_mixed_set_rejected(self):
        """{go, go, rust} with go-1 → [go-2] is NOT mixed-client proof."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "go_to_go_only_in_mixed_set"
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b", "implementation": "go"},
                {"name": "node-c", "implementation": "rust"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-b"]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path", "submitter", "observer")

    def test_rust_to_go_passes(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "rust_to_go_propagation"
            data["participants"] = [
                {"name": "node-a", "implementation": "rust"},
                {"name": "node-b", "implementation": "go"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-b"]
            self.assertEqual(_validate_dict(Path(td), data), [])

    def test_unknown_observer_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["tx_path"]["observed_at"] = ["node-ghost"]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path.observed_at", "node-ghost")

    def test_pass_without_tx_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            del data["tx_path"]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path", "required")

    def test_duplicate_participant_names_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"][1]["name"] = "node-a"
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "duplicate")


class FailClosedCliTests(unittest.TestCase):
    """The CLI must never raise to the user; every input failure mode
    yields a deterministic single-line `<prefix>: ...` message and an
    exit code of 1."""

    def test_invalid_schema_path_returns_deterministic_error(self):
        with tempfile.TemporaryDirectory() as td:
            errors = validator.validate(
                TESTDATA_DIR / "valid_minimal_mixed.json", Path(td) / "no_such.json"
            )
            self.assertTrue(
                any(e.startswith("schema:") and "cannot read" in e for e in errors),
                f"expected `schema: cannot read ...`; got {errors}",
            )
            self.assertFalse(
                any("Traceback" in e for e in errors),
                f"validator leaked a traceback; got {errors}",
            )

    def test_malformed_schema_json_returns_deterministic_error(self):
        with tempfile.TemporaryDirectory() as td:
            bad_schema = Path(td) / "bad.json"
            bad_schema.write_text("{not valid", encoding="utf-8")
            errors = validator.validate(
                TESTDATA_DIR / "valid_minimal_mixed.json", bad_schema
            )
            _assert_one(self, errors, "schema:", "malformed JSON")

    def test_invalid_schema_object_returns_deterministic_error(self):
        """A parseable but Draft 2020-12-invalid schema (e.g. `type: 99`)
        must be caught by `Draft202012Validator.check_schema` and yield
        a `schema: invalid schema: ...` line, never a traceback."""
        with tempfile.TemporaryDirectory() as td:
            bad_schema = Path(td) / "bad.json"
            bad_schema.write_text(json.dumps({"type": 99}), encoding="utf-8")
            errors = validator.validate(
                TESTDATA_DIR / "valid_minimal_mixed.json", bad_schema
            )
            self.assertTrue(
                any(e.startswith("schema:") and "invalid schema" in e for e in errors),
                f"expected `schema: invalid schema: ...`; got {errors}",
            )
            self.assertFalse(
                any("Traceback" in e for e in errors),
                f"validator leaked a traceback; got {errors}",
            )

    def test_missing_fixture_returns_deterministic_error(self):
        with tempfile.TemporaryDirectory() as td:
            errors = validator.validate(Path(td) / "no_such.json", SCHEMA_PATH)
            _assert_one(self, errors, "fixture:", "cannot read")

    def test_malformed_fixture_json_returns_deterministic_error(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text("{not valid", encoding="utf-8")
            _assert_one(
                self, validator.validate(bad, SCHEMA_PATH), "fixture:", "malformed JSON"
            )

    def _permissive_schema(self, td: Path) -> Path:
        """Helper: write a permissive schema (only $schema declared) to td."""
        p = td / "permissive.json"
        p.write_text(
            json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema"}),
            encoding="utf-8",
        )
        return p

    def test_permissive_alternate_schema_non_object_root_rejected(self):
        """Non-object root under alternate permissive schema: committed
        schema is enforced as floor regardless of user's --schema, so
        the validator returns a deterministic schema-owned type error."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            permissive = self._permissive_schema(tdp)
            for fixture_text in ("[]", "42", "null", '"hello"'):
                fix = tdp / "f.json"
                fix.write_text(fixture_text, encoding="utf-8")
                errors = validator.validate(fix, permissive)
                self.assertTrue(
                    errors,
                    f"validator silently PASSed non-object fixture {fixture_text!r}",
                )
                self.assertTrue(
                    any("is not of type" in e and "object" in e for e in errors),
                    f"validator did not surface schema-owned type error for "
                    f"{fixture_text!r}; got {errors}",
                )
                self.assertFalse(
                    any("Traceback" in e for e in errors),
                    f"validator leaked traceback for {fixture_text!r}; got {errors}",
                )

    def test_permissive_alternate_schema_empty_object_rejected(self):
        """`{}` under permissive alternate schema: committed-schema floor
        catches missing required top-level fields."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            permissive = self._permissive_schema(tdp)
            fix = tdp / "f.json"
            fix.write_text("{}", encoding="utf-8")
            errors = validator.validate(fix, permissive)
            _assert_one(self, errors, "required")

    def test_permissive_alternate_schema_empty_participants_rejected(self):
        """`{participants: []}` under permissive alternate schema:
        committed-schema floor catches `minItems: 1`."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            permissive = self._permissive_schema(tdp)
            fix = tdp / "f.json"
            fix.write_text(json.dumps({"participants": []}), encoding="utf-8")
            errors = validator.validate(fix, permissive)
            self.assertTrue(errors)
            self.assertFalse(any("Traceback" in e for e in errors))

    def test_permissive_alternate_schema_participant_missing_implementation_rejected(self):
        """Participant missing `implementation` under permissive alt
        schema: committed-schema floor catches missing required."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            permissive = self._permissive_schema(tdp)
            fix = tdp / "f.json"
            fix.write_text(
                json.dumps({"participants": [{"name": "node-a"}]}),
                encoding="utf-8",
            )
            errors = validator.validate(fix, permissive)
            self.assertTrue(any("implementation" in e for e in errors))
            self.assertFalse(any("Traceback" in e for e in errors))

    def test_permissive_alternate_schema_empty_tx_path_rejected(self):
        """`tx_path: {}` under permissive alt schema: committed-schema
        floor catches missing required tx_path keys."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            permissive = self._permissive_schema(tdp)
            data = _load_committed_valid()
            data["tx_path"] = {}
            fix = tdp / "f.json"
            fix.write_text(json.dumps(data), encoding="utf-8")
            errors = validator.validate(fix, permissive)
            self.assertTrue(any("tx_path" in e for e in errors))
            self.assertFalse(any("Traceback" in e for e in errors))

    def test_permissive_alternate_schema_wrong_type_observed_at_rejected(self):
        """`tx_path.observed_at` non-list under permissive alt schema:
        committed-schema floor catches wrong type."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            permissive = self._permissive_schema(tdp)
            data = _load_committed_valid()
            data["tx_path"]["observed_at"] = "node-b"  # wrong type — should be array
            fix = tdp / "f.json"
            fix.write_text(json.dumps(data), encoding="utf-8")
            errors = validator.validate(fix, permissive)
            self.assertTrue(any("observed_at" in e for e in errors))
            self.assertFalse(any("Traceback" in e for e in errors))

    def test_alternate_schema_with_mixed_path_types_does_not_typeerror(self):
        """Sort key for `_schema_layer` errors must be total-orderable
        across mixed-type `absolute_path` (int + str). Constructed by
        passing a fixture with errors at both `participants[0]` (int
        index path) and `evidence_type` (str key path) under the
        committed schema."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            data = _load_committed_valid()
            data["evidence_type"] = "bogus"  # str-path enum violation
            data["participants"][0]["name"] = "BAD-CAPS"  # int-then-str pattern violation
            fix = tdp / "f.json"
            fix.write_text(json.dumps(data), encoding="utf-8")
            try:
                errors = validator.validate(fix, SCHEMA_PATH)
            except TypeError as e:
                self.fail(f"sorted() raised TypeError on mixed path types: {e}")
            self.assertTrue(errors)
            # Should contain both errors
            self.assertTrue(any("evidence_type" in e for e in errors))
            self.assertTrue(any("name" in e for e in errors))


class SchemaOwnedTests(unittest.TestCase):
    """For each shape/type/const/minLength/pattern problem the schema
    layer is the sole authority; the cross-field layer must not run on
    these inputs (the validator returns schema-owned errors only and
    cross-field is short-circuited)."""

    def test_top_level_array_schema_owned_only(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "arr.json"
            f.write_text("[]", encoding="utf-8")
            errors = validator.validate(f, SCHEMA_PATH)
            _assert_one(self, errors, "is not of type", "object")
            # No cross-field message about top-level shape.
            self.assertFalse(
                any("top-level" in e for e in errors),
                f"cross-field root message duplicates schema; got {errors}",
            )

    def test_empty_failure_reason_schema_owned_only(self):
        """`failure_reason: ""` violates schema's `minLength: 1`. The
        cross-field «verdict=FAIL ⇒ failure_reason required» rule must
        not fire on top of the schema's authoritative rejection."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["verdict"] = "FAIL"
            data["failure_reason"] = ""
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "failure_reason", "too short")
            self.assertFalse(
                any(
                    "required when verdict=FAIL" in e
                    for e in errors
                ),
                f"cross-field FAIL rule duplicates schema minLength; got {errors}",
            )

    def test_wrong_type_schema_version_schema_owned_only(self):
        """`schema_version: 42` violates schema's `const`. The error
        list must contain a schema-owned `schema_version` rejection
        (positive assertion) and no cross-field 'must be exactly'
        wording (negative assertion)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["schema_version"] = 42  # type: ignore[assignment]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "schema_version")
            self.assertFalse(
                any("must be exactly" in e for e in errors),
                f"cross-field 'must be exactly' duplicates schema; got {errors}",
            )

    def test_wrong_type_participants_schema_owned_only(self):
        """`participants: {"node-a": "go"}` violates schema's
        `type: array`. The error list must contain a schema-owned
        `participants` type rejection (positive assertion) and no
        cross-field semantics on top of it."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"] = {"node-a": "go"}  # type: ignore[assignment]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "participants", "is not of type")
            self.assertFalse(
                any("duplicate" in e for e in errors),
                f"cross-field S7 fired on schema-invalid participants; got {errors}",
            )
            self.assertFalse(
                any("requires at least one implementation" in e for e in errors),
                f"cross-field S5 fired on schema-invalid participants; got {errors}",
            )


class DeterminismTests(unittest.TestCase):
    def test_deterministic_on_identical_input(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"][1]["implementation"] = "go"
            runs = [_validate_dict(Path(td), copy.deepcopy(data)) for _ in range(3)]
            self.assertEqual(runs[0], runs[1])
            self.assertEqual(runs[1], runs[2])


class CliTests(unittest.TestCase):
    def test_main_zero_on_valid_fixture(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = validator.main([str(TESTDATA_DIR / "valid_minimal_mixed.json")])
        self.assertEqual(rc, 0)
        self.assertIn("PASS", buf.getvalue())

    def test_main_nonzero_on_invalid_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b", "implementation": "go"},
                {"name": "node-c", "implementation": "rust"},
            ]
            data["tx_path"]["observed_at"] = ["node-b"]
            f = Path(td) / "go_to_go.json"
            f.write_text(json.dumps(data), encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = validator.main([str(f)])
            self.assertEqual(rc, 1)
            self.assertIn("FAIL", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
