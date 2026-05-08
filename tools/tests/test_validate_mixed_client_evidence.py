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

    # F1 owner tests — UnicodeDecodeError on each of three file-read sites
    # in `validate()` (user schema, fixture, committed schema). Without
    # explicit `UnicodeDecodeError` catches, non-UTF-8 bytes (e.g. 0xff)
    # in any of these files would escape `validate()` as a Python
    # traceback, breaking the fail-closed CLI contract.

    def test_non_utf8_schema_returns_deterministic_error(self):
        """Non-UTF-8 bytes in --schema path must yield a deterministic
        `schema: non-UTF-8 bytes ...` error and exit 1; no traceback.
        """
        with tempfile.TemporaryDirectory() as td:
            bad_schema = Path(td) / "bad_schema.json"
            bad_schema.write_bytes(b"\xff\xfe{\"$schema\": \"x\"}")
            errors = validator.validate(
                TESTDATA_DIR / "valid_minimal_mixed.json", bad_schema
            )
            _assert_one(self, errors, "schema:", "non-UTF-8 bytes")
            self.assertFalse(
                any("Traceback" in e for e in errors),
                f"validator leaked traceback on non-UTF-8 schema; got {errors}",
            )

    def test_non_utf8_fixture_returns_deterministic_error(self):
        """Non-UTF-8 bytes in fixture path must yield a deterministic
        `fixture: non-UTF-8 bytes ...` error and exit 1; no traceback.
        """
        with tempfile.TemporaryDirectory() as td:
            bad_fixture = Path(td) / "bad_fixture.json"
            bad_fixture.write_bytes(b"\xff\xfe{\"k\": \"v\"}")
            errors = validator.validate(bad_fixture, SCHEMA_PATH)
            _assert_one(self, errors, "fixture:", "non-UTF-8 bytes")
            self.assertFalse(
                any("Traceback" in e for e in errors),
                f"validator leaked traceback on non-UTF-8 fixture; got {errors}",
            )

    def test_non_utf8_committed_schema_returns_deterministic_error(self):
        """Non-UTF-8 bytes in the committed (DEFAULT_SCHEMA) file must
        yield a deterministic `schema: non-UTF-8 bytes in committed
        schema ...` error and exit 1; no traceback. Exercised by
        monkeypatching `validator.DEFAULT_SCHEMA` to a corrupted
        committed-schema fixture so the floor read fails.
        """
        with tempfile.TemporaryDirectory() as td:
            bad_committed = Path(td) / "committed_corrupt.json"
            bad_committed.write_bytes(b"\xff\xfe{}")
            original = validator.DEFAULT_SCHEMA
            try:
                validator.DEFAULT_SCHEMA = bad_committed
                errors = validator.validate(
                    TESTDATA_DIR / "valid_minimal_mixed.json", SCHEMA_PATH
                )
            finally:
                validator.DEFAULT_SCHEMA = original
            _assert_one(
                self,
                errors,
                "schema:",
                "non-UTF-8 bytes",
                "committed schema",
            )
            self.assertFalse(
                any("Traceback" in e for e in errors),
                f"validator leaked traceback on non-UTF-8 committed schema; "
                f"got {errors}",
            )

    def test_main_cli_fail_closed_on_non_utf8_fixture(self):
        """End-to-end CLI: non-UTF-8 fixture → exit 1, deterministic
        prefix to stderr, no Python traceback at all.
        """
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_bytes(b"\xff\xfe garbage")
            err_buf = io.StringIO()
            out_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf), contextlib.redirect_stdout(out_buf):
                rc = validator.main([str(bad)])
            self.assertEqual(rc, 1, f"main rc={rc}; stderr={err_buf.getvalue()!r}")
            stderr = err_buf.getvalue()
            self.assertIn("fixture:", stderr)
            self.assertIn("non-UTF-8 bytes", stderr)
            self.assertNotIn("Traceback", stderr)

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

    def test_path_key_total_orderable_across_int_and_str(self):
        """Direct unit test of `_schema_layer`'s `_path_key`. A naive
        `key=lambda e: list(e.absolute_path)` raises `TypeError` when
        Python is asked to compare an int to a str at the same index;
        the typed tuple key `(type-tag, str(p))` reduces both to
        comparable str pairs. This is the regression vector identified
        by the wave-2 prepush-hostile finding."""
        # Synthetic error stand-ins — only `absolute_path` is read by
        # `_path_key` per the implementation contract.
        class _FakeErr:
            def __init__(self, path):
                self.absolute_path = path

        # The buggy `list(absolute_path)` key raises TypeError on this:
        keys = [validator._path_key(_FakeErr([0])), validator._path_key(_FakeErr(["x"]))]
        # Sort must complete without raising.
        try:
            ordered = sorted(keys)
        except TypeError as e:
            self.fail(f"_path_key not total-orderable on int vs str: {e}")
        # 'int' < 'str' lexicographically, so [0] sorts before ["x"].
        self.assertEqual(ordered[0], (("int", "0"),))
        self.assertEqual(ordered[1], (("str", "x"),))

        # Same depth, mixed types — must not raise.
        same_depth = [
            validator._path_key(_FakeErr(["participants", 0])),
            validator._path_key(_FakeErr(["participants", "extra_key"])),
        ]
        try:
            sorted(same_depth)
        except TypeError as e:
            self.fail(f"_path_key not total-orderable at same depth: {e}")

    def test_fail_without_failure_reason_cross_field_rejected(self):
        """Cross-field positive branch: `verdict=FAIL` without
        `failure_reason` must surface the conditional-required error
        (committed schema makes failure_reason optional; cross-field is
        sole authority)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["verdict"] = "FAIL"
            # Don't include failure_reason at all (committed schema
            # accepts because failure_reason is not in `required`).
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "failure_reason", "required")

    def test_mixed_client_with_only_go_impls_rejected(self):
        """Cross-field positive branch: `mixed_client_process_soak`
        with all-go impls must surface the «requires at least one go
        and one rust» rule (committed schema's enum admits both labels;
        cross-field enforces distribution)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "all_go_in_mixed_set"
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b", "implementation": "go"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-b"]
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self,
                errors,
                "implementation=go",
                "implementation=rust",
            )

    def test_mixed_client_with_single_participant_rejected(self):
        """Cross-field positive branch: `mixed_client_process_soak`
        with a single participant must surface the «requires at least
        2 participants» rule (committed schema's `minItems: 1` admits
        a single-participant list; cross-field enforces ≥2)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "single_participant_in_mixed_set"
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
            ]
            # Drop tx_path — single-participant data can't satisfy
            # cross-impl invariant; we only want to surface the
            # «requires at least 2 participants» message.
            del data["tx_path"]
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self,
                errors,
                "requires at least 2 participants",
            )


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

    def test_scenario_empty_string_schema_owned_only(self):
        """`scenario: ""` violates schema's `minLength: 1`. Schema layer
        is the sole authority for the bound."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = ""
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "scenario", "too short")

    def test_scenario_too_long_schema_owned_only(self):
        """`scenario` longer than `maxLength: 200` is rejected by the
        schema layer."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "x" * 201  # 1 over the maxLength: 200 bound
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "scenario", "too long")

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


class CrossFieldDirectFallbackTests(unittest.TestCase):
    """Direct invocation of `_cross_field` that BYPASSES `validate()`'s
    committed-schema floor, exercising the defensive `minimal_shape_errors`
    branches that protect future callers (refactor / direct unit test) which
    skip the floor. Without these tests the defensive `(alternate schema
    admitted)` diagnostics for `participants` would be unreachable on the
    standard call path and would drift from the comment contract documented
    in `_cross_field`.
    """

    def test_cross_field_non_list_participants_returns_minimal_shape_error(self):
        # participants is a dict, not a list.
        errors = validator._cross_field({
            "schema_version": "rubin-mixed-client-devnet-evidence-v1",
            "evidence_type": "mixed_client_process_soak",
            "scenario": "x",
            "verdict": "PASS",
            "participants": {"node-a": "go"},
            "tx_path": {
                "submitted_at": "node-a",
                "observed_at": ["node-b"],
                "tx_id": "0" * 64,
            },
        })
        self.assertEqual(
            errors,
            ["<root>: alternate schema admitted; expected non-empty `participants` list"],
        )

    def test_cross_field_empty_participants_returns_minimal_shape_error(self):
        errors = validator._cross_field({
            "evidence_type": "mixed_client_process_soak",
            "verdict": "PASS",
            "participants": [],
        })
        self.assertEqual(
            errors,
            ["<root>: alternate schema admitted; expected non-empty `participants` list"],
        )

    def test_cross_field_participant_not_object_returns_minimal_shape_error(self):
        errors = validator._cross_field({
            "evidence_type": "mixed_client_process_soak",
            "verdict": "PASS",
            "participants": ["node-a"],
        })
        self.assertTrue(
            any(
                "participants[0] not an object" in e and "alternate schema admitted" in e
                for e in errors
            ),
            f"expected participant-not-object minimal-shape error; got {errors}",
        )

    def test_cross_field_participant_name_not_string_returns_minimal_shape_error(self):
        errors = validator._cross_field({
            "evidence_type": "mixed_client_process_soak",
            "verdict": "PASS",
            "participants": [{"name": 1, "implementation": "go"}],
        })
        self.assertTrue(
            any(
                "participants[0].name not a string" in e and "alternate schema admitted" in e
                for e in errors
            ),
            f"expected name-not-string minimal-shape error; got {errors}",
        )

    def test_cross_field_participant_implementation_not_string_returns_minimal_shape_error(self):
        errors = validator._cross_field({
            "evidence_type": "mixed_client_process_soak",
            "verdict": "PASS",
            "participants": [{"name": "node-a", "implementation": 7}],
        })
        self.assertTrue(
            any(
                "participants[0].implementation not a string" in e
                and "alternate schema admitted" in e
                for e in errors
            ),
            f"expected implementation-not-string minimal-shape error; got {errors}",
        )


class TxPathDirectFallbackTests(unittest.TestCase):
    """Direct invocation of `_cross_field` that BYPASSES `validate()`'s
    committed-schema floor for the `tx_path` defensive shape branch.
    Without these tests the defensive `tx_path` minimal-shape `(alternate
    schema admitted)` diagnostics would be unreachable on the standard
    call path and would drift from the comment contract documented in
    `_cross_field` (parallel to `CrossFieldDirectFallbackTests` above for
    `participants`).
    """

    @staticmethod
    def _mixed_pass_with(tx_path) -> dict:
        return {
            "schema_version": "rubin-mixed-client-devnet-evidence-v1",
            "evidence_type": "mixed_client_process_soak",
            "scenario": "x",
            "verdict": "PASS",
            "participants": [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b", "implementation": "rust"},
            ],
            "tx_path": tx_path,
        }

    def test_cross_field_tx_path_submitted_at_not_string_returns_minimal_shape_error(self):
        errors = validator._cross_field(
            self._mixed_pass_with({
                "submitted_at": 1,
                "observed_at": ["node-b"],
                "tx_id": "0" * 64,
            })
        )
        self.assertTrue(
            any(
                "tx_path.submitted_at not a string" in e
                and "alternate schema admitted" in e
                for e in errors
            ),
            f"expected submitted_at-not-string minimal-shape error; got {errors}",
        )

    def test_cross_field_tx_path_observed_at_not_list_returns_minimal_shape_error(self):
        errors = validator._cross_field(
            self._mixed_pass_with({
                "submitted_at": "node-a",
                "observed_at": "node-b",
                "tx_id": "0" * 64,
            })
        )
        self.assertTrue(
            any(
                "tx_path.observed_at not a non-empty list of strings" in e
                and "alternate schema admitted" in e
                for e in errors
            ),
            f"expected observed_at-not-list minimal-shape error; got {errors}",
        )

    def test_cross_field_tx_path_observed_at_empty_returns_minimal_shape_error(self):
        errors = validator._cross_field(
            self._mixed_pass_with({
                "submitted_at": "node-a",
                "observed_at": [],
                "tx_id": "0" * 64,
            })
        )
        self.assertTrue(
            any(
                "tx_path.observed_at not a non-empty list of strings" in e
                and "alternate schema admitted" in e
                for e in errors
            ),
            f"expected observed_at-empty minimal-shape error; got {errors}",
        )

    def test_cross_field_tx_path_tx_id_not_string_returns_minimal_shape_error(self):
        errors = validator._cross_field(
            self._mixed_pass_with({
                "submitted_at": "node-a",
                "observed_at": ["node-b"],
                "tx_id": 1,
            })
        )
        self.assertTrue(
            any(
                "tx_path.tx_id not a string" in e
                and "alternate schema admitted" in e
                for e in errors
            ),
            f"expected tx_id-not-string minimal-shape error; got {errors}",
        )

    def test_cross_field_tx_path_non_dict_non_none_returns_alternate_admitted_error(self):
        # Non-dict, non-None `tx_path` (e.g. a string or int admitted by a
        # permissive alternate schema). Direct path must surface a
        # deterministic minimal-shape error, not silently fall through.
        errors = validator._cross_field(self._mixed_pass_with("not-an-object"))
        self.assertTrue(
            any(
                "tx_path not an object" in e
                and "alternate schema admitted" in e
                for e in errors
            ),
            f"expected tx_path-not-object alternate-admitted error; got {errors}",
        )


class CrossFieldUnknownSubmitterTests(unittest.TestCase):
    """Positive owner test for the `_cross_field` diagnostic
    `tx_path.submitted_at: <name> not in participants`. Schema cannot
    express participant-name membership, so the diagnostic is a true
    cross-field invariant. This test must reach the diagnostic on the
    standard call path (schema-valid fixture with a submitter name not
    declared in `participants`).
    """

    def test_unknown_submitter_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["tx_path"]["submitted_at"] = "node-ghost"
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path.submitted_at", "node-ghost", "not in participants")
            # Class-closure: when the submitter is unknown, the T13
            # cross-impl gate (`submitted_at in impl_by_name` predicate
            # in `_cross_field`) short-circuits, so the cross-impl
            # diagnostic must NOT also fire — defense against a future
            # refactor that drops the membership gate.
            self.assertFalse(
                any("requires observer implementation to differ" in e for e in errors),
                f"unknown submitter must NOT spuriously trigger the T13 cross-impl "
                f"message; got {errors}",
            )


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


# ---------------------------------------------------------------------------
# RUB-207 (RUB-24B): restart and reorg cross-field invariants.
# Schema owns: type, required, minLength, minimum, hex pattern,
# additionalProperties. Cross-field owns: participant-name membership,
# accepted_by_peer distinct-from-stopped_node, catch_up_height >=
# pre_restart_height (with reorg-explained-rollback escape), reorg
# fork_height < winning_branch_height, and final_state consistency
# with the declared winning branch when present.
# ---------------------------------------------------------------------------


_VALID_TIP_HASH = "a" * 64
_VALID_TIP_HASH_2 = "b" * 64


def _valid_with_restart(stopped="node-a", peer="node-b",
                        pre_h=100, catch_h=100,
                        include_live_action=True) -> dict:
    """Helper: committed valid fixture mutated to include a coherent
    restart object with optional post_restart_live_action. Default
    pairs (node-a stopped, node-b accepts live action) match the
    committed participants set so cross-field membership passes."""
    data = _load_committed_valid()
    data["restart"] = {
        "stopped_node": stopped,
        "pre_restart_height": pre_h,
        "catch_up_height": catch_h,
    }
    if include_live_action:
        data["restart"]["post_restart_live_action"] = {
            "accepted_by_peer": peer,
        }
    return data


def _valid_with_reorg(fork_h=95, winning_h=100,
                      winning_tip=_VALID_TIP_HASH,
                      include_final_state=False,
                      final_tip=None, final_height=None) -> dict:
    """Helper: committed valid fixture mutated to include a coherent
    reorg object with optional final_state. Default fork=95<winning=100
    satisfies the lifecycle-order invariant; final_state is omitted by
    default to exercise the false_positive_cases clause that absent
    final_state must not be required retroactively."""
    data = _load_committed_valid()
    data["reorg"] = {
        "fork_height": fork_h,
        "winning_branch_height": winning_h,
        "winning_branch_tip": winning_tip,
    }
    if include_final_state:
        data["reorg"]["final_state"] = {
            "tip": final_tip if final_tip is not None else winning_tip,
            "height": final_height if final_height is not None else winning_h,
        }
    return data


class RestartEvidenceTests(unittest.TestCase):
    """Cross-field invariants for the optional `restart` object."""

    def test_restart_only_evidence_passes(self):
        """Valid restart added to committed valid fixture (no reorg)
        passes; default catch_up >= pre_restart, accepted_by_peer in
        participants and != stopped_node."""
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(_validate_dict(Path(td), _valid_with_restart()), [])

    def test_restart_no_live_action_passes(self):
        """post_restart_live_action is optional — restart without it
        passes per false_positive_cases."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(include_live_action=False)
            self.assertEqual(_validate_dict(Path(td), data), [])

    def test_restart_stopped_node_unknown_rejected(self):
        """stopped_node references undeclared participant — schema
        validates string shape only; the cross-field membership check
        is the sole authority."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(stopped="node-ghost")
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "restart.stopped_node",
                        "node-ghost", "not in participants")

    def test_restart_live_action_accepted_by_unknown_peer_rejected(self):
        """accepted_by_peer references undeclared participant."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(peer="node-ghost")
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self, errors,
                "post_restart_live_action.accepted_by_peer",
                "node-ghost", "not in participants",
            )

    def test_restart_live_action_accepted_by_stopped_node_rejected(self):
        """accepted_by_peer equals stopped_node — live action cannot be
        accepted by the stopped participant."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(stopped="node-a", peer="node-a")
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self, errors,
                "post_restart_live_action.accepted_by_peer",
                "equals stopped_node",
            )

    def test_restart_catch_up_height_decrease_without_reorg_rejected(self):
        """catch_up_height < pre_restart_height with no reorg
        explanation — silent rollback is a lifecycle-order violation."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(pre_h=100, catch_h=80)
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self, errors,
                "restart.catch_up_height",
                "below pre_restart_height",
                "no reorg explanation",
            )

    def test_restart_catch_up_height_decrease_with_reorg_explanation_passes(self):
        """site×site interaction: catch_up_height < pre_restart_height
        is allowed when reorg.fork_height < pre_restart_height
        explains the rollback."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(pre_h=100, catch_h=80)
            data.update(_valid_with_reorg(fork_h=70, winning_h=85))
            self.assertEqual(_validate_dict(Path(td), data), [])

    def test_restart_catch_up_height_decrease_with_high_fork_reorg_still_rejected(self):
        """site×site negative: a reorg whose fork_height >=
        pre_restart_height does NOT explain the catch_up rollback."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(pre_h=100, catch_h=80)
            data.update(_valid_with_reorg(fork_h=100, winning_h=110))
            errors = _validate_dict(Path(td), data)
            # Exactly one finding expected: restart.catch_up_height fires
            # because fork_height=100 is NOT < pre_restart_height=100, so
            # the reorg-explained-rollback escape clause does not apply.
            # The reorg lifecycle-order invariant (fork < winning) is
            # satisfied here (100 < 110), so reorg.fork_height does NOT
            # also fire.
            _assert_one(
                self, errors,
                "restart.catch_up_height",
                "no reorg explanation",
            )

    def test_restart_catch_up_height_equal_to_pre_restart_passes(self):
        """Boundary: catch_up_height == pre_restart_height passes
        (the rule is >= not >)."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(pre_h=100, catch_h=100)
            self.assertEqual(_validate_dict(Path(td), data), [])


class ReorgEvidenceTests(unittest.TestCase):
    """Cross-field invariants for the optional `reorg` object."""

    def test_reorg_only_evidence_passes(self):
        """Valid reorg added (fork < winning) without restart object
        and without final_state passes per false_positive_cases."""
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(_validate_dict(Path(td), _valid_with_reorg()), [])

    def test_reorg_fork_height_equals_winning_rejected(self):
        """Boundary: fork_height == winning_branch_height violates
        lifecycle-order (fork must be strictly below winning)."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_reorg(fork_h=100, winning_h=100)
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self, errors,
                "reorg.fork_height",
                "must be less than winning_branch_height",
            )

    def test_reorg_fork_height_above_winning_rejected(self):
        """fork_height > winning_branch_height violates lifecycle order."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_reorg(fork_h=120, winning_h=100)
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self, errors,
                "reorg.fork_height",
                "must be less than winning_branch_height",
            )

    def test_reorg_final_state_consistent_passes(self):
        """final_state present and matches winning branch — passes."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_reorg(
                fork_h=95, winning_h=100,
                winning_tip=_VALID_TIP_HASH,
                include_final_state=True,
                final_tip=_VALID_TIP_HASH, final_height=100,
            )
            self.assertEqual(_validate_dict(Path(td), data), [])

    def test_reorg_final_state_tip_inconsistent_rejected(self):
        """final_state.tip differs from winning_branch_tip."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_reorg(
                fork_h=95, winning_h=100,
                winning_tip=_VALID_TIP_HASH,
                include_final_state=True,
                final_tip=_VALID_TIP_HASH_2, final_height=100,
            )
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self, errors,
                "reorg.final_state.tip",
                "must equal winning_branch_tip",
            )

    def test_reorg_final_state_height_inconsistent_rejected(self):
        """final_state.height differs from winning_branch_height."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_reorg(
                fork_h=95, winning_h=100,
                winning_tip=_VALID_TIP_HASH,
                include_final_state=True,
                final_tip=_VALID_TIP_HASH, final_height=99,
            )
            errors = _validate_dict(Path(td), data)
            _assert_one(
                self, errors,
                "reorg.final_state.height",
                "must equal winning_branch_height",
            )

    def test_reorg_final_state_absent_passes(self):
        """false_positive_cases: reorg without final_state passes."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_reorg(include_final_state=False)
            self.assertEqual(_validate_dict(Path(td), data), [])


class RestartReorgSchemaOwnedTests(unittest.TestCase):
    """Schema layer is the sole authority for type/required/minimum/
    pattern problems on restart/reorg fields. The cross-field layer
    must NOT also fire on schema-rejected inputs (short-circuit drift
    check)."""

    def test_restart_missing_required_field_schema_owned_only(self):
        """restart without `stopped_node` is schema-rejected; no
        cross-field "restart.stopped_node: ... not in participants"
        diagnostic should appear."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["restart"] = {
                # missing stopped_node
                "pre_restart_height": 100,
                "catch_up_height": 100,
            }
            errors = _validate_dict(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(
                any("stopped_node" in e and "required" in e for e in errors),
                f"expected schema-required violation; got {errors}",
            )
            self.assertFalse(
                any("not in participants" in e for e in errors),
                f"cross-field membership must not fire on schema-rejected "
                f"input; got {errors}",
            )

    def test_reorg_missing_required_field_schema_owned_only(self):
        """reorg without winning_branch_tip is schema-rejected; no
        cross-field lifecycle error should fire."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["reorg"] = {
                "fork_height": 95,
                "winning_branch_height": 100,
                # missing winning_branch_tip
            }
            errors = _validate_dict(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(
                any("winning_branch_tip" in e and "required" in e for e in errors),
                f"expected schema-required violation; got {errors}",
            )
            self.assertFalse(
                any("must be less than winning_branch_height" in e for e in errors),
                f"cross-field lifecycle order must not fire on schema-rejected "
                f"input; got {errors}",
            )

    def test_reorg_winning_branch_tip_pattern_schema_owned_only(self):
        """reorg.winning_branch_tip not matching ^[0-9a-f]{64}$ is
        schema-rejected before cross-field consistency runs."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_reorg(winning_tip="not-a-hash")
            errors = _validate_dict(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(
                any("winning_branch_tip" in e for e in errors),
                f"expected schema-pattern violation; got {errors}",
            )

    def test_restart_stopped_node_empty_string_schema_owned_only(self):
        """restart.stopped_node empty string violates minLength:1."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_with_restart(stopped="")
            errors = _validate_dict(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(
                any("stopped_node" in e and "too short" in e for e in errors),
                f"expected schema minLength violation; got {errors}",
            )


class RestartDirectFallbackTests(unittest.TestCase):
    """Direct invocation of `_cross_field_restart` BYPASSING the
    committed-schema floor, exercising the defensive
    `(alternate schema admitted)` minimal-shape branches that protect
    direct callers from KeyError. Parallel to
    `CrossFieldDirectFallbackTests` for participants and
    `TxPathDirectFallbackTests` for tx_path."""

    @staticmethod
    def _names() -> set[str]:
        return {"node-a", "node-b"}

    def test_cross_field_restart_non_dict(self):
        errors = validator._cross_field_restart(
            {"restart": "not-an-object"}, self._names()
        )
        self.assertTrue(
            any("restart not an object" in e
                and "alternate schema admitted" in e for e in errors),
            f"got {errors}",
        )

    def test_cross_field_restart_stopped_node_not_string(self):
        errors = validator._cross_field_restart(
            {"restart": {
                "stopped_node": 1,
                "pre_restart_height": 100,
                "catch_up_height": 100,
            }},
            self._names(),
        )
        self.assertTrue(
            any("restart.stopped_node not a string" in e
                and "alternate schema admitted" in e for e in errors),
            f"got {errors}",
        )

    def test_cross_field_restart_pre_restart_height_not_int(self):
        errors = validator._cross_field_restart(
            {"restart": {
                "stopped_node": "node-a",
                "pre_restart_height": "100",
                "catch_up_height": 100,
            }},
            self._names(),
        )
        self.assertTrue(
            any("restart.pre_restart_height not an integer" in e
                and "alternate schema admitted" in e for e in errors),
            f"got {errors}",
        )

    def test_cross_field_restart_catch_up_height_not_int(self):
        errors = validator._cross_field_restart(
            {"restart": {
                "stopped_node": "node-a",
                "pre_restart_height": 100,
                "catch_up_height": "100",
            }},
            self._names(),
        )
        self.assertTrue(
            any("restart.catch_up_height not an integer" in e
                and "alternate schema admitted" in e for e in errors),
            f"got {errors}",
        )

    def test_cross_field_restart_pre_restart_height_bool_rejected(self):
        """bool is a Python int subclass; the validator must explicitly
        reject it because schema declares type:integer."""
        errors = validator._cross_field_restart(
            {"restart": {
                "stopped_node": "node-a",
                "pre_restart_height": True,
                "catch_up_height": 100,
            }},
            self._names(),
        )
        self.assertTrue(
            any("restart.pre_restart_height not an integer" in e for e in errors),
            f"got {errors}",
        )


class ReorgDirectFallbackTests(unittest.TestCase):
    """Direct invocation of `_cross_field_reorg` BYPASSING the
    committed-schema floor (parallel to RestartDirectFallbackTests)."""

    def test_cross_field_reorg_non_dict(self):
        errors = validator._cross_field_reorg({"reorg": "not-an-object"})
        self.assertTrue(
            any("reorg not an object" in e
                and "alternate schema admitted" in e for e in errors),
            f"got {errors}",
        )

    def test_cross_field_reorg_fork_height_not_int(self):
        errors = validator._cross_field_reorg({"reorg": {
            "fork_height": "95",
            "winning_branch_height": 100,
            "winning_branch_tip": "a" * 64,
        }})
        self.assertTrue(
            any("reorg.fork_height not an integer" in e
                and "alternate schema admitted" in e for e in errors),
            f"got {errors}",
        )

    def test_cross_field_reorg_winning_branch_height_not_int(self):
        errors = validator._cross_field_reorg({"reorg": {
            "fork_height": 95,
            "winning_branch_height": "100",
            "winning_branch_tip": "a" * 64,
        }})
        self.assertTrue(
            any("reorg.winning_branch_height not an integer" in e
                and "alternate schema admitted" in e for e in errors),
            f"got {errors}",
        )

    def test_cross_field_reorg_winning_branch_tip_not_string(self):
        errors = validator._cross_field_reorg({"reorg": {
            "fork_height": 95,
            "winning_branch_height": 100,
            "winning_branch_tip": 12345,
        }})
        self.assertTrue(
            any("reorg.winning_branch_tip not a string" in e
                and "alternate schema admitted" in e for e in errors),
            f"got {errors}",
        )

    def test_cross_field_reorg_fork_height_bool_rejected(self):
        """bool is a Python int subclass; reject explicitly."""
        errors = validator._cross_field_reorg({"reorg": {
            "fork_height": True,
            "winning_branch_height": 100,
            "winning_branch_tip": "a" * 64,
        }})
        self.assertTrue(
            any("reorg.fork_height not an integer" in e for e in errors),
            f"got {errors}",
        )


if __name__ == "__main__":
    unittest.main()
