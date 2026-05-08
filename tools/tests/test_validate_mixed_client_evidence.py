#!/usr/bin/env python3
"""Tests for scripts/devnet/validate_mixed_client_evidence.py — base slice (PR-A).

Targets the cross-implementation tx_path invariant established by RUB-206:
mixed_client_process_soak with verdict=PASS must include at least one observer
whose implementation differs from the submitter's. Tests cover the hostile
matrix from the issue contract plus accepted/false-positive paths.

Restart/reorg cross-field, timestamp policy, endpoint policy, and helper-vs-
real-process distinction are not exercised here (deferred to RUB-207/RUB-208).
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


def _validate_dict(td: Path, data: dict) -> list[str]:
    fixture = td / "case.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")
    return validator.validate(fixture, SCHEMA_PATH)


def _assert_one(testcase: unittest.TestCase, errors: list[str], *needles: str) -> None:
    """Assert at least one error contains every needle."""
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


class MalformedInputTests(unittest.TestCase):
    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            errors = validator.validate(Path(td) / "nope.json", SCHEMA_PATH)
            _assert_one(self, errors, "cannot read")

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bad.json"
            f.write_text("{not valid", encoding="utf-8")
            _assert_one(self, validator.validate(f, SCHEMA_PATH), "malformed JSON")

    def test_top_level_array_rejected(self):
        """Top-level non-object input: schema owns the root `type: object`
        rejection; the cross-field `<root>: top-level JSON must be an
        object` message must NOT fire on top of the schema's authoritative
        error (S1 wave-7 close)."""
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "arr.json"
            f.write_text("[]", encoding="utf-8")
            errors = validator.validate(f, SCHEMA_PATH)
            # Schema reports the root type-mismatch authoritatively.
            _assert_one(self, errors, "is not of type", "object")
            # Custom cross-field root message must NOT fire.
            self.assertFalse(
                any("top-level JSON must be an object" in e for e in errors),
                f"cross-field S1 root message duplicates schema error; got {errors}",
            )

    def test_missing_schema_version_no_duplicate_cross_field_message(self):
        """When `schema_version` is missing, schema's `const` reports the
        real problem; the cross-field "expected vs got" wording must NOT
        additionally fire (S2 class-closure)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            del data["schema_version"]
            errors = _validate_dict(Path(td), data)
            self.assertTrue(
                any("schema_version" in e for e in errors),
                f"expected schema error on missing schema_version; got {errors}",
            )
            self.assertFalse(
                any("must be exactly" in e for e in errors),
                f"cross-field 'must be exactly' fired on missing field; got {errors}",
            )

    def test_wrong_type_schema_version_no_duplicate_cross_field_message(self):
        """When `schema_version` is wrong-type (int), schema's `type` is
        authoritative; cross-field message must NOT fire (S2)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["schema_version"] = 42  # type: ignore[assignment]
            errors = _validate_dict(Path(td), data)
            self.assertFalse(
                any("must be exactly" in e for e in errors),
                f"cross-field 'must be exactly' fired on wrong-type; got {errors}",
            )

    def test_failure_reason_wrong_type_no_duplicate_message(self):
        """verdict=FAIL with wrong-type failure_reason: schema's type
        check is authoritative; cross-field "required and non-empty" must
        NOT fire (S3)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["verdict"] = "FAIL"
            data["failure_reason"] = 42  # type: ignore[assignment]
            errors = _validate_dict(Path(td), data)
            self.assertTrue(
                any("failure_reason" in e for e in errors),
                f"expected schema error on wrong-type failure_reason; got {errors}",
            )
            self.assertFalse(
                any(
                    "required and must be non-empty when verdict=FAIL" in e
                    for e in errors
                ),
                f"cross-field 'required and non-empty' fired on wrong-type; got {errors}",
            )

    def test_participants_wrong_type_no_duplicate_required_message(self):
        """When participants is wrong-type (dict instead of list), schema
        is authoritative; cross-field 'required for evidence_type=' must
        NOT fire (S4 closure: cross-field message removed)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"] = {"node-a": "go"}  # type: ignore[assignment]
            errors = _validate_dict(Path(td), data)
            self.assertFalse(
                any("participants: required" in e for e in errors),
                f"cross-field 'participants: required' fired; got {errors}",
            )

    def test_partial_schema_shape_participants_suppress_membership_diagnostic(self):
        """When ANY participant is partially schema-invalid (item is not a
        dict, or item.name is not a string), `valid_names` is incomplete;
        the schema layer's per-item type/required errors are authoritative.
        S8/S9 `tx_path.{submitted_at,observed_at} not in participants`
        diagnostics must NOT fire on top of that incomplete view (S8/S9
        wave-6 element-shape gate)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "partial_shape_participant_with_tx_path_lookup"
            # First participant has wrong-type name (int); second is
            # well-shaped. tx_path references a name that ISN'T in
            # `valid_names` so without the gate S8/S9 would emit a
            # misleading "not in participants" message even though the
            # real problem is reported by the schema (`participants[0].name`
            # type error).
            data["participants"] = [
                {"name": 42, "implementation": "go"},  # type: ignore[dict-item]
                {"name": "node-b", "implementation": "rust"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-b"]
            errors = _validate_dict(Path(td), data)
            # Schema reports the type error on the malformed name.
            self.assertTrue(
                any("name" in e for e in errors),
                f"expected schema type/pattern error on participants[0].name; got {errors}",
            )
            # Cross-field membership diagnostic must NOT fire because
            # `all_participant_names_valid` is False.
            self.assertFalse(
                any("not in participants" in e for e in errors),
                f"S8/S9 membership diagnostic fired despite partial-shape participants; got {errors}",
            )

    def test_observed_at_with_non_string_item_suppresses_cross_impl_check(self):
        """When `observed_at` is a list whose items are not all strings,
        the schema layer reports the item-type error authoritatively. S10
        cross-impl observer-differ check must NOT additionally fire on the
        string subset (S10 wave-6 list-purity gate)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "observed_at_mixed_types"
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b", "implementation": "go"},
                {"name": "node-c", "implementation": "rust"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            # Mixed-type observed_at: schema reports item-type error on 42;
            # without the gate, cross-impl would still run on the string
            # subset ["node-b"] (same impl as submitter "go") and emit a
            # misleading differ message.
            data["tx_path"]["observed_at"] = ["node-b", 42]  # type: ignore[list-item]
            errors = _validate_dict(Path(td), data)
            # Schema reports the item-type error.
            self.assertTrue(
                any("observed_at" in e for e in errors),
                f"expected schema error on tx_path.observed_at item-type; got {errors}",
            )
            # Cross-impl differ must NOT fire on the string subset.
            self.assertFalse(
                any(
                    ("submitter" in e and "observer" in e and "differ" in e)
                    for e in errors
                ),
                f"S10 fired on string subset of mixed-type observed_at; got {errors}",
            )

    def test_duplicate_names_suppress_cross_impl_observer_differ_check(self):
        """When participant names are duplicated, `impl_by_name` is
        last-write-wins ambiguous; the duplicate-names cross-field error
        is authoritative. The cross-impl observer-differ check must NOT
        additionally fire on top of an ambiguous mapping (S10 wave-5
        gate)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "duplicate_names_with_cross_impl_setup"
            # node-a appears twice (same impl=go); node-c is rust. Without
            # the gate, the cross-impl algorithm would resolve `node-a` via
            # last-write-wins `impl_by_name` and, with submitted_at and the
            # sole observer both pointing at node-a, emit a misleading
            # "submitter/observer differ" message even though the underlying
            # ambiguity is the duplicate-name cross-field error.
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-a", "implementation": "go"},
                {"name": "node-c", "implementation": "rust"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-a"]
            errors = _validate_dict(Path(td), data)
            self.assertTrue(
                any("duplicate names" in e for e in errors),
                f"expected duplicate-names cross-field error; got {errors}",
            )
            self.assertFalse(
                any(
                    ("submitter" in e and "observer" in e and "differ" in e)
                    for e in errors
                ),
                f"cross-impl observer-differ fired despite duplicate names; got {errors}",
            )

    def test_all_participants_missing_impl_no_cross_impl_requirement_message(self):
        """When ALL participants lack `implementation`, schema reports
        each missing-required error; the cross-impl 'go AND rust required'
        message must NOT additionally fire (S5)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            for p in data["participants"]:
                p.pop("implementation", None)
            errors = _validate_dict(Path(td), data)
            self.assertTrue(
                any("implementation" in e for e in errors),
                f"expected schema errors on missing impls; got {errors}",
            )
            self.assertFalse(
                any(
                    "implementation=go and one implementation=rust" in e
                    for e in errors
                ),
                f"cross-impl requirement message duplicates schema; got {errors}",
            )

    def test_wrong_type_tx_path_does_not_trigger_required_fallback(self):
        """When `tx_path` is present but has a wrong type (e.g. list, string),
        the schema layer reports the type error authoritatively; the
        cross-field fallback must NOT additionally emit
        `tx_path: required ...` on the same case (Copilot wave-4 P2).
        """
        for wrong in ([], "", 42):
            with tempfile.TemporaryDirectory() as td:
                data = _load_committed_valid()
                data["scenario"] = "tx_path_wrong_type"
                data["tx_path"] = wrong  # type: ignore[assignment]
                errors = _validate_dict(Path(td), data)
                self.assertTrue(
                    any("tx_path" in e for e in errors),
                    f"expected schema type error on wrong-type tx_path={wrong!r}; got {errors}",
                )
                self.assertFalse(
                    any(
                        ("tx_path: required" in e and "mixed_client_process_soak" in e)
                        for e in errors
                    ),
                    f"`tx_path: required` fallback fired on wrong-type tx_path={wrong!r}; got {errors}",
                )

    def test_observer_missing_impl_does_not_trigger_cross_impl_error(self):
        """If a string observer references a participant with no string
        `implementation`, the schema layer reports the missing field; the
        cross-impl check must NOT additionally emit a duplicative
        submitter/observer error on the same case (Copilot wave-3 P2).
        """
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "observer_missing_impl"
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b"},  # implementation field omitted
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-b"]
            errors = _validate_dict(Path(td), data)
            # schema layer must report the missing field
            self.assertTrue(
                any("implementation" in e for e in errors),
                f"expected schema error on missing implementation; got {errors}",
            )
            # cross-impl algorithm must NOT additionally fire
            self.assertFalse(
                any(
                    ("submitter" in e and "observer" in e and "differ" in e)
                    for e in errors
                ),
                f"cross-impl check fired on incomplete data; got {errors}",
            )


class CrossImplTxPathRejectionTests(unittest.TestCase):
    """T13 hostile cases: same-impl propagation in mixed-client set rejected."""

    def test_go_to_go_only_in_mixed_set_rejected(self):
        """{go, go, rust} with tx_path go-1 -> [go-2] must reject (T13 case 1)."""
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

    def test_rust_to_rust_only_in_mixed_set_rejected(self):
        """{rust, rust, go} with tx_path rust-1 -> [rust-2] must reject (T13 case 2)."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "rust_to_rust_only_in_mixed_set"
            data["participants"] = [
                {"name": "node-a", "implementation": "rust"},
                {"name": "node-b", "implementation": "rust"},
                {"name": "node-c", "implementation": "go"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-b"]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path", "submitter", "observer")

    def test_submitter_only_observer_rejected(self):
        """observed_at == [submitted_at] for mixed-client PASS must reject."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["tx_path"]["observed_at"] = ["node-a"]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path", "implementation")

    def test_unknown_observer_rejected(self):
        """tx_path.observed_at referencing a non-participant rejects."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["tx_path"]["observed_at"] = ["node-ghost"]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path.observed_at", "node-ghost")

    def test_unknown_submitter_rejected(self):
        """tx_path.submitted_at referencing a non-participant rejects."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["tx_path"]["submitted_at"] = "node-ghost"
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path.submitted_at", "node-ghost")

    def test_pass_without_tx_path_rejected(self):
        """mixed-client PASS without tx_path block must reject."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            del data["tx_path"]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path", "required")


class CrossImplTxPathAcceptedTests(unittest.TestCase):
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
            self.assertEqual(
                _validate_dict(Path(td), data), [], "rust->go must pass"
            )

    def test_multi_hop_go_go_rust_passes(self):
        """Submitter Go, observer Go AND observer Rust — cross-impl exists, passes."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "multi_hop_go_go_rust"
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b", "implementation": "go"},
                {"name": "node-c", "implementation": "rust"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-b", "node-c"]
            self.assertEqual(
                _validate_dict(Path(td), data),
                [],
                "multi-hop with cross-impl observer must pass",
            )

    def test_fail_without_propagation_passes(self):
        """FAIL evidence may describe partial propagation without cross-impl rule."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["scenario"] = "fail_partial_propagation"
            data["verdict"] = "FAIL"
            data["failure_reason"] = "node-b crashed before tx observation"
            data["tx_path"]["observed_at"] = ["node-a"]
            self.assertEqual(
                _validate_dict(Path(td), data),
                [],
                "FAIL is not gated by cross-impl rule",
            )

    def test_single_client_go_to_go_passes(self):
        """single_client_process_soak with one impl is not gated by mixed rule."""
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["evidence_type"] = "single_client_process_soak"
            data["scenario"] = "single_client_go_local"
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b", "implementation": "go"},
            ]
            data["tx_path"]["submitted_at"] = "node-a"
            data["tx_path"]["observed_at"] = ["node-b"]
            self.assertEqual(
                _validate_dict(Path(td), data),
                [],
                "single_client go->go must pass",
            )


class SchemaShapeTests(unittest.TestCase):
    def test_unknown_schema_version_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["schema_version"] = "rubin-mixed-client-devnet-evidence-v2"
            _assert_one(self, _validate_dict(Path(td), data), "schema_version")

    def test_implementation_missing_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            del data["participants"][0]["implementation"]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "implementation")

    def test_implementation_unknown_value_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"][0]["implementation"] = "java"
            _assert_one(self, _validate_dict(Path(td), data), "implementation")

    def test_mixed_client_with_one_impl_only_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"] = [
                {"name": "node-a", "implementation": "go"},
                {"name": "node-b", "implementation": "go"},
            ]
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "implementation=go", "implementation=rust")

    def test_fail_without_failure_reason_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["verdict"] = "FAIL"
            _assert_one(self, _validate_dict(Path(td), data), "failure_reason")

    def test_duplicate_participant_names_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"][1]["name"] = "node-a"
            _assert_one(self, _validate_dict(Path(td), data), "duplicate")

    def test_tx_id_wrong_length_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["tx_path"]["tx_id"] = "abc123"
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "tx_path.tx_id", "does not match")

    def test_participant_name_uppercase_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"][0]["name"] = "NODE-A"
            errors = _validate_dict(Path(td), data)
            _assert_one(self, errors, "participants.0.name", "does not match")


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
