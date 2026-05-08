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
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "arr.json"
            f.write_text("[]", encoding="utf-8")
            self.assertTrue(validator.validate(f, SCHEMA_PATH))


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
            self.assertTrue(_validate_dict(Path(td), data))

    def test_participant_name_uppercase_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _load_committed_valid()
            data["participants"][0]["name"] = "NODE-A"
            self.assertTrue(_validate_dict(Path(td), data))


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
