#!/usr/bin/env python3
"""Tests for scripts/devnet/validate_mixed_client_evidence.py.

Runs under stdlib unittest so the existing CI step
`python3 -m unittest discover -s tools/tests -p 'test_*.py'` discovers them.

Exercises every hostile case enumerated in RUB-24 contract:
- missing implementation field
- same implementation for both sides claimed mixed-client
- helper-only artifact
- empty metrics object claimed pass
- ambiguous tx path direction
- restart/reorg fields omitted but report claims covered
- unknown schema version
- non-deterministic timestamp-only evidence (no substantive content)

Plus accepted/false-positive cases:
- valid minimal mixed (committed fixture)
- valid no_data with reason (committed fixture)
- valid single_client_process_soak
- valid restart/reorg with sub-fields
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


def _load_fixture(name: str) -> dict:
    with open(TESTDATA_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def _valid_mixed() -> dict:
    return _load_fixture("valid_minimal_mixed.json")


def _valid_no_data() -> dict:
    return _load_fixture("valid_no_data_with_reason.json")


def _write_and_validate(tmp_dir: Path, data: dict, filename: str = "case.json") -> list[str]:
    fixture = tmp_dir / filename
    fixture.write_text(json.dumps(data), encoding="utf-8")
    return validator.validate(fixture, SCHEMA_PATH)


class CommittedFixtureTests(unittest.TestCase):
    def test_valid_minimal_mixed_passes(self):
        errors = validator.validate(
            TESTDATA_DIR / "valid_minimal_mixed.json", SCHEMA_PATH
        )
        self.assertEqual(errors, [], f"valid_minimal_mixed must pass; got {errors}")

    def test_valid_no_data_with_reason_passes(self):
        errors = validator.validate(
            TESTDATA_DIR / "valid_no_data_with_reason.json", SCHEMA_PATH
        )
        self.assertEqual(
            errors, [], f"valid_no_data_with_reason must pass; got {errors}"
        )

    def test_invalid_helper_only_fails_on_node_role_const(self):
        errors = validator.validate(
            TESTDATA_DIR / "invalid_helper_only.json", SCHEMA_PATH
        )
        self.assertTrue(errors, "invalid_helper_only must fail")
        joined = " ".join(errors)
        self.assertTrue(
            "node_role" in joined or "real_node_process" in joined,
            f"helper-only failure should cite node_role const; got {errors}",
        )

    def test_invalid_same_implementation_fails(self):
        errors = validator.validate(
            TESTDATA_DIR / "invalid_same_implementation.json", SCHEMA_PATH
        )
        self.assertTrue(errors, "invalid_same_implementation must fail")
        self.assertTrue(
            any(
                "implementation=go" in e and "implementation=rust" in e
                for e in errors
            ),
            f"same-impl failure should cite missing rust; got {errors}",
        )

    def test_invalid_missing_implementation_fails(self):
        errors = validator.validate(
            TESTDATA_DIR / "invalid_missing_implementation.json", SCHEMA_PATH
        )
        self.assertTrue(errors, "invalid_missing_implementation must fail")
        self.assertTrue(
            any("implementation" in e for e in errors),
            f"missing-impl failure should cite implementation; got {errors}",
        )


class MalformedInputTests(unittest.TestCase):
    def test_missing_fixture_file(self):
        with tempfile.TemporaryDirectory() as td:
            errors = validator.validate(Path(td) / "nope.json", SCHEMA_PATH)
            self.assertTrue(any("cannot read" in e for e in errors), errors)

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td) / "bad.json"
            fixture.write_text("{not valid json", encoding="utf-8")
            errors = validator.validate(fixture, SCHEMA_PATH)
            self.assertTrue(any("malformed JSON" in e for e in errors), errors)

    def test_top_level_array_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td) / "arr.json"
            fixture.write_text("[]", encoding="utf-8")
            errors = validator.validate(fixture, SCHEMA_PATH)
            self.assertTrue(errors, "non-object top level must produce error")


class HostileMutationTests(unittest.TestCase):
    def test_unknown_schema_version_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["schema_version"] = "rubin-mixed-client-devnet-evidence-v2"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "unknown schema version must be rejected")
            self.assertTrue(
                any("schema_version" in e for e in errors), errors
            )

    def test_empty_metrics_object_claimed_pass_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["metrics"] = {
                "duration_seconds": 0,
                "blocks_observed": 0,
                "txs_observed": 0,
            }
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "empty metrics with verdict=PASS must be rejected")
            self.assertTrue(
                any(
                    "metrics" in e and ("> 0" in e or "timestamp-only" in e)
                    for e in errors
                ),
                errors,
            )

    def test_metrics_field_missing_when_pass_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            del data["metrics"]
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(
                errors, "metrics missing with verdict=PASS must be rejected"
            )

    def test_ambiguous_tx_path_direction_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["tx_path"]["observed_at"] = ["node-a"]
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(
                errors,
                "ambiguous tx_path (observed_at == [submitted_at]) must be rejected",
            )
            self.assertTrue(
                any("tx_path" in e and "ambiguous" in e for e in errors), errors
            )

    def test_restart_enabled_missing_subfields_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["restart"] = {"enabled": True}
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(
                errors, "restart.enabled=true with no sub-fields must be rejected"
            )
            self.assertTrue(
                any("restart.checkpoint_before_stop" in e for e in errors), errors
            )
            self.assertTrue(
                any("restart.state_after_catchup" in e for e in errors), errors
            )
            self.assertTrue(
                any("restart.post_restart_live_action" in e for e in errors), errors
            )

    def test_reorg_enabled_missing_subfields_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["reorg"] = {"enabled": True}
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(any("reorg.fork_height" in e for e in errors), errors)
            self.assertTrue(
                any("reorg.winning_branch_height" in e for e in errors), errors
            )
            self.assertTrue(
                any("reorg.loser_branch_height" in e for e in errors), errors
            )

    def test_no_data_without_reason_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = {
                "schema_version": "rubin-mixed-client-devnet-evidence-v1",
                "evidence_type": "no_data",
                "scenario": "no_data_missing_reason",
                "verdict": "NO_DATA",
            }
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(any("no_data_reason" in e for e in errors), errors)

    def test_no_data_with_process_soak_fields_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_no_data()
            data["participants"] = [
                {
                    "name": "node-a",
                    "implementation": "go",
                    "node_role": "real_node_process",
                    "process": {
                        "pid": 1,
                        "command": "x",
                        "started_at": "2026-05-07T22:30:00Z",
                    },
                    "rpc": "127.0.0.1:1",
                    "p2p": "127.0.0.1:2",
                    "checkpoint_height": 0,
                    "tip_hash": "0" * 64,
                    "peer_count": 0,
                }
            ]
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "no_data with participants must be rejected")
            self.assertTrue(
                any("participants" in e and "no_data" in e for e in errors), errors
            )

    def test_verdict_no_data_outside_no_data_type_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["verdict"] = "NO_DATA"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(
                any("NO_DATA" in e and "no_data" in e for e in errors), errors
            )

    def test_verdict_fail_without_failure_reason_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["verdict"] = "FAIL"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(any("failure_reason" in e for e in errors), errors)

    def test_topology_edge_endpoint_not_in_participants_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["topology"]["edges"] = [["node-a", "node-ghost"]]
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(
                any("topology.edges" in e and "node-ghost" in e for e in errors),
                errors,
            )

    def test_tx_path_submitted_at_unknown_node_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["tx_path"]["submitted_at"] = "node-ghost"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(
                any(
                    "tx_path.submitted_at" in e and "node-ghost" in e
                    for e in errors
                ),
                errors,
            )

    def test_participants_duplicate_names_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][1]["name"] = "node-a"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors)
            self.assertTrue(any("duplicate" in e for e in errors), errors)

    def test_pid_zero_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["process"]["pid"] = 0
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(
                errors,
                "process.pid=0 must be rejected (helpers often lack real pids)",
            )

    def test_tip_hash_wrong_length_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["tip_hash"] = "abc123"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "tip_hash not 64 hex must be rejected")

    def test_invalid_started_at_timestamp_rejected(self):
        """format_checker must reject malformed RFC3339 timestamps."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["process"]["started_at"] = "not-a-timestamp"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "malformed started_at must be rejected by format_checker")
            self.assertTrue(
                any("started_at" in e for e in errors),
                f"expected error to cite started_at; got {errors}",
            )

    def test_started_at_invalid_month_rejected(self):
        """Shape-valid but calendar-invalid month must be rejected (semantic check)."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["process"]["started_at"] = "2026-13-07T22:30:00Z"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "month=13 must be rejected by semantic RFC3339 check")
            self.assertTrue(
                any("started_at" in e for e in errors),
                f"expected error to cite started_at; got {errors}",
            )

    def test_started_at_invalid_hour_rejected(self):
        """Shape-valid but calendar-invalid hour=25 must be rejected."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["process"]["started_at"] = "2026-05-07T25:30:00Z"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "hour=25 must be rejected by semantic RFC3339 check")
            self.assertTrue(
                any("started_at" in e for e in errors),
                f"expected error to cite started_at; got {errors}",
            )

    def test_started_at_invalid_day_for_month_rejected(self):
        """Calendar-invalid day-for-month (Feb 30) must be rejected."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["process"]["started_at"] = "2026-02-30T12:00:00Z"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "Feb 30 must be rejected by semantic RFC3339 check")
            self.assertTrue(
                any("started_at" in e for e in errors),
                f"expected error to cite started_at; got {errors}",
            )

    def test_started_at_invalid_second_rejected(self):
        """Calendar-invalid second=60 (leap second) must be rejected per producer contract."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["process"]["started_at"] = "2026-05-07T22:30:60Z"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "second=60 must be rejected by semantic RFC3339 check")
            self.assertTrue(
                any("started_at" in e for e in errors),
                f"expected error to cite started_at; got {errors}",
            )

    def test_stopped_at_invalid_timestamp_rejected(self):
        """format_checker must apply to stopped_at too (global registration)."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["process"]["stopped_at"] = "2026-13-07T22:30:00Z"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "invalid stopped_at month must be rejected")
            self.assertTrue(
                any("stopped_at" in e for e in errors),
                f"expected error to cite stopped_at; got {errors}",
            )

    def test_port_above_max_rejected(self):
        """Port > 65535 must be rejected via structural check."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["rpc"] = "127.0.0.1:99999"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "port 99999 must be rejected")
            self.assertTrue(
                any("65535" in e and "rpc" in e for e in errors),
                f"expected port-range error citing 65535; got {errors}",
            )

    def test_port_just_above_max_rejected(self):
        """Boundary: 65536 must be rejected."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][1]["p2p"] = "127.0.0.1:65536"
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "port 65536 must be rejected")
            self.assertTrue(
                any("65535" in e and "p2p" in e for e in errors),
                f"expected port-range error citing 65535; got {errors}",
            )

    def test_restart_checkpoint_invalid_port_rejected(self):
        """restart.checkpoint endpoint with port > 65535 must be rejected."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["restart"] = {
                "enabled": True,
                "stopped_node": "node-b",
                "checkpoint_before_stop": {
                    "height": 102,
                    "tip_hash": "1" * 64,
                    "rpc": "127.0.0.1:70000",
                },
                "state_after_catchup": {
                    "height": 104,
                    "tip_hash": "4" * 64,
                },
                "post_restart_live_action": {
                    "action": "mine_next",
                    "height": 105,
                    "block_hash": "5" * 64,
                },
            }
            errors = _write_and_validate(Path(td), data)
            self.assertTrue(errors, "restart checkpoint port > 65535 must be rejected")
            self.assertTrue(
                any(
                    "restart.checkpoint_before_stop.rpc" in e and "65535" in e
                    for e in errors
                ),
                f"expected restart checkpoint port-range error; got {errors}",
            )


class FalsePositivePassTests(unittest.TestCase):
    def test_single_client_with_one_implementation_passes(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["evidence_type"] = "single_client_process_soak"
            data["scenario"] = "single_client_smoke"
            for p in data["participants"]:
                p["implementation"] = "go"
            errors = _write_and_validate(Path(td), data)
            self.assertEqual(
                errors,
                [],
                f"single_client_process_soak with one implementation must pass; got {errors}",
            )

    def test_single_client_local_only_tx_path_passes(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["evidence_type"] = "single_client_process_soak"
            data["scenario"] = "single_client_local_smoke"
            for p in data["participants"]:
                p["implementation"] = "go"
            data["tx_path"]["observed_at"] = ["node-a"]
            errors = _write_and_validate(Path(td), data)
            self.assertEqual(
                errors,
                [],
                f"single_client local-only tx_path must pass; got {errors}",
            )

    def test_restart_with_subfields_passes(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["restart"] = {
                "enabled": True,
                "stopped_node": "node-b",
                "checkpoint_before_stop": {
                    "height": 102,
                    "tip_hash": "1" * 64,
                },
                "state_after_catchup": {
                    "height": 104,
                    "tip_hash": "4" * 64,
                },
                "post_restart_live_action": {
                    "action": "mine_next",
                    "height": 105,
                    "block_hash": "5" * 64,
                    "tx_count": 1,
                },
            }
            errors = _write_and_validate(Path(td), data)
            self.assertEqual(
                errors, [], f"restart with all sub-fields must pass; got {errors}"
            )

    def test_reorg_with_subfields_passes(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["reorg"] = {
                "enabled": True,
                "fork_height": 100,
                "winning_branch_height": 105,
                "loser_branch_height": 103,
            }
            errors = _write_and_validate(Path(td), data)
            self.assertEqual(
                errors, [], f"reorg with all sub-fields must pass; got {errors}"
            )

    def test_restart_disabled_no_subfields_required(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["restart"] = {"enabled": False}
            errors = _write_and_validate(Path(td), data)
            self.assertEqual(
                errors,
                [],
                f"restart.enabled=false should not require sub-fields; got {errors}",
            )

    def test_port_boundary_max_accepted(self):
        """Port 65535 is the inclusive upper bound and must pass."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["rpc"] = "127.0.0.1:65535"
            data["participants"][1]["p2p"] = "127.0.0.1:65535"
            errors = _write_and_validate(Path(td), data)
            self.assertEqual(
                errors, [], f"port 65535 must be accepted; got {errors}"
            )

    def test_port_boundary_min_accepted(self):
        """Port 1 is the inclusive lower bound and must pass."""
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["participants"][0]["rpc"] = "127.0.0.1:1"
            errors = _write_and_validate(Path(td), data)
            self.assertEqual(
                errors, [], f"port 1 must be accepted; got {errors}"
            )


class DeterminismTests(unittest.TestCase):
    def test_deterministic_on_identical_input(self):
        with tempfile.TemporaryDirectory() as td:
            data = _valid_mixed()
            data["metrics"] = {
                "duration_seconds": 0,
                "blocks_observed": 0,
                "txs_observed": 0,
            }
            runs = [
                _write_and_validate(Path(td), copy.deepcopy(data)) for _ in range(3)
            ]
            self.assertEqual(runs[0], runs[1])
            self.assertEqual(runs[1], runs[2])


class CliTests(unittest.TestCase):
    def test_main_zero_on_valid_fixture(self):
        buf_out = io.StringIO()
        with contextlib.redirect_stdout(buf_out):
            rc = validator.main([str(TESTDATA_DIR / "valid_minimal_mixed.json")])
        self.assertEqual(rc, 0)
        self.assertIn("PASS", buf_out.getvalue())

    def test_main_nonzero_on_invalid_fixture(self):
        buf_err = io.StringIO()
        with contextlib.redirect_stderr(buf_err):
            rc = validator.main([str(TESTDATA_DIR / "invalid_helper_only.json")])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", buf_err.getvalue())


if __name__ == "__main__":
    unittest.main()
