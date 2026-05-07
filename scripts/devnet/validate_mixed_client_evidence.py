#!/usr/bin/env python3
"""Validate process-level mixed-client devnet soak evidence.

Distinguishes real Go/Rust node-process evidence from helper/interop evidence
and enforces cross-field invariants the JSON Schema cannot express directly.

Used by RUB-25's fail-closed soak gate.

Usage:
    python3 scripts/devnet/validate_mixed_client_evidence.py FIXTURE.json
    python3 scripts/devnet/validate_mixed_client_evidence.py --schema PATH FIXTURE.json

Exits 0 on PASS, 1 on validation failure or unreadable input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SCHEMA = REPO_ROOT / "scripts" / "devnet" / "schema" / "mixed_client_evidence_v1.json"

SCHEMA_VERSION = "rubin-mixed-client-devnet-evidence-v1"
PROCESS_SOAK_TYPES = ("mixed_client_process_soak", "single_client_process_soak")


def _validate_with_jsonschema(data: Any, schema: dict) -> list[str]:
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        return [
            "<root>: jsonschema library unavailable; install jsonschema for full Draft 2020-12 validation"
        ]
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    return [
        f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in errors
    ]


def _validate_cross_field(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["<root>: top-level JSON must be an object"]

    schema_version = data.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        errors.append(
            f"schema_version: must be exactly '{SCHEMA_VERSION}'; got {schema_version!r}"
        )

    evidence_type = data.get("evidence_type")
    verdict = data.get("verdict")

    if evidence_type == "no_data":
        if verdict != "NO_DATA":
            errors.append(
                f"verdict: evidence_type=no_data requires verdict=NO_DATA; got {verdict!r}"
            )
        no_data_reason = data.get("no_data_reason")
        if not isinstance(no_data_reason, str) or not no_data_reason.strip():
            errors.append(
                "no_data_reason: required and must be non-empty when evidence_type=no_data"
            )
        for fld in ("participants", "topology", "tx_path", "metrics", "restart", "reorg"):
            if fld in data:
                errors.append(
                    f"{fld}: must not be present when evidence_type=no_data"
                )
        return errors

    if verdict == "NO_DATA" and evidence_type != "no_data":
        errors.append("verdict: NO_DATA requires evidence_type=no_data")

    if verdict == "FAIL":
        failure_reason = data.get("failure_reason")
        if not isinstance(failure_reason, str) or not failure_reason.strip():
            errors.append(
                "failure_reason: required and must be non-empty when verdict=FAIL"
            )

    participants = data.get("participants")
    has_participants = isinstance(participants, list) and len(participants) > 0
    impls: list[Any] = []
    names: list[Any] = []
    valid_names: list[str] = []
    if has_participants:
        impls = [
            p.get("implementation") for p in participants if isinstance(p, dict)
        ]
        names = [p.get("name") for p in participants if isinstance(p, dict)]
        valid_names = [n for n in names if isinstance(n, str)]

        if evidence_type == "mixed_client_process_soak":
            has_go = any(i == "go" for i in impls)
            has_rust = any(i == "rust" for i in impls)
            if not (has_go and has_rust):
                observed = sorted({i for i in impls if isinstance(i, str)})
                errors.append(
                    "participants: evidence_type=mixed_client_process_soak requires "
                    "at least one implementation=go and one implementation=rust; "
                    f"observed implementations={observed}"
                )
            if len(participants) < 2:
                errors.append(
                    "participants: evidence_type=mixed_client_process_soak "
                    "requires at least 2 participants"
                )
        elif evidence_type == "single_client_process_soak":
            unique_impls = {i for i in impls if isinstance(i, str)}
            if len(unique_impls) > 1:
                errors.append(
                    "participants: evidence_type=single_client_process_soak "
                    f"requires one implementation; observed={sorted(unique_impls)}"
                )

        if len(valid_names) != len(set(valid_names)):
            duplicates = sorted(
                {n for n in valid_names if valid_names.count(n) > 1}
            )
            errors.append(
                f"participants: duplicate names: {duplicates}"
            )
    elif evidence_type in PROCESS_SOAK_TYPES:
        errors.append(
            f"participants: required for evidence_type={evidence_type!r}"
        )

    participant_names = set(valid_names)

    topology = data.get("topology")
    if isinstance(topology, dict):
        edges = topology.get("edges", [])
        if isinstance(edges, list):
            for i, edge in enumerate(edges):
                if isinstance(edge, list) and len(edge) == 2:
                    for endpoint in edge:
                        if (
                            isinstance(endpoint, str)
                            and participant_names
                            and endpoint not in participant_names
                        ):
                            errors.append(
                                f"topology.edges[{i}]: endpoint {endpoint!r} "
                                "not in participants"
                            )
    elif evidence_type in PROCESS_SOAK_TYPES:
        errors.append("topology: required for process_soak evidence")

    tx_path = data.get("tx_path")
    if verdict == "PASS":
        if isinstance(tx_path, dict):
            submitted_at = tx_path.get("submitted_at")
            observed_at = tx_path.get("observed_at")

            if (
                isinstance(submitted_at, str)
                and participant_names
                and submitted_at not in participant_names
            ):
                errors.append(
                    f"tx_path.submitted_at: {submitted_at!r} not in participants"
                )
            if isinstance(observed_at, list):
                for i, observer in enumerate(observed_at):
                    if (
                        isinstance(observer, str)
                        and participant_names
                        and observer not in participant_names
                    ):
                        errors.append(
                            f"tx_path.observed_at[{i}]: {observer!r} "
                            "not in participants"
                        )
                if (
                    evidence_type == "mixed_client_process_soak"
                    and isinstance(submitted_at, str)
                    and observed_at == [submitted_at]
                ):
                    errors.append(
                        "tx_path: mixed_client_process_soak requires at least "
                        "one observer different from submitted_at to prove "
                        "cross-process propagation (ambiguous tx path direction)"
                    )
        elif evidence_type in PROCESS_SOAK_TYPES:
            errors.append("tx_path: required when verdict=PASS")

    restart = data.get("restart")
    if isinstance(restart, dict) and restart.get("enabled") is True:
        for fld in (
            "checkpoint_before_stop",
            "state_after_catchup",
            "post_restart_live_action",
        ):
            if fld not in restart:
                errors.append(
                    f"restart.{fld}: required when restart.enabled=true"
                )

    reorg = data.get("reorg")
    if isinstance(reorg, dict) and reorg.get("enabled") is True:
        for fld in ("fork_height", "winning_branch_height", "loser_branch_height"):
            if fld not in reorg:
                errors.append(
                    f"reorg.{fld}: required when reorg.enabled=true"
                )

    if verdict == "PASS":
        metrics = data.get("metrics")
        if isinstance(metrics, dict):
            keys = ("duration_seconds", "blocks_observed", "txs_observed")
            values = [metrics.get(k) for k in keys]
            if not any(isinstance(v, int) and v > 0 for v in values):
                errors.append(
                    "metrics: at least one of duration_seconds/blocks_observed/"
                    "txs_observed must be > 0 when verdict=PASS "
                    "(timestamp-only evidence is rejected)"
                )
        elif evidence_type in PROCESS_SOAK_TYPES:
            errors.append("metrics: required when verdict=PASS")

    return errors


def validate(fixture_path: Path, schema_path: Path) -> list[str]:
    """Return sorted, deduplicated error messages. Empty list = PASS."""
    try:
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
    except OSError as e:
        return [f"schema: cannot read {schema_path}: {e}"]
    except json.JSONDecodeError as e:
        return [f"schema: malformed JSON in {schema_path}: {e}"]

    try:
        with open(fixture_path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        return [f"fixture: cannot read {fixture_path}: {e}"]
    except json.JSONDecodeError as e:
        return [f"fixture: malformed JSON in {fixture_path}: {e}"]

    errors: list[str] = []
    errors.extend(_validate_with_jsonschema(data, schema))
    errors.extend(_validate_cross_field(data))
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate mixed-client devnet soak evidence JSON."
    )
    parser.add_argument(
        "fixture",
        type=Path,
        help="Path to evidence JSON file to validate.",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA,
        help=(
            f"Path to schema JSON (default: {DEFAULT_SCHEMA.relative_to(REPO_ROOT)})."
        ),
    )
    args = parser.parse_args(argv)

    errors = validate(args.fixture, args.schema)
    if errors:
        print(f"FAIL: {args.fixture}", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"PASS: {args.fixture}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
