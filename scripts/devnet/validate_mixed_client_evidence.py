#!/usr/bin/env python3
"""Validate mixed-client devnet process-soak evidence.

Design rule:
  * JSON Schema (Draft 2020-12) owns ALL shape/type/const/minLength/pattern
    validation. The schema layer is the sole authority for «is this value
    well-shaped?» errors.
  * The Python cross-field layer runs ONLY when schema validation passes.
    It enforces invariants jsonschema cannot express: participant-name
    uniqueness, tx_path participant references, the cross-implementation
    tx_path invariant, and the conditional «mixed PASS ⇒ tx_path
    required» rule.
  * On any malformed schema input (unreadable schema file, invalid JSON,
    invalid Draft 2020-12 schema object), the CLI returns a deterministic
    `schema: ...` error and exits 1 — never raises a traceback.

Used as the offline gate for `mixed_client_process_soak` PASS evidence.

Usage:
    python3 scripts/devnet/validate_mixed_client_evidence.py FIXTURE.json
    python3 scripts/devnet/validate_mixed_client_evidence.py --schema PATH FIXTURE.json

Exits 0 on PASS, 1 on validation failure or unreadable input.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SCHEMA = REPO_ROOT / "scripts" / "devnet" / "schema" / "mixed_client_evidence_v1.json"

SCHEMA_VERSION = "rubin-mixed-client-devnet-evidence-v1"


def _schema_layer(data: Any, schema: dict) -> tuple[list[str], bool]:
    """Run jsonschema Draft 2020-12 validation against `data`.

    Returns (errors, schema_available). `schema_available=False` means
    `jsonschema` is not importable; the caller treats that as a fatal
    deterministic error and skips cross-field validation.
    """
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        return (
            [
                "<root>: jsonschema library unavailable; install jsonschema "
                "for full Draft 2020-12 validation"
            ],
            False,
        )

    # Construct the validator and explicitly check the schema object so a
    # malformed Draft 2020-12 schema produces a deterministic
    # `schema: invalid schema: ...` error rather than a traceback.
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
    except jsonschema.exceptions.SchemaError as e:
        return ([f"schema: invalid schema: {e.message}"], True)
    except Exception as e:  # defensive: any other validator-init failure
        return (
            [f"schema: validator construction failed: {type(e).__name__}: {e}"],
            True,
        )

    try:
        raw_errors = list(validator.iter_errors(data))
    except Exception as e:  # defensive: jsonschema runtime exceptions
        return (
            [f"schema: validation runtime failed: {type(e).__name__}: {e}"],
            True,
        )

    errors = sorted(raw_errors, key=lambda e: list(e.absolute_path))
    return (
        [
            f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in errors
        ],
        True,
    )


def _cross_field(data: dict) -> list[str]:
    """Cross-field invariants. Caller MUST run this only after the schema
    layer reports zero errors — otherwise schema-owned shape problems
    would be re-asserted here as semantic «name lookup failed» messages.

    Invariants (each one not expressible as a JSON Schema constraint):

      * participants must have unique names (schema lacks per-property
        uniqueItems).
      * tx_path.submitted_at must reference a declared participant.
      * tx_path.observed_at[i] must each reference a declared participant.
      * mixed_client_process_soak with verdict=PASS requires tx_path
        (and at least one observer whose implementation differs from the
        submitter's — the T13 cross-implementation invariant).
      * mixed_client_process_soak requires both `go` and `rust` impls.
    """
    errors: list[str] = []
    evidence_type = data.get("evidence_type")
    verdict = data.get("verdict")
    participants = data["participants"]

    impls = {p["implementation"] for p in participants}
    names_list = [p["name"] for p in participants]
    impl_by_name: dict[str, str] = {p["name"]: p["implementation"] for p in participants}
    valid_names = set(impl_by_name)

    # Mixed-client must have at least one go AND one rust participant.
    if evidence_type == "mixed_client_process_soak":
        if not ({"go", "rust"} <= impls):
            errors.append(
                "participants: evidence_type=mixed_client_process_soak requires "
                "at least one implementation=go and one implementation=rust; "
                f"observed implementations={sorted(impls)}"
            )
        if len(participants) < 2:
            errors.append(
                "participants: evidence_type=mixed_client_process_soak "
                "requires at least 2 participants"
            )

    # Participant-name uniqueness.
    duplicates = sorted(
        n for n, c in collections.Counter(names_list).items() if c > 1
    )
    if duplicates:
        errors.append(f"participants: duplicate names: {duplicates}")

    # verdict=FAIL conditional requirement (schema makes failure_reason
    # optional and `minLength: 1` rejects empty strings; cross-field is
    # the authoritative source for the «verdict=FAIL ⇒ failure_reason
    # must be present» rule).
    if verdict == "FAIL" and "failure_reason" not in data:
        errors.append(
            "failure_reason: required when verdict=FAIL"
        )

    tx_path = data.get("tx_path")
    if isinstance(tx_path, dict):
        submitted_at = tx_path["submitted_at"]
        observed_at = tx_path["observed_at"]

        if submitted_at not in valid_names:
            errors.append(
                f"tx_path.submitted_at: {submitted_at!r} not in participants"
            )
        for i, observer in enumerate(observed_at):
            if observer not in valid_names:
                errors.append(
                    f"tx_path.observed_at[{i}]: {observer!r} not in participants"
                )

        # T13 cross-implementation invariant: mixed_client_process_soak
        # PASS evidence must show an observer whose implementation
        # differs from the submitter's; otherwise it is not mixed-client
        # propagation proof. Skipped when names are duplicated (the
        # name -> impl mapping is ambiguous and the duplicate-names
        # error above is authoritative) or when any observer name is
        # unknown (the per-observer "not in participants" error above
        # is authoritative; chaining the cross-impl algorithm off an
        # unknown name would KeyError on impl_by_name lookup).
        if (
            evidence_type == "mixed_client_process_soak"
            and verdict == "PASS"
            and not duplicates
            and submitted_at in impl_by_name
            and all(o in impl_by_name for o in observed_at)
        ):
            submitter_impl = impl_by_name[submitted_at]
            observer_pairs = sorted(
                {(o, impl_by_name[o]) for o in observed_at}
            )
            if not any(impl != submitter_impl for _, impl in observer_pairs):
                errors.append(
                    "tx_path: mixed_client_process_soak with verdict=PASS "
                    "requires observer implementation to differ from submitter "
                    "implementation; submitter "
                    f"{submitted_at!r}/{submitter_impl}, observers="
                    f"{[f'{n}/{i}' for n, i in observer_pairs]}"
                )
    elif evidence_type == "mixed_client_process_soak" and verdict == "PASS":
        errors.append(
            "tx_path: required for evidence_type=mixed_client_process_soak "
            "with verdict=PASS"
        )

    return errors


def validate(fixture_path: Path, schema_path: Path) -> list[str]:
    """Return sorted, deduplicated error messages. Empty list = PASS.

    On any deterministic input failure (unreadable file, malformed JSON,
    invalid schema object, or schema-layer rejection of the fixture),
    cross-field validation is NOT run; only the schema-owned errors are
    returned.
    """
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

    schema_errors, schema_available = _schema_layer(data, schema)
    if schema_errors:
        return sorted(set(schema_errors))

    # Schema PASS → run cross-field invariants. (When jsonschema is
    # unavailable, `schema_errors` already contains the «library
    # unavailable» message and we never reach this branch.)
    if not schema_available:
        return sorted(set(schema_errors))

    if not isinstance(data, dict):
        # Defensive: schema's `type: object` would have already rejected
        # non-dict input above, but the cross-field code below
        # dereferences `data` as a dict.
        return []

    return sorted(set(_cross_field(data)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate mixed-client devnet evidence JSON."
    )
    parser.add_argument(
        "fixture", type=Path, help="Path to evidence JSON file to validate."
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
