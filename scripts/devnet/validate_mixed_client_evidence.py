#!/usr/bin/env python3
"""Validate mixed-client devnet process-soak evidence — base slice (PR-A).

Enforces the minimum invariants needed to prove cross-implementation tx
propagation between Go and Rust nodes:

* JSON Schema Draft 2020-12 shape (top-level fields, participant shape, tx_path
  shape) via the committed schema.
* Cross-field invariants the schema cannot express on its own:
    - mixed_client_process_soak requires both go and rust participants;
    - single_client_process_soak requires one implementation;
    - verdict=FAIL requires non-empty failure_reason;
    - tx_path.submitted_at and observed_at must reference declared participants;
    - mixed_client_process_soak with verdict=PASS must include at least one
      observer whose implementation differs from the submitter's; same-impl
      propagation in a mixed participant set is NOT mixed-client proof.

Restart / reorg cross-field invariants, timestamp / endpoint textual policy,
and the helper-vs-real-process distinction are deferred to follow-up slices.

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
PROCESS_SOAK_TYPES = ("mixed_client_process_soak", "single_client_process_soak")


def _validate_with_jsonschema(data: Any, schema: dict) -> list[str]:
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        return [
            "<root>: jsonschema library unavailable; install jsonschema for full Draft 2020-12 validation"
        ]
    validator = jsonschema.Draft202012Validator(schema)
    # Iteration order is left to `validate`, which deduplicates and
    # lexicographically re-sorts the merged error stream via
    # `sorted(set(...))`; an inner sort here would be discarded.
    return [
        f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in validator.iter_errors(data)
    ]


def _validate_cross_field(data: Any) -> list[str]:
    """Cross-field invariants jsonschema cannot express.

    Class-closure invariant: every cross-field check below MUST gate on
    the input being schema-valid for the field it inspects, so the
    cross-field message does not duplicate or contradict the schema
    layer's authoritative type/const/required error on the same case.

    Per-site decisions:

      S1  top-level non-object             AUTHORITATIVE (jsonschema-absent path)
      S2  schema_version mismatch          GATED on isinstance(str)
                                              (schema `const` handles None/wrong-type)
      S3  verdict=FAIL ⇒ failure_reason    GATED on (None or empty str)
                                              (schema `type` handles wrong-type)
      S4  participants required             REMOVED (schema `required` + `minItems`
                                              already authoritative)
      S5  mixed_client go+rust              GATED on any valid string impl
                                              (schema per-participant required
                                               handles all-missing)
      S6  single_client one impl            implicit gate (needs ≥2 string impls)
      S7  duplicate participant names       AUTHORITATIVE (schema lacks uniqueItems
                                              over `name`)
      S8  tx_path.submitted_at not in set   gates on isinstance(str)
      S9  tx_path.observed_at[i] not in set gates on isinstance(str)
      S10 cross-impl observer differ        GATED on every observer impl known
                                              (wave-3)
      S11 mixed PASS ⇒ tx_path required     GATED on `tx_path is None`
                                              (schema `type` handles wrong-type)
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["<root>: top-level JSON must be an object"]

    # S2: only emit cross-field "expected vs got" wording when schema_version
    # is a string but wrong value; missing or wrong-type cases are reported
    # authoritatively by the schema's `const` constraint, and emitting a
    # second cross-field message would duplicate.
    schema_version = data.get("schema_version")
    if isinstance(schema_version, str) and schema_version != SCHEMA_VERSION:
        errors.append(
            f"schema_version: must be exactly '{SCHEMA_VERSION}'; got {schema_version!r}"
        )

    evidence_type = data.get("evidence_type")
    verdict = data.get("verdict")

    # S3: cross-field is the authoritative source for the conditional
    # requirement (verdict=FAIL ⇒ failure_reason non-empty); only emit
    # when the field is missing or an empty string. Wrong-type values are
    # reported authoritatively by the schema's `type: string` constraint.
    if verdict == "FAIL":
        reason = data.get("failure_reason")
        if reason is None or (isinstance(reason, str) and not reason.strip()):
            errors.append(
                "failure_reason: required and must be non-empty when verdict=FAIL"
            )

    # S4: when participants is missing/wrong-type/empty the schema layer
    # reports `required` / `type` / `minItems` authoritatively; the early
    # return below is a guard against None-deref in downstream cross-field
    # code, not a duplicate message source.
    participants = data.get("participants")
    if not isinstance(participants, list) or not participants:
        return errors

    impls = [p.get("implementation") for p in participants if isinstance(p, dict)]
    names_list = [
        p.get("name")
        for p in participants
        if isinstance(p, dict) and isinstance(p.get("name"), str)
    ]
    # Restrict impl_by_name to fully-typed (str, str) entries so the dict's
    # declared type holds at runtime — None implementations are filtered out
    # here and re-surfaced via the schema-level "implementation: required" error
    # rather than leaking through the cross-impl branch.
    impl_by_name: dict[str, str] = {
        p["name"]: p["implementation"]
        for p in participants
        if isinstance(p, dict)
        and isinstance(p.get("name"), str)
        and isinstance(p.get("implementation"), str)
    }
    valid_names = {
        p.get("name")
        for p in participants
        if isinstance(p, dict) and isinstance(p.get("name"), str)
    }

    if evidence_type == "mixed_client_process_soak":
        # S5: only emit the "go AND rust required" cross-impl message when
        # at least one participant has a known string `implementation`. If
        # every participant is schema-invalid (missing impl or wrong type),
        # the per-participant `participants[i].implementation: required`
        # errors from the schema layer are authoritative; emitting a
        # cross-field "observed implementations=[]" message on top would
        # duplicate.
        valid_impls = [i for i in impls if isinstance(i, str)]
        if valid_impls and not (
            any(i == "go" for i in valid_impls)
            and any(i == "rust" for i in valid_impls)
        ):
            observed = sorted(set(valid_impls))
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
        unique = {i for i in impls if isinstance(i, str)}
        if len(unique) > 1:
            errors.append(
                "participants: evidence_type=single_client_process_soak "
                f"requires one implementation; observed={sorted(unique)}"
            )

    name_counts = collections.Counter(names_list)
    duplicates = sorted(n for n, c in name_counts.items() if c > 1)
    if duplicates:
        errors.append(f"participants: duplicate names: {duplicates}")

    tx_path = data.get("tx_path")
    if isinstance(tx_path, dict):
        submitted_at = tx_path.get("submitted_at")
        observed_at = tx_path.get("observed_at")

        if isinstance(submitted_at, str) and submitted_at not in valid_names:
            errors.append(
                f"tx_path.submitted_at: {submitted_at!r} not in participants"
            )

        if isinstance(observed_at, list):
            for i, observer in enumerate(observed_at):
                if isinstance(observer, str) and observer not in valid_names:
                    errors.append(
                        f"tx_path.observed_at[{i}]: {observer!r} not in participants"
                    )

        # Cross-impl tx_path invariant only fires when every participant on
        # the tx_path has a known string implementation. If the submitter or
        # any string observer is missing impl, the schema layer already emits
        # `participants[i].implementation` as the real problem; running the
        # cross-impl check on a partial dataset would emit a duplicative and
        # misleading "submitter/observer differ" error on top of it.
        string_observers = (
            [o for o in observed_at if isinstance(o, str)]
            if isinstance(observed_at, list)
            else []
        )
        if (
            evidence_type == "mixed_client_process_soak"
            and verdict == "PASS"
            and isinstance(submitted_at, str)
            and submitted_at in impl_by_name
            and string_observers
            and all(o in impl_by_name for o in string_observers)
        ):
            submitter_impl = impl_by_name[submitted_at]
            observer_pairs = sorted(
                {(o, impl_by_name[o]) for o in string_observers}
            )
            observer_impls = {impl for _, impl in observer_pairs}
            if not any(impl != submitter_impl for impl in observer_impls):
                errors.append(
                    "tx_path: mixed_client_process_soak with verdict=PASS "
                    "requires observer implementation to differ from submitter "
                    "implementation; submitter "
                    f"{submitted_at!r}/{submitter_impl}, observers="
                    f"{[f'{n}/{i}' for n, i in observer_pairs]}"
                )
    elif (
        # Only emit the cross-field tx_path-required message when the
        # field is genuinely absent or null. A wrong-type tx_path (list,
        # string, etc.) is reported authoritatively by the schema layer
        # as a type error; emitting a cross-field required-message on top
        # would be misleading (S11 in the verdict table above).
        tx_path is None
        and evidence_type == "mixed_client_process_soak"
        and verdict == "PASS"
    ):
        errors.append(
            "tx_path: required for evidence_type=mixed_client_process_soak "
            "with verdict=PASS"
        )

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
        description="Validate mixed-client devnet evidence JSON (base slice)."
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
