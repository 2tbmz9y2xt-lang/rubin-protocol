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

    # Total-orderable sort key: tuple of (type-tag, str-of-element) for
    # each path component. `e.absolute_path` may legitimately mix int
    # (array indices) and str (object keys) depending on which schema
    # the validator runs against; a plain `list(e.absolute_path)` key
    # raises `TypeError: '<' not supported between 'int' and 'str'` when
    # adjacent errors have different element types at the same depth.
    def _path_key(err: object) -> tuple:
        return tuple(
            (type(p).__name__, str(p)) for p in getattr(err, "absolute_path", ())
        )

    errors = sorted(raw_errors, key=_path_key)
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

    # Schema-independent minimal-shape guard. Defensive against
    # permissive alternate `--schema` overrides that could admit input
    # violating the committed shape; without these checks the direct
    # indexing below would raise KeyError/TypeError instead of returning
    # deterministic validation errors. The committed schema enforces
    # all of these via `required` / `type` / `items`; this guard is the
    # minimum needed to keep cross-field code safe under any schema.
    minimal_shape_errors: list[str] = []
    if not isinstance(data.get("participants"), list) or not data.get("participants"):
        minimal_shape_errors.append(
            "<root>: alternate schema admitted; expected non-empty `participants` list"
        )
        return minimal_shape_errors
    participants = data["participants"]
    for i, p in enumerate(participants):
        if not isinstance(p, dict):
            minimal_shape_errors.append(
                f"<root>: participants[{i}] not an object (alternate schema admitted)"
            )
            continue
        if not isinstance(p.get("name"), str):
            minimal_shape_errors.append(
                f"<root>: participants[{i}].name not a string (alternate schema admitted)"
            )
        if not isinstance(p.get("implementation"), str):
            minimal_shape_errors.append(
                f"<root>: participants[{i}].implementation not a string (alternate schema admitted)"
            )
    if minimal_shape_errors:
        return minimal_shape_errors
    # all_participant_names_valid by construction (every p is dict with str name)

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
    # The T13 cross-impl invariant below is gated on `not duplicates` so
    # name->impl-keyed semantics do not chain off the ambiguous
    # last-write-wins `impl_by_name` mapping when names duplicate; the
    # duplicate-names cross-field error above is then authoritative.

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
        # Committed-shape prerequisites for tx_path (same checks the
        # committed schema enforces). Defensive against permissive
        # alternate schemas that admit dict-shaped tx_path missing
        # required keys or with wrong-type values.
        tx_path_shape_errors: list[str] = []
        submitted_at = tx_path.get("submitted_at")
        observed_at = tx_path.get("observed_at")
        tx_id = tx_path.get("tx_id")
        if not isinstance(submitted_at, str):
            tx_path_shape_errors.append(
                "<root>: tx_path.submitted_at not a string (alternate schema admitted)"
            )
        if (
            not isinstance(observed_at, list)
            or not observed_at
            or not all(isinstance(o, str) for o in observed_at)
        ):
            tx_path_shape_errors.append(
                "<root>: tx_path.observed_at not a non-empty list of strings "
                "(alternate schema admitted)"
            )
        if not isinstance(tx_id, str):
            tx_path_shape_errors.append(
                "<root>: tx_path.tx_id not a string (alternate schema admitted)"
            )
        if tx_path_shape_errors:
            errors.extend(tx_path_shape_errors)
            return errors

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
        # is authoritative).
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
    elif (
        # `tx_path is None` (absent) is the only remaining branch: schema
        # validated `tx_path` as `type: object` when present, so the
        # cross-field tx_path-required message only fires for genuinely
        # absent tx_path on a mixed-client PASS soak.
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
    """Return sorted, deduplicated error messages. Empty list = PASS.

    Contract: `result == [] ⇒ data conforms to the committed-shape
    encoded by `mixed_client_evidence_v1.json`. The committed schema is
    ALWAYS enforced as a floor; the user-supplied `--schema` may add
    extra constraints but cannot relax committed ones. This prevents
    silent PASS on permissive alternate schemas.

    On any deterministic input failure (unreadable file, malformed JSON,
    invalid schema object, or any schema-layer rejection of the fixture),
    cross-field validation is NOT run; only the schema-owned errors are
    returned. The CLI never raises a Python exception on bad input.
    """
    try:
        with open(schema_path, encoding="utf-8") as f:
            user_schema = json.load(f)
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

    # Floor: ALWAYS run the committed schema regardless of `schema_path`.
    # If the user supplied `DEFAULT_SCHEMA` (the canonical path), this is
    # a no-op duplicate; if they supplied a permissive alternate schema,
    # this catches every committed-shape violation the alternate schema
    # would have admitted.
    try:
        with open(DEFAULT_SCHEMA, encoding="utf-8") as f:
            committed_schema = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [f"schema: cannot read committed schema {DEFAULT_SCHEMA}: {e}"]

    committed_errors, schema_available = _schema_layer(data, committed_schema)
    if not schema_available:
        return committed_errors  # «jsonschema library unavailable» path
    if committed_errors:
        return sorted(set(committed_errors))

    # User-supplied schema may add extra constraints (e.g., stricter
    # patterns or extra required fields). Run only when distinct from
    # the committed schema to avoid duplicate work.
    try:
        same_schema = (
            schema_path.resolve(strict=False) == DEFAULT_SCHEMA.resolve(strict=False)
        )
    except (OSError, RuntimeError):
        same_schema = False
    if not same_schema:
        user_errors, _ = _schema_layer(data, user_schema)
        if user_errors:
            return sorted(set(user_errors))

    # Both schema layers passed; data is committed-shape by construction
    # (the committed schema enforces `type: object`, root `required`,
    # `properties.*`, `additionalProperties: false`, and every
    # constraint the cross-field code below relies on). `_cross_field`
    # may safely index data["participants"], p["name"], p["implementation"],
    # tx_path["submitted_at"], etc.
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
