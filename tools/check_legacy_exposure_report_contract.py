#!/usr/bin/env python3
"""Validate legacy exposure report v1 example + hook vectors fixtures.

Exits 0 on success, 1 on validation failure.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = REPO_ROOT / "conformance" / "schemas" / "legacy_exposure_report_v1.json"
EXAMPLE = REPO_ROOT / "conformance" / "fixtures" / "protocol" / "legacy_exposure_report_v1_example.json"
HOOK_VECTORS = REPO_ROOT / "conformance" / "fixtures" / "protocol" / "legacy_exposure_hook_vectors.json"

CANONICAL_HOOK_CASES: list[tuple[str, bool, int, str, str, str]] = [
    (
        "no_chainstate_tip_zero_total",
        False,
        0,
        "invalid_no_chainstate_tip",
        "none",
        "not_applicable_no_chainstate_tip",
    ),
    (
        "no_chainstate_tip_nonzero_total",
        False,
        5,
        "invalid_no_chainstate_tip",
        "none",
        "not_applicable_no_chainstate_tip",
    ),
    (
        "tipped_chain_zero_exposure",
        True,
        0,
        "ready_for_operator_defined_grace_window",
        "none",
        "start_operator_defined_grace_window",
    ),
    (
        "tipped_chain_nonzero_exposure",
        True,
        3,
        "not_ready_legacy_exposure_present",
        "legacy_exposure_present_notify_operator_and_council",
        "not_applicable_legacy_exposure_present",
    ),
]


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)


def _schema_enum_strings(schema: dict, property_name: str) -> frozenset[str] | None:
    props = schema.get("properties")
    if not isinstance(props, dict):
        return None
    prop = props.get(property_name)
    if not isinstance(prop, dict):
        return None
    raw = prop.get("enum")
    if not isinstance(raw, list):
        return None
    out: list[str] = []
    for x in raw:
        if isinstance(x, str):
            out.append(x)
    return frozenset(out)


def _validate_hook_vectors_structure(
    data: object, schema: dict
) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["hook vectors: top-level must be an object"]
    if data.get("contract_version") != 1:
        errors.append("hook vectors: contract_version must be 1")
    if data.get("fixture_kind") != "legacy_exposure_hook_vectors":
        errors.append("hook vectors: fixture_kind mismatch")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("hook vectors: cases must be a non-empty array")
        return errors
    required = (
        "name",
        "has_chainstate_tip",
        "legacy_exposure_total",
        "sunset_readiness",
        "warning_hook",
        "grace_hook",
    )
    sr_enum = _schema_enum_strings(schema, "sunset_readiness")
    wh_enum = _schema_enum_strings(schema, "warning_hook")
    gh_enum = _schema_enum_strings(schema, "grace_hook")
    if sr_enum is None or wh_enum is None or gh_enum is None:
        errors.append("hook vectors: schema missing enum lists for hook fields")
        return errors
    normalized_cases: list[tuple[str, bool, int, str, str, str]] = []
    for i, c in enumerate(cases):
        if not isinstance(c, dict):
            errors.append(f"cases[{i}]: expected object")
            continue
        for k in required:
            if k not in c:
                errors.append(f"cases[{i}]: missing {k}")
        if "name" in c and not isinstance(c.get("name"), str):
            errors.append(f"cases[{i}]: name must be a string")
        if "has_chainstate_tip" in c and not isinstance(c.get("has_chainstate_tip"), bool):
            errors.append(f"cases[{i}]: has_chainstate_tip must be a boolean")
        if "legacy_exposure_total" in c:
            t = c.get("legacy_exposure_total")
            if not isinstance(t, int) or isinstance(t, bool):
                errors.append(f"cases[{i}]: legacy_exposure_total must be an integer")
            elif t < 0:
                errors.append(f"cases[{i}]: legacy_exposure_total must be >= 0")
        for k, allowed, label in (
            ("sunset_readiness", sr_enum, "sunset_readiness"),
            ("warning_hook", wh_enum, "warning_hook"),
            ("grace_hook", gh_enum, "grace_hook"),
        ):
            if k not in c:
                continue
            val = c.get(k)
            if not isinstance(val, str):
                errors.append(f"cases[{i}]: {label} must be a string")
                continue
            if val not in allowed:
                errors.append(
                    f"cases[{i}]: {label}={val!r} not in schema enum for {label}"
                )
        if all(k in c for k in required):
            normalized_cases.append(
                (
                    c["name"],
                    c["has_chainstate_tip"],
                    c["legacy_exposure_total"],
                    c["sunset_readiness"],
                    c["warning_hook"],
                    c["grace_hook"],
                )
            )
    if errors:
        return errors
    if normalized_cases != CANONICAL_HOOK_CASES:
        errors.append(
            f"hook vectors: cases drifted from frozen canonical truth table: {normalized_cases!r}"
        )
    return errors


def _legacy_exposure_hooks(has_tip: bool, total: int) -> tuple[str, str, str]:
    if not has_tip:
        return (
            "invalid_no_chainstate_tip",
            "none",
            "not_applicable_no_chainstate_tip",
        )
    if total == 0:
        return (
            "ready_for_operator_defined_grace_window",
            "none",
            "start_operator_defined_grace_window",
        )
    return (
        "not_ready_legacy_exposure_present",
        "legacy_exposure_present_notify_operator_and_council",
        "not_applicable_legacy_exposure_present",
    )


def _validate_example_semantics(example: object) -> list[str]:
    if not isinstance(example, dict):
        return ["example fixture: top-level must be an object"]
    errors: list[str] = []
    if example.get("chainstate_has_tip") is not True:
        errors.append("example fixture: chainstate_has_tip must be true for emitted scanner JSON")
    watched = example.get("watched_legacy_suite_ids")
    if not isinstance(watched, list) or not all(isinstance(x, int) for x in watched):
        return errors + ["example fixture: watched_legacy_suite_ids must be an integer array"]
    reports = example.get("legacy_suite_reports")
    if not isinstance(reports, list) or not all(isinstance(x, dict) for x in reports):
        return errors + ["example fixture: legacy_suite_reports must be an array of objects"]
    if len(reports) != len(watched):
        errors.append(
            "example fixture: legacy_suite_reports must contain exactly one row per watched_legacy_suite_id"
        )
    report_suite_ids: list[int] = []
    total = 0
    include_outpoints = example.get("include_outpoints")
    for idx, report in enumerate(reports):
        suite_id = report.get("suite_id")
        utxo_exposure_count = report.get("utxo_exposure_count")
        outpoint_count = report.get("outpoint_count")
        if not isinstance(suite_id, int):
            errors.append(f"example fixture: legacy_suite_reports[{idx}].suite_id must be an integer")
            continue
        report_suite_ids.append(suite_id)
        if not isinstance(utxo_exposure_count, int):
            errors.append(
                f"example fixture: legacy_suite_reports[{idx}].utxo_exposure_count must be an integer"
            )
            continue
        if not isinstance(outpoint_count, int):
            errors.append(
                f"example fixture: legacy_suite_reports[{idx}].outpoint_count must be an integer"
            )
            continue
        if outpoint_count != utxo_exposure_count:
            errors.append(
                f"example fixture: legacy_suite_reports[{idx}] outpoint_count must equal utxo_exposure_count"
            )
        total += utxo_exposure_count
        outpoints = report.get("outpoints")
        if include_outpoints is True:
            if not isinstance(outpoints, list):
                errors.append(
                    f"example fixture: legacy_suite_reports[{idx}].outpoints must be present when include_outpoints=true"
                )
            elif len(outpoints) != outpoint_count:
                errors.append(
                    f"example fixture: legacy_suite_reports[{idx}] outpoints length must equal outpoint_count"
                )
        elif "outpoints" in report:
            errors.append(
                f"example fixture: legacy_suite_reports[{idx}].outpoints must be absent when include_outpoints=false"
            )
    if report_suite_ids != watched:
        errors.append(
            f"example fixture: legacy_suite_reports suite_id order {report_suite_ids!r} must match watched_legacy_suite_ids {watched!r}"
        )
    legacy_exposure_total = example.get("legacy_exposure_total")
    if not isinstance(legacy_exposure_total, int):
        errors.append("example fixture: legacy_exposure_total must be an integer")
        return errors
    if legacy_exposure_total != total:
        errors.append(
            f"example fixture: legacy_exposure_total={legacy_exposure_total} must equal summed utxo_exposure_count={total}"
        )
    expected_hooks = _legacy_exposure_hooks(True, legacy_exposure_total)
    for field, expected in (
        ("sunset_readiness", expected_hooks[0]),
        ("warning_hook", expected_hooks[1]),
        ("grace_hook", expected_hooks[2]),
    ):
        if example.get(field) != expected:
            errors.append(
                f"example fixture: {field}={example.get(field)!r} must equal canonical hook output {expected!r}"
            )
    return errors


def main() -> int:
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        _fail("jsonschema required (pip install jsonschema)")
        return 1

    for label, path in (
        ("schema", SCHEMA),
        ("example fixture", EXAMPLE),
        ("hook vectors fixture", HOOK_VECTORS),
    ):
        if not path.is_file():
            _fail(f"missing {label}: {path}")
            return 1

    try:
        with open(SCHEMA) as f:
            schema = json.load(f)
    except OSError as e:
        _fail(f"cannot read schema {SCHEMA}: {e}")
        return 1
    except json.JSONDecodeError as e:
        _fail(f"invalid JSON in schema {SCHEMA}: {e}")
        return 1

    try:
        with open(EXAMPLE) as f:
            example = json.load(f)
    except OSError as e:
        _fail(f"cannot read example {EXAMPLE}: {e}")
        return 1
    except json.JSONDecodeError as e:
        _fail(f"invalid JSON in example {EXAMPLE}: {e}")
        return 1

    validator = jsonschema.Draft202012Validator(schema)
    schema_errors = sorted(validator.iter_errors(example), key=lambda e: list(e.path))
    if schema_errors:
        for e in schema_errors:
            path = ".".join(str(p) for p in e.absolute_path)
            print(f"FAIL: example JSON at {path}: {e.message}", file=sys.stderr)
        return 1
    example_errors = _validate_example_semantics(example)
    if example_errors:
        for msg in example_errors:
            _fail(msg)
        return 1

    try:
        with open(HOOK_VECTORS) as f:
            hook_doc = json.load(f)
    except OSError as e:
        _fail(f"cannot read hook vectors {HOOK_VECTORS}: {e}")
        return 1
    except json.JSONDecodeError as e:
        _fail(f"invalid JSON in hook vectors {HOOK_VECTORS}: {e}")
        return 1

    struct_errors = _validate_hook_vectors_structure(hook_doc, schema)
    if struct_errors:
        for msg in struct_errors:
            _fail(msg)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
