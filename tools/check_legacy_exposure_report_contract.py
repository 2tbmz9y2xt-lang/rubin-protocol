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
    for i, c in enumerate(cases):
        if not isinstance(c, dict):
            errors.append(f"cases[{i}]: expected object")
            continue
        for k in required:
            if k not in c:
                errors.append(f"cases[{i}]: missing {k}")
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
    return errors


def main() -> int:
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        print("jsonschema required", file=sys.stderr)
        return 1

    with open(SCHEMA) as f:
        schema = json.load(f)
    with open(EXAMPLE) as f:
        example = json.load(f)

    validator = jsonschema.Draft202012Validator(schema)
    schema_errors = sorted(validator.iter_errors(example), key=lambda e: list(e.path))
    if schema_errors:
        for e in schema_errors:
            path = ".".join(str(p) for p in e.absolute_path)
            print(f"example JSON: {path}: {e.message}", file=sys.stderr)
        return 1

    with open(HOOK_VECTORS) as f:
        hook_doc = json.load(f)
    struct_errors = _validate_hook_vectors_structure(hook_doc, schema)
    if struct_errors:
        for msg in struct_errors:
            print(msg, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
