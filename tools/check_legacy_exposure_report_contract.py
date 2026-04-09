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


def _validate_hook_vectors_structure(data: object) -> list[str]:
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
    for i, c in enumerate(cases):
        if not isinstance(c, dict):
            errors.append(f"cases[{i}]: expected object")
            continue
        for k in required:
            if k not in c:
                errors.append(f"cases[{i}]: missing {k}")
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
    struct_errors = _validate_hook_vectors_structure(hook_doc)
    if struct_errors:
        for msg in struct_errors:
            print(msg, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
