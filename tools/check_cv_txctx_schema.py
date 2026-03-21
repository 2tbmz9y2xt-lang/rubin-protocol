#!/usr/bin/env python3
"""Validate CV-TXCTX.json against its JSON Schema.

Usage:
    python3 tools/check_cv_txctx_schema.py [--fixtures PATH] [--schema PATH]

Exits 0 on success, 1 on validation failure.
"""
import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = REPO_ROOT / "conformance" / "fixtures" / "CV-TXCTX.json"
DEFAULT_SCHEMA = REPO_ROOT / "conformance" / "schemas" / "cv-txctx-v1.json"


def validate(fixture_path: Path, schema_path: Path) -> list[str]:
    """Return list of error messages. Empty = valid."""
    # Always run structural invariants (duplicate IDs, vector_count consistency)
    structural_errors = validate_structural_invariants(fixture_path)

    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        # Fallback: structural checks without jsonschema library
        return structural_errors + validate_structural(fixture_path, schema_path)

    with open(schema_path) as f:
        schema = json.load(f)
    with open(fixture_path) as f:
        data = json.load(f)

    validator = jsonschema.Draft202012Validator(schema)
    schema_errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    return [f"{'.'.join(str(p) for p in e.absolute_path)}: {e.message}" for e in schema_errors] + structural_errors


def validate_structural_invariants(fixture_path: Path) -> list[str]:
    """Invariants that JSON Schema cannot express: duplicate IDs, count consistency."""
    errors: list[str] = []
    with open(fixture_path) as f:
        data = json.load(f)

    vectors = data.get("vectors")
    if not isinstance(vectors, list):
        errors.append("vectors must be an array")
        return errors

    ids_seen: set[str] = set()
    for i, vec in enumerate(vectors):
        if not isinstance(vec, dict):
            errors.append(f"vectors[{i}]: expected object, got {type(vec).__name__}")
            continue
        vid = vec.get("id")
        if isinstance(vid, str):
            if vid in ids_seen:
                errors.append(f"vectors[{i}]: duplicate id '{vid}'")
            ids_seen.add(vid)

    vc = data.get("vector_count")
    if isinstance(vc, int) and vc != len(vectors):
        errors.append(
            f"vector_count={vc} does not match actual vector count={len(vectors)}"
        )

    return errors


def validate_structural(fixture_path: Path, schema_path: Path) -> list[str]:
    """Validate without jsonschema library — checks required fields and types."""
    errors: list[str] = []

    with open(fixture_path) as f:
        data = json.load(f)

    # Top-level required fields
    for key in ("gate", "spec", "version", "profiles", "vectors", "vector_count"):
        if key not in data:
            errors.append(f"missing required top-level key: {key}")

    if data.get("gate") != "CV-TXCTX":
        errors.append(f"gate must be 'CV-TXCTX', got '{data.get('gate')}'")

    if not isinstance(data.get("profiles"), dict):
        errors.append("profiles must be an object")
    else:
        for name, profile in data["profiles"].items():
            for req in ("ext_id", "suite_id", "txcontext_enabled",
                        "max_ext_payload_bytes", "activation_height"):
                if req not in profile:
                    errors.append(f"profiles.{name}: missing required key '{req}'")

    if not isinstance(data.get("vectors"), list):
        errors.append("vectors must be an array")
    else:
        ids_seen: set[str] = set()
        for i, vec in enumerate(data["vectors"]):
            vid = vec.get("id", f"<index {i}>")

            if "id" not in vec:
                errors.append(f"vectors[{i}]: missing required key 'id'")
            elif not isinstance(vec["id"], str):
                errors.append(f"vectors[{i}]: 'id' must be a string")
            else:
                if vec["id"] in ids_seen:
                    errors.append(f"vectors[{i}]: duplicate id '{vec['id']}'")
                ids_seen.add(vec["id"])

            if "description" not in vec:
                errors.append(f"vectors[{i}] ({vid}): missing required key 'description'")

        # vector_count consistency
        vc = data.get("vector_count")
        if isinstance(vc, int) and vc != len(data["vectors"]):
            errors.append(
                f"vector_count={vc} does not match actual vector count={len(data['vectors'])}"
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate CV-TXCTX.json schema")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    args = parser.parse_args()

    if not args.fixtures.exists():
        print(f"FAIL: fixture file not found: {args.fixtures}", file=sys.stderr)
        return 1
    if not args.schema.exists():
        print(f"FAIL: schema file not found: {args.schema}", file=sys.stderr)
        return 1

    errors = validate(args.fixtures, args.schema)
    if errors:
        print(f"FAIL: {len(errors)} schema validation error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print("PASS: CV-TXCTX.json schema validation OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
