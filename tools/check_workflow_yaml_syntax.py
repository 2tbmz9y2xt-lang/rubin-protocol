#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

MAX_WORKFLOW_YAML_BYTES = 2 * 1024 * 1024


def load_yaml_module():
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        return None
    return yaml


def validate_paths(paths: list[Path]) -> tuple[bool, str]:
    for path in paths:
        if not path.is_file():
            return False, f"missing workflow file: {path}"
        if path.stat().st_size > MAX_WORKFLOW_YAML_BYTES:
            return False, (
                f"workflow yaml too large: {path} exceeds "
                f"{MAX_WORKFLOW_YAML_BYTES} bytes"
            )

    yaml = load_yaml_module()
    if yaml is None:
        return True, "SKIP: PyYAML unavailable; workflow YAML syntax remains a server-side actionlint truth"

    for path in paths:
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            return False, f"invalid workflow yaml encoding in {path}: {exc}"
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as exc:  # type: ignore[attr-defined]
            return False, f"invalid workflow yaml in {path}: {exc}"
    return True, f"OK: parsed {len(paths)} workflow file(s)"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate workflow YAML locally when PyYAML is available.")
    parser.add_argument("paths", nargs="+", help="Workflow YAML file paths")
    args = parser.parse_args(argv[1:])

    ok, message = validate_paths([Path(item) for item in args.paths])
    stream = sys.stdout if ok else sys.stderr
    print(message, file=stream)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
