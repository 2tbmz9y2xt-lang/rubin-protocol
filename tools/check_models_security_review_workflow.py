#!/usr/bin/env python3
"""Fail-closed contract checks for `.github/workflows/models-security-review.yml`.

Catches regressions that tend to produce noisy automated PR review threads:
stale parity paths, unsafe file reads, O(n) membership in hot loops, and
payload budget mistakes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "models-security-review.yml"

PAIR_RE = re.compile(r"\['([^']+)',\s*'([^']+)'\]")

REQUIRED_SUBSTRINGS = [
    "readChangedFile(modRel)",
    "separatorOverhead",
    "introOverhead",
    "shrinkSectionToFit",
    "changedFilesSet",
    "maxUserCharsBeforeNotice",
    "security-review final user message length",
]

BANNED_SUBSTRINGS = [
    "fs.readFileSync(modFile",
    "changedFiles.includes(",
]


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)


def load_yaml_module():
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        return None
    return yaml


def main() -> int:
    if not WORKFLOW.is_file():
        _fail(f"missing workflow file: {WORKFLOW}")
        return 1

    text = WORKFLOW.read_text(encoding="utf-8")
    errors: list[str] = []

    yaml = load_yaml_module()
    if yaml is not None:
        try:
            yaml.safe_load(text)
        except yaml.YAMLError as exc:  # type: ignore[attr-defined]
            errors.append(f"invalid YAML: {exc}")

    for s in REQUIRED_SUBSTRINGS:
        if s not in text:
            errors.append(f"missing required invariant substring {s!r}")
    for s in BANNED_SUBSTRINGS:
        if s in text:
            errors.append(f"banned regression substring present: {s!r}")

    pairs = PAIR_RE.findall(text)
    if len(pairs) < 10:
        errors.append(f"expected parityMap-style pairs, got only {len(pairs)}")

    missing_files: list[str] = []
    for a, b in pairs:
        for p in (a, b):
            fp = REPO_ROOT / p
            if not fp.is_file():
                missing_files.append(p)
    if missing_files:
        preview = ", ".join(missing_files[:25])
        extra = f" (+{len(missing_files) - 25} more)" if len(missing_files) > 25 else ""
        errors.append(f"parityMap references missing files: {preview}{extra}")

    if errors:
        for e in errors:
            _fail(e)
        return 1

    print(f"OK: models-security-review.yml contract ({len(pairs)} parity pairs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
