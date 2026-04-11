#!/usr/bin/env python3
"""Fail-closed contract checks for security review workflows.

Checks the shared reusable workflow for regressions: stale parity paths,
unsafe file reads, O(n) membership in hot loops, and payload budget mistakes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SHARED_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security-review-shared.yml"
DEEPSEEK_CALLER = REPO_ROOT / ".github" / "workflows" / "models-security-review.yml"
QWEN_CALLER = REPO_ROOT / ".github" / "workflows" / "qwen-security-review.yml"

PAIR_RE = re.compile(r"\['([^']+)',\s*'([^']+)'\]")

REQUIRED_SUBSTRINGS = [
    "readChangedFile(modRel)",
    "separatorOverhead",
    "introOverhead",
    "changedFilesSet",
    "slice(0,",  # payload cap
    "getSevIdx",  # severity normalization
    "normSev",    # severity normalization
]

BANNED_SUBSTRINGS = [
    "fs.readFileSync(modFile",
    "changedFiles.includes(",
    "sevOrder.indexOf(a.severity)",  # raw indexOf without normalization
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
    errors: list[str] = []

    # Check shared workflow exists
    if not SHARED_WORKFLOW.is_file():
        _fail(f"missing shared workflow: {SHARED_WORKFLOW}")
        return 1

    # Check callers exist
    for caller in [DEEPSEEK_CALLER, QWEN_CALLER]:
        if not caller.is_file():
            errors.append(f"missing caller workflow: {caller}")

    text = SHARED_WORKFLOW.read_text(encoding="utf-8")

    yaml = load_yaml_module()
    if yaml is not None:
        try:
            yaml.safe_load(text)
        except yaml.YAMLError as exc:
            errors.append(f"invalid YAML in shared workflow: {exc}")

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

    print(f"OK: security-review-shared.yml contract ({len(pairs)} parity pairs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
