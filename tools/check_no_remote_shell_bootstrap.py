#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REMOTE_SHELL_PATTERNS = (
    ("remote shell pipe", re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:env\s+)?(?:bash|sh)\b", re.IGNORECASE)),
    (
        "remote shell process substitution",
        re.compile(r"(?:^|[^\w])(?:bash|sh|source|\.)\s*<\(\s*(?:curl|wget)\b", re.IGNORECASE),
    ),
    (
        "remote shell eval command substitution",
        re.compile(r"\beval\b\s+[\"']?\$\(\s*(?:curl|wget)\b", re.IGNORECASE),
    ),
)


def workflow_paths(repo_root: Path) -> list[Path]:
    workflow_dir = repo_root / ".github" / "workflows"
    return sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))


def command_windows(lines: list[str], start: int) -> list[tuple[int, str]]:
    windows: list[tuple[int, str]] = []
    parts: list[str] = []
    for idx in range(start, min(len(lines), start + 4)):
        stripped = lines[idx].strip()
        if not stripped or stripped.startswith("#"):
            if parts:
                break
            continue
        parts.append(stripped.rstrip("\\").strip())
        windows.append((idx, " ".join(parts)))
    return windows


def find_violations(path: Path) -> list[str]:
    violations: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = 0
    while line_no < len(lines):
        matched_end: int | None = None
        for end_idx, window in command_windows(lines, line_no):
            for label, pattern in REMOTE_SHELL_PATTERNS:
                if pattern.search(window):
                    violations.append(f"{path}:{line_no + 1}: {label}: {window}")
                    matched_end = end_idx
                    break
            else:
                continue
            break
        if matched_end is not None:
            line_no = matched_end + 1
            continue
        line_no += 1
    return violations


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Reject remote shell bootstrap patterns in workflow YAML.")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root containing .github/workflows",
    )
    args = parser.parse_args(argv[1:])

    repo_root = args.repo_root.resolve()
    bad: list[str] = []
    for workflow in workflow_paths(repo_root):
        bad.extend(find_violations(workflow))

    if bad:
        print("ERROR: remote shell bootstrap is not allowed in workflow surface:", file=sys.stderr)
        for item in bad:
            print(f" - {item}", file=sys.stderr)
        print(file=sys.stderr)
        print("Fix: download pinned artifacts or use a repo-local helper instead of curl|bash/process substitution.", file=sys.stderr)
        return 1

    print("OK: no remote shell bootstrap patterns found in workflow surface.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
