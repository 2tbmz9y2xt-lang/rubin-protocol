#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SHELL_EXECUTABLE_PATTERN = r"(?:/(?:usr/)?bin/)?(?:bash|sh)"
ENV_LAUNCHER_PATTERN = r"(?:/(?:usr/)?bin/)?env(?:\s+\S+)*\s+(?:bash|sh)"
SUDO_OPTION_PATTERN = r"(?:--|--?[A-Za-z][\w-]*(?:[= ]\S+)?)"
SUDO_PREFIX_PATTERN = rf"(?:sudo(?:\s+{SUDO_OPTION_PATTERN})*\s+)?"
SHELL_LAUNCHER_PATTERN = rf"{SUDO_PREFIX_PATTERN}(?:{ENV_LAUNCHER_PATTERN}|{SHELL_EXECUTABLE_PATTERN})"
YAML_BOUNDARY_PATTERN = re.compile(r"^(?:-\s+|[A-Za-z0-9_-]+:(?:\s|$))")

REMOTE_SHELL_PATTERNS = (
    ("remote shell pipe", re.compile(rf"\b(?:curl|wget)\b.*\|\s*{SHELL_LAUNCHER_PATTERN}\b", re.IGNORECASE)),
    (
        "remote shell process substitution",
        re.compile(rf"(?:^|[^\w])(?:{SHELL_LAUNCHER_PATTERN}|source|\.)\s*<\(\s*(?:curl|wget)\b", re.IGNORECASE),
    ),
    (
        "remote shell -c command substitution",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}\s+-c\s+(?:[\"']?\$\(\s*(?:curl|wget)\b|[\"']?`[^`]*(?:curl|wget)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell eval command substitution",
        re.compile(r"\beval\b\s+(?:[\"']?\$\(\s*(?:curl|wget)\b|[\"']?`[^`]*(?:curl|wget)\b)", re.IGNORECASE),
    ),
)


def workflow_paths(repo_root: Path) -> list[Path]:
    workflow_dir = repo_root / ".github" / "workflows"
    return sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))


def render_path(path: Path, repo_root: Path | None = None) -> str:
    if repo_root is None:
        return path.as_posix()
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def command_windows(lines: list[str], start: int) -> list[tuple[int, str]]:
    windows: list[tuple[int, str]] = []
    parts: list[str] = []
    boundary_indent: int | None = None
    for idx in range(start, len(lines)):
        raw = lines[idx]
        stripped = raw.strip()
        if not stripped:
            if parts:
                if parts[-1].endswith("|"):
                    continue
                break
            continue
        if stripped.startswith("#"):
            if parts:
                continue
            continue
        indent = len(raw) - len(raw.lstrip())
        if boundary_indent is None:
            boundary_indent = indent
        elif indent <= boundary_indent and YAML_BOUNDARY_PATTERN.match(raw.lstrip()):
            break
        parts.append(stripped.rstrip("\\").strip())
        windows.append((idx, " ".join(parts)))
    return windows


def infer_repo_root(path: Path) -> Path | None:
    for parent in path.parents:
        if parent.name == ".github" and parent.parent.name:
            return parent.parent
    return None


def find_violations(path: Path) -> list[str]:
    violations: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    rendered_path = render_path(path, infer_repo_root(path))
    line_no = 0
    while line_no < len(lines):
        matched_end: int | None = None
        for end_idx, window in command_windows(lines, line_no):
            for label, pattern in REMOTE_SHELL_PATTERNS:
                if pattern.search(window):
                    violations.append(f"{rendered_path}:{end_idx + 1}: {label}: {window}")
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
        print("ERROR: remote shell bootstrap is not allowed in .github/workflows:", file=sys.stderr)
        for item in bad:
            print(f" - {item}", file=sys.stderr)
        print(file=sys.stderr)
        print("Fix: download pinned artifacts or use a repo-local helper instead of curl|bash/process substitution.", file=sys.stderr)
        return 1

    print("OK: no remote shell bootstrap patterns found in workflow surface.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
