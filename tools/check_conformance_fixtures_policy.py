#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(".")
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
CHANGELOG = Path("conformance/fixtures/CHANGELOG.md")
FIXTURE_RE = re.compile(r"^conformance/fixtures/CV-[A-Z0-9-]+\.json$")


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def git_ref_exists(ref: str) -> bool:
    p = run(["git", "rev-parse", "--verify", "--quiet", ref], check=False)
    return p.returncode == 0


def changed_files() -> list[str]:
    base_ref = os.getenv("GITHUB_BASE_REF", "").strip()
    if base_ref:
        run(["git", "fetch", "--depth=1", "origin", base_ref], check=False)
        diff_ref = f"origin/{base_ref}...HEAD"
    elif git_ref_exists("origin/main"):
        diff_ref = "origin/main...HEAD"
    elif git_ref_exists("main"):
        diff_ref = "main...HEAD"
    else:
        diff_ref = "HEAD~1..HEAD"

    p = run(["git", "diff", "--name-only", "--diff-filter=ACMRT", diff_ref], check=False)
    if p.returncode != 0:
        p = run(["git", "diff", "--name-only", "--diff-filter=ACMRT", "HEAD~1..HEAD"], check=False)
        if p.returncode != 0:
            return []
    files = {line.strip() for line in p.stdout.splitlines() if line.strip()}
    # Local convenience: include working tree changes (staged + unstaged) and
    # untracked files so the policy check also works before first commit.
    p_worktree = run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRT"], check=False
    )
    if p_worktree.returncode == 0:
        for line in p_worktree.stdout.splitlines():
            line = line.strip()
            if line:
                files.add(line)

    p_cached = run(
        ["git", "diff", "--name-only", "--cached", "--diff-filter=ACMRT"],
        check=False,
    )
    if p_cached.returncode == 0:
        for line in p_cached.stdout.splitlines():
            line = line.strip()
            if line:
                files.add(line)

    p_untracked = run(
        ["git", "ls-files", "--others", "--exclude-standard"], check=False
    )
    if p_untracked.returncode == 0:
        for line in p_untracked.stdout.splitlines():
            line = line.strip()
            if line:
                files.add(line)
    return sorted(files)


def check_generator_not_in_ci(errors: list[str]) -> None:
    if not WORKFLOWS_DIR.exists():
        errors.append("missing .github/workflows")
        return

    forbidden_patterns = [
        "gen-conformance-fixtures",
        "go run ./cmd/gen-conformance-fixtures",
        "go run ./clients/go/cmd/gen-conformance-fixtures",
    ]

    for wf in sorted(WORKFLOWS_DIR.glob("*.y*ml")):
        text = wf.read_text(encoding="utf-8", errors="strict")
        for pat in forbidden_patterns:
            if pat in text:
                errors.append(
                    f"workflow {wf.as_posix()} must not invoke fixture generator ({pat})"
                )


def check_fixture_changelog_guard(changed: list[str], errors: list[str]) -> None:
    fixtures_changed = [p for p in changed if FIXTURE_RE.match(p)]
    if not fixtures_changed:
        return

    if CHANGELOG.as_posix() not in changed:
        errors.append(
            "fixture JSON changed but conformance/fixtures/CHANGELOG.md not updated"
        )
        return

    try:
        changelog_text = (ROOT / CHANGELOG).read_text(encoding="utf-8", errors="strict")
    except FileNotFoundError:
        errors.append("missing conformance/fixtures/CHANGELOG.md")
        return

    for fixture_path in fixtures_changed:
        name = Path(fixture_path).name
        if name not in changelog_text:
            errors.append(f"CHANGELOG.md missing reference for changed fixture {name}")


def main() -> int:
    errors: list[str] = []
    changed = changed_files()

    check_generator_not_in_ci(errors)
    check_fixture_changelog_guard(changed, errors)

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print("OK: conformance fixture policy is satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
