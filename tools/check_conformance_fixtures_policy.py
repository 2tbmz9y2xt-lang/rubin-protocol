#!/usr/bin/env python3
from __future__ import annotations

import os
import re
# Safe subprocess use in this tool is limited to fixed git argv lists.
import subprocess  # nosec B404
import sys
from pathlib import Path


ROOT = Path(".")
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
CHANGELOG = Path("conformance/fixtures/CHANGELOG.md")
FIXTURE_RE = re.compile(r"^conformance/fixtures/CV-[A-Z0-9-]+\.json$")
PROTOCOL_FIXTURE_RE = re.compile(r"^conformance/fixtures/protocol/[A-Za-z0-9._-]+\.json$")
FALLBACK_RANGE = "HEAD~1..HEAD"
GIT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,127}$")


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    if not cmd or any("\x00" in part for part in cmd):
        raise ValueError("invalid subprocess command")
    # shell=False with argv lists; git refs are validated before caller use.
    return subprocess.run(cmd, text=True, capture_output=True, check=check)  # nosec B603


def is_safe_git_ref(ref: str) -> bool:
    return bool(GIT_REF_RE.fullmatch(ref)) and not ref.startswith("-")


def git_ref_exists(ref: str) -> bool:
    p = run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], check=False)
    return p.returncode == 0


def select_diff_ref() -> str:
    base_ref = os.getenv("GITHUB_BASE_REF", "").strip()
    if base_ref and is_safe_git_ref(base_ref):
        run(["git", "fetch", "--depth=1", "origin", base_ref], check=False)
        return f"origin/{base_ref}...HEAD"
    if base_ref:
        print(f"WARN: ignoring unsafe GITHUB_BASE_REF={base_ref!r}", file=sys.stderr)
    if git_ref_exists("origin/main"):
        return "origin/main...HEAD"
    if git_ref_exists("main"):
        return "main...HEAD"
    print(f"policy: origin/main and main unresolved \u2014 falling back to {FALLBACK_RANGE}", file=sys.stderr)
    return FALLBACK_RANGE


def committed_names(diff_ref: str) -> tuple[str, str | None]:
    """Return (effective range, `git diff --name-only` stdout); stdout is None when no range could be diffed."""
    cmd = ["git", "diff", "--name-only", "--diff-filter=ACMRT"]
    p = run([*cmd, diff_ref], check=False)
    if p.returncode != 0 and diff_ref != FALLBACK_RANGE:
        print(f"policy: git diff {diff_ref} failed \u2014 falling back to {FALLBACK_RANGE}", file=sys.stderr)
        diff_ref = FALLBACK_RANGE
        p = run([*cmd, diff_ref], check=False)
    if p.returncode != 0:
        print(f"policy: git diff {FALLBACK_RANGE} failed \u2014 no committed changes inspected", file=sys.stderr)
        print("policy: diff range = none", file=sys.stderr)
        return "none", None
    print(f"policy: diff range = {diff_ref}", file=sys.stderr)
    return diff_ref, p.stdout


def changed_files(diff_ref: str, effective: list[str]) -> list[str]:
    """Append the effective committed range (or "none") to `effective` for changelog_added_text()."""
    effective_ref, committed = committed_names(diff_ref)
    effective.append(effective_ref)
    if committed is None:
        return []
    files = {line.strip() for line in committed.splitlines() if line.strip()}
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


def added_lines(p: subprocess.CompletedProcess[str]) -> list[str]:
    return [l[1:] for l in p.stdout.splitlines() if l.startswith("+") and not l.startswith("+++")]


def changelog_added_text(effective_ref: str) -> str:
    added: list[str] = []
    path = CHANGELOG.as_posix()
    if effective_ref != "none":
        p = run(["git", "diff", "--unified=0", effective_ref, "--", path], check=False)
        if p.returncode == 0:
            added += added_lines(p)
        else:
            print(
                f"policy: git diff {effective_ref} -- {path} failed \u2014 committed CHANGELOG text not inspected",
                file=sys.stderr,
            )
    for cmd in (["git", "diff", "--unified=0", "--", path], ["git", "diff", "--cached", "--unified=0", "--", path]):
        p = run(cmd, check=False)
        if p.returncode == 0:
            added += added_lines(p)
    return "\n".join(added)


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


def check_fixture_changelog_guard(changed: list[str], errors: list[str], effective_ref: str) -> None:
    fixtures_changed = [p for p in changed if FIXTURE_RE.match(p) or PROTOCOL_FIXTURE_RE.match(p)]
    if not fixtures_changed:
        return

    if CHANGELOG.as_posix() not in changed:
        errors.append(
            "fixture JSON changed but conformance/fixtures/CHANGELOG.md not updated"
        )
        return

    if not (ROOT / CHANGELOG).exists():
        errors.append("missing conformance/fixtures/CHANGELOG.md")
        return
    changelog_text = changelog_added_text(effective_ref)

    for fixture_path in fixtures_changed:
        name = Path(fixture_path).name
        if name not in changelog_text:
            errors.append(f"CHANGELOG.md missing fresh entry for changed fixture {name}")


def main() -> int:
    errors: list[str] = []
    effective: list[str] = []
    changed = changed_files(select_diff_ref(), effective)

    check_generator_not_in_ci(errors)
    check_fixture_changelog_guard(changed, errors, effective[0])

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print("OK: conformance fixture policy is satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
