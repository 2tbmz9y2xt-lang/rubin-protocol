#!/usr/bin/env python3
"""Pre-commit hygiene checks for rubin-protocol.

Catches the top bot-thread patterns BEFORE commit, reducing push→bot→fix cycles.
Based on 39 real threads from PR #1199 and PR #1203.

Usage:
    python3 tools/check_pre_commit_hygiene.py [--fix] [--staged-only]

Exit codes: 0 = clean, 1 = violations found, 2 = usage error.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_DIR = REPO_ROOT / "clients" / "rust"

_PATH_RE = re.compile(
    r"/(?:Users|home|root|workspace|var/folders|tmp|opt|private|runner/work|nix|build|data|run|mnt|srv|proc|usr)/[^\s\"']+"
)


def _sanitize_paths(text: str) -> str:
    """Replace absolute filesystem paths with <path> placeholder."""
    return _PATH_RE.sub("<path>", text)


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd or REPO_ROOT)


def get_staged_files() -> list[str]:
    r = run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    if r.returncode != 0:
        print("⚠ git diff --cached failed — fail closed", file=sys.stderr)
        sys.exit(2)
    return [f for f in r.stdout.splitlines() if f.strip()]


def get_changed_files() -> list[str]:
    """All modified/added files vs origin/main."""
    base_result = run(["git", "merge-base", "origin/main", "HEAD"])
    if base_result.returncode != 0:
        print(f"⚠ git merge-base failed (rc={base_result.returncode}) — fail closed", file=sys.stderr)
        sys.exit(2)
    base = base_result.stdout.strip()
    if not base:
        print("⚠ git merge-base returned empty — fail closed", file=sys.stderr)
        sys.exit(2)
    r = run(["git", "diff", "--name-only", f"{base}...HEAD"])
    if r.returncode != 0:
        print(f"⚠ git diff failed (rc={r.returncode}) — fail closed", file=sys.stderr)
        sys.exit(2)
    return [f for f in r.stdout.splitlines() if f.strip()]


# ── Check 1: Bot thread IDs in code ──────────────────────────────────

BOT_THREAD_RE = re.compile(r"PRRT_\w+|Codex thread|Copilot thread|chatgpt-codex-connector")


def check_bot_thread_ids(files: list[str]) -> list[str]:
    """Bot thread IDs are temporary PR artifacts, not permanent code."""
    violations = []
    for f in files:
        # Skip self — this file contains the pattern as a regex literal.
        if f.endswith("check_pre_commit_hygiene.py"):
            continue
        path = REPO_ROOT / f
        if not path.is_file():
            continue
        for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if BOT_THREAD_RE.search(line):
                snippet = _sanitize_paths(line.strip())[:80]
                violations.append(f"{f}:{i}: bot thread ID in code: {snippet}")
    return violations


# ── Check 2: Exported test helpers in production ─────────────────────

TEST_HELPER_RE = re.compile(r"InjectTestEntry|inject_test_entry")


def check_test_helpers_in_production(files: list[str]) -> list[str]:
    """Test-only helpers must not be exported in production code."""
    violations = []
    for f in files:
        # Skip test files
        if "_test.go" in f or f.endswith("_test.rs") or "/tests/" in f:
            continue
        if not (f.endswith(".go") or f.endswith(".rs")):
            continue
        path = REPO_ROOT / f
        if not path.is_file():
            continue
        content = path.read_text(errors="replace")
        lines = content.splitlines()
        # Rust: only check lines BEFORE the final `#[cfg(test)] mod tests`
        # block.  Standard pattern is a trailing test module; also handle
        # `#[cfg(test)] mod tests {` on a single line.
        prod_end = len(lines)
        if f.endswith(".rs"):
            for idx in range(len(lines) - 1, -1, -1):
                if "#[cfg(test)]" in lines[idx]:
                    # Same line: `#[cfg(test)] mod tests {`
                    if "mod tests" in lines[idx] or "mod test" in lines[idx]:
                        prod_end = idx
                        break
                    # Within next 2 lines
                    for nxt in range(idx + 1, min(idx + 3, len(lines))):
                        if "mod tests" in lines[nxt] or "mod test" in lines[nxt]:
                            prod_end = idx
                            break
                    if prod_end < len(lines):
                        break  # found mod tests block
        for i, line in enumerate(lines[:prod_end], 1):
            if TEST_HELPER_RE.search(line):
                snippet = _sanitize_paths(line.strip())[:80]
                violations.append(f"{f}:{i}: test helper in production: {snippet}")
    return violations


# ── Check 3: cargo clippy --workspace --all-targets -- -D warnings ──

def check_rust_warnings(files: list[str]) -> list[str]:
    """Mirror CI's clippy gate: cargo clippy --workspace --all-targets -- -D warnings.

    Slower than `cargo check` but catches clippy lints CI catches.
    """
    rs_files = [f for f in files if f.endswith(".rs")]
    if not rs_files:
        return []

    cargo_args = [
        "cargo",
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]
    env = {**os.environ}

    dev_env = REPO_ROOT / "scripts" / "dev-env.sh"
    if dev_env.exists():
        cmd = [str(dev_env), "--", *cargo_args]
    else:
        cmd = cargo_args

    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=RUST_DIR,
        env=env,
    )
    if r.returncode != 0:
        combined = (r.stdout or "") + (r.stderr or "")
        errors = [line for line in combined.splitlines()
                  if "error[" in line or "error:" in line.lower()]
        if errors:
            # Strip file paths from cargo output for cleaner messages.
            return [
                f"clippy -D warnings: {_sanitize_paths(re.sub(r' --> .*$', '', e.strip()))[:100]}"
                for e in errors[:5]
            ]
        raw = re.sub(r"^\s*-->.*$", "", combined, flags=re.MULTILINE).strip()
        raw = _sanitize_paths(raw)[:200]
        return [f"clippy --workspace --all-targets -- -D warnings failed: {raw or '(no output)'}"]
    return []


# ── Check 4: git diff HEAD after amend ───────────────────────────────

def check_amend_completeness(staged_only: bool) -> list[str]:
    """Check for unstaged modifications in tracked files (not staged vs HEAD).

    In staged-only mode (pre-commit), skip this check — staged diff from
    HEAD is intentional.  Only run after amend when we expect zero diff.
    """
    if staged_only:
        return []
    r = run(["git", "diff", "--stat"])  # unstaged only, not vs HEAD
    if r.stdout.strip():
        files = r.stdout.strip().splitlines()
        return [f"unstaged changes in working tree: {f.strip()}" for f in files[:5]]
    return []


# ── Main ─────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-only", action="store_true",
                        help="Check only staged files (for pre-commit hook)")
    parser.add_argument("--fix", action="store_true",
                        help="Reserved for future auto-fix (not yet implemented)")
    parser.add_argument("--skip-rust-warnings", action="store_true",
                        help="Skip cargo clippy --workspace --all-targets check (slow)")
    args = parser.parse_args(argv)

    files = get_staged_files() if args.staged_only else get_changed_files()
    if not files:
        print("No changed files to check.")
        return 0

    all_violations: list[str] = []

    # Fast checks
    v = check_bot_thread_ids(files)
    if v:
        print(f"\n❌ Bot thread IDs in code ({len(v)}):")
        for line in v:
            print(f"  {line}")
        all_violations.extend(v)

    v = check_test_helpers_in_production(files)
    if v:
        print(f"\n❌ Test helpers in production ({len(v)}):")
        for line in v:
            print(f"  {line}")
        all_violations.extend(v)

    v = check_amend_completeness(args.staged_only)
    if v:
        print(f"\n❌ Unstaged changes after amend ({len(v)}):")
        for line in v:
            print(f"  {line}")
        all_violations.extend(v)

    # Slow check
    if not args.skip_rust_warnings:
        v = check_rust_warnings(files)
        if v:
            print(f"\n❌ cargo clippy --workspace --all-targets -- -D warnings failures ({len(v)}):")
            for line in v:
                print(f"  {line}")
            all_violations.extend(v)

    if all_violations:
        print(f"\n🛑 {len(all_violations)} violation(s) found. Fix before commit.")
        return 1

    print("✅ Pre-commit hygiene: clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
