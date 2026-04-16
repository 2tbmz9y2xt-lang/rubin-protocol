#!/usr/bin/env python3
"""Pre-commit hygiene checks for rubin-protocol.

Catches the top bot-thread patterns BEFORE commit, reducing push -> bot -> fix cycles.
Based on 39 real threads from PR #1199 and PR #1203.

Usage:
    python3 tools/check_pre_commit_hygiene.py [--fix] [--staged-only]
                                              [--skip-rust-warnings]

Exit codes: 0 = clean, 1 = violations found, 2 = usage error or git failure.
"""
from __future__ import annotations

import argparse
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
    try:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd or REPO_ROOT)
    except FileNotFoundError as exc:
        detail = _sanitize_paths(str(exc)).strip()
        command = cmd[0] if cmd else "<unknown>"
        print(
            f"[WARN] failed to execute {command!r} -- fail closed: {detail}",
            file=sys.stderr,
        )
        sys.exit(2)


def get_staged_files() -> list[str]:
    # Include D (deletions) so commits that only delete files still trigger
    # downstream checks (clippy on Cargo.toml/lock changes, etc.).
    # Individual check_* helpers skip paths that no longer exist on disk.
    r = run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRD"])
    if r.returncode != 0:
        detail = _sanitize_paths((r.stderr or "").strip())
        print(
            f"[WARN] git diff --cached failed -- fail closed: {detail}",
            file=sys.stderr,
        )
        sys.exit(2)
    return [f for f in r.stdout.splitlines() if f.strip()]


_BASE_REF_CANDIDATES = ("origin/main", "upstream/main", "main", "master")


def get_changed_files() -> list[str]:
    """All changed (added/modified/deleted) files vs the project's base branch.

    Union of:
      - committed diff `base...HEAD` (commit-to-commit, ignores index)
      - staged diff (`--cached`, includes index)
      - unstaged working-tree diff
    so first-commit / pre-commit / amend workflows all surface their
    changes.  `git diff --name-only` includes deletions; downstream
    check_* helpers skip paths that no longer exist on disk.

    Tries common base refs in order; falls back to staged-only mode (with
    a loud warning) only when no candidate ref is available locally.
    """
    last_err = ""
    for ref in _BASE_REF_CANDIDATES:
        base_result = run(["git", "merge-base", ref, "HEAD"])
        if base_result.returncode == 0 and base_result.stdout.strip():
            base = base_result.stdout.strip()
            files: list[str] = []
            seen: set[str] = set()
            for diff_args in (
                ["git", "diff", "--name-only", f"{base}...HEAD"],
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRD"],
                ["git", "diff", "--name-only", "--diff-filter=ACMRD"],
            ):
                r = run(diff_args)
                if r.returncode != 0:
                    detail = _sanitize_paths((r.stderr or "").strip())
                    print(
                        f"[WARN] git {' '.join(diff_args[1:])} failed (rc={r.returncode}) "
                        f"-- fail closed: {detail}",
                        file=sys.stderr,
                    )
                    sys.exit(2)
                for line in r.stdout.splitlines():
                    f = line.strip()
                    if f and f not in seen:
                        seen.add(f)
                        files.append(f)
            return files
        last_err = _sanitize_paths((base_result.stderr or "").strip())
    print(
        f"[WARN] no base ref found ({', '.join(_BASE_REF_CANDIDATES)}); "
        f"falling back to staged files. Last git error: {last_err}",
        file=sys.stderr,
    )
    return get_staged_files()


# ── Check 1: Bot thread IDs in code ──────────────────────────────────

BOT_THREAD_RE = re.compile(r"PRRT_\w+|Codex thread|Copilot thread|chatgpt-codex-connector")
_BINARY_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf",
    ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class",
    ".jar", ".wasm", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".ogg",
})
_MAX_SCAN_BYTES = 1 * 1024 * 1024  # 1 MiB


def _should_scan(f: str, path: Path) -> bool:
    if Path(f).suffix.lower() in _BINARY_EXTS:
        return False
    try:
        if path.stat().st_size > _MAX_SCAN_BYTES:
            return False
    except OSError:
        return False
    return True


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
        if not _should_scan(f, path):
            continue
        for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if BOT_THREAD_RE.search(line):
                snippet = _sanitize_paths(line.strip())[:80]
                violations.append(f"{f}:{i}: bot thread ID in code: {snippet}")
    return violations


# ── Check 2: Exported test helpers in production ─────────────────────

TEST_HELPER_RE = re.compile(r"InjectTestEntry|inject_test_entry")
# Match the conventional trailing test module only: `mod tests`/`mod test`,
# but NOT siblings like `mod test_helpers`, `mod testing`, etc.
MOD_TESTS_RE = re.compile(r"\bmod\s+tests?\b")


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
        # `#[cfg(test)] mod tests {` on a single line.  Match only the
        # conventional `mod tests` / `mod test` module name with word
        # boundaries — `mod test_helpers` is a real production module
        # that must not be treated as the end-of-prod marker.
        prod_end = len(lines)
        if f.endswith(".rs"):
            for idx in range(len(lines) - 1, -1, -1):
                if "#[cfg(test)]" in lines[idx]:
                    # Same line: `#[cfg(test)] mod tests {`
                    if MOD_TESTS_RE.search(lines[idx]):
                        prod_end = idx
                        break
                    # Within next 2 lines
                    for nxt in range(idx + 1, min(idx + 3, len(lines))):
                        if MOD_TESTS_RE.search(lines[nxt]):
                            prod_end = idx
                            break
                    if prod_end < len(lines):
                        break  # found mod tests block
        for i, line in enumerate(lines[:prod_end], 1):
            if TEST_HELPER_RE.search(line):
                # Skip if the previous non-blank line gates this with #[cfg(test)]
                # (inline test-only function pattern, e.g. txpool.rs:150).
                if f.endswith(".rs"):
                    j = i - 2  # zero-based, line before this match
                    while j >= 0 and not lines[j].strip():
                        j -= 1
                    if j >= 0 and "#[cfg(test)]" in lines[j]:
                        continue
                snippet = _sanitize_paths(line.strip())[:80]
                violations.append(f"{f}:{i}: test helper in production: {snippet}")
    return violations


# ── Check 3: cargo clippy --workspace --all-targets -- -D warnings ──

def check_rust_warnings(files: list[str]) -> list[str]:
    """Mirror CI's clippy gate: cargo clippy --workspace --all-targets -- -D warnings.

    Slower than `cargo check` but catches clippy lints CI catches.
    Fires on .rs changes AND on Cargo.toml/Cargo.lock changes (which
    can change feature sets or dependency versions and break clippy).
    """
    triggers = [
        f for f in files
        if f.endswith(".rs")
        or f.endswith("Cargo.toml")
        or f.endswith("Cargo.lock")
    ]
    if not triggers:
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

    dev_env = REPO_ROOT / "scripts" / "dev-env.sh"
    if dev_env.exists():
        cmd = [str(dev_env), "--", *cargo_args]
    else:
        cmd = cargo_args

    # Inherit caller env (no overrides needed; -D warnings is on the
    # cargo arg list, not RUSTFLAGS).
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=RUST_DIR,
        )
    except FileNotFoundError as exc:
        detail = _sanitize_paths(str(exc)).strip()
        command = cmd[0] if cmd else "<unknown>"
        print(
            f"[WARN] failed to execute {command!r} -- fail closed: {detail}",
            file=sys.stderr,
        )
        sys.exit(2)
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
    """Check for any working-tree changes (staged + unstaged) vs HEAD.

    In staged-only mode (pre-commit), skip — staged diff from HEAD is
    intentional.  Otherwise compare working tree against HEAD: catches
    BOTH staged-but-not-amended fixes AND unstaged edits, so the
    after-amend "zero diff" guard actually fires when fixes are still
    sitting in the index.
    """
    if staged_only:
        return []
    r = run(["git", "diff", "HEAD", "--stat"])  # vs HEAD = staged + unstaged
    if r.returncode != 0:
        detail = _sanitize_paths((r.stderr or "").strip())
        print(
            f"[WARN] git diff HEAD --stat failed (rc={r.returncode}) -- fail closed: "
            f"{detail}",
            file=sys.stderr,
        )
        sys.exit(2)
    if r.stdout.strip():
        files = r.stdout.strip().splitlines()
        return [f"changes vs HEAD (staged or unstaged): {f.strip()}" for f in files[:5]]
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

    all_violations: list[str] = []

    # Run amend-completeness FIRST so unstaged working-tree changes are
    # surfaced even if the file-set derivation came back empty.
    v = check_amend_completeness(args.staged_only)
    if v:
        print(f"\n[FAIL] Changes vs HEAD after amend ({len(v)}):")
        for line in v:
            print(f"  {line}")
        all_violations.extend(v)

    if not files:
        if all_violations:
            print(f"\n[STOP] {len(all_violations)} violation(s) found. Fix before commit.")
            return 1
        print("No changed files to check.")
        return 0

    # Fast checks
    v = check_bot_thread_ids(files)
    if v:
        print(f"\n[FAIL] Bot thread IDs in code ({len(v)}):")
        for line in v:
            print(f"  {line}")
        all_violations.extend(v)

    v = check_test_helpers_in_production(files)
    if v:
        print(f"\n[FAIL] Test helpers in production ({len(v)}):")
        for line in v:
            print(f"  {line}")
        all_violations.extend(v)

    # Slow check
    if not args.skip_rust_warnings:
        v = check_rust_warnings(files)
        if v:
            print(f"\n[FAIL] cargo clippy --workspace --all-targets -- -D warnings failures ({len(v)}):")
            for line in v:
                print(f"  {line}")
            all_violations.extend(v)

    if all_violations:
        print(f"\n[STOP] {len(all_violations)} violation(s) found. Fix before commit.")
        return 1

    print("[OK] Pre-commit hygiene: clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
