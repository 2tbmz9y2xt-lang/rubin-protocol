#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess  # nosec B404
from pathlib import Path


DISALLOWED_SUBSTRINGS = [
    "/" + "Users" + "/",
    "\\" + "Users" + "\\",
]


def git_executable() -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git executable not found")
    return git


def resolve_repo_root(start: Path) -> Path:
    out = subprocess.check_output(  # nosec B603
        [git_executable(), "rev-parse", "--show-toplevel"],
        cwd=str(start),
        text=True,
    )
    return Path(out.strip()).resolve()


def iter_tracked_files(repo_root: Path) -> list[Path]:
    out = subprocess.check_output(  # nosec B603
        [git_executable(), "ls-files"],
        cwd=str(repo_root),
        text=True,
    )
    paths: list[Path] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        paths.append(repo_root / line)
    return paths


def should_scan(p: Path) -> bool:
    if not p.is_file():
        return False
    try:
        if p.stat().st_size > 2_000_000:
            return False
    except OSError:
        return False
    if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reject tracked files containing local absolute home paths."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root to scan. Defaults to the current working directory.",
    )
    args = parser.parse_args(argv)
    repo_root = resolve_repo_root(args.repo_root.resolve())

    bad: list[str] = []
    for p in iter_tracked_files(repo_root):
        rel = str(p.relative_to(repo_root))
        if not should_scan(p):
            continue
        try:
            data = p.read_bytes()
        except OSError as e:
            bad.append(f"READ_FAIL {rel}: {e}")
            continue

        try:
            s = data.decode("utf-8")
        except UnicodeDecodeError:
            continue

        for needle in DISALLOWED_SUBSTRINGS:
            if needle in s:
                bad.append(f"ABS_PATH {rel}: contains {needle!r}")
                break

    if bad:
        print("ERROR: absolute home paths are not allowed in tracked files:")
        for line in bad:
            print(" -", line)
        print()
        print("Fix: replace with repo-relative paths or environment variables.")
        return 1

    print("OK: no disallowed absolute home paths found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
