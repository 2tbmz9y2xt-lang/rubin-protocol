#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

DISALLOWED_SUBSTRINGS = [
    "/Users/",
    "\\Users\\",
]


def iter_tracked_files() -> list[Path]:
    out = subprocess.check_output(["git", "ls-files"], cwd=str(REPO_ROOT), text=True)
    paths: list[Path] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        paths.append(REPO_ROOT / line)
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


def main() -> int:
    bad: list[str] = []
    for p in iter_tracked_files():
        rel = str(p.relative_to(REPO_ROOT))
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

