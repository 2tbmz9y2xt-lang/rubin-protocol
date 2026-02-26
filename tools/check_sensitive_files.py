#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath

BLOCKED_PATH_PREFIXES = [
    "spec/",
    "audit/",
    "threat-model/",
    "private/",
]

BLOCKED_EXACT_FILES = {
    "RUBIN_L1_CANONICAL.md",
    "RUBIN_COMPACT_BLOCKS.md",
    "RUBIN_NETWORK_PARAMS.md",
    "RUBIN_L1_P2P_AUX.md",
    "RUBIN_CORE_HTLC_SPEC.md",
    "RUBIN_CORE_VAULT_2FA_DRAFT.md",
    "SECTION_HASHES.json",
    "AUDIT_CONTEXT.md",
}

BLOCKED_NAME_PATTERNS = [
    "*.pem",
    "*.key",
    "*.p12",
    "*.kdbx",
    ".env",
    ".env.*",
]

def pem_begin(label: str) -> str:
    return f"-----BEGIN {label}-----"


BLOCKED_CONTENT_MARKERS = [
    pem_begin("OPENSSH PRIVATE KEY"),
    pem_begin("PRIVATE KEY"),
    pem_begin("EC PRIVATE KEY"),
    pem_begin("RSA PRIVATE KEY"),
]


def run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def detect_range_from_github_event() -> tuple[str, str, bool] | None:
    event_path = os.getenv("GITHUB_EVENT_PATH")
    event_name = os.getenv("GITHUB_EVENT_NAME", "")
    if not event_path or not Path(event_path).exists():
        return None

    with open(event_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    if event_name in {"pull_request", "pull_request_target"}:
        base = payload["pull_request"]["base"]["sha"]
        head = payload["pull_request"]["head"]["sha"]
        return base, head, True

    if event_name == "push":
        base = payload.get("before", "")
        head = payload.get("after", "")
        if not base or set(base) == {"0"}:
            return None
        return base, head, False

    return None


def changed_files(base: str, head: str, pr_mode: bool) -> list[str]:
    range_expr = f"{base}...{head}" if pr_mode else f"{base}..{head}"
    out = run_git(["diff", "--name-only", "--diff-filter=ACMR", range_expr])
    files = [line.strip() for line in out.splitlines() if line.strip()]
    return sorted(set(files))


def all_tracked_files() -> list[str]:
    out = run_git(["ls-files"])
    return [line.strip() for line in out.splitlines() if line.strip()]


def is_path_blocked(path: str) -> bool:
    normalized = path.lstrip("./")
    if normalized in BLOCKED_EXACT_FILES:
        return True
    for prefix in BLOCKED_PATH_PREFIXES:
        if normalized.startswith(prefix):
            return True
    filename = PurePosixPath(normalized).name
    for pattern in BLOCKED_NAME_PATTERNS:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


def contains_blocked_content(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except Exception:
        return None

    if b"\x00" in raw:
        return None

    text = raw.decode("utf-8", errors="ignore")
    for marker in BLOCKED_CONTENT_MARKERS:
        if marker in text:
            return marker
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail if PR/commit introduces sensitive files that must stay private."
    )
    parser.add_argument("--base", help="Git base SHA")
    parser.add_argument("--head", help="Git head SHA")
    parser.add_argument(
        "--pr-mode",
        action="store_true",
        help="Use base...head diff semantics (pull request mode)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan all tracked files instead of diff range",
    )
    args = parser.parse_args()

    if args.all:
        files = all_tracked_files()
    else:
        if args.base and args.head:
            files = changed_files(args.base, args.head, args.pr_mode)
        else:
            detected = detect_range_from_github_event()
            if detected is None:
                files = all_tracked_files()
            else:
                base, head, pr_mode = detected
                files = changed_files(base, head, pr_mode)

    blocked_paths: list[str] = []
    blocked_content: list[tuple[str, str]] = []
    for rel in files:
        if is_path_blocked(rel):
            blocked_paths.append(rel)
            continue
        marker = contains_blocked_content(Path(rel))
        if marker:
            blocked_content.append((rel, marker))

    if blocked_paths or blocked_content:
        print("ERROR: sensitive content detected in public repository.")
        if blocked_paths:
            print("Blocked paths:")
            for path in blocked_paths:
                print(f"  - {path}")
        if blocked_content:
            print("Blocked file content markers:")
            for path, marker in blocked_content:
                print(f"  - {path}: {marker}")
        print("Move sensitive assets to private rubin-spec (or other private repo).")
        return 1

    print("OK: no sensitive files/content detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
