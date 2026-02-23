#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(".")
PROFILE = ROOT / "spec" / "RUBIN_CRYPTO_BACKEND_PROFILE.md"
SPEC_README = ROOT / "spec" / "README.md"
FORBIDDEN_PATH = ROOT / "scripts" / "crypto" / "wolfssl"

REQUIRED_PROFILE_PHRASES = [
    "OpenSSL 3.5+",
    "MUST use",
    "non-OpenSSL PQ backend binding is forbidden",
]

ALLOWED_MENTION_FILES = {
    "tools/check_crypto_backend_policy.py",
}

SCAN_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".mjs",
    ".js",
    ".ts",
    ".go",
    ".rs",
    ".toml",
    ".json",
    ".yml",
    ".yaml",
    ".sh",
    ".c",
    ".h",
}

FORBIDDEN_RE = re.compile(
    r"(?i)\b(wolfssl|wolfcrypt|liboqs)\b|oqs/|OQS_[A-Z0-9_]+"
)


def git_tracked_files() -> list[str]:
    out = subprocess.check_output(["git", "ls-files"], text=True)
    return [line.strip() for line in out.splitlines() if line.strip()]


def main() -> int:
    failed = False

    if not PROFILE.exists():
        print("ERROR: missing spec/RUBIN_CRYPTO_BACKEND_PROFILE.md", file=sys.stderr)
        return 2

    profile_text = PROFILE.read_text(encoding="utf-8", errors="strict")
    for phrase in REQUIRED_PROFILE_PHRASES:
        if phrase not in profile_text:
            print(
                f"ERROR: RUBIN_CRYPTO_BACKEND_PROFILE.md missing phrase: {phrase}",
                file=sys.stderr,
            )
            failed = True

    readme_text = SPEC_README.read_text(encoding="utf-8", errors="strict")
    if "./RUBIN_CRYPTO_BACKEND_PROFILE.md" not in readme_text:
        print(
            "ERROR: spec/README.md must reference RUBIN_CRYPTO_BACKEND_PROFILE.md",
            file=sys.stderr,
        )
        failed = True

    if FORBIDDEN_PATH.exists():
        tracked_under_forbidden = subprocess.check_output(
            ["git", "ls-files", "scripts/crypto/wolfssl/**"], text=True
        ).strip()
        if tracked_under_forbidden:
            print(
                "ERROR: tracked files under scripts/crypto/wolfssl are forbidden",
                file=sys.stderr,
            )
            failed = True

    for rel in git_tracked_files():
        path = ROOT / rel
        if path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        if rel in ALLOWED_MENTION_FILES:
            continue
        match = FORBIDDEN_RE.search(text)
        if match:
            print(
                f"ERROR: forbidden backend reference in {rel}: {match.group(0)!r}",
                file=sys.stderr,
            )
            failed = True

    if failed:
        return 1

    print("OK: crypto backend policy (OpenSSL-only) is consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
