#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "codacy-coverage-reporter.sh"


def extract_var(name: str) -> str:
    text = SCRIPT_PATH.read_text(encoding="utf-8")
    match = re.search(rf'^{name}="([^"]+)"$', text, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing {name} in {SCRIPT_PATH}")
    return match.group(1)


class CodacyCoverageReporterContractTests(unittest.TestCase):
    def test_sha512_constants_are_full_length_hex_digests(self):
        for name in ("LINUX_SHA512", "DARWIN_ARM64_SHA512"):
            digest = extract_var(name)
            self.assertEqual(len(digest), 128, name)
            self.assertRegex(digest, r"^[0-9a-f]{128}$", name)

    def test_pinned_version_is_explicit_semver(self):
        version = extract_var("PINNED_VERSION")
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
