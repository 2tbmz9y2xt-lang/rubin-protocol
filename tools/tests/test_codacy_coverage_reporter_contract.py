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

    def test_cache_root_falls_back_when_home_is_unset(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('${CODACY_REPORTER_TMP_FOLDER:-${HOME:-${TMPDIR:-/tmp}}/.cache/codacy/coverage-reporter}', text)

    def test_wget_download_failures_are_reported_explicitly(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('if ! wget -q "$url" -O "$out"; then', text)
        self.assertIn('echo "ERROR: wget failed to download $url" >&2', text)

    def test_sha_tool_failures_do_not_fall_through_as_checksum_mismatch(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('actual="$(compute_sha512 "$path")" || return 2', text)
        self.assertIn('if [[ $verify_rc -eq 2 ]]; then', text)


if __name__ == "__main__":
    unittest.main()
