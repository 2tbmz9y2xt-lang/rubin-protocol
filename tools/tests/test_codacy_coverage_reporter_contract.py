#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import tempfile
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
        for name in ("LINUX_SHA512", "DARWIN_SHA512"):
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
        self.assertIn('if wget -q "$url" -O "$out"; then', text)
        self.assertIn('echo "ERROR: wget failed to download $url" >&2', text)

    def test_sha_tool_failures_do_not_fall_through_as_checksum_mismatch(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('if ! actual="$(compute_sha512 "$path")"; then', text)
        self.assertIn('if [[ $verify_rc -eq 2 ]]; then', text)

    def test_mismatched_cached_binary_is_removed_before_redownload(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('rm -f "$CODACY_REPORTER_PATH"', text)

    def test_download_uses_unique_temp_file_in_cache_dir(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('tmp_path="$(mktemp "${reporter_dir}/${CODACY_BINARY_NAME}.tmp.XXXXXX")"', text)
        self.assertNotIn('local tmp_path="$CODACY_REPORTER_PATH.tmp"', text)

    def test_download_failures_cleanup_temp_file_before_return(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('if ! download_file "$reporter_url" "$tmp_path"; then', text)
        self.assertIn('rm -f "$tmp_path"', text)

    def test_download_failure_reports_transport_error_not_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "curl").write_text(
                "#!/usr/bin/env bash\n"
                "out=''\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  if [[ \"$1\" == '-o' ]]; then\n"
                "    shift\n"
                "    out=\"$1\"\n"
                "  fi\n"
                "  shift || break\n"
                "done\n"
                "printf 'partial' > \"$out\"\n"
                "exit 22\n",
                encoding="utf-8",
            )
            (fake_bin / "curl").chmod(0o755)
            env = {
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "CODACY_REPORTER_TMP_FOLDER": str(root / "cache"),
            }
            proc = subprocess.run(
                ["bash", str(SCRIPT_PATH), "download"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("curl failed to download", proc.stderr)
        self.assertNotIn("checksum mismatch", proc.stderr)

    def test_hash_tool_failure_is_not_reported_as_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake_bin = root / "bin"
            cache_root = root / "cache"
            fake_bin.mkdir()
            reporter_dir = cache_root / extract_var("PINNED_VERSION")
            reporter_dir.mkdir(parents=True)
            reporter_path = reporter_dir / "codacy-coverage-reporter-darwin"
            reporter_path.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            reporter_path.chmod(0o755)
            (fake_bin / "uname").write_text("#!/usr/bin/env bash\necho 'Darwin arm64'\n", encoding="utf-8")
            (fake_bin / "uname").chmod(0o755)
            (fake_bin / "sha512sum").write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
            (fake_bin / "sha512sum").chmod(0o755)
            (fake_bin / "shasum").write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
            (fake_bin / "shasum").chmod(0o755)
            env = {
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "CODACY_REPORTER_TMP_FOLDER": str(cache_root),
            }
            proc = subprocess.run(
                ["bash", str(SCRIPT_PATH), "download"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertRegex(proc.stderr, r"(sha512sum|shasum) failed")
        self.assertNotIn("checksum mismatch", proc.stderr)


if __name__ == "__main__":
    unittest.main()
