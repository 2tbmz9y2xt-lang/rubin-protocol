#!/usr/bin/env python3
"""Executing contract for build-openssl-bundle.sh: each row drives the real script with
curl and the OpenSSL compile stubbed, asserting exit status and whether it extracted."""
from __future__ import annotations

import hashlib
import io
import re
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "crypto" / "openssl" / "build-openssl-bundle.sh"
CHECKSUM_PATH = SCRIPT_PATH.with_name("source-checksums.sha256")
VERSION_PATH = SCRIPT_PATH.with_name("VERSION")
BENCHMARK_PATHS = (
    SCRIPT_PATH.with_name("bench-pq-speed.py"),
    SCRIPT_PATH.with_name("bench-pq-pkeyutl.py"),
)
PAYLOAD = object()  # pin the served bytes; ABSENT writes no checksum file at all
ABSENT = object()
VERSION = VERSION_PATH.read_text(encoding="utf-8").removesuffix("\n")
MIRROR_URL = "https://mirror.example/openssl.tar.gz"
GARBAGE = b"not the pinned openssl source"

CURL_STUB = '#!/usr/bin/env bash\n: > "$CURL_RAN"\ncp -- "$SERVED" "${@: -1}"\n'
MAKE_STUB = """#!/usr/bin/env bash
mkdir -p "$PREFIX/bin" "$PREFIX/lib/ossl-modules"
printf '#!/bin/sh\\nexit 0\\n' > "$PREFIX/bin/openssl"
chmod +x "$PREFIX/bin/openssl"
: > "$PREFIX/lib/ossl-modules/fips.so"
"""
FAILING_STUB = "#!/usr/bin/env bash\nexit 1\n"


def write_stub(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def source_tarball() -> bytes:
    """A real tar.gz shaped like the upstream archive: strip-components=1 plus ./config."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, body in (("EXTRACTED", b"marker\n"), ("config", b"#!/bin/sh\nexit 0\n")):
            info = tarfile.TarInfo(f"openssl-{VERSION}/{name}")
            info.size, info.mode = len(body), 0o755
            archive.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def repin_text(text: str, digest: str, version: str) -> str:
    """Repoint one version's pinned line, leaving every other pinned version intact."""
    patched, count = re.subn(rf"^[0-9a-f]{{64}}(  openssl-{re.escape(version)}\.tar\.gz)$",
                             rf"{digest}\g<1>", text, flags=re.MULTILINE)
    assert count == 1, f"expected one pinned digest for {version}, found {count}"
    return patched


class OpenSSLBundleContractTests(unittest.TestCase):
    def run_bundle(self, tmp, *, served, pin=None, precache=False, version=VERSION,
                   archive_url=None, break_sha_tools=False, use_default=False,
                   check_selection=False, version_bytes=None):
        """pin=None runs the real script against the repository pin file; anything else copies
        the script beside PAYLOAD (pin the served bytes), ABSENT (no file), or literal text."""
        root = Path(tmp)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        work = root / "work"
        tarball = work / f"openssl-{version}.tar.gz"
        write_stub(bin_dir / "curl", CURL_STUB)
        write_stub(bin_dir / "make", MAKE_STUB)
        for tool in ("sha256sum", "shasum") if break_sha_tools else ():
            write_stub(bin_dir / tool, FAILING_STUB)
        if precache:
            work.mkdir(parents=True)
            tarball.write_bytes(served)
        (root / "served.tar.gz").write_bytes(served)
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(root), "JOBS": "1",
               "WORK_ROOT": str(work), "PREFIX": str(root / "prefix"),
               "SERVED": str(root / "served.tar.gz"),
               "CURL_RAN": str(root / "curl-ran")}
        if not use_default:
            env["OPENSSL_VERSION"] = version
        if archive_url is not None:
            env["ARCHIVE_URL"] = archive_url
        script = SCRIPT_PATH
        if pin is not None:
            script = root / "build-openssl-bundle.sh"
            script.write_text(SCRIPT_PATH.read_text(encoding="utf-8"), encoding="utf-8")
            (root / "VERSION").write_bytes(VERSION_PATH.read_bytes() if version_bytes is None else version_bytes)
            if pin is not ABSENT:
                (root / "source-checksums.sha256").write_text(
                    repin_text(CHECKSUM_PATH.read_text(encoding="utf-8"),
                               hashlib.sha256(served).hexdigest(), version)
                    if pin is PAYLOAD else pin, encoding="utf-8")
        command = ["/bin/bash", str(script)]
        if check_selection:
            command.append("--check-selection")
        proc = subprocess.run(command,
                              capture_output=True, text=True, env=env, cwd=root)
        return SimpleNamespace(proc=proc, tarball=tarball, curl_ran=root / "curl-ran",
                               extracted=work / f"openssl-{version}" / "EXTRACTED")

    def test_verified_source_is_extracted_and_built(self):
        for name, kwargs, downloaded in (
            ("fresh download", {}, True),
            ("cached tarball", {"precache": True}, False),
            ("mirror serving pinned bytes", {"archive_url": MIRROR_URL}, True),
        ):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                run = self.run_bundle(tmp, served=source_tarball(), pin=PAYLOAD, **kwargs)
                self.assertEqual(run.proc.returncode, 0, run.proc.stderr)
                self.assertEqual(run.curl_ran.exists(), downloaded)
                self.assertTrue(run.extracted.exists())

    def test_selection_check_is_effect_free_and_pin_bound(self):
        pinned = f"{'d' * 64}  openssl-{VERSION}.tar.gz\n"
        cases = (
            (PAYLOAD, VERSION, None, 0, "selection-ok"),
            (None, "9.9.9", None, 1, "no pinned sha256"),
            (pinned + pinned, VERSION, None, 1, "duplicate pinned sha256"),
            (PAYLOAD, VERSION, b"3.5\x00.5\n", 1, "canonical newline-terminated"),
        )
        for pin, version, version_bytes, code, expected in cases:
            with self.subTest(version=version, expected=expected), tempfile.TemporaryDirectory() as tmp:
                run = self.run_bundle(
                    tmp, served=source_tarball(), pin=pin, version=version,
                    use_default=pin is PAYLOAD, check_selection=True, version_bytes=version_bytes,
                )
                self.assertEqual(run.proc.returncode, code, run.proc.stderr)
                self.assertIn(expected, run.proc.stdout + run.proc.stderr)
                self.assertFalse(run.curl_ran.exists())
                self.assertFalse(run.tarball.exists())
                self.assertFalse(run.extracted.exists())

    def test_unverified_source_is_refused_and_removed_without_extraction(self):
        for name, kwargs in (
            ("fresh download", {}),
            ("poisoned cache", {"precache": True}),
            ("mirror serving other bytes", {"archive_url": MIRROR_URL}),
        ):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                run = self.run_bundle(tmp, served=GARBAGE, **kwargs)
                self.assertNotEqual(run.proc.returncode, 0)
                self.assertIn("sha256 mismatch", run.proc.stderr)
                self.assertFalse(run.tarball.exists())
                self.assertFalse(run.extracted.exists())

    def test_unpinned_version_refuses_before_any_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.run_bundle(tmp, served=source_tarball(), version="9.9.9")
            self.assertNotEqual(run.proc.returncode, 0)
            self.assertFalse(run.curl_ran.exists())
            self.assertIn("no pinned sha256 for OpenSSL 9.9.9", run.proc.stderr)
            self.assertIn("scripts/crypto/openssl/source-checksums.sha256", run.proc.stderr)
            self.assertIn("openssl-9.9.9.tar.gz.sha256", run.proc.stderr)

    def test_malformed_version_refuses_before_any_download(self):
        for version in ("3.5", "3.5.5.", "3.5.5.1", "3.x.5", "3.5-beta"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                run = self.run_bundle(tmp, served=source_tarball(), version=version)
                self.assertNotEqual(run.proc.returncode, 0)
                self.assertFalse(run.curl_ran.exists())
                self.assertIn("must be MAJOR.MINOR.PATCH decimal", run.proc.stderr)

    def test_unusable_pin_file_refuses_before_any_download(self):
        pinned = f"{'d' * 64}  openssl-{VERSION}.tar.gz\n"
        for name, pin, expected in (
            ("no pin file at all", ABSENT, "cannot read pinned checksum file"),
            ("only another version pinned", f"{'d' * 64}  openssl-3.4.0.tar.gz\n", "no pinned sha256"),
            ("digest too short", f"{'d' * 63}  openssl-{VERSION}.tar.gz\n", "malformed entry"),
            ("uppercase digest", f"{'D' * 64}  openssl-{VERSION}.tar.gz\n", "malformed entry"),
            ("single-space separator", f"{'d' * 64} openssl-{VERSION}.tar.gz\n", "malformed entry"),
            ("NUL byte", pinned.replace(".tar.gz", ".tar.gz\x00"), "NUL byte"),
            ("malformed line for another version", pinned + "garbage\n", "malformed entry"),
            ("duplicate entry", pinned + pinned, "duplicate pinned sha256"),
        ):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                run = self.run_bundle(tmp, served=source_tarball(), pin=pin)
                self.assertNotEqual(run.proc.returncode, 0)
                self.assertFalse(run.curl_ran.exists())
                self.assertFalse(run.extracted.exists())
                self.assertIn(expected, run.proc.stderr)

    def test_hash_tool_failure_is_not_reported_as_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.run_bundle(tmp, served=source_tarball(), precache=True, break_sha_tools=True)
            self.assertNotEqual(run.proc.returncode, 0)
            self.assertRegex(run.proc.stderr, r"(sha256sum|shasum) failed")
            self.assertNotIn("mismatch", run.proc.stderr)
            self.assertTrue(run.tarball.exists())

    def test_repin_targets_one_line_when_a_second_version_is_pinned(self):
        original = CHECKSUM_PATH.read_text(encoding="utf-8")
        old_line = next(line for line in original.splitlines() if line.endswith(f"  openssl-{VERSION}.tar.gz"))
        text = original + f"{'a' * 64}  openssl-3.6.0.tar.gz\n"
        patched = repin_text(text, "b" * 64, VERSION)
        self.assertIn(f"{'a' * 64}  openssl-3.6.0.tar.gz", patched)
        self.assertIn(f"{'b' * 64}  openssl-{VERSION}.tar.gz", patched)
        self.assertNotIn(old_line, patched)

    def test_version_file_selects_one_pinned_release(self):
        raw = VERSION_PATH.read_bytes()
        self.assertRegex(raw, rb"^[0-9]+\.[0-9]+\.[0-9]+\n$")
        selected = raw.decode("ascii").removesuffix("\n")
        rows = []
        for line in CHECKSUM_PATH.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([^\s]+)", line)
            if match and match.group(2) == f"openssl-{selected}.tar.gz":
                rows.append(line)
        self.assertEqual(len(rows), 1, f"expected exactly one checksum row for {selected}")
        digest = rows[0].split()[0]
        self.assertNotIn(digest, SCRIPT_PATH.read_text(encoding="utf-8"))
        for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml")):
            self.assertNotIn(digest, workflow.read_text(encoding="utf-8"),
                             f"pin duplicated in {workflow.name}")

    def test_benchmark_defaults_reject_noncanonical_version_file(self):
        for benchmark in BENCHMARK_PATHS:
            for raw in (b" 3.5.5 \n", b"3.5.5\r\n"):
                with self.subTest(benchmark=benchmark.name, raw=raw), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    copied = root / benchmark.name
                    copied.write_bytes(benchmark.read_bytes())
                    (root / "VERSION").write_bytes(raw)
                    proc = subprocess.run(
                        ["python3", str(copied), "--help"], capture_output=True, text=True
                    )
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("must be one MAJOR.MINOR.PATCH decimal line", proc.stderr)


if __name__ == "__main__":
    unittest.main()
