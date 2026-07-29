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
VERSION = "3.5.5"
PUBLISHED_SHA256 = "b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89"
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


def repin(root: Path, payload: bytes) -> Path:
    """The real script with its 3.5.5 pin repointed at a locally built payload."""
    patched, count = re.subn(
        r'(?<=EXPECTED_SHA256=")[0-9a-f]{64}(?=")',
        hashlib.sha256(payload).hexdigest(),
        SCRIPT_PATH.read_text(encoding="utf-8"),
    )
    assert count == 1, f"expected one pinned digest in {SCRIPT_PATH}, found {count}"
    path = root / "build-openssl-bundle.sh"
    path.write_text(patched, encoding="utf-8")
    return path


class OpenSSLBundleContractTests(unittest.TestCase):
    def run_bundle(self, tmp, *, served, repinned=False, precache=False, version=VERSION,
                   archive_url=None, break_sha_tools=False):
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
               "OPENSSL_VERSION": version, "SERVED": str(root / "served.tar.gz"),
               "CURL_RAN": str(root / "curl-ran")}
        if archive_url is not None:
            env["ARCHIVE_URL"] = archive_url
        proc = subprocess.run(["/bin/bash", str(repin(root, served) if repinned else SCRIPT_PATH)],
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
                run = self.run_bundle(tmp, served=source_tarball(), repinned=True, **kwargs)
                self.assertEqual(run.proc.returncode, 0, run.proc.stderr)
                self.assertEqual(run.curl_ran.exists(), downloaded)
                self.assertTrue(run.extracted.exists())

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
            self.assertIn("scripts/crypto/openssl/build-openssl-bundle.sh", run.proc.stderr)
            self.assertIn("openssl-9.9.9.tar.gz.sha256", run.proc.stderr)

    def test_hash_tool_failure_is_not_reported_as_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.run_bundle(tmp, served=source_tarball(), precache=True, break_sha_tools=True)
            self.assertNotEqual(run.proc.returncode, 0)
            self.assertRegex(run.proc.stderr, r"(sha256sum|shasum) failed")
            self.assertNotIn("mismatch", run.proc.stderr)
            self.assertTrue(run.tarball.exists())

    def test_script_is_the_single_definition_of_the_published_pin(self):
        self.assertIn(f'EXPECTED_SHA256="{PUBLISHED_SHA256}"',
                      SCRIPT_PATH.read_text(encoding="utf-8"))
        for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml")):
            self.assertNotIn(PUBLISHED_SHA256, workflow.read_text(encoding="utf-8"),
                             f"pin duplicated in {workflow.name}")


if __name__ == "__main__":
    unittest.main()
