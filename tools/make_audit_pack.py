#!/usr/bin/env python3

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[1]


DEFAULT_PREFIXES = [
    "spec/",
    "conformance/",
    "clients/",
    "scripts/",
    "tools/",
    "rubin-formal/",
    ".github/workflows/",
]


@dataclass(frozen=True)
class GitTrackedFile:
    path: str
    mode: int
    blob: str


def _run_git(args: list[str], *, cwd: Path) -> str:
    return subprocess.check_output(["git", *args], cwd=str(cwd), text=True)


def _git_head(repo_root: Path) -> str:
    return _run_git(["rev-parse", "HEAD"], cwd=repo_root).strip()


def _git_branch(repo_root: Path) -> str:
    # Empty on detached HEAD; keep deterministic.
    out = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root).strip()
    return "" if out == "HEAD" else out


def _git_describe(repo_root: Path) -> str:
    try:
        return _run_git(["describe", "--always", "--dirty"], cwd=repo_root).strip()
    except Exception:
        return _git_head(repo_root)[:12]


def _git_is_dirty(repo_root: Path) -> bool:
    out = _run_git(["status", "--porcelain"], cwd=repo_root)
    return bool(out.strip())


def _iter_git_ls_files_stage(repo_root: Path) -> list[GitTrackedFile]:
    out = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=str(repo_root))
    items: list[GitTrackedFile] = []
    for raw in out.split(b"\x00"):
        if not raw:
            continue
        # Format: "<mode> <blob> <stage>\t<path>"
        try:
            meta, path_b = raw.split(b"\t", 1)
            mode_b, blob_b, _stage_b = meta.split(b" ", 2)
            mode = int(mode_b.decode("ascii"), 10)
            blob = blob_b.decode("ascii")
            path = path_b.decode("utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to parse git ls-files --stage entry: {raw!r}: {e}") from e
        items.append(GitTrackedFile(path=path, mode=mode, blob=blob))
    return items


def _normalize_prefix(p: str) -> str:
    p = p.strip()
    if not p:
        return p
    p = p.replace("\\", "/")
    if p == ".":
        return ""
    if not p.endswith("/"):
        p += "/"
    return p


def _select_files(all_items: list[GitTrackedFile], prefixes: list[str]) -> list[GitTrackedFile]:
    norm = [_normalize_prefix(p) for p in prefixes if _normalize_prefix(p)]
    if not norm:
        return []
    selected: list[GitTrackedFile] = []
    for it in all_items:
        if any(it.path.startswith(p) for p in norm):
            selected.append(it)
    selected.sort(key=lambda x: x.path)
    return selected


def _safe_version(cmd: str) -> Optional[str]:
    exe = shutil.which(cmd)
    if not exe:
        return None
    try:
        out = subprocess.check_output([exe, "--version"], text=True, stderr=subprocess.STDOUT)
        return out.strip().splitlines()[0].strip()
    except Exception:
        return None


def _tool_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for key, cmd in [
        ("python3", "python3"),
        ("go", "go"),
        ("node", "node"),
        ("npm", "npm"),
        ("rustc", "rustc"),
        ("cargo", "cargo"),
    ]:
        v = _safe_version(cmd)
        if v:
            versions[key] = v
    return versions


def _tar_add_bytes(
    tf: tarfile.TarFile,
    arcname: str,
    data: bytes,
    *,
    mode: int = 0o644,
) -> None:
    ti = tarfile.TarInfo(name=arcname)
    ti.size = len(data)
    ti.mtime = 0
    ti.uid = 0
    ti.gid = 0
    ti.uname = ""
    ti.gname = ""
    ti.mode = mode
    tf.addfile(ti, io.BytesIO(data))


def _tar_add_tracked_file(
    tf: tarfile.TarFile,
    repo_root: Path,
    it: GitTrackedFile,
) -> None:
    src = repo_root / it.path
    if it.mode == 120000:
        # Symlink.
        target = os.readlink(src)
        ti = tarfile.TarInfo(name=it.path)
        ti.type = tarfile.SYMTYPE
        ti.linkname = target
        ti.size = 0
        ti.mtime = 0
        ti.uid = 0
        ti.gid = 0
        ti.uname = ""
        ti.gname = ""
        ti.mode = 0o777
        tf.addfile(ti)
        return

    if it.mode not in (100644, 100755):
        raise RuntimeError(f"Unsupported git file mode for archive: {it.path}: {it.mode}")

    data = src.read_bytes()
    mode = 0o755 if it.mode == 100755 else 0o644

    ti = tarfile.TarInfo(name=it.path)
    ti.size = len(data)
    ti.mtime = 0
    ti.uid = 0
    ti.gid = 0
    ti.uname = ""
    ti.gname = ""
    ti.mode = mode
    tf.addfile(ti, io.BytesIO(data))


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a deterministic RUBIN audit pack from tracked sources.")
    ap.add_argument(
        "--repo-root",
        default=str(REPO_ROOT),
        help="Repository root (default: auto-detected).",
    )
    ap.add_argument(
        "--out",
        default="artifacts/audit-pack/rubin-audit-pack.tar.gz",
        help="Output path (relative to repo-root unless absolute).",
    )
    ap.add_argument(
        "--prefix",
        action="append",
        default=[],
        help="Tracked path prefix to include (repeatable). Default is a safe allowlist.",
    )
    ap.add_argument(
        "--include-toolchain",
        action="store_true",
        help="Include toolchain versions in the manifest (may reduce cross-machine determinism).",
    )
    ap.add_argument(
        "--print-sha256",
        action="store_true",
        help="Print sha256 of the generated archive.",
    )
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    prefixes = args.prefix if args.prefix else DEFAULT_PREFIXES

    head = _git_head(repo_root)
    branch = _git_branch(repo_root)
    describe = _git_describe(repo_root)
    dirty = _git_is_dirty(repo_root)

    all_items = _iter_git_ls_files_stage(repo_root)
    selected = _select_files(all_items, prefixes)
    if not selected:
        raise SystemExit("ERROR: no files selected (check --prefix).")

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = repo_root / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, object] = {
        "audit_pack_version": 1,
        "git": {
            "head": head,
            "branch": branch,
            "describe": describe,
            "dirty": dirty,
        },
        "included_prefixes": [_normalize_prefix(p) for p in prefixes],
        "files": [
            {"path": it.path, "mode": it.mode, "blob": it.blob}
            for it in selected
        ],
    }
    if args.include_toolchain:
        manifest["toolchain"] = _tool_versions()

    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )

    # Deterministic gzip: mtime=0.
    with out_path.open("wb") as f_out:
        # NOTE: pass filename="" to avoid embedding the output file name in the gzip header.
        with gzip.GzipFile(filename="", fileobj=f_out, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                _tar_add_bytes(tf, "AUDIT_PACK_MANIFEST.json", manifest_bytes, mode=0o644)
                for it in selected:
                    _tar_add_tracked_file(tf, repo_root, it)

    if args.print_sha256:
        print(_sha256_file(out_path))

    rel = str(out_path.relative_to(repo_root)) if out_path.is_relative_to(repo_root) else str(out_path)
    print(f"OK: wrote {rel} ({len(selected)} files), head={head[:12]} dirty={dirty}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
