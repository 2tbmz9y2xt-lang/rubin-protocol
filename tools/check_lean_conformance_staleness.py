#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


GENERATOR_MARKER = "tools/formal/gen_lean_conformance_vectors.py"


def generated_vector_files(conformance_dir: Path) -> set[Path]:
    out: set[Path] = set()
    for path in conformance_dir.glob("*.lean"):
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        if GENERATOR_MARKER in text:
            out.add(path)
    return out


def snapshot(paths: set[Path]) -> dict[Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in paths if path.exists()}


def restore(paths: set[Path], before: dict[Path, str]) -> None:
    for path in paths:
        original = before.get(path)
        if original is None:
            if path.exists():
                path.unlink()
            continue
        path.write_text(original, encoding="utf-8")


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    conformance_dir = repo_root / "rubin-formal" / "RubinFormal" / "Conformance"
    generator = repo_root / "tools" / "formal" / "gen_lean_conformance_vectors.py"

    before_paths = generated_vector_files(conformance_dir)
    before = snapshot(before_paths)

    proc = subprocess.run(
        [sys.executable, str(generator), "--repo-root", str(repo_root)],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )

    after_paths = generated_vector_files(conformance_dir)
    tracked_paths = before_paths | after_paths
    stale = sorted(
        path.relative_to(repo_root).as_posix()
        for path in tracked_paths
        if before.get(path) != (path.read_text(encoding="utf-8") if path.exists() else None)
    )
    restore(tracked_paths, before)

    if proc.returncode != 0:
        if proc.stdout:
            sys.stdout.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        return proc.returncode
    if stale:
        print("ERROR: stale Lean conformance vectors detected:")
        for rel in stale:
            print(f" - {rel}")
        return 1
    print(f"OK: Lean conformance vectors are up to date ({len(tracked_paths)} files checked).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
