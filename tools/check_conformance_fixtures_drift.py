#!/usr/bin/env python3
"""Check-only conformance fixture drift gate.

Generates the deterministic generator-owned fixture set into an isolated
temporary output directory via `clients/go/cmd/gen-conformance-fixtures
--output-dir <abs>` and compares each produced file byte-for-byte against
the corresponding file under `conformance/fixtures/`. Exits 0 when every
generated file matches its committed counterpart, exits 1 on any drift,
exits 2 on usage / environment errors. Never writes inside
`conformance/fixtures/**` and never invokes the generator without the
`--output-dir` flag, so committed fixtures are never mutated. Manual
fixture regeneration remains the authoritative path; this gate only
detects drift after the fact.
"""

from __future__ import annotations

import argparse
import filecmp
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence


COMMITTED_FIXTURES_REL = Path("conformance/fixtures")
GENERATOR_PACKAGE = "./cmd/gen-conformance-fixtures"
GO_MODULE_REL = Path("clients/go")

# Hardcoded expected generator-owned fixture set per
# rubin-protocol#1358 task body. Every entry MUST be emitted by the
# deterministic generator and MUST byte-match the committed fixture.
# Adding or removing an entry here is a deliberate scope change.
EXPECTED_FIXTURES: tuple[Path, ...] = (
    Path("CV-UTXO-BASIC.json"),
    Path("CV-MULTISIG.json"),
    Path("CV-EXT.json"),
    Path("CV-VAULT.json"),
    Path("CV-HTLC.json"),
    Path("CV-SUBSIDY.json"),
    Path("devnet/devnet-vault-create-01.json"),
    Path("devnet/devnet-htlc-claim-01.json"),
    Path("devnet/devnet-multisig-spend-01.json"),
)


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="check_conformance_fixtures_drift.py",
        description=(
            "Generate fixtures into an isolated temp dir and fail on byte "
            "drift vs committed fixtures. Never writes committed files."
        ),
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Path to the rubin-protocol repo root (default: cwd).",
    )
    parser.add_argument(
        "--keep-output-dir",
        action="store_true",
        help="Do not delete the candidate output directory on exit.",
    )
    return parser.parse_args(argv)


def run_generator(repo_root: Path, output_dir: Path) -> None:
    if not output_dir.is_absolute():
        raise RuntimeError(f"output_dir must be absolute: {output_dir}")
    cmd = [
        "go",
        "run",
        GENERATOR_PACKAGE,
        f"--output-dir={output_dir}",
    ]
    go_cwd = repo_root / GO_MODULE_REL
    if not go_cwd.is_dir():
        raise RuntimeError(f"missing Go module dir: {go_cwd}")
    completed = subprocess.run(
        cmd,
        cwd=str(go_cwd),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise RuntimeError(
            f"generator exited with code {completed.returncode}"
        )


def relative_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out.append(path.relative_to(root))
    return out


def diff_set(
    candidate_root: Path, committed_root: Path
) -> tuple[list[Path], list[Path], list[Path], list[Path], list[Path]]:
    missing_committed: list[Path] = []
    differing: list[Path] = []
    matching: list[Path] = []
    seen_in_candidate: set[Path] = set()
    for rel in relative_files(candidate_root):
        seen_in_candidate.add(rel)
        committed_path = committed_root / rel
        candidate_path = candidate_root / rel
        if not committed_path.is_file():
            missing_committed.append(rel)
            continue
        if filecmp.cmp(str(candidate_path), str(committed_path), shallow=False):
            matching.append(rel)
        else:
            differing.append(rel)
    expected_set = set(EXPECTED_FIXTURES)
    missing_candidate = sorted(expected_set - seen_in_candidate)
    extra_candidate = sorted(seen_in_candidate - expected_set)
    return missing_committed, differing, matching, missing_candidate, extra_candidate


def assert_committed_untouched(
    repo_root: Path, candidate_root: Path
) -> None:
    committed_root = (repo_root / COMMITTED_FIXTURES_REL).resolve()
    candidate_resolved = candidate_root.resolve()
    if str(candidate_resolved).startswith(str(committed_root) + os.sep):
        raise RuntimeError(
            f"candidate output {candidate_resolved} is inside committed "
            f"fixture root {committed_root}; refusing to run"
        )
    if candidate_resolved == committed_root:
        raise RuntimeError(
            f"candidate output equals committed fixture root {committed_root}; "
            f"refusing to run"
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    committed_root = repo_root / COMMITTED_FIXTURES_REL
    if not committed_root.is_dir():
        print(
            f"ERROR: committed fixtures dir not found: {committed_root}",
            file=sys.stderr,
        )
        return 2

    output_dir = Path(tempfile.mkdtemp(prefix="rubin-fixture-drift-")).resolve()
    try:
        assert_committed_untouched(repo_root, output_dir)
        run_generator(repo_root, output_dir)
        (
            missing_committed,
            differing,
            matching,
            missing_candidate,
            extra_candidate,
        ) = diff_set(output_dir, committed_root)
        expected_count = len(EXPECTED_FIXTURES)
        all_expected_matched = (
            len(matching) == expected_count
            and not missing_committed
            and not differing
            and not missing_candidate
            and not extra_candidate
        )
        if all_expected_matched:
            print(
                f"OK: conformance fixture drift check passed "
                f"({len(matching)} generator-owned files match committed)"
            )
            return 0
        if missing_candidate:
            print(
                "ERROR: candidate generator did not emit expected "
                "generator-owned fixture(s) (regression in generator output set):",
                file=sys.stderr,
            )
            for rel in missing_candidate:
                print(f"  - {rel}", file=sys.stderr)
        if extra_candidate:
            print(
                "ERROR: candidate generator emitted unexpected file(s) "
                "outside the declared generator-owned set:",
                file=sys.stderr,
            )
            for rel in extra_candidate:
                print(f"  ? {rel}", file=sys.stderr)
        if missing_committed:
            print(
                "ERROR: candidate generator produced files that are not "
                "present under conformance/fixtures/:",
                file=sys.stderr,
            )
            for rel in missing_committed:
                print(f"  + {rel}", file=sys.stderr)
        if differing:
            print(
                "ERROR: candidate fixture bytes differ from committed "
                "fixture bytes (manual regeneration required):",
                file=sys.stderr,
            )
            for rel in differing:
                print(f"  ~ {rel}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if not args.keep_output_dir:
            shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
