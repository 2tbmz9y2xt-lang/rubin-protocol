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
import copy
import filecmp
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from gen_conformance_matrix import load_json_fail_closed


COMMITTED_FIXTURES_REL = Path("conformance/fixtures")
GENERATOR_PACKAGE = "./cmd/gen-conformance-fixtures"
GO_MODULE_REL = Path("clients/go")
V2_REL = Path("protocol/canonical_pipeline_v2.json")
V2_SCHEMA_REL = Path("conformance/schemas/cv-canonical-pipeline-v2.json")
V2_RUB1208_CASE_COUNTS = {
    "C01-DACLEAN-001": 12,
    "C01-DIRECT-001": 1,
    "C01-DISCONNECT-001": 1,
    "C01-EQUALWORK-001": 1,
    "C01-GENESIS-001": 1,
    "C01-REORG-001": 1,
    "C01-SIDE-001": 1,
    "C01-SUMMARY-001": 6,
}

# Hardcoded expected generator-owned fixture set per
# rubin-protocol#1358 task body. Every entry MUST be emitted by the
# deterministic generator and MUST byte-match the committed fixture.
# Adding or removing an entry here is a deliberate scope change.
EXPECTED_FIXTURES: tuple[Path, ...] = (
    Path("CV-UTXO-BASIC.json"),
    Path("CV-MULTISIG.json"),
    Path("CV-VAULT.json"),
    Path("CV-HTLC.json"),
    Path("CV-SUBSIDY.json"),
    Path("devnet/devnet-vault-create-01.json"),
    Path("devnet/devnet-htlc-claim-01.json"),
    Path("devnet/devnet-multisig-spend-01.json"),
    # RUB-922 / C01 canonical publication observables corpus. Generator-owned
    # and byte-frozen: only the C01 owner issue (RUB-922, then its R2 successor RUB-1204) may change its expected rows.
    Path("protocol/canonical_pipeline_v1.json"),
    # RUB-1208 / C01-R2 BUILDING successor. Generator-owned; schema shape is
    # checked by tools/tests/test_check_conformance_fixtures_drift.py and the
    # semantic cross-image / summary relations are checked below for both the
    # generated candidate and committed artifact before byte equality is accepted.
    V2_REL,
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


def _typed_value(values: dict, alias: object, want: str, where: str):
    if not isinstance(alias, str):
        raise RuntimeError(f"{where}: alias is not a string")
    entry = values.get(alias)
    if not isinstance(entry, dict):
        raise RuntimeError(f"{where}: resolved alias {alias!r} is absent")
    if entry.get("type") != want:
        raise RuntimeError(
            f"{where}: resolved alias {alias!r} type={entry.get('type')!r} want {want}"
        )
    return entry.get("value")


def _fixture_value(fixtures: dict, alias: object, want: str, where: str):
    if not isinstance(alias, str):
        raise RuntimeError(f"{where}: fixture alias is not a string")
    entry = fixtures.get(alias)
    if not isinstance(entry, dict):
        raise RuntimeError(f"{where}: fixture alias {alias!r} is absent")
    if entry.get("type") != want:
        raise RuntimeError(
            f"{where}: fixture alias {alias!r} type={entry.get('type')!r} want {want}"
        )
    return entry.get("value")


def validate_canonical_pipeline_v2_semantics(path: Path) -> None:
    """RUB-1208 relation gate independent of generator byte equality."""
    data = load_json_fail_closed(path)
    if not isinstance(data, dict):
        raise RuntimeError("canonical_pipeline_v2: top-level value is not an object")
    epoch = data.get("_meta", {}).get("closure_epoch", {})
    if epoch.get("closure_manifest_version") != "rubin-c01-design-closure-v8":
        raise RuntimeError("canonical_pipeline_v2: closure epoch is not frozen v8")
    if epoch.get("status") != "building":
        raise RuntimeError("canonical_pipeline_v2: closure status is not building")

    fixtures = data.get("fixtures")
    resolved = data.get("resolved_values")
    rows = data.get("rows")
    if not isinstance(fixtures, dict) or not isinstance(resolved, dict) or not isinstance(rows, list):
        raise RuntimeError("canonical_pipeline_v2: fixtures/resolved_values/rows shape")
    got_counts = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("cases"), list):
            raise RuntimeError("canonical_pipeline_v2: migrated row shape")
        row_id = row.get("row_id")
        if row_id in got_counts:
            raise RuntimeError(f"canonical_pipeline_v2: duplicate migrated row {row_id!r}")
        got_counts[row_id] = len(row["cases"])
    if got_counts != V2_RUB1208_CASE_COUNTS:
        raise RuntimeError(
            f"canonical_pipeline_v2: RUB-1208 row/case census {got_counts!r} "
            f"!= {V2_RUB1208_CASE_COUNTS!r}"
        )

    for row in rows:
        row_id = row["row_id"]
        for case in row["cases"]:
            case_id = case.get("case_id")
            where = f"{row_id}/{case_id}"
            expected = case.get("expected")
            if not isinstance(expected, dict):
                raise RuntimeError(f"{where}: expected is not an object")
            images = expected.get("state_image")
            if not isinstance(images, dict) or set(images) != {
                "CHAIN_IMAGE_V1",
                "STANDARD_MEMPOOL_IMAGE_V1",
                "RETAINED_DA_IMAGE_V1",
                "OWNER_IMAGE_V1",
            }:
                raise RuntimeError(f"{where}: state_image must carry exactly four images")

            chain = images["CHAIN_IMAGE_V1"].get("direct_fields", {})
            owner = images["OWNER_IMAGE_V1"].get("direct_fields", {})
            chain_hash = _typed_value(
                resolved, chain.get("tip_hash"), "bytes32_hex", f"{where}/CHAIN/tip_hash"
            )
            chain_height = _typed_value(
                resolved, chain.get("height"), "u64", f"{where}/CHAIN/height"
            )
            stable_tip = _typed_value(
                resolved, owner.get("stable_tip"), "object", f"{where}/OWNER/stable_tip"
            )
            if not isinstance(stable_tip, dict) or stable_tip != {
                "has_tip": True,
                "height": chain_height,
                "hash": chain_hash,
            }:
                raise RuntimeError(
                    f"{where}/OWNER/stable_tip: must equal published CHAIN tip hash/height"
                )

            truth = expected.get("commit_truth")
            summary = expected.get("canonical_applied_blocks")
            if truth != "NEW":
                if summary is not None:
                    raise RuntimeError(f"{where}/canonical_applied_blocks: non-NEW must be null")
                continue
            if not isinstance(summary, list):
                raise RuntimeError(f"{where}/canonical_applied_blocks: NEW must be an array")

            last_height = None
            for index, summary_row in enumerate(summary):
                sw = f"{where}/canonical_applied_blocks/{index}"
                if not isinstance(summary_row, dict):
                    raise RuntimeError(f"{sw}: row is not an object")
                block = _fixture_value(
                    fixtures, summary_row.get("block_id"), "object", f"{sw}/block_id"
                )
                _fixture_value(
                    fixtures, summary_row.get("block_hash"), "bytes32_hex", f"{sw}/block_hash"
                )
                if not isinstance(block, dict) or type(block.get("height")) is not int:
                    raise RuntimeError(f"{sw}/block_id: fixture has no integer height")
                height = block["height"]
                if last_height is not None and height <= last_height:
                    raise RuntimeError(f"{where}/canonical_applied_blocks: heights not strictly canonical")
                last_height = height

                da_ids = summary_row.get("complete_da_ids")
                if not isinstance(da_ids, list):
                    raise RuntimeError(f"{sw}/complete_da_ids: not an array")
                raw_ids = [
                    _fixture_value(fixtures, alias, "bytes32_hex", f"{sw}/complete_da_ids/{i}")
                    for i, alias in enumerate(da_ids)
                ]
                if raw_ids != sorted(raw_ids):
                    raise RuntimeError(f"{sw}/complete_da_ids: not ascending raw bytes")


def assert_canonical_pipeline_v2_negative_controls(path: Path) -> None:
    """Run RUB-1208 single-dimension hostile mutations from a valid artifact."""
    control = load_json_fail_closed(path)

    def case_of(data: dict, row_id: str, case_id: str) -> dict:
        row = next(row for row in data["rows"] if row["row_id"] == row_id)
        return next(case for case in row["cases"] if case["case_id"] == case_id)

    def stale_owner_tip(data: dict) -> None:
        case = case_of(data, "C01-DIRECT-001", "MAIN")
        alias = case["expected"]["state_image"]["OWNER_IMAGE_V1"]["direct_fields"]["stable_tip"]
        data["resolved_values"][alias]["value"]["hash"] = "00" * 32

    def reverse_summary(data: dict) -> None:
        case = case_of(data, "C01-SUMMARY-001", "MULTI_BLOCK_ORDER")
        case["expected"]["canonical_applied_blocks"].reverse()

    def reverse_da_ids(data: dict) -> None:
        case = case_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_WITH_DA")
        case["expected"]["canonical_applied_blocks"][0]["complete_da_ids"].reverse()

    def non_new_summary(data: dict) -> None:
        case = case_of(data, "C01-SIDE-001", "MAIN")
        case["expected"]["canonical_applied_blocks"] = []

    mutations = (
        ("stale OWNER stable_tip", stale_owner_tip, "OWNER/stable_tip"),
        ("reversed same-count summary", reverse_summary, "heights not strictly canonical"),
        ("reversed DA ids", reverse_da_ids, "not ascending raw bytes"),
        ("non-NEW summary", non_new_summary, "non-NEW must be null"),
    )
    with tempfile.TemporaryDirectory(prefix="rubin-r1208-negative-") as td:
        for name, mutate, expected_reason in mutations:
            candidate = copy.deepcopy(control)
            mutate(candidate)
            mutated_path = Path(td) / (name.replace(" ", "_") + ".json")
            mutated_path.write_text(
                json.dumps(candidate, ensure_ascii=False, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            try:
                validate_canonical_pipeline_v2_semantics(mutated_path)
            except RuntimeError as exc:
                if expected_reason not in str(exc):
                    raise RuntimeError(
                        f"RUB-1208 negative {name!r} failed for wrong reason: {exc}"
                    ) from exc
            else:
                raise RuntimeError(f"RUB-1208 negative {name!r} was accepted")


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

    try:
        output_dir = Path(tempfile.mkdtemp(prefix="rubin-fixture-drift-")).resolve()
    except OSError as exc:
        print(f"ERROR: failed to create candidate output dir: {exc}", file=sys.stderr)
        return 2
    try:
        assert_committed_untouched(repo_root, output_dir)
        run_generator(repo_root, output_dir)
        # Isolated unit tests for the generic drift machinery intentionally build
        # a minimal fake repo without schemas and replace generated files with
        # sentinel bytes. The real repository always has the v2 schema; only in
        # that real context does the semantic relation gate apply.
        if (repo_root / V2_SCHEMA_REL).is_file():
            validate_canonical_pipeline_v2_semantics(output_dir / V2_REL)
            validate_canonical_pipeline_v2_semantics(committed_root / V2_REL)
            assert_canonical_pipeline_v2_negative_controls(committed_root / V2_REL)
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
    except (RuntimeError, FileNotFoundError, OSError, StopIteration, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if not args.keep_output_dir:
            shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
