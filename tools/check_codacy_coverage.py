#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


GO_RECORD_RE = re.compile(
    r"^(?P<path>.+):(?P<start_line>\d+)\.\d+,(?P<end_line>\d+)\.\d+ \d+ (?P<count>\d+)$"
)
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Predict Codacy coverage gates locally.")
    parser.add_argument(
        "--summary-title",
        default="Codacy coverage preflight",
        help="Header shown before the coverage summary.",
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--base-go", required=True, type=Path)
    parser.add_argument("--base-rust", required=True, type=Path)
    parser.add_argument("--head-go", required=True, type=Path)
    parser.add_argument("--head-rust", required=True, type=Path)
    parser.add_argument("--min-diff-coverage", type=float, default=85.0)
    parser.add_argument("--min-variation", type=float, default=-0.10)
    return parser.parse_args()


def read_go_module_prefix(repo_root: Path) -> str:
    go_mod = repo_root / "clients/go/go.mod"
    for line in go_mod.read_text(encoding="utf-8").splitlines():
        if line.startswith("module "):
            return line.split(None, 1)[1].strip()
    raise ValueError(f"module line not found in {go_mod}")


def normalize_go_path(repo_root: Path, raw: str, module_prefix: str) -> Path:
    module_root = f"{module_prefix}/"
    if raw.startswith(module_root):
        return (repo_root / "clients/go" / raw[len(module_root) :]).resolve()
    marker = "/clients/go/"
    if marker in raw:
        return (repo_root / "clients/go" / raw.split(marker, 1)[1]).resolve()
    return (repo_root / raw).resolve()


def parse_go_cover(path: Path, repo_root: Path, module_prefix: str) -> dict[Path, dict[int, bool]]:
    coverage: dict[Path, dict[int, bool]] = defaultdict(dict)
    lines = path.read_text(encoding="utf-8").splitlines()
    for raw in lines[1:]:
        if not raw:
            continue
        match = GO_RECORD_RE.match(raw)
        if not match:
            raise ValueError(f"unrecognized go coverage record: {raw}")
        file_path = normalize_go_path(repo_root, match.group("path"), module_prefix)
        start_line = int(match.group("start_line"))
        end_line = int(match.group("end_line"))
        covered = int(match.group("count")) > 0
        file_lines = coverage[file_path]
        for line_no in range(start_line, end_line + 1):
            file_lines[line_no] = file_lines.get(line_no, False) or covered
    return coverage


def parse_lcov(path: Path) -> dict[Path, dict[int, bool]]:
    coverage: dict[Path, dict[int, bool]] = defaultdict(dict)
    current_file: Path | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("SF:"):
            current_file = Path(raw[3:]).resolve()
            continue
        if raw.startswith("DA:") and current_file is not None:
            line_part, count_part = raw[3:].split(",", 1)
            line_no = int(line_part)
            covered = int(count_part) > 0
            file_lines = coverage[current_file]
            file_lines[line_no] = file_lines.get(line_no, False) or covered
    return coverage


def merge_coverage(*maps: dict[Path, dict[int, bool]]) -> dict[Path, dict[int, bool]]:
    merged: dict[Path, dict[int, bool]] = defaultdict(dict)
    for coverage in maps:
        for file_path, lines in coverage.items():
            dst = merged[file_path]
            for line_no, covered in lines.items():
                dst[line_no] = dst.get(line_no, False) or covered
    return merged


def coverage_totals(coverage: dict[Path, dict[int, bool]]) -> tuple[int, int]:
    coverable = 0
    covered = 0
    for lines in coverage.values():
        coverable += len(lines)
        covered += sum(1 for value in lines.values() if value)
    return coverable, covered


def coverage_percent(coverable: int, covered: int) -> float:
    if coverable == 0:
        return 100.0
    return (covered / coverable) * 100.0


def changed_lines(repo_root: Path, base_ref: str) -> dict[Path, set[int]]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "diff",
            "--no-ext-diff",
            "--find-renames",
            "--unified=0",
            f"{base_ref}...HEAD",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    changed: dict[Path, set[int]] = defaultdict(set)
    current_file: Path | None = None
    for raw in result.stdout.splitlines():
        if raw.startswith("+++ "):
            new_path = raw[4:]
            if new_path == "/dev/null":
                current_file = None
                continue
            if new_path.startswith("b/"):
                new_path = new_path[2:]
            current_file = (repo_root / new_path).resolve()
            continue
        if current_file is None:
            continue
        match = HUNK_RE.match(raw)
        if not match:
            continue
        start = int(match.group("start"))
        count = int(match.group("count") or "1")
        if count == 0:
            continue
        changed[current_file].update(range(start, start + count))
    return changed


def diff_coverage(
    head: dict[Path, dict[int, bool]], changed: dict[Path, set[int]]
) -> tuple[int, int, list[str]]:
    coverable = 0
    covered = 0
    uncovered_refs: list[str] = []
    for file_path, changed_lines_set in changed.items():
        file_lines = head.get(file_path)
        if not file_lines:
            continue
        for line_no in sorted(changed_lines_set):
            line_covered = file_lines.get(line_no)
            if line_covered is None:
                continue
            coverable += 1
            if line_covered:
                covered += 1
            else:
                uncovered_refs.append(f"{file_path}:{line_no}")
    return coverable, covered, uncovered_refs


def diff_coverage_by_file(
    head: dict[Path, dict[int, bool]], changed: dict[Path, set[int]]
) -> dict[Path, tuple[int, int, list[int]]]:
    per_file: dict[Path, tuple[int, int, list[int]]] = {}
    for file_path, changed_lines_set in changed.items():
        file_lines = head.get(file_path)
        if not file_lines:
            continue
        coverable = 0
        covered = 0
        uncovered: list[int] = []
        for line_no in sorted(changed_lines_set):
            line_covered = file_lines.get(line_no)
            if line_covered is None:
                continue
            coverable += 1
            if line_covered:
                covered += 1
            else:
                uncovered.append(line_no)
        if coverable:
            per_file[file_path] = (coverable, covered, uncovered)
    return per_file


def compress_ranges(lines: list[int]) -> list[str]:
    if not lines:
        return []
    ranges: list[str] = []
    start = prev = lines[0]
    for line_no in lines[1:]:
        if line_no == prev + 1:
            prev = line_no
            continue
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = line_no
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ranges


def print_summary(
    summary_title: str,
    repo_root: Path,
    base_ref: str,
    base_coverable: int,
    base_covered: int,
    head_coverable: int,
    head_covered: int,
    diff_coverable: int,
    diff_covered: int,
    uncovered_refs: list[str],
    per_file: dict[Path, tuple[int, int, list[int]]],
    min_variation: float,
    min_diff_coverage: float,
) -> None:
    base_pct = coverage_percent(base_coverable, base_covered)
    head_pct = coverage_percent(head_coverable, head_covered)
    variation = head_pct - base_pct
    diff_pct = coverage_percent(diff_coverable, diff_covered)

    print(summary_title)
    print(f"  base {base_ref[:12]}: {base_pct:.2f}% ({base_covered}/{base_coverable})")
    print(f"  head HEAD:      {head_pct:.2f}% ({head_covered}/{head_coverable})")
    print(f"  variation:      {variation:+.2f}%")
    print(f"  diff coverage:  {diff_pct:.2f}% ({diff_covered}/{diff_coverable})")
    print(f"  gates:          variation >= {min_variation:+.2f}%, diff >= {min_diff_coverage:.2f}%")
    if per_file:
        print("  changed files:")
        for file_path, (coverable, covered, uncovered) in sorted(
            per_file.items(),
            key=lambda item: (len(item[1][2]), str(item[0])),
            reverse=True,
        ):
            rel = file_path.resolve().relative_to(repo_root)
            pct = coverage_percent(coverable, covered)
            if uncovered:
                ranges = ", ".join(compress_ranges(uncovered[:12]))
                print(f"    - {rel}: {pct:.2f}% ({covered}/{coverable}), uncovered {ranges}")
            else:
                print(f"    - {rel}: {pct:.2f}% ({covered}/{coverable})")
    if uncovered_refs:
        print("  uncovered changed lines:")
        for ref in uncovered_refs[:20]:
            print(f"    - {ref}")


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    module_prefix = read_go_module_prefix(repo_root)

    base_coverage = merge_coverage(
        parse_go_cover(args.base_go, repo_root, module_prefix),
        parse_lcov(args.base_rust),
    )
    head_coverage = merge_coverage(
        parse_go_cover(args.head_go, repo_root, module_prefix),
        parse_lcov(args.head_rust),
    )
    base_coverable, base_covered = coverage_totals(base_coverage)
    head_coverable, head_covered = coverage_totals(head_coverage)

    changed = changed_lines(repo_root, args.base_ref)
    diff_coverable, diff_covered, uncovered_refs = diff_coverage(head_coverage, changed)
    per_file = diff_coverage_by_file(head_coverage, changed)

    print_summary(
        args.summary_title,
        repo_root,
        args.base_ref,
        base_coverable,
        base_covered,
        head_coverable,
        head_covered,
        diff_coverable,
        diff_covered,
        uncovered_refs,
        per_file,
        args.min_variation,
        args.min_diff_coverage,
    )

    base_pct = coverage_percent(base_coverable, base_covered)
    head_pct = coverage_percent(head_coverable, head_covered)
    variation = head_pct - base_pct
    diff_pct = coverage_percent(diff_coverable, diff_covered)

    failed = False
    if variation < args.min_variation:
        print(
            f"FAIL: coverage variation {variation:+.2f}% is below gate {args.min_variation:+.2f}%",
            file=sys.stderr,
        )
        failed = True
    if diff_pct < args.min_diff_coverage:
        print(
            f"FAIL: diff coverage {diff_pct:.2f}% is below gate {args.min_diff_coverage:.2f}%",
            file=sys.stderr,
        )
        failed = True
    if failed:
        return 1
    print("PASS: local coverage preflight matches Codacy gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
