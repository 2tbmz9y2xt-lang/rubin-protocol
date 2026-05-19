#!/usr/bin/env python3
"""Run the Rubin production duplication gate with pinned jscpd settings."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_JSCPD_PACKAGE = "jscpd@4.2.3"
DEFAULT_SOURCE_PATHS = (
    "clients/go/consensus",
    "clients/rust/crates/rubin-consensus/src",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_config(root: Path) -> dict[str, Any]:
    config_path = root / ".jscpd.json"
    with config_path.open("r", encoding="utf-8") as fh:
        config = json.load(fh)
    if not isinstance(config, dict):
        raise ValueError(".jscpd.json must contain a JSON object")
    return config


def total_stats(report_path: Path) -> dict[str, Any]:
    with report_path.open("r", encoding="utf-8") as fh:
        report = json.load(fh)
    total = report.get("statistics", {}).get("total")
    if not isinstance(total, dict):
        raise ValueError(f"{report_path} does not contain statistics.total")
    duplicates = report.get("duplicates")
    if not isinstance(duplicates, list):
        raise ValueError(f"{report_path} does not contain duplicates list")
    total["duplicates"] = duplicates
    return total


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default="/tmp/rubin-jscpd-production-report",
        help="Directory for the jscpd JSON report.",
    )
    parser.add_argument(
        "--jscpd-package",
        default=DEFAULT_JSCPD_PACKAGE,
        help="Pinned npm package spec used by npx.",
    )
    parser.add_argument(
        "--strict-zero-clones",
        action="store_true",
        help="Fail on any clone, even when duplicated percentage is under threshold.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(DEFAULT_SOURCE_PATHS),
        help="Source paths to scan. Defaults to production Go/Rust consensus surfaces.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root()
    config = load_config(root)
    output_dir = Path(args.output).expanduser().resolve()
    shutil.rmtree(output_dir, ignore_errors=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as fh:
        json.dump(config, fh, indent=2, sort_keys=True)
        fh.write("\n")
        temp_config = Path(fh.name)

    cmd = [
        "npx",
        "--yes",
        args.jscpd_package,
        "--config",
        str(temp_config),
        "--reporters",
        "console,json",
        "--output",
        str(output_dir),
        *args.paths,
    ]

    try:
        completed = subprocess.run(cmd, cwd=root, check=False)
        report_path = output_dir / "jscpd-report.json"
        if not report_path.exists():
            print(f"FAIL: jscpd did not write {report_path}", file=sys.stderr)
            return completed.returncode or 1
        total = total_stats(report_path)
        clone_count = int(total.get("clones", 0))
        percentage = float(total.get("percentage", 0))
        token_percentage = float(total.get("percentageTokens", 0))
        print(
            "RUBIN DUPLICATION GATE: "
            f"clones={clone_count}, duplicated_lines={total.get('duplicatedLines', 0)}, "
            f"percentage={percentage:.2f}%, token_percentage={token_percentage:.2f}%"
        )
        print(f"Report: {report_path}")
        if args.strict_zero_clones and clone_count != 0:
            print("FAIL: strict zero-clone mode found clones", file=sys.stderr)
            return 1
        return completed.returncode
    finally:
        temp_config.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
