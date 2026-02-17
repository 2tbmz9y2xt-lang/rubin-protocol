#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from run_cv_common import load_yaml


def run_unimplemented(gate: str, reason: str) -> int:
    parser = argparse.ArgumentParser(description=f"Run {gate} conformance placeholder.")
    parser.add_argument(
        "--fixture",
        default=None,
        help=f"Path to {gate}.yml (default: repo/conformance/fixtures/{gate}.yml)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    fixture_path = (
        Path(args.fixture).resolve()
        if args.fixture
        else repo_root / "conformance" / "fixtures" / f"{gate}.yml"
    )
    fixture = load_yaml(fixture_path)
    if fixture.get("gate") != gate:
        print(f"invalid gate in fixture: {fixture_path}")
        return 1
    print(f"{gate}: NOT RUN (runner shell added)")
    print(f"reason: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_unimplemented("CV-PLACEHOLDER", "not configured"))
