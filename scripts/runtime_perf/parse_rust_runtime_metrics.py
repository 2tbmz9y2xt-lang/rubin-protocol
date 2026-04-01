#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


TARGETS = [
    "rubin_node_txpool/admit",
    "rubin_node_txpool/relay_metadata",
    "rubin_node_chainstate_clone",
    "rubin_node_sync_chain_state_snapshot",
    "rubin_node_sync/apply_genesis",
    "rubin_node_sync/disconnect_tip_after_genesis",
    "rubin_node_undo/build_large_block",
    "rubin_node_undo/disconnect_large_block",
    "rubin_node_miner_mine_one",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse Criterion runtime benchmark estimates.")
    parser.add_argument("--criterion-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    criterion_root = Path(args.criterion_root)
    output_path = Path(args.output)
    metrics: dict[str, dict[str, float]] = {}
    missing: list[str] = []

    for name in TARGETS:
        estimates_path = criterion_root / name / "new" / "estimates.json"
        if not estimates_path.exists():
            missing.append(name)
            continue
        doc = json.loads(estimates_path.read_text(encoding="utf-8", errors="strict"))
        metrics[name] = {
            "ns_per_op": float(doc["mean"]["point_estimate"]),
            "lower_bound": float(doc["mean"]["confidence_interval"]["lower_bound"]),
            "upper_bound": float(doc["mean"]["confidence_interval"]["upper_bound"]),
        }

    if not metrics:
        raise SystemExit("ERROR: no Rust runtime criterion estimates found")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"suite": "rust", "metrics": metrics, "missing": missing}, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
