#!/usr/bin/env python3
"""
Generate a skeleton dev-fund premine schedule CSV for RUBIN v1.1.

No secrets are included: owner_key_id_hex is left empty and must be filled.

Controller decisions baked in:
- 1 RBN = 100_000_000 base units
- Premine total = 1_000_000 RBN, split into 100 outputs of 10_000 RBN each
- Vesting = 48 months (4 years), height-based
- days_per_year = 365, blocks_per_month = 4_380 (10-min blocks)
- Distribution: months 1..4 => 3 outputs/month; months 5..48 => 2 outputs/month
"""

from __future__ import annotations

import argparse
import csv
import sys


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="-", help="Output path or '-' for stdout")
    args = ap.parse_args(argv)

    base_units_per_rbn = 100_000_000
    per_output_rbn = 10_000
    value_base_units = per_output_rbn * base_units_per_rbn

    blocks_per_month = 4_380

    # Build (month -> count) schedule.
    month_counts: list[tuple[int, int]] = []
    for m in range(1, 49):
        month_counts.append((m, 3 if m <= 4 else 2))

    rows: list[dict[str, object]] = []
    out_index = 0
    for m, count in month_counts:
        delay = m * blocks_per_month
        for _ in range(count):
            rows.append(
                {
                    "output_index": out_index,
                    "month": m,
                    "value_base_units": value_base_units,
                    "owner_key_id_hex": "",
                    "spend_delay_blocks": delay,
                }
            )
            out_index += 1

    if len(rows) != 100:
        raise SystemExit(f"internal error: expected 100 outputs, got {len(rows)}")

    dest = sys.stdout if args.out == "-" else open(args.out, "w", newline="", encoding="utf-8")
    try:
        w = csv.DictWriter(
            dest,
            fieldnames=[
                "output_index",
                "month",
                "value_base_units",
                "owner_key_id_hex",
                "spend_delay_blocks",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(r)
    finally:
        if dest is not sys.stdout:
            dest.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

