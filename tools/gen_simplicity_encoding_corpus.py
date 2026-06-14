#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance/fixtures/protocol/simplicity_program_encoding_corpus_v1.json"


def vector(
    vector_id: str,
    program_hex: str,
    *,
    witness_hex: str = "",
    semantics_version: int = 1,
    covenant_cmr_hex: str = "",
    expected_cmr_hex: str = "",
    expected_error: str = "",
    zero_tail_bytes: int = 0,
) -> dict[str, object]:
    item: dict[str, object] = {
        "id": vector_id,
        "program_hex": program_hex + ("00" * zero_tail_bytes),
        "semantics_version": semantics_version,
        "witness_hex": witness_hex,
    }
    if covenant_cmr_hex:
        item["covenant_cmr_hex"] = covenant_cmr_hex
    if expected_cmr_hex:
        item["expected_cmr_hex"] = expected_cmr_hex
    if expected_error:
        item["expected_error"] = expected_error
    return item


CASES = [
    vector("VEC-PE-001", "24", expected_cmr_hex="c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7"),
    vector("VEC-PE-002", "c1220f0100", expected_cmr_hex="afeae8c18903b9e0aae2c125f31f7b8e09de916e461f221936b633d587c1b434"),
    vector("VEC-PE-003", "8900", expected_cmr_hex="d296a48e538af38908242ab30244036fdb66e9056d5f812a5b328fae2b6a2726"),
    vector("VEC-PE-004A", "c1d21014", witness_hex="00", covenant_cmr_hex="d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83", expected_cmr_hex="d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83"),
    vector("VEC-PE-004B", "c1d21014", witness_hex="80", expected_cmr_hex="d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83"),
    vector("VEC-PE-005", "60", expected_cmr_hex="3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637"),
    vector("VEC-PE-006", "70", expected_cmr_hex="f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941"),
    vector("VEC-PE-007", "24", semantics_version=2, expected_error="TX_ERR_SIMPLICITY_DECODE"),
    vector("VEC-PE-008", "25", expected_error="TX_ERR_SIMPLICITY_DECODE"),
    vector("VEC-PE-009", "24", zero_tail_bytes=16_384, expected_error="TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE"),
    vector("VEC-PE-010", "24", covenant_cmr_hex="0000000000000000000000000000000000000000000000000000000000000000", expected_error="TX_ERR_SIMPLICITY_CMR_MISMATCH"),
    vector("VEC-PE-011", "28", zero_tail_bytes=64, expected_error="TX_ERR_SIMPLICITY_DECODE"),
    vector("VEC-PE-012", "8958", expected_error="TX_ERR_SIMPLICITY_DECODE"),
    vector("VEC-PE-013", "7c0680", expected_error="TX_ERR_SIMPLICITY_JET_DISALLOWED"),
    vector("VEC-PE-014", "c1d21014", expected_error="TX_ERR_SIMPLICITY_DECODE"),
    vector("VEC-PE-015", "c1d21014", witness_hex="01", expected_error="TX_ERR_SIMPLICITY_DECODE"),
    vector("VEC-PE-016", "c1d21014", witness_hex="0000", expected_error="TX_ERR_SIMPLICITY_DECODE"),
    vector("VEC-PE-017", "2400", expected_error="TX_ERR_SIMPLICITY_DECODE"),
    vector("VEC-PE-018", "24", zero_tail_bytes=16_383, expected_error="TX_ERR_SIMPLICITY_DECODE"),
]


def corpus_bytes() -> bytes:
    payload = {
        "contract_version": 1,
        "fixture_kind": "simplicity_program_encoding_cmr_v1",
        "description": "Generator-owned shared corpus for RUB-484 Go/Rust Simplicity encoding and CMR parity tests.",
        "cases": CASES,
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the committed corpus bytes differ")
    args = parser.parse_args()
    data = corpus_bytes()
    if args.check:
        try:
            got = OUT.read_bytes()
        except OSError as exc:
            print(f"ERROR: read committed corpus: {exc}", file=sys.stderr)
            return 1
        if got != data:
            print(f"ERROR: {OUT.relative_to(ROOT)} is stale; rerun this generator", file=sys.stderr)
            return 1
        print("OK: Simplicity encoding corpus matches generator")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(data)
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
