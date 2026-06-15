#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENCODING_OUT = ROOT / "conformance/fixtures/protocol/simplicity_program_encoding_corpus_v1.json"
EXEC_OUT = ROOT / "conformance/fixtures/protocol/simplicity_exec_corpus_v1.json"


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


MAX_EXEC_COST = 400_000
MAX_FRAME_BITS = 65_536 * 8


EXEC_CASES = [
    {"id": "VEC-SE-001", "program_hex": "24", "expected_accepted": True, "expected_final_counter": 1},
    {"id": "VEC-SE-002", "program_hex": "8900", "expected_accepted": True, "expected_final_counter": 2},
    {"id": "VEC-SE-003", "program_hex": "c1220f0100", "expected_accepted": True, "expected_final_counter": 4},
    {"id": "VEC-SE-004", "program_hex": "c1d21014", "witness_hex": "00", "expected_accepted": True, "expected_final_counter": 4},
    {"id": "VEC-SE-005", "program_hex": "c1d21014", "witness_hex": "80", "expected_accepted": True, "expected_final_counter": 4},
    {"id": "VEC-SE-010", "program_hex": "60", "jet_accepted": True, "jet_cost": MAX_EXEC_COST, "expected_accepted": True, "expected_final_counter": MAX_EXEC_COST},
    {"id": "VEC-SE-011", "program_hex": "60", "jet_accepted": True, "jet_cost": MAX_EXEC_COST + 1, "expected_accepted": True, "expected_error": "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED", "expected_final_counter": MAX_EXEC_COST},
    {"id": "VEC-SE-012", "program_hex": "60", "jet_cost": 3, "expected_accepted": False, "expected_error": "TX_ERR_SIMPLICITY_REJECTED", "expected_final_counter": 3},
    {"id": "VEC-SE-020", "eval_steps": 1, "frame_bit_widths": [MAX_FRAME_BITS], "expected_accepted": True, "expected_final_counter": 1},
    {"id": "VEC-SE-021", "eval_steps": 1, "frame_bit_widths": [MAX_FRAME_BITS + 1], "expected_accepted": False, "expected_error": "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED", "expected_final_counter": 0},
    {"id": "VEC-SE-022", "eval_steps": 1, "frame_bit_widths": ([MAX_FRAME_BITS] * 16) + [8], "expected_accepted": False, "expected_error": "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED", "expected_final_counter": 0},
    {"id": "VEC-SE-030A", "program_hex": "24", "expected_accepted": True, "expected_final_counter": 1},
    {"id": "VEC-SE-030B", "program_hex": "24", "expected_accepted": True, "expected_final_counter": 1},
]


def corpus_bytes(fixture_kind: str, description: str, cases: list[dict[str, object]]) -> bytes:
    payload = {
        "contract_version": 1,
        "fixture_kind": fixture_kind,
        "description": description,
        "cases": cases,
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


ARTIFACTS = (
    (ENCODING_OUT, "simplicity_program_encoding_cmr_v1", "Generator-owned shared corpus for RUB-484 Go/Rust Simplicity encoding and CMR parity tests.", CASES),
    (EXEC_OUT, "simplicity_exec_corpus_v1", "Generator-owned shared corpus for RUB-488 Go/Rust Simplicity execution parity tests.", EXEC_CASES),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed corpus bytes differ")
    args = parser.parse_args()
    if args.check:
        for out, fixture_kind, description, cases in ARTIFACTS:
            if not out.exists():
                print(
                    f"ERROR: missing {out.relative_to(ROOT)}; run tools/gen_simplicity_encoding_corpus.py to (re)generate",
                    file=sys.stderr,
                )
                return 1
            if out.read_bytes() != corpus_bytes(fixture_kind, description, cases):
                print(f"ERROR: {out.relative_to(ROOT)} is stale; rerun this generator", file=sys.stderr)
                return 1
        print("OK: Simplicity corpora match generator")
        return 0
    for out, fixture_kind, description, cases in ARTIFACTS:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(corpus_bytes(fixture_kind, description, cases))
        print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
