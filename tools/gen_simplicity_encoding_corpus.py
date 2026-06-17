#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENCODING_OUT = ROOT / "conformance/fixtures/protocol/simplicity_program_encoding_corpus_v1.json"
EXEC_OUT = ROOT / "conformance/fixtures/protocol/simplicity_exec_corpus_v1.json"
CV_EXEC_OUT = ROOT / "conformance/fixtures/CV-SIMPLICITY-EXEC.json"
CRYPTO_JETS_OUT = ROOT / "conformance/fixtures/protocol/simplicity_crypto_jets_corpus_v1.json"
DATA_JETS_OUT = ROOT / "conformance/fixtures/protocol/simplicity_data_jets_corpus_v1.json"
JETS_REGISTRY_OUT = ROOT / "conformance/fixtures/protocol/simplicity_jets_registry_corpus_v1.json"


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
MLDSA87_PUBKEY_BYTES = 2_592
MLDSA87_SIG_BYTES = 4_627
MLDSA87_VERIFY_JET_COST = 50_000


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


CV_EXEC_CASES = [
    {"id": "CV-SE-PE-001", "program_hex": "24", "expect_ok": True, "expect_accepted": True, "expect_final_counter": 1},
    {"id": "CV-SE-PE-002", "program_hex": "c1220f0100", "expect_ok": True, "expect_accepted": True, "expect_final_counter": 4},
    {"id": "CV-SE-PE-003", "program_hex": "8900", "expect_ok": True, "expect_accepted": True, "expect_final_counter": 2},
    {"id": "CV-SE-PE-004A", "program_hex": "c1d21014", "witness_hex": "00", "covenant_cmr_hex": "d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83", "expect_ok": True, "expect_accepted": True, "expect_final_counter": 4},
    {"id": "CV-SE-PE-004B", "program_hex": "c1d21014", "witness_hex": "80", "expect_ok": True, "expect_accepted": True, "expect_final_counter": 4},
    {"id": "CV-SE-PE-005", "program_hex": "60", "jet_accepted": True, "jet_cost": 64, "expect_ok": True, "expect_accepted": True, "expect_final_counter": 64},
    {"id": "CV-SE-PE-006", "program_hex": "70", "jet_accepted": True, "jet_cost": MLDSA87_VERIFY_JET_COST, "expect_ok": True, "expect_accepted": True, "expect_final_counter": MLDSA87_VERIFY_JET_COST},
    {"id": "CV-SE-PE-007", "program_hex": "24", "semantics_version": 2, "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-PE-008", "program_hex": "25", "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-PE-009", "program_hex": "24" + ("00" * 16_384), "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE"},
    {"id": "CV-SE-PE-010", "program_hex": "24", "covenant_cmr_hex": "00" * 32, "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_CMR_MISMATCH"},
    {"id": "CV-SE-PE-011", "program_hex": "28" + ("00" * 64), "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-PE-012", "program_hex": "8958", "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-PE-013", "program_hex": "7c0680", "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_JET_DISALLOWED"},
    {"id": "CV-SE-PE-014", "program_hex": "c1d21014", "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-PE-015", "program_hex": "c1d21014", "witness_hex": "01", "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-PE-016", "program_hex": "c1d21014", "witness_hex": "0000", "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-PE-017", "program_hex": "2400", "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-PE-018", "program_hex": "24" + ("00" * 16_383), "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_DECODE"},
    {"id": "CV-SE-EXEC-001", "program_hex": "60", "jet_accepted": True, "jet_cost": MAX_EXEC_COST, "expect_ok": True, "expect_accepted": True, "expect_final_counter": MAX_EXEC_COST},
    {"id": "CV-SE-EXEC-002", "program_hex": "60", "jet_accepted": True, "jet_cost": MAX_EXEC_COST + 1, "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED", "expect_accepted": True, "expect_final_counter": MAX_EXEC_COST},
    {"id": "CV-SE-EXEC-003", "program_hex": "60", "jet_accepted": False, "jet_cost": 3, "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_REJECTED", "expect_accepted": False, "expect_final_counter": 3},
    {"id": "CV-SE-MEM-001", "eval_steps": 1, "frame_bit_widths": [MAX_FRAME_BITS], "expect_ok": True, "expect_accepted": True, "expect_final_counter": 1},
    {"id": "CV-SE-MEM-002", "eval_steps": 1, "frame_bit_widths": [MAX_FRAME_BITS + 1], "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED", "expect_accepted": False, "expect_final_counter": 0},
    {"id": "CV-SE-MEM-003", "eval_steps": 1, "frame_bit_widths": ([MAX_FRAME_BITS] * 16) + [8], "expect_ok": False, "expect_err": "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED", "expect_accepted": False, "expect_final_counter": 0},
    {"id": "CV-SE-REPEAT-001", "program_hex": "24", "expect_ok": True, "expect_accepted": True, "expect_final_counter": 1},
    {"id": "CV-SE-REPEAT-002", "program_hex": "24", "expect_ok": True, "expect_accepted": True, "expect_final_counter": 1},
]


def sha3_case(vector_id: str, message: bytes) -> dict[str, object]:
    return {
        "id": vector_id,
        "jet": "sha3_256",
        "message_hex": message.hex(),
        "expected_digest_hex": hashlib.sha3_256(message).hexdigest(),
        "expected_cost": 64 + len(message),
    }


def mldsa87_case(
    vector_id: str,
    digest: bytes | str,
    pubkey_len: int,
    signature_len: int,
    verifier_result: bool,
    expected_verified: bool,
    expect_verifier_called: bool,
    *,
    expected_error: str = "",
) -> dict[str, object]:
    item: dict[str, object] = {
        "id": vector_id,
        "jet": "mldsa87_verify",
        "digest_hex": digest if isinstance(digest, str) else hashlib.sha3_256(digest).hexdigest(),
        "pubkey_len": pubkey_len,
        "signature_len": signature_len,
        "verifier_result": verifier_result,
        "expected_verified": expected_verified,
        "expected_cost": MLDSA87_VERIFY_JET_COST,
        "expect_verifier_called": expect_verifier_called,
    }
    if expected_error:
        item["expected_error"] = expected_error
    return item


CRYPTO_JET_CASES = [
    sha3_case("VEC-SCJ-001", b""),
    sha3_case("VEC-SCJ-002", b"abc"),
    sha3_case("VEC-SCJ-003", bytes([0xA5]) * 65),
    mldsa87_case("VEC-SCJ-100", b"simplicity mldsa87_verify", MLDSA87_PUBKEY_BYTES, MLDSA87_SIG_BYTES, True, True, True),
    mldsa87_case("VEC-SCJ-101", b"simplicity wrong digest", MLDSA87_PUBKEY_BYTES, MLDSA87_SIG_BYTES, False, False, True),
    mldsa87_case("VEC-SCJ-102", "00" * 32, MLDSA87_PUBKEY_BYTES - 1, MLDSA87_SIG_BYTES, True, False, False),
    mldsa87_case("VEC-SCJ-103", "11" * 32, MLDSA87_PUBKEY_BYTES, MLDSA87_SIG_BYTES + 1, True, False, False),
    mldsa87_case("VEC-SCJ-104", "22" * 32, MLDSA87_PUBKEY_BYTES, MLDSA87_SIG_BYTES, False, False, True, expected_error="TX_ERR_SIMPLICITY_DECODE"),
]


U64_MAX = (1 << 64) - 1
DATA_JET_BYTES_CHUNK_SIZE = 32
DATA_JET_MAX_SLICE_COST = 1 + (
    (U64_MAX + DATA_JET_BYTES_CHUNK_SIZE - 1) // DATA_JET_BYTES_CHUNK_SIZE
)


DATA_JET_INPUT_DEFAULTS = {
    "u64_checked_add": {"a_u64": 0, "b_u64": 0},
    "u64_checked_sub": {"a_u64": 0, "b_u64": 0},
    "u64_checked_mul": {"a_u64": 0, "b_u64": 0},
    "u64_cmp": {"a_u64": 0, "b_u64": 0},
    "u128_checked_add": {"a_u128_hi": 0, "a_u128_lo": 0, "b_u128_hi": 0, "b_u128_lo": 0},
    "u128_checked_sub": {"a_u128_hi": 0, "a_u128_lo": 0, "b_u128_hi": 0, "b_u128_lo": 0},
    "u128_cmp": {"a_u128_hi": 0, "a_u128_lo": 0, "b_u128_hi": 0, "b_u128_lo": 0},
    "bytes_eq": {"bytes_a_hex": "", "bytes_b_hex": ""},
    "bytes_cmp": {"bytes_a_hex": "", "bytes_b_hex": ""},
    "bytes_slice": {"source_hex": "", "start": 0, "length": 0},
}


def data_jet_case(vector_id: str, jet: str, **fields: object) -> dict[str, object]:
    item: dict[str, object] = {"id": vector_id, "jet": jet}
    item.update(DATA_JET_INPUT_DEFAULTS[jet])
    item.update(fields)
    return item


DATA_JET_CASES = [
    data_jet_case("VEC-SDJ-001", "u64_checked_add", a_u64=2, b_u64=3, expected_accepted=True, expected_u64=5, expected_cost=1),
    data_jet_case("VEC-SDJ-002", "u64_checked_add", a_u64=U64_MAX, b_u64=1, expected_accepted=False, expected_u64=0, expected_cost=1),
    data_jet_case("VEC-SDJ-003", "u64_checked_sub", a_u64=5, b_u64=3, expected_accepted=True, expected_u64=2, expected_cost=1),
    data_jet_case("VEC-SDJ-004", "u64_checked_sub", a_u64=3, b_u64=5, expected_accepted=False, expected_u64=0, expected_cost=1),
    data_jet_case("VEC-SDJ-005", "u64_checked_mul", a_u64=7, b_u64=6, expected_accepted=True, expected_u64=42, expected_cost=1),
    data_jet_case("VEC-SDJ-006", "u64_checked_mul", a_u64=1 << 63, b_u64=2, expected_accepted=False, expected_u64=0, expected_cost=1),
    data_jet_case("VEC-SDJ-010", "u64_cmp", a_u64=1, b_u64=2, expected_ordering=-1, expected_cost=1),
    data_jet_case("VEC-SDJ-011", "u64_cmp", a_u64=2, b_u64=2, expected_ordering=0, expected_cost=1),
    data_jet_case("VEC-SDJ-012", "u64_cmp", a_u64=3, b_u64=2, expected_ordering=1, expected_cost=1),
    data_jet_case("VEC-SDJ-020", "u128_checked_add", a_u128_lo=U64_MAX, b_u128_lo=1, expected_accepted=True, expected_u128_hi=1, expected_u128_lo=0, expected_cost=1),
    data_jet_case("VEC-SDJ-021", "u128_checked_add", a_u128_hi=U64_MAX, a_u128_lo=U64_MAX, b_u128_lo=1, expected_accepted=False, expected_u128_hi=0, expected_u128_lo=0, expected_cost=1),
    data_jet_case("VEC-SDJ-022", "u128_checked_sub", a_u128_hi=1, b_u128_lo=1, expected_accepted=True, expected_u128_hi=0, expected_u128_lo=U64_MAX, expected_cost=1),
    data_jet_case("VEC-SDJ-023", "u128_checked_sub", b_u128_lo=1, expected_accepted=False, expected_u128_hi=0, expected_u128_lo=0, expected_cost=1),
    data_jet_case("VEC-SDJ-030", "u128_cmp", a_u128_hi=1, b_u128_hi=2, expected_ordering=-1, expected_cost=1),
    data_jet_case("VEC-SDJ-031", "u128_cmp", a_u128_hi=2, a_u128_lo=3, b_u128_hi=2, b_u128_lo=3, expected_ordering=0, expected_cost=1),
    data_jet_case("VEC-SDJ-032", "u128_cmp", a_u128_hi=2, a_u128_lo=4, b_u128_hi=2, b_u128_lo=3, expected_ordering=1, expected_cost=1),
    data_jet_case("VEC-SDJ-040", "bytes_eq", bytes_a_hex="", bytes_b_hex="", expected_bool=True, expected_cost=1),
    data_jet_case("VEC-SDJ-041", "bytes_eq", bytes_a_hex="11" * 33, bytes_b_hex="11" * 32, expected_bool=False, expected_cost=3),
    data_jet_case("VEC-SDJ-050", "bytes_cmp", bytes_a_hex="ff", bytes_b_hex="01", expected_ordering=1, expected_cost=2),
    data_jet_case("VEC-SDJ-051", "bytes_cmp", bytes_a_hex="6162", bytes_b_hex="616263", expected_ordering=-1, expected_cost=2),
    data_jet_case("VEC-SDJ-052", "bytes_cmp", bytes_a_hex="616263", bytes_b_hex="6162", expected_ordering=1, expected_cost=2),
    data_jet_case("VEC-SDJ-053", "bytes_cmp", bytes_a_hex="616263", bytes_b_hex="616263", expected_ordering=0, expected_cost=2),
    data_jet_case("VEC-SDJ-060", "bytes_slice", source_hex="616263646566", start=2, length=3, expected_accepted=True, expected_bytes_hex="636465", expected_cost=2),
    data_jet_case("VEC-SDJ-061", "bytes_slice", source_hex="616263646566", start=6, length=0, expected_accepted=True, expected_bytes_hex="", expected_cost=1),
    data_jet_case("VEC-SDJ-062", "bytes_slice", source_hex="616263646566", start=5, length=2, expected_accepted=False, expected_bytes_hex="", expected_cost=2),
    data_jet_case("VEC-SDJ-063", "bytes_slice", source_hex="616263646566", start=U64_MAX, length=1, expected_accepted=False, expected_bytes_hex="", expected_cost=2),
    data_jet_case("VEC-SDJ-064", "bytes_slice", source_hex="", start=0, length=U64_MAX, expected_accepted=False, expected_bytes_hex="", expected_cost=DATA_JET_MAX_SLICE_COST),
]


JETS_REGISTRY_HASH_HEX = "5aee78aae6b610a3eb3c05bd1487523e318418e0419de48e4fe9555b37f1c059"

JETS_REGISTRY_CASES = [
    {"id": "VEC-SJR-001", "jet_id": 0x0001, "sub_op": 0x00, "name": "sha3_256", "signature": "bytes -> bytes32", "expected_present": True},
    {"id": "VEC-SJR-002", "jet_id": 0x0002, "sub_op": 0x00, "name": "mldsa87_verify", "signature": "(pubkey:bytes, sig:bytes, digest32:bytes32) -> bool", "expected_present": True},
    {"id": "VEC-SJR-003", "jet_id": 0x0010, "sub_op": 0x00, "name": "u64_checked_add", "signature": "(u64, u64) -> Either<unit, u64>", "expected_present": True},
    {"id": "VEC-SJR-004", "jet_id": 0x0010, "sub_op": 0x01, "name": "u64_checked_sub", "signature": "(u64, u64) -> Either<unit, u64>", "expected_present": True},
    {"id": "VEC-SJR-005", "jet_id": 0x0010, "sub_op": 0x02, "name": "u64_checked_mul", "signature": "(u64, u64) -> Either<unit, u64>", "expected_present": True},
    {"id": "VEC-SJR-006", "jet_id": 0x0010, "sub_op": 0x03, "name": "u64_cmp", "signature": "(u64, u64) -> ordering", "expected_present": True},
    {"id": "VEC-SJR-007", "jet_id": 0x0011, "sub_op": 0x00, "name": "u128_checked_add", "signature": "(u128, u128) -> Either<unit, u128>", "expected_present": True},
    {"id": "VEC-SJR-008", "jet_id": 0x0011, "sub_op": 0x01, "name": "u128_checked_sub", "signature": "(u128, u128) -> Either<unit, u128>", "expected_present": True},
    {"id": "VEC-SJR-009", "jet_id": 0x0011, "sub_op": 0x03, "name": "u128_cmp", "signature": "(u128, u128) -> ordering", "expected_present": True},
    {"id": "VEC-SJR-010", "jet_id": 0x0020, "sub_op": 0x00, "name": "bytes_eq", "signature": "(bytes, bytes) -> bool", "expected_present": True},
    {"id": "VEC-SJR-011", "jet_id": 0x0020, "sub_op": 0x01, "name": "bytes_cmp", "signature": "(bytes, bytes) -> ordering", "expected_present": True},
    {"id": "VEC-SJR-012", "jet_id": 0x0021, "sub_op": 0x00, "name": "bytes_slice", "signature": "(src:bytes, start:u64, len:u64) -> Either<unit, bytes>", "expected_present": True},
    {"id": "VEC-SJR-900", "jet_id": 0x0011, "sub_op": 0x02, "program_hex": "7c0680", "expected_present": False, "expected_error": "TX_ERR_SIMPLICITY_JET_DISALLOWED"},
]


def corpus_bytes(fixture_kind: str, description: str, cases: list[dict[str, object]]) -> bytes:
    payload = {
        "contract_version": 1,
        "fixture_kind": fixture_kind,
        "description": description,
        "cases": cases,
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def jets_registry_corpus_bytes() -> bytes:
    payload = {
        "contract_version": 1,
        "fixture_kind": "simplicity_jets_registry_corpus_v1",
        "description": "Generator-owned shared corpus for RUB-558 Go/Rust Simplicity jets registry hash and disallowed-id rejection parity tests.",
        "expected_registry_hash_hex": JETS_REGISTRY_HASH_HEX,
        "cases": JETS_REGISTRY_CASES,
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def cv_exec_fixture_bytes() -> bytes:
    payload = {
        "gate": "CV-SIMPLICITY-EXEC",
        "description": "Generator-owned executable conformance gate for Go/Rust simplicity_exec_vector parity.",
        "vectors": [
            {"op": "simplicity_exec_vector", **case}
            for case in CV_EXEC_CASES
        ],
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


ARTIFACTS = (
    (ENCODING_OUT, "simplicity_program_encoding_cmr_v1", "Generator-owned shared corpus for RUB-484 Go/Rust Simplicity encoding and CMR parity tests.", CASES),
    (EXEC_OUT, "simplicity_exec_corpus_v1", "Generator-owned shared corpus for RUB-488 Go/Rust Simplicity execution parity tests.", EXEC_CASES),
    (CRYPTO_JETS_OUT, "simplicity_crypto_jets_corpus_v1", "Generator-owned shared corpus for RUB-552 Go/Rust Simplicity crypto jet output, error, verifier-call, and cost parity tests.", CRYPTO_JET_CASES),
    (DATA_JETS_OUT, "simplicity_data_jets_corpus_v1", "Generator-owned shared corpus for RUB-555 Go Simplicity arithmetic and bytes data jet result, error, and cost tests.", DATA_JET_CASES),
)

EXTRA_ARTIFACTS = (
    (CV_EXEC_OUT, cv_exec_fixture_bytes),
    (JETS_REGISTRY_OUT, jets_registry_corpus_bytes),
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
        for out, build in EXTRA_ARTIFACTS:
            if not out.exists():
                print(
                    f"ERROR: missing {out.relative_to(ROOT)}; run tools/gen_simplicity_encoding_corpus.py to (re)generate",
                    file=sys.stderr,
                )
                return 1
            if out.read_bytes() != build():
                print(f"ERROR: {out.relative_to(ROOT)} is stale; rerun this generator", file=sys.stderr)
                return 1
        print("OK: Simplicity corpora match generator")
        return 0
    for out, fixture_kind, description, cases in ARTIFACTS:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(corpus_bytes(fixture_kind, description, cases))
        print(f"wrote {out.relative_to(ROOT)}")
    for out, build in EXTRA_ARTIFACTS:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(build())
        print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
