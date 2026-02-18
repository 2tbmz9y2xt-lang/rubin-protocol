#!/usr/bin/env python3
"""
Deterministic RUBIN v1.1 genesis builder (non-consensus tooling).

It builds:
- genesis coinbase tx bytes (TxBytes)
- genesis header bytes (BlockHeaderBytes)
- derived chain_id and genesis_block_hash per chain-instance profile derivation

No network calls; pure SHA3-256 + byte serialization.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Optional


def sha3_256(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def u16le(n: int) -> bytes:
    if n < 0 or n > 0xFFFF:
        raise ValueError(f"u16le overflow: {n}")
    return n.to_bytes(2, "little", signed=False)


def u32le(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError(f"u32le overflow: {n}")
    return n.to_bytes(4, "little", signed=False)


def u64le(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"u64le overflow: {n}")
    return n.to_bytes(8, "little", signed=False)


def compact_size(n: int) -> bytes:
    if n < 0:
        raise ValueError("compact_size negative")
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little", signed=False)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little", signed=False)
    if n <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + n.to_bytes(8, "little", signed=False)
    raise ValueError("compact_size overflow")


def hex_decode_strict(s: str) -> bytes:
    cleaned = "".join(s.split()).lower()
    if cleaned.startswith("0x"):
        raise ValueError("hex must not include 0x prefix")
    if cleaned == "":
        return b""
    if not re.fullmatch(r"[0-9a-f]+", cleaned):
        raise ValueError("invalid hex")
    if len(cleaned) % 2 != 0:
        raise ValueError("hex has odd length")
    return bytes.fromhex(cleaned)


def hex_encode(b: bytes) -> str:
    return b.hex()


CORE_P2PK = 0x0000
CORE_VAULT_V1 = 0x0101

LOCK_MODE_HEIGHT = 0x00
LOCK_VALUE_NEVER = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class VaultOutput:
    value: int
    owner_key_id: bytes  # bytes32
    spend_delay: int
    recovery_key_id: bytes  # bytes32 (typically unspendable / unused)


def make_vault_covenant_data_ext(
    owner_key_id: bytes, spend_delay: int, recovery_key_id: bytes
) -> bytes:
    if len(owner_key_id) != 32:
        raise ValueError("owner_key_id must be 32 bytes")
    if len(recovery_key_id) != 32:
        raise ValueError("recovery_key_id must be 32 bytes")
    # Extended encoding (81 bytes):
    # owner_key_id || spend_delay || lock_mode || lock_value || recovery_key_id
    return (
        owner_key_id
        + u64le(spend_delay)
        + bytes([LOCK_MODE_HEIGHT])
        + u64le(LOCK_VALUE_NEVER)
        + recovery_key_id
    )


def tx_input_coinbase() -> bytes:
    prev_txid = b"\x00" * 32
    prev_vout = u32le(0xFFFFFFFF)
    script_sig = b""
    sequence = u32le(0xFFFFFFFF)
    return prev_txid + prev_vout + compact_size(len(script_sig)) + script_sig + sequence


def tx_output(value: int, covenant_type: int, covenant_data: bytes) -> bytes:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("value out of range")
    return (
        u64le(value)
        + u16le(covenant_type)
        + compact_size(len(covenant_data))
        + covenant_data
    )


def witness_section_empty() -> bytes:
    # witness_count = 0
    return compact_size(0)


def make_coinbase_tx_bytes_v1_1(outputs: list[bytes], height: int) -> tuple[bytes, bytes]:
    """
    Returns (tx_no_witness_bytes, tx_bytes).
    Coinbase rules per CANONICAL v1.1:
    - tx_nonce = 0
    - input_count = 1, witness_count = 0
    - script_sig_len = 0
    - sequence = 0xffffffff
    - locktime = height
    """
    version = u32le(1)
    tx_nonce = u64le(0)
    inputs = compact_size(1) + tx_input_coinbase()
    outs = compact_size(len(outputs)) + b"".join(outputs)
    locktime = u32le(height)
    tx_no_wit = version + tx_nonce + inputs + outs + locktime
    tx_bytes = tx_no_wit + witness_section_empty()
    return tx_no_wit, tx_bytes


def txid_from_no_witness(tx_no_witness_bytes: bytes) -> bytes:
    return sha3_256(tx_no_witness_bytes)


def merkle_root_from_txids(txids: list[bytes]) -> bytes:
    if not txids:
        raise ValueError("merkle: empty txids")
    leaves = [sha3_256(b"\x00" + txid) for txid in txids]
    level = leaves
    while len(level) > 1:
        nxt: list[bytes] = []
        it = iter(level)
        for left in it:
            right = next(it, None)
            if right is None:
                nxt.append(left)
            else:
                nxt.append(sha3_256(b"\x01" + left + right))
        level = nxt
    return level[0]


def block_header_bytes(
    *,
    version: int,
    prev_block_hash: bytes,
    merkle_root: bytes,
    timestamp: int,
    target_be: bytes,
    nonce: int,
) -> bytes:
    if len(prev_block_hash) != 32:
        raise ValueError("prev_block_hash must be 32 bytes")
    if len(merkle_root) != 32:
        raise ValueError("merkle_root must be 32 bytes")
    if len(target_be) != 32:
        raise ValueError("target must be 32 bytes")
    return (
        u32le(version)
        + prev_block_hash
        + merkle_root
        + u64le(timestamp)
        + target_be
        + u64le(nonce)
    )


def derive_chain_id(genesis_header_bytes: bytes, genesis_tx_bytes: bytes) -> bytes:
    # serialized_genesis_without_chain_id_field =
    #   ASCII("RUBIN-GENESIS-v1") || genesis_header_bytes || CompactSize(1) || genesis_tx_bytes
    preimage = b"RUBIN-GENESIS-v1" + genesis_header_bytes + compact_size(1) + genesis_tx_bytes
    return sha3_256(preimage)


def extract_inline_backticked_value(doc: str, key: str) -> str:
    for line in doc.splitlines():
        if key not in line:
            continue
        colon = line.find(":")
        if colon < 0:
            continue
        after = line[colon + 1 :]
        first = after.find("`")
        if first < 0:
            continue
        after_first = after[first + 1 :]
        second = after_first.find("`")
        if second < 0:
            continue
        value = after_first[:second].strip()
        if value:
            return value
    raise ValueError(f"missing inline backticked value for key: {key}")


def replace_inline_backticked_value(doc: str, key: str, new_hex: str) -> str:
    out_lines: list[str] = []
    replaced = False
    for line in doc.splitlines():
        if not replaced and key in line and ":" in line and "`" in line:
            colon = line.find(":")
            after = line[colon + 1 :]
            first = after.find("`")
            if first >= 0:
                after_first = after[first + 1 :]
                second = after_first.find("`")
                if second >= 0:
                    before = line[: colon + 1] + after[: first + 1]
                    after_val = after_first[second:]
                    line = before + new_hex + after_val
                    replaced = True
        out_lines.append(line)
    if not replaced:
        raise ValueError(f"failed to replace key: {key}")
    return "\n".join(out_lines) + ("\n" if doc.endswith("\n") else "")


def load_schedule_csv(path: str) -> list[VaultOutput]:
    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    def get_col(row: dict[str, str], names: Iterable[str]) -> str:
        for n in names:
            if n in row and row[n] is not None:
                return str(row[n]).strip()
        raise ValueError(f"missing required column (one of {list(names)})")

    outs: list[VaultOutput] = []
    for idx, row in enumerate(rows):
        owner_hex = get_col(row, ["owner_key_id_hex", "owner_key_id"])
        value_s = get_col(row, ["value_base_units", "value_sat", "value"])
        delay_s = get_col(row, ["spend_delay_blocks", "spend_delay", "delay_blocks"])

        owner = hex_decode_strict(owner_hex)
        if len(owner) != 32:
            raise ValueError(f"row {idx}: owner_key_id must be 32 bytes")
        value = int(value_s.replace("_", ""))
        delay = int(delay_s.replace("_", ""))

        outs.append(
            VaultOutput(
                value=value,
                owner_key_id=owner,
                spend_delay=delay,
                recovery_key_id=b"",  # filled later
            )
        )
    return outs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", help="chain-instance profile .md to read/write")
    ap.add_argument("--verify-profile", action="store_true", help="verify profile genesis bytes are self-consistent")
    ap.add_argument("--update-profile", action="store_true", help="rewrite genesis_* and derived fields in --profile")

    ap.add_argument("--schedule-csv", help="CSV with owner_key_id_hex,value_base_units,spend_delay_blocks rows")
    ap.add_argument(
        "--recovery-key-id-unspendable-hex",
        help="bytes32 hex used as recovery_key_id for all VAULT outputs (disables recovery path)",
    )

    ap.add_argument("--timestamp", type=int, default=0)
    ap.add_argument("--target-hex", default="ff" * 32)
    ap.add_argument("--nonce", type=int, default=0)
    ap.add_argument("--header-version", type=int, default=1)
    ap.add_argument("--height", type=int, default=0, help="genesis height (must be 0 for real genesis)")

    args = ap.parse_args(argv)

    if args.verify_profile:
        if not args.profile:
            ap.error("--verify-profile requires --profile")
        doc = open(args.profile, "r", encoding="utf-8").read()
        header_hex = extract_inline_backticked_value(doc, "genesis_header_bytes")
        tx_hex = extract_inline_backticked_value(doc, "genesis_tx_bytes")
        header_bytes = hex_decode_strict(header_hex)
        tx_bytes = hex_decode_strict(tx_hex)
        if len(header_bytes) != 116:
            raise SystemExit(f"profile: genesis_header_bytes must be 116 bytes, got {len(header_bytes)}")

        # Recompute derived
        chain_id = derive_chain_id(header_bytes, tx_bytes)
        genesis_block_hash = sha3_256(header_bytes)
        print("chain_id_hex:", hex_encode(chain_id))
        print("genesis_block_hash_hex:", hex_encode(genesis_block_hash))
        return 0

    schedule: list[VaultOutput] = []
    if args.schedule_csv:
        schedule = load_schedule_csv(args.schedule_csv)
        if len(schedule) != 100:
            raise SystemExit(f"schedule must have exactly 100 rows (got {len(schedule)})")
        if not args.recovery_key_id_unspendable_hex:
            ap.error("--schedule-csv requires --recovery-key-id-unspendable-hex")

    recovery_key_id = b""
    if args.recovery_key_id_unspendable_hex:
        recovery_key_id = hex_decode_strict(args.recovery_key_id_unspendable_hex)
        if len(recovery_key_id) != 32:
            raise SystemExit("--recovery-key-id-unspendable-hex must be 32 bytes")

    outputs: list[bytes] = []
    for o in schedule:
        cov = make_vault_covenant_data_ext(o.owner_key_id, o.spend_delay, recovery_key_id)
        outputs.append(tx_output(o.value, CORE_VAULT_V1, cov))

    tx_no_wit, tx_bytes = make_coinbase_tx_bytes_v1_1(outputs, args.height)
    txid = txid_from_no_witness(tx_no_wit)
    merkle = merkle_root_from_txids([txid])

    header_bytes = block_header_bytes(
        version=args.header_version,
        prev_block_hash=b"\x00" * 32,
        merkle_root=merkle,
        timestamp=args.timestamp,
        target_be=hex_decode_strict(args.target_hex),
        nonce=args.nonce,
    )

    chain_id = derive_chain_id(header_bytes, tx_bytes)
    genesis_block_hash = sha3_256(header_bytes)

    print("genesis_header_bytes_hex:", hex_encode(header_bytes))
    print("genesis_tx_bytes_hex:", hex_encode(tx_bytes))
    print("chain_id_hex:", hex_encode(chain_id))
    print("genesis_block_hash_hex:", hex_encode(genesis_block_hash))

    if args.update_profile:
        if not args.profile:
            ap.error("--update-profile requires --profile")
        doc = open(args.profile, "r", encoding="utf-8").read()
        doc = replace_inline_backticked_value(doc, "genesis_header_bytes", hex_encode(header_bytes))
        doc = replace_inline_backticked_value(doc, "genesis_tx_bytes", hex_encode(tx_bytes))
        # Optional convenience lines (present in devnet/testnet/mainnet profiles)
        try:
            doc = replace_inline_backticked_value(doc, "chain_id", hex_encode(chain_id))
        except Exception:
            pass
        try:
            doc = replace_inline_backticked_value(doc, "genesis_block_hash", hex_encode(genesis_block_hash))
        except Exception:
            pass

        tmp = args.profile + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(doc)
        os.replace(tmp, args.profile)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

