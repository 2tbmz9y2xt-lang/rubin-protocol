#!/usr/bin/env python3
from __future__ import annotations

import os
import os.path
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


def relpath(from_dir: Path, to_path: Path) -> str:
    return os.path.relpath(str(to_path), start=str(from_dir))


@dataclass(frozen=True)
class ClientCmd:
    name: str
    cwd: Path
    argv_prefix: list[str]


def build_clients(repo_root: Path) -> dict[str, ClientCmd]:
    rust_prefix: list[str] = [
        "cargo",
        "run",
        "-q",
        "--manifest-path",
        "clients/rust/Cargo.toml",
    ]
    if os.environ.get("RUBIN_CONFORMANCE_RUST_NO_DEFAULT", "").strip() not in (
        "",
        "0",
        "false",
        "False",
    ):
        rust_prefix.append("--no-default-features")
    rust_features = os.environ.get("RUBIN_CONFORMANCE_RUST_FEATURES", "").strip()
    if rust_features:
        rust_prefix.extend(["--features", rust_features])
    rust_prefix.extend(["-p", "rubin-node", "--"])

    go_prefix: list[str] = ["go", "-C", "clients/go", "run"]
    go_tags = os.environ.get("RUBIN_CONFORMANCE_GO_TAGS", "").strip()
    if go_tags:
        go_prefix.extend(["-tags", go_tags])
    go_prefix.append("./node")

    return {
        "rust": ClientCmd(
            name="rust",
            cwd=repo_root,
            argv_prefix=rust_prefix,
        ),
        "go": ClientCmd(
            name="go",
            cwd=repo_root,
            argv_prefix=go_prefix,
        ),
    }


def encode_u16_le(v: int) -> bytes:
    return v.to_bytes(2, "little", signed=False)


def encode_u32_le(v: int) -> bytes:
    return v.to_bytes(4, "little", signed=False)


def encode_u64_le(v: int) -> bytes:
    return v.to_bytes(8, "little", signed=False)


def encode_compact_size(v: int) -> bytes:
    if v < 0xFD:
        return bytes([v])
    if v <= 0xFFFF:
        return bytes([0xFD]) + v.to_bytes(2, "little")
    if v <= 0xFFFFFFFF:
        return bytes([0xFE]) + v.to_bytes(4, "little")
    return bytes([0xFF]) + v.to_bytes(8, "little")


def parse_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"invalid int value: {value!r}")


def parse_hex(value: object) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"invalid hex value: {value!r}")
    return bytes.fromhex("".join(value.split()))


def hexlify(b: bytes) -> str:
    return "".join(f"{x:02x}" for x in b)


def make_parse_tx_bytes(ctx: dict[str, object]) -> str:
    version = 1
    tx_nonce = 0
    tx_parts = bytearray()
    tx_parts.extend(encode_u32_le(version))
    tx_parts.extend(encode_u64_le(tx_nonce))

    field = ctx.get("field")
    if field == "input_count":
        encoded = parse_hex(ctx.get("encoded"))
        tx_parts.extend(encoded)
        return hexlify(tx_parts)

    input_count = parse_int(ctx.get("input_count", 1))
    output_count = parse_int(ctx.get("output_count", 0))
    witness_count = parse_int(ctx.get("witness_count", 0))
    witness_item = ctx.get("witness_item", {})
    witness_items_present = parse_int(ctx.get("witness_items_present", 0))
    witness_item = witness_item if isinstance(witness_item, dict) else {}

    witness_size = ctx.get("witness_size_bytes")
    if witness_size is not None:
        witness_count = 1
        witness_items_present = 1

    tx_parts.extend(encode_compact_size(input_count))

    for _ in range(input_count):
        tx_parts.extend(bytes(32))
        tx_parts.extend(encode_u32_le(0))
        tx_parts.extend(encode_compact_size(0))
        tx_parts.extend(encode_u32_le(0))

    tx_parts.extend(encode_compact_size(output_count))
    for _ in range(output_count):
        tx_parts.extend(encode_u64_le(0))
        tx_parts.extend(encode_u16_le(0))
        tx_parts.extend(encode_compact_size(0))

    tx_parts.extend(encode_u32_le(0))
    tx_parts.extend(encode_compact_size(witness_count))

    suite_id = parse_int(witness_item.get("suite_id", 0x00))
    pubkey_len = parse_int(witness_item.get("pubkey_length", 0))
    sig_len = parse_int(witness_item.get("sig_length", 0))
    if suite_id not in range(0, 256):
        raise ValueError(f"suite_id out of range: {suite_id}")

    if witness_size is not None:
        target = parse_int(witness_size)
        if target < 1:
            target = 1
        sig_len = max(0, target)

    for _ in range(witness_items_present):
        tx_parts.append(suite_id & 0xFF)
        tx_parts.extend(encode_compact_size(pubkey_len))
        tx_parts.extend(bytes(pubkey_len))
        tx_parts.extend(encode_compact_size(sig_len))
        tx_parts.extend(bytes(sig_len))

    return hexlify(tx_parts)


def extract_error_token(stderr: str) -> str:
    normalized = (
        stderr.replace(":", " ")
        .replace(",", " ")
        .replace("(", " ")
        .replace(")", " ")
    )
    for tok in normalized.split():
        if tok.startswith("TX_ERR_") or tok.startswith("BLOCK_ERR_") or tok.startswith("REORG_ERR_"):
            return tok
    return stderr.strip()


def build_tx_hex(
    *,
    version: int,
    tx_nonce: int,
    inputs: list[dict[str, object]],
    outputs: list[dict[str, object]],
    locktime: int,
    witnesses: list[dict[str, object]],
) -> str:
    b = bytearray()
    b.extend(encode_u32_le(version))
    b.extend(encode_u64_le(tx_nonce))

    b.extend(encode_compact_size(len(inputs)))
    for item in inputs:
        prev_txid = item.get("prev_txid", bytes(32))
        if not isinstance(prev_txid, (bytes, bytearray)) or len(prev_txid) != 32:
            raise ValueError("input.prev_txid must be 32 bytes")
        prev_vout = parse_int(item.get("prev_vout", 0))
        script_sig = item.get("script_sig", b"")
        if not isinstance(script_sig, (bytes, bytearray)):
            raise ValueError("input.script_sig must be bytes")
        sequence = parse_int(item.get("sequence", 0))

        b.extend(prev_txid)
        b.extend(encode_u32_le(prev_vout))
        b.extend(encode_compact_size(len(script_sig)))
        b.extend(script_sig)
        b.extend(encode_u32_le(sequence))

    b.extend(encode_compact_size(len(outputs)))
    for item in outputs:
        value = parse_int(item.get("value", 0))
        covenant_type = parse_int(item.get("covenant_type", 0))
        covenant_data = item.get("covenant_data", b"")
        if not isinstance(covenant_data, (bytes, bytearray)):
            raise ValueError("output.covenant_data must be bytes")
        b.extend(encode_u64_le(value))
        b.extend(encode_u16_le(covenant_type))
        b.extend(encode_compact_size(len(covenant_data)))
        b.extend(covenant_data)

    b.extend(encode_u32_le(locktime))
    b.extend(encode_compact_size(len(witnesses)))
    for item in witnesses:
        suite_id = parse_int(item.get("suite_id", 0))
        pubkey = item.get("pubkey", b"")
        sig = item.get("sig", b"")
        if not isinstance(pubkey, (bytes, bytearray)):
            raise ValueError("witness.pubkey must be bytes")
        if not isinstance(sig, (bytes, bytearray)):
            raise ValueError("witness.sig must be bytes")
        if not (0 <= suite_id <= 255):
            raise ValueError("witness.suite_id must fit u8")

        b.append(suite_id & 0xFF)
        b.extend(encode_compact_size(len(pubkey)))
        b.extend(pubkey)
        b.extend(encode_compact_size(len(sig)))
        b.extend(sig)

    return hexlify(bytes(b))


def run(
    client: ClientCmd,
    argv: list[str],
    capture_stderr: bool = True,
) -> tuple[str, str, int]:
    timeout_s = int(os.environ.get("RUBIN_CONFORMANCE_TIMEOUT_S", "60"))
    p = subprocess.run(
        client.argv_prefix + argv,
        cwd=str(client.cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
        text=True,
        timeout=timeout_s,
    )
    return p.stdout.strip(), p.stderr.strip(), p.returncode


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"fixture root must be a mapping: {path}")
    return obj
