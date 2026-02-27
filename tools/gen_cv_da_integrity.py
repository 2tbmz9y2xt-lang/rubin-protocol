#!/usr/bin/env python3
import argparse
import hashlib
import json
from dataclasses import dataclass


def sha3_256(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def u16le(n: int) -> bytes:
    return int(n).to_bytes(2, "little", signed=False)


def u32le(n: int) -> bytes:
    return int(n).to_bytes(4, "little", signed=False)


def u64le(n: int) -> bytes:
    return int(n).to_bytes(8, "little", signed=False)


def encode_compact_size(n: int) -> bytes:
    n = int(n)
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xFD" + u16le(n)
    if n <= 0xFFFF_FFFF:
        return b"\xFE" + u32le(n)
    return b"\xFF" + u64le(n)


def merkle_root_tagged(ids: list[bytes], leaf_tag: int, node_tag: int) -> bytes:
    if not ids:
        raise ValueError("empty id list")

    level: list[bytes] = []
    for _id in ids:
        if len(_id) != 32:
            raise ValueError("id must be 32 bytes")
        level.append(sha3_256(bytes([leaf_tag]) + _id))

    while len(level) > 1:
        nxt: list[bytes] = []
        i = 0
        while i < len(level):
            if i == len(level) - 1:
                nxt.append(level[i])
                i += 1
                continue
            nxt.append(sha3_256(bytes([node_tag]) + level[i] + level[i + 1]))
            i += 2
        level = nxt

    return level[0]


def merkle_root_txids(txids: list[bytes]) -> bytes:
    return merkle_root_tagged(txids, 0x00, 0x01)


def witness_merkle_root_wtxids(wtxids: list[bytes]) -> bytes:
    if not wtxids:
        raise ValueError("empty wtxid list")
    ids = list(wtxids)
    ids[0] = b"\x00" * 32
    return merkle_root_tagged(ids, 0x02, 0x03)


def witness_commitment_hash(witness_root: bytes) -> bytes:
    return sha3_256(b"RUBIN-WITNESS/" + witness_root)


@dataclass
class TxParts:
    core: bytes
    full: bytes

    @property
    def txid(self) -> bytes:
        return sha3_256(self.core)

    @property
    def wtxid(self) -> bytes:
        return sha3_256(self.full)


def build_coinbase(height: int, witness_commitment: bytes) -> TxParts:
    assert len(witness_commitment) == 32
    out = b"".join(
        [
            u64le(0),  # value
            u16le(0x0002),  # CORE_ANCHOR
            encode_compact_size(32),
            witness_commitment,
        ]
    )

    core = b"".join(
        [
            u32le(1),
            b"\x00",  # tx_kind
            u64le(0),  # tx_nonce
            encode_compact_size(1),  # input_count
            b"\x00" * 32,  # prev_txid
            u32le(0xFFFF_FFFF),  # prev_vout
            encode_compact_size(0),  # script_sig_len
            u32le(0xFFFF_FFFF),  # sequence
            encode_compact_size(1),  # output_count
            out,
            u32le(height),  # locktime
        ]
    )

    full = b"".join(
        [
            core,
            encode_compact_size(0),  # witness_count
            encode_compact_size(0),  # da_payload_len
        ]
    )
    return TxParts(core=core, full=full)


def build_da_commit_tx(
    tx_nonce: int,
    da_id: bytes,
    chunk_count: int,
    payload_commitment: bytes,
    *,
    manifest: bytes,
    commitment_mode: str,
) -> TxParts:
    assert len(da_id) == 32
    assert len(payload_commitment) == 32
    if commitment_mode not in ("ok", "bad", "missing", "duplicate"):
        raise ValueError("bad commitment_mode")

    # One dummy input (block_basic does not check UTXO existence).
    dummy_input = b"".join(
        [
            b"\xA1" * 32,
            u32le(0),
            encode_compact_size(0),
            u32le(0),
        ]
    )

    outputs: list[bytes] = []
    if commitment_mode in ("ok", "bad", "duplicate"):
        cov = payload_commitment if commitment_mode != "bad" else (b"\x00" * 32)
        outputs.append(b"".join([u64le(0), u16le(0x0103), encode_compact_size(32), cov]))
    if commitment_mode == "duplicate":
        outputs.append(b"".join([u64le(0), u16le(0x0103), encode_compact_size(32), payload_commitment]))

    core = b"".join(
        [
            u32le(1),
            b"\x01",  # tx_kind
            u64le(tx_nonce),
            encode_compact_size(1),  # input_count
            dummy_input,
            encode_compact_size(len(outputs)),  # output_count
            b"".join(outputs),
            u32le(0),  # locktime
            # DaCommitCoreFields (CANONICAL §5.1 order)
            da_id,
            u16le(chunk_count),
            b"\x42" * 32,  # retl_domain_id
            u64le(1),  # batch_number
            b"\x10" * 32,  # tx_data_root
            b"\x11" * 32,  # state_root
            b"\x12" * 32,  # withdrawals_root
            b"\x01",  # batch_sig_suite
            encode_compact_size(4),
            b"BBBB",  # batch_sig (opaque)
        ]
    )

    full = b"".join(
        [
            core,
            encode_compact_size(0),  # witness_count
            encode_compact_size(len(manifest)),
            manifest,
        ]
    )
    return TxParts(core=core, full=full)


def build_da_chunk_tx(tx_nonce: int, da_id: bytes, chunk_index: int, payload: bytes, *, bad_hash: bool) -> TxParts:
    assert len(da_id) == 32
    assert len(payload) >= 1
    chunk_hash = (b"\x00" * 32) if bad_hash else sha3_256(payload)

    dummy_input = b"".join(
        [
            b"\xA2" * 32,
            u32le(0),
            encode_compact_size(0),
            u32le(0),
        ]
    )

    core = b"".join(
        [
            u32le(1),
            b"\x02",  # tx_kind
            u64le(tx_nonce),
            encode_compact_size(1),  # input_count
            dummy_input,
            encode_compact_size(0),  # output_count
            u32le(0),  # locktime
            # DaChunkCoreFields (CANONICAL §5.1 order)
            da_id,
            u16le(chunk_index),
            chunk_hash,
        ]
    )

    full = b"".join(
        [
            core,
            encode_compact_size(0),  # witness_count
            encode_compact_size(len(payload)),
            payload,
        ]
    )
    return TxParts(core=core, full=full)


def build_block(height: int, prev_timestamps: list[int], txs: list[TxParts]) -> dict:
    if not txs:
        raise ValueError("txs must not be empty")

    prev_hash = b"\x11" * 32
    target = b"\xFF" * 32
    timestamp = 1003
    nonce = 7

    txids = [t.txid for t in txs]
    wtxids = [t.wtxid for t in txs]

    merkle_root = merkle_root_txids(txids)
    header = b"".join(
        [
            u32le(1),
            prev_hash,
            merkle_root,
            u64le(timestamp),
            target,
            u64le(nonce),
        ]
    )

    block = b"".join([header, encode_compact_size(len(txs))] + [t.full for t in txs])

    return {
        "height": height,
        "prev_timestamps": prev_timestamps,
        "block_hex": block.hex(),
        "expected_prev_hash": prev_hash.hex(),
        "expected_target": target.hex(),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="-", help="output path (default: stdout)")
    args = ap.parse_args()

    height = 5
    prev_timestamps = [1000, 1001, 1002, 1003, 1004]

    # Shared DA set.
    da_id = bytes.fromhex("59890c1d183aa279505750422e6384ccb1499c793872d6f31bb3bcaa4bc9f5a5")
    payloads = [b"abc", b"def", b"ghi"]
    payload_commitment = sha3_256(b"".join(payloads))

    # Build non-coinbase txs first (coinbase commitment depends on them only).
    def build_ok_set(commitment_mode: str, bad_chunk_hash: bool, omit_last_chunk: bool) -> list[TxParts]:
        commit = build_da_commit_tx(
            10,
            da_id,
            3,
            payload_commitment,
            manifest=b"m1",
            commitment_mode=commitment_mode,
        )
        chunks = [
            build_da_chunk_tx(11, da_id, 0, payloads[0], bad_hash=bad_chunk_hash),
            build_da_chunk_tx(12, da_id, 1, payloads[1], bad_hash=False),
        ]
        if not omit_last_chunk:
            chunks.append(build_da_chunk_tx(13, da_id, 2, payloads[2], bad_hash=False))
        return [commit] + chunks

    vectors = []

    def build_vector_from_non_coinbase_txs(vector_id: str, txs_noncb: list[TxParts], expect_ok: bool, expect_err: str | None = None) -> None:
        witness_root = witness_merkle_root_wtxids([b"\x00" * 32] + [t.wtxid for t in txs_noncb])
        witness_commitment = witness_commitment_hash(witness_root)
        coinbase = build_coinbase(height, witness_commitment)
        block_ctx = build_block(height, prev_timestamps, [coinbase] + txs_noncb)

        vector = {
            "id": vector_id,
            "op": "block_basic_check",
            "expect_ok": expect_ok,
            **block_ctx,
        }
        if expect_err is not None:
            vector["expect_err"] = expect_err
        vectors.append(vector)

    build_vector_from_non_coinbase_txs(
        "CV-DA-01",
        build_ok_set("ok", bad_chunk_hash=False, omit_last_chunk=False),
        expect_ok=True,
    )
    build_vector_from_non_coinbase_txs(
        "CV-DA-02",
        build_ok_set("ok", bad_chunk_hash=True, omit_last_chunk=False),
        expect_ok=False,
        expect_err="BLOCK_ERR_DA_CHUNK_HASH_INVALID",
    )
    build_vector_from_non_coinbase_txs(
        "CV-DA-03",
        build_ok_set("ok", bad_chunk_hash=False, omit_last_chunk=True),
        expect_ok=False,
        expect_err="BLOCK_ERR_DA_INCOMPLETE",
    )
    build_vector_from_non_coinbase_txs(
        "CV-DA-04",
        build_ok_set("bad", bad_chunk_hash=False, omit_last_chunk=False),
        expect_ok=False,
        expect_err="BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID",
    )

    orphan_da_id = b"\xA3" * 32
    orphan_chunk = build_da_chunk_tx(11, orphan_da_id, 0, b"abc", bad_hash=False)
    build_vector_from_non_coinbase_txs(
        "CV-DA-05",
        [orphan_chunk],
        expect_ok=False,
        expect_err="BLOCK_ERR_DA_SET_INVALID",
    )

    zero_commit = build_da_commit_tx(
        14,
        b"\xA4" * 32,
        0,
        sha3_256(b""),
        manifest=b"m0",
        commitment_mode="ok",
    )
    build_vector_from_non_coinbase_txs(
        "CV-DA-06",
        [zero_commit],
        expect_ok=False,
        expect_err="TX_ERR_PARSE",
    )

    out_obj = {"gate": "CV-DA-INTEGRITY", "vectors": vectors}
    out_text = json.dumps(out_obj, indent=2, sort_keys=False) + "\n"

    if args.out == "-" or args.out == "":
        print(out_text, end="")
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_text)


if __name__ == "__main__":
    main()
