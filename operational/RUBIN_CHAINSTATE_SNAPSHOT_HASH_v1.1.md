# RUBIN Chainstate Snapshot Hash v1.1 (Phase 1)

Status: ENGINEERING SPEC (non-consensus)
Audience: Rust + Go node implementers, conformance runner authors
Date: 2026-02-19

This document defines a canonical `utxo_set_hash` for Phase 1 cross-client comparability.
It does not change L1 consensus.

Related:
- Storage model: `operational/RUBIN_NODE_STORAGE_MODEL_v1.1.md`
- Block import: `operational/RUBIN_BLOCK_IMPORT_PIPELINE_v1.1.md`
- Reorg: `operational/RUBIN_REORG_DISCONNECT_CONNECT_v1.1.md`

## 1. Purpose

Phase 1 needs a deterministic, engine-agnostic way to compare Rust vs Go chainstate after applying the same block
sequence. The minimal comparable state is the spendable UTXO set (`utxo_by_outpoint`).

This spec defines:
- key ordering
- canonical byte encoding per entry
- the exact hash construction

## 2. Definitions

- `outpoint`: `(txid[32], vout[u32])`
- `UtxoEntry` (Phase 1 minimum): `(value[u64], covenant_type[u16], covenant_data[bytes], creation_height[u64], created_by_coinbase[bool])`
- `utxo_by_outpoint`: map/dictionary keyed by outpoint (see storage model)

Cryptographic hash:
- `SHA3-256` (same as CANONICAL hash primitive)

Domain separation tag (ASCII bytes):
- `DST = "RUBINv1-utxo-set-hash/"`

## 3. Canonical ordering (normative)

Entries MUST be iterated in ascending lexicographic order of `outpoint_key_bytes`, where:

`outpoint_key_bytes = txid[32] || vout_le[4]`

Notes:
- `txid` is the 32-byte transaction id in its canonical byte order (as used on-wire in inputs).
- `vout_le` is `vout` encoded as little-endian `u32`.

## 4. Canonical entry encoding (normative)

For each entry, define:

1. `outpoint_bytes = txid[32] || vout_le[4]` (36 bytes)
2. `utxo_entry_bytes` encoding:
   - `value_le[8]` (u64 little-endian)
   - `covenant_type_le[2]` (u16 little-endian)
   - `covenant_data_len` encoded as CompactSize (same encoding rule as consensus)
   - `covenant_data` raw bytes
   - `creation_height_le[8]` (u64 little-endian)
   - `created_by_coinbase_u8[1]` (`0x00` for false, `0x01` for true)

`pair_bytes = outpoint_bytes || utxo_entry_bytes`

## 5. Hash construction (normative)

Let `N` be the number of entries in `utxo_by_outpoint`.

Compute:

`utxo_set_hash = SHA3-256( DST || N_le[8] || pair_bytes_0 || pair_bytes_1 || ... || pair_bytes_{N-1} )`

Where:
- `N_le[8]` is `N` encoded as u64 little-endian.
- `pair_bytes_i` are concatenated in the canonical ordering defined in §3.

Rationale:
- `DST` prevents cross-protocol collisions.
- `N_le` makes the construction non-ambiguous and simplifies debugging.

## 6. Recommended node interfaces (non-normative)

For Phase 1 parity and conformance tooling, implementers SHOULD expose at least one of:

1. CLI command:
   - `rubin-node utxo-set-hash --datadir <path>` (hash current persisted applied UTXO set)
2. Local API endpoint:
   - `GET /debug/utxo-set-hash` returning `{ tip_hash, tip_height, utxo_set_hash }`

Conformance runners SHOULD treat `(tip_hash, tip_height, utxo_set_hash)` as the comparable snapshot.

