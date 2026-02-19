# RUBIN Node KV Engine Spec v1.1 (Phase 1)

Status: ENGINEERING SPEC (non-consensus)
Audience: Rust + Go node implementers
Date: 2026-02-19

This document defines the **canonical on-disk key/value byte layouts** for the Phase 1 node tables.

Scope:
- tables (buckets)
- key encoding
- value encoding
- schema versioning expectations

Non-goals (Phase 1):
- engine selection mandate (engine is implementation-specific)
- pruning
- snapshot sync

Related:
- storage model: `operational/RUBIN_NODE_STORAGE_MODEL_v1.1.md`
- import pipeline: `operational/RUBIN_BLOCK_IMPORT_PIPELINE_v1.1.md`
- reorg: `operational/RUBIN_REORG_DISCONNECT_CONNECT_v1.1.md`
- chainstate hash: `operational/RUBIN_CHAINSTATE_SNAPSHOT_HASH_v1.1.md`

---

## 1. Engine selection (Phase 1)

Implementations MAY choose any KV engine that supports:
- atomic write batch / transaction
- deterministic iteration by key order (or an explicit sorted scan)

Current reference direction:
- Go: bbolt (embedded, ordered buckets)
- Rust: TBD (sled/redb/etc.), but MUST implement the exact byte layouts below.

---

## 2. Canonical tables (normative)

Logical tables (names are canonical even if an engine uses a different internal representation):
- `headers_by_hash`
- `blocks_by_hash`
- `block_index_by_hash`
- `utxo_by_outpoint`
- `undo_by_block_hash`

---

## 3. Key encodings (normative)

### 3.1 Common primitives

- `hash32`: 32 raw bytes (as used by consensus functions), no hex, no endianness reversal.
- `u32le`: 4 bytes little-endian.
- `u64le`: 8 bytes little-endian.
- `CompactSize`: consensus CompactSize encoding (see `spec/RUBIN_L1_CANONICAL_v1.1.md §3.2.1`).

### 3.2 Keys

1. `headers_by_hash` key:
- `block_hash[32]`

2. `blocks_by_hash` key:
- `block_hash[32]`

3. `block_index_by_hash` key:
- `block_hash[32]`

4. `utxo_by_outpoint` key:
- `outpoint_key_bytes = txid[32] || vout_le[4]`

5. `undo_by_block_hash` key:
- `block_hash[32]`

---

## 4. Value encodings (normative)

### 4.1 `headers_by_hash` value

- `BlockHeaderBytes` (116 bytes) exactly as consensus encoding.

### 4.2 `blocks_by_hash` value

- raw `BlockBytes` exactly as consensus wire encoding.

### 4.3 `block_index_by_hash` value (minimum)

Byte layout:
- `height: u64le`
- `prev_hash: hash32`
- `status: u8`
- `cumulative_work_len: u16le`
- `cumulative_work_be: bytes` (big-endian, minimal, unsigned; length = cumulative_work_len)

Status enum (Phase 1 minimum):
- `0` UNKNOWN
- `1` VALID
- `2` INVALID
- `3` ORPHANED

Status enum (Phase 1 reference implementations MAY extend):
- `4` INVALID_HEADER (Stage 1 failed: PoW/target/timestamp/merkle)
- `5` INVALID_ANCESTRY (Stage 2 failed: parent known-invalid)
- `6` INVALID_BODY (Stage 4 failed: full consensus block validation)

Notes:
- `cumulative_work` is stored as a non-negative integer.
- `cumulative_work_be` MUST be minimal-length for determinism (no leading zero bytes).

### 4.4 `utxo_by_outpoint` value (`UtxoEntry`)

This encoding MUST match `operational/RUBIN_CHAINSTATE_SNAPSHOT_HASH_v1.1.md §4`.

Byte layout:
- `value: u64le`
- `covenant_type: u16le`
- `covenant_data_len: CompactSize`
- `covenant_data: bytes` (length = covenant_data_len)
- `creation_height: u64le`
- `created_by_coinbase: u8` (`0x00` false, `0x01` true)

### 4.5 `undo_by_block_hash` value (`UndoRecord`)

Byte layout:
- `spent_count: u32le`
- repeated `spent_count` times:
  - `outpoint_key_bytes: 36 bytes` (txid[32] || vout_le[4])
  - `utxo_entry_len: u32le` (length of encoded `UtxoEntry` bytes)
  - `utxo_entry_bytes: bytes` (exact bytes per §4.4)
- `created_count: u32le`
- repeated `created_count` times:
  - `outpoint_key_bytes: 36 bytes`

---

## 5. Schema versioning

The chain directory contains `MANIFEST.json` with:
- `schema_version` (monotonic)

Rules:
- Any breaking change to the encodings in §4 MUST bump `schema_version`.
- Implementations MUST refuse to open a datadir with `schema_version` greater than supported.

Phase 1 note:
- Until public devnet is launched, a schema bump is acceptable with a clear changelog.
