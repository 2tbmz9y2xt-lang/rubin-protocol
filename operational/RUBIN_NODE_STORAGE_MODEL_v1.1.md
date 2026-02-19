# RUBIN Node Storage Model v1.1 (Phase 1)

Status: ENGINEERING SPEC (non-consensus)
Audience: Rust + Go node implementers
Date: 2026-02-19

This document defines the minimum persistent storage model required to implement:
- deterministic block import
- reorg (disconnect/connect) with bounded recovery work
- cross-client chainstate comparability in Phase 1

It does not change L1 consensus. Consensus rules are defined in `spec/RUBIN_L1_CANONICAL_v1.1.md`.

## 1. Design goals

- Crash safety: after power loss, the node must recover to a self-consistent state.
- Determinism: persistence must not introduce nondeterministic behavior in validation results.
- Reorg support: fast rollback to a common ancestor using undo logs.
- Bounded complexity: Phase 1 prefers a simple, explicit model over maximal performance.

Non-goals (Phase 1):
- pruning policies
- archive vs. pruned node requirements
- a network protocol for state snapshots

## 2. Terminology

- `chain_id_hex`: chain identity pinned by genesis bytes (CANONICAL v1.1).
- `tip`: best chain head chosen by the node's fork-choice rule (CANONICAL v1.1).
- `height`: best chain height (0 = genesis).
- `block_hash`: 32-byte block hash.
- `txid`: 32-byte transaction id.
- `outpoint`: `(txid, vout)` pair.

## 3. Datadir layout (normative for Phase 1)

All persistence lives under a configurable `datadir`.

Directory layout:
- `datadir/chains/<chain_id_hex>/`
  - `MANIFEST.json` (small, fsync-ed, rewritten atomically)
  - `db/` (key-value store directory; engine is implementation-specific)
  - `blocks/` (optional: raw block bytes store if not stored in `db/`)
  - `snapshots/` (optional; future)
  - `logs/` (optional; operational)

Rationale:
- per-chain separation prevents accidental cross-network corruption.
- `MANIFEST.json` provides a single recovery anchor for crash consistency.

## 4. Persistent entities

Nodes MUST persist the following logical entities.

### 4.1 Manifest (MANIFEST.json)

The manifest is the authoritative commit point for the last fully applied block.

Required fields:
- `schema_version` (u32)
- `chain_id_hex` (string)
- `tip_hash` (hex string)
- `tip_height` (u64)
- `tip_cumulative_work` (u128 or decimal string; implementation choice, but deterministic)
- `last_applied_block_hash` (hex string; equals tip on a consistent state)
- `last_applied_height` (u64; equals tip_height on a consistent state)

Rules:
- Update the manifest only after a block is fully applied (all DB writes committed).
- Writes MUST be atomic (write temp + fsync + rename).

### 4.2 Headers

Logical table: `headers_by_hash`.

Key: `block_hash`.
Value: canonical header bytes (as defined by consensus encoding).

Optional secondary index: `header_hash_by_height`.

### 4.3 Block store

Nodes MUST be able to retrieve full block bytes by `block_hash` for:
- reorg rollback (undo verification and/or post-mortem)
- serving data to local tooling

Storage options (choose one):
- store block bytes in the KV store (`blocks_by_hash`)
- store block bytes in `blocks/` with an index (`block_index_by_hash`)

### 4.4 Block index (chain index)

Logical table: `block_index_by_hash`.

Key: `block_hash`.
Value (minimum):
- `height` (u64)
- `prev_hash` (32 bytes)
- `cumulative_work` (u128 or deterministic encoding)
- `status` (enum: `VALID`, `INVALID`, `ORPHANED`, `UNKNOWN`)

Notes:
- INVALID marking is an engineering feature; consensus errors must remain deterministic.
- The index MUST allow walking backwards by `prev_hash`.

### 4.5 Spendable UTXO set

Logical table: `utxo_by_outpoint`.

Key: `outpoint = txid(32) || vout(u32 little-endian)`.
Value (minimum):
- `value` (u64)
- `covenant_type` (u16)
- `covenant_data` (bytes)
- `creation_height` (u64)
- `created_by_coinbase` (bool)

Consensus reminder:
- non-spendable outputs (e.g., `CORE_ANCHOR`) MUST NOT be inserted into this table.

### 4.6 Undo log (per block)

Logical table: `undo_by_block_hash`.

Key: `block_hash`.
Value contains enough information to revert the block's application:
- list of consumed outpoints with their previous `UtxoEntry` values
- list of created outpoints (or deterministically recomputable from block txs)

Rule:
- A node MUST NOT advance the manifest tip unless the undo log for that tip is persisted.

## 5. Atomic block apply (engineering requirement)

Applying a block MUST be atomic with respect to:
- `utxo_by_outpoint`
- `block_index_by_hash`
- `headers_by_hash`
- `undo_by_block_hash`
- manifest update

Minimum acceptable implementation:
- use the storage engine's write batch/transaction
- commit batch
- update `MANIFEST.json`

Crash recovery rule:
- if DB state contains a partially written block (manifest not updated), the node MUST treat it as not applied and MUST revert/ignore it on restart.

## 6. Schema versioning and migrations

`schema_version` is a monotonically increasing integer.

Rules:
- Any breaking change to on-disk encodings MUST bump `schema_version`.
- Nodes MUST refuse to start if `schema_version` is greater than what the binary supports.
- Migrations MUST be deterministic and idempotent.

Recommended operational behavior:
- provide a `rubin-node migrate --datadir ...` command that upgrades in place (or via copy) with explicit operator intent.

## 7. Phase 1 cross-client comparability (bridge to Q-076/Q-077)

Phase 1 parity work needs a canonical, engine-agnostic hash of chainstate.

This document intentionally defines `utxo_by_outpoint` key encoding as:
`txid || vout_le` so an ordered iteration is well-defined.

Follow-up:
- Q-076: Define `utxo_set_hash` as a canonical hash over lexicographically ordered `(outpoint, utxo_entry_bytes)` pairs.
- Q-077: Add `CV-CHAINSTATE` conformance gate to compare Rust vs Go on block sequences.
