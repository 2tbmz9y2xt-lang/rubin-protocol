# RUBIN Reorg (Disconnect/Connect) v1.1 (Phase 1)

Status: ENGINEERING SPEC (non-consensus)
Audience: Rust + Go node implementers
Date: 2026-02-19

This document defines the Phase 1 reorg algorithm and its persistence semantics:
- fork-point discovery
- deterministic disconnect/connect order
- minimum undo-log requirements
- crash safety boundaries and commit points

Consensus rules (PoW/tx validation/error codes) are defined in `spec/RUBIN_L1_CANONICAL_v1.1.md`.
Storage entities referenced here are defined in `operational/RUBIN_NODE_STORAGE_MODEL_v1.1.md`.
Block import stage ordering is defined in `operational/RUBIN_BLOCK_IMPORT_PIPELINE_v1.1.md`.

## 1. Goals

- Deterministic behavior: for a given persisted state and set of stored blocks, the node performs the same disconnect/connect steps.
- Crash safety: after a crash, the node resumes from a self-consistent applied tip (manifest), without partial reorg effects.
- Bounded work: rollback does not require re-executing full validation for disconnected blocks.

Non-goals (Phase 1):
- canonical on-disk byte encoding for undo records (engine-specific)
- pruning policies
- network-level reorg messages/protocols

## 2. Preconditions and invariants (normative)

1. The only authoritative applied chain tip is:
   - `MANIFEST.last_applied_block_hash` and `MANIFEST.last_applied_height`.
2. `utxo_by_outpoint` MUST correspond to the manifest applied tip.
3. For any applied block at the manifest tip, `undo_by_block_hash[block_hash]` MUST exist.
4. Non-spendable outputs (e.g., `CORE_ANCHOR`) MUST NOT be in `utxo_by_outpoint` (consensus reminder).

## 3. When a reorg is required

A reorg is required when the node's fork-choice selects a new best tip `new_tip_hash` which is not equal to the current
applied tip `old_tip_hash`.

Fork-choice selection itself is out of scope here; it is performed in Stage 3 of block import.

## 4. Fork-point discovery (required algorithm)

Inputs:
- `old_tip_hash` (applied tip from manifest)
- `new_tip_hash` (candidate tip selected by fork-choice)

Required persisted data:
- `block_index_by_hash[hash].prev_hash`
- `block_index_by_hash[hash].height`

Algorithm (deterministic):
1. Let `a = old_tip_hash`, `b = new_tip_hash`.
2. While `height(a) > height(b)`: set `a = prev_hash(a)`.
3. While `height(b) > height(a)`: set `b = prev_hash(b)`.
4. While `a != b`: set `a = prev_hash(a)` and `b = prev_hash(b)`.
5. The fork point is `fork_hash = a` (common ancestor).

Failure handling:
- If any required index entry is missing, the node MUST treat the reorg as not executable in Phase 1 and MUST NOT
  mutate chainstate. (Recommended error token: `REORG_ERR_INDEX_MISSING`.)

## 5. Deterministic disconnect/connect order (required)

Let:
- `old_path = blocks(old_tip_hash -> fork_hash]` (excluding fork, inclusive old tip)
- `new_path = blocks(new_tip_hash -> fork_hash]` (excluding fork, inclusive new tip)

Order MUST be:
- Disconnect `old_path` in descending height order: `old_tip, old_tip-1, ..., fork+1`.
- Connect `new_path` in ascending height order: `fork+1, ..., new_tip`.

Within a block:
- transactions MUST be applied in wire order.
- within a transaction, inputs MUST be processed in input order.
- outputs MUST be created in output order.

## 6. Undo log: minimum schema (normative)

Undo is a per-block record that allows deterministic reversal of Stage 5 application.

### 6.1 UTXO entry encoding (logical)

An `UtxoEntry` (as stored in `utxo_by_outpoint`) contains at minimum:
- `value: u64`
- `covenant_type: u16`
- `covenant_data: bytes`
- `creation_height: u64`
- `created_by_coinbase: bool`

### 6.2 Undo record (logical)

For a block `B` with `block_hash` and `height = h`, `undo_by_block_hash[block_hash]` MUST contain:

1. `spent`: list of records, one per spent outpoint in `B`:
   - `outpoint`: `(prev_txid[32], prev_vout[u32])`
   - `restored_entry`: full `UtxoEntry` bytes/fields as they existed immediately before applying `B`
2. `created`: list of outpoints created by `B` that were inserted into `utxo_by_outpoint`:
   - `outpoint`: `(txid[32], vout[u32])`

Rationale:
- `spent` is required to restore previous UTXOs.
- `created` is required to delete UTXOs that did not exist pre-apply, without re-parsing block bytes.

Determinism requirement:
- The `spent` list SHOULD be in the deterministic spend order (tx order, then input order). If an implementation uses a
  different order, disconnect MUST still be correct, but cross-client comparability becomes harder.
- The `created` list SHOULD be in deterministic creation order (tx order, then output index).

## 7. Disconnect algorithm (Phase 1)

Disconnect means: revert the applied chainstate from `tip` down to (but excluding) the fork point.

For each `block_hash` in disconnect order:
1. Load `undo = undo_by_block_hash[block_hash]`. If missing: STOP without mutating chainstate.
   - Recommended error token: `REORG_ERR_UNDO_MISSING`.
2. In a single DB write transaction/batch:
   - For each `outpoint` in `undo.created`: delete `utxo_by_outpoint[outpoint]` if present.
   - For each `spent_item` in `undo.spent`: set `utxo_by_outpoint[spent_item.outpoint] = spent_item.restored_entry`.
   - Update `block_index_by_hash[block_hash].status` MAY remain `VALID` (it was valid historically); do not mark invalid.
   - Update internal applied tip variables to the parent block (but do not update manifest yet).
3. Commit the DB write transaction/batch.
4. Atomically rewrite `MANIFEST.json` to the new applied tip (parent).

Hard rule:
- The manifest update is the commit point. If a crash happens before the manifest update, the node MUST treat the block
  as still applied and MUST ensure it can recover to that state.

## 8. Connect algorithm (Phase 1)

Connect means: apply blocks from the fork point's child up to `new_tip`, using Stage 4 + Stage 5 semantics.

For each `block_hash` in connect order:
1. Ensure full block bytes are available (from `blocks_by_hash` or `blocks/`).
2. Run Stage 4 full validation against the current applied chainstate.
   - If validation fails, the block MUST be marked invalid and MUST NOT be applied.
   - The reorg attempt MUST STOP; the node MUST remain on a consistent applied tip.
3. Run Stage 5 apply:
   - compute `undo_by_block_hash[block_hash]` as per §6
   - update `utxo_by_outpoint` by consuming inputs and creating spendable outputs
   - update `block_index_by_hash` and tip variables
4. Commit DB transaction/batch, then atomically update manifest to the new applied tip.

## 9. Crash recovery rules (Phase 1)

On startup:
- Read `MANIFEST.json` and treat it as authoritative applied tip.
- If the DB contains stored headers/blocks/index entries above the manifest tip: treat them as stored-only, not applied.

If the node detects chainstate inconsistency (e.g., missing undo for manifest tip):
- The node MUST refuse to proceed with further connects/disconnects and SHOULD require operator intervention.
- Recommended error token: `REORG_ERR_CHAINSTATE_INCONSISTENT`.

## 10. Operational diagnostics (recommended)

Implementations SHOULD expose a tooling mode (non-mutating) that:
- computes fork point between two tips
- prints the planned disconnect/connect sequences
- verifies undo availability for the current applied tip path

This mode MUST NOT write `undo_by_block_hash` and MUST NOT mutate chainstate.

