# RUBIN Block Import Pipeline v1.1 (Phase 1)

Status: ENGINEERING SPEC (non-consensus)
Audience: Rust + Go node implementers
Date: 2026-02-19

This document defines the Phase 1 block import pipeline for a full node:
- staged validation
- invalid marking semantics
- atomic commit/rollback boundaries
- crash recovery expectations

Consensus rules are defined in `spec/RUBIN_L1_CANONICAL_v1.1.md`. This document specifies node behavior around
those rules and persistence (see `operational/RUBIN_NODE_STORAGE_MODEL_v1.1.md`).

## 1. Goals

- Deterministic acceptance/rejection decisions for a given `(block_bytes, chainstate)`.
- Atomic application of a block to persistent storage (no partial chainstate visible after crash).
- Fast reorg handling by keeping per-block undo data.
- Explicit invalid marking that prevents repeated work on known-bad blocks.

## 2. Inputs / outputs

Input:
- raw `block_bytes` (wire encoding)
- current persisted state at `tip` (manifest + DB)

Output:
- either "accepted as new tip" or "stored but not selected" or "rejected"
- updated persistent state (if accepted/applied)
- optional invalid marking for blocks proven invalid

## 3. Pipeline stages (normative for Phase 1)

Implementations MUST process blocks using the following stage order. Stages may share parsing results, but the
observable outcome MUST match this order.

### Stage 0: Decode and basic structure checks

- Parse `block_bytes` according to consensus encoding.
- Reject malformed encodings as `BLOCK_ERR_PARSE`.
- Compute `block_hash` and `merkle_root` deterministically.

Persist:
- `headers_by_hash[block_hash] = header_bytes` MAY be persisted at this stage.
- Full `block_bytes` MAY be persisted at this stage to avoid re-download.

### Stage 1: Header-level validation (stateless)

Validate:
- PoW / target (`BLOCK_ERR_POW_INVALID`, `BLOCK_ERR_TARGET_INVALID`).
- timestamp bounds (`BLOCK_ERR_TIMESTAMP_OLD`, `BLOCK_ERR_TIMESTAMP_FUTURE`).
- `merkle_root` correctness (`BLOCK_ERR_MERKLE_INVALID`).

If Stage 1 fails:
- The block is INVALID and MUST be marked invalid in `block_index_by_hash` with reason category `INVALID_HEADER`.

### Stage 2: Prev-link / ancestry checks

Validate:
- `prev_block_hash` linkage is well-formed.

Cases:
- If `prev_block_hash` is unknown: store as ORPHANED (`status=ORPHANED`) and stop. Do not attempt full validation.
- If `prev_block_hash` is known but marked INVALID: mark this block as INVALID (`INVALID_ANCESTRY`) and stop.

### Stage 3: Candidate chain selection (fork-choice)

Using `block_index_by_hash`:
- compute `cumulative_work` for the candidate by adding this header's work to its parent's cumulative work.
- compare candidate tip(s) to the current `tip` using the CANONICAL fork-choice rule (higher work; deterministic tie-break).

Rules:
- If candidate is not better than current `tip`, the node MAY keep it stored as `VALID_HEADER` but MUST NOT apply it to
  the active UTXO set in Phase 1.
- If candidate is better than current `tip`, proceed to Stage 4 and Stage 5 to apply it (including any required reorg).

### Stage 4: Full block validation against chainstate (consensus)

This is the expensive stage and MUST only run when:
- block is not known-invalid, and
- its parent chain is available, and
- it is a candidate for best chain.

Operator tooling (diagnostics):
- An operator MAY request Stage 4 for a non-candidate block strictly for diagnostics/forensics; such runs MUST NOT mutate
  persistent chainstate, MUST NOT affect fork-choice, and MUST NOT write any `undo_by_block_hash` entries.

Validation:
- Run transaction-level validation in the consensus-defined order.
- Enforce per-block constraints: weight limit, anchor bytes limit, coinbase validity, subsidy+fees cap.
- MUST return the exact consensus error code on failure (see CANONICAL §3.3).

If Stage 4 fails:
- Mark the block INVALID with reason `INVALID_BODY` and persist the failure reason token.
- Do not apply any chainstate changes.

### Stage 5: Apply to chainstate (connect) with undo log

Apply the block to persistent chainstate as an atomic unit:
- compute and persist `undo_by_block_hash[block_hash]`
- update `utxo_by_outpoint` to reflect consumed/created spendable outputs
- update `block_index_by_hash[block_hash]` with `height`, `prev_hash`, `cumulative_work`, and `status=VALID`
- update manifest `tip_hash/tip_height/tip_cumulative_work`

Atomicity (required):
- All DB mutations for Stage 5 MUST commit before manifest update.
- Manifest update is the commit point (see storage model).

## 4. Invalid marking rules

The node MUST distinguish:
- INVALID (proof of invalidity available locally)
- ORPHANED (missing parent)

Propagation:
- If a block is INVALID due to header/body rules, all descendants MUST be treated as INVALID_ANCESTRY without re-validating.

Operational note:
- A node MAY keep invalid block bytes for forensics, but MUST NOT serve them as valid to local APIs.

## 5. Crash recovery (Phase 1)

On startup:
- Read `MANIFEST.json`.
- Treat `MANIFEST.last_applied_*` as the only authoritative applied height.
- If the DB contains data for blocks above manifest tip (e.g., headers, block bytes, index stubs), treat them as stored but not applied.

Hard requirement:
- The node MUST NOT end up with a UTXO set that corresponds to a different tip than manifest.

## 6. Reorg integration points

If a better chain tip arrives:
- find fork point (common ancestor) using `prev_hash` links in `block_index_by_hash`.
- disconnect blocks from old tip down to fork point using `undo_by_block_hash`.
- connect blocks from fork point to new tip using Stage 5.

Deterministic reapply order (required):
- Disconnect order MUST be strictly from the current applied tip down to (but excluding) the fork point, in descending
  height order (tip, tip-1, ..., fork_point+1).
- Connect order MUST be strictly from (and excluding) the fork point up to the new tip, in ascending height order
  (fork_point+1, ..., new_tip).
- Within a block, transactions MUST be applied in their wire order.

Undo format (minimum required fields):
- `undo_by_block_hash[block_hash]` MUST allow deterministic reversal of every spent outpoint in that block. The minimal
  record per spent outpoint is:
  - outpoint: (prev_txid[32], prev_vout[u32])
  - restored_output: (value[u64], covenant_type[u16], covenant_data[bytes])
  - restored_creation_height: u64

Note:
- A fuller reorg/disconnect/connect engineering spec (including crash boundaries and undo schema) is defined in:
  `operational/RUBIN_REORG_DISCONNECT_CONNECT_v1.1.md`.

## 7. Minimal observability hooks (recommended)

Implementations SHOULD emit structured logs for:
- stage transitions for each block (with `block_hash`, `height` if known)
- reason category for invalid marking
- connect/disconnect counts during reorg
- wall-clock timings for Stage 4 and Stage 5
