# RUBIN Theorem / Invariant Index v1.1

Status: NON-NORMATIVE (active)
Date: 2026-02-18
Audience: implementers + auditors + formal-methods contributors

This index records all consensus-critical invariants for RUBIN L1 v1.1.
For toolchain rationale and proof strategy see `formal/RUBIN_FORMAL_APPENDIX_v1.1.md`.

Proof status:
- `spec+vector`  — stated in canonical spec, covered by conformance vector; Lean 4 proof pending
- `spec+axiom`   — depends on cryptographic hardness assumption; stated as `axiom` in Lean 4 model
- `lean4-proven` — machine-checked at pinned commit (none yet; target: production freeze)
- `pending`      — not yet covered by spec section or conformance vector

---

## Determinism and State

### T-001 — Sighash determinism: output_count=0 edge case

- **Statement**: `hashOutputs(tx)` when `tx.output_count = 0` MUST equal `SHA3-256("")` (empty preimage), not an implementation-defined value.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §4.2` hashOutputs rule
- **Evidence**: `conformance/fixtures/CV-SIGHASH.yml` SIGHASH-06
- **Status**: `spec+vector`

### T-004 — ApplyBlock determinism

- **Statement**: For fixed `(UTXOSet, chain_id, height, timestamp, BlockBytes)`, `ApplyBlock` returns a uniquely determined `(UTXOSet', outcome)`. No valid implementation may return different outcomes for identical inputs.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §9 inv-1`
- **Evidence**: `CV-BLOCK`, `CV-UTXO` (all tests are deterministic by construction)
- **Status**: `spec+vector`

### T-010 — Replay protection: (chain_id, tx_nonce) uniqueness

- **Statement**: A transaction accepted into a valid chain at height `h` with `(chain_id, tx_nonce)` MUST NOT be re-accepted at any height `h' > h` in the same chain. Cross-chain replay is prevented by `chain_id` domain separation in sighash.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §3.4`
- **Evidence**: `CV-UTXO` (double-spend vector)
- **Status**: `spec+vector`

### T-012 — CompactSize round-trip

- **Statement**: For all `n : ℕ` with `n < 2^64`, `decode(encode(n)) = n` and `encode` is canonical (no non-minimal encodings accepted).
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §3.2.1`
- **Evidence**: `conformance/fixtures/CV-COMPACTSIZE.yml`
- **Status**: `spec+vector`

---

## Value and UTXO Integrity

### T-005 — Value conservation: non-coinbase

- **Statement**: For any valid non-coinbase `Tx`: `Σ output.value ≤ Σ spent_utxo.value`. Fee = difference ≥ 0.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §9 inv-2`, §4.5
- **Evidence**: `conformance/fixtures/CV-FEES.yml` FEES-02 (TX_ERR_VALUE_CONSERVATION)
- **Status**: `spec+vector`

### T-006 — Non-spendable ANCHOR exclusion from UTXO

- **Statement**: Any output with `covenant_type = CORE_ANCHOR` MUST NOT be added to the spendable UTXO set. Any attempt to spend a `CORE_ANCHOR` output MUST be rejected as `TX_ERR_MISSING_UTXO`.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §9 inv-3`, §3.6
- **Evidence**: `CV-UTXO`
- **Status**: `spec+vector`

### T-015 — Coinbase subsidy non-overflow (PENDING)

- **Statement**: For all block heights `h`, the coinbase subsidy formula produces a value in `[0, 2^64 − 1]` with no integer overflow. Halving epochs reduce subsidy monotonically to zero.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §4.4`
- **Evidence**: no dedicated conformance vector yet
- **Status**: `pending` — needs T-015 conformance vector in CV-FEES or new CV-COINBASE gate

---

## Covenant Semantics

### T-009 — HTLC_V2 envelope uniqueness (prefix-scoped matching)

- **Statement**: The matching set `M` for a `CORE_HTLC_V2` input is filtered strictly by `anchor_data[0:22] = "RUBINv1-htlc-preimage/"` AND `|anchor_data| = 54`. Non-HTLC anchors never contribute to `|M|`. Outcome is uniquely determined by `|M| ∈ {0, 1, ≥2}`.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §4.1 item 6`
- **Evidence**: `CV-HTLC-ANCHOR` HTLC2-08 (extra non-matching anchor → SIG_INVALID, not PARSE), HTLC2-09 (two matching → PARSE), HTLC2-10 (multi-app narrative)
- **Closes**: Q-048
- **Status**: `spec+vector`

### T-011 — CORE_VAULT_V1 spend_delay monotonicity

- **Statement**: The `spend_delay` field in `CORE_VAULT_V1` extended form enforces `height(B) ≥ o.creation_height + spend_delay`. This is monotone: once satisfiable at height `h`, it remains satisfiable at all `h' > h`.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §4.1 item 5`
- **Evidence**: `conformance/fixtures/CV-VAULT.yml` VAULT-06
- **Status**: `spec+vector`

### T-016 — Anchor relay cap non-interference (PENDING)

- **Statement**: The relay policy `MAX_ANCHOR_PAYLOAD_RELAY = 1_024` is strictly narrower than the consensus `MAX_ANCHOR_PAYLOAD_SIZE = 65_536`. Any block containing a `CORE_ANCHOR` output with `|anchor_data| ∈ (1024, 65536]` is consensus-valid even if the originating transaction was relay-rejected.
- **Spec**: `operational/RUBIN_NODE_POLICY_DEFAULTS_v1.1.md §3.1`
- **Evidence**: `CV-ANCHOR-RELAY` RELAY-08 (documents the gap)
- **Status**: `pending` — separation lemma not yet formally stated; RELAY-08 is narrative only

---

## Cryptographic and Hash Invariants

### T-002 — Difficulty retarget 320-bit arithmetic

- **Statement**: The intermediate product `target_old × T_actual` in §6.4 requires at least 320-bit unsigned arithmetic. Any implementation using narrower integers silently truncates and produces incorrect `target_new`, causing a consensus split.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §6.4`
- **Evidence**: `conformance/fixtures/CV-BLOCK.yml` BLOCK-09
- **Status**: `spec+vector`

### T-008 — Sighash domain separation by chain_id

- **Statement**: For any two signing contexts with `ctx1.chain_id ≠ ctx2.chain_id`, `SighashPreimage(I, ctx1) ≠ SighashPreimage(I, ctx2)` (structurally, by construction of the preimage). A valid signature for chain A cannot be a valid signature for chain B.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §4.2` (ASCII("RUBINv1-sighash/") || chain_id prefix)
- **Evidence**: `CV-SIGHASH`
- **Status**: `spec+axiom` (relies on SHA3-256 collision resistance for hash distinctness; structural separation is provable without axiom)

### T-013 — Merkle root collision resistance

- **Statement**: For two distinct transaction sets `{T_1,...,T_n}` and `{T_1',...,T_m'}`, their Merkle roots (as computed by §5.1.1) are equal with probability at most `2^{-256}`, modeled as a cryptographic axiom over SHA3-256.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §5.1.1`
- **Evidence**: `CV-BLOCK` BLOCK-05
- **Status**: `spec+axiom`

### T-017 — key_id collision resistance (PENDING)

- **Statement**: For two distinct public keys `pk1 ≠ pk2` (of the same or different `suite_id`), `SHA3-256(pk1_wire) ≠ SHA3-256(pk2_wire)` with probability `1 − 2^{-256}`. Two different keys cannot bind to the same `key_id`.
- **Spec**: `spec/RUBIN_L1_KEY_MANAGEMENT_v1.1.md §1.2` (`key_id = SHA3-256(pubkey_wire)`)
- **Evidence**: no dedicated conformance vector
- **Status**: `pending` (needs a CV-BIND vector covering collision scenario)

---

## VERSION_BITS and Deployment

### T-003 — VERSION_BITS boundary transition ordering

- **Statement**: At each window boundary, transitions are evaluated in the order: DEFINED→STARTED, STARTED→LOCKED_IN, STARTED→FAILED, LOCKED_IN→ACTIVE. If LOCKED_IN fires, FAILED MUST NOT be evaluated in the same boundary.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §8 FSM`
- **Evidence**: `conformance/fixtures/CV-DEP.yml` DEP-05
- **Status**: `spec+vector`

### T-007 — VERSION_BITS monotonicity

- **Statement**: For any deployment `D` and chain `C`, state transitions are monotone: once `ACTIVE`, always `ACTIVE`; once `FAILED`, always `FAILED`. No backwards transitions exist for a fixed chain history.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §9 inv-4`
- **Evidence**: `CV-DEP` DEP-04
- **Status**: `spec+vector`

---

## Weight and Fee Arithmetic

### T-014 — Block weight non-overflow

- **Statement**: `BlockWeight(B)` for any valid block fits in a u64. Given `MAX_BLOCK_WEIGHT`, `MAX_TX_COUNT`, and `VERIFY_COST_*` bounds from §1.2, the maximum theoretical weight is well below `2^64 − 1`.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §4.3`, §11
- **Evidence**: `conformance/fixtures/CV-WEIGHT.yml`
- **Status**: `spec+vector`

---

## Reorg Safety

### T-018 — Reorg determinism (PENDING)

- **Statement**: For any two chains `C1` and `C2` sharing a common ancestor at height `h`, and any block `B` at height `h+k` present in both, `ApplyBlock^k(S_h, B_{h+1}..B_{h+k})` produces the same final `UTXOSet` regardless of which chain tip was the node's previous best chain.
- **Spec**: `spec/RUBIN_L1_CANONICAL_v1.1.md §2` (ApplyBlock is defined over block bytes, not chain state)
- **Evidence**: `CV-REORG`
- **Status**: `pending` — CV-REORG covers the behavioral outcome; formal statement not yet written

---

## Open / Pending Summary

| ID | Title | Blocker |
|----|-------|---------|
| T-015 | Coinbase subsidy non-overflow | needs CV-COINBASE |
| T-016 | Anchor relay cap non-interference | needs formal separation lemma |
| T-017 | key_id collision resistance | needs CV-BIND vector |
| T-018 | Reorg determinism | needs formal statement |

All T-xxx entries with `lean4-proven` status are required before production freeze
per `operational/RUBIN_L1_FREEZE_TRANSITION_POLICY_v1.1.md §4`.
