# RUBIN L1 Crypto Agility and Algorithm Upgrade Path v1.1

Status: CANONICAL-AUXILIARY
Date: 2026-02-18
Scope: Versioned migration between PQ signature algorithms

## 1. Canonical Rule

1. `suite_id` (also referred to as `alg_id` in earlier drafts) fully determines signature algorithm semantics in consensus contexts. `suite_id` is the canonical field name as defined in `WitnessItem` (CANONICAL §3.1).
2. Unknown `suite_id` in consensus-relevant witness fields is rejected as `TX_ERR_SIG_ALG_INVALID`.
3. Known but inactive `suite_id` (deployment gate NOT ACTIVE at the validated height) MUST be rejected as `TX_ERR_DEPLOYMENT_INACTIVE`.

## 2. Migration Framework (VERSION_BITS-driven)

1. No algorithm replacement is permitted without `VERSION_BITS` deployment state transitions.
2. During transition to `ACTIVE`:
   - Mixed acceptance may be configured by activation profile,
   - Only migration bits explicitly declared in `VERSION_BITS` are valid.
3. `suite_id` values accepted outside activation are consensus-invalid.

### 2.1 Recommended deployment IDs (reserved registry)

This file reserves human-readable `deployment_id` strings for future chain-instance deployment tables
(CANONICAL §8.1). These IDs are *names only*; activation parameters (bit, heights) are chain-instance specific.

Reserved IDs for v1.1-era evolution:

1. `sig_slh_dsa_p2pk_v1`:
   - Feature summary: permit `suite_id = 0x02` in `CORE_P2PK` spends (and any other key-based covenants that reuse the same witness semantics).
2. `sig_alt_dsa_slot_v1`:
   - Feature summary: reserve a future `suite_id` for a second post-quantum signature family (e.g., FN-DSA/Falcon if standardized/selected), including fixed canonical pubkey/sig lengths and error mapping.
   - Note: this deployment MUST include a `verify_cost` field in its deployment table entry (see §6.3) determined by benchmark before `start_height` is published.
3. `p2p_hybrid_kex_v1` (non-consensus transport profile):
   - Feature summary: allow an operator-enforced hybrid handshake mode (e.g., ECDH + ML-KEM) for P2P links. This does not change block validity; it is a network policy/interop profile.

Important: `p2p_hybrid_kex_v1` MUST NOT be used as a consensus gate. It is listed here only to align naming
across spec/operational documents.

## 3. SLH-DSA Sequencer Constraint

1. For `CORE_P2PK`, if `suite_id=0x02` is used before explicit migration activation,
   validation MUST fail as `TX_ERR_DEPLOYMENT_INACTIVE`.
2. RETL sequencer signatures are restricted by separate deployment policy and remain at `suite_id=0x02` unless a future profile defines otherwise.

## 4. Rollout / Rollback (chain safety)

1. Block validity is determined by the VERSION_BITS deployment state at the height
   of the block being validated, NOT at the height of the current chain tip.
   Formally: for block `B` at height `h`, the set of accepted `suite_id` values
   is `AcceptedSuites(deployment_state(h))`. A reorg that changes the tip does not
   retroactively invalidate blocks whose `suite_id` was valid at their own height.
2. Rollback must preserve reorg safety:
   - if a chain includes signatures with `suite_id` that was ACTIVE at block height `h`,
     those blocks remain valid even if a reorg causes `suite_id` to revert to DEFINED
     at a later tip height.
3. New activation may never loosen constraints before block validity gates for that
   deployment are met.
4. Deactivation of a `suite_id` (transition to FAILED) does not invalidate previously
   confirmed blocks — it only prevents new blocks from using that `suite_id`.

## 5. Dual-sign and Shadow-TX (non-consensus migration protocol)

RUBIN v1.1 does not include a general script system. A single input contains exactly one `WitnessItem`,
so a consensus-level *dual-signature per input* is not representable without a new covenant type.

However, a robust migration still requires an operational protocol that:

1. permits wallets/bridges/L2 to bind a "new" PQ key to an "old" PQ key (or old algorithm choice),
2. mitigates harvest-now-decrypt-later risks for long-lived identities,
3. does not change block validity rules until the network explicitly activates a consensus deployment.

### 5.1 Shadow-binding envelope (CORE_ANCHOR)

Wallets MAY publish a cryptographic binding between keys using a `CORE_ANCHOR` output.
This is not a spend condition; it is an auditable on-chain statement.

Recommended envelope (application-layer, non-consensus):

```
ASCII("RUBIN-KEYMIG-v1") ||
old_suite_id:u8 || old_pubkey:bytes || 
new_suite_id:u8 || new_pubkey:bytes ||
sig_old_over_new || sig_new_over_old
```

Rules:

1. `sig_old_over_new` is a signature by the old key over `SHA3-256(new_suite_id || new_pubkey)`.
2. `sig_new_over_old` is a signature by the new key over `SHA3-256(old_suite_id || old_pubkey)`.
3. Observers can treat this as a bidirectional binding that survives partial compromise assumptions.

Because this is an ANCHOR payload, it is subject to ANCHOR size/weight policy and does not alter consensus.

### 5.2 Shadow-TX for bridges/L2

Bridges/L2 systems that require key migration without halting operations SHOULD:

1. continue to accept v1.1 consensus spends with the currently ACTIVE `suite_id`,
2. require an associated shadow-binding envelope (above) before accepting a new key as authoritative,
3. switch their internal authorization to the new key only after a safety delay (e.g., K confirmations).

This yields "dual-sign security" at the application layer while keeping L1 minimal and deterministic.

## 6. VERIFY_COST Parameters and Update Process

### 6.1 Current values (v1.1)

`VERIFY_COST_*` constants are defined in `spec/RUBIN_L1_CANONICAL_v1.1.md §1.2`:

```
VERIFY_COST_ML_DSA   = 8
VERIFY_COST_SLH_DSA  = 64
```

These values enter the block weight formula (CANONICAL §11):

```
sig_cost = ml_count * VERIFY_COST_ML_DSA + slh_count * VERIFY_COST_SLH_DSA
weight(T) = 4 * base_size + wit_size + sig_cost
```

### 6.2 Why VERIFY_COST cannot be updated via VERSION_BITS alone

`VERIFY_COST_*` affect the weight of **every transaction** that uses the corresponding
`suite_id`, including transactions already confirmed in the chain. A retroactive change
to `VERIFY_COST_*` would alter the computed weight of historical blocks, breaking
deterministic re-validation — a consensus split hazard.

Therefore:

> **Rule**: `VERIFY_COST_*` for existing `suite_id` values (`0x01`, `0x02`) MUST NOT
> be changed via a VERSION_BITS deployment. They can only change via a new canonical
> revision of `RUBIN_L1_CANONICAL_v1.1.md`, which requires a hard fork.

A VERSION_BITS deployment MAY introduce a `VERIFY_COST` for a **new** `suite_id` (see §6.3).

### 6.3 New algorithm activations — declaring VERIFY_COST

When a deployment activates a new `suite_id` (e.g., `sig_alt_dsa_slot_v1` for FN-DSA),
the deployment table entry MUST include a `verify_cost` field. This extends the normative
schema from `CANONICAL §8.1`:

Extended deployment table schema for algorithm-adding deployments:

| deployment_id | bit | start_height | timeout_height | signal_window | threshold | state_machine | verify_cost | feature_summary |
|---|---:|---:|---:|---:|---:|---:|---:|---|

`verify_cost` is:
- Required when `feature_summary` introduces a new `suite_id`.
- Omitted (or set to `—`) for deployments that do not introduce a new `suite_id`.
- An integer in `[0, 65535]` representing the weight cost per input using the new algorithm.
- Applied identically to `VERIFY_COST_ML_DSA`/`VERIFY_COST_SLH_DSA` in the weight formula from the activation height onwards.

**Determination process for `verify_cost`:**

The value MUST be determined by benchmark before the deployment `start_height` is published:

1. Measure median single-thread verification time for one signature of the new algorithm
   on reference hardware (to be defined per deployment, at minimum an x86-64 node
   representative of validator infrastructure).
2. Express as a ratio relative to `VERIFY_COST_ML_DSA = 8` (which represents one
   ML-DSA-87 verification unit).
3. Round up to the nearest integer. Minimum value: `1`.
4. Publish the benchmark methodology and raw numbers alongside the deployment table.

Example: if FN-DSA verification takes 3× longer than ML-DSA-87 per signature,
`verify_cost = 24`. If it takes 0.5×, `verify_cost = 4` (minimum 1).

Rationale: cost proportional to verification time ensures that a block filled with
the cheapest-to-create but slowest-to-verify algorithm cannot exceed the block time
budget, preserving the invariant `BlockWeight ≤ MAX_BLOCK_WEIGHT` as a proxy for
maximum validation latency.

### 6.4 Cost recalibration (hard fork path)

If benchmarks show that a deployed algorithm's actual verification cost has diverged
significantly from its `VERIFY_COST_*` value (e.g., due to hardware improvements
or cryptographic implementation optimizations), recalibration requires:

1. A new canonical revision (e.g., `RUBIN_L1_CANONICAL_v1.2.md`).
2. Updated `VERIFY_COST_*` constants in that revision.
3. A hard fork height `H_recal` at which the new values take effect.
4. Updated conformance vectors covering the boundary block at `H_recal`
   (per CANONICAL §8 P0 item 3: "Any change to consensus weight accounting
   MUST be accompanied by updated conformance vectors").
5. All historical blocks before `H_recal` are re-validated using the **old** constants;
   all blocks at `H_recal` and later use the **new** constants.

This is a consensus-breaking change and MUST follow the full release gate process
in `operational/RUBIN_L1_FREEZE_TRANSITION_POLICY_v1.1.md §4`.

### 6.5 Conformance requirement

Any deployment introducing a new `suite_id` with a declared `verify_cost` MUST
add a conformance vector to `CV-WEIGHT` (or a new `CV-WEIGHT-<alg>` gate) covering:

- a single-input transaction using the new `suite_id` with known pubkey/sig lengths,
- the expected `weight(T)` computed with the declared `verify_cost`,
- a boundary block at `MAX_BLOCK_WEIGHT` using the new algorithm exclusively.

This ensures cross-client weight determinism before the deployment reaches LOCKED_IN.
