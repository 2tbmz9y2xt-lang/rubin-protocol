# RUBIN L1 Crypto Agility and Algorithm Upgrade Path v1.1

Status: CANONICAL-AUXILIARY
Date: 2026-02-15
Scope: Versioned migration between PQ signature algorithms

## 1. Canonical Rule

1. `suite_id` (also referred to as `alg_id` in earlier drafts) fully determines signature algorithm semantics in consensus contexts. `suite_id` is the canonical field name as defined in `WitnessItem` (CANONICAL §3.1).
2. Unknown `suite_id` in consensus-relevant witness fields is rejected as `TX_ERR_SIG_ALG_INVALID`.
3. Known but inactive `suite_id` (deployment gate NOT ACTIVE at the validated height) MUST be rejected as `TX_ERR_DEPLOYMENT_INACTIVE`.

## 2. Migration Framework

1. No algorithm replacement is permitted without `VERSION_BITS` deployment state transitions.
2. During transition to `ACTIVE`:
   - Mixed acceptance may be configured by activation profile,
   - Only migration bits explicitly declared in `VERSION_BITS` are valid.
3. `suite_id` values accepted outside activation are consensus-invalid.

## 3. SLH-DSA Sequencer Constraint

1. For `CORE_P2PK`, if `suite_id=0x02` is used before explicit migration activation,
   validation MUST fail as `TX_ERR_DEPLOYMENT_INACTIVE`.
2. RETL sequencer signatures are restricted by separate deployment policy and remain at `suite_id=0x02` unless a future profile defines otherwise.

## 4. Rollout / Rollback

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
