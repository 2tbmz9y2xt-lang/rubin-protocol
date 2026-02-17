# RUBIN L1 Crypto Agility and Algorithm Upgrade Path v1.1

Status: CANONICAL-AUXILIARY
Date: 2026-02-15
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
