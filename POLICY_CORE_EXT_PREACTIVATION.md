# Policy: CORE_EXT pre-activation guardrails (non-consensus)

Consensus permits `CORE_EXT` spends pre-activation under the keyless-sentinel rule (in practice: anyone-can-spend).
This file documents the required **policy-only** guardrails to prevent accidental fund loss before an intended
deployment profile is ACTIVE.

## Guardrails (recommended defaults)

1. **Wallet policy (mandatory for user safety):**
   - Wallets MUST NOT create transactions that produce `CORE_EXT` outputs until the intended `ext_id` profile is known
     ACTIVE under CANONICAL §23.2.2.

2. **Mempool/relay policy (non-standard):**
   - Nodes SHOULD reject (as non-standard) transactions that create or spend `CORE_EXT` while the relevant profile is
     not ACTIVE.

3. **Miner template policy:**
   - Miners SHOULD exclude such transactions from block templates to avoid including anyone-can-spend funds by mistake.

4. **Strict mode:**
   - Production profiles SHOULD default to strict mode ON (fail-closed).

## Current implementation status

`rubin-node` is a minimal node and does not yet implement a full tx mempool/relay or wallet.
The currently implemented guardrail is **miner template filtering**:

- By default, `Miner` excludes any transaction that creates a `CORE_EXT` output or spends a `CORE_EXT` UTXO.
- This is policy-only and does not change consensus validity.

## Rationale

If `CORE_EXT` outputs are created pre-activation, they may be spent by anyone under consensus rules (no signature),
which is indistinguishable from user error after the fact. Policy guardrails must block creation, not only spend.

