# CANONICAL v1.1 Changelog (internal) — 2026-02-17

Scope: summary of consensus-spec text changes made during the 2026-02-17 hardening pass.

This document is non-normative. The authoritative text is:
- `spec/RUBIN_L1_CANONICAL_v1.1.md`

## 1. Economy / minting

- Added a normative definition of `fees(T) = sum_in(T) - sum_out(T)` for non-coinbase transactions and clarified that coinbase fees are undefined.
- Rewrote the coinbase minting bound in explicit terms:
  - `sum(coinbase.outputs.value) ≤ block_subsidy(height) + Σ fees(T_i)` over all non-coinbase tx in the same block.
- Added a normative genesis exception:
  - for height `0`, the coinbase bound is not evaluated; genesis outputs are chain-instance allocations fixed by published genesis bytes.
- Updated consensus constants to the agreed issuance plan:
  - `MAX_SUPPLY = 100,000,000 RBN` (8 decimals),
  - `SUBSIDY_HALVING_INTERVAL = 420,000`,
  - genesis burn allocation `GENESIS_BURN_SAT = 1,000 RBN`,
  - developer fund premine `GENESIS_DEV_FUND_SAT = 1,000,000 RBN` across `GENESIS_DEV_FUND_OUTPUTS = 100`,
  - `BLOCK_SUBSIDY_INITIAL` adjusted so that mined emission plus genesis allocations stays under `MAX_SUPPLY`.

## 2. HTLC via ANCHOR (CORE_HTLC_V2)

- Changed redeem anchor rule from "exactly one CORE_ANCHOR output in the transaction" to a prefix-scoped rule:
  - redeem requires exactly one matching HTLC anchor envelope among CORE_ANCHOR outputs (length 54 and prefix `RUBINv1-htlc-preimage/`),
  - additional non-matching CORE_ANCHOR outputs are permitted.

## 3. Determinism / clarity notes

- Clarified the scope of lexicographic ordering requirements (§3.5) to avoid confusion with wire-order-defined iteration.
- Added non-normative guidance on practical max inputs being bounded by `MAX_WITNESS_BYTES_PER_TX`.
- Added non-normative guidance on integer-division rounding and the relationship between `MAX_SUPPLY` and realized emission (now expressed in terms of `MAX_SUPPLY` minus genesis allocations).

## 4. VERSION_BITS / deployments publication

- Added a normative requirement to publish a per-network deployments registry file:
  - `spec/RUBIN_L1_DEPLOYMENTS_<network>_v1.1.md`,
  - and listed minimum expected deployment_ids for v1.1 (`sig_suite_02_v1`, `htlc_anchor_v1`) if the features exist.

