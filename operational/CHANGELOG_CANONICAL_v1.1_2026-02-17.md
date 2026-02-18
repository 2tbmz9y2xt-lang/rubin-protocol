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
- Economics constants were finalized in CANONICAL v1.1 (landed 2026-02-18):
  - `BASE_UNITS_PER_RBN = 100_000_000`,
  - `MAX_SUPPLY = 100,000,000 RBN`,
  - mined subsidy emission is linear over 25 years:
    - `SUBSIDY_TOTAL_MINED = 99,000,000 RBN`,
    - `SUBSIDY_DURATION_BLOCKS = 1_314_900`,
    - remainder is distributed to earliest blocks (`BASE+1` for the first `REM` blocks).
  - Genesis allocations (e.g., premine) are chain-instance decisions and are bounded operationally
    by the gap `MAX_SUPPLY - SUBSIDY_TOTAL_MINED = 1,000,000 RBN` (1% of total).

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
