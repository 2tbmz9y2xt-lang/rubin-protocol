# POLICY: DA/anchor anti-abuse (policy-only; non-consensus)

This document describes **non-consensus** policy guardrails intended to reduce arbitrary DA/anchor payload abuse
without changing consensus validity rules.

Tracking issue: `rubin-protocol#353`.

## Scope

Policy is enforced by the miner template builder (and can be reused by wallet/mempool admission where applicable).

## Rules

1. **Non-coinbase CORE_ANCHOR is non-standard**
   - Transactions creating `CORE_ANCHOR` outputs (`COV_TYPE_ANCHOR`) are excluded from policy-compliant templates.
   - Coinbase witness commitment output remains allowed (coinbase-only behavior).

2. **DA template byte budget cap (policy-only)**
   - Total DA payload bytes included in a template are capped by `PolicyMaxDaBytesPerBlock`.
   - Default is a conservative fraction of the consensus DA cap (initially `MAX_DA_BYTES_PER_BLOCK / 4`).

3. **DA fee surcharge (optional, policy-only)**
   - For transactions with `da_bytes(tx) > 0`, enforce:
     - `fee(tx) >= da_bytes(tx) * PolicyDaSurchargePerByte`
   - Disabled by default (`PolicyDaSurchargePerByte = 0`).

## Notes

- This policy does not alter consensus validity or error codes.
- Parameters are controller-tunable and should be rolled out with observability/rollback gates.

