# RUBIN SLH Fallback Playbook

Status: Operational (non-consensus)

Purpose: define a deterministic operational procedure for enabling and operating
`SUITE_ID_SLH_DSA_SHAKE_256F (0x02)` as an emergency signature fallback.

This document does not change consensus rules. Consensus values are defined in
`RUBIN_L1_CANONICAL.md`.

## 1. Consensus Baseline

- `SLH_DSA_ACTIVATION_HEIGHT` is consensus-critical.
- Before `SLH_DSA_ACTIVATION_HEIGHT`, any required spend witness item with
  `suite_id = 0x02` MUST be rejected as `TX_ERR_SIG_ALG_INVALID`.
- At and after `SLH_DSA_ACTIVATION_HEIGHT`, SLH witness items are valid if
  canonical length and signature checks pass.

## 2. Preconditions Before Activation

1. Controller approval for activation height (consensus change window control).
2. Cross-client conformance pass (Go and Rust) on SLH boundary vectors:
   - `height = SLH_DSA_ACTIVATION_HEIGHT - 1` => reject `TX_ERR_SIG_ALG_INVALID`
   - `height = SLH_DSA_ACTIVATION_HEIGHT` => accept (if otherwise valid)
3. Performance benchmark on target validator hardware:
   - P95 block validation latency under SLH traffic within operational budget.
   - No sustained mempool backlog growth under nominal traffic.
4. Upgrade readiness:
   - >= 95% upgraded validators before boundary height.
   - Fallback communication published to operators and exchanges.

## 3. Activation Procedure

1. Freeze release candidates and publish final binaries.
2. Confirm all monitoring dashboards and alerts are green.
3. Announce `SLH_DSA_ACTIVATION_HEIGHT` publicly with UTC timestamp estimate.
4. At boundary height, monitor:
   - block propagation delay,
   - orphan/stale rate,
   - validation CPU saturation,
   - compact block miss/recovery behavior.

## 4. Runtime Guardrails

- Keep SLH as emergency mode; prefer ML-DSA-87 in normal operation.
- Track degradation expectations from `RUBIN_NETWORK_PARAMS.md`:
  - lower L1 TPS in SLH-heavy traffic,
  - higher verification cost per signature.
- If abnormal behavior occurs, trigger incident process and isolate peers with
  malformed or abusive SLH traffic using existing relay policy controls.

## 5. Rollback Policy

Consensus rollback is not automatic after activation height.

If SLH mode causes unacceptable risk:
1. Declare incident and halt new release rollouts.
2. Prepare coordinated consensus update with a new activation plan.
3. Ship patched binaries and execute standard network coordination procedure.

## 6. Audit Artifacts

Before production sign-off, archive:
- conformance run logs (Go/Rust parity),
- benchmark report (hardware + methodology),
- activation readiness checklist,
- post-activation monitoring snapshot (first 24h and 7d).
