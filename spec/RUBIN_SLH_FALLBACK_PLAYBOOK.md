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
3. Performance benchmark on target validator hardware (see §2.1):
   - P95/P99 block validation latency under SLH-heavy traffic within SLO.
   - Propagation delay and stale/orphan rate within SLO.
   - No sustained mempool backlog growth under nominal traffic.
   - Benchmark backend MUST match repository profile in
     `RUBIN_CRYPTO_BACKEND_PROFILE.md` (OpenSSL 3.5+ path).
4. Upgrade readiness:
   - >= 95% upgraded validators before boundary height.
   - Fallback communication published to operators and exchanges.

### 2.1 Performance SLO (numeric)

These SLOs are **operational** and are used to decide whether activation is safe
and whether post-activation conditions require incident escalation. They do not
change consensus.

**Hardware profile (baseline for measurements)**
- CPU: 16 physical cores (x86_64), >= 3.0 GHz base
- RAM: 32 GiB
- Storage: NVMe SSD
- Network: 1 Gbps, stable RTT <= 50 ms to at least 8 peers

**Implementation guidance (non-consensus)**
- In SLH-heavy validation, implementations SHOULD use parallel verification
  across independent transactions / inputs using a worker pool mapped to
  available physical cores (baseline target: 16 cores).
- In this profile, SLH-DSA-SHAKE-256f has no batch-verify path; performance is
  achieved via parallelism, unlike ML-DSA-87 batch verification in
  `RUBIN_COMPACT_BLOCKS.md` §12.

**Benchmark workload (SLH-heavy)**
- Block template: >= 90% of `MAX_BLOCK_WEIGHT`
- Signature mix: >= 80% of required spend witness items use `suite_id = 0x02`
- DA: disabled for benchmark (no DA payloads), to isolate signature verification

**Validation SLO (local, per block)**
- Block validation latency (end-to-end, including tx+UTXO checks):
  - P95 <= 2.0 s
  - P99 <= 5.0 s
- CPU saturation (process-level):
  - sustained (5 min) <= 90% average
  - no single-core pegged at 100% for > 60 s due to a validation hot loop

**Propagation / liveness SLO (network)**
- Block propagation delay (first-seen -> >= 80% of monitored peers report seen):
  - P95 <= 3.0 s
  - P99 <= 8.0 s
- Stale/orphan rate (rolling window, excluding reorg drills):
  - <= 1.0% over 6 hours

**Mempool health SLO (network-wide symptom proxy)**
- Mempool backlog (rolling 60 min):
  - MUST NOT grow monotonically for > 60 min at steady input rate
  - SHOULD stay <= 5 blocks worth of weight (approx `5 × MAX_BLOCK_WEIGHT`)

**Measurement requirements**
- Record raw samples and compute P95/P99 from >= 1,000 blocks or an equivalent
  synthetic replay (>= 24 hours at target load).
- Publish benchmark methodology (node version, flags, peer count, dataset).

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

### 5.1 Rollback Triggers (numeric)

“Rollback trigger” means: **initiate incident process immediately** and prepare
a coordinated network response. It does **not** imply automatic chain rollback.

Trigger any of the following if attributable to SLH mode (not to a known
partition or planned maintenance):

- **T-1: Validation latency blow-up**
  - P99 block validation latency > 10 s for >= 30 min (rolling), or
  - P99 > 20 s at any time.
- **T-2: Propagation regression**
  - P99 propagation delay > 15 s for >= 30 min (rolling), or
  - P95 > 6 s for >= 60 min (rolling).
- **T-3: Stale/orphan spike**
  - stale/orphan rate > 3.0% over 60 min, or
  - stale/orphan rate > 1.5% over 6 hours.
- **T-4: Network throughput collapse**
  - mempool backlog exceeds 10 blocks worth of weight for >= 120 min, or
  - backlog grows monotonically for >= 120 min at steady input rate.

**Controller gate:** any consensus rollback / reconfiguration plan still requires
explicit controller approval and a coordinated release.

## 6. Audit Artifacts

Before production sign-off, archive:
- conformance run logs (Go/Rust parity),
- benchmark report (hardware + methodology),
- activation readiness checklist,
- post-activation monitoring snapshot (first 24h and 7d).
