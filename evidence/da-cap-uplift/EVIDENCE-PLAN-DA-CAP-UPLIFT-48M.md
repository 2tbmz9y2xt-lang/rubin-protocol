# EVIDENCE PLAN: DA Cap Uplift 32M -> 48M

**Status:** Draft / non-normative  
**Type:** Evidence plan before any controller discussion  
**Home:** `rubin-protocol/evidence/da-cap-uplift/`  
**Related issue:** `rubin-protocol#820`  
**Scope boundary:** This document defines how to measure whether a future uplift of `MAX_DA_BYTES_PER_BLOCK` from `32_000_000` to `48_000_000` would be operationally safe enough to bring to controller review. It does **not** approve the uplift, change consensus constants, change policy defaults, or recommend activation.

---

## 1. Goal

Build a reproducible evidence program that can answer four questions before any consensus proposal exists:

1. Does the current `32 MB` DA cap already behave cleanly under saturated and adversarial load?
2. Do `48 MB`-equivalent pressure scenarios remain within acceptable propagation, orphaning, memory, and relay-fallback bounds?
3. Do Go and Rust remain behaviorally aligned under stressed DA conditions?
4. Would a future uplift materially increase validator centralization pressure through bandwidth, memory, or operator hardware requirements?

This is an evidence lane, not a decision lane.

---

## 2. Inputs and Baseline

### 2.1 Baseline constants

The evidence program starts from the current canonical baseline:

- `MAX_DA_BYTES_PER_BLOCK = 32_000_000`
- `CHUNK_BYTES = 524_288`
- `MAX_DA_CHUNK_COUNT = 61`

### 2.2 Pressure-point parameters to review

The evidence program must explicitly measure and review the operational surfaces most likely to absorb pressure if the DA cap is ever raised:

- `PREFETCH_BYTES_PER_SEC`
- `PREFETCH_GLOBAL_BPS`
- `DA_MEMPOOL_PINNED_PAYLOAD_MAX`
- `RELAY_TIMEOUT_RATE`
- `DA_ORPHAN_POOL_SIZE`

### 2.3 Comparison lane

Every benchmark family must include:

- a `32 MB` baseline run;
- a `48 MB`-equivalent pressure run, using either controlled uplifted environments or traffic patterns that faithfully emulate the larger DA envelope.

The point is not only to measure the current network contour, but to compare it against the prospective stress shape.

---

## 3. Scope

### 3.1 In scope

- Saturated-load measurements for DA-heavy block production and propagation.
- Adversarial DA relay / orphan / prefetch scenarios.
- Controlled devnet/testnet DA demand campaigns.
- Go/Rust parity checks under DA stress.
- Review of the five pressure-point operational parameters listed above.
- Hardware-tier comparison sufficient to assess centralization pressure.
- A reproducible acceptance package for later controller review.

### 3.2 Out of scope

- Changing consensus constants.
- Changing policy defaults.
- Changing `MAX_BLOCK_BYTES`.
- Recommending activation.
- Treating this evidence plan as proof that `48 MB` is the preferred outcome.

---

## 4. Hardware Tiers

Evidence must not be collected only on powerful operator hardware.

At minimum, every benchmark family must run on:

- **Baseline validator tier:** representative hardware for a serious validator/operator.
- **Constrained tier:** a meaningfully weaker machine that still represents a plausible honest node.

If possible, also include:

- **Recommended tier:** the hardware profile Rubin would be comfortable recommending if DA-heavy operation becomes common.

The report must identify the hardware class used for every run.

---

## 5. Benchmark Families

### 5.1 Saturated-load baseline

Purpose:

- establish reproducible `32 MB` behavior;
- establish reproducible `48 MB`-equivalent behavior;
- compare them on the same network topologies and hardware tiers.

Required measurements:

- block propagation latency;
- compact/relay reconstruction success and fallback rate;
- orphan rate;
- prefetch completion time;
- peak RSS / memory spikes;
- CPU wall-clock on DA validation paths.

### 5.2 Adversarial relay scenarios

Purpose:

- measure how expensive the DA path becomes under malicious or degraded peer behavior.

Required scenarios:

- delayed chunk delivery;
- missing chunk / partial-set behavior;
- duplicate or redundant chunk delivery;
- peer churn during active DA propagation;
- orphan-pool pressure near configured limits;
- prefetch saturation near configured per-peer and global limits.

The point of this lane is not throughput alone. It is resilience under Byzantine or degraded relay conditions.

### 5.3 Controlled demand campaigns

Purpose:

- approximate real DA demand without waiting for mainnet demand to appear.

Required campaigns:

- repeated DA-heavy block windows;
- mixed L1 + DA contention windows;
- bursty demand rather than only smooth sustained demand;
- runs where DA-heavy blocks are rare and runs where they are clustered.

### 5.4 Parity lane

Purpose:

- ensure that stressed DA conditions do not cause Go/Rust divergence in validation or recovery behavior.

Required checks:

- identical accept/reject outcomes for the same stress cases;
- identical error ordering where the contract is deterministic;
- no evidence that one client degrades into a materially different fallback path.

---

## 6. Metrics and Thresholds

This issue must not rely on undefined “agreed thresholds”.

As part of the evidence lane, Rubin must first publish or pin the thresholds used for:

- propagation latency;
- orphan rate;
- relay fallback rate;
- peak memory / sustained memory pressure;
- prefetch completion behavior;
- parity pass/fail expectations.

If an existing Rubin SLO or benchmark target document already defines some of these, the evidence package should cite that source directly. If not, the thresholds must be defined explicitly before the final comparison verdict is written.

---

## 7. Centralization Pressure Assessment

The evidence package must explicitly answer:

- whether bandwidth requirements rise materially;
- whether memory requirements rise materially;
- whether validator/operator hardware expectations rise materially;
- whether the constrained hardware tier begins to fail or degrade nonlinearly under `48 MB`-equivalent pressure.

If the answer to any of these is “yes”, the evidence package must say so directly even if raw throughput results look attractive.

Throughput gains are not sufficient if they come with unacceptable validator centralization pressure.

---

## 8. Exit Criteria

Evidence is sufficient for later controller review only if all of the following are true:

- the saturated `32 MB` baseline is measured and reproducible;
- `48 MB`-equivalent scenarios are measured under the same benchmark families;
- the constrained hardware tier is included in the evidence package;
- stressed scenarios stay within explicitly defined propagation, orphan, memory, and relay-fallback thresholds;
- Go/Rust parity remains unchanged under stressed DA scenarios;
- the five pressure-point parameters are reviewed and either confirmed unchanged or paired with an explicit rationale for future adjustment;
- the centralization-pressure assessment is explicit rather than implied.

If any item is missing, the evidence lane is incomplete and should not be treated as controller-ready.

---

## 9. Deliverables

The evidence program should produce:

1. a benchmark matrix with hardware tier, topology, traffic shape, and DA profile;
2. reproducible raw results or scripts sufficient to replay the measurements;
3. a short comparison summary: `32 MB baseline` vs `48 MB`-equivalent pressure;
4. a relay-parameter review note covering the five pressure-point parameters;
5. a centralization-pressure note;
6. a final recommendation package stating one of:
   - insufficient evidence;
   - evidence supports further controller discussion;
   - evidence suggests the uplift should not proceed.

None of these outputs by themselves change consensus rules.

---

## 10. Relationship to Design Work

This document complements, but does not replace, a separate design note describing what would need to change if the evidence package later supports a `48 MB` uplift.

The separation is intentional:

- this plan asks **how to measure**;
- a design note asks **what would change if the answer is favorable**.

Keeping those apart reduces the risk of turning evidence collection into a hidden pre-approval path.
