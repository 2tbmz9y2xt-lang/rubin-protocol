# DA-Cap Evidence: Benchmark Matrix and Thresholds

**Status:** Executable definition  
**Type:** Evidence-only — no consensus changes, no policy changes  
**Parent:** rubin-protocol#820  
**Issue:** rubin-protocol#821  
**Source:** `./EVIDENCE-PLAN-DA-CAP-UPLIFT-48M.md`

---

## 1. Baseline Constants

| Parameter | Value | Source |
|-----------|-------|--------|
| `MAX_DA_BYTES_PER_BLOCK` | `32_000_000` (32 MB) | `constants.go:23` / `constants.rs:20` |
| `CHUNK_BYTES` | `524_288` (512 KB) | `constants.go:28` / `constants.rs:25` |
| `MAX_DA_CHUNK_COUNT` | `61` | derived: `32_000_000 / 524_288` |
| `PolicyMaxDaBytesPerBlock` | `8_000_000` (25%) | `miner.go:93` / `miner.rs:72` |

48 MB-equivalent values (for comparison runs only, NOT applied to consensus):

| Parameter | 48 MB-equivalent | Notes |
|-----------|------------------|-------|
| DA envelope | `48_000_000` | traffic pattern only |
| Chunk count | `91` | `48_000_000 / 524_288 ≈ 91.55` |
| Policy budget (25%) | `12_000_000` | proportional |

---

## 2. Hardware Tiers

### 2.1 Baseline Validator Tier (REQUIRED)

Representative hardware for a serious validator/operator.

| Resource | Specification |
|----------|---------------|
| CPU | 8 cores / 16 threads (AMD Ryzen 7 / Intel i7 class) |
| RAM | 32 GB DDR4/DDR5 |
| Storage | 1 TB NVMe SSD (≥ 3000 MB/s seq read) |
| Network | 1 Gbps symmetric |
| OS | Linux x86_64 (Ubuntu 22.04+ or equivalent) |

### 2.2 Constrained Tier (REQUIRED)

A meaningfully weaker machine that still represents a plausible honest node.

| Resource | Specification |
|----------|---------------|
| CPU | 4 cores / 8 threads (budget server or VPS class) |
| RAM | 16 GB DDR4 |
| Storage | 500 GB NVMe SSD (≥ 1500 MB/s seq read) |
| Network | 500 Mbps symmetric |
| OS | Linux x86_64 |

### 2.3 Recommended Tier (OPTIONAL)

The hardware Rubin would be comfortable recommending if DA-heavy operation becomes common.

| Resource | Specification |
|----------|---------------|
| CPU | 16 cores / 32 threads (AMD Ryzen 9 / EPYC class) |
| RAM | 64 GB DDR5 |
| Storage | 2 TB NVMe SSD (≥ 5000 MB/s seq read) |
| Network | 10 Gbps symmetric |
| OS | Linux x86_64 |

### 2.4 Tier Selection Rules

- Every benchmark family MUST run on **both** Baseline and Constrained tiers.
- Recommended tier is for comparison only — it MUST NOT be the sole tier.
- Each run report MUST identify the hardware tier used.
- If the constrained tier degrades nonlinearly under 48 MB-equivalent pressure, this MUST be flagged as a centralization pressure concern.

---

## 3. Benchmark Families

### 3.1 BM-SAT: Saturated-Load Baseline

**Purpose:** Establish reproducible 32 MB and 48 MB-equivalent behavior under sustained full-capacity DA blocks.

| Run ID | DA Fill | Topology | Duration | Hardware |
|--------|---------|----------|----------|----------|
| BM-SAT-32-BV | 32 MB/block | 8-node devnet, star | 100 blocks | Baseline |
| BM-SAT-32-CT | 32 MB/block | 8-node devnet, star | 100 blocks | Constrained |
| BM-SAT-48-BV | 48 MB-equiv/block | 8-node devnet, star | 100 blocks | Baseline |
| BM-SAT-48-CT | 48 MB-equiv/block | 8-node devnet, star | 100 blocks | Constrained |
| BM-SAT-32-MESH | 32 MB/block | 8-node devnet, mesh | 100 blocks | Baseline |
| BM-SAT-48-MESH | 48 MB-equiv/block | 8-node devnet, mesh | 100 blocks | Baseline |

**Required measurements per run:**

| Metric | Unit | How |
|--------|------|-----|
| Block propagation latency (p50/p95/p99) | ms | timestamp delta: miner-broadcast to last-node-accept |
| Compact relay reconstruction success rate | % | successful compact reconstructions / total relay attempts |
| Relay fallback rate | % | full-block fallback / total relay attempts |
| Orphan rate | % | orphaned blocks / total blocks |
| Prefetch completion time (p50/p95/p99) | ms | time from first chunk request to full DA set |
| Prefetch stall rate | % | blocks where prefetch did not complete before validation |
| Peak RSS | MB | max resident set during DA validation window |
| Sustained RSS (p95 over run) | MB | 95th percentile RSS during steady state |
| CPU wall-clock on DA validation | ms/block | time spent in DA validation path per block |

### 3.2 BM-ADV: Adversarial Relay Scenarios

**Purpose:** Measure DA path cost under malicious or degraded peer behavior.

Defined in detail by Q-DEVNET-DA-CAP-ADVERSARIAL-01 (issue #822). This matrix defines the measurement contract.

| Run ID | Scenario | DA Fill | Hardware |
|--------|----------|---------|----------|
| BM-ADV-DELAY-32 | Delayed chunk delivery (500ms per chunk) | 32 MB | Baseline |
| BM-ADV-DELAY-48 | Delayed chunk delivery (500ms per chunk) | 48 MB-equiv | Baseline |
| BM-ADV-MISSING-32 | Missing chunks (10% drop rate) | 32 MB | Baseline |
| BM-ADV-MISSING-48 | Missing chunks (10% drop rate) | 48 MB-equiv | Baseline |
| BM-ADV-DUP-32 | Duplicate chunk delivery (2x) | 32 MB | Baseline |
| BM-ADV-DUP-48 | Duplicate chunk delivery (2x) | 48 MB-equiv | Baseline |
| BM-ADV-CHURN-32 | Peer churn (25% disconnect/reconnect per block) | 32 MB | Baseline |
| BM-ADV-CHURN-48 | Peer churn (25% disconnect/reconnect per block) | 48 MB-equiv | Baseline |
| BM-ADV-ORPHAN-32 | Orphan pool near capacity | 32 MB | Constrained |
| BM-ADV-ORPHAN-48 | Orphan pool near capacity | 48 MB-equiv | Constrained |
| BM-ADV-PREFETCH-32 | Prefetch saturation (all peers at BPS limit) | 32 MB | Baseline |
| BM-ADV-PREFETCH-48 | Prefetch saturation (all peers at BPS limit) | 48 MB-equiv | Baseline |

**Same measurement set as BM-SAT** plus:

| Metric | Unit |
|--------|------|
| Chunk retry count (total / per block) | count |
| Recovery time after adversarial event | ms |
| Node desync count | count |

### 3.3 BM-CAMP: Controlled Demand Campaigns

**Purpose:** Approximate real DA demand patterns.

| Run ID | Pattern | DA Fill | Duration | Hardware |
|--------|---------|---------|----------|----------|
| BM-CAMP-REPEAT-32 | Repeated DA-heavy blocks (100% fill) | 32 MB | 200 blocks | Baseline |
| BM-CAMP-REPEAT-48 | Repeated DA-heavy blocks (100% fill) | 48 MB-equiv | 200 blocks | Baseline |
| BM-CAMP-MIXED-32 | Mixed L1 + DA contention (50% DA fill) | 32 MB | 200 blocks | Baseline |
| BM-CAMP-MIXED-48 | Mixed L1 + DA contention (50% DA fill) | 48 MB-equiv | 200 blocks | Baseline |
| BM-CAMP-BURST-32 | Bursty demand (10 full → 10 empty → repeat) | 32 MB | 200 blocks | Constrained |
| BM-CAMP-BURST-48 | Bursty demand (10 full → 10 empty → repeat) | 48 MB-equiv | 200 blocks | Constrained |

**Required measurements per run:** Same measurement set as BM-SAT (§3.1). Additionally, campaign runs must capture the centralization pressure dimensions from §6.

### 3.4 BM-PARITY: Go/Rust Parity Under Stress

**Purpose:** Ensure stressed DA does not cause Go/Rust divergence.

Defined in detail by Q-DEVNET-DA-CAP-PARITY-01 (issue #823). This matrix defines the parity contract.

| Run ID | Scenario | Hardware | Parity Check |
|--------|----------|----------|--------------|
| BM-PAR-SAT-BV | Saturated load (32 + 48) | Baseline | accept/reject identical |
| BM-PAR-SAT-CT | Saturated load (32 + 48) | Constrained | accept/reject identical |
| BM-PAR-ADV-BV | Adversarial (all BM-ADV runs) | Baseline | accept/reject identical |
| BM-PAR-ADV-CT | Adversarial (all BM-ADV runs) | Constrained | accept/reject identical |
| BM-PAR-ERR-BV | Error ordering under stress | Baseline | deterministic where contracted |
| BM-PAR-FALLBACK-BV | Fallback path comparison | Baseline | no materially different fallback |
| BM-PAR-FALLBACK-CT | Fallback path comparison | Constrained | no materially different fallback |

---

## 4. Thresholds

### 4.1 Propagation and Orphaning

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Block propagation p95 | ≤ 30000 ms | Must propagate within 25% of block interval (TARGET_BLOCK_INTERVAL = 120s) |
| Block propagation p99 | ≤ 60000 ms | Hard upper bound — beyond half the block interval, orphaning risk becomes systemic |
| Orphan rate | ≤ 1.0% | At sustained load over 100+ blocks |
| Orphan rate (adversarial) | ≤ 5.0% | Under active adversarial conditions |

### 4.2 Relay and Reconstruction

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Compact relay reconstruction success | ≥ 95% | Below this, full-block fallback dominates bandwidth |
| Relay fallback rate | ≤ 10% | More than 10% fallback indicates compact relay is ineffective |
| Relay fallback rate (adversarial) | ≤ 25% | Under active adversarial conditions |

### 4.3 Memory Pressure

| Metric | Threshold (Baseline) | Threshold (Constrained) | Rationale |
|--------|---------------------|------------------------|-----------|
| Peak RSS during DA validation | ≤ 4 GB above idle | ≤ 2 GB above idle | Must not exhaust memory on constrained tier |
| Sustained RSS p95 | ≤ 2 GB above idle | ≤ 1 GB above idle | Sustained pressure matters more than spikes |

### 4.4 Prefetch Behavior

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Prefetch completion p95 | ≤ 3000 ms | Must complete well within block interval |
| Prefetch completion p99 | ≤ 8000 ms | Hard upper bound |
| Prefetch stall rate | ≤ 2% | Blocks where prefetch did not complete before validation |

### 4.5 Parity

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Accept/reject divergence | 0 | Any divergence is a blocker |
| Error ordering divergence | 0 where deterministic | Contracted deterministic paths must match |
| Fallback path divergence | Flag only | Not a hard blocker but must be documented |

### 4.6 Threshold Source

These thresholds are defined by this document as part of Q-DEVNET-DA-CAP-MATRIX-01. They are not drawn from a pre-existing SLO. If an existing Rubin SLO document is later established that supersedes these, the evidence package should reference that document instead.

---

## 5. Pressure-Point Parameter Review

Each evidence run must capture the current effective value and observed behavior of:

| Parameter | Current Value (if known) | Review Focus |
|-----------|------------------------|--------------|
| `PREFETCH_BYTES_PER_SEC` | TBD (code search) | Does 48 MB-equiv exceed per-peer capacity? |
| `PREFETCH_GLOBAL_BPS` | TBD (code search) | Does aggregate prefetch hit global limit? |
| `DA_MEMPOOL_PINNED_PAYLOAD_MAX` | TBD (code search) | Does pinned payload size under 48 MB cause eviction storms? |
| `RELAY_TIMEOUT_RATE` | TBD (code search) | Does relay timeout increase materially under 48 MB? |
| `DA_ORPHAN_POOL_SIZE` | TBD (code search) | Does orphan pool fill under 48 MB sustained load? |

If any parameter is not yet defined in code, the review note must state that explicitly. "TBD" entries must be resolved before the evidence package is controller-ready.

---

## 6. Centralization Pressure Assessment

Every comparison run (32 MB vs 48 MB-equiv) must produce a centralization assessment covering:

| Dimension | Question |
|-----------|----------|
| Bandwidth | Does 48 MB-equiv require meaningfully higher sustained bandwidth? |
| Memory | Does 48 MB-equiv require meaningfully more RAM? |
| Hardware floor | Does the constrained tier begin to fail or degrade nonlinearly? |
| Operator cost | Would the hardware recommendation change if 48 MB were the norm? |

If any answer is "yes", the evidence package MUST say so directly, even if throughput results look attractive.

---

## 7. Run Reproducibility

Every benchmark run must include:

| Field | Required |
|-------|----------|
| Run ID | From matrix above |
| Hardware tier | Baseline / Constrained / Recommended |
| Git SHA (Go client) | Exact commit |
| Git SHA (Rust client) | Exact commit |
| Network topology | Star / Mesh / description |
| Node count | Integer |
| Block count | Integer |
| DA fill strategy | Full / Mixed / Burst / description |
| Start timestamp | ISO 8601 |
| End timestamp | ISO 8601 |
| Raw results path | Relative to repo |

---

## 8. Relationship to Other Tasks

| Task | Depends On | Produces |
|------|-----------|----------|
| Q-DEVNET-DA-CAP-MATRIX-01 (this) | Q-DEVNET-DA-CAP-EVIDENCE-01 | Matrix + thresholds |
| Q-DEVNET-DA-CAP-ADVERSARIAL-01 | This task | Adversarial scenario implementations |
| Q-DEVNET-DA-CAP-PARITY-01 | This task | Parity test implementations |
| Q-DEVNET-DA-CAP-CAMPAIGN-01 | All above | Campaign runs + centralization assessment |
