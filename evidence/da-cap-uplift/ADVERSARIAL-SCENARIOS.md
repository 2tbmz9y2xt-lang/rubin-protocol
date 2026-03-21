# DA-Cap Evidence: Adversarial Scenario Catalog

**Status:** Executable specification  
**Type:** Evidence-only — no consensus changes, no policy changes  
**Parent:** rubin-protocol#820  
**Issue:** rubin-protocol#822  
**Depends:** Q-DEVNET-DA-CAP-MATRIX-01 (BENCHMARK-MATRIX.md)  
**Source:** EVIDENCE-PLAN-DA-CAP-UPLIFT-48M.md §5.2

---

## 1. Purpose

Measure how expensive the DA path becomes under malicious or degraded peer behavior. The point is resilience under Byzantine or degraded relay conditions, not throughput alone.

Every scenario runs at both 32 MB baseline and 48 MB-equivalent pressure. See BENCHMARK-MATRIX.md §3.2 for the run ID matrix and §4 for pass/fail thresholds.

---

## 2. Scenario Catalog

### 2.1 ADV-DELAY: Delayed Chunk Delivery

**Run IDs:** BM-ADV-DELAY-32, BM-ADV-DELAY-48

**Setup:**
- 8-node devnet, star topology
- 1 adversarial relay node injected between miner and 3 honest peers
- Adversarial node adds configurable delay to each DA chunk relay

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Chunk relay delay | 500 ms per chunk | Simulates high-latency or throttled relay peer |
| Affected peers | 3 of 7 honest (miner excluded) | ~43% of network sees delayed DA |
| Duration | 50 blocks | Enough to measure steady-state impact |

**Injection method:**
- Adversarial node intercepts `inv`/`getdata` for DA chunks
- Adds `sleep(delay)` before forwarding each chunk
- No chunks dropped — only delayed

**Expected behavior:**
- Honest peers eventually reconstruct full DA set
- Propagation latency increases proportionally to `delay × chunk_count`
- No permanent chain split

**Measurements:** Per BENCHMARK-MATRIX.md §3.1 measurement set + chunk retry count

---

### 2.2 ADV-MISSING: Missing Chunk / Partial-Set Behavior

**Run IDs:** BM-ADV-MISSING-32, BM-ADV-MISSING-48

**Setup:**
- 8-node devnet, star topology
- 1 adversarial relay node drops DA chunks at configured rate

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Chunk drop rate | 10% uniform random | Simulates unreliable relay or selective withholding |
| Affected peers | 3 of 7 honest | Meaningful fraction sees partial DA |
| Duration | 50 blocks | |

**Injection method:**
- Adversarial node drops selected chunks silently (no error response)
- Affected peers must discover missing chunks from other peers
- Tracks which chunks are missing per block

**Expected behavior:**
- Peers detect missing chunks via DA set integrity check
- Peers request missing chunks from alternate peers
- Full DA set eventually assembled (or block falls back to full relay)
- Relay fallback rate increases

**Recovery metric:** Time from first missing-chunk detection to full DA set assembly

---

### 2.3 ADV-DUP: Duplicate Chunk Delivery

**Run IDs:** BM-ADV-DUP-32, BM-ADV-DUP-48

**Setup:**
- 8-node devnet, star topology
- 1 adversarial relay node sends each chunk twice

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Duplication factor | 2x (every chunk sent twice) | Simulates amplification or confused relay |
| Affected peers | All 7 honest | Worst case for dedup overhead |
| Duration | 50 blocks | |

**Injection method:**
- Adversarial node relays each DA chunk normally, then immediately re-sends
- Honest nodes must deduplicate without performance degradation

**Expected behavior:**
- No duplicate chunks accepted into DA set
- Memory usage does not increase significantly from dedup buffers
- No increase in orphan rate
- CPU overhead from dedup is measurable but bounded

**Key metric:** Additional RSS from dedup buffers (should be ≤ 1 chunk size per peer)

---

### 2.4 ADV-CHURN: Peer Churn During DA Propagation

**Run IDs:** BM-ADV-CHURN-32, BM-ADV-CHURN-48

**Setup:**
- 8-node devnet, mesh topology
- Controlled peer disconnect/reconnect cycle during DA propagation

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Churn rate | 25% of peers disconnect per block | Aggressive but plausible during network partition |
| Churn timing | During DA chunk relay (after block header, before full DA set) | Worst timing for DA completion |
| Reconnect delay | 2-5 seconds (random uniform) | Simulates real reconnection behavior |
| Duration | 50 blocks | |

**Injection method:**
- At block announcement, randomly select 25% of non-miner peers
- Force TCP disconnect for selected peers
- Reconnect after random delay
- Track which chunks each peer had before disconnect

**Expected behavior:**
- Reconnecting peers can resume DA assembly from partial state
- No full re-download required if peer preserved partial chunks
- Orphan rate may increase but must stay within adversarial threshold (≤ 5%)

**Key metric:** Chunk re-download waste (bytes fetched twice due to churn)

---

### 2.5 ADV-ORPHAN: Orphan-Pool Pressure Near Capacity

**Run IDs:** BM-ADV-ORPHAN-32, BM-ADV-ORPHAN-48

**Setup:**
- 8-node devnet, star topology, constrained tier hardware
- Controlled injection of orphan-inducing conditions

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Orphan injection rate | 20% of blocks have competing blocks | Simulates mining race conditions |
| DA fill | 100% per block | Maximum DA pressure during orphan resolution |
| Orphan pool size | Near configured limit | Tests pool eviction behavior |
| Duration | 100 blocks | Longer run to measure pool pressure buildup |
| Hardware | Constrained tier | Measures worst-case memory behavior |

**Injection method:**
- Two miners produce competing blocks at same height
- Both blocks have full DA payloads
- Network must resolve fork and clean up orphan DA
- Monitor orphan pool size, eviction events, RSS

**Expected behavior:**
- Orphan pool does not exceed configured capacity
- Eviction is deterministic (oldest-first or lowest-fee)
- Memory from orphan DA chunks is released promptly
- No unbounded memory growth

**Key metric:** Orphan pool high-water mark + memory release latency

---

### 2.6 ADV-PREFETCH: Prefetch Saturation Near Configured Limits

**Run IDs:** BM-ADV-PREFETCH-32, BM-ADV-PREFETCH-48

**Setup:**
- 8-node devnet, star topology
- All peers simultaneously requesting DA chunks at maximum rate

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Prefetch request rate | At per-peer BPS limit | Tests rate limiter behavior |
| Concurrent prefetch peers | All 7 honest | Global BPS limit pressure |
| DA fill | 100% per block | Maximum chunk count |
| Duration | 50 blocks | |

**Injection method:**
- Every peer requests DA chunks from every other peer simultaneously
- Requests issued at the maximum allowed per-peer rate
- Global BPS limiter must throttle aggregate demand
- Measure actual throughput vs configured limits

**Expected behavior:**
- Per-peer rate limiter enforces BPS cap
- Global rate limiter prevents aggregate saturation
- Prefetch completion time increases but stays within threshold (p95 ≤ 3s for 32 MB, to be measured for 48 MB)
- No deadlock between prefetch requests
- No starvation of non-DA peer communication

**Key metrics:**
- Actual per-peer throughput vs configured limit
- Global aggregate throughput vs configured limit
- Prefetch stall events (count)
- Non-DA message latency during prefetch saturation

---

## 3. Common Implementation Requirements

### 3.1 Adversarial Node Framework

All scenarios require an adversarial relay node that can:

1. Intercept DA chunk relay messages (`inv`, `getdata`, chunk payload)
2. Apply configurable behavior (delay, drop, duplicate, disconnect)
3. Log all interventions with timestamps for analysis
4. Be parameterized via configuration file or CLI flags
5. Run as either Go or Rust node variant

### 3.2 Measurement Collection

Every run must collect the full measurement set from BENCHMARK-MATRIX.md §3.1, plus scenario-specific metrics listed above.

Measurements must be collected as structured JSON with schema:

```json
{
  "run_id": "BM-ADV-DELAY-32",
  "scenario": "delayed_chunk_delivery",
  "da_fill_bytes": 32000000,
  "hardware_tier": "baseline",
  "blocks": 50,
  "measurements": {
    "propagation_p50_ms": 0,
    "propagation_p95_ms": 0,
    "propagation_p99_ms": 0,
    "orphan_rate_pct": 0.0,
    "relay_fallback_rate_pct": 0.0,
    "prefetch_completion_p50_ms": 0,
    "prefetch_completion_p95_ms": 0,
    "prefetch_completion_p99_ms": 0,
    "prefetch_stall_rate_pct": 0.0,
    "peak_rss_mb": 0,
    "sustained_rss_p95_mb": 0,
    "chunk_retry_count": 0,
    "recovery_time_ms": 0
  }
}
```

### 3.3 Parity Requirement

Every adversarial scenario must run on both Go and Rust nodes. Accept/reject behavior must be identical. Any divergence in recovery path or fallback behavior must be documented.

---

## 4. Implementation Priority

| Priority | Scenario | Rationale |
|----------|----------|-----------|
| 1 | ADV-DELAY | Simplest to implement, most common real-world degradation |
| 2 | ADV-MISSING | Tests DA set integrity and chunk recovery path |
| 3 | ADV-PREFETCH | Tests rate limiter correctness under load |
| 4 | ADV-ORPHAN | Tests memory management under fork conditions |
| 5 | ADV-DUP | Tests dedup — usually handled well by existing code |
| 6 | ADV-CHURN | Most complex — requires TCP-level manipulation |

---

## 5. Relationship to Other Tasks

| Task | Role |
|------|------|
| Q-DEVNET-DA-CAP-MATRIX-01 | Defines run IDs, thresholds, measurement contract |
| Q-DEVNET-DA-CAP-ADVERSARIAL-01 (this) | Defines scenario implementations |
| Q-DEVNET-DA-CAP-PARITY-01 | Uses these scenarios for Go/Rust comparison |
| Q-DEVNET-DA-CAP-CAMPAIGN-01 | May combine adversarial with demand campaigns |
