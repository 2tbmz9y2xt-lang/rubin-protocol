# RUBIN Compact Block Relay — Security Specification

**Status:** Draft v0.6 — pending controller approval
**Date:** 2026-02-21

This document is normative for P2P relay behavior. Requirements expressed with MUST / MUST NOT
are mandatory. SHOULD / MAY are recommendations.

---

## Units

| Symbol | Value |
|--------|-------|
| MB     | 10^6 bytes (decimal, used in throughput calculations) |
| MiB    | 2^20 bytes (binary, used in memory limits) |
| GiB    | 2^30 bytes |
| TiB    | 2^40 bytes |

Example: 32_000_000 bytes = 32 MB = 30.5 MiB.
Note for hardware provisioning: 18.05 TiB raw data requires a disk marketed as ~20 TB.

---

## 1. Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| `TARGET_BLOCK_INTERVAL` | 120 s | |
| `MAX_BLOCK_WEIGHT` | 68_000_000 wu | 36M L1 + 32M DA |
| `MAX_BLOCK_BYTES` | 75_497_472 bytes (= 72 MiB) | |
| `MAX_DA_BYTES_PER_BLOCK` | 32_000_000 bytes (= 30.5 MiB) | |
| `WINDOW_SIZE` | 10_080 blocks | retarget = 14 days |
| `MIN_DA_RETENTION_BLOCKS` | 15_120 blocks | DA pruning window = 21 days |
| `MAX_RELAY_MSG_BYTES` | 96_000_000 bytes (= 91.6 MiB) | |
| `DA_MEMPOOL_SIZE` | 512 MiB | minimum for high-bandwidth relay |
| `DA_MEMPOOL_PINNED_PAYLOAD_MAX` | 96_000_000 bytes | 3 full DA blocks (payload bytes only) |
| `DA_ORPHAN_POOL_SIZE` | 64 MiB | = 2 x MAX_DA_BYTES_PER_BLOCK |
| `DA_ORPHAN_POOL_PER_PEER_MAX` | 4 MiB | |
| `DA_ORPHAN_POOL_PER_DA_ID_MAX` | 8 MiB | one da_id from 2+ peers accumulates |
| `DA_ORPHAN_COMMIT_OVERHEAD_MAX` | 8 MiB | commit metadata cap within orphan pool |
| `DA_ORPHAN_TTL_BLOCKS` | 3 (= 360 s) | independent from DA_CHUNK_WINDOW_BLOCKS |
| `DA_CHUNK_WINDOW_BLOCKS` | 2 | expected chunk arrival spread under normal conditions |
| `SHORT_ID_LENGTH` | 6 bytes (48 bits) | upgrade path reserved via feature-bit |
| `GRACE_PERIOD_BLOCKS` | 1_440 | ~2 days after genesis |
| `FINALITY_K_L1` | 8 blocks | = 16 min |
| `FINALITY_K_BRIDGE` | 12 blocks | = 24 min |
| `ML_DSA_BATCH_SIZE` | 64 signatures | for batch verification |
| `PREFETCH_BYTES_PER_SEC` | 4_000_000 B/s per peer | [NON-NORMATIVE, empirical default] |
| `PREFETCH_GLOBAL_BPS` | 32_000_000 B/s | global cap across all peers |
| `PREFETCH_GLOBAL_PARALLEL` | 64 sets | global parallel prefetch cap |

### 1.1 Network Characteristics

```
Blocks per year     = 365 x 86400 / 120       = 262_800

L1 TPS              ~ 19     (ML-DSA-87, 1-in/1-out)
L2 TPS              ~ 2667   (32_000_000 / 120 / 100 B/tx)
DA throughput       = 32_000_000 / 120         = 266_667 B/s = 0.267 MB/s = 0.254 MiB/s
Orphan rate         ~ 0.02%  (compact blocks eliminate propagation bottleneck)
Finality L1         = 16 min (FINALITY_K_L1 = 8)
Finality bridge     = 24 min (FINALITY_K_BRIDGE = 12)
```

### 1.2 Storage

```
Storage (100% fill rate, max load):

  DA-only / year       = 32_000_000 x 262_800 / 2^40  = 7.65 TiB
  Full block / year    = 75_497_472 x 262_800 / 2^40  = 18.05 TiB
  Live window DA       = 32_000_000 x 15_120  / 2^30  = 451 GiB
  Live window full     = 75_497_472 x 15_120  / 2^40  = 1.04 TiB

Storage (30% fill rate, non-normative target):

  DA-only / year       = 7.65  x 0.3 = 2.29 TiB
  Full block / year    = 18.05 x 0.3 = 5.41 TiB
  Live window DA       = 451   x 0.3 = 135  GiB

Formula: storage = max_storage x fill_rate
         live_window = MAX_DA_BYTES_PER_BLOCK x MIN_DA_RETENTION_BLOCKS x fill_rate
```

**Node roles and storage requirements:**

| Role | Storage | Growth |
|------|---------|--------|
| L1 validator / miner (pruning enabled) | ~1.04 TiB | Fixed, does not grow |
| L2 operator / archival node | ~7.65 TiB DA/year | Grows continuously |
| Watchtower | Channels only | Depends on scope |

Hardware provisioning MUST account for max load (100% fill rate).
Economics MAY use target fill rate. Target fill rate is established by the Tokenomics WG
and is outside the scope of this document.

---

## 2. sendcmpct Modes

All sections of this document use the following notation:

| Mode | Meaning |
|------|---------|
| `sendcmpct_mode = 0` | Compact blocks disabled — full blocks only |
| `sendcmpct_mode = 1` | Compact enabled, low-bandwidth (node receives cmpctblock, does not push) |
| `sendcmpct_mode = 2` | Compact enabled, high-bandwidth (node receives and pushes cmpctblock) |

---

## 3. Cache Miss Protection

**Risk:** Node does not have a transaction in the mempool on block arrival → round-trip getblocktxn
request → propagation delay → at high miss rates compact blocks perform worse than full block relay.

**Mitigations:**

- `DA_MEMPOOL_SIZE = 512 MiB` is the minimum size for participation in high-bandwidth compact relay.
  Nodes below this threshold remain valid validators but degrade as relay peers.
  A node MUST NOT reduce its DA mempool below 512 MiB while participating in DA relay.
  Nodes MAY increase DA mempool size locally.

- On receipt of DA_COMMIT_TX, the node MUST initiate prefetch of all associated DA_CHUNK_TX
  identified by `da_id`. Prefetch is rate-limited:

  ```
  Per-peer:  PREFETCH_BYTES_PER_SEC   = 4_000_000 B/s  [NON-NORMATIVE]
  Global:    PREFETCH_GLOBAL_BPS      = 32_000_000 B/s
             PREFETCH_GLOBAL_PARALLEL = 64 concurrent sets
  ```

  Exceeding the global cap reduces the offending peer's quality score; it does not disconnect.

- On cache miss: send `getblocktxn` for specific missing transaction indices only.
  Request a full block only if `getblocktxn` reconstruction fails.

- Relay timeout scales with payload size:
  `timeout = BASE_TIMEOUT_MS + len(DA_Payload) / RELAY_RATE`

**Formal definition of miss_rate_bytes:**

```
miss_rate_bytes = sum(wire_bytes(missing_tx)) / sum(wire_bytes(all_tx_in_block))

wire_bytes = serialized bytes on the wire (not in-memory representation)
Tracked separately: miss_rate_bytes_L1 and miss_rate_bytes_DA
```

**Health thresholds:**

```
miss_rate_bytes      < 0.5%  at tip          normal
da_mempool_fill_pct  > 80%   for > 10 min    alert
orphan_pool_fill_pct > 75%                   alert
```

---

## 4. DA Mempool — Set State Machine

`DA_CHUNK_WINDOW_BLOCKS = 2` is the expected spread of chunk arrival under normal network
conditions. `DA_ORPHAN_TTL_BLOCKS = 3` is the hard timeout with margin
(= DA_CHUNK_WINDOW_BLOCKS + 1). The two constants are independent.

Each DA set (one DA_COMMIT_TX and its associated DA_CHUNK_TX records) transitions through
three states:

### State A: ORPHAN_CHUNKS

Chunks arrived before the corresponding commit transaction.

```
Pool:       DA_ORPHAN_POOL

Limits (applied independently and simultaneously):
  global:     64 MiB total
  commits:    DA_ORPHAN_COMMIT_OVERHEAD_MAX = 8 MiB
  chunks:     remaining 56 MiB
  per-peer:   4 MiB
  per-da_id:  8 MiB
  
  A chunk from peer P for da_id X reduces both
  the quota of peer P and the quota of da_id X.
  The per-da_id limit (8 MiB) > per-peer limit (4 MiB)
  because one da_id may arrive from 2+ peers simultaneously.

Eviction:   primary key:   fee / wire_bytes (lower = evicted first)
            tie-break:     received_time (older = evicted first)
            NOT LRU        (LRU depends on local access patterns,
                           causing divergence between implementations)

TTL:        DA_ORPHAN_TTL_BLOCKS = 3 blocks (360 s)
```

### State B: STAGED_COMMIT

Commit transaction received; not all chunks present yet.

```
NOT pinned.
NOT mineable.

TTL resets to DA_ORPHAN_TTL_BLOCKS = 3 on transition from A to B.
(Full 3 blocks available for prefetch regardless of time spent in State A.)

On entry: initiate prefetch of all missing DA_CHUNK_TX for this da_id.

On TTL expiry:
  - Delete commit and all associated chunks atomically by da_id.
  - Record "incomplete_set" in the quality score of the peer
    that sent the commit transaction.
  - Do NOT disconnect. Role degrades; network participation continues.
```

### State C: COMPLETE_SET

Commit transaction and all associated chunks present.

```
HARD PIN: enters DA_MEMPOOL_PINNED_PAYLOAD_MAX = 96_000_000 bytes.
Eligible for inclusion in a candidate block.
Eviction: total_fee / total_bytes (lower = evicted first), atomic by da_id.
```

**Invariants:**

- Only COMPLETE_SET may be pinned. Pinning an incomplete set is a DoS vector
  (commit spam without chunks blocks pinned memory at no real cost to attacker).
- Eviction is always atomic by da_id. No orphaned chunks without a commit.
- CheckBlock independently forbids inclusion of an incomplete set regardless
  of mempool state.
- Per-peer and per-da_id limits are applied simultaneously and independently.

---

## 5. Mempool Policy Divergence

**Risk:** Different nodes filter transactions differently → mempools diverge → miss rate increases.

**Mitigations:**

- Relay rules are normative in RUBIN_L1_CANONICAL.md, not in a separate policy document.
- `MIN_RELAY_FEE_RATE` is a consensus constant.
- A node with non-standard relay rules experiences high miss rates, making it
  economically disadvantageous. This is a self-correcting mechanism.
- Conformance gate `CV-COMPACT` covers: short_id generation (SipHash-2-4 on WTXID),
  prefill logic, `getblocktxn` / `blocktxn` round-trip, ML-DSA-87 witness serialization,
  collision fallback paths, tx_nonce in preimage, ML-DSA-87 batch verification (64 sigs).

---

## 6. Short ID and Collision Handling

```
SHORT_ID_LENGTH = 6 bytes
Hash function:  SipHash-2-4 keyed on (nonce1, nonce2) from cmpctblock header
Input:          WTXID (see Section 9 for tx_nonce requirement)
Analogue:       BIP-152
```

**Collision probability at ML-DSA-87 parameters:**

```
Max transactions per block:
  n = 68_000_000 wu / ~8_000 wu/tx = ~8_500

Birthday approximation:
  P(collision per block) = n(n-1) / 2^49
                         = 8500 x 8499 / 562_949_953_421_312
                         ~= 1.28 x 10^-7

Expected collisions per year:
  E = P x 262_800 ~= 0.034
  => approximately once every 29 years

"48-bit short IDs at n~9000 yield a failure rate lower than
random network faults." (analogous to BIP-152 rationale)
```

**Collision fallback (deterministic):**

1. Send `getblocktxn` for the specific conflicting indices.
2. If reconstruction still fails, request full block.
3. Never ban or penalize a peer for a short_id collision.

**Normative collision monitoring:**

```
Metrics:
  shortid_collision_count   (per node, per block)
  shortid_collision_blocks  (block hashes where collisions occurred)
  shortid_collision_peers   (peer IDs involved)

Thresholds:
  Warning:  > 0.01 collisions/year across 1000-node sample
  Action:   > 0.5  collisions/year -> initiate 8-byte upgrade working group
```

**Upgrade path:** 8-byte short_id reserved via feature-bit.
Activation requires observed threshold breach and a coordinated upgrade plan.
Do not activate preemptively.

---

## 7. Private Transactions and Pre-mining

**Risk:** Miner withholds transactions from the mempool before announcing a block →
all nodes issue getblocktxn round-trips → miner gains time advantage (MEV-like).

**Mitigation — peer quality scoring (not banning):**

```
P2P handshake declares relay mode:
  tx_relay = 1   transaction relay expected from this peer
  tx_relay = 0   block-relay-only peer

For peers with tx_relay = 1 exhibiting systematic high miss rates:
  Step 1: Set sendcmpct_mode = 1 for this peer (downgrade from high to low bandwidth).
  Step 2: Lower peer priority in selection.
  Step 3: On chronic violation: disconnect. No ban.

BAN is not applied.
Attribution is unreliable: a relay node cannot be held responsible
for the original miner's behavior.
```

**Grace period:**

During the first `GRACE_PERIOD_BLOCKS = 1_440` blocks (~2 days after genesis),
quality scores are logged only. No disconnects are applied.
This accommodates bootstrap conditions and early network instability.

**Self-downgrade:**

If `miss_rate_bytes > 10%` for 5 consecutive blocks, the node MUST set
`sendcmpct_mode = 0` and fall back to full block relay until the mempool stabilizes.

---

## 8. IBD and Warm-up

**IBD exit and warm-up are receiver-driven. No hardcoded timers.**

```
Step 1. A node is in IBD while its tip timestamp lags system time by more than 24 hours.

Step 2. While in IBD: sendcmpct_mode = 0 (full blocks only).

Step 3. After IBD exit: the node receives and validates at least one new full block
        at the chain tip. During the ~120 s block interval the mempool populates
        via standard inv / getdata propagation.

Step 4. After validating the first full block at tip:
        the node MAY send sendcmpct_mode = 2 to up to 3 peers.
        The node is NOT required to enable compact blocks immediately.
        It MAY remain in sendcmpct_mode = 0 or 1 until
        miss_rate_bytes falls below 0.5%.

Step 5. Self-downgrade at any time:
        miss_rate_bytes > 10% for 5 consecutive blocks
        -> sendcmpct_mode = 0 -> full blocks until mempool stabilizes.
```

`IBD_THRESHOLD = 144 blocks` is a local heuristic for when to automatically
send `sendcmpct`. It is NOT a protocol norm. The receiver-driven `sendcmpct`
mechanism is the authoritative gating condition.

---

## 9. DA Retention and Pruning

- A node announces `pruned_below_height` in its P2P `version` message.
- A node with `pruned_below_height > current_height - MIN_DA_RETENTION_BLOCKS`
  is deprioritized for DA data requests. It is NOT banned.
- A pruning node remains a full validator. The following are retained permanently:
  TXID, DA_Core_Fields, SHA3-256(DA_Payload). The chain
  TXID -> MerkleRoot -> BlockHeader remains intact.
- `DA_Core_Fields` MUST include a commitment to DA_Payload so that an archival node
  can cryptographically match payload to L1 data.
- Node roles are explicit and non-overlapping:

  | Role | DA Retention | Consensus Participation |
  |------|-------------|------------------------|
  | L1 validator / miner | MIN_DA_RETENTION_BLOCKS (21 days) | Full |
  | DA archival node | Indefinite (operator policy) | Full |
  | Watchtower | Channel-scoped | Optional |

---

## 10. tx_nonce — Consensus Requirement

`tx_nonce: u64le` MUST satisfy all of the following:

1. **WTXID preimage:** tx_nonce MUST be included in the canonical transaction
   serialization used to compute the WTXID.
2. **Signature preimage:** tx_nonce MUST be included in the ML-DSA-87 signature
   preimage. Omitting it opens a malleability edge case.
3. **Not in TXID:** tx_nonce MUST NOT be included in the TXID preimage.
   This preserves soft-fork compatibility.
4. **Semantic neutrality:** tx_nonce does not change transaction semantics.
   It affects only the transaction identifier.

**Rationale:** Without this requirement, an attacker can modify tx_nonce to
produce a short_id collision without invalidating the signature.
tx_nonce guarantees WTXID uniqueness even for two transactions
identical in all other fields.

Test vectors for tx_nonce in WTXID computation are required in `CV-COMPACT`.

---

## 11. ML-DSA-87 Batch Verification

When reconstructing a block from compact form, implementations MUST use
batch verification for ML-DSA-87 signatures:

```
Step 1. Verify all non-witness data first (cheap).
Step 2. Batch ML-DSA-87 signatures in groups of ML_DSA_BATCH_SIZE = 64.
        Amortized cost reduction: approximately 35-40% vs individual verification.
Step 3. If a batch fails, fall back to individual verification to identify
        the specific invalid transaction.
```

`CV-COMPACT` MUST include a test case for ML-DSA-87 batch verification,
including the batch-fail -> individual-fallback path.

---

## 12. Normative Telemetry Fields

Implementations MUST expose the following metrics:

```
shortid_collision_count       per block, per node
shortid_collision_blocks      block hashes
shortid_collision_peers       peer IDs
da_mempool_fill_pct           percentage of DA_MEMPOOL_SIZE in use
orphan_pool_fill_pct          percentage of DA_ORPHAN_POOL_SIZE in use
miss_rate_bytes_L1            per block
miss_rate_bytes_DA            per block
partial_set_count             sets in State B at any given time
partial_set_age_p95           95th percentile age of State B sets
prefetch_latency_ms           per peer, per set
```

---

## 13. Design Decisions

The following items were open during drafting and are now resolved.

| Parameter | Decision | Rationale |
|-----------|----------|-----------|
| `DA_ORPHAN_TTL_BLOCKS` | **3** (360 s) | K=2 is insufficient for real propagation delays (~1-2 blocks). K=4 extends the DoS window to 8 min. K=3 provides one relay window of margin — standard practice in distributed state machine design. Revisit if `orphan_recovery_success_rate` < 99.9% at peak latency on mainnet. |
| `TARGET_FILL_RATE` | **30% (non-normative)** | Protocol and consensus MUST be designed for 100% fill rate. 30% is a reasonable baseline for economic models (miner revenue, first-year inflation). It does not affect any node code path. Established by Tokenomics WG; outside the scope of this document. |
| `PREFETCH_BYTES_PER_SEC` | **4_000_000 B/s (empirical default)** | Allows prefetch of a maximum DA block (32 MB) in ~8 s, well within the 120 s block interval. Does not saturate a standard 100 Mbps home node uplink. Global cap 32_000_000 B/s = 8x per-peer. Both values to be calibrated on testnet metrics (latency, bandwidth distribution). |
