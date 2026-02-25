# RUBIN Compact Block Relay — Security Specification

**Status:** Approved v0.7
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
Note for hardware provisioning: 17.21 TiB raw data requires a disk marketed as ~20 TB.

---

## 1. Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| `TARGET_BLOCK_INTERVAL` | 120 s | |
| `MAX_BLOCK_WEIGHT` | 68_000_000 wu | Single unified weight pool; DA has a *separate* byte cap (MAX_DA_BYTES_PER_BLOCK) |
| `MAX_BLOCK_BYTES` | 72_000_000 bytes (= 72 MB) | Operational P2P parser cap; exceeds consensus weight limit by design (safety margin) |
| `MAX_DA_BYTES_PER_BLOCK` | 32_000_000 bytes (= 30.5 MiB) | |
| `WINDOW_SIZE` | 10_080 blocks | retarget = 14 days |
| `MIN_DA_RETENTION_BLOCKS` | 15_120 blocks | DA pruning window = 21 days |
| `MAX_RELAY_MSG_BYTES` | 96_000_000 bytes (= 91.6 MiB) | |
| `DA_MEMPOOL_SIZE` | 512 MiB | minimum for high-bandwidth relay |
| `DA_MEMPOOL_PINNED_PAYLOAD_MAX` | 96_000_000 bytes | hard cap for COMPLETE_SET payload pinning (max 3 full DA sets pinned at once) |
| `DA_ORPHAN_POOL_SIZE` | 64 MiB | ≈ 2 x MAX_DA_BYTES_PER_BLOCK |
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
| `PREFETCH_TARGET_COMPLETE_SEC` | 8 s | [NON-NORMATIVE] target time to fetch a full DA payload from one peer |
| `PREFETCH_BYTES_PER_SEC` | 4_000_000 B/s per peer | = ceil(MAX_DA_BYTES_PER_BLOCK / PREFETCH_TARGET_COMPLETE_SEC) |
| `PREFETCH_GLOBAL_PARALLEL` | 8 sets | global parallel prefetch cap for STAGED_COMMIT sets (independent from pinned COMPLETE_SET cap) |
| `PREFETCH_GLOBAL_BPS` | 32_000_000 B/s | = PREFETCH_GLOBAL_PARALLEL x PREFETCH_BYTES_PER_SEC |
| `RELAY_TIMEOUT_BASE_MS` | 2_000 ms | base relay timeout before payload scaling |
| `RELAY_TIMEOUT_RATE` | 1_000_000 B/s | divisor for payload-size timeout extension |

### 1.1 Network Characteristics

```
Blocks per year     = 365 x 86400 / 120       = 262_800

L1 TPS (ML-DSA-87)  ~ 74    (8,886 tx/block; weight = 7,652 wu/tx; assumes DA bytes near zero)
L1 TPS (SLH-DSA)    ~ 11    (1,349 tx/block; weight = 50,407 wu/tx; assumes DA bytes near zero)
L2 TPS              ~ 2667  (32_000_000 / 120 / 100 B/tx; assumes DA budget saturated)
DA throughput       = 32_000_000 / 120         = 266_667 B/s = 0.267 MB/s = 0.254 MiB/s
Orphan rate         ~ 0.02%  (compact blocks eliminate propagation bottleneck)
Finality L1         = 16 min (FINALITY_K_L1 = 8)
Finality bridge     = 24 min (FINALITY_K_BRIDGE = 12)
```

### 1.2 Storage

```
Storage (100% fill rate, max load):

  DA-only / year       = 32_000_000 x 262_800 / 2^40  = 7.65 TiB
  Full block / year    = 72_000_000 x 262_800 / 2^40  = 17.21 TiB
  Live window DA       = 32_000_000 x 15_120  / 2^30  = 451 GiB
  Live window full     = 72_000_000 x 15_120  / 2^40  = 0.99 TiB

Storage (30% fill rate, non-normative target):

  DA-only / year       = 7.65  x 0.3 = 2.29 TiB
  Full block / year    = 17.21 x 0.3 = 5.16 TiB
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

## 2. DA Transaction Types

DA transaction types (`DA_COMMIT_TX`, `DA_CHUNK_TX`), `da_id` linkage, chunk integrity,
and set completeness (CheckBlock DA) are fully defined in
**RUBIN_L1_CANONICAL.md §5 (Transaction Wire), §14 (Covenant Registry), and §21 (DA Set Integrity)**.

This document refers to those types by name. Implementations MUST satisfy all consensus rules
in RUBIN_L1_CANONICAL.md before applying the P2P relay policies defined here.

---

## 3. sendcmpct Modes

All sections of this document use the following notation:

| Mode | Meaning |
|------|---------|
| `sendcmpct_mode = 0` | Compact blocks disabled — full blocks only |
| `sendcmpct_mode = 1` | Compact enabled, low-bandwidth (node receives cmpctblock, does not push) |
| `sendcmpct_mode = 2` | Compact enabled, high-bandwidth (node receives and pushes cmpctblock) |

### 3.1 Reject Message Policy

The legacy `reject` P2P message is deprecated for public mainnet operation.

- Mainnet nodes SHOULD NOT send `reject`.
- Implementations MUST NOT depend on `reject` for protocol correctness or relay progress.
- Invalid data handling MUST use deterministic local validation, peer quality scoring,
  and normal request/response flows (`inv/getdata/getblocktxn/blocktxn`).

For testnet/devnet debugging, implementations MAY expose an operator-only flag to emit
diagnostic reject payloads. Such diagnostics are non-consensus and MUST NOT alter relay
state transitions or block/transaction validity outcomes.

---

## 4. Cache Miss Protection

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
  Per-peer:  PREFETCH_BYTES_PER_SEC   = ceil(MAX_DA_BYTES_PER_BLOCK / PREFETCH_TARGET_COMPLETE_SEC)
                                       = ceil(32_000_000 / 8) = 4_000_000 B/s
             Goal: fetch a full DA payload from one peer within PREFETCH_TARGET_COMPLETE_SEC (8 s),
             well within TARGET_BLOCK_INTERVAL (120 s).

  Global:    PREFETCH_GLOBAL_BPS      = PREFETCH_GLOBAL_PARALLEL x PREFETCH_BYTES_PER_SEC
                                       = 8 x 4_000_000 = 32_000_000 B/s
             PREFETCH_GLOBAL_PARALLEL = 8 concurrent sets
  ```

  The global cap is derived from per-peer rate and parallel set count — not an independent
  magic number. Exceeding the global cap reduces the offending peer's quality score; it does
  not disconnect.

  **Testnet calibration criteria** (to validate or adjust these defaults):
  - `commit -> complete_set` latency distribution: p50 / p95 / p99 by peer type
  - Actual bytes prefetched per DA set
  - Impact on `miss_rate_bytes_DA` and cmpctblock reconstruction time
  - `incomplete_set` rate at various TTL and rate-limit combinations
  - Total prefetch traffic per node at N active peers

- On cache miss: send `getblocktxn` for specific missing transaction indices only.
  Request a full block only if `getblocktxn` reconstruction fails.

- Relay timeout scales with payload size:
  `timeout_ms = RELAY_TIMEOUT_BASE_MS + (1000 * len(DA_Payload) / RELAY_TIMEOUT_RATE)`
  where `RELAY_TIMEOUT_RATE` is in `bytes/second` and `len(DA_Payload)` is in `bytes`.
  Example: 32 MB payload → 2000 + (1000 * 32_000_000 / 1_000_000) = 34_000 ms

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
orphan_pool_fill_pct > 90% for > 120 s       trigger storm-mode admission
orphan_recovery_success_rate < 95% for 10 min trigger rollback to full-block-first relay
```

---

## 5. DA Mempool — Set State Machine

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

Storm-mode admission (non-consensus, MUST for production relay):
  - When orphan_pool_fill_pct > 90%, node MUST prioritize commit-bearing traffic
    (commit-first bias) over additional orphan chunks.
  - Under storm mode, chunk admission MAY be reduced for low-quality peers before
    commit-bearing messages are dropped.
  - Exit storm mode after orphan_pool_fill_pct < 70% for 60 s.

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
  of mempool state. See RUBIN_L1_CANONICAL.md §21.3 for the consensus rule.
- Per-peer and per-da_id limits are applied simultaneously and independently.

---

## 6. Mempool Policy Divergence

**Risk:** Different nodes filter transactions differently → mempools diverge → miss rate increases.

**Mitigations:**

- Relay rules in this document are normative for P2P behavior; consensus validity rules remain in
  RUBIN_L1_CANONICAL.md.
- `MIN_RELAY_FEE_RATE` is a relay-policy default (non-consensus).
- A node with non-standard relay rules experiences high miss rates, making it
  economically disadvantageous. This is a self-correcting mechanism.
- Conformance gate `CV-COMPACT` covers: short_id generation (SipHash-2-4 on WTXID),
  prefill logic, `getblocktxn` / `blocktxn` round-trip, ML-DSA-87 witness serialization,
  collision fallback paths, tx_nonce in preimage, ML-DSA-87 batch verification (64 sigs).

---

## 7. Short ID and Collision Handling

```
SHORT_ID_LENGTH = 6 bytes
Hash function:  SipHash-2-4 keyed on (nonce1, nonce2) from cmpctblock header
Input:          WTXID (see Section 11 for tx_nonce relay requirement)
Analogue:       BIP-152
```

**SipHash key generation:**

```
nonce1, nonce2 are two u64le values included in the cmpctblock header message.
The sender generates them as cryptographically random values per block announcement.
Let h = SipHash-2-4( key=(nonce1 || nonce2), input=wtxid(T) ) as a 64-bit unsigned integer.
short_id(tx) = first 6 bytes of little-endian(h & 0x0000ffffffffffff)  (lower 48 bits, LE byte order)

The receiver uses the same nonce1, nonce2 from the received cmpctblock header
to recompute short_ids for all transactions in its mempool.
Nonces are per-announcement, not per-peer or per-session.
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
Activation MUST follow the feature-bit framework in
`RUBIN_L1_CANONICAL.md` Section 23.2 (default window/threshold: 2016 / 1815),
with a dedicated deployment descriptor for short-id length change.
Do not activate preemptively.

---

## 8. Private Transactions and Pre-mining

**Risk:** Miner withholds transactions from the mempool before announcing a block →
all nodes issue getblocktxn round-trips → miner gains time advantage (MEV-like).

**Mitigation — peer quality scoring (not banning):**

```
P2P handshake declares relay mode:
  tx_relay = 1   transaction relay expected from this peer
  tx_relay = 0   block-relay-only peer

`tx_relay` is defined in RUBIN_L1_P2P_AUX.md §3.1 (`version` payload).

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

## 9. IBD and Warm-up

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

**Steady-state peer connection (non-IBD):**

When a fully-synced node accepts a new inbound or outbound peer connection:

```
If local sendcmpct_mode >= 1:
  Send sendcmpct_mode = 1 to the new peer immediately after version handshake.
  If the peer is selected as a high-bandwidth peer (up to 3 peers total):
    Send sendcmpct_mode = 2.

A node MUST NOT send sendcmpct_mode = 2 to more than 3 peers simultaneously.
High-bandwidth peers are selected based on peer_quality_score (see Section 14).
If a better peer connects, demote the lowest-scoring current HB peer to mode = 1.
```

---

## 10. DA Retention and Pruning

- A node announces `pruned_below_height` in its P2P `version` message (RUBIN_L1_P2P_AUX.md §3.1).
- A node with `pruned_below_height > current_height - MIN_DA_RETENTION_BLOCKS`
  is deprioritized for DA data requests. It is NOT banned.
- A pruning node remains a full validator. The following are retained permanently:
  TXID, DA_Core_Fields, SHA3-256(DA_Payload). The chain
  TXID -> MerkleRoot -> BlockHeader remains intact.
- `DA_Core_Fields` MUST include a commitment to DA_Payload so that an archival node
  can cryptographically match payload to L1 data.
  This is enforced at consensus level by RUBIN_L1_CANONICAL.md §21.4 (Payload Commitment Verification).
- Node roles are explicit and non-overlapping:

  | Role | DA Retention | Consensus Participation |
  |------|-------------|------------------------|
  | L1 validator / miner | MIN_DA_RETENTION_BLOCKS (21 days) | Full |
  | DA archival node | Indefinite (operator policy) | Full |
  | Watchtower | Channel-scoped | Optional |

---

## 11. tx_nonce — P2P Relay Requirement

`tx_nonce` consensus rules (wire format, preimage inclusion, uniqueness) are defined in
**RUBIN_L1_CANONICAL.md §5.1, §8, §16, §17**.

Summary relevant to compact block relay:

- `txid(T) = SHA3-256(TxCoreBytes(T))` — `tx_nonce` is included in `TxCoreBytes`, therefore in `txid`.
- `wtxid(T) = SHA3-256(TxBytes(T))` — `tx_nonce` is included in `TxBytes`, therefore in `wtxid`.
- `tx_nonce` is included in the ML-DSA-87 signature preimage (`preimage_tx_sig` in §12 of CANONICAL).
- Witness commitment is anchored in coinbase (`CORE_ANCHOR`) per CANONICAL §10.4.1; compact relay still uses `wtxid`.

**Consequence for short_id uniqueness:**

Because `tx_nonce` is part of `TxBytes` (WTXID preimage), two transactions that are
identical in all semantic fields but differ in `tx_nonce` produce different WTXIDs and
therefore different `short_id` values. This eliminates a class of deliberate short_id
collision attacks.

**Relay requirement:**

A node MUST NOT relay a transaction with `tx_nonce = 0` (reserved for coinbase).
Any such transaction MUST be rejected at the relay layer before mempool admission.

Test vectors for `tx_nonce` in WTXID computation are required in `CV-COMPACT` (Section 15).

---

## 12. ML-DSA-87 Batch Verification

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

### 12.1 SLH-DSA Parallel Verification (Implementation Note)

This note is non-consensus and describes implementation guidance for validator
performance in SLH fallback mode.

- ML-DSA-87 batch verification remains unchanged (`ML_DSA_BATCH_SIZE = 64`).
- SLH-DSA-SHAKE-256f does not have a batch-verify path in this profile; nodes
  SHOULD parallelize verification across independent transactions / inputs.
- For SLO targets defined in `RUBIN_SLH_FALLBACK_PLAYBOOK.md` §2.1, the
  baseline hardware profile is 16 physical CPU cores.

Reference local baseline (Apple Silicon, 16 cores, OpenSSL 3.5.5 speed test):
- `SLH-DSA-SHAKE-256f verify/s = 7360.8`
- `ML-DSA-87 verify/s = 102012.8`

The `VERIFY_COST` constants are consensus parameters and are not changed by
this implementation note.

---

## 13. Normative Telemetry Fields

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
orphan_recovery_success_rate  sets reaching COMPLETE_SET before TTL / total sets received
peer_quality_score            current score per peer (see Section 14)
```

---

## 14. Peer Quality Score

Peer quality score is a local, non-consensus value. It is never transmitted to peers.
It influences peer selection and sendcmpct mode assignment only.

**Score definition:**

```
peer_quality_score: integer, range [0, 100], default 50 on new connection.

Positive events (increase score):
  +2   block reconstruction succeeded without getblocktxn
  +1   getblocktxn succeeded on first attempt
  +1   prefetch completed before block arrival

Negative events (decrease score):
  -5   incomplete_set recorded (State B TTL expiry attributed to this peer)
  -3   getblocktxn required for reconstruction
  -10  full block request required (getblocktxn failed)
  -2   prefetch rate cap exceeded

Score is clamped to [0, 100] after each update.
Score decays toward 50 at rate of 1 point per 144 blocks (passive normalization).
```

**Score thresholds and actions:**

```
score >= 75   eligible for sendcmpct_mode = 2 (high-bandwidth)
score >= 40   eligible for sendcmpct_mode = 1 (low-bandwidth)
score <  40   sendcmpct_mode = 0 (full blocks only) for this peer
score <  20   disconnect candidate (subject to GRACE_PERIOD_BLOCKS)

Maximum 3 peers at sendcmpct_mode = 2 simultaneously.
On new connection: assign mode = 1 initially; promote to mode = 2
after 6 blocks if score >= 75.
```

**Grace period:**

During `GRACE_PERIOD_BLOCKS = 1_440` blocks after genesis, score penalties
are halved and disconnect threshold is score < 5 (effectively disabled).
Grace period applicability is evaluated per-block (block height < GRACE_PERIOD_BLOCKS),
not per-peer-session. A peer connected during the grace period does not retain grace treatment
after block height 1_440.

---

## 15. CV-COMPACT Conformance Gate

`CV-COMPACT` is the conformance test suite for compact block relay.
All items marked MUST are required for mainnet readiness.

Normative machine-readable vectors (inputs and expected outputs) are stored in:

- `conformance/fixtures/CV-COMPACT.json`

Execution path:

- `conformance/runner/run_cv_bundle.py --only-gates CV-COMPACT`

Vector schema (normative for CI gate):

- required fields: `id`, `op`, `expect_ok`
- on failure vectors: `expect_err`
- on success vectors: operation-specific `expect_*` fields (`expect_short_id`, `expect_txid`, etc.)

| Test ID | Description | MUST / SHOULD |
|---------|-------------|---------------|
| CV-C-01 | short_id generation: SipHash-2-4 on WTXID with given nonce1/nonce2 | MUST |
| CV-C-02 | short_id collision: getblocktxn fallback, then full block fallback | MUST |
| CV-C-03 | tx_nonce in WTXID preimage: two identical txs differ only by nonce → different WTXID | MUST |
| CV-C-04 | tx_nonce in TXID preimage: two txs identical except tx_nonce produce different TXID | MUST |
| CV-C-05 | ML-DSA-87 witness serialization round-trip | MUST |
| CV-C-06 | ML-DSA-87 batch verification (64 sigs), happy path | MUST |
| CV-C-07 | ML-DSA-87 batch verification fail → individual fallback identifies invalid tx | MUST |
| CV-C-08 | getblocktxn / blocktxn prefill round-trip | MUST |
| CV-C-09 | State machine A→B→C: chunks before commit, then commit arrives | MUST |
| CV-C-10 | State machine A→B TTL expiry: atomic eviction of commit + chunks | MUST |
| CV-C-11 | COMPLETE_SET pinned; incomplete set rejected by CheckBlock | MUST |
| CV-C-12 | per-peer orphan limit enforced (4 MiB cap) | MUST |
| CV-C-13 | per-da_id orphan limit enforced (8 MiB cap) | MUST |
| CV-C-14 | TTL resets on A→B transition | MUST |
| CV-C-15 | sendcmpct_mode 0/1/2 transitions: IBD, warm-up, self-downgrade | MUST |
| CV-C-16 | peer_quality_score updates on reconstruction success/failure | SHOULD |
| CV-C-17 | prefetch rate cap per-peer and global | SHOULD |
| CV-C-18 | orphan_recovery_success_rate telemetry output | SHOULD |
| CV-C-24 | orphan storm saturation (16 peers x 4 MiB) with commit-first eviction policy | SHOULD |
| CV-C-25 | overflow storm path with pure-fee eviction policy fallback | SHOULD |

---

## 16. Design Decisions

The following items were open during drafting and are now resolved.

| Parameter | Decision | Rationale |
|-----------|----------|-----------|
| `DA_ORPHAN_TTL_BLOCKS` | **3** (360 s) | K=2 insufficient for real propagation delays. K=4 extends DoS window to 8 min. K=3 provides one relay window of margin. Revisit if `orphan_recovery_success_rate` < 99.9% at peak latency on mainnet. |
| `TARGET_FILL_RATE` | **30% (non-normative)** | Protocol MUST be designed for 100% fill. 30% is a baseline for economic models only. Does not affect any node code path. Established by Tokenomics WG; outside scope of this document. Actual fill may be 0-100% in any period. |
| `PREFETCH_BYTES_PER_SEC` | **4_000_000 B/s** per peer | Derived: ceil(MAX_DA_BYTES_PER_BLOCK / PREFETCH_TARGET_COMPLETE_SEC). Calibrate on testnet. Non-consensus; may be adjusted via coordinated node upgrade (no hard fork required). |
| `PREFETCH_GLOBAL_BPS` | **32_000_000 B/s** | Derived: PREFETCH_GLOBAL_PARALLEL x PREFETCH_BYTES_PER_SEC. Not an independent constant. |
