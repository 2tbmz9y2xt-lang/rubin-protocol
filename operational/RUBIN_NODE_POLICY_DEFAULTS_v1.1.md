# RUBIN Node Policy Defaults v1.1 (Non-Consensus)

Status: OPERATIONAL GUIDANCE (non-consensus)  
Date: 2026-02-16  
Scope: relay/mempool/p2p/operator policies that MAY be changed without a network-wide consensus upgrade.

This document deliberately does **not** change consensus validity. A transaction or block that is consensus-valid may still be rejected by local policy (mempool/relay/mining policy).

## 0. Launch priorities (P0/P1/P2)

These priorities are **operational** (non-consensus) and intended for launch readiness.

P0 (must-have before any private/public mainnet operations):
- Enforce `MIN_RELAY_FEE_RATE` floor and eviction under load (§1.1, §1.3).
- Per-peer bandwidth ceilings + connection caps + stale-peer eviction (§2.1).
- Mempool-level nonce dedup + rate limiting (best-effort) (§5).
- Shim pinning + strict fail-stop for crypto provider errors (if using wolfCrypt shim) (§9).

P1 (strongly recommended for partner/private phase):
- ANCHOR fee multiplier + near-limit deprioritization + per-peer rate limiting (§3).
- Eclipse mitigations: diverse outbound + rotation + anchor connections (§2.2).
- Explicit monitoring with alert thresholds (§8.1).

P2 (optional / environment-dependent):
- Light-client extra checks (checkpoints, anomaly detection) (§6).
- RETL “preferred domain” prioritization for UI/relay (§4).

## 1. Relay + mempool policies

### 1.1 Fee floor

- Nodes MUST enforce `MIN_RELAY_FEE_RATE` as a local floor (`MIN_RELAY_FEE_RATE = 1` in CANONICAL v1.1 §1.2; non-consensus relay policy).
- Nodes MAY raise the floor dynamically under load (DoS defense).
- Mempool admission SHOULD prioritize by `fee / weight(T)` (economic efficiency).

### 1.2 Size and complexity caps (policy)

These are already defined as policy knobs in CANONICAL v1.1:
- `MAX_WITNESS_ITEM_BYTES` (single witness item cap, relay-only)
- `MAX_RELAY_MSG_BYTES` (P2P message cap, relay-only)

Nodes MAY enforce additional local caps, but SHOULD log and surface them as policy decisions (not “consensus failures”).

### 1.3 Eviction + anti-starvation

- When mempool is full, evict lowest `fee/weight` first.
- Apply anti-starvation backoff so short bursts cannot permanently crowd out moderate-fee traffic.
- Prefer “first-seen” ordering for conflicting spends.

Replacement (RBF-like) position (policy default):
- Default for v1.1: **no replacement**. Conflicting spends are rejected from mempool/relay even if they pay higher fees.
- Rationale: PQ witness sizes make replacement a DoS surface (large signatures amplify bandwidth/CPU churn).

If an operator enables replacement (non-default), it SHOULD be constrained and measurable:
1. Require a strict fee-rate bump: `new_fee_rate ≥ 2× old_fee_rate`.
2. Require bounded churn: `new_witness_bytes ≤ old_witness_bytes` (do not allow a replacement that increases witness size).
3. Limit per-outpoint churn: at most 1 replacement attempt per outpoint per 10 minutes.
4. Keep replacement local-only: do not advertise replacement behavior unless it is published in release notes for the private/public phase.

## 2. P2P DoS defenses (policy)

### 2.1 Connection management

Operators SHOULD configure:
- per-peer bandwidth ceilings,
- maximum concurrent connections,
- per-peer request quotas (headers/blocks/tx),
- stale-peer eviction (idle or misbehaving peers).

Recommended starting defaults (non-consensus):
- Outbound peers: 16
- Inbound peers: 64
- Total peers hard cap: 128
- Per-IP inbound cap: 4
- Stale-peer eviction: disconnect if idle > 15 minutes
- Per-peer bandwidth ceiling (sustained): 1 MiB/s inbound, 1 MiB/s outbound

### 2.2 Eclipse mitigations

Nodes SHOULD:
- diversify inbound/outbound peers across buckets,
- rotate a portion of outbound connections periodically,
- maintain a small set of long-lived “anchor” connections for liveness.

This is policy guidance; it is not a consensus requirement.

## 3. ANCHOR spam resistance (policy)

Because `CORE_ANCHOR` outputs are non-spendable and require `value = 0` by consensus (CANONICAL v1.1 §3.6), spam pressure must be handled primarily by policy.

### 3.1 Relay-level hard cap (pre-mempool)

Consensus allows up to `MAX_ANCHOR_PAYLOAD_SIZE = 65_536` bytes per ANCHOR output.
Without a relay-level cap, a peer can relay transactions carrying 65 KB anchor payloads
at near-zero weight cost (ANCHOR is non-spendable, adds no sig_cost), creating a cheap
relay DoS vector even when block inclusion never happens.

**Default relay policy — enforced before mempool admission (non-consensus):**

```
MAX_ANCHOR_PAYLOAD_RELAY      = 1_024   # bytes per single ANCHOR output
MAX_ANCHOR_OUTPUTS_PER_TX_RELAY = 4    # max ANCHOR outputs accepted per tx
MAX_ANCHOR_BYTES_PER_TX_RELAY = 2_048  # total anchor bytes across all outputs in tx
```

Enforcement steps on receiving a tx via P2P:

1. For each output where `covenant_type = CORE_ANCHOR`:
   - If `|anchor_data| > MAX_ANCHOR_PAYLOAD_RELAY` → **reject relay**, increment ban-score.
2. If tx has more than `MAX_ANCHOR_OUTPUTS_PER_TX_RELAY` ANCHOR outputs → reject relay.
3. If sum of `|anchor_data|` across ANCHOR outputs exceeds `MAX_ANCHOR_BYTES_PER_TX_RELAY` → reject relay.
4. Log rejection for monitoring; do not propagate as a consensus error.

Rationale for 1 KB: covers all legitimate ANCHOR use cases:
- RETL batch state root: 32–64 bytes
- Key migration shadow-binding envelope: ~200 bytes
- HTLC preimage commitment: 32 bytes
- Application metadata: up to ~800 bytes remaining

Payloads above 1 KB per output indicate misconfigured clients or active spam.
The consensus backstops `MAX_ANCHOR_PAYLOAD_SIZE = 65_536` and
`MAX_ANCHOR_BYTES_PER_BLOCK = 131_072` remain unchanged.

Operator override: operators with legitimate large-anchor needs (e.g., rollup DA)
MAY raise `MAX_ANCHOR_PAYLOAD_RELAY` up to the consensus limit on their own nodes.
They MUST document the override and accept the associated relay DoS risk locally.

### 3.2 Mempool fee and prioritization policy

Applies after relay cap passes:

- Require higher effective fees for transactions containing `CORE_ANCHOR` payload bytes.
- Deprioritize near-limit anchor_data unless fee/weight is competitive.
- Rate-limit submission from peers that relay repeated near-limit anchors.

Concrete starting point:

- `ANCHOR_FEE_MULTIPLIER = 4x` over the base floor for the `anchor_data` bytes component.
- "Near-limit" threshold: `|anchor_data| >= 0.9 x MAX_ANCHOR_PAYLOAD_RELAY` (relay cap, not consensus limit).
- Per-peer rate limit: accept at most 1 near-limit ANCHOR tx per 10 seconds.

Do **not** rely on "sender identity" in UTXO contexts; apply limits per peer / per connection rather than per "address".


## 4. RETL-specific policies (application-layer)

RETL semantics are application-level (CANONICAL v1.1 §7). Nodes and operators MAY apply policy gates for what they *relay* or *surface*:

- optional minimum RETL bond threshold for “preferred” domains (UI/relay prioritization),
- domain reputation scoring (non-consensus),
- caching of sequencer signature verification results where safe.

Avoid hard whitelists for validity; prefer prioritization over censorship.

## 5. Nonce replay hardening (mempool policy)

Consensus `tx_nonce` replay prevention is per-block (CANONICAL v1.1 §3.4). To reduce spam and reorg churn, nodes MAY add:

- mempool-level deduplication over `(key_id, tx_nonce)` for a rolling window,
- per-key rate limits in mempool,
- persistence of recently-seen nonces across restarts (operator option).

Recommended starting window (non-consensus):
- Rolling window: keep recently-seen `(key_id, tx_nonce)` for 144 blocks (~24 hours) or until mempool eviction.
- Storage bound: cap dedup table at 200,000 entries (LRU/TTL eviction).
- Per-key cap: max 1,000 outstanding nonces per `key_id` in mempool (beyond cap, reject or evict lowest-fee).

Implementation note: `key_id` is derived from witness pubkey bytes; for policy dedup, only apply after canonical parsing and basic witness typing (do not require signature verification to apply dedup).

### 5.1 PQ signature CPU exhaustion (policy)

Because SLH-DSA verification is significantly more expensive than ML-DSA in v1.1 cost model (`VERIFY_COST_SLH_DSA = 64` vs `VERIFY_COST_ML_DSA = 8`), nodes SHOULD add CPU-safety limits:

Recommended starting controls (non-consensus):
- Per-peer SLH-DSA verify budget: 2 verifications/second sustained (burst 10, then backoff).
- Per-peer ML-DSA verify budget: 20 verifications/second sustained (burst 100).
- Under load, deprioritize `suite_id = 0x02` spends unless fee/weight is strictly higher than competing traffic.
- Cache verification results keyed by `(sighash, pubkey, signature)` to avoid repeated work across peers.

## 6. Light client and SPV policies (non-consensus)

Light clients MAY add extra safety checks beyond consensus:
- checkpoints (operator-selected trust anchors),
- difficulty anomaly detection,
- proof caching with bounded memory.

These change the client’s trust model; document them explicitly.

## 7. Upgrade coordination policies

For VERSION_BITS deployments, operators SHOULD:
- monitor signaling progress,
- stage rollouts (canary → wider),
- keep rollback playbooks for client releases (non-consensus operational control).

## 8. Monitoring (recommended)

Operators SHOULD track:
- mempool size, rejection reasons, eviction rates,
- per-peer connection churn and bandwidth,
- anchor bytes per block and per tx (observed),
- signature verification latency,
- reorg frequency and depth (observed).

### 8.1 Suggested alert thresholds (starting points)

These are suggested starting points; tune for your hardware, bandwidth, and phase (private vs public).

Mempool / relay:
- Alert if mempool occupancy stays > 80% of configured limit for > 15 minutes.
- Alert if eviction rate spikes to > 100 evictions/minute for > 5 minutes.
- Alert if rejection rate spikes to > 30% of inbound tx for > 10 minutes (separate by reason).

P2P:
- Alert if new inbound connections exceed your expected peer set by > 10% (private phase) or > 2× baseline (public phase).
- Alert if any single peer exceeds its bandwidth ceiling for > 60 seconds (misconfig or attack).
- Alert if peer churn rate (disconnects/minute) exceeds 2× baseline for > 10 minutes.

ANCHOR:
- Alert if `Σ |anchor_data|` observed per block exceeds 80% of `MAX_ANCHOR_BYTES_PER_BLOCK` for > 3 consecutive blocks.
- Alert if near-limit `anchor_data` submissions dominate (> 50% of anchor tx) for > 30 minutes.

Crypto verification:
- Alert if signature verification latency p95 exceeds 2× baseline for > 10 minutes.
- Alert if any crypto provider internal error occurs in “strict” mode (treat as incident).

Reorg:
- Alert on any reorg depth ≥ 2.
- Alert if reorg frequency exceeds 1/day (baseline-dependent; investigate hashrate instability or partitioning).

## 9. FIPS-path operational controls (non-consensus)

For compliance-oriented deployments:
- pin and attest wolfCrypt shim binaries (hash + provenance),
- record build identifiers and operating environment,
- fail-stop on crypto provider internal errors (do not silently substitute hashes).
