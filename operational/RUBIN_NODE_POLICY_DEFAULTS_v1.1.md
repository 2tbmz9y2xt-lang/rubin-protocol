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

These limits are defined in CANONICAL v1.1:
- `MAX_WITNESS_BYTES_PER_TX` (consensus per-tx witness cap)
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

### 1.4 Keyless covenant flood resistance (CORE_TIMELOCK_V1)

`CORE_TIMELOCK_V1` spends are keyless by design and use a sentinel witness (`suite_id = 0x00`,
zero-length pubkey/signature). This means `sig_cost = 0` and no cryptographic verification on spend.
As a result, these transactions can be much lighter than key-bearing spends and are a relay/mempool DoS surface.

A minimal 1-in/1-out TIMELOCK transaction weighs approximately **334 wu** (about **22x lighter**
than a comparable ML-DSA spend at ~7,561 wu). At `MAX_BLOCK_WEIGHT = 4,000,000`, a block could
theoretically include ~11,976 TIMELOCK spends.

**Default policy (non-consensus, relay + mempool):**

```
MIN_TIMELOCK_RELAY_FEE_MULTIPLIER = 4           # require 4x base MIN_RELAY_FEE_RATE
MIN_KEYLESS_EFFECTIVE_WEIGHT = 1_500            # floor for fee/priority accounting
MAX_TIMELOCK_TX_PER_PEER_PER_SECOND = 10        # sustained per-peer relay cap
MAX_TIMELOCK_TX_IN_MEMPOOL = 5_000              # absolute mempool cap for TIMELOCK spends
MAX_TIMELOCK_WEIGHT_PER_BLOCK_FRACTION = 0.25   # soft cap: <= 25% of block weight
```

Enforcement:

1. **Fee floor with effective weight**:
   - `effective_weight(T) = max(weight(T), MIN_KEYLESS_EFFECTIVE_WEIGHT)`
   - `required_fee(T) = effective_weight(T) x MIN_RELAY_FEE_RATE x MIN_TIMELOCK_RELAY_FEE_MULTIPLIER`
   - Admit only if `fee(T) >= required_fee(T)`.
   - For eviction/prioritization, compare by `fee / effective_weight(T)`.

2. **Per-peer relay rate**: if a peer exceeds `MAX_TIMELOCK_TX_PER_PEER_PER_SECOND`
   in a 1-second window, drop excess and increment ban-score (+5).

3. **Mempool cap**: if TIMELOCK spends already occupy `MAX_TIMELOCK_TX_IN_MEMPOOL`,
   reject new arrivals (relay rejection, no ban). Under pressure, evict lowest-fee
   TIMELOCK spends before key-bearing spends.

4. **UTXO-health bias under load**: deprioritize transactions creating many tiny UTXOs
   (policy-only heuristic; not a consensus rule).

5. **Block-level soft cap** (mining policy): miners/validators SHOULD keep TIMELOCK spends
   below `MAX_TIMELOCK_WEIGHT_PER_BLOCK_FRACTION` of block weight.

Operators MAY tune these defaults for legitimate workloads, but overrides SHOULD be documented.

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

### 2.3 Clock skew handling (BLOCK_ERR_TIMESTAMP_FUTURE)

Consensus rule (CANONICAL v1.1 §6.5.3):
- A block is invalid if `timestamp(B_h) > local_time + MAX_FUTURE_DRIFT` and MUST be rejected as
  `BLOCK_ERR_TIMESTAMP_FUTURE`.

Operational reality:
- `local_time` is node-local system time and is not globally consistent across the network.
- Therefore, the same header may be temporarily rejected as "future" by some nodes while being
  accepted by others, until wall-clock time catches up.

Recommended default policy (non-consensus):
- Do **not** immediately ban-score or disconnect a peer solely for relaying a future-timestamp block,
  unless the peer repeatedly sends far-future blocks beyond a configured abuse threshold.
- Cache the block/header as a **deferred candidate** and re-evaluate when `local_time` advances.
- If the deferred block becomes valid under the consensus time rule, process it normally.

Operator guidance:
- Nodes SHOULD run a stable time source (NTP/chrony) and monitor local clock drift.
- If the local clock is detected to be behind wall-clock by more than `MAX_FUTURE_DRIFT / 2`,
  operators SHOULD treat all future-timestamp rejections as suspect and fix system time before
  attributing misbehavior to peers.

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

### 4.1 Sequencer bond trust model (non-consensus)

**Trust model:** RETL sequencers are expected to be institutional operators (exchanges, custodians, licensed entities). Users select a sequencer the same way they select an exchange — based on reputation, legal accountability, and published SLAs. L1 does not enforce bond slashing; accountability is off-chain.

This is an explicit design choice: on-chain slashing requires a new covenant type and consensus upgrade. For v1.1, institutional accountability is the primary enforcement mechanism.

### 4.2 Canonical bond pattern (operational standard)

To ensure observability and consistency across sequencer operators, v1.1 defines a canonical bond pattern. Sequencers SHOULD follow this pattern so watchtowers and indexers can monitor uniformly.

**Step 1 — Bond UTXO creation:**

```
CORE_VAULT_V1 {
  owner_key_id    = sequencer_key_id
  lock_mode       = 0x00  (height lock)
  lock_value      = registration_height + BOND_LOCK_BLOCKS
  recovery_key_id = SHA3-256("RUBIN-UNSPENDABLE-v1")  // provably unspendable
}
```

Recommended `BOND_LOCK_BLOCKS`: operator policy (suggested minimum: 2016 blocks, ~2 weeks).

Using a provably-unspendable `recovery_key_id` means the bond cannot be slashed on-chain — it can only be withdrawn by the sequencer after the lock expires. This is an acknowledged limitation of the v1.1 trust model.

**Step 2 — Per-batch commitment (each batch):**

Each batch transaction MUST include a `CORE_ANCHOR` output with:

```
anchor_data =
  ASCII("RUBINv1-retl-bond-commit/") ||
  bond_outpoint_txid  : bytes32 ||
  bond_outpoint_vout  : u32le   ||
  batch_hash          : bytes32
```

Total anchor_data: 25 + 32 + 4 + 32 = 93 bytes. This creates an on-chain linkage between every batch and the active bond UTXO, allowing any observer to verify continuity.

**Step 3 — Exit notice (before withdrawal):**

Before spending the bond UTXO, the sequencer MUST publish an exit-notice `CORE_ANCHOR` at least `EXIT_NOTICE_BLOCKS` blocks prior:

```
anchor_data =
  ASCII("RUBINv1-retl-bond-exit/") ||
  sequencer_key_id : bytes32 ||
  exit_height      : u64le
```

Total anchor_data: 24 + 32 + 8 = 64 bytes. Recommended `EXIT_NOTICE_BLOCKS`: suggested minimum 144 blocks (~24 hours).

L1 consensus does NOT enforce this notice — it is an observable convention. Watchtowers that detect a bond withdrawal without a preceding exit-notice SHOULD flag the domain as untrusted and alert downstream clients.

**Step 4 — Watchtower responsibilities (indexers/relay nodes):**

Nodes and indexers SHOULD:
- track active bond UTXOs per `retl_domain_id`,
- verify per-batch `bond-commit` anchors are present and link to an active bond,
- alert if a bond UTXO is spent without a preceding `bond-exit` notice,
- alert if `bond-commit` anchors are absent for more than N consecutive batches (suggested N=3).

### 4.3 Acknowledged limitations

- A sequencer CAN withdraw bond via `owner_key_id` without following the exit-notice protocol. L1 will not reject this.
- Slashing is reputational and legal, not cryptographic.
- Future versions MAY introduce `CORE_BOND_V1` (a new covenant type via VERSION_BITS) to enforce exit windows on-chain. This is deferred to post-MVP phase.

### 4.4 On-chain bond upgrade path (informative)

When the sequencer ecosystem is established, `CORE_BOND_V1` can be activated via one of two VERSION_BITS paths (CANONICAL v1.1 §8.2):

- **Direct bit allocation:** use one bit from the `COVENANTS` range (bits 12..17). Appropriate if `CORE_BOND_V1` is the only or first covenant extension needed.
- **Via meta-bit (preferred for post-MVP):** if `upgrade_framework_v1` (bit 20, `UPGRADE_FRAMEWORK_META`) is active, `bond_v1` can be deployed as a sub-feature under the upgrade framework without consuming a `COVENANTS` bit. This is the preferred path once multiple covenant extensions are queued.

The meta-bit path is intentionally deferred in v1.1 to avoid over-complexity (CANONICAL §8.2). Operators planning to deploy `CORE_BOND_V1` SHOULD reserve a `COVENANTS` bit in their chain-instance deployment registry now to avoid bit conflicts later.

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

### 5.2 Witness byte bandwidth floor (policy)

`WITNESS_DISCOUNT_DIVISOR` reduces transaction weight independently of raw wire size.
A large-witness transaction is cheaper by weight but still consumes full bandwidth and storage on every relay node.

Nodes SHOULD apply a bandwidth-aware admission floor in addition to the weight-based floor:

```
bandwidth_cost(T) = base_size + wit_size   # undiscounted, reflects actual wire bytes
bandwidth_fee_floor(T) = MIN_RELAY_FEE_RATE × ceil(bandwidth_cost(T) / 1_000)
weight_fee_floor(T)    = MIN_RELAY_FEE_RATE × weight(T)
required_fee(T)        = max(weight_fee_floor(T), bandwidth_fee_floor(T))
```

Effective admission: `fee(T) ≥ required_fee(T)`.

Starting parameters (non-consensus; tune per hardware/phase):
- `MIN_RELAY_FEE_RATE = 1` (from CANONICAL §1.2; non-consensus relay policy).
- Bandwidth floor adds ~1 sat per KB of raw witness on top of weight-based fee.
- At `wit_size = 90_000` (near `MAX_WITNESS_BYTES_PER_TX`): bandwidth floor ≈ 90 sat; weight floor ≈ 30 sat — bandwidth floor wins, as intended.

Rationale: without this floor, the witness discount creates an asymmetry where an attacker can fill relay bandwidth at 3× lower cost than the weight-based fee model implies. This floor restores the fee/bandwidth relationship without changing consensus.

Operators SHOULD raise the bandwidth floor multiplier if large-witness spam is observed in private or public phase.

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
