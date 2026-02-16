# RUBIN Node Policy Defaults v1.1 (Non-Consensus)

Status: OPERATIONAL GUIDANCE (non-consensus)  
Date: 2026-02-16  
Scope: relay/mempool/p2p/operator policies that MAY be changed without a network-wide consensus upgrade.

This document deliberately does **not** change consensus validity. A transaction or block that is consensus-valid may still be rejected by local policy (mempool/relay/mining policy).

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
- Prefer “first-seen” ordering for conflicting spends; any “replacement policies” and the trigger for switching behavior MUST be published via an operational update + release notes, and operators SHOULD switch only when that update defines deterministic criteria.

## 2. P2P DoS defenses (policy)

### 2.1 Connection management

Operators SHOULD configure:
- per-peer bandwidth ceilings,
- maximum concurrent connections,
- per-peer request quotas (headers/blocks/tx),
- stale-peer eviction (idle or misbehaving peers).

### 2.2 Eclipse mitigations

Nodes SHOULD:
- diversify inbound/outbound peers across buckets,
- rotate a portion of outbound connections periodically,
- maintain a small set of long-lived “anchor” connections for liveness.

This is policy guidance; it is not a consensus requirement.

## 3. ANCHOR spam resistance (policy)

Because `CORE_ANCHOR` outputs are non-spendable and require `value = 0` by consensus (CANONICAL v1.1 §3.6), spam pressure must be handled primarily by policy.

Recommended mempool policy:
- require higher effective fees for transactions containing `CORE_ANCHOR` payload bytes (e.g., a multiplier over the base fee floor),
- deprioritize near-limit `anchor_data` unless fee/weight is competitive,
- rate-limit submission from peers that relay repeated near-limit anchors.

Do **not** rely on “sender identity” in UTXO contexts; apply limits per peer / per connection rather than per “address”.

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

Implementation note: `key_id` is derived from witness pubkey bytes; for policy dedup, only apply after canonical parsing and basic witness typing (do not require signature verification to apply dedup).

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

## 9. FIPS-path operational controls (non-consensus)

For compliance-oriented deployments:
- pin and attest wolfCrypt shim binaries (hash + provenance),
- record build identifiers and operating environment,
- fail-stop on crypto provider internal errors (do not silently substitute hashes).
