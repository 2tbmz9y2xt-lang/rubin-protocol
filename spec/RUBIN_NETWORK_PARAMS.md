# RUBIN Network Parameters

**Status:** Approved v1.0
**Date:** 2026-02-21

This document is the authoritative reference for RUBIN network parameters,
node requirements, and technical characteristics. It is derived from and
must remain consistent with RUBIN_L1_CANONICAL.md and RUBIN_COMPACT_BLOCKS.md.

In case of conflict, RUBIN_L1_CANONICAL.md takes precedence.

Units convention:
- Unless explicitly marked as binary (`MiB`, `GiB`, `TiB`), byte quantities use SI prefixes
  (`1 MB = 1_000_000 bytes`, `1 GB = 1_000_000_000 bytes`).

---

## 1. Block Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| `TARGET_BLOCK_INTERVAL` | 120 s | CANONICAL §4 |
| `POW_LIMIT` | 0xffff..ffff (bytes32 max) | CANONICAL §4, §15 |
| `MAX_BLOCK_WEIGHT` | 68,000,000 wu | CANONICAL §4 |
| `MAX_BLOCK_BYTES` | 72,000,000 bytes (72 MB) | CANONICAL §4 |
| `MAX_DA_BYTES_PER_BLOCK` | 32,000,000 bytes (30.5 MiB) | CANONICAL §4 |
| `WINDOW_SIZE` (retarget) | 10,080 blocks (14 days) | CANONICAL §4 |
| `MIN_DA_RETENTION_BLOCKS` | 15,120 blocks (21 days) | COMPACT §1 |
| `COINBASE_MATURITY` | 100 blocks | CANONICAL §4 |
| `MAX_FUTURE_DRIFT` | 7,200 s | CANONICAL §4 |
| `MAX_TIMESTAMP_STEP_PER_BLOCK` | 1,200 s (`10 * TARGET_BLOCK_INTERVAL`) | CANONICAL §4, §15 |
| `WITNESS_DISCOUNT_DIVISOR` | 4 | CANONICAL §4 |
| `SLH_DSA_ACTIVATION_HEIGHT` | 1,000,000 | CANONICAL §4, §14.1, §14.2 |
| Coinbase witness commitment | Required (CORE_ANCHOR, single 32-byte hash) | CANONICAL §10.4.1 |

---

## 2. Network Throughput

| Metric | Value | Notes |
|--------|-------|-------|
| Blocks per year | 262,800 | 365 × 86400 / 120 |
| L1 TPS (ML-DSA-87) | ~74 | 8,886 tx/block / 120s; weight = 7,652 wu/tx; assumes DA bytes near zero |
| L1 TPS (SLH-DSA fallback) | ~11 | 1,349 tx/block / 120s; weight = 50,407 wu/tx; assumes DA bytes near zero |
| L2 TPS | ~2,667 | 32 MB DA / 120 s / 100 B/tx; assumes DA budget saturated |
| DA throughput | 0.267 MB/s | 32,000,000 / 120 |
| Orphan rate | ~0.02% | compact blocks |
| TPS drop at SLH-DSA activation | 6.6× | emergency fallback only |

Notes:
- L1 TPS and L2 DA-saturated TPS are different operating points and are not simultaneously achievable in one block.
- When DA usage increases, available L1 transaction capacity decreases proportionally due to shared `MAX_BLOCK_WEIGHT`.

---

## 3. Finality

| Context | Confirmations | Time |
|---------|--------------|------|
| L1 transaction | 8 blocks | 16 min |
| Bridge / cross-chain | 12 blocks | 24 min |
| Governance | 16 blocks | 32 min |

---

## 4. Economics

| Parameter | Value |
|-----------|-------|
| Emission anchor supply | 50,000,000 RBN |
| Pre-allocated (genesis) | 1,000,000 RBN (2%) |
| Mineable cap (pre-tail) | 49,000,000 RBN |
| Emission curve | Smooth decay (`remaining >> 20`) + tail |
| Tail emission | 0.19025875 RBN/block (50,000 RBN/year @ 120s, 365d) |
| Base unit | 1 RBN = 100,000,000 base units |
| Emission anchor (base units) | 5,000,000,000,000,000 |

Subsidy schedule: CryptoNote-style smooth decay with a fixed tail emission floor.
See CANONICAL §19 for the exact consensus formula.

Notes:
- Total supply is unbounded after tail activation (tail continues indefinitely).
- The stated "50,000 RBN/year" is informative; consensus uses the fixed per-block constant.
- Genesis allocation split (informative):
  - 500,000 RBN airdrop pool (unlocked at genesis).
  - 500,000 RBN treasury pool, unlocked linearly over 5 years using `CORE_HTLC` refund-height tranches.

Treasury tranche schedule (informative):
- Total treasury amount: 500,000 RBN split into `N = 20` tranches (quarterly over 5 years).
- Each tranche unlocks at `refund_lock_height = i * 65,700` blocks, for tranche index `i = 1..20`
  (since `65,700 * 20 = 1,314,000` blocks ≈ 5 years at 120s block time).
- Tranche values use integer base units:
  - `500,000 RBN / 20 = 25,000 RBN` per tranche (2,500,000,000,000 base units); no remainder.

Exact recipient key IDs and hashes are chain-instance parameters and MUST be fixed by the published genesis bytes.

---

## 5. Cryptography

| Parameter | Value |
|-----------|-------|
| Primary signature | ML-DSA-87 (FIPS 204) |
| ML-DSA-87 pubkey | 2,592 bytes |
| ML-DSA-87 signature | 4,627 bytes |
| ML-DSA-87 weight cost | 8 wu / signature |
| Backup signature | SLH-DSA-SHAKE-256f (consensus-gated; active from `SLH_DSA_ACTIVATION_HEIGHT`) |
| SLH-DSA pubkey | 64 bytes |
| SLH-DSA max signature | 49,856 bytes |
| SLH-DSA weight cost | 64 wu / signature |
| Hash function | SHA3-256 (FIPS 202) |
| Batch verification | 64 signatures per batch (ML-DSA-87) |

---

## 6. Transaction Limits

| Parameter | Value |
|-----------|-------|
| Max inputs per tx | 1,024 |
| Max outputs per tx | 1,024 |
| Max witness items per tx | 1,024 |
| Max witness bytes per tx | 100,000 |
| Max script_sig bytes | 32 |
| Max DA batches per block | 128 |
| Max chunks per DA set | 61 (derived: floor(MAX_DA_BYTES_PER_BLOCK / CHUNK_BYTES)) |
| Chunk size | 524,288 bytes (512 KiB) |
| Max DA manifest bytes per tx | 65,536 |
| Max anchor payload per tx | 65,536 bytes |
| Max anchor bytes per block | 131,072 bytes |

---

## 7. Storage Requirements

All storage figures use binary units (1 TiB = 2^40 bytes).
Hardware provisioning MUST account for 100% fill rate.
Economics MAY use the 30% target fill rate as a planning baseline.

```
Formulas:
  storage_year = MAX_BLOCK_BYTES x 262_800 / 2^40
  da_year      = MAX_DA_BYTES_PER_BLOCK x 262_800 / 2^40
  live_window  = MAX_DA_BYTES_PER_BLOCK x MIN_DA_RETENTION_BLOCKS / 2^30
```

### 7.1 L1 Validator / Miner (pruning enabled)

| Item | Size | Growth |
|------|------|--------|
| DA live window | 451 GiB | Fixed |
| L1 chain (headers + UTXO) | ~590 GiB | Slow |
| **Total recommended** | **~1.04 TiB** | **Fixed** |

A standard 2 TB SSD is sufficient with margin.
Pruning discards DA payloads older than `MIN_DA_RETENTION_BLOCKS`.
Retained permanently: TXID, DA_Core_Fields, SHA3-256(DA_Payload).

### 7.2 L2 Operator / DA Archival Node

| Fill rate | DA only / year | Full block / year | Live window DA |
|-----------|---------------|-------------------|----------------|
| 100% (max load) | 7.65 TiB | 17.21 TiB | 451 GiB |
| 30% (planning target) | 2.29 TiB | 5.16 TiB | 135 GiB |

Recommended: NAS or object storage with ≥ 20 TB usable at launch,
expandable. This is an operator cost, not a protocol requirement.

### 7.3 Watchtower

Stores only channels relevant to its scope.
Storage depends on number of monitored channels; no protocol minimum.

---

## 8. Node Hardware Recommendations

### 8.1 L1 Validator / Miner

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Disk | 2 TB SSD | 4 TB NVMe SSD |
| RAM | 4 GB | 8 GB |
| RAM (DA mempool) | 512 MiB (included above) | 1 GiB |
| Uplink | 50 Mbps | 100 Mbps |
| CPU | 4 cores | 8 cores (ML-DSA-87 batch verify) |

### 8.2 L2 Operator / DA Archival Node

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Disk | 10 TB HDD | 20+ TB expandable NAS |
| RAM | 8 GB | 16 GB |
| Uplink | 100 Mbps | 1 Gbps |
| CPU | 4 cores | 16 cores |

---

## 9. P2P Relay Parameters

| Parameter | Value |
|-----------|-------|
| Short ID length | 6 bytes (SipHash-2-4 on `wtxid`, lower-48 LE bytes) |
| sendcmpct_mode 0 | Compact disabled, full blocks only |
| sendcmpct_mode 1 | Compact low-bandwidth |
| sendcmpct_mode 2 | Compact high-bandwidth |
| reject message | Deprecated for mainnet (diagnostic-only on testnet/devnet) |
| Max high-bandwidth peers | 3 simultaneous |
| Prefetch rate per peer | 4 MB/s |
| Prefetch rate global | 32 MB/s |
| DA orphan TTL | 3 blocks (360 s) |
| DA orphan pool | 64 MiB |
| DA orphan commit overhead cap | 8 MiB (`DA_ORPHAN_COMMIT_OVERHEAD_MAX`) |
| Max relay message | 96,000,000 bytes (91.6 MiB) |
| Grace period | 1,440 blocks (~2 days) |
| IBD exit condition | Tip timestamp lag < 24 h from system time |

---

## 10. Covenant Types (Genesis Registry)

| Code | Name | Description |
|------|------|-------------|
| 0x0000 | CORE_P2PK | Standard pay-to-public-key (ML-DSA-87) |
| 0x0001 | UNASSIGNED | Forbidden — TX_ERR_COVENANT_TYPE_INVALID |
| 0x0002 | CORE_ANCHOR | Non-spendable data anchor |
| 0x00FF | CORE_RESERVED_FUTURE | Forbidden — TX_ERR_COVENANT_TYPE_INVALID |
| 0x0100 | CORE_HTLC | Hash Time-Locked Contract, active from genesis (`covenant_data_len = 105`, witness_slots=2) |
| 0x0101 | CORE_VAULT | Consensus-native: M-of-N multisig + mandatory destination whitelist |
| 0x0102 | UNASSIGNED | Forbidden — TX_ERR_COVENANT_TYPE_INVALID |
| 0x0103 | CORE_DA_COMMIT | DA payload commitment (non-spendable, tx_kind=0x01 only) |
| 0x0104 | CORE_MULTISIG | Consensus-native: M-of-N multisig without whitelist restrictions |

---

## 11. Document Map

| Document | Scope |
|----------|-------|
| `RUBIN_L1_CANONICAL.md` | Consensus rules: wire format, validation, state transitions |
| `RUBIN_COMPACT_BLOCKS.md` | P2P relay policy: compact blocks, mempool, peer scoring |
| `RUBIN_NETWORK_PARAMS.md` | This file: reference summary for TZ, roadmap, hardware planning |
| `RUBIN_L1_P2P_AUX.md` | Auxiliary P2P rules |
| `RUBIN_SLH_FALLBACK_PLAYBOOK.md` | Operational activation/rollback runbook for SLH fallback mode |

---

## 12. Feature-Bit Activation Defaults

Consensus and relay parameter changes that require coordinated activation MUST use the
feature-bit framework defined in `RUBIN_L1_CANONICAL.md` §23.2.

Default signaling parameters:

- `SIGNAL_WINDOW = 2016` blocks
- `SIGNAL_THRESHOLD = 1815` blocks (90%)

Each deployment MUST define at least:

- deployment `name`
- `bit` index in block header `version`
- `start_height`
- `timeout_height`

No deployment is ACTIVE by default unless explicitly declared in canonical specs.
