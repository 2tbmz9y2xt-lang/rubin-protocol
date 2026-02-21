# RUBIN Network Parameters

**Status:** Approved v1.0
**Date:** 2026-02-21

This document is the authoritative reference for RUBIN network parameters,
node requirements, and technical characteristics. It is derived from and
must remain consistent with RUBIN_L1_CANONICAL.md and RUBIN_COMPACT_BLOCKS.md.

In case of conflict, RUBIN_L1_CANONICAL.md takes precedence.

---

## 1. Block Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| `TARGET_BLOCK_INTERVAL` | 120 s | CANONICAL §4 |
| `MAX_BLOCK_WEIGHT` | 68,000,000 wu | CANONICAL §4 |
| `MAX_BLOCK_BYTES` | 75,497,472 bytes (72 MiB) | CANONICAL §4 |
| `MAX_DA_BYTES_PER_BLOCK` | 32,000,000 bytes (30.5 MiB) | CANONICAL §4 |
| `WINDOW_SIZE` (retarget) | 10,080 blocks (14 days) | CANONICAL §4 |
| `MIN_DA_RETENTION_BLOCKS` | 15,120 blocks (21 days) | COMPACT §1 |
| `COINBASE_MATURITY` | 100 blocks | CANONICAL §4 |
| `MAX_FUTURE_DRIFT` | 7,200 s | CANONICAL §4 |
| `WITNESS_DISCOUNT_DIVISOR` | 4 | CANONICAL §4 |

---

## 2. Network Throughput

| Metric | Value | Notes |
|--------|-------|-------|
| Blocks per year | 262,800 | 365 × 86400 / 120 |
| L1 TPS | ~19 | ML-DSA-87, 1-in/1-out, ~8000 wu/tx |
| L2 TPS | ~2,667 | 32 MB DA / 120 s / 100 B/tx |
| DA throughput | 0.267 MB/s | 32,000,000 / 120 |
| Orphan rate | ~0.02% | compact blocks |

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
| Max supply | 100,000,000 RBN |
| Mined supply | 99,000,000 RBN |
| Pre-allocated (genesis) | 1,000,000 RBN |
| Subsidy duration | 876,600 blocks (~3.3 years) |
| Base unit | 1 RBN = 100,000,000 base units |
| Max supply (base units) | 10,000,000,000,000,000 |

Subsidy schedule: linear decay with remainder distribution.
See CANONICAL §19 for exact formula.

---

## 5. Cryptography

| Parameter | Value |
|-----------|-------|
| Primary signature | ML-DSA-87 (FIPS 204) |
| ML-DSA-87 pubkey | 2,592 bytes |
| ML-DSA-87 signature | 4,627 bytes |
| ML-DSA-87 weight cost | 8 wu / signature |
| Backup signature | SLH-DSA-SHAKE-256f (inactive at genesis) |
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
| Max chunks per DA set | 4,096 |
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
| 100% (max load) | 7.65 TiB | 18.05 TiB | 451 GiB |
| 30% (planning target) | 2.29 TiB | 5.41 TiB | 135 GiB |

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
| Short ID length | 6 bytes (SipHash-2-4 on WTXID) |
| sendcmpct_mode 0 | Compact disabled, full blocks only |
| sendcmpct_mode 1 | Compact low-bandwidth |
| sendcmpct_mode 2 | Compact high-bandwidth |
| Max high-bandwidth peers | 3 simultaneous |
| Prefetch rate per peer | 4 MB/s |
| Prefetch rate global | 32 MB/s |
| DA orphan TTL | 3 blocks (360 s) |
| DA orphan pool | 64 MiB |
| Max relay message | 96,000,000 bytes (91.6 MiB) |
| Grace period | 1,440 blocks (~2 days) |
| IBD exit condition | Tip timestamp lag < 24 h from system time |

---

## 10. Covenant Types (Genesis Active)

| Code | Name | Description |
|------|------|-------------|
| 0x0000 | CORE_P2PK | Standard pay-to-public-key (ML-DSA-87) |
| 0x0001 | CORE_TIMELOCK_V1 | Height or timestamp lock |
| 0x0002 | CORE_ANCHOR | Non-spendable data anchor |
| 0x0103 | CORE_DA_COMMIT | DA payload commitment (non-spendable) |
| 0x00ff | CORE_RESERVED_FUTURE | Forbidden at genesis |

---

## 11. Document Map

| Document | Scope |
|----------|-------|
| `RUBIN_L1_CANONICAL.md` | Consensus rules: wire format, validation, state transitions |
| `RUBIN_COMPACT_BLOCKS.md` | P2P relay policy: compact blocks, mempool, peer scoring |
| `RUBIN_NETWORK_PARAMS.md` | This file: reference summary for TZ, roadmap, hardware planning |
| `RUBIN_L1_P2P_AUX.md` | Auxiliary P2P rules |
