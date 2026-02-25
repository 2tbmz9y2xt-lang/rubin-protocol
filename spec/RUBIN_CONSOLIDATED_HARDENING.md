# RUBIN — Consolidated Consensus & Relay Hardening

**Status:** NON-CONSENSUS / Engineering Consolidation  
**Scope:** CANONICAL + DA relay + CORE_VAULT (2FA) + HTLC ordering  
**Consensus impact:** none (clarifications, deterministic relay rules, conformance expansion)

This document is an engineering consolidation layer.  
Normative precedence remains:

`RUBIN_L1_CANONICAL.md > RUBIN_COMPACT_BLOCKS.md > RUBIN_NETWORK_PARAMS.md > AUX docs`.

---

## 1. Operational Baseline

RUBIN is designed for server-class validator nodes.

- Minimum: CPU >= 16 physical cores, uplink >= 100 Mbps sustained
- Production recommendation: CPU >= 64 cores, uplink >= 1 Gbps
- Light/mobile devices are not full-validator targets

---

## 2. Relay Timeout Model (locked)

```
timeout_ms = RELAY_TIMEOUT_BASE_MS + (len(DA_Payload) * 1000) / RELAY_TIMEOUT_RATE
```

- `RELAY_TIMEOUT_BASE_MS = 2000`
- `RELAY_TIMEOUT_RATE = 4_000_000 B/s`
- For `MAX_DA_BYTES_PER_BLOCK = 32_000_000`:
  `timeout_ms = 10_000 ms`

This model keeps B/s units consistent across COMPACT and NETWORK_PARAMS.

---

## 3. DA Relay Determinism (consolidated)

The following relay behavior is now explicitly documented in `RUBIN_COMPACT_BLOCKS.md`:

- Monotonic `received_time` (no wall-clock eviction ordering)
- A→B retention: orphan chunks are kept when commit appears; prefetch only missing chunks
- Duplicate commit rule: first-seen commit kept, duplicates dropped + peer penalty
- `total_fee` definition for DA-set eviction:
  `fee(DA_COMMIT_TX) + Σ fee(DA_CHUNK_TX[i])`
- Pinned accounting counts payload bytes only
- Storm-mode commit-bearing classification and priority
- Invariant: orphan chunks may exist without commit, but incomplete sets are never pinned
- Informational alignment for `CHUNK_BYTES=524_288`, `MAX_DA_CHUNK_COUNT=61` (derived from CANONICAL)

---

## 4. CORE_VAULT (2FA) deterministic model

Canonical source: `RUBIN_L1_CANONICAL.md` §14.1, §16, §24.1.

Consolidated invariants:

- At most one `CORE_VAULT` input per transaction
- Every non-vault input must satisfy `lock_id(e) == owner_lock_id`
- `sum_out >= sum_in_vault` for vault spend
- `witness_slots(e) = key_count(e)` for vault
- Sentinel slot is non-participating only (`suite_id=0x00`, zero lengths, no `verify_sig`)
- Keys and whitelist are strictly sorted; duplicates forbidden

Validation order remains the canonical order from §24.1.

---

## 5. HTLC ordering consistency

Canonical source: `RUBIN_CORE_HTLC_SPEC.md` §5 and `RUBIN_L1_CANONICAL.md` §13.

Consolidated checks:

- Structural checks are executed before cryptographic verification
- SLH activation gate (`TX_ERR_SIG_ALG_INVALID`) is evaluated before `verify_sig(...)`
- Claim/refund path behavior remains per canonical HTLC semantics

---

## 6. Quantitative risk envelope (relay)

- Orphan pool bounded by global/per-peer/per-da_id limits and TTL
- Incomplete sets are not pinned
- Pinned payload cap is deterministic and fee/byte eviction is atomic by `da_id`
- Relay stall risk constrained by timeout model and multi-peer prefetch

---

## 7. Conformance expansion set

Required extension IDs from this consolidation:

- Vault: `CV-V-01..CV-V-06`
- DA relay: `CV-C-26..CV-C-31`
- HTLC ordering: `CV-H-Ordering`, `CV-H-Structural-first`

Implementation in this repo is expressed through conformance fixtures and the runner:

- `conformance/fixtures/CV-COMPACT.json`
- `conformance/fixtures/CV-VAULT-POLICY.json`
- `conformance/fixtures/CV-HTLC-ORDERING.json`
- `conformance/runner/run_cv_bundle.py`

---

## 8. Outcome

This consolidation does not alter block-validity rules.  
It tightens deterministic relay behavior, documents already-approved covenant semantics,
and enforces them through explicit conformance coverage.
