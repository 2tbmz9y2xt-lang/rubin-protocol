# RUBIN Public L2 External DA Profile v1.1 (Operational, Non-consensus)

Status: OPERATIONAL (non-consensus)  
Scope: Public L2 / RETL data availability (DA) via external DA providers + open retrieval.  
Date: 2026-02-17

This document defines a recommended operational profile for public L2 deployments where L1 is used only as a compact
commitment channel (via `CORE_ANCHOR`). It does not change L1 consensus.

## 0. Summary

- L1 publishes only commitments (roots/hashes) for RETL batches.
- Full L2 calldata is stored and distributed via an external DA network (one or more providers + replication).
- Anyone can fetch DA objects and recompute `tx_data_root` to audit and verify L2 state transitions.
- Availability is provided by market/infrastructure redundancy, not by L1 on-chain DA.

## 1. Goals and non-goals

Goals:
1. Public verifiability: any observer can retrieve data and validate commitments.
2. Minimal L1 footprint: keep L1 as settlement + commitment layer.
3. Composability: enable DEX/bridges/rollup-like execution without requiring L1 consensus upgrades.

Non-goals:
1. Guaranteed availability purely from L1.
2. "Free" DA without cost: storage and bandwidth must be paid for by L2 economics.

## 2. Roles

- RETL Sequencer:
  - produces RETL batches and publishes L1 commitments (`state_root`, `tx_data_root`, `withdrawals_root`).
- External DA Provider:
  - stores batch data objects and serves them over open endpoints.
- Replicator / Mirror:
  - independently mirrors DA objects to reduce censorship and outages.
- Indexer:
  - watches L1 commitments and provides discovery of DA object locations.
- User / Verifier:
  - fetches DA objects and verifies that `tx_data_root` recomputes correctly.

## 3. What must be on L1 (commitments)

At minimum, public L2 operation requires that L1 commitments exist for each batch:
- `retl_domain_id`
- `batch_number`
- `state_root`
- `tx_data_root`
- `withdrawals_root`

These commitments may be included in RETL batch fields and/or anchored as compact envelopes via `CORE_ANCHOR` for
interoperable indexing (see `operational/RUBIN_RETL_INTEROP_FREEZE_CHECKLIST_v1.1.md`).

## 4. Data object model (external DA)

External DA stores a canonical object `DA_OBJECT` per batch.

Requirements:
1. `DA_OBJECT` MUST be sufficient to deterministically recompute `tx_data_root`.
2. `DA_OBJECT` SHOULD include:
   - L2 transaction payload (calldata),
   - deterministic encoding/version fields,
   - chunking/compression metadata,
   - replay metadata needed by verifiers (if any).

Content addressing:
- `da_object_id = SHA3-256(ASCII(\"RUBINv1-da-object/\") || chain_id || retl_domain_id || u64le(batch_number) || tx_data_root)`

The DA provider MUST serve `DA_OBJECT` by `da_object_id`.

## 5. Discovery (how users find DA objects)

Public discovery should be multi-path:
1. Indexer APIs (recommended):
   - map `(retl_domain_id, batch_number)` -> `(tx_data_root, da_object_id, urls[])`.
2. DA provider registries:
   - public list of provider base URLs for a domain/epoch.
3. Optional L1 anchoring of pointers (bounded):
   - if you must anchor a pointer, anchor a compact hash of a pointer-list manifest rather than raw URLs.

Avoid anchoring raw URLs in L1 unless necessary; prefer off-chain discovery plus anchoring only immutable commitments.

## 6. Retrieval protocol expectations (operational)

Minimum:
- HTTP(S) GET by `da_object_id`:
  - `GET /da/v1/{chain_id}/{retl_domain_id}/{batch_number}/{da_object_id}`
  - or equivalent stable path.

Recommended:
- Bulk snapshot endpoints by range of batches.
- Content-type and encoding headers (compression).

## 7. Availability targets and economics

Public L2 should plan for redundancy:
- Minimum replication: at least 3 independent DA providers/mirrors per domain.
- Retention window: recommended >= 30 days for hot availability, >= 180 days for archival (mirrors).

Economics:
- L2 fee schedule SHOULD fund DA storage + bandwidth.
- Operators SHOULD publish cost model and retention guarantees.

## 8. Failure modes and user safety

If data is withheld:
- Verifiers cannot recompute state; L2 should halt or degrade depending on product policy.
- Bridges/gateways MUST define what happens if DA becomes unavailable (freeze withdrawals, pause finality, etc.).

Mitigations:
- multi-provider replication and automatic mirroring,
- open-source retrieval clients,
- community-run mirrors and archival programs.

## 9. Security checklist (operational)

1. Deterministic encoding library and test vectors for `tx_data_root` computation.
2. Multi-provider mirroring with continuous audit checks:
   - monitor fetch success per provider,
   - verify recomputed roots match L1 commitments.
3. Domain config changes (provider lists, formats) must be versioned and announced.

