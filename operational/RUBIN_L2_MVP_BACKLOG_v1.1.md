# RUBIN L2 MVP Backlog v1.1 (Operational, Non-consensus)

Status: DRAFT (execution plan)  
Scope: Minimum viable L2 stack on top of v1.1 L1: RETL sequencer + DA + indexer + gateway.  
Date: 2026-02-17

This document is a development backlog. It does not change L1 consensus.

## 0. Product split (from strategy)

Public:
- L1: settlement + commitments + **on-chain DA** (RETL `DA_OBJECT` bytes are retrievable from L1 blocks).
- L2: RETL domain + gateway policy.
- Spec: `spec/RUBIN_L2_RETL_ONCHAIN_DA_MVP_v1.1.md` (draft auxiliary).

Corporate:
- L1: settlement + commitments.
- L2: RETL domain + (policy choice):
  - on-chain DA (public auditability), or
  - DA committee (private/corporate deployments; see `operational/RUBIN_RETL_DA_COMMITTEE_PROFILE_v1.1.md`).

## 1. MVP deliverables (what "done" means)

MVP is complete when:
1. A RETL sequencer can produce batch commitments and publish them in a way indexers can track deterministically.
2. DA objects are retrievable and verifiable against `tx_data_root`.
3. An indexer can serve discovery: map `(retl_domain_id, batch_number)` -> commitments + DA locations.
4. A gateway can enforce:
   - public: external DA availability (multi-provider fetch),
   - corporate: DA committee quorum attestations.
5. End-to-end integration tests exist and are reproducible locally.

## 2. Sequencer MVP

Goal: produce RETL batches and publish L1-visible commitments.

Tasks:
1. Define the canonical L2 transaction encoding for the MVP (versioned).
2. Implement batch builder:
   - input: ordered L2 tx list,
   - output: `tx_data_root` + `state_root` + `withdrawals_root` + batch metadata.
3. Implement deterministic `tx_data_root` computation library + test vectors.
4. Implement signing:
   - sign RETL batch commitment preimage as defined in the canonical spec.
5. Publish commitments:
   - provide a stable "batch announcement" channel for indexers (e.g., via `CORE_ANCHOR` commitment envelope, or via a sequencer API whose outputs are anchored by L1 txs).

Outputs:
- `sequencer` binary/service
- test vectors for root computation and signing

## 3. On-chain DA (public) MVP

Goal: publish `DA_OBJECT` bytes on L1 (no external withholding) and make them discoverable and verifiable against `tx_data_root`.

Tasks:
1. Define `DA_OBJECT` container format (versioned):
   - encoding, chunking, DoS caps.
   - Reference: `spec/RUBIN_L2_RETL_ONCHAIN_DA_MVP_v1.1.md` (DA_OBJECT_V1).
2. Define L1 publication mechanism for on-chain DA bytes:
   - block-level DA section or dedicated carrier wire (requires L1 upgrade).
   - Draft carrier spec: `spec/RUBIN_L1_DA_TX_CARRIER_DRAFT_v1.1.md` (DRAFT).
3. Implement sequencer-side publisher:
   - build DA_OBJECT bytes,
   - publish on L1 together with RETL commitments.
4. Implement retrieval + validation:
   - locate matching DA_OBJECT by `(retl_domain_id, batch_number, tx_data_root)`,
   - recompute `tx_data_root`,
   - fail closed if mismatch.

Outputs:
- `da-publisher` module
- `da-client` module
- L1 publication mechanism spec + reference implementation plan

## 3.1 Optional: external mirroring (non-consensus)

Even with on-chain DA, public deployments MAY operate mirrors and discovery endpoints to reduce initial sync burden.
See `operational/RUBIN_PUBLIC_L2_EXTERNAL_DA_PROFILE_v1.1.md` for an external mirroring profile.

## 4. DA committee (corporate) MVP

Goal: committee members attest availability under SLA and commitments are auditable.

Tasks:
1. Define committee configuration model:
   - membership list, epoch, quorum Q.
2. Implement attestation signer:
   - signing preimage `RUBINv1-da-attest/` (per committee profile),
   - store/serve attestations.
3. Implement attestation aggregator:
   - collect signatures,
   - compute `attest_set_root`,
   - publish commitment for audit (prefer anchoring a compact envelope; avoid raw URLs).
4. Implement verifier:
   - verify quorum, membership for epoch, and binding to `(retl_domain_id, batch_number, tx_data_root)`.

Outputs:
- `da-attest-signer` tool/service
- `da-attest-aggregator`
- `da-attest-verifier`

## 5. Indexer MVP (L1 watcher + discovery API)

Goal: one canonical source for clients to find L2 batches and DA locations.

Tasks:
1. L1 watcher:
   - follow headers + blocks,
   - extract RETL batch announcements and relevant `CORE_ANCHOR` envelopes (if used).
2. Storage schema:
   - `domains`, `batches`, `commitments`, `da_locations`, `attestations` (corporate).
3. Discovery API:
   - query by `(retl_domain_id, batch_number)` and ranges,
   - return `tx_data_root`, `withdrawals_root`, and DA info.
4. Integrity checks:
   - periodic job: fetch DA object and verify recomputed roots match commitments.

Outputs:
- `indexer` service + API spec

## 6. Gateway MVP (bridges/settlement policy)

Goal: safe operational policy layer for exchanges/bridges.

Tasks:
1. Define deposit/withdraw flows (MVP scope):
   - what constitutes a deposit event on L1,
   - how withdrawals are authorized from L2 to L1 (proof shape + policy).
2. Public gateway policy:
   - require multi-provider DA retrieval success,
   - require `K_CONFIRM_BRIDGE` confirmations.
3. Corporate gateway policy:
   - require DA committee quorum attestations,
   - require `K_CONFIRM_BRIDGE` confirmations.
4. Observability:
   - alerts for missing DA, attestation failures, root mismatches.

Outputs:
- `gateway` service + policy configuration model

## 7. Integration tests and tooling

Tasks:
1. End-to-end test:
   - produce batch -> publish commitment -> publish DA -> index -> verify root.
2. Corporate E2E:
   - attest quorum -> anchor commitment -> verify gateway acceptance.
3. Failure tests:
   - withheld data, wrong DA object, bad attestation, partial quorum.

Outputs:
- reproducible local scripts + fixtures

## 8. Explicit out-of-scope (for MVP)

1. Trustless rollup correctness (fraud proofs / validity proofs).
2. Full Ethereum bridge with light-client verification.
3. General-purpose VM; MVP can be app-specific.
