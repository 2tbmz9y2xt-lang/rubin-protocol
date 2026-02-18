# RUBIN RETL DA Committee Profile v1.1 (Operational, Non-consensus)

Status: OPERATIONAL (non-consensus)  
Scope: Corporate L2 / RETL data availability (DA) via a semi-trusted committee with SLA.  
Date: 2026-02-17

This document defines a recommended operational profile for ensuring L2 data availability when L1 is used only as a
commitment channel (via `CORE_ANCHOR`). It does not change L1 consensus.

## 0. Summary

- L1 (`CORE_ANCHOR`) publishes only compact commitments (roots/hashes).
- A DA committee provides the actual L2 batch data (calldata) under an SLA, and produces signed availability
  attestations for each RETL batch.
- Attestations are anchored in L1 as a compact commitment so that:
  - auditors can verify which committee attested,
  - clients can require quorum before accepting a batch as "available",
  - availability can be monitored and proven post-facto.

## 1. Roles

- RETL Sequencer:
  - produces RETL batches and publishes L1 commitments (e.g., `state_root`, `tx_data_root`, `withdrawals_root`).
- DA Provider (Committee member):
  - stores the batch data,
  - serves it to clients,
  - signs an availability attestation for the batch.
- Gateway / Exchange / Custodian:
  - enforces policy: only accept batches as "final for operations" after DA quorum is attested.
- Auditor / Monitor:
  - verifies anchored attestations and retrieves data from DA providers to independently reproduce L2 state.

## 2. Trust model and goals

Goals:
- High availability with clear accountability (SLA).
- Auditability: post-facto proof that a quorum of known entities attested availability for a batch.
- Operational simplicity: no L1 consensus upgrade required.

Non-goals:
- Full trust-minimized DA (this is not on-chain DA).
- Preventing all withholding by a colluding committee (mitigate via diversification and governance).

Assumptions:
- Committee membership is governed off-chain (contracts/legal + operational controls).
- A threshold quorum reduces single-operator failure risk.

## 3. Committee membership and keys

Membership:
- Committee is an ordered list `DA_COMMITTEE = [m0, m1, ..., m(n-1)]` published via operator configuration and/or
  a chain-instance operational manifest.

Keys:
- Each member `mi` has a stable `da_pubkey` and `da_key_id = SHA3-256(da_pubkey_wire)`.
- Recommended signature suite for attestations:
  - `SLH-DSA-SHAKE-256f` (aligns with the RETL public sequencer suite; treat as operational, not consensus).

Rotation:
- Key and membership rotation must be versioned (e.g., `committee_epoch`) and announced ahead of time.

## 4. Quorum policy (operational)

Define:
- `N = |DA_COMMITTEE|`
- `Q = quorum_threshold`, recommended `Q = ceil(2N/3)` for strong liveness under faults.

Client policy:
- A corporate gateway SHOULD require at least `Q` valid attestations for `(retl_domain_id, batch_number)` before
  considering the batch "available" for business operations (e.g., crediting deposits, processing withdrawals).

## 5. Data object model (what is "available")

The committee attests availability of a canonical batch data object `DA_OBJECT`:
- `DA_OBJECT` MUST be sufficient to recompute `tx_data_root` deterministically.
- `DA_OBJECT` SHOULD include:
  - L2 transactions payload (calldata),
  - any auxiliary metadata required to parse and replay (format/version, compression flags, chunk ordering),
  - the RETL batch header fields needed for binding (`retl_domain_id`, `batch_number`, `tx_data_root`).

Retrieval:
- The object is addressed by content identifier derived from commitments:
  - `da_object_id = SHA3-256(ASCII(\"RUBINv1-da-object/\") || chain_id || retl_domain_id || u64le(batch_number) || tx_data_root)`

## 6. Availability attestation (signed statement)

Each committee member `mi` MAY publish a signed attestation:

Attestation fields:
- `version: u8 = 1`
- `chain_id: bytes32`
- `committee_epoch: u32le`
- `retl_domain_id: bytes32`
- `batch_number: u64le`
- `tx_data_root: bytes32`
- `da_object_id: bytes32`
- `member_key_id: bytes32` (optional; or derived from `da_pubkey_wire`)

Signing preimage (bytes):

```
ASCII(\"RUBINv1-da-attest/\") ||
u8(1) ||
chain_id ||
u32le(committee_epoch) ||
retl_domain_id ||
u64le(batch_number) ||
tx_data_root ||
da_object_id
```

Signature:
- `da_sig = Sign(da_privkey, preimage)` using the committee's chosen suite.

Verification:
- A verifier MUST check:
  - signature validity,
  - that `da_pubkey` belongs to a member of the active committee for `committee_epoch`,
  - that `da_object_id` matches the derived value for the same `(chain_id, retl_domain_id, batch_number, tx_data_root)`.

## 7. L1 anchoring of attestations (commitment only)

Because `CORE_ANCHOR` is bounded, L1 anchoring should publish a compact commitment to the set of attestations.

Recommended approach:
- Off-chain: collect attestations `{A_i}` from committee members.
- Compute:
  - `attest_set_root = MerkleRoot( SHA3-256(attestation_bytes_i) for each member i in committee index order, using empty leaves for non-signers )`
  - `signer_bitmap` (bitset length N) MAY be published off-chain; on-chain it may be omitted if size constrained.

Anchor envelope (recommended, non-consensus but stable for interoperability):
- `DA_ANCHOR_PREFIX = ASCII(\"RUBINv1-da-attest-set/\")`
- `anchor_data = DA_ANCHOR_PREFIX || u8(1) || retl_domain_id || u64le(batch_number) || tx_data_root || attest_set_root`

Notes:
- This anchors *which* set of attestations existed, not the entire calldata.
- Full attestations and signer details are distributed via DA provider endpoints and audit logs.

## 8. SLA and retention (operational requirements)

Recommended defaults (adjust per corporate contract):
- Retention: minimum 180 days online availability for all `DA_OBJECT`s.
- Serving: at least 2 independent access paths per member (API + bulk download).
- RPO/RTO: define target recovery objectives for storage corruption/outage.

## 9. Failure handling

If quorum is not reached:
- Gateways SHOULD:
  - delay business actions (e.g., withdrawals finalization),
  - alert operators,
  - optionally fall back to a smaller trusted subset (explicitly disclosed policy).

If a member withholds data:
- Record incident and reduce trust score / remove member per governance.

## 10. Security checklist (operational)

1. Committee keys in HSM or equivalent controls (FIPS-aligned where possible).
2. Multi-region storage replication for DA objects.
3. Public audit logs of:
   - committee membership epochs,
   - attestation hashes,
   - outages and incident tickets.
4. Independent monitors verify:
   - L1 anchors exist for expected batches,
   - DA objects can be fetched and `tx_data_root` recomputes correctly.

