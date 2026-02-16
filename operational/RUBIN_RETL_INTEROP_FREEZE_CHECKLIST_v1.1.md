# RUBIN RETL Interop Freeze Checklist v1.1

Status: NON-CONSENSUS (application-layer interoperability)  
Scope: RETL domain builders, indexers, relayers, and tooling

This checklist defines what must be standardized for RETL to be interoperable across independent implementations.
It does not change L1 consensus rules: L1 treats `CORE_ANCHOR` payload bytes as opaque.

## 1. Interop freeze goal

RETL is "interop-freeze-ready" when two independent RETL implementations (plus two independent indexers) can:

1. Compute identical `retl_domain_id` for the same domain descriptor.
2. Parse identical `RETLBatch` objects from identical `anchor_data` bytes.
3. Produce/verify identical sequencer signatures over the standardized signing preimage.
4. Produce identical batch hashes / roots / canonical digests used by downstream tooling.

## 2. Required specifications (P0 for RETL interop)

### 2.1 Domain descriptor (`descriptor_bytes`) canonicalization

Frozen in CANONICAL v1.1:

- `descriptor_bytes` is defined byte-for-byte in `spec/RUBIN_L1_CANONICAL_v1.1.md §7.0.1`.
- `retl_domain_id = SHA3-256("RUBINv1-retl-domain/" || chain_id || descriptor_bytes)` is defined in `spec/RUBIN_L1_CANONICAL_v1.1.md §7`.

Interop freeze requirement:

- Two independent implementations MUST compute identical `descriptor_bytes` and identical `retl_domain_id` for the same descriptor object.

Acceptance criteria:

- Given the same domain descriptor object, all implementations produce identical `descriptor_bytes` and identical `retl_domain_id`.

### 2.2 `RETLBatch` wire format (byte-level)

Frozen (field types + signing serialization) in CANONICAL v1.1:

- `RETLBatch` field types and signing serialization are specified in `spec/RUBIN_L1_CANONICAL_v1.1.md §7.0.2` (application-layer interoperability).

Interop freeze requirement:

- The RETL ecosystem MUST use a single canonical `anchor_data` envelope for RETLBatch v1.1 payload bytes.

#### 2.2.1 `anchor_data` envelope v1.1 (Canonical for RETL interop)

`anchor_data` bytes for RETL v1.1 MUST be:

```
anchor_data =
  ASCII("RUBIN-RETL-v1") ||
  chain_id ||
  RETLBatchV1Bytes
```

where `RETLBatchV1Bytes` is:

```
RETLBatchV1Bytes =
  retl_domain_id     : bytes32 ||
  batch_number       : u64le   ||
  prev_batch_hash    : bytes32 ||
  state_root         : bytes32 ||
  tx_data_root       : bytes32 ||
  withdrawals_root   : bytes32 ||
  sequencer_sig      : WitnessItemBytes
```

and `WitnessItemBytes` is the canonical L1 witness item encoding (as in CANONICAL v1.1):

```
WitnessItemBytes =
  suite_id      : u8 ||
  pubkey_length : CompactSize (MUST be minimally encoded) ||
  pubkey        : bytes[pubkey_length] ||
  sig_length    : CompactSize (MUST be minimally encoded) ||
  signature     : bytes[sig_length]
```

Constraints for interop:

- `suite_id` MUST be `0x02` (SLH-DSA-SHAKE-256f) for public RETL domains.
- `pubkey_length` MUST equal 64.
- `sig_length` MUST satisfy `0 < sig_length ≤ MAX_SLH_DSA_SIG_BYTES` (from CANONICAL v1.1) and verify under SLH-DSA.
- Any non-minimal CompactSize encoding inside the RETL envelope MUST be rejected by RETL parsers.

Acceptance criteria:

- Two independent parsers accept the same `anchor_data` and produce identical decoded `RETLBatch` fields.

### 2.3 Sequencer signing preimage canonicalization

Define and freeze:

- signing domain tag (ASCII literal) and exact concatenation order
- per-field serialization table (byte lengths, endianness)

Acceptance criteria:

- Two implementations compute identical signing preimages and verify each other's signatures.

### 2.4 Hash/commitment registry for RETL semantics

Define and freeze:

- what each root commits to (e.g., `state_root` = root of a specific Merkle tree definition)
- exact leaf/internal hashing rules (domain separation tags, odd-leaf handling, canonical sorting rules)
- how batch hashes are derived (if needed), including domain tags

Acceptance criteria:

- Independent indexers compute identical roots and batch digests from identical off-chain data.

## 3. Optional but recommended specifications (P1 for RETL interop)

### 3.1 Key rotation / domain upgrade rules

Define and freeze:

- how a domain changes the sequencer key
- how upgrades are announced/anchored
- how indexers determine the active key set

### 3.2 Availability and replay policy

Define and freeze:

- how RETL data availability is provided (external DA, P2P, or explicit endpoints)
- how reorgs affect RETL batch numbering and indexer reconciliation

## 4. Test vectors and conformance

Before declaring interop freeze:

1. Publish at least 5 canonical `anchor_data` hex fixtures:
   - minimal valid batch
   - invalid magic/version
   - invalid length / overflow
   - invalid signature
   - batch_number discontinuity case (indexer behavior)
2. Publish expected parse results and signature verification outcomes.
3. Require cross-implementation reproduction of:
   - `retl_domain_id`
   - parsed fields
   - signing preimage hash
   - signature verification result

### 4.1 Fixture location (repo)

The canonical fixture pack for RETL interop is published under:

- `conformance/fixtures/retl/`

## 5. Governance note

Because this file is non-consensus, it can evolve without a chain upgrade. However, once applications rely on a particular
RETL encoding, changes SHOULD be versioned and published with a new explicit RETL version tag and fixtures.
