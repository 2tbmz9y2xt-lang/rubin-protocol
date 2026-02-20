# RUBIN L2 RETL On-chain DA MVP v1.1 (auxiliary)

Status: DRAFT (NON-CONSENSUS for L1)  
Date: 2026-02-20  
Scope: Proposed RETL/L2 data-availability and transaction-encoding model ("Mode A") for high-throughput L2 UX on top of a safe, slow PoW L1.

This document does **not** change L1 consensus by itself. It defines **RETL/L2-side consensus rules** (what RETL
sequencers/indexers/gateways MUST accept as a valid batch/DA object) and the **wire formats** required for
interoperability and deterministic auditing.

Normative L1 reference points (unchanged by this doc):
- RETL domain identity and `RETLBatch` envelope: `spec/RUBIN_L1_CANONICAL_v1.1.md §7` and
  `operational/RUBIN_RETL_INTEROP_FREEZE_CHECKLIST_v1.1.md §2.2.1`.

---

## 0. Model Summary (Mode A)

This MVP model is intentionally simple:

- L1 is the settlement layer. L1 consensus does not execute L2 semantics.
- L2 batches are published as commitments (`state_root`, `tx_data_root`, `withdrawals_root`) and a batch signature.
- **On-chain DA**: the batch's `DA_OBJECT` bytes are retrievable from L1 blocks (no external DA withholding).
- **No per-L2-tx PQ signatures in DA**: per-transaction user signatures exist, but are *not* carried on-chain in DA.
  (Optional: commit to them via `sig_root` for later audit.)
- A **gateway policy** (operational) decides how withdrawals are authorized from L2 to L1 (bridge semantics).

This is a trust tradeoff: it optimizes throughput and UX for L2 DEX/bridges, not "trustless rollup" correctness.

---

## 1. Target L1 Parameters (Non-normative Planning Profile)

These parameters are **planning targets** for a "safe L1 + DA32" profile. They are not part of CANONICAL v1.1.

- `TARGET_BLOCK_INTERVAL = 900s`
- L1 tx budget (approx): `W_L1 ≈ 36_000_000 wu` (targets ~5 L1 TPS for ~7_900 wu/tx PQ profile)
- On-chain DA budget: `DA_BYTES_PER_BLOCK = 32_000_000 bytes` (32 MB)
- Block weight target: `MAX_BLOCK_WEIGHT ≈ 68_000_000 wu` (order-of-magnitude planning)
  - Assumption: the L1 DA carrier charges DA bytes at ~`1 wu/byte` (witness-like accounting).
    If DA is carried as base bytes (e.g., via output covenant payload bytes), it costs ~`4 wu/byte` and the
    block-weight model must be re-derived.
- To keep bytes and weight consistent, an explicit consensus cap is required:
  - `MAX_BLOCK_BYTES` (recommended planning value: ~72 MiB)
- P2P policy must be compatible with the above:
  - `MAX_RELAY_MSG_BYTES` must be raised above `MAX_BLOCK_BYTES`
  - compact-block relay must exist to keep orphan rate near Bitcoin under realistic peering

---

## 2. Trust Model (Normative for Mode A)

### 2.1 Roles

- **Sequencer**: builds L2 transactions into RETL batches; publishes batch commitments and DA bytes.
- **Indexer**: watches L1 for RETL batch announcements and DA publication; provides discovery APIs.
- **Gateway**: policy component that authorizes withdrawals from L2 to L1 (bridge/settlement policy).
- **User / Verifier**: can independently fetch DA bytes from L1 and audit `tx_data_root` deterministically.

### 2.2 Guarantees and non-guarantees

Guaranteed by on-chain DA (assuming L1 liveness):
- Batch DA bytes are available from L1; a sequencer cannot withhold DA to prevent auditing.
- Anyone can recompute and verify `tx_data_root` for an announced batch.

Not guaranteed in Mode A (by design):
- L1 does not enforce L2 state-transition correctness.
- "Trustless exit" is not provided by L1 in this MVP; withdrawals are authorized by gateway policy.

---

## 3. Commitments and Anchoring

RETL interop anchoring uses a compact `CORE_ANCHOR` envelope for the `RETLBatch` commitment bytes:

- Canonical `anchor_data` envelope: `operational/RUBIN_RETL_INTEROP_FREEZE_CHECKLIST_v1.1.md §2.2.1`.
- `RETLBatchV1Bytes` includes:
  - `state_root`, `tx_data_root`, `withdrawals_root`
  - `sequencer_sig : WitnessItemBytes` (public RETL uses `suite_id=0x02` per the interop checklist)

This doc adds **optional** commitment `sig_root` (see §6) but does not change the v1.1 RETLBatch envelope.

---

## 4. On-chain DA: Publishing Requirement (Normative for Mode A)

For each announced RETL batch `(retl_domain_id, batch_number, tx_data_root, ...)` there MUST exist at least one
`DA_OBJECT` whose header fields match:

- `retl_domain_id`
- `batch_number`
- `tx_data_root`

The mechanism that makes `DA_OBJECT` bytes retrievable from L1 is **out of scope** for this document and must be
defined by an L1 upgrade. Two plausible publication mechanisms exist:

### 4.1 Option A (RECOMMENDED): `tx-carrier` (chunked DA transactions)

Design intent:

- Make on-chain DA compatible with compact block relay (§1) by ensuring the heavy DA bytes are relayed and present in
  peer mempools **before** a block is mined.

Operationally:

1. Sequencer builds `DAObjectV1Bytes` (this spec) and publishes it to the L1 network as one or more **DA carrier
   transactions** ("DA-txs").
2. DA-txs are relayed over P2P (entering peer mempools).
3. When a miner finds a block, the block can be reconstructed quickly from mempools using compact blocks, because the
   DA-txs are already present locally on receivers.

Commitment requirements:

- L1 consensus MUST commit to the DA bytes in the block. If the DA bytes are not directly committed by `txid` /
  `merkle_root` (e.g., if carried in a prunable field), the carrier format MUST include an explicit commitment
  (e.g., `SHA3-256(da_bytes)` stored in consensus-committed bytes) and L1 validation MUST reject mismatches.

Pruning note (non-consensus):

- "On-chain DA" means the bytes are in L1 blocks at inclusion time. Node-local pruning does not change the chain, but
  it reduces long-term retrievability unless sufficient archival infrastructure exists.
- Gateways/watchtowers SHOULD archive DA bytes for at least the maximum withdrawal finalization horizon of the domain.

This document assumes Option A for the `DA_BYTES_PER_BLOCK = 32 MB` planning profile because it minimizes stale/orphan
pressure when combined with compact-block relay.

### 4.2 Option B: block-level DA section (`DASection`)

Design intent:

- Attach DA bytes to the block as a separate section not represented as transactions.

Tradeoff:

- Compact blocks do not help if the receiver cannot reconstruct the DA section from its mempool. In that case the
  miner must transmit the full DA section (e.g., 32 MB) in real time after mining, increasing propagation delay and
  stale/orphan rates.

If a block-level DA section is used, the P2P layer likely needs a dedicated "DA chunk inventory" protocol to pre-gossip
DA bytes, which makes it operationally closer to Option A but with additional protocol complexity.

RETL indexers and gateways MUST treat an announced batch as "DA missing" until a matching `DA_OBJECT` is found and
validated per §7.

---

## 5. `DA_OBJECT` Wire Format (DA_OBJECT_V1) (Normative)

All integer fields are little-endian.

### 5.1 Constants (Normative)

These caps are RETL/L2 consensus caps (indexers/gateways MUST enforce them).

- `MAX_DA_OBJECT_BYTES = 32_000_000`
- `MAX_ADDR_TABLE_LEN = 4_096`
- `MAX_TOKEN_TABLE_LEN = 1_024`
- `MAX_L2_TX_COUNT = 1_000_000`
- `MAX_DA_CHUNK_COUNT = 1_024`
- `MAX_DA_CHUNK_BYTES = 1_048_576`  (1 MiB)

Compression:
- In DA_OBJECT_V1 MVP, `compressed` is forbidden (`flags.compressed MUST be 0`).

### 5.2 Header

`DAObjectV1Bytes`:

```
magic            : bytes8    = ASCII("RUBINDA1") || 0x00
version          : u8        = 1
flags            : u8        (bit 0 = has_sig_root, bit 1 = compressed; bits 2..7 MUST be 0)
retl_domain_id   : bytes32
batch_number     : u64le
state_root       : bytes32
tx_data_root     : bytes32
withdrawals_root : bytes32
sig_root         : bytes32   (present iff flags.has_sig_root = 1)
addr_table_len   : u16le
token_table_len  : u16le
tx_count         : u32le
chunk_count      : u16le
addr_table       : bytes32[addr_table_len]
token_table      : bytes32[token_table_len]
chunk_table      : ChunkDesc[chunk_count]
chunk_payload    : bytes[ sum(chunk_len) ]
```

`ChunkDesc`:

```
chunk_len  : u32le
chunk_hash : bytes32   = SHA3-256(chunk_bytes)
```

### 5.3 `tx_data_root` definition (Normative)

Let `chunk_hashes` be the `chunk_hash` values in `chunk_table` order.

Define the Merkle tree as:

```
Leaf = SHA3-256(0x00 || u32le(chunk_len) || chunk_hash)
Node = SHA3-256(0x01 || left || right)
```

If a level has an odd number of nodes, the final node is promoted to the next level unchanged.
Duplicating the last element is forbidden.

Then:

```
tx_data_root = MerkleRoot( Leaf_i for each chunk i )
```

---

## 6. `sig_root` (Optional Commitment to Per-Tx Signatures) (Normative If Present)

Mode A does not require per-transaction signatures to be published on-chain as DA bytes. However, for auditability
and dispute handling, implementations MAY commit to an ordered set of per-tx signatures via `sig_root`.

If `flags.has_sig_root = 1` then:

- The DA object commits to a signature record for each L2 transaction in the batch, in the same order as the L2 tx list.
- `sig_root` MUST be computed as a Merkle root over signature commitments:

Define:

```
SigEntryBytes = WitnessItemBytes (as in CANONICAL v1.1 §11, minimally-encoded CompactSize lengths)
SigCommit     = SHA3-256(SigEntryBytes)

Leaf = SHA3-256(0x02 || SigCommit)
Node = SHA3-256(0x03 || left || right)
```

Odd-leaf promotion rules are the same as §5.3.

Notes:
- `SigEntryBytes` is a wire format definition. Where signatures are stored/served is an operational choice.
- A gateway policy MAY require signature availability for certain operations (e.g., withdrawals) even in Mode A.

---

## 7. DA_OBJECT Validation Algorithm (Normative)

Given candidate `DAObjectV1Bytes`:

1. Parse header and tables with checked arithmetic.
2. Enforce:
   - `magic` matches exactly.
   - `version = 1`.
   - `flags.compressed = 0`.
   - reserved flag bits 2..7 are `0`.
3. Enforce caps:
   - total byte length `<= MAX_DA_OBJECT_BYTES`.
   - `addr_table_len <= MAX_ADDR_TABLE_LEN`.
   - `token_table_len <= MAX_TOKEN_TABLE_LEN`.
   - `tx_count <= MAX_L2_TX_COUNT`.
   - `1 <= chunk_count <= MAX_DA_CHUNK_COUNT`.
4. Parse `chunk_table`:
   - each `chunk_len` MUST satisfy `0 < chunk_len <= MAX_DA_CHUNK_BYTES`.
   - `sum(chunk_len)` MUST equal the length of the remaining `chunk_payload` bytes (exact match).
5. For each chunk `i` in order:
   - compute `SHA3-256(chunk_bytes)` and verify it equals `chunk_hash`.
6. Recompute `tx_data_root` per §5.3 and verify it equals the header `tx_data_root`.
7. If `flags.has_sig_root = 1`, the `sig_root` field is syntactically present (32 bytes). Its semantic verification
   depends on signature availability (operational), but the root value is treated as consensus-visible commitment.

If any check fails, the DA object is invalid for RETL; indexers/gateways MUST NOT accept it as satisfying on-chain DA.

---

## 8. L2 Transaction Encoding (Constrained Ops, Dictionary Encoding) (Normative)

### 8.1 Address and token references

- `addr_table` entries are 32-byte identifiers (e.g., `key_id`-derived or L2 account ids).
- `token_table` entries are 32-byte identifiers (token ids).

Any tx referencing an index `>= table_len` is invalid.

### 8.2 L2Tx wire (MVP)

All variable-length integers use L1 `CompactSize` encoding rules (minimally encoded).

`L2TxBytes`:

```
op          : u8
from_idx    : CompactSize
nonce_delta : CompactSize
... op-specific fields ...
```

Opcode set (MVP):

- `0x01 TRANSFER`
- `0x02 SWAP` (app-specific pool model; see below)
- `0x03 WITHDRAW_REQUEST`

#### 8.2.1 `TRANSFER`

```
to_idx    : CompactSize
token_idx : CompactSize
amount    : CompactSize
max_fee   : CompactSize
```

#### 8.2.2 `SWAP` (MVP placeholder)

MVP `SWAP` encoding is app-specific. For generic interop, define:

```
pool_id        : CompactSize
token_in_idx   : CompactSize
token_out_idx  : CompactSize
amount_in      : CompactSize
min_amount_out : CompactSize
max_fee        : CompactSize
```

#### 8.2.3 `WITHDRAW_REQUEST`

```
l1_dest_key_id : bytes32
token_idx      : CompactSize
amount         : CompactSize
max_fee        : CompactSize
```

### 8.3 Tx stream and count binding

Let `TxStreamBytes` be the concatenation of `tx_count` transactions:

```
TxStreamBytes = concat( L2TxBytes(tx_i) for i in [0..tx_count-1] )
```

In DA_OBJECT_V1, the `chunk_payload` bytes MUST be exactly `TxStreamBytes` (no trailing bytes).

---

## 9. Notes for Roadmap / Implementation

To operationalize this model, the following must exist:

- A concrete L1 mechanism to carry `DA_OBJECT` bytes on-chain (block/tx wire upgrade).
- P2P compact-block relay to keep orphan rate low at higher block bytes.
- A gateway policy spec (what proofs/inputs authorize L2->L1 withdrawals in Mode A).
