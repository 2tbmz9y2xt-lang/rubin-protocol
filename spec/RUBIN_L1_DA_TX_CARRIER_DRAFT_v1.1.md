# RUBIN L1 DA Tx-Carrier via Transaction Wire v2 (Draft) v1.1 (auxiliary)

Status: DRAFT (NON-CANONICAL)  
Date: 2026-02-20  
Scope: Proposed L1 transaction-wire v2 changes to carry large L2 DA bytes on-chain while remaining compatible with
compact block relay (mempool-first propagation).

This document is a **draft**. It does **not** change `spec/RUBIN_L1_CANONICAL_v1.1.md` by itself. Any adoption
requires an explicit L1 network upgrade plan (new canonical revision and/or chain-instance activation schedule).

Related:
- L2 DA model and `DA_OBJECT_V1` manifest format: `spec/RUBIN_L2_RETL_ONCHAIN_DA_MVP_v1.1.md` (Option A).
- P2P compact blocks (mempool-first reconstruction): `spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md` (compact blocks draft).

---

## 0. Design intent (why tx-carrier)

If DA bytes are published only as a block-level payload (`DASection`), compact blocks do not help propagation because
peers do not have the DA bytes in mempools before the block is found. Miners must transmit the full DA bytes in real
time, increasing propagation delay and stale/orphan rate.

Tx-carrier solves this by making DA bytes travel as mempool-relayed transactions:

1. Sequencer publishes a small manifest transaction (`DA_COMMIT_TX`) plus many chunk transactions (`DA_CHUNK_TX`).
2. Peers download these transactions into mempool **before** block mining.
3. When the block is found, compact blocks can reference the DA transactions by shortid derived from `wtxid`, so the
   receiver reconstructs quickly from mempool.

---

## 1. Scope boundary: consensus vs policy

This draft separates:

Consensus (validity):
- the transaction wire v2 structure,
- binding of DA payload bytes to consensus-committed fields,
- per-tx and per-block hard caps.

Policy (relay/mempool/L2 logic):
- any "window" such as `H..H+K` for accepting late chunks,
- retention/pruning horizons,
- separate DA mempool sizing and eviction rules.

In particular, a chunk-acceptance window `H..H+K` is **policy-only**: it MUST NOT make blocks retrospectively invalid.

---

## 2. Draft: Transaction Wire v2 (L1 upgrade)

### 2.0 Activation semantics (draft)

This draft assumes an explicit activation height `H_activation` published in the chain-instance profile for the
upgraded network instance.

Wire versions:
- Wire v1 (CANONICAL v1.1): `T.version = 1` and the transaction wire format is exactly `TxBytes(T)` as defined in
  `spec/RUBIN_L1_CANONICAL_v1.1.md` (no `tx_kind`, no `da_payload`).
- Wire v2 (this draft): `T.version = 2` and the wire format is as defined in §2.1 (includes `tx_kind` and `da_payload`).

Validity rules:

1. If `height(B) < H_activation` then any transaction with `T.version = 2` MUST cause `B` to be rejected as invalid.
2. If `height(B) ≥ H_activation` then:
   - Any DA transaction (`tx_kind in {0x01, 0x02}`) MUST use wire v2 (`T.version = 2`).
   - Standard transactions MAY be encoded as either wire v1 (`T.version = 1`) or wire v2 (`T.version = 2` with
     `tx_kind = 0x00`), subject to local policy and wallet conventions.

Notes:
- Wire v1 nodes are not full validators after activation. They may remain header-only peers if the P2P layer supports it.

### 2.1 Wire structure

This draft extends the transaction bytes with a `tx_kind` discriminator, optional DA core fields, and an optional
DA payload blob.

```
version            : u32le
tx_kind            : u8                  # 0x00=standard, 0x01=DA_COMMIT, 0x02=DA_CHUNK
tx_nonce           : u64le
inputs             : CompactSize + Input[]
outputs            : CompactSize + Output[]
locktime           : u32le
da_core_fields     : bytes[...]          # present iff tx_kind in {0x01, 0x02}
witness_section    : WitnessSectionBytes # as in CANONICAL v1.1
da_payload_len     : CompactSize
da_payload         : bytes[da_payload_len]
```

Constraints:
- For `tx_kind = 0x00`, `da_payload_len` MUST be `0` and `da_core_fields` MUST be empty.
- For `tx_kind in {0x01, 0x02}`, `da_payload_len` MUST be `> 0` and `da_core_fields` MUST be present.
- `MAX_WITNESS_BYTES_PER_TX` continues to apply only to the witness section (not to `da_payload`).

### 2.2 Identifiers (`txid` vs `wtxid`)

To support pruning of `da_payload` without changing consensus commitments:

- `txid` MUST NOT commit to `da_payload` bytes.
- `wtxid` MUST commit to the full wire bytes (including witness and `da_payload`) for mempool matching and compact relay.

Define:

```
TxCoreBytes(T) = all fields of the wire encoding up to and including witness_section,
                 excluding da_payload_len and da_payload
```

Then:

```
txid  = SHA3-256(TxCoreBytes(T))
wtxid = SHA3-256(TxBytesV2(T))   # full bytes including witness + da_payload
```

Interop note:
- After activation, P2P inventory and compact blocks MUST use `wtxid` for DA-capable nodes (shortid derived from `wtxid`).

### 2.3 Sighash scope (draft)

DA payload bytes SHOULD NOT be covered by signature hashes to avoid signing bulk data.

Draft rule:
- all signature-hash constructions MUST commit to `TxCoreBytes(T)` only (not to `da_payload` bytes).

---

## 3. Draft: DA transaction kinds

### 3.1 `DA_COMMIT_TX` (`tx_kind = 0x01`)

`da_core_fields` encoding:

```
da_id              : bytes32  # derived identifier (see below)
chunk_count        : u16le
retl_domain_id     : bytes32
batch_number       : u64le
tx_data_root       : bytes32
state_root         : bytes32
withdrawals_root   : bytes32
batch_sig_suite    : u8       # 0x01=ML-DSA-87, 0x02=SLH-DSA
batch_sig_len      : CompactSize
batch_sig          : bytes[batch_sig_len]
```

Payload:
- `da_payload` MUST be a valid `DA_OBJECT_V1` manifest bytes (see `spec/RUBIN_L2_RETL_ONCHAIN_DA_MVP_v1.1.md`).

Derived identifier:

```
da_id = SHA3-256( ASCII("RUBIN_DA_ID") || da_payload )
```

Consensus binding rules (draft):
- The `DA_OBJECT_V1` header fields MUST match the corresponding `da_core_fields`:
  - `retl_domain_id`, `batch_number`, `tx_data_root`, `state_root`, `withdrawals_root`, `chunk_count`.
- `tx_data_root` MUST equal the Merkle root over the manifest's chunk table (per `DA_OBJECT_V1` definition).

### 3.2 `DA_CHUNK_TX` (`tx_kind = 0x02`)

`da_core_fields` encoding:

```
da_id        : bytes32
chunk_index  : u16le
chunk_hash   : bytes32    # SHA3-256(da_payload)
```

Consensus binding rules (draft):
- `chunk_hash` MUST equal `SHA3-256(da_payload)`.

Note:
- Any additional "only accept chunk if commit seen within K blocks" rule is **policy-only** (not consensus).

---

## 4. Draft covenant type: `CORE_DA_COMMIT` (deployment-gated)

This draft uses a deployment-gated covenant output as an explicit consensus commitment to the DA payload hash in the
transaction outputs.

Registry (draft):
- `0x0103` `CORE_DA_COMMIT` (deployment-gated; activation via VERSION_BITS-like schedule)

Output rules (draft):
- `value` MUST be exactly `0`.
- Output MUST be non-spendable and MUST NOT be added to the spendable UTXO set.
- Any transaction attempting to spend such an output MUST be rejected as `TX_ERR_MISSING_UTXO`.

Encoding (draft):
- `covenant_data_len` MUST be exactly `32`.
- `covenant_data` MUST equal `SHA3-256(da_payload)` of the same transaction.

Placement rules (draft):
- A `DA_COMMIT_TX` MUST contain exactly one `CORE_DA_COMMIT` output.
- A `DA_CHUNK_TX` MAY omit `CORE_DA_COMMIT` (it already commits `chunk_hash` in core fields).

Deployment gating (draft):
- Before the deployment is ACTIVE, any transaction that uses `tx_kind in {0x01, 0x02}` or includes a
  `CORE_DA_COMMIT` output MUST be rejected as `TX_ERR_DEPLOYMENT_INACTIVE`.

---

## 5. Hard caps (draft consensus)

Per-transaction caps:
- `MAX_DA_MANIFEST_BYTES_PER_TX = 65_536` (64 KiB): applies to `DA_COMMIT_TX da_payload_len`.
- `MAX_DA_CHUNK_BYTES_PER_TX = 524_288` (512 KiB): applies to `DA_CHUNK_TX da_payload_len`.

Per-block caps:
- `MAX_DA_BYTES_PER_BLOCK = 32_000_000` (DA32 planning profile)
- `MAX_DA_COMMITS_PER_BLOCK = 128`

Rules (draft):
- For a block `B`:
  - `Σ da_payload_len` over all DA transactions in `B` MUST be ≤ `MAX_DA_BYTES_PER_BLOCK`.
  - `count(DA_COMMIT_TX in B)` MUST be ≤ `MAX_DA_COMMITS_PER_BLOCK`.
- For each DA transaction `T`:
  - If `T` is `DA_COMMIT_TX`, then `da_payload_len(T) MUST be ≤ MAX_DA_MANIFEST_BYTES_PER_TX`.
  - If `T` is `DA_CHUNK_TX`, then `da_payload_len(T) MUST be ≤ MAX_DA_CHUNK_BYTES_PER_TX`.

Duplicate control (draft):
- Within a single block, duplicate `(da_id, chunk_index)` pairs across `DA_CHUNK_TX` MUST be rejected as invalid.

Chunk-index semantics:
- `chunk_index < chunk_count` is enforced by L2/policy logic using the referenced commit's manifest.
- L1 consensus MUST remain stateless across blocks; therefore, L1 consensus validity MUST NOT depend on discovering
  the referenced commit outside the current block.

---

## 6. Weight accounting (draft)

To preserve the planning model where DA bytes cost ~`1 wu/byte`, treat DA payload bytes as witness-like bytes:

```
base_size = |TxCoreBytes(T)| without witness and without da_payload
wit_size  = |WitnessSectionBytes(T.witness)|
da_size   = da_payload_len
sig_cost  = (as in CANONICAL v1.1)

weight(T) = 4 * base_size + wit_size + da_size + sig_cost
```

Note:
- This is a consensus change if introduced. Until then it is a planning target.

---

## 7. Conformance (planned)

If adopted, this draft should be covered by a new conformance gate (e.g., `CV-DA-WIRE2`) with minimum vectors:

- reject: `tx_kind=0x00` but `da_payload_len>0`
- reject: `DA_COMMIT_TX` missing `CORE_DA_COMMIT`
- reject: `CORE_DA_COMMIT.covenant_data != SHA3(da_payload)`
- reject: `DA_CHUNK_TX.chunk_hash != SHA3(da_payload)`
- reject: per-tx DA cap exceeded (manifest/chunk)
- reject: per-block DA cap exceeded
- reject: duplicate `(da_id, chunk_index)` within a block
