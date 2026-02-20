# RUBIN L1 DA Tx-Carrier (Draft) v1.1 (auxiliary)

Status: DRAFT (NON-CANONICAL)  
Date: 2026-02-20  
Scope: Proposed L1 wire + covenant extensions to carry large L2 DA bytes on-chain while remaining compatible with compact block relay.

This document is a **draft**. It describes a concrete path to implement "Mode A + 32MB on-chain DA" from
`spec/RUBIN_L2_RETL_ONCHAIN_DA_MVP_v1.1.md` without relying on a block-level DA section.

It **does not** change `spec/RUBIN_L1_CANONICAL_v1.1.md` by itself. Any adoption requires a new canonical revision
or an explicit network upgrade plan.

---

## 0. Why tx-carrier (design intent)

If DA bytes are only available as a block-level payload (a `DASection` attached to the block), compact blocks do not
help propagation: peers do not have the DA bytes in their mempools prior to block mining, so miners must transmit
full DA bytes in real time, increasing propagation delay and stale/orphan rate.

Tx-carrier solves this by making DA bytes travel as mempool-relayed transactions:

1. Sequencer publishes DA chunk transactions.
2. Peers download them into mempool **before** the block is found.
3. When the block is found, compact blocks can reference the DA txs by shortid (wtxid), so receivers reconstruct
   quickly from mempool.

---

## 1. Draft wire extension: `TxBytes` carries an optional `data_section`

This draft introduces an additional prunable data section at the end of `TxBytes`.

### 1.1 Extended transaction bytes

Define:

```
DataSectionBytes =
  CompactSize(data_len) ||
  data_bytes[data_len]
```

Then redefine:

```
TxBytes(T) = TxNoWitnessBytes(T) || WitnessBytes(T.witness) || DataSectionBytes(T.data)
```

Notes:

- For ordinary L1 transactions, `data_len = 0`.
- `data_bytes` are not part of `txid` (see §1.2), and SHOULD NOT be part of `sighash` (to avoid signing bulk bytes).
- The `MAX_WITNESS_BYTES_PER_TX` limit from CANONICAL v1.1 is unchanged and continues to apply only to the witness section.

### 1.2 Hash identifiers

Consensus `txid` remains unchanged (CANONICAL v1.1):

```
txid = SHA3-256(TxNoWitnessBytes(T))
```

Network `wtxid` (for compact blocks / mempool inventory) MUST include `data_section`:

```
wtxid = SHA3-256(TxBytes(T))
```

Rationale:

- compact blocks and mempool matching must uniquely identify the full transaction bytes required to validate DA chunks.

---

## 2. Draft covenant type: `CORE_DA_CHUNK_V1`

This draft introduces a new covenant type used only as a non-spendable DA carrier output.

### 2.1 Registry entry (draft)

Add to the covenant registry (future canonical revision):

- `0x0200` `CORE_DA_CHUNK_V1`

### 2.2 Output rules (draft)

For `CORE_DA_CHUNK_V1` outputs:

- `value` MUST be exactly `0`.
- The output is **non-spendable** and MUST NOT be added to the spendable UTXO set.
- Any transaction attempting to spend a `CORE_DA_CHUNK_V1` output MUST be rejected as `TX_ERR_MISSING_UTXO`.

### 2.3 Covenant data encoding (draft)

```
covenant_data =
  da_object_id : bytes32 ||
  chunk_index  : u32le   ||
  chunk_len    : u32le   ||
  chunk_hash   : bytes32
```

Where:

- `chunk_hash = SHA3-256(chunk_bytes)` over the corresponding bytes in the transaction `data_section`.

Encoding constraints:

- `covenant_data_len` MUST be exactly `32 + 4 + 4 + 32 = 72`.

### 2.4 Binding `data_section` to DA outputs (draft consensus rule)

Let `DAOutputs(T)` be the list of outputs in `T` whose `covenant_type = CORE_DA_CHUNK_V1`, in output order.

Rules:

- A transaction with `|DAOutputs(T)| = 0` MUST have `data_len = 0`.
- A transaction with `|DAOutputs(T)| > 0` MUST:
  - have `data_len > 0`,
  - have `|DAOutputs(T)| = 1` (one chunk per transaction, in v1),
  - satisfy `data_len == chunk_len`,
  - satisfy `SHA3-256(data_bytes) == chunk_hash`.

Rationale:

- one-chunk-per-tx simplifies mempool, compact-block reconstruction, and DoS caps.

---

## 3. Per-block DA caps (draft consensus rule)

Define a per-block cap for total DA bytes:

- `MAX_DA_BYTES_PER_BLOCK = 32_000_000` (planning profile for DA32)

Rule:

For a block `B`, let:

```
da_bytes(B) = Σ chunk_len over all CORE_DA_CHUNK_V1 outputs in all txs of B
```

Then:

- `da_bytes(B) MUST be ≤ MAX_DA_BYTES_PER_BLOCK`.

Nodes MUST also enforce a per-tx cap (DoS hardening):

- `MAX_DA_BYTES_PER_TX = 1_048_576` (1 MiB)

Rule:

- for any tx with a DA output, `data_len MUST be ≤ MAX_DA_BYTES_PER_TX`.

---

## 4. Weight accounting (draft)

To preserve the planning model where DA bytes cost ~`1 wu/byte`, the weight formula must treat `data_section` bytes
as witness-like discounted bytes.

Draft weight definition:

```
base_size = |TxNoWitnessBytes(T)|
wit_size  = |WitnessBytes(T.witness)|
da_size   = |DataSectionBytes(T.data)|
sig_cost  = (as in CANONICAL v1.1)

weight(T) = 4 * base_size + wit_size + da_size + sig_cost
```

If instead DA bytes are carried as base bytes (e.g., in output covenant payload), they cost ~`4 wu/byte` and the
block weight parameters must be re-derived.

---

## 5. P2P requirements (policy, not consensus)

To support DA32 in practice, nodes MUST raise message-size policy caps above legacy defaults.

Recommended:

- `MAX_RELAY_MSG_BYTES >= 96 MiB` (covers large blocks and fallback full-block relay)

Compact blocks are RECOMMENDED (P2P protocol draft):

- `spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md` (Compact blocks: `sendcmpct`, `cmpctblock`, `getblocktxn`, `blocktxn`;
  see the "Compact blocks" section)

Note:

- even with compact blocks, a safe fallback path must exist for peers missing DA txs.

---

## 6. Pruning (node policy)

Nodes MAY prune `data_section` bytes for historical DA-chunk transactions after they are older than a configured
retention horizon.

However, pruning reduces long-term retrievability. Gateways/watchtowers operating withdrawals MUST archive DA bytes
for at least the domain's withdrawal finalization horizon.

---

## 7. Conformance (planned)

If adopted, this draft should be covered by a new conformance gate (e.g., `CV-DA-CARRIER`) with minimum vectors:

- reject: tx has DA output but `data_len = 0`
- reject: `data_len != chunk_len`
- reject: `SHA3(data) != chunk_hash`
- reject: `data_len > MAX_DA_BYTES_PER_TX`
- reject: block where `Σ chunk_len > MAX_DA_BYTES_PER_BLOCK`
