# RUBIN L1 CANONICAL

This document is consensus-critical. All requirements expressed with MUST / MUST NOT are mandatory for
consensus validity.

## 1. Genesis Rule (Transaction Wire)

- "Transaction wire" is the byte-level transaction serialization used in blocks and P2P relay.
- The chain uses a **single transaction wire format from genesis**.
- `tx_kind` is the only transaction-shape selector. Wire-level activation by transaction version is not used.
- The `version` field is committed into `TxCoreBytes`, `txid`, and sighash preimages, but MUST NOT be interpreted as
  a deployment gate.

## 2. Primitive Encodings

### 2.1 Integers

- `u8`: 1 byte
- `u16le`: 2 bytes, little-endian
- `u32le`: 4 bytes, little-endian
- `u64le`: 8 bytes, little-endian

### 2.2 Byte Strings

- `bytesN`: exactly N raw bytes.
- `bytes[L]`: exactly L raw bytes.

### 2.3 DA Terminology

- **DA set** (consensus term): one `DA_COMMIT_TX` plus all `DA_CHUNK_TX` records linked by the same `da_id`.
- **DA batch** (application term): L2 metadata carried inside `da_payload` (for example `batch_number`).
  Unless explicitly stated otherwise, this document uses **DA set** for consensus rules.

### 2.4 Units

- Consensus constants are specified in exact byte counts.
- Unless explicitly marked `MiB`/`GiB`, SI prefixes are used:
  - `1 MB = 1_000_000 bytes`
  - `1 GB = 1_000_000_000 bytes`
- `MiB` and `GiB` are binary units (`2^20` and `2^30` bytes).

## 3. CompactSize (Varint)

CompactSize encodes an unsigned integer `n` in 1, 3, 5, or 9 bytes:

- If `n < 0xfd`: encode as `[u8(n)]`.
- If `0xfd <= n <= 0xffff`: encode as `[0xfd] || u16le(n)`.
- If `0x1_0000 <= n <= 0xffff_ffff`: encode as `[0xfe] || u32le(n)`.
- If `0x1_0000_0000 <= n <= 0xffff_ffff_ffff_ffff`: encode as `[0xff] || u64le(n)`.

Canonical rule (minimality):

- CompactSize values MUST be minimally encoded. Any non-minimal encoding MUST be rejected as `TX_ERR_PARSE`.

## 4. Consensus Constants (Wire-Level)

These constants are consensus-critical for this protocol ruleset:

- `WITNESS_DISCOUNT_DIVISOR = 4`
- `TARGET_BLOCK_INTERVAL = 120` seconds
- `WINDOW_SIZE = 10_080` blocks
- `COINBASE_MATURITY = 100` blocks
- `MAX_FUTURE_DRIFT = 7_200` seconds
- `MAX_TIMESTAMP_STEP_PER_BLOCK = 10 * TARGET_BLOCK_INTERVAL = 1_200` seconds (derived)
- `MAX_TX_INPUTS = 1024`
- `MAX_TX_OUTPUTS = 1024`
- `MAX_WITNESS_ITEMS = 1024`
- `MAX_WITNESS_BYTES_PER_TX = 100_000`
- `MAX_SCRIPT_SIG_BYTES = 32`
- `POW_LIMIT = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` (bytes32)
- `MAX_BLOCK_WEIGHT = 68_000_000` weight units
- `MAX_DA_BYTES_PER_BLOCK = 32_000_000` bytes
- `MAX_DA_MANIFEST_BYTES_PER_TX = 65_536` bytes
- `CHUNK_BYTES = 524_288` bytes
- `MAX_DA_BATCHES_PER_BLOCK = 128`
- `MAX_DA_CHUNK_COUNT = floor(MAX_DA_BYTES_PER_BLOCK / CHUNK_BYTES) = 61` (derived)
- `MAX_ANCHOR_PAYLOAD_SIZE = 65_536` bytes
- `MAX_ANCHOR_BYTES_PER_BLOCK = 131_072` bytes
- `MAX_P2PK_COVENANT_DATA = 33` bytes
- `MAX_HTLC_COVENANT_DATA = 105` bytes
- `MAX_HTLC_PREIMAGE_BYTES = 256` bytes
- `MAX_VAULT_KEYS = 12`
- `MAX_VAULT_WHITELIST_ENTRIES = 1_024`
- `MAX_MULTISIG_KEYS = 12`

Monetary constants (consensus-critical):

- `BASE_UNITS_PER_RBN = 100_000_000`
- `MAX_SUPPLY = 5_000_000_000_000_000` base units (50_000_000 RBN, emission anchor; total supply becomes unbounded after tail activation)
- `GENESIS_ALLOCATION = 100_000_000_000_000` base units (1_000_000 RBN)
- `MINEABLE_CAP = 4_900_000_000_000_000` base units (49_000_000 RBN)
- `EMISSION_SPEED_FACTOR = 20` (smooth-decay right-shift)
- `TAIL_EMISSION_PER_BLOCK = 19_025_875` base units (0.19025875 RBN)

Non-consensus operational defaults (not used for validity):

- `K_CONFIRM_L1 = 8`
- `K_CONFIRM_BRIDGE = 12`
- `K_CONFIRM_GOV = 16`
- `MIN_DA_RETENTION_BLOCKS = 15_120` blocks (21 days at 120s per block)

Non-consensus relay policy defaults (not used for validity):

- `MAX_BLOCK_BYTES = 72_000_000`
- `MAX_WITNESS_ITEM_BYTES = 65_000`
- `MAX_RELAY_MSG_BYTES = 96_000_000`
- `MIN_RELAY_FEE_RATE = 1`

PQC witness canonical sizes:

- `SUITE_ID_ML_DSA_87 = 0x01`
  - `ML_DSA_87_PUBKEY_BYTES = 2592`
  - `ML_DSA_87_SIG_BYTES = 4627`
- `SUITE_ID_SLH_DSA_SHAKE_256F = 0x02`
  - `SLH_DSA_SHAKE_256F_PUBKEY_BYTES = 64`
  - `MAX_SLH_DSA_SIG_BYTES = 49_856`
- `SLH_DSA_ACTIVATION_HEIGHT = 1_000_000`

Signature verification cost weights:

- `VERIFY_COST_ML_DSA_87 = 8`
- `VERIFY_COST_SLH_DSA_SHAKE_256F = 64`

Keyless sentinel witness:

- `SUITE_ID_SENTINEL = 0x00` (reserved; MUST NOT be used for cryptographic verification)

## 5. Transaction Wire

### 5.1 Transaction Data Structures

```text
Tx {
  version : u32le
  tx_kind : u8
  tx_nonce : u64le
  input_count : CompactSize
  inputs[] : TxInput[input_count]
  output_count : CompactSize
  outputs[] : TxOutput[output_count]
  locktime : u32le
  da_core_fields : DaCoreFields
  witness : WitnessSection
  da_payload_len : CompactSize
  da_payload : bytes[da_payload_len]
}

TxInput {
  prev_txid : bytes32
  prev_vout : u32le
  script_sig_len : CompactSize
  script_sig : bytes[script_sig_len]
  sequence : u32le
}

TxOutput {
  value : u64le
  covenant_type : u16le
  covenant_data_len : CompactSize
  covenant_data : bytes[covenant_data_len]
}

WitnessSection {
  witness_count : CompactSize
  witnesses : WitnessItem[witness_count]
}

WitnessItem {
  suite_id : u8
  pubkey_length : CompactSize
  pubkey : bytes[pubkey_length]
  sig_length : CompactSize
  signature : bytes[sig_length]
}

DaCoreFields depends on `tx_kind`:

DaCoreFields(tx_kind=0x00) = empty

DaCoreFields(tx_kind=0x01) = DaCommitCoreFields

DaCoreFields(tx_kind=0x02) = DaChunkCoreFields

DaCommitCoreFields {
  da_id : bytes32
  chunk_count : u16le
  retl_domain_id : bytes32
  batch_number : u64le
  tx_data_root : bytes32
  state_root : bytes32
  withdrawals_root : bytes32
  batch_sig_suite : u8
  batch_sig_len : CompactSize
  batch_sig : bytes[batch_sig_len]
}

DaChunkCoreFields {
  da_id : bytes32
  chunk_index : u16le
  chunk_hash : bytes32
}
```

Note:
- `batch_sig` is L2-application data. L1 consensus MUST NOT verify `batch_sig` contents and MUST NOT reject a
  transaction based on `batch_sig` bytes. L1 stores and hashes this field as opaque data.

### 5.2 `tx_kind`

`tx_kind` is an explicit transaction kind selector:

- `0x00`: standard transaction (no DA).
- `0x01`: DA commit transaction.
- `0x02`: DA chunk transaction.

Rules:

- `tx_kind` MUST be one of `0x00`, `0x01`, or `0x02`. Any other value MUST be rejected as `TX_ERR_PARSE`.
- For `tx_kind = 0x00`, `da_payload_len` MUST equal `0`. Any other value MUST be rejected as `TX_ERR_PARSE`.
- For `tx_kind = 0x01`, `da_payload` is the DA set manifest (application-layer metadata for the L2 operator;
  it may contain L2 batch fields such as `batch_number`).
  `da_payload_len MUST be <= MAX_DA_MANIFEST_BYTES_PER_TX`. Otherwise reject as `TX_ERR_PARSE`.
- For `tx_kind = 0x01`, `chunk_count` MUST satisfy `1 <= chunk_count <= MAX_DA_CHUNK_COUNT`.
  Otherwise reject as `TX_ERR_PARSE`.
- For `tx_kind = 0x01`, `batch_sig_len MUST be <= MAX_DA_MANIFEST_BYTES_PER_TX`. Otherwise reject as `TX_ERR_PARSE`.
- For `tx_kind = 0x02`, `da_payload_len` MUST satisfy `1 <= da_payload_len <= CHUNK_BYTES`.
  Otherwise reject as `TX_ERR_PARSE`.

### 5.3 Syntax Limits (Parsing)

For any transaction `T`:

1. `input_count MUST be <= MAX_TX_INPUTS`. Otherwise reject as `TX_ERR_PARSE`.
2. `output_count MUST be <= MAX_TX_OUTPUTS`. Otherwise reject as `TX_ERR_PARSE`.
3. `script_sig_len MUST be <= MAX_SCRIPT_SIG_BYTES`. Otherwise reject as `TX_ERR_PARSE`.
4. `witness.witness_count MUST be <= MAX_WITNESS_ITEMS`. Otherwise reject as `TX_ERR_WITNESS_OVERFLOW`.
5. `WitnessBytes(T.witness) MUST be <= MAX_WITNESS_BYTES_PER_TX`. Otherwise reject as `TX_ERR_WITNESS_OVERFLOW`.

Where `WitnessBytes(WitnessSection)` is the exact serialized byte length of:

```text
CompactSize(witness_count) || concat(witness_item_bytes[i] for i in [0..witness_count-1])
```

### 5.4 Witness Item Canonicalization (Parsing)

Witness items are parsed and checked for canonical form:

- If `suite_id = SUITE_ID_SENTINEL (0x00)`:
  - This suite_id is a **meta witness**: it MUST NOT be used for cryptographic signature verification.
  - Either:
    - keyless sentinel form: `pubkey_length MUST equal 0` and `sig_length MUST equal 0`; or
    - `CORE_HTLC` selector form:
      - `pubkey_length MUST equal 32` (selector `key_id`), and
      - `sig_length MUST be`:
        - `1` (refund selector), or
        - `3 <= sig_length <= 3 + MAX_HTLC_PREIMAGE_BYTES` (claim selector).
      - The selector payload is encoded inside the `signature` bytes as:
        - `signature[0] = 0x00` (claim) or `0x01` (refund); any other value MUST be rejected as `TX_ERR_PARSE`.
        - If claim (`0x00`): `signature[1:3]` is `u16le(preimage_len)` and `signature[3:]` is `preimage`.
          `preimage_len MUST be <= MAX_HTLC_PREIMAGE_BYTES` and `sig_length MUST equal 3 + preimage_len`.
        - If refund (`0x01`): `sig_length MUST equal 1`.
  - Any other encoding MUST be rejected as `TX_ERR_PARSE`.
- If `suite_id = SUITE_ID_ML_DSA_87 (0x01)`:
  - `pubkey_length MUST equal ML_DSA_87_PUBKEY_BYTES` and `sig_length MUST equal ML_DSA_87_SIG_BYTES`;
    otherwise reject as `TX_ERR_SIG_NONCANONICAL`.
- If `suite_id = SUITE_ID_SLH_DSA_SHAKE_256F (0x02)`:
  - `pubkey_length MUST equal SLH_DSA_SHAKE_256F_PUBKEY_BYTES` and
    `0 < sig_length <= MAX_SLH_DSA_SIG_BYTES`; otherwise reject as `TX_ERR_SIG_NONCANONICAL`.
- Any other `suite_id` MUST be rejected as `TX_ERR_SIG_ALG_INVALID`.

Activation note:

- Witness canonicalization in this section validates byte-level encoding only.
- Consensus activation gate for `SUITE_ID_SLH_DSA_SHAKE_256F` is enforced in spend validation sections
  (Sections 14.1, 14.2, and `spec/RUBIN_CORE_HTLC_SPEC.md` §5) against block height.
- If `block_height < SLH_DSA_ACTIVATION_HEIGHT` and any required spend witness uses
  `SUITE_ID_SLH_DSA_SHAKE_256F`, validation MUST reject as `TX_ERR_SIG_ALG_INVALID`.

## 6. Canonical Encode/Parse Invariant

For any valid transaction `T`, serialization and parsing MUST be mutually inverse:

```text
parse_tx(serialize_tx(T)) = T
```

## 7. Deterministic Parse Error Mapping (Wire)

If multiple parsing errors exist, implementations MUST apply checks in this order and reject with the first
applicable error code:

1. CompactSize minimality and integer decode bounds (`TX_ERR_PARSE`).
2. `tx_kind` / `da_payload_len` rules (`TX_ERR_PARSE`).
3. Input/output/script_sig length bounds (`TX_ERR_PARSE`).
4. Witness section item count / total bytes bounds (`TX_ERR_WITNESS_OVERFLOW`).
5. Witness item canonicalization (`TX_ERR_PARSE` / `TX_ERR_SIG_NONCANONICAL` / `TX_ERR_SIG_ALG_INVALID`).

No cryptographic verification is performed in this section. Signature verification, covenant evaluation, and
value/binding rules are specified in later sections.

## 8. Transaction Identifiers (TXID / WTXID)

### 8.1 Hash Function

RUBIN uses `SHA3-256` (FIPS 202) as the consensus hash function.

### 8.1.1 SHA3-256 Security Properties (Informative)

`SHA3-256` (FIPS 202, Keccak[512](M, 256)) provides the following asymptotic security properties:

- **Preimage resistance:** ~256-bit (classical), ~128-bit (quantum; Grover)
- **Second-preimage resistance:** ~256-bit (classical), ~128-bit (quantum; Grover)
- **Collision resistance:** ~128-bit (classical; birthday bound), ~85-bit (quantum; BHT)

Binding targets by usage domain (informative):

- `txid/wtxid` (Section 8.3): collision / second-preimage resistance (identifier uniqueness and outpoint safety)
- Merkle root (Section 10.4): collision / second-preimage resistance (prevents tree mutation / ambiguity)
- `key_id = SHA3-256(pubkey)` (e.g. `CORE_P2PK`, `CORE_VAULT`, `CORE_HTLC`): preimage resistance (prevents key_id spoofing)
- `whitelist[j] = SHA3-256(OutputDescriptorBytes(output_j))` (Section 18.3): preimage resistance (prevents destination spoofing)
- sighash digest (Section 12): collision / second-preimage resistance (prevents signature substitution across different preimages)
- DA `chunk_hash = SHA3-256(da_payload)` (Section 21.2): second-preimage resistance (prevents payload substitution)
- witness commitment hash (Section 10.4.1): second-preimage resistance (prevents witness substitution)

RUBIN does not require 256-bit collision resistance for consensus-critical safety. `SHA3-256` collision resistance
(~128-bit classical) is sufficient for identifier uniqueness and Merkle-style commitments under the stated threat model.

### 8.2 Canonical Transaction Serializations

For any valid transaction `T` (i.e. one that parses under Transaction Wire (Section 5) with all rules in Sections 3-7):

`TxCoreBytes(T)` is defined as the canonical serialization of:

```text
u32le(T.version) ||
u8(T.tx_kind) ||
u64le(T.tx_nonce) ||
CompactSize(T.input_count) ||
concat(T.inputs[i] for i in [0..input_count-1]) ||
CompactSize(T.output_count) ||
concat(T.outputs[j] for j in [0..output_count-1]) ||
u32le(T.locktime) ||
DaCoreFieldsBytes(T)
```

Where each `TxInput` and `TxOutput` is serialized exactly as in Section 5.1, and all `CompactSize` values MUST be
minimally encoded (see Section 3).

`DaCoreFieldsBytes(T)` is defined as:

- If `T.tx_kind = 0x00`: the empty byte string.
- If `T.tx_kind = 0x01`: the canonical serialization of `DaCommitCoreFields` (Section 5.1) in that exact field order,
  with `batch_sig_len` minimally-encoded CompactSize.
- If `T.tx_kind = 0x02`: the canonical serialization of `DaChunkCoreFields` (Section 5.1) in that exact field order.

`TxBytes(T)` is defined as:

```text
TxBytes(T) =
  TxCoreBytes(T) ||
  WitnessBytes(T.witness) ||
  CompactSize(T.da_payload_len) ||
  T.da_payload[T.da_payload_len]
```

### 8.3 Identifier Definitions (Normative)

- `txid(T) = SHA3-256(TxCoreBytes(T))`
- `wtxid(T) = SHA3-256(TxBytes(T))`

Consensus usage:

- `txid` is the identifier used by consensus for outpoints (`prev_txid`).
- `wtxid` is a wire identifier that commits to witness bytes and (future) DA payload bytes.

### 8.4 Canonicality and Undefined Inputs

- For invalid transactions (that do not parse canonically), `TxCoreBytes`, `TxBytes`, `txid`, and `wtxid` are
  undefined.
- Implementations MUST NOT compute or cache identifiers for non-canonically parsed transactions.

## 9. Weight Accounting (Normative)

For any valid transaction `T`:

```text
base_size = |TxCoreBytes(T)|
wit_size  = |WitnessBytes(T.witness)|
da_size   = |CompactSize(T.da_payload_len)| + T.da_payload_len
ml_count  = count witness items where
            suite_id = SUITE_ID_ML_DSA_87 AND
            pubkey_length = ML_DSA_87_PUBKEY_BYTES AND
            sig_length = ML_DSA_87_SIG_BYTES
slh_count = count witness items where
            suite_id = SUITE_ID_SLH_DSA_SHAKE_256F AND
            pubkey_length = SLH_DSA_SHAKE_256F_PUBKEY_BYTES AND
            0 < sig_length <= MAX_SLH_DSA_SIG_BYTES
sig_cost  = ml_count * VERIFY_COST_ML_DSA_87 + slh_count * VERIFY_COST_SLH_DSA_SHAKE_256F
weight(T) = WITNESS_DISCOUNT_DIVISOR * base_size + wit_size + da_size + sig_cost
```

Notes:

- `WITNESS_DISCOUNT_DIVISOR = 4` discounts witness bytes relative to non-witness bytes.
- `sig_cost` exists to account for CPU verification work that is not captured by byte length alone.

For any block `B` with transactions `B.txs[]`:

```text
sum_weight = sum(weight(T) for each transaction T in B.txs)
```

`sum_weight MUST be <= MAX_BLOCK_WEIGHT`. Otherwise the block is invalid.

Per-block DA bytes constraint:

- Let `sum_da_bytes(B) = sum(T.da_payload_len for each transaction T in B.txs where T.tx_kind != 0x00)`.
- `sum_da_bytes(B) MUST be <= MAX_DA_BYTES_PER_BLOCK`. Otherwise the block is invalid (`BLOCK_ERR_WEIGHT_EXCEEDED`).

## 10. Block Wire Format (Normative)

### 10.1 BlockHeader

```text
BlockHeader {
  version: u32le
  prev_block_hash: bytes32
  merkle_root: bytes32
  timestamp: u64le
  target: bytes32    # compared as a big-endian integer
  nonce: u64le
}
```

`BlockHeaderBytes(B)` is the canonical serialization:

```text
u32le(version) ||
prev_block_hash ||
merkle_root ||
u64le(timestamp) ||
target ||
u64le(nonce)
```

Integer fields use little-endian, except `target` which is serialized as raw 32 bytes and compared as a
big-endian integer.

### 10.2 Block and BlockBytes

```text
Block {
  header: BlockHeader
  tx_count: CompactSize
  txs: Tx[tx_count]
}
```

`BlockBytes(B)` is:

```text
BlockHeaderBytes(B.header) ||
CompactSize(tx_count) ||
TxBytes(B.txs[0]) || ... || TxBytes(B.txs[tx_count-1])
```

### 10.3 Block Hash and Proof-of-Work Check

- `block_hash(B) = SHA3-256(BlockHeaderBytes(B.header))`

Proof-of-Work validity:

```text
valid_pow(B) iff integer(block_hash(B), big-endian) < integer(B.header.target, big-endian)
```

Target range validity:

- `integer(B.header.target, big-endian)` MUST satisfy `1 <= target <= POW_LIMIT`.
- A block with out-of-range `target` MUST be rejected as `BLOCK_ERR_TARGET_INVALID`.

### 10.4 Merkle Root (Transaction Commitment)

Merkle tree hashing is defined over transaction identifiers (`txid`), in block transaction order.

```text
Leaf = SHA3-256(0x00 || txid)
Node = SHA3-256(0x01 || left || right)
```

Odd-element rule (normative):

- If the number of elements at any level is odd, the lone element is promoted to the next level unchanged.
- Duplicating the last element is forbidden.

`merkle_root` is the final root after full binary reduction over all transaction `txid` values.

### 10.4.1 Witness Commitment (Coinbase Anchor)

Witness commitment uses transaction `wtxid` values and commits them through a coinbase `CORE_ANCHOR` output.

Define witness commitment IDs per transaction index `i`:

- For `i = 0` (coinbase), `wtxid_commit[0] = 0x00..00` (32 zero bytes).
- For `i > 0`, `wtxid_commit[i] = wtxid(B.txs[i])`.

Witness Merkle tree:

```text
Leaf = SHA3-256(0x02 || wtxid_commit[i])
Node = SHA3-256(0x03 || left || right)
```

Odd-element rule is identical to Section 10.4: promote unchanged; duplication forbidden.

Let `witness_merkle_root` be the final root from this tree.

Define:

```text
witness_commitment_hash = SHA3-256(ASCII("RUBIN-WITNESS/") || witness_merkle_root)
```

Coinbase commitment rule:

- The coinbase transaction `B.txs[0]` MUST contain exactly one output with:
  - `covenant_type = CORE_ANCHOR`, and
  - `covenant_data_len = 32`, and
  - `covenant_data = witness_commitment_hash`.

If missing or duplicated, reject block as `BLOCK_ERR_WITNESS_COMMITMENT`.

### 10.5 Coinbase Basics (Structural)

Every block MUST contain exactly one coinbase transaction and it MUST be the first transaction.

Define `is_coinbase_tx(T)` for `Tx` as:

- `T.input_count = 1`, and
- `T.tx_kind = 0x00`, and
- `T.inputs[0].prev_txid` is 32 zero bytes, and
- `T.inputs[0].prev_vout = 0xffff_ffff`, and
- `T.inputs[0].script_sig_len = 0`, and
- `T.inputs[0].sequence = 0xffff_ffff`, and
- `T.witness.witness_count = 0`, and
- `T.da_payload_len = 0`, and
- `T.tx_nonce = 0`.

Rules:

- `tx_count MUST be >= 1`.
- `B.txs[0]` MUST satisfy `is_coinbase_tx(B.txs[0])`.
- No other transaction `B.txs[i]` with `i > 0` may satisfy `is_coinbase_tx`.

Coinbase economics (subsidy, maturity, and fee rules) are defined in later sections.

## 11. Chain ID (Consensus Identity)

`chain_id` is a 32-byte consensus identifier used for signature domain separation.

Definition:

```text
chain_id = SHA3-256(serialized_genesis_for_chain_id)
```

Where `serialized_genesis_for_chain_id` is:

```text
ASCII("RUBIN-GENESIS-v1") ||
BlockHeaderBytes(genesis_header) ||
CompactSize(genesis_tx_count) ||
TxBytes(genesis_txs[0]) || ... || TxBytes(genesis_txs[genesis_tx_count-1])
```

Chain-instance requirement:

- A concrete network (devnet/testnet/mainnet) MUST publish its exact genesis bytes so all nodes derive the same
  `chain_id`.

## 12. Sighash v1 (Normative)

Sighash is computed for each non-coinbase input to produce a 32-byte digest that is signed by the witness
signature.

Definitions:

```text
hash_of_da_core_fields = SHA3-256(DaCoreFieldsBytes(T))
hash_of_all_prevouts = SHA3-256(concat(inputs[i].prev_txid || u32le(inputs[i].prev_vout) for i in [0..input_count-1]))
hash_of_all_sequences = SHA3-256(concat(u32le(inputs[i].sequence) for i in [0..input_count-1]))
hash_of_all_outputs = SHA3-256(concat(outputs[j] in TxOutput wire order for j in [0..output_count-1]))
```

For `output_count = 0`, `hash_of_all_outputs = SHA3-256("")`.

Preimage and digest:

```text
preimage_tx_sig =
  ASCII("RUBINv1-sighash/") ||
  chain_id ||
  u32le(version) ||
  u8(tx_kind) ||
  u64le(tx_nonce) ||
  hash_of_da_core_fields ||
  hash_of_all_prevouts ||
  hash_of_all_sequences ||
  u32le(input_index) ||
  prev_txid ||
  u32le(prev_vout) ||
  u64le(input_value) ||
  u32le(sequence) ||
  hash_of_all_outputs ||
  u32le(locktime)

digest = SHA3-256(preimage_tx_sig)
```

All fields in `preimage_tx_sig` are taken from the transaction `T` being signed, except `input_value`.
`input_value` is the `value` of the spendable UTXO entry referenced by this input's `(prev_txid, prev_vout)`.

For coinbase transactions, sighash is not computed (no witness).

Forward-compatibility note:
- `locktime` and `sequence` are committed in the sighash preimage for deterministic transaction binding and future
  covenant extensibility (for example, HTLC semantics when specified).
- In the current active covenant set, there is no additional covenant-specific locktime/sequence semantics beyond the
  transaction structural checks in Section 16.

### 12.1 `verify_sig` Profile (Normative)

`verify_sig` is a consensus predicate over raw bytes and MUST be implemented as a deterministic,
side-effect-free function:

```text
verify_sig(suite_id, pubkey, signature, digest32) -> bool
```

Rules:

1. `digest32` MUST be exactly the 32-byte `digest` defined in this section. No additional hashing,
   truncation, pre-hash wrapper, context string, or domain prefix may be added by the implementation.
2. `suite_id = SUITE_ID_ML_DSA_87 (0x01)`:
   - MUST invoke ML-DSA-87 verification over `(pubkey, signature, digest32)` using canonical byte strings.
3. `suite_id = SUITE_ID_SLH_DSA_SHAKE_256F (0x02)`:
   - MUST invoke SLH-DSA-SHAKE-256f verification over `(pubkey, signature, digest32)` using canonical byte strings.
4. Any other `suite_id` MUST be rejected as `TX_ERR_SIG_ALG_INVALID` before `verify_sig` is invoked.
5. Any verification failure from rule 2 or 3 MUST be mapped to `TX_ERR_SIG_INVALID`.

Dispatch, input bytes, and success/failure mapping are consensus-critical.

### 12.2 Signature Profile Vectors (Normative)

Consensus vectors for signature-profile behavior:

| Vector ID | Condition | Expected |
| --- | --- | --- |
| CV-SIG-01 | `suite_id = 0x01`, canonical ML-DSA lengths, cryptographically invalid signature bytes | `TX_ERR_SIG_INVALID` |
| CV-SIG-02 | `suite_id = 0x02`, `block_height < SLH_DSA_ACTIVATION_HEIGHT` in required spend slot | `TX_ERR_SIG_ALG_INVALID` |
| CV-SIG-03 | unknown `suite_id` in spend slot | `TX_ERR_SIG_ALG_INVALID` |
| CV-SIG-04 | non-canonical signature lengths for selected suite | `TX_ERR_SIG_NONCANONICAL` |

## 13. Consensus Error Codes (Normative)

The following error codes are consensus-critical and MUST be returned identically by all conforming
implementations for the described failure classes:

- Non-minimal CompactSize                          -> `TX_ERR_PARSE`
- Malformed witness encoding                       -> `TX_ERR_PARSE`
- Duplicate input outpoint                         -> `TX_ERR_PARSE`
- Value conservation overflow (`sum_in`/`sum_out` beyond u128) -> `TX_ERR_PARSE`
- Output value > input value                       -> `TX_ERR_VALUE_CONSERVATION`
- Invalid tx_nonce                                 -> `TX_ERR_TX_NONCE_INVALID`
- Invalid sequence number                          -> `TX_ERR_SEQUENCE_INVALID`
- Duplicate nonce                                  -> `TX_ERR_NONCE_REPLAY`
- Cryptographically invalid signature              -> `TX_ERR_SIG_INVALID`
- Invalid signature type                           -> `TX_ERR_SIG_ALG_INVALID`
- Invalid signature length / non-canonical witness -> `TX_ERR_SIG_NONCANONICAL`
- HTLC refund locktime not met                    -> `TX_ERR_TIMELOCK_NOT_MET`
- Witness overflow                                 -> `TX_ERR_WITNESS_OVERFLOW`
- Invalid covenant_type / covenant encoding        -> `TX_ERR_COVENANT_TYPE_INVALID`
- Missing UTXO / attempt to spend non-spendable    -> `TX_ERR_MISSING_UTXO`
- Coinbase immature                                -> `TX_ERR_COINBASE_IMMATURE`
- Invalid prev_block_hash linkage                  -> `BLOCK_ERR_LINKAGE_INVALID`
- Invalid merkle_root                              -> `BLOCK_ERR_MERKLE_INVALID`
- Missing/duplicate witness commitment             -> `BLOCK_ERR_WITNESS_COMMITMENT`
- PoW invalid                                      -> `BLOCK_ERR_POW_INVALID`
- Target mismatch                                  -> `BLOCK_ERR_TARGET_INVALID`
- Timestamp too old (MTP)                          -> `BLOCK_ERR_TIMESTAMP_OLD`
- Timestamp too far in future                      -> `BLOCK_ERR_TIMESTAMP_FUTURE`
- Coinbase rule violation                          -> `BLOCK_ERR_COINBASE_INVALID`
- Coinbase subsidy exceeded                        -> `BLOCK_ERR_SUBSIDY_EXCEEDED`
- Weight exceedance                                -> `BLOCK_ERR_WEIGHT_EXCEEDED`
- Anchor bytes exceeded                            -> `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED`
- DA set incomplete (commit without all chunks)    -> `BLOCK_ERR_DA_INCOMPLETE`
- DA chunk hash mismatch                           -> `BLOCK_ERR_DA_CHUNK_HASH_INVALID`
- DA set orphan chunk (chunk without commit)       -> `BLOCK_ERR_DA_SET_INVALID`
- DA duplicate commit for same da_id              -> `BLOCK_ERR_DA_SET_INVALID`
- DA payload commitment mismatch or ambiguous      -> `BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID`
- DA set count exceeded (`MAX_DA_BATCHES_PER_BLOCK`) -> `BLOCK_ERR_DA_BATCH_EXCEEDED`
- Malformed block encoding                         -> `BLOCK_ERR_PARSE`

Note: Value conservation overflow (`sum_in` or `sum_out` exceeding unsigned u128 range)
MUST be reported as `TX_ERR_PARSE`. This mapping is intentional and consensus-critical.

Note: `MAX_TIMESTAMP_STEP_PER_BLOCK` is enforced via clamping in Section 15 and does not
produce a dedicated error code.

Error priority (short-circuit):

- Implementations MUST apply checks in the validation order and return the first applicable error code.
- Signature verification MUST NOT be attempted if prior parsing, covenant, or UTXO rules already
  cause rejection.

## 14. Covenant Type Registry (Normative)

The following `covenant_type` values are valid:

- `0x0000` `CORE_P2PK`
- `0x0001` *(unassigned — MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`)*
- `0x0002` `CORE_ANCHOR`
- `0x00FF` `CORE_RESERVED_FUTURE`
- `0x0100` `CORE_HTLC`
- `0x0101` `CORE_VAULT`
- `0x0102` *(unassigned — MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`)*
- `0x0103` `CORE_DA_COMMIT`
- `0x0104` `CORE_MULTISIG`

Any other unknown or future `covenant_type` MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.

Semantics:

- `CORE_P2PK`:
  - `covenant_data = suite_id:u8 || key_id:bytes32`.
  - `covenant_data_len MUST equal MAX_P2PK_COVENANT_DATA`.
  - At output creation:
    - `value MUST be > 0`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `suite_id` MUST be `SUITE_ID_ML_DSA_87 (0x01)`, or
    - `suite_id` MAY be `SUITE_ID_SLH_DSA_SHAKE_256F (0x02)` only if `block_height >= SLH_DSA_ACTIVATION_HEIGHT`.
    Any other value MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.
  - Spend authorization requires exactly one witness item:
    - `w.suite_id` MUST equal `suite_id` from `covenant_data`; otherwise reject as `TX_ERR_SIG_ALG_INVALID`.
    - If `w.suite_id = SUITE_ID_SLH_DSA_SHAKE_256F (0x02)` and `block_height < SLH_DSA_ACTIVATION_HEIGHT`,
      reject as `TX_ERR_SIG_ALG_INVALID`.
    - `SHA3-256(pubkey) = key_id`, and a valid signature over `digest` (Section 12).
  - `key_id = SHA3-256(pubkey)` where `pubkey` is the canonical witness public key byte string for the selected
    `suite_id` (no extra length prefixes are included).
- `CORE_ANCHOR`:
  - `covenant_data = anchor_data` (raw bytes, no additional wrapping).
  - `0 < covenant_data_len <= MAX_ANCHOR_PAYLOAD_SIZE` MUST hold; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
  - `value MUST equal 0`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
  - In coinbase, witness commitment anchoring requirements are defined in Section 10.4.1.
  - `CORE_ANCHOR` outputs are non-spendable and MUST NOT be added to the spendable UTXO set. Any attempt to spend an
    ANCHOR output MUST be rejected as `TX_ERR_MISSING_UTXO`.
  - Per-block constraint: sum of `covenant_data_len` across all `CORE_ANCHOR` and `CORE_DA_COMMIT` outputs in a block
    MUST be `<= MAX_ANCHOR_BYTES_PER_BLOCK`; otherwise reject the block as `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED`.
- `CORE_HTLC`:
  - Hash Time-Locked Contract.
  - Active from genesis block 0.
  - `covenant_data_len MUST equal MAX_HTLC_COVENANT_DATA (105)`.
  - Spend semantics: `spec/RUBIN_CORE_HTLC_SPEC.md` §5.
  - Witness consumption: 2 WitnessItems (Section 16).
- `CORE_VAULT`:
  - Consensus-native covenant for value storage with mandatory destination whitelist.
  - Active from genesis block 0.
  - `covenant_data` format:
    - `threshold:u8 || key_count:u8 || keys[key_count] || whitelist_count:u16le || whitelist[whitelist_count]`
    - each `keys[i]` is `bytes32`; each `whitelist[j]` is `bytes32`
    - `covenant_data_len MUST equal 2 + 32*key_count + 2 + 32*whitelist_count`
  - Constraints at creation (CheckTx):
    - `value MUST be > 0`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `1 <= key_count <= MAX_VAULT_KEYS`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `1 <= threshold <= key_count`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `keys[]` MUST be strictly lexicographically sorted (ascending) with no duplicates;
      otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `1 <= whitelist_count <= MAX_VAULT_WHITELIST_ENTRIES`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `whitelist_count = 0` is explicitly forbidden; reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `whitelist[]` MUST be strictly lexicographically sorted (ascending) with no duplicates;
      otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
  - `keys[i] = SHA3-256(pubkey_i)`.
  - `whitelist[j] = SHA3-256(OutputDescriptorBytes(output_j))` (Section 18.3).
  - Spend semantics: Section 14.1.
  - Witness consumption: `key_count` WitnessItems (Section 16).
- `CORE_MULTISIG`:
  - Operational M-of-N multisig covenant without destination restrictions.
  - Active from genesis block 0.
  - `covenant_data` format:
    - `threshold:u8 || key_count:u8 || keys[key_count]`
    - each `keys[i]` is `bytes32`
    - `covenant_data_len MUST equal 2 + 32*key_count`
  - Constraints at creation (CheckTx):
    - `value MUST be > 0`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `1 <= key_count <= MAX_MULTISIG_KEYS`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `1 <= threshold <= key_count`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
    - `keys[]` MUST be strictly lexicographically sorted (ascending) with no duplicates;
      otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
  - `keys[i] = SHA3-256(pubkey_i)`.
  - Spend semantics: Section 14.2.
  - Witness consumption: `key_count` WitnessItems (Section 16).
- `CORE_DA_COMMIT`:
  - `covenant_data_len MUST equal 32`. Otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
  - `covenant_data` is the DA payload commitment hash and is verified at block level (Section 21.4).
    Commitment mismatch or ambiguity MUST reject as `BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID`.
  - `value MUST equal 0`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
  - `CORE_DA_COMMIT` outputs are counted toward `MAX_ANCHOR_BYTES_PER_BLOCK`.
  - `CORE_DA_COMMIT` outputs are non-spendable and MUST NOT be added to the spendable UTXO set. Any attempt to spend a
    DA_COMMIT output MUST be rejected as `TX_ERR_MISSING_UTXO`.
  - `CORE_DA_COMMIT` MAY only appear in `tx_kind = 0x01` (DA commit transactions). Any appearance in other
    `tx_kind` values MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.
- `CORE_RESERVED_FUTURE`:
  - Forbidden; any appearance MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.

### 14.1 CORE_VAULT Semantics (Normative)

For each non-coinbase input spending a `CORE_VAULT` UTXO entry `e`,
with WitnessItems `witnesses[W .. W+key_count-1]` assigned by the cursor model (Section 16):

#### Signature verification

For each index `i` in `[0..key_count-1]`:

Let `w = witnesses[W+i]`.

If `w.suite_id = SUITE_ID_SENTINEL (0x00)` (non-participating key):
- `w.pubkey_length MUST equal 0` and `w.sig_length MUST equal 0`. Otherwise reject as `TX_ERR_PARSE`.

If `w.suite_id = SUITE_ID_ML_DSA_87 (0x01)`:
- Require `SHA3-256(w.pubkey) = keys[i]`. Otherwise reject as `TX_ERR_SIG_INVALID`.
- Require `verify_sig(w.suite_id, w.pubkey, w.signature, digest) = true` where `digest` is per Section 12
  with `input_index` bound to this input's index in the transaction.
  Otherwise reject as `TX_ERR_SIG_INVALID`.
- Count as one valid signature.

If `w.suite_id = SUITE_ID_SLH_DSA_SHAKE_256F (0x02)`:
- If `block_height < SLH_DSA_ACTIVATION_HEIGHT`, reject as `TX_ERR_SIG_ALG_INVALID`.
- Require `SHA3-256(w.pubkey) = keys[i]`. Otherwise reject as `TX_ERR_SIG_INVALID`.
- Require `verify_sig(w.suite_id, w.pubkey, w.signature, digest) = true` where `digest` is per Section 12
  with `input_index` bound to this input's index in the transaction.
  Otherwise reject as `TX_ERR_SIG_INVALID`.
- Count as one valid signature.

Any other `suite_id` MUST be rejected as `TX_ERR_SIG_ALG_INVALID`.

Let `valid = count of valid signatures across all key_count WitnessItems`.

If `valid < threshold`: reject as `TX_ERR_SIG_INVALID`.

#### Whitelist verification

For each output `out` in the spending transaction:

Compute `h = SHA3-256(OutputDescriptorBytes(out))` (Section 18.3).

`h` MUST be found in `e.whitelist[]` using binary search
(whitelist is guaranteed sorted at UTXO creation).

If any output is not found: reject as `TX_ERR_COVENANT_TYPE_INVALID`.

Multi-input rule:

- If a transaction spends multiple `CORE_VAULT` inputs with different whitelists,
  the whitelist check above is applied independently for each input.
  Therefore every output MUST belong to the intersection of all referenced vault whitelists.
- Fee preservation rule (strong vault mode):
  - Let `sum_in_vault` be the sum of input values whose referenced UTXO covenant type is `CORE_VAULT`.
  - For any transaction that spends at least one `CORE_VAULT` input, `sum_out MUST be >= sum_in_vault`.
    Otherwise reject as `TX_ERR_VALUE_CONSERVATION`.
  - This forbids spending miner fee from `CORE_VAULT` value; fee must be funded by non-VAULT inputs.
- Design note:
  - Vault whitelist constrains allowed destinations, not per-destination amounts.
  - Amount-per-destination constraints are intentionally out of L1 scope and belong to L2 logic or off-chain policy.

### 14.2 CORE_MULTISIG Semantics (Normative)

For each non-coinbase input spending a `CORE_MULTISIG` UTXO entry `e`,
with WitnessItems `witnesses[W .. W+key_count-1]` assigned by the cursor model (Section 16):

#### Signature verification

For each index `i` in `[0..key_count-1]`:

Let `w = witnesses[W+i]`.

If `w.suite_id = SUITE_ID_SENTINEL (0x00)`:
- `w.pubkey_length MUST equal 0` and `w.sig_length MUST equal 0`. Otherwise reject as `TX_ERR_PARSE`.

If `w.suite_id = SUITE_ID_ML_DSA_87 (0x01)`:
- Require `SHA3-256(w.pubkey) = keys[i]`. Otherwise reject as `TX_ERR_SIG_INVALID`.
- Require `verify_sig(w.suite_id, w.pubkey, w.signature, digest) = true` where `digest` is per Section 12
  with `input_index` bound to this input's index.
  Otherwise reject as `TX_ERR_SIG_INVALID`.
- Count as one valid signature.

If `w.suite_id = SUITE_ID_SLH_DSA_SHAKE_256F (0x02)`:
- If `block_height < SLH_DSA_ACTIVATION_HEIGHT`, reject as `TX_ERR_SIG_ALG_INVALID`.
- Require `SHA3-256(w.pubkey) = keys[i]`. Otherwise reject as `TX_ERR_SIG_INVALID`.
- Require `verify_sig(w.suite_id, w.pubkey, w.signature, digest) = true` where `digest` is per Section 12
  with `input_index` bound to this input's index.
  Otherwise reject as `TX_ERR_SIG_INVALID`.
- Count as one valid signature.

Any other `suite_id` MUST be rejected as `TX_ERR_SIG_ALG_INVALID`.

Let `valid = count of valid signatures`.

If `valid < threshold`: reject as `TX_ERR_SIG_INVALID`.

No whitelist check is performed for `CORE_MULTISIG`.

## 15. Difficulty Update (Normative)

Let:

```text
T_expected = TARGET_BLOCK_INTERVAL * WINDOW_SIZE
```

For the purpose of retarget only, define clamped timestamps `ts'[i]` over the preceding retarget
window as follows:

```text
ts'[h-WINDOW_SIZE] = timestamp(B_{h-WINDOW_SIZE})

for i = h-WINDOW_SIZE+1 .. h-1:
    lo = ts'[i-1] + 1
    hi = ts'[i-1] + MAX_TIMESTAMP_STEP_PER_BLOCK
    ts'[i] = clamp(timestamp(B_i), lo, hi)

where clamp(v, lo, hi) = max(lo, min(v, hi)).
```

`ts'` is a pure function of block timestamps in the retarget window. It is NOT stored in consensus
state and is NOT used outside this section.

Then:

```text
T_actual = ts'[h-1] - ts'[h-WINDOW_SIZE]
```

If `T_actual <= 0`, set `T_actual = 1`.

```text
target_new =
    clamp(
        floor(target_old * T_actual / T_expected),
        max(1, floor(target_old / 4)),
        min(target_old * 4, POW_LIMIT)
    )
```

Window boundaries and applicability:

1. Let block height be `h` (genesis has `h = 0`).
2. For `h = 0`, the expected `target(B_0)` is the `target` field encoded in the published genesis header bytes.
3. For `h > 0` and `h % WINDOW_SIZE != 0`, the expected `target(B_h)` MUST equal `target(B_{h-1})`.
4. For `h > 0` and `h % WINDOW_SIZE = 0` (a retarget boundary), define the preceding window as blocks:
   - first block in window: `B_{h-WINDOW_SIZE}`
   - last block in window: `B_{h-1}`

   Then:
   - `target_old = target(B_{h-1})`
   - `timestamp_first_block_in_window = timestamp(B_{h-WINDOW_SIZE})`
   - `timestamp_last_block_in_window  = timestamp(B_{h-1})`
   - expected `target(B_h)` MUST equal `target_new` as computed by the formula above.

Any block whose `target` field does not match the expected value is invalid (`BLOCK_ERR_TARGET_INVALID`).

Note: Clamping is applied only to the retarget calculation. Block timestamps are validated as-is per
Section 22 (`MTP` floor + `MAX_FUTURE_DRIFT` ceiling).

Implementation note:
- The first retarget window (`0 .. WINDOW_SIZE-1`) uses the genesis timestamp as `T_start`.
- Accuracy of the first adjustment depends on genesis ceremony timestamp quality.

Target range:

- `target_old` and `target_new` MUST satisfy `1 <= target <= POW_LIMIT`.

All division is integer division with floor.
Intermediate products (`target_old * T_actual` and `target_old * 4`) MUST be computed using at least 320-bit
unsigned integer arithmetic (or arbitrary-precision). Silent truncation is non-conforming.

## 16. Transaction Structural Rules (Normative)

These rules apply after a transaction has been parsed under Transaction Wire (Section 5).

Define `is_coinbase_prevout` for an input `I` as:

- `I.prev_txid` is 32 zero bytes, and
- `I.prev_vout = 0xffff_ffff`.

For any non-coinbase transaction `T`:

1. `T.tx_nonce` MUST be in `[1, 0xffff_ffff_ffff_ffff]`. Otherwise reject as `TX_ERR_TX_NONCE_INVALID`.
2. `T.input_count` MUST be `>= 1`. Otherwise reject as `TX_ERR_PARSE`.
3. No input may use the coinbase prevout encoding. If any input satisfies `is_coinbase_prevout`, reject as
   `TX_ERR_PARSE`.
4. For genesis covenant set (Section 14 only), every input MUST have `script_sig_len = 0`. Otherwise reject as
   `TX_ERR_PARSE`.
5. For each input, `sequence` MUST be `<= 0x7fffffff`. Otherwise reject as `TX_ERR_SEQUENCE_INVALID`.
6. All input outpoints `(prev_txid, prev_vout)` within the transaction MUST be unique. Otherwise reject as
   `TX_ERR_PARSE`.
7. WitnessItems are consumed by inputs using a cursor model.

   Define `witness_slots(e)` for a referenced UTXO entry `e`:
   - If `e.covenant_type = CORE_HTLC`: `witness_slots(e) = 2`.
   - If `e.covenant_type ∈ {CORE_VAULT, CORE_MULTISIG}`: `witness_slots(e) = key_count(e)`,
     where `key_count(e)` is read from `e.covenant_data` (validated at UTXO creation).
   - Otherwise: `witness_slots(e) = 1`.

   Any unknown or future `covenant_type` encountered during cursor iteration MUST be rejected immediately
   as `TX_ERR_COVENANT_TYPE_INVALID`. The default `witness_slots = 1` applies only to known covenant types
   not listed above. Future covenant types MUST explicitly declare their `witness_slots` value in this document.

   Normative cursor algorithm (implementations MUST produce identical results):

   ```
   W := 0
   for i in 0 .. input_count-1:
       e := utxo_lookup(inputs[i].prev_txid, inputs[i].prev_vout)
       if e is missing: reject TX_ERR_MISSING_UTXO
       if e.covenant_type is unknown: reject TX_ERR_COVENANT_TYPE_INVALID
       slots := witness_slots(e.covenant_type, e.covenant_data)
       // witnesses[W .. W+slots-1] are assigned to input i
       W := W + slots
   if W != witness_count: reject TX_ERR_PARSE
   ```

   WitnessItems assigned to input `i` are: `T.witness.witnesses[W_i .. W_i+slots_i-1]`
   where `W_i` is the value of `W` before processing input `i`.

If multiple failures apply in this section, checks MUST be applied in the numbered order above.

For coinbase transaction `T` (the first transaction in a block at height `h = height(B)`):

1. `T` MUST satisfy `is_coinbase_tx(T)` (Section 10.5). Otherwise the block is invalid (`BLOCK_ERR_COINBASE_INVALID`).
2. `T.locktime` MUST equal `u32le(h)` (height-commitment). Otherwise the block is invalid (`BLOCK_ERR_COINBASE_INVALID`).

`locktime` has no general transaction-level semantics in this ruleset. The only consensus use of `locktime` is the
coinbase height-commitment above.

## 17. Replay-Domain Checks (Normative)

For each non-coinbase transaction `T` in block order:

1. Let `N_seen` be the set of `tx_nonce` values already observed in prior non-coinbase transactions of the same block.
2. If `T.tx_nonce` already appears in `N_seen`, reject as `TX_ERR_NONCE_REPLAY`.

Note on scope: `tx_nonce` replay protection is **intra-block only** — it prevents two transactions with the
same nonce from appearing in the same block. It does not provide cross-block replay protection.
Cross-block replay is prevented by a separate mechanism: UTXO exhaustion. Once an input outpoint is consumed,
it is removed from the spendable UTXO set and cannot be referenced again in any future block.
Additionally, including `tx_nonce` in `preimage_tx_sig` (Section 12) binds signatures to a specific nonce value,
eliminating nonce-malleability for otherwise identical transactions.
These are complementary mechanisms with different scopes.

## 18. UTXO State Model (Normative)

Define an outpoint as:

```text
Outpoint = (txid: bytes32, vout: u32le)
```

Define a spendable UTXO entry as:

```text
UtxoEntry = (value: u64, covenant_type: u16, covenant_data: bytes, creation_height: u64, created_by_coinbase: bool)
```

Let `U_h : Outpoint -> UtxoEntry` be the spendable UTXO map at chain height `h`.

State transition is defined by applying a block's transactions sequentially in block order:

```text
U_work := U_{h-1}
for i = 0..(tx_count-1):
  T := B_h.txs[i]
  if i = 0:
    U_work := ApplyCoinbase(U_work, T, h)
  else:
    U_work := SpendTx(U_work, T, B_h, h)
U_h := U_work
```

If any transaction application rejects with an error, the entire block is invalid and MUST NOT advance state.

### 18.1 Coinbase Maturity (Normative)

If a referenced UTXO entry `e` has `created_by_coinbase = true` and `h < e.creation_height + COINBASE_MATURITY`,
reject the spending transaction as `TX_ERR_COINBASE_IMMATURE`.

### 18.2 Covenant Evaluation (Genesis Covenants) (Normative)

For each non-coinbase input at index `i`, WitnessItems assigned to this input are determined
by the cursor model defined in Section 16.

Let `e = U_work[(prev_txid, prev_vout)]` be the referenced UTXO entry. If missing, reject as `TX_ERR_MISSING_UTXO`.

Then enforce:

1. If `e.covenant_type = CORE_P2PK`:
   - Let `w` be the single WitnessItem assigned to this input by the cursor model.
   - `w.suite_id` MUST be `SUITE_ID_ML_DSA_87 (0x01)` or `SUITE_ID_SLH_DSA_SHAKE_256F (0x02)`.
     Any other suite MUST be rejected as `TX_ERR_SIG_ALG_INVALID`.
   - If `w.suite_id = SUITE_ID_SLH_DSA_SHAKE_256F (0x02)` and `block_height < SLH_DSA_ACTIVATION_HEIGHT`,
     reject as `TX_ERR_SIG_ALG_INVALID`.
   - Require `len(e.covenant_data) = MAX_P2PK_COVENANT_DATA` and the first byte equals `w.suite_id`. Otherwise reject as
     `TX_ERR_COVENANT_TYPE_INVALID`.
   - Let `key_id = e.covenant_data[1:33]` (after the suite_id byte).
   - Require `SHA3-256(w.pubkey) = key_id`. Otherwise reject as `TX_ERR_SIG_INVALID`.
   - Require `verify_sig(w.suite_id, w.pubkey, w.signature, digest) = true` where `digest` is per Section 12.
     Otherwise reject as
     `TX_ERR_SIG_INVALID`.
2. If `e.covenant_type = CORE_VAULT`:
   - Evaluate per Section 14.1 using WitnessItems assigned by the cursor model.
3. If `e.covenant_type = CORE_MULTISIG`:
   - Evaluate per Section 14.2 using WitnessItems assigned by the cursor model.
4. If `e.covenant_type = CORE_HTLC`:
   - Evaluate per `spec/RUBIN_CORE_HTLC_SPEC.md` §5 using WitnessItems assigned by the cursor model.
5. If `e.covenant_type = CORE_ANCHOR`: this output is non-spendable. Any attempt to spend it MUST be rejected as
   `TX_ERR_MISSING_UTXO`.
6. Any other covenant type MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.

### 18.3 OutputDescriptorBytes (Normative)

`OutputDescriptorBytes` is the canonical serialization of a transaction output
used for `CORE_VAULT` whitelist membership hashing.

```text
OutputDescriptorBytes(output) =
    u16le(output.covenant_type) ||
    CompactSize(output.covenant_data_len) ||
    output.covenant_data
```

`output.value` is intentionally excluded so that whitelist entries are
independent of transfer amounts.

Normative definition for all `CORE_VAULT` whitelist computations:

```text
whitelist[j] = SHA3-256(OutputDescriptorBytes(output_j))
```

### 18.4 Output Creation Validation and UTXO Transition (Normative)

Output validation at creation is consensus-critical and MUST be applied before any new spendable output
is inserted into the UTXO map.

Define:

- `ValidateOutputAtCreation(out)` = Section 14 constraints for `out.covenant_type` and `out.covenant_data`.
- `IsSpendable(out)` is true iff `out.covenant_type` is neither `CORE_ANCHOR` nor `CORE_DA_COMMIT`.

#### `ApplyCoinbase(U_in, T, h)`

1. `T` MUST satisfy coinbase structural rules (Sections 10.5 and 16). Otherwise reject `BLOCK_ERR_COINBASE_INVALID`.
2. For each output `out` in index order:
   - run `ValidateOutputAtCreation(out)`; on failure reject with the first returned `TX_ERR_*`;
   - if `IsSpendable(out)`, add
     `U[(txid(T), vout_index)] = (value, covenant_type, covenant_data, creation_height=h, created_by_coinbase=true)`.

#### `SpendTx(U_in, T, B_h, h)`

1. Validate transaction-level structural rules and replay-domain rules (Sections 16 and 17).
2. For each output `out` in index order, run `ValidateOutputAtCreation(out)` first.
   On first failure reject with the returned `TX_ERR_*`.
3. Resolve and validate all referenced inputs against `U_in` (missing/non-spendable/maturity/covenant checks).
4. Remove spent outpoints from working state.
5. Apply value conservation and covenant spend checks (Sections 18.2 and 20).
6. Add new spendable outputs in `vout` order with `created_by_coinbase=false`.

If any step fails, the entire transaction application fails and no state update is committed.

## 19. Coinbase and Subsidy (Normative)

Every block MUST contain exactly one coinbase transaction and it MUST be the first transaction.

Any missing coinbase or additional coinbase transaction(s) MUST be rejected as `BLOCK_ERR_COINBASE_INVALID`.

### 19.1 Subsidy Schedule (Normative)

Let:

- `h` be the height of the block being validated.
- `already_generated(h)` be the sum of **subsidy only** (excluding fees) for coinbase transactions in heights `1..h-1`.
  - For `h = 0`, define `already_generated(0) = 0`.
- `remaining(h) = max(0, MINEABLE_CAP - already_generated(h))`.
- `base_reward(h) = remaining(h) >> EMISSION_SPEED_FACTOR`.

Define:

```text
block_subsidy(0) = 0
block_subsidy(h) = max(base_reward(h), TAIL_EMISSION_PER_BLOCK), for h > 0
```

Arithmetic MUST use integer operations only; no floating-point is permitted.

Notes (informative):

- `MAX_SUPPLY` is an emission anchor used to parameterize the mineable phase and tail emission magnitude. After tail activation,
  the total supply increases without a fixed hard cap.
- The tail constant `TAIL_EMISSION_PER_BLOCK` is fixed at genesis and is not computed from wall-clock time during consensus validation.

### 19.2 Coinbase Value Bound (Normative)

For a block at height `h > 0`:

```text
sum_coinbase_outputs_value <= block_subsidy(h) + sum_fees
```

Where `sum_fees` is:

```text
sum_fees = Σ (sum_in(T) - sum_out(T)) over all non-coinbase transactions T in the block
```

Genesis exception:

- For height `h = 0`, the coinbase value bound is not evaluated. Genesis outputs are chain-instance allocations fixed
  by the published genesis bytes.

Note (informative):

- A chain instance MAY encode genesis allocations with consensus-native restrictions (for example, distributing a treasury
  allocation across multiple `CORE_HTLC` outputs using refund height locks). This does not alter consensus rules; it is
  expressed entirely by the published genesis outputs.

If the coinbase value bound is violated, the block MUST be rejected as `BLOCK_ERR_SUBSIDY_EXCEEDED`.

## 20. Value Conservation (Normative)

For each non-coinbase transaction `T`:

1. Let `sum_in` be the sum of referenced input values.
2. Let `sum_out` be the sum of `T.outputs[j].value` over all outputs `j`.
3. Let `sum_in_vault` be the sum of referenced input values whose UTXO covenant type is `CORE_VAULT`.
4. If `sum_out > sum_in`, reject as `TX_ERR_VALUE_CONSERVATION`.
5. If `T` spends at least one `CORE_VAULT` input and `sum_out < sum_in_vault`,
   reject as `TX_ERR_VALUE_CONSERVATION`.
6. Arithmetic MUST be exact and MUST be computed in at least 128-bit unsigned integer arithmetic.
   Any overflow MUST be rejected as `TX_ERR_PARSE`.

## 21. DA Set Integrity (Normative)

These rules apply during block validation after all transaction parsing is complete.

### 21.1 Definitions

A **DA set** is identified by a `da_id` value (bytes32). A DA set consists of:
- Exactly one `DA_COMMIT_TX` (`tx_kind = 0x01`) whose `DaCommitCoreFields.da_id` equals the set's `da_id`.
- Exactly `chunk_count` `DA_CHUNK_TX` records (`tx_kind = 0x02`) whose `DaChunkCoreFields.da_id` equals the set's `da_id`,
  with `chunk_index` values `0, 1, ..., chunk_count - 1` each appearing exactly once.

### 21.2 Chunk Hash Integrity

For each `DA_CHUNK_TX` transaction `T` in a block:

- `T.da_core_fields.chunk_hash MUST equal SHA3-256(T.da_payload)`.
  If violated, reject the block as `BLOCK_ERR_DA_CHUNK_HASH_INVALID`.

### 21.3 Set Completeness (CheckBlock DA)

For each block `B`:

1. Let `commits` be the set of all `DA_COMMIT_TX` in `B`, keyed by `da_id`.
2. Let `chunks` be the multiset of all `DA_CHUNK_TX` in `B`, grouped by `da_id`.

Rules:

- **No orphan chunks:** Every `DA_CHUNK_TX` in `B` MUST have a corresponding `DA_COMMIT_TX` in `B` with the same `da_id`.
  If any `DA_CHUNK_TX` exists without a matching commit, reject as `BLOCK_ERR_DA_SET_INVALID`.

- **No duplicate commits:** For each `da_id` value, `B` MUST contain exactly one `DA_COMMIT_TX` with that `da_id`.
  If more than one `DA_COMMIT_TX` with the same `da_id` appears in `B`, reject as `BLOCK_ERR_DA_SET_INVALID`.

- **Complete sets only:** For every `DA_COMMIT_TX` with `chunk_count = C` and `da_id = D` in `B`,
  the block MUST contain exactly `C` `DA_CHUNK_TX` records with `da_id = D` and `chunk_index` values
  `{0, 1, ..., C-1}` each appearing exactly once.
  If any chunk is missing or duplicated, reject as `BLOCK_ERR_DA_INCOMPLETE`.

- **DA set count:** The number of distinct `da_id` values in `B` MUST be `<= MAX_DA_BATCHES_PER_BLOCK`.
  If exceeded, reject as `BLOCK_ERR_DA_BATCH_EXCEEDED`.

- **Chunk count per set:** For each `DA_COMMIT_TX`, `chunk_count MUST be <= MAX_DA_CHUNK_COUNT`.
  If exceeded, reject as `TX_ERR_PARSE`.

Note:
- `da_id` uniqueness is enforced per block only.
- Cross-block reuse of `da_id` is permitted by L1 consensus.
- Namespace separation across blocks is an L2 responsibility (`retl_domain_id` and application logic).

### 21.4 Payload Commitment Verification

For each `DA_COMMIT_TX` `T` with `chunk_count = C` and `da_id = D`:

- Let `chunks_sorted` be the `C` DA_CHUNK_TX records for `D` sorted by `chunk_index` ascending.
- `T` MUST contain **exactly one** `CORE_DA_COMMIT` output whose `covenant_data` equals
  `SHA3-256(concat(chunk.da_payload for chunk in chunks_sorted))`.
  If no such output exists, or if more than one `CORE_DA_COMMIT` output exists in `T`, reject as `BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID`.

This is the binding commitment that links the on-chain commit to the full DA payload.

## 22. Block Timestamp Rules (Normative)

Timestamp is a 64-bit unsigned integer representing seconds since UNIX epoch.

For block `B_h` with `h > 0`:

1. Let `k = min(11, h)` and define the multiset:

   ```text
   S_h = { timestamp(B_{h-1}), timestamp(B_{h-2}), ..., timestamp(B_{h-k}) }
   ```

2. Let `median(S_h)` be defined as:
   - sort `S_h` in non-decreasing order;
   - select the element at index `floor((|S_h| - 1)/2)` (the lower median).

3. `timestamp(B_h)` MUST be strictly greater than `median(S_h)`. If violated, reject as `BLOCK_ERR_TIMESTAMP_OLD`.

4. `timestamp(B_h)` MUST be `<= median(S_h) + MAX_FUTURE_DRIFT`. If violated, reject as `BLOCK_ERR_TIMESTAMP_FUTURE`.

Note (non-normative): unlike Bitcoin, the upper bound uses Median Time Past (`median(S_h)`) as baseline,
not node-local wall clock time. This keeps the timestamp rule fully deterministic across implementations.

Security note (non-normative): because both the lower and upper timestamp bounds are derived from Median Time Past,
block producers can influence chain time within the allowed window. In particular, an adversary who can
consistently dominate recent block production (or a material fraction of a retarget window) may gradually
advance `median(S_h)` and therefore advance accepted timestamps, which can bias `T_actual` in the difficulty
update procedure (Section 15). Per-window difficulty changes remain bounded by the retarget clamp (at most
4x increase or 4x decrease), but sustained dominance can bias difficulty over multiple windows. Implementations
MUST treat the block timestamp as miner-provided data constrained by consensus rules, not as a trusted wall-clock
time source; protocol time semantics should be expressed in block height where possible.

For genesis (`h = 0`), these rules are not evaluated.

## 23. Chainwork and Fork Choice (Non-Validation Procedure)

Fork choice is not part of block validity. Nodes select a canonical chain among valid candidates.

Define per-block work with unsigned arbitrary-precision arithmetic:

```text
work(B) = floor(2^256 / target(B))
```

Where:

- `target(B)` is parsed as an unsigned 256-bit big-endian integer from `header.target`.
- `target(B)` range is constrained by Section 10.3 to `1 <= target <= POW_LIMIT`.
- `2^256` MUST be represented exactly as an arbitrary-precision integer constant (not `u256`, not float).
- Implementations MUST NOT use floating-point arithmetic for work or chainwork.

Define cumulative chainwork:

```text
ChainWork(chain) = Σ work(B_i), i=0..n
```

`B_0` (genesis) is included in the sum.

Canonical chain selection (deterministic):

1. Prefer the valid chain with maximal `ChainWork`.
2. If `ChainWork` is equal, choose the chain whose tip `block_hash` is lexicographically smaller (bytewise big-endian).

### 23.1 Fork-Choice Test Vectors (Normative)

| Vector ID | Inputs | Expected |
| --- | --- | --- |
| CV-FC-01 | `target = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | `work = 0x1` |
| CV-FC-02 | `target = 0x8000000000000000000000000000000000000000000000000000000000000000` | `work = 0x2` |
| CV-FC-03 | Chain A targets: `[ff..ff, 80..00]`; Chain B targets: `[ff..ff, ff..ff, ff..ff]`; `tip_hash_A < tip_hash_B` | equal `ChainWork`, choose Chain A |
| CV-FC-04 | `target = 0x0000000000000000000000000000000000000000000000000000000000000001` | `work = 0x10000000000000000000000000000000000000000000000000000000000000000` |

### 23.2 Feature-Bit Activation Framework (Upgrade Procedure)

This framework defines how future consensus changes are coordinated using block header `version` signaling.
It is an upgrade procedure and does not change block validity unless a specific deployment is declared ACTIVE.

Default activation parameters (unless overridden by a deployment specification):

- `SIGNAL_WINDOW = 2016` blocks
- `SIGNAL_THRESHOLD = 1815` signaling blocks (90%)

A deployment descriptor MUST define:

- `name`
- `bit` (bit index in header `version`)
- `start_height`
- `timeout_height`

Signaling rule:

- A block `B_h` signals deployment bit `b` iff `((version(B_h) >> b) & 1) = 1`.

State machine (evaluated only at `SIGNAL_WINDOW` boundaries):

- `DEFINED` -> `STARTED` when `h >= start_height`.
- `STARTED` -> `LOCKED_IN` if signaling count in the previous full window is `>= SIGNAL_THRESHOLD`.
- `STARTED` -> `FAILED` if `h >= timeout_height` and lock-in was not reached.
- `LOCKED_IN` -> `ACTIVE` after one full additional window.
- `ACTIVE` and `FAILED` are terminal.

Operational constraints:

- Rollback is never automatic. Deactivation/replacement MUST use a new deployment.
- Nodes SHOULD expose telemetry for each deployment (`state`, signaling count per window, estimated activation height).

Current profile:

- No feature-bit deployments are ACTIVE by default in this document.

## 24. Determinism Requirements (Normative)

Consensus validity MUST be deterministic given the same chain state and the same block bytes.

- Implementations MUST NOT rely on non-deterministic iteration order (for example, hash-map iteration order).
- If any rule requires iterating over an unordered set/map, the iteration order MUST be defined as lexicographic order
  over the canonical key bytes for that collection.

### 24.1 CORE_VAULT Input Validation Order

For inputs spending `CORE_VAULT` (after standard Section 18 parse):

1. Parse `covenant_data`: verify `threshold`, `key_count`, `whitelist_count`, and data length.
2. Whitelist canonical order is checked at UTXO creation only and MUST NOT be re-checked at spend.
3. Assign `key_count` WitnessItems via the cursor model (Section 16).
4. Signature threshold check: count valid signatures and require `valid >= threshold`.
5. Whitelist membership check per output using binary search (`O(log W)`).
6. Value conservation, including strong vault fee-preservation rule (`sum_out >= sum_in_vault` for VAULT spends).

Short-circuit on first error.

## 25. Block Validation Order (Normative)

Implementations MUST apply validity checks in a deterministic order and return the first applicable error code.

Minimum required order for validating a candidate block `B_h` at height `h`:

1. Parse `BlockHeaderBytes` and all `TxBytes` encodings; any malformed encoding MUST reject as `BLOCK_ERR_PARSE` or the
   corresponding `TX_ERR_*` (Section 13).
2. Check header `target` range and PoW validity (Section 10.3):
   - if `target` is out of range, reject as `BLOCK_ERR_TARGET_INVALID`;
   - otherwise, if PoW is invalid, reject as `BLOCK_ERR_POW_INVALID`.
3. Check the header `target` matches the expected target (Section 15). If mismatch, reject as `BLOCK_ERR_TARGET_INVALID`.
4. Check `prev_block_hash` linkage against the selected parent block hash. If invalid, reject as `BLOCK_ERR_LINKAGE_INVALID`.
5. Check `merkle_root` matches the Merkle root computed from transaction `txid` values (Section 10.4). If invalid, reject
   as `BLOCK_ERR_MERKLE_INVALID`.
6. Check coinbase witness commitment (Section 10.4.1). If missing or duplicated, reject as `BLOCK_ERR_WITNESS_COMMITMENT`.
7. Check block timestamp rules (Section 22). If invalid, reject as `BLOCK_ERR_TIMESTAMP_OLD` or `BLOCK_ERR_TIMESTAMP_FUTURE`.
8. Check total block weight (Section 9). If exceeded, reject as `BLOCK_ERR_WEIGHT_EXCEEDED`.
9. Check per-block ANCHOR byte limits (Section 14). If exceeded, reject as `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED`.
10. Check DA chunk hash integrity (Section 21.2). If any chunk_hash mismatch, reject as `BLOCK_ERR_DA_CHUNK_HASH_INVALID`.
11. Check DA set completeness (Section 21.3): no orphan chunks, complete sets, DA set count. Reject as applicable.
12. Check DA payload commitment (Section 21.4). If mismatch or ambiguous (missing or duplicate CORE_DA_COMMIT output), reject as `BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID`.
13. Apply transactions sequentially using `ApplyCoinbase`/`SpendTx` semantics (Section 18.4), enforcing:
   - coinbase structural rules (Sections 10.5 and 16),
   - transaction structural rules (Section 16),
   - replay-domain checks (Section 17),
   - output creation validation at insertion time (Sections 14 and 18.4),
   - covenant evaluation (Section 18.2),
   - coinbase subsidy/value bound (Section 19),
   - value conservation (Section 20).
