# RUBIN L1 CANONICAL (DRAFT)

This document is consensus-critical. All requirements expressed with MUST / MUST NOT are mandatory for
consensus validity.

## 1. Genesis Rule (Wire Version)

- The chain uses **transaction wire v2 at genesis**.
- There is no activation height and no VERSION_BITS gate for wire versions.
- Any node that does not implement Transaction Wire v2 cannot validate the chain.

## 2. Primitive Encodings

### 2.1 Integers

- `u8`: 1 byte
- `u16le`: 2 bytes, little-endian
- `u32le`: 4 bytes, little-endian
- `u64le`: 8 bytes, little-endian

### 2.2 Byte Strings

- `bytesN`: exactly N raw bytes.
- `bytes[L]`: exactly L raw bytes.

## 3. CompactSize (Varint)

CompactSize encodes an unsigned integer `n` in 1, 3, 5, or 9 bytes:

- If `n < 0xfd`: encode as `[u8(n)]`.
- If `0xfd <= n <= 0xffff`: encode as `[0xfd] || u16le(n)`.
- If `0x1_0000 <= n <= 0xffff_ffff`: encode as `[0xfe] || u32le(n)`.
- If `0x1_0000_0000 <= n <= 0xffff_ffff_ffff_ffff`: encode as `[0xff] || u64le(n)`.

Canonical rule (minimality):

- CompactSize values MUST be minimally encoded. Any non-minimal encoding MUST be rejected as `TX_ERR_PARSE`.

## 4. Consensus Constants (Wire-Level)

These constants are consensus-critical defaults for the genesis ruleset:

- `TX_WIRE_VERSION = 2`
- `WITNESS_DISCOUNT_DIVISOR = 4`
- `MAX_TX_INPUTS = 1024`
- `MAX_TX_OUTPUTS = 1024`
- `MAX_WITNESS_ITEMS = 1024`
- `MAX_WITNESS_BYTES_PER_TX = 100_000`
- `MAX_SCRIPT_SIG_BYTES = 32`
- `MAX_BLOCK_WEIGHT = 4_000_000` weight units
- `MAX_ANCHOR_PAYLOAD_SIZE = 65_536` bytes
- `MAX_ANCHOR_BYTES_PER_BLOCK = 131_072` bytes

PQC witness canonical sizes (genesis profile):

- `SUITE_ID_ML_DSA_87 = 0x01`
  - `ML_DSA_87_PUBKEY_BYTES = 2592`
  - `ML_DSA_87_SIG_BYTES = 4627`
- `SUITE_ID_SLH_DSA_SHAKE_256F = 0x02`
  - `SLH_DSA_SHAKE_256F_PUBKEY_BYTES = 64`
  - `MAX_SLH_DSA_SIG_BYTES = 49_856`

Signature verification cost weights (genesis profile):

- `VERIFY_COST_ML_DSA_87 = 8`
- `VERIFY_COST_SLH_DSA_SHAKE_256F = 64`

Keyless sentinel witness:

- `SUITE_ID_SENTINEL = 0x00` (reserved; MUST NOT be used for cryptographic verification)

## 5. Transaction Wire v2

### 5.1 Transaction Data Structures

```text
TxV2 {
  version : u32le
  tx_kind : u8
  tx_nonce : u64le
  input_count : CompactSize
  inputs[] : TxInput[input_count]
  output_count : CompactSize
  outputs[] : TxOutput[output_count]
  locktime : u32le
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
```

### 5.2 `tx_kind`

`tx_kind` is an explicit transaction kind selector:

- `0x00`: standard transaction (no DA).
- `0x01`: reserved (future).
- `0x02`: reserved (future).

Rules:

- For genesis ruleset, `tx_kind` MUST equal `0x00`. Any other value MUST be rejected as `TX_ERR_PARSE`.
- For `tx_kind = 0x00`, `da_payload_len` MUST equal `0`. Any other value MUST be rejected as `TX_ERR_PARSE`.

### 5.3 Syntax Limits (Parsing)

For any transaction `T`:

1. `T.version` MUST equal `TX_WIRE_VERSION`. Otherwise reject as `TX_ERR_PARSE`.
2. `input_count MUST be <= MAX_TX_INPUTS`. Otherwise reject as `TX_ERR_PARSE`.
3. `output_count MUST be <= MAX_TX_OUTPUTS`. Otherwise reject as `TX_ERR_PARSE`.
4. `script_sig_len MUST be <= MAX_SCRIPT_SIG_BYTES`. Otherwise reject as `TX_ERR_PARSE`.
5. `witness.witness_count MUST be <= MAX_WITNESS_ITEMS`. Otherwise reject as `TX_ERR_WITNESS_OVERFLOW`.
6. `WitnessBytes(T.witness) MUST be <= MAX_WITNESS_BYTES_PER_TX`. Otherwise reject as `TX_ERR_WITNESS_OVERFLOW`.

Where `WitnessBytes(WitnessSection)` is the exact serialized byte length of:

```text
CompactSize(witness_count) || concat(witness_item_bytes[i] for i in [0..witness_count-1])
```

### 5.4 Witness Item Canonicalization (Parsing)

Witness items are parsed and checked for canonical form:

- If `suite_id = SUITE_ID_SENTINEL (0x00)`:
  - `pubkey_length MUST equal 0` and `sig_length MUST equal 0`; otherwise reject as `TX_ERR_PARSE`.
- If `suite_id = SUITE_ID_ML_DSA_87 (0x01)`:
  - `pubkey_length MUST equal ML_DSA_87_PUBKEY_BYTES` and `sig_length MUST equal ML_DSA_87_SIG_BYTES`;
    otherwise reject as `TX_ERR_SIG_NONCANONICAL`.
- If `suite_id = SUITE_ID_SLH_DSA_SHAKE_256F (0x02)`:
  - `pubkey_length MUST equal SLH_DSA_SHAKE_256F_PUBKEY_BYTES` and
    `0 < sig_length <= MAX_SLH_DSA_SIG_BYTES`; otherwise reject as `TX_ERR_SIG_NONCANONICAL`.
- Any other `suite_id` MUST be rejected as `TX_ERR_SIG_ALG_INVALID`.

## 6. Canonical Encode/Parse Invariant

For any valid transaction `T`, serialization and parsing MUST be mutually inverse:

```text
parse_tx_v2(serialize_tx_v2(T)) = T
```

## 7. Deterministic Parse Error Mapping (Wire)

If multiple parsing errors exist, implementations MUST apply checks in this order and reject with the first
applicable error code:

1. CompactSize minimality and integer decode bounds (`TX_ERR_PARSE`).
2. `version` / `tx_kind` / `da_payload_len` rules (`TX_ERR_PARSE`).
3. Input/output/script_sig length bounds (`TX_ERR_PARSE`).
4. Witness section item count / total bytes bounds (`TX_ERR_WITNESS_OVERFLOW`).
5. Witness item canonicalization (`TX_ERR_PARSE` / `TX_ERR_SIG_NONCANONICAL` / `TX_ERR_SIG_ALG_INVALID`).

No cryptographic verification is performed in this section. Signature verification, covenant evaluation, and
value/binding rules are specified in later sections.

## 8. Transaction Identifiers (TXID / WTXID)

### 8.1 Hash Function

RUBIN uses `SHA3-256` (FIPS 202) as the consensus hash function.

### 8.2 Canonical Transaction Serializations

For any valid transaction `T` (i.e. one that parses under Transaction Wire v2 with all rules in Sections 3-7):

`TxCoreBytes(T)` is defined as the canonical serialization of:

```text
u32le(T.version) ||
u8(T.tx_kind) ||
u64le(T.tx_nonce) ||
CompactSize(T.input_count) ||
concat(T.inputs[i] for i in [0..input_count-1]) ||
CompactSize(T.output_count) ||
concat(T.outputs[j] for j in [0..output_count-1]) ||
u32le(T.locktime)
```

Where each `TxInput` and `TxOutput` is serialized exactly as in Section 5.1, and all `CompactSize` values MUST be
minimally encoded (see Section 3).

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
ml_count  = count witness items where suite_id = SUITE_ID_ML_DSA_87
slh_count = count witness items where suite_id = SUITE_ID_SLH_DSA_SHAKE_256F
sig_cost  = ml_count * VERIFY_COST_ML_DSA_87 + slh_count * VERIFY_COST_SLH_DSA_SHAKE_256F
weight(T) = WITNESS_DISCOUNT_DIVISOR * base_size + wit_size + sig_cost
```

Notes:

- `WITNESS_DISCOUNT_DIVISOR = 4` discounts witness bytes relative to non-witness bytes.
- `sig_cost` exists to account for CPU verification work that is not captured by byte length alone.

For any block `B` with transactions `B.txs[]`:

```text
sum_weight = sum(weight(T) for each transaction T in B.txs)
```

`sum_weight MUST be <= MAX_BLOCK_WEIGHT`. Otherwise the block is invalid.

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
  txs: TxV2[tx_count]
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

### 10.5 Coinbase Basics (Structural)

Every block MUST contain exactly one coinbase transaction and it MUST be the first transaction.

Define `is_coinbase_tx(T)` for `TxV2` as:

- `T.input_count = 1`, and
- `T.inputs[0].prev_txid` is 32 zero bytes, and
- `T.inputs[0].prev_vout = 0xffff_ffff`, and
- `T.inputs[0].script_sig_len = 0`, and
- `T.inputs[0].sequence = 0xffff_ffff`, and
- `T.witness.witness_count = 0`, and
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
chain_id = SHA3-256(serialized_genesis_without_chain_id_field)
```

Where `serialized_genesis_without_chain_id_field` is:

```text
ASCII("RUBIN-GENESIS-v2") ||
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
hash_of_da_core_fields = SHA3-256("")   # genesis tx_kind=0x00 has no DA core fields
hash_of_all_prevouts = SHA3-256(concat(inputs[i].prev_txid || u32le(inputs[i].prev_vout) for i in [0..input_count-1]))
hash_of_all_sequences = SHA3-256(concat(u32le(inputs[i].sequence) for i in [0..input_count-1]))
hash_of_all_outputs = SHA3-256(concat(outputs[j] in TxOutput wire order for j in [0..output_count-1]))
```

For `output_count = 0`, `hash_of_all_outputs = SHA3-256("")`.

Preimage and digest:

```text
preimage_tx_sig =
  ASCII("RUBINv2-sighash/") ||
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

## 13. Consensus Error Codes (Normative)

The following error codes are consensus-critical and MUST be returned identically by all conforming
implementations for the described failure classes:

- Non-minimal CompactSize                          -> `TX_ERR_PARSE`
- Malformed witness encoding                       -> `TX_ERR_PARSE`
- Cryptographically invalid signature              -> `TX_ERR_SIG_INVALID`
- Invalid signature type                           -> `TX_ERR_SIG_ALG_INVALID`
- Invalid signature length / non-canonical witness -> `TX_ERR_SIG_NONCANONICAL`
- Witness overflow                                 -> `TX_ERR_WITNESS_OVERFLOW`
- Invalid covenant_type / covenant encoding        -> `TX_ERR_COVENANT_TYPE_INVALID`
- Missing UTXO / attempt to spend non-spendable    -> `TX_ERR_MISSING_UTXO`
- Timelock condition not met                       -> `TX_ERR_TIMELOCK_NOT_MET`
- Invalid prev_block_hash linkage                  -> `BLOCK_ERR_LINKAGE_INVALID`
- Invalid merkle_root                              -> `BLOCK_ERR_MERKLE_INVALID`
- PoW invalid                                      -> `BLOCK_ERR_POW_INVALID`
- Weight exceedance                                -> `BLOCK_ERR_WEIGHT_EXCEEDED`
- Anchor bytes exceeded                            -> `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED`
- Malformed block encoding                         -> `BLOCK_ERR_PARSE`

Error priority (short-circuit):

- Implementations MUST apply checks in the validation order and return the first applicable error code.
- Signature verification MUST NOT be attempted if prior parsing, covenant, timelock, or UTXO rules already
  cause rejection.

## 14. Covenant Type Registry (Normative)

The following `covenant_type` values are valid at genesis:

- `0x0000` `CORE_P2PK`
- `0x0001` `CORE_TIMELOCK_V1`
- `0x0002` `CORE_ANCHOR`
- `0x00ff` `CORE_RESERVED_FUTURE`

Any unknown or future `covenant_type` MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.

Semantics:

- `CORE_P2PK`:
  - `covenant_data = suite_id:u8 || key_id:bytes32`.
  - `covenant_data_len MUST equal 33`.
  - Spend authorization requires a witness item whose `suite_id` matches and whose `pubkey` hashes to `key_id`,
    and a valid signature over `digest` (Section 12).
  - `key_id = SHA3-256(pubkey)` where `pubkey` is the canonical witness public key byte string for the selected
    `suite_id` (no extra length prefixes are included).
- `CORE_TIMELOCK_V1`:
  - `covenant_data = lock_mode:u8 || lock_value:u64le`.
  - `covenant_data_len MUST equal 9`.
  - `lock_mode = 0x00` means height lock; `lock_mode = 0x01` means timestamp lock.
  - Spend is forbidden until the corresponding lock condition is satisfied by the current validated chain state;
    otherwise reject as `TX_ERR_TIMELOCK_NOT_MET`.
- `CORE_ANCHOR`:
  - `covenant_data = anchor_data` (raw bytes, no additional wrapping).
  - `0 < covenant_data_len <= MAX_ANCHOR_PAYLOAD_SIZE` MUST hold; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
  - `value MUST equal 0`; otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.
  - `CORE_ANCHOR` outputs are non-spendable and MUST NOT be added to the spendable UTXO set. Any attempt to spend an
    ANCHOR output MUST be rejected as `TX_ERR_MISSING_UTXO`.
  - Per-block constraint: sum of `covenant_data_len` across all `CORE_ANCHOR` outputs in a block MUST be
    `<= MAX_ANCHOR_BYTES_PER_BLOCK`; otherwise reject the block as `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED`.
- `CORE_RESERVED_FUTURE`:
  - Forbidden at genesis; any appearance MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.
