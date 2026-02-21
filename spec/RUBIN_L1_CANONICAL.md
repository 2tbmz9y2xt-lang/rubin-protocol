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
- `MAX_TX_INPUTS = 1024`
- `MAX_TX_OUTPUTS = 1024`
- `MAX_WITNESS_ITEMS = 1024`
- `MAX_WITNESS_BYTES_PER_TX = 100_000`
- `MAX_SCRIPT_SIG_BYTES = 32`

PQC witness canonical sizes (genesis profile):

- `SUITE_ID_ML_DSA_87 = 0x01`
  - `ML_DSA_87_PUBKEY_BYTES = 2592`
  - `ML_DSA_87_SIG_BYTES = 4627`
- `SUITE_ID_SLH_DSA_SHAKE_256F = 0x02`
  - `SLH_DSA_SHAKE_256F_PUBKEY_BYTES = 64`
  - `MAX_SLH_DSA_SIG_BYTES = 49_856`

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

