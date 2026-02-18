# RUBIN L1 Canonical Specification v1.1

Status: CANONICAL  
Model: Fully Permissionless  
Scope: L1 consensus + byte-anchored RETL envelope. RETL domain identity and constraints are defined; RETL semantics are application-layer.  
Date: 2026-02-15

This file is normative.

## 1. Canonical Protocol Data and Constants

### 1.1 Consensus identity and genesis

- `chain_id` is defined once and only once as:

```
chain_id = SHA3-256(serialized_genesis_without_chain_id_field)
```

- `chain_id` is immutable for this spec version and is part of the consensus domain separation.

#### 1.1.1 Genesis serialization (Normative)

`serialized_genesis_without_chain_id_field` is defined as:

```
ASCII("RUBIN-GENESIS-v1") ||
BlockHeaderBytes(genesis_header) ||
CompactSize(genesis_tx_count) ||
TxBytes(genesis_txs[0]) || ... || TxBytes(genesis_txs[genesis_tx_count-1])
```

Constraints:

1. Genesis MUST contain exactly one transaction and it MUST be a coinbase transaction as defined in §3.1.
2. Genesis MUST contain no CORE_ANCHOR outputs.
3. `TxBytes(T)` is the full transaction wire encoding including the witness section (which is empty for coinbase in this profile).
4. `BlockHeaderBytes` is as defined in §5.1 and MUST be used verbatim (including `target` bytes).
5. This definition is chain-instance specific: mainnet/testnet/devnet differ only by their chosen genesis bytes; protocol rules are otherwise identical.

Development status note (non-normative):

- During early development, the spec defines the genesis serialization function but does not fix concrete genesis bytes.
- Any concrete network (devnet/testnet/mainnet) MUST publish a chain-instance profile that fixes the exact genesis bytes (or genesis header/tx bytes) so all clients derive the same `chain_id`.

### 1.2 Consensus constants

- `COINBASE_MATURITY = 100`
- `TARGET_BLOCK_INTERVAL = 600` seconds
- `MAX_BLOCK_WEIGHT = 4_000_000` weight units
- `MAX_ANCHOR_BYTES_PER_BLOCK = 131_072` bytes
- `MAX_ANCHOR_PAYLOAD_SIZE = 65_536` bytes
- `WINDOW_SIZE = 2_016` blocks (difficulty/activation window)
- `MAX_FUTURE_DRIFT = 7_200` seconds
- `SIGNAL_WINDOW = 2_016` blocks
- `THRESHOLD = 1_916` signals
- `VERSION_BITS_START_HEIGHT = 0` blocks
- `K_CONFIRM_L1 = 8` (non-consensus recommended parameter)
- `K_CONFIRM_BRIDGE = 12` (non-consensus recommended parameter)
- `K_CONFIRM_GOV = 16` (non-consensus recommended parameter)
- `BLOCK_SUBSIDY_INITIAL = 5_000_000_000`
- `SUBSIDY_HALVING_INTERVAL = 210_000`
- `MAX_SUPPLY = 2_100_000_000_000_000`

Non-normative note (emission schedule and genesis intent): total supply target is
100,000,000 RBN (`MAX_SUPPLY = 2_100_000_000_000_000` base units; 1 RBN = 21_000_000
base units).

Under the v1.1 subsidy schedule (mined emission only, excluding any genesis allocations),
the discrete halving schedule over 34 epochs (epoch 0..33) yields a theoretical maximum
mined emission of `2_099_999_997_690_000` base units, which is `2_310_000` base units
below `MAX_SUPPLY`. Epoch 32 subsidy = 1 base unit (last non-zero); epoch 33+ = 0.

Genesis allocations (e.g., premine / unspendables) are chain-instance decisions. Current
v1.1 chain-instance profiles contain a placeholder genesis with 0 outputs pending final
ceremony (see `spec/TODO_ECONOMICS_AND_GENESIS.md`). If genesis outputs are introduced,
emission parameters MUST be revised in a future canonical revision to keep the total
supply target consistent.

Full subsidy formula: §4.5.
- `MAX_TX_INPUTS = 1_024`
- `MAX_TX_OUTPUTS = 1_024`
- `MAX_WITNESS_ITEMS = 1_024`
- `MAX_WITNESS_ITEM_BYTES = 65_000` (non-consensus relay policy)
- `MAX_WITNESS_BYTES_PER_TX = 100_000`
- `MAX_ML_DSA_SIGNATURE_BYTES = 4_627`
- `MAX_SLH_DSA_SIG_BYTES = 49_856`
- `VERIFY_COST_ML_DSA = 8`
- `VERIFY_COST_SLH_DSA = 64`
- `MAX_P2PK_COVENANT_DATA = 33`
- `MAX_TIMELOCK_COVENANT_DATA = 9`
- `MAX_VAULT_COVENANT_DATA = 81`
- `MAX_RELAY_MSG_BYTES = 8_388_608`
- `MIN_RELAY_FEE_RATE = 1` (non-consensus relay policy)

All implementations MUST treat consensus-valued entries in this section as fixed for v1.1.
`MAX_WITNESS_ITEM_BYTES`, `MAX_RELAY_MSG_BYTES`, and `MIN_RELAY_FEE_RATE` are relay-policy constraints and may be adjusted by application governance only outside consensus.

## 2. Formal State Model

Let:

- \( \mathcal{U}_h : \mathcal{O} \to \mathrm{UtxoEntry} \) be the spendable UTXO map at height \(h\).
- \( \mathcal{S}_h = \mathcal{U}_h \) denote the protocol state at height \(h\).
- \( \mathcal{B}_h \) be the block at height \(h\).

Define:

```
UtxoEntry = (value, covenant_type, covenant_data, creation_height, created_by_coinbase)
```

State transition is:

```
\mathcal{S}_h = ApplyBlock(\mathcal{S}_{h-1}, \mathcal{B}_h)
```

and is defined sequentially over transactions in block order:

```
\mathcal{U}^{work} := \mathcal{U}_{h-1}

for i = 0..(\mathcal{B}_h.txs.count-1):
  T := \mathcal{B}_h.txs[i]
  is_coinbase := (i = 0)
  \mathcal{U}^{work} := SpendTx(\mathcal{U}^{work}, T, h, is_coinbase)

\mathcal{U}_h := \mathcal{U}^{work}
```

where:

1. `SpendTx(U, T, h, is_coinbase)` removes all input outpoints of `T` from `U` and adds all **spendable** outputs of `T` with `creation_height = h` and `created_by_coinbase = is_coinbase`.
2. Non-spendable covenant outputs (e.g., `CORE_ANCHOR`) are never added to the spendable UTXO set.
3. This sequential definition permits intra-block spending: a later transaction in the same block MAY spend a spendable output created by an earlier transaction in the same block.

### 2.1 Key material and script-binding

- `ML-DSA-87` public keys are 2592-byte wire values.
- `SLH-DSA-SHAKE-256f` public keys are 64-byte wire values.
- `ML-DSA-87` signatures are fixed 4,627-byte wire values.
- `SLH-DSA-SHAKE-256f` signatures are bounded by `MAX_SLH_DSA_SIG_BYTES`.
- An output authorization reference is the canonical key hash:

```
key_id = SHA3-256(pubkey)
```

- Address encoding, key-rotation lifecycle, and policy throttling are protocol-application decisions; L1 validation checks only that witness public keys are correctly typed and verify signatures. Address binding rules are specified in `spec/RUBIN_L1_KEY_MANAGEMENT_v1.1.md`.

Canonical wire lengths and key identifiers used by consensus:

- `ml_dsa_pubkey_bytes = 2592`
- `slh_dsa_pubkey_bytes = 64`
- `ml_dsa_sig_len = MAX_ML_DSA_SIGNATURE_BYTES`
- `slh_dsa_sig_max_len = MAX_SLH_DSA_SIG_BYTES`
- `key_id = SHA3-256(pubkey)`
- `script_sig` is reserved and non-functional in this profile, except where explicitly specified (see `CORE_HTLC_V1`).

### 2.2 Key management and address binding

- L1-consensus requires only `pubkey`, `key_id`, and `signature` validation.
- `ML-DSA-87` public key wire format is exactly 2592 bytes.
- `SLH-DSA-SHAKE-256f` public key wire format is exactly 64 bytes.
- L1-consensus does not define version bytes for addresses.
- A validator MUST treat key identifiers as 32-byte `key_id`.
- `key_id` is computed as:

```
key_id = SHA3-256(pubkey)
```

- Where `pubkey` is the **canonical wire value** of the witness public key for the selected `suite_id`
  (e.g., exactly 2592 bytes for `ML-DSA-87`, exactly 64 bytes for `SLH-DSA-SHAKE-256f`).
  The `suite_id` byte and any witness length prefixes are NOT included in `key_id` derivation.

- `address_version = 0x00` for `ML-DSA-87` key binding.
- `address_version = 0x01` for `SLH-DSA-SHAKE-256f` key binding.
- `key_id_wire = address_version || key_id` is used for address display and external identification.
- Consensus witness binding checks use `key_id` (32 bytes) only. `address_version` is non-consensus.
- Address encoding formats and wallet UX are protocol-application decisions.
- `bech32m("rbin", key_id_wire)` is RECOMMENDED for non-consensus display.

- Key update and revocation policies are outside L1 consensus and enforced by application logic.

For protocol implementations:

- key generators SHOULD use ≥256-bit cryptographic entropy for seed material;
- key serialization MUST be deterministic and byte-for-byte stable;
- key_id reuse is application policy unless constrained by script semantics;
- key_revocation and key rotation are not consensus-visible fields.

## 3. Deterministic Transaction and Block Processing

### 3.1 Transaction format

```
Tx {
  version : u32le
  tx_nonce : u64le
  input_count : CompactSize
  inputs[]
  output_count : CompactSize
  outputs[]
  locktime : u32le
  witness : WitnessSection
}

TxInput {
  prevout : OutPoint
  script_sig_len : CompactSize
  script_sig : bytes[script_sig_len]
  sequence : u32le
}

OutPoint ::= prev_txid : bytes32 || prev_vout : u32le

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

For each input, exactly one witness item corresponds to its authorization data by index.

`script_sig` is reserved by default:

- For any input spending a non-HTLC covenant, `script_sig_len` MUST be 0.
- For an input spending `CORE_HTLC_V1`, `script_sig_len` MUST be either:
  - `0` (refund path), or
  - `32` (claim path; `script_sig` carries the 32-byte preimage).
- For an input spending `CORE_HTLC_V2`, `script_sig_len` MUST be `0`.
  The preimage is delivered via a `CORE_ANCHOR` envelope output in the same transaction (see §3.6 and §4 rule 4a).

For covenant types that do not require key-based authorization (`CORE_TIMELOCK_V1`),
the corresponding witness item MUST be a sentinel:

```
Sentinel WitnessItem {
  suite_id = 0x00
  pubkey_length = 0
  pubkey = (empty)
  sig_length = 0
  signature = (empty)
}
```

For `CORE_TIMELOCK_V1` spends, any non-sentinel witness item (`suite_id != 0x00`) MUST be rejected as `TX_ERR_SIG_ALG_INVALID`.

`suite_id = 0x00` is reserved as the sentinel value and MUST NOT be used for cryptographic verification.
If `suite_id = 0x00` then `pubkey_length` MUST equal 0 and `sig_length` MUST equal 0; any violation MUST be rejected as `TX_ERR_PARSE`.

Transaction syntax limits:

1. `input_count ≤ MAX_TX_INPUTS`.
2. `output_count ≤ MAX_TX_OUTPUTS`.
3. `witness.witness_count ≤ MAX_WITNESS_ITEMS`. Any violation MUST be rejected as `TX_ERR_WITNESS_OVERFLOW`.
4. `|WitnessBytes(T.witness)| ≤ MAX_WITNESS_BYTES_PER_TX`. Any violation MUST be rejected as `TX_ERR_WITNESS_OVERFLOW`.
5. For each witness item, signature lengths MUST be bounded by the configured profile. Any violation MUST be rejected as `TX_ERR_SIG_NONCANONICAL`:
   - `suite_id = 0x01`: `sig_length = 4_627`;
   - `suite_id = 0x02`: `0 < sig_length ≤ MAX_SLH_DSA_SIG_BYTES`.
6. `|witness.witnesses|` is bounded by protocol limits under the block weight constraints in §4.3.

> **Non-normative note — effective maximum inputs per transaction (v1.1):**
> The practical upper bound on inputs is determined by `MAX_WITNESS_BYTES_PER_TX = 100_000`
> (consensus, §1.2), not by `MAX_TX_INPUTS = 1_024` or `MAX_BLOCK_WEIGHT`.
> With canonical v1.1 key sizes:
> - `suite_id = 0x01` (ML-DSA-87): pubkey 2592 B + sig 4627 B → **≤ 13 inputs** per transaction
>   (13 inputs ≈ 93,913 witness bytes; 14 inputs would exceed `MAX_WITNESS_BYTES_PER_TX`).
> - `suite_id = 0x02` (SLH-DSA-SHAKE-256f): pubkey 64 B + sig 49856 B → **≤ 2 inputs** per transaction
>   (2 inputs ≈ 99,851 witness bytes; 3 inputs would exceed `MAX_WITNESS_BYTES_PER_TX`).
> - `suite_id = 0x00` (sentinel / TIMELOCK): witness is zero-length → up to `MAX_TX_INPUTS = 1_024` inputs,
>   but each such transaction has `sig_cost = 0` and weighs ~334 wu (1-in/1-out),
>   making mempool rate-limiting necessary (see node policy §1.4).
>
> Wallet implementations SHOULD respect these effective caps when constructing transactions
> to avoid consensus rejection (`TX_ERR_WITNESS_OVERFLOW`). These bounds shift if
> `MAX_WITNESS_BYTES_PER_TX` changes in a future canonical revision.

Witness is excluded from `txid` (consensus-critical serialization rule). `sighash` is computed from the transaction fields and `chain_id` per §4.2; it does not include the witness section bytes.

`TxNoWitnessBytes(T)` and `TxBytes(T)` are defined as:

```
TxNoWitnessBytes(T) =
  u32le(T.version) ||
  u64le(T.tx_nonce) ||
  CompactSize(T.input_count) ||
  concat(inputs[i] encoded in the TxInput wire format of §3.1 for i in [0..input_count-1]) ||
  CompactSize(T.output_count) ||
  concat(outputs[j] encoded in the TxOutput wire format of §3.1 for j in [0..output_count-1]) ||
  u32le(T.locktime)

TxBytes(T) = TxNoWitnessBytes(T) || WitnessBytes(T.witness)
```

For each non-coinbase input `i`:

1. `witness.witness_count` MUST equal `input_count`.
2. `prevout` MUST be present and well-formed.
3. `script_sig` MUST be empty (`script_sig_len = 0`).
4. In v1.1, `prevout` MUST NOT be all-zero (`prev_txid=0` and `prev_vout=0xffffffff`) for any non-coinbase input.
5. `sequence` MUST be between 0 and 0x7fffffff.
6. `witness.witnesses[i]` MUST be a canonical `WitnessItem`.
7. All input outpoints within a single transaction MUST be unique. Duplicate input outpoints MUST be rejected as `TX_ERR_PARSE`.

For coinbase:

1. `input_count = 1`.
2. The single `prevout` MUST be all-zero `prev_txid` and `prev_vout = 0xffffffff`.
3. `witness.witness_count = 0`.
4. `tx_nonce = 0`.
5. `sequence` for the coinbase input MUST be `0xffffffff`.
6. `script_sig_len` for the coinbase input MUST be `0`.
7. `locktime` MUST equal `height(B)` where `B` is the block containing this coinbase transaction (see §5.1.2).

`locktime` is committed to in `txid` and `sighash`, but has no general transaction-level consensus semantics in v1.1.
The only consensus use of `locktime` in v1.1 is coinbase uniqueness (rule 7 above). Future revisions may define additional semantics.

### 3.2 Canonical encoding rules

1. All `CompactSize` values MUST be minimally encoded.
2. Parsing and serialization are mutually inverse for valid encodings:

```
parse(serialize(x)) = x
```

3. Deterministic failure code mapping is normative and defined in §3.3.

#### 3.2.1 CompactSize encoding (Normative)

`CompactSize` is encoded as:

1. If `n < 253`, encode as single byte `u8(n)`.
2. If `253 ≤ n ≤ 0xffff`, encode as `0xfd || u16le(n)`.
3. If `0x1_0000 ≤ n ≤ 0xffff_ffff`, encode as `0xfe || u32le(n)`.
4. If `0x1_0000_0000 ≤ n ≤ 0xffff_ffff_ffff_ffff`, encode as `0xff || u64le(n)`.

Minimal encoding rule:

- Any value encoded with a longer form than required by the ranges above MUST be rejected as `TX_ERR_PARSE`.

### 3.3 Consensus Error Mapping (Normative)

The following error codes are consensus-critical and MUST be returned identically by all
conforming implementations:

- Non-minimal CompactSize              → `TX_ERR_PARSE`
- Malformed witness encoding           → `TX_ERR_PARSE`
- Duplicate input outpoint             → `TX_ERR_PARSE`
- Cryptographically invalid signature  → `TX_ERR_SIG_INVALID`
- Output value > input value           → `TX_ERR_VALUE_CONSERVATION`
- Invalid tx_nonce                     → `TX_ERR_TX_NONCE_INVALID`
- Invalid sequence number              → `TX_ERR_SEQUENCE_INVALID`
- Invalid covenant_type               → `TX_ERR_COVENANT_TYPE_INVALID`
- Invalid CORE_ANCHOR output encoding → `TX_ERR_COVENANT_TYPE_INVALID`
- Missing UTXO                        → `TX_ERR_MISSING_UTXO`
- Coinbase immature                    → `TX_ERR_COINBASE_IMMATURE`
- Deployment inactive                  → `TX_ERR_DEPLOYMENT_INACTIVE`
- Invalid signature type               → `TX_ERR_SIG_ALG_INVALID`
- Duplicate nonce                      → `TX_ERR_NONCE_REPLAY`
- Invalid signature length             → `TX_ERR_SIG_NONCANONICAL`
- Non-canonical signature encoding     → `TX_ERR_SIG_NONCANONICAL`
- Witness overflow                     → `TX_ERR_WITNESS_OVERFLOW`
- Timelock condition not met           → `TX_ERR_TIMELOCK_NOT_MET`
- Weight exceedance                    → `BLOCK_ERR_WEIGHT_EXCEEDED`
- Anchor bytes exceeded                → `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED`
- PoW invalid                          → `BLOCK_ERR_POW_INVALID`
- Target mismatch                      → `BLOCK_ERR_TARGET_INVALID`
- Invalid prev_block_hash linkage      → `BLOCK_ERR_LINKAGE_INVALID`
- Invalid merkle_root                  → `BLOCK_ERR_MERKLE_INVALID`
- Coinbase rule violation              → `BLOCK_ERR_COINBASE_INVALID`
- Coinbase subsidy exceeded            → `BLOCK_ERR_SUBSIDY_EXCEEDED`
- Timestamp too old (MTP)              → `BLOCK_ERR_TIMESTAMP_OLD`
- Timestamp too far in future          → `BLOCK_ERR_TIMESTAMP_FUTURE`

Any alternative error code for these cases is non-conforming.

### 3.4 Replay-domain checks (Normative)

For each non-coinbase transaction `T` in block order:

1. `T.tx_nonce` MUST be non-zero and MUST satisfy `1 ≤ tx_nonce ≤ max(u64)`.
2. `tx_nonce` is part of the signed domain and is compared only within the same consensus chain.
3. Let `N_seen` be the multiset of non-coinbase `tx_nonce` in the current block.
4. If `T.tx_nonce` already appears in `N_seen`, return `TX_ERR_NONCE_REPLAY`.
5. If `T.tx_nonce` is not in `[1, max(u64)]`, return `TX_ERR_TX_NONCE_INVALID`.

**Cross-block replay protection (normative):** `tx_nonce` uniqueness is enforced only
within a single block. Cross-block replay is prevented by UTXO exhaustion: once an input
outpoint is consumed by `SpendTx` (§2), it is removed from `U` and any subsequent transaction
attempting to spend the same outpoint will fail with `TX_ERR_MISSING_UTXO`. A transaction
cannot be replayed across blocks because its input UTXOs no longer exist after the first
inclusion. `tx_nonce` therefore serves as an intra-block deduplication guard, not as a
global sequence number.

For each non-coinbase input `i`:

1. `sequence` MUST NOT be `0xffffffff`.
2. `sequence` MUST be ≤ `0x7fffffff`.
3. If `sequence` is structurally invalid, return `TX_ERR_SEQUENCE_INVALID`.

### 3.5 Deterministic iteration and ordering

For consensus determinism, implementations MUST iterate all collections in lexicographic order of:

1. Transaction input outpoints
2. UTXO map keys when scanning candidates
3. Block header tie-break comparisons (see §6.3)

No non-deterministic iteration (including hash-map order effects) is allowed.

### 3.6 Covenant Type Registry (Normative)

The following `covenant_type` values are valid:

- `0x0000` `CORE_P2PK`
- `0x0001` `CORE_TIMELOCK_V1`
- `0x0002` `CORE_ANCHOR`
- `0x0100` `CORE_HTLC_V1`
- `0x0101` `CORE_VAULT_V1`
- `0x0102` `CORE_HTLC_V2`
- `0x00ff` `CORE_RESERVED_FUTURE`

Semantics:

- `CORE_P2PK`:
  - `covenant_data = suite_id:u8 || key_id:bytes32`.
  - `suite_id` is `0x01` or `0x02` (see §4.4 for the active policy and VERSION_BITS deployment gates).
  - The output is spendable only by a witness packet with matching `suite_id` and a signature over `sighash`.
  - Non-normative note (wallet safety): creating outputs with `suite_id = 0x02` before VERSION_BITS activation is syntactically valid, but spending is deployment-gated; if the deployment never reaches ACTIVE (e.g., FAILED), such outputs may become unspendable. Wallet implementations SHOULD warn users before creating such outputs. Conformance: CV-BIND BIND-04; CV-DEP DEP-01/DEP-05.
  - `covenant_data_len` MUST be exactly `1 + 32`.
- `CORE_TIMELOCK_V1`:
  - `covenant_data = lock_mode:u8 || lock_value:u64le`.
  - `lock_mode = 0x00` for height lock, `0x01` for UNIX-time lock.
  - Spend is forbidden until `lock_value` condition is met by current chain consensus state.
  - `covenant_data_len` MUST be exactly `1 + 8`.
- `CORE_ANCHOR`:
  - `covenant_data = anchor_data` (raw bytes, no additional wrapping).
  - `covenant_data_len` MUST be `0 < covenant_data_len ≤ MAX_ANCHOR_PAYLOAD_SIZE`.
  - `value` MUST be exactly `0`. A non-zero `value` in a `CORE_ANCHOR` output MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.
  - CORE_ANCHOR outputs are **non-spendable**: they MUST NOT be added to the spendable UTXO set.
  - Any transaction attempting to spend an ANCHOR output MUST be rejected as `TX_ERR_MISSING_UTXO`.
  - Per-block constraint: `Σ |anchor_data|` over all CORE_ANCHOR outputs MUST NOT exceed `MAX_ANCHOR_BYTES_PER_BLOCK`.
  - If the per-block constraint is violated, the block MUST be rejected as `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED`.
  - `anchor_commitment = SHA3-256(anchor_data)` is computable by any observer but is NOT stored on-chain separately.
- `CORE_HTLC_V1`:
  - Purpose: fixed-template hashlock+timelock for atomicity primitives without a general-purpose script language.
  - `covenant_data = hash:bytes32 || lock_mode:u8 || lock_value:u64le || claim_key_id:bytes32 || refund_key_id:bytes32`.
  - `hash = SHA3-256(preimage32)` for the 32-byte secret preimage.
  - `lock_mode = 0x00` for height lock, `0x01` for UNIX-time lock.
  - Claim path: provides `preimage32` in `script_sig` and spends using `claim_key_id`.
  - Refund path: uses `refund_key_id` and is forbidden until `lock_value` condition is met by current chain consensus state.
  - `covenant_data_len` MUST be exactly `32 + 1 + 8 + 32 + 32 = 105`.
- `CORE_VAULT_V1`:
  - Purpose: fixed-template owner-bound vault with delayed recovery, intended for safer self-custody and key-compromise recovery.
  - `covenant_data` has two encodings (backward compatible):
    - Legacy: `owner_key_id:bytes32 || lock_mode:u8 || lock_value:u64le || recovery_key_id:bytes32` (73 bytes).
    - Extended: `owner_key_id:bytes32 || spend_delay:u64le || lock_mode:u8 || lock_value:u64le || recovery_key_id:bytes32` (81 bytes).
  - `spend_delay` is a relative height delay (in blocks) for the owner path, computed from the output's `creation_height` stored in the spendable UTXO set:
    - If `spend_delay = 0`, owner path is immediate (legacy behavior).
    - If `spend_delay > 0`, owner path is forbidden until `height(B) ≥ o.creation_height + spend_delay`.
  - `lock_mode = 0x00` for height lock, `0x01` for UNIX-time lock.
  - Owner path: `owner_key_id` may spend at any time (no timelock check).
  - Recovery path: `recovery_key_id` may spend only when the lock condition is met.
  - `covenant_data_len` MUST be exactly `73` or `81`:
    - `73` implies `spend_delay = 0`.
    - `81` parses `spend_delay` as defined above.
- `CORE_HTLC_V2`:
  - Deployment-gated: MUST be rejected as `TX_ERR_DEPLOYMENT_INACTIVE` unless deployment `htlc_anchor_v1` is ACTIVE at the validated height.
  - Purpose: HTLC with preimage delivered on-chain via a `CORE_ANCHOR` envelope, rather than in `script_sig`. Enables anchor-based atomic swaps without exposing the preimage in the input witness.
  - `covenant_data = hash:bytes32 || lock_mode:u8 || lock_value:u64le || claim_key_id:bytes32 || refund_key_id:bytes32`.
  - `hash = SHA3-256(preimage32)` for a 32-byte secret preimage.
  - `lock_mode = 0x00` for height lock, `0x01` for UNIX-time lock.
  - `claim_key_id != refund_key_id` MUST be enforced; equal values MUST be rejected as `TX_ERR_PARSE`.
  - `covenant_data_len` MUST be exactly `32 + 1 + 8 + 32 + 32 = 105`.
  - Claim path (`script_sig_len = 0`, preimage in ANCHOR envelope):
    - Scan all `CORE_ANCHOR` outputs in the transaction for a matching envelope:
      - A matching envelope has `|anchor_data| = 54` AND `anchor_data[0:22] = ASCII("RUBINv1-htlc-preimage/")`.
    - If no matching envelope is found: reject as `TX_ERR_PARSE`.
    - If two or more matching envelopes are found: reject as `TX_ERR_PARSE` (non-deterministic).
    - If exactly one matching envelope: `preimage32 = anchor_data[22:54]`.
      - Require `SHA3-256(preimage32) = hash`; otherwise reject as `TX_ERR_SIG_INVALID`.
      - Witness public key hash MUST equal `claim_key_id`; otherwise reject as `TX_ERR_SIG_INVALID`.
  - Refund path (determined by witness key matching `refund_key_id`):
    - If no matching ANCHOR envelope and witness public key hash equals `refund_key_id`:
      - `lock_mode = 0x00`: require `height(B) >= lock_value`.
      - `lock_mode = 0x01`: require `timestamp(B) >= lock_value`.
      - If lock condition is not met: reject as `TX_ERR_TIMELOCK_NOT_MET`.
    - If lock condition met and key matches `refund_key_id`: proceed to signature verification.
  - Non-matching `CORE_ANCHOR` outputs in the same transaction are permitted and do not affect HTLC_V2 validation.
- `CORE_RESERVED_FUTURE`: forbidden until explicit activation by consensus.

Any unknown or future `covenant_type` MUST be rejected as `TX_ERR_COVENANT_TYPE_INVALID`.

## 4. Validation Rule Set

Validation for each non-coinbase transaction is fixed in this order:

1. Canonical parse (including output covenant constraints per §3.6)
2. Replay-domain checks (`tx_nonce`, `sequence`)
3. UTXO lookup
4. Coinbase maturity (non-coinbase skip)
5. Covenant binding
6. Deployment rule gate (VERSION_BITS-driven activation)
7. Covenant evaluation
8. Signature verification
9. Value conservation

UTXO lookup semantics (Normative):

- Transaction validation operates against an incrementally updated working UTXO set for the current block.
- Specifically, for transaction `T_i` in block order, all UTXO lookups and spends occur against the state produced after applying `SpendTx` for all prior transactions `T_0..T_{i-1}` in the same block (see §2).

Coinbase maturity (Normative):

For each input spending a spendable UTXO entry `e` at validated block height `h = height(B)`:

1. If `e.created_by_coinbase = true` and `h < e.creation_height + COINBASE_MATURITY`,
   the transaction MUST be rejected as `TX_ERR_COINBASE_IMMATURE`.
2. Otherwise, the spend is not blocked by coinbase maturity.

### 4.1 Covenant binding and evaluation (Deterministic)

For each non-coinbase input spending output `o`:

1. Read `o.covenant_type` and `o.covenant_data`.
2. If `o.covenant_type = CORE_P2PK`:
   - parse `suite_id || key_id` from `o.covenant_data`;
   - witness public key hash MUST equal `key_id`;
   - witness `suite_id` MUST equal parsed `suite_id`;
   - if parse fails, return `TX_ERR_PARSE`.
3. If `o.covenant_type = CORE_TIMELOCK_V1`:
   - parse `lock_mode || lock_value`;
   - `lock_mode = 0x00`: require `height(B) ≥ lock_value`;
   - `lock_mode = 0x01`: require `timestamp(B) ≥ lock_value`;
   - any other `lock_mode` MUST be `TX_ERR_PARSE`;
   - if lock condition is not met, reject with `TX_ERR_TIMELOCK_NOT_MET`.
4. If `o.covenant_type = CORE_HTLC_V1`:
   - parse `hash || lock_mode || lock_value || claim_key_id || refund_key_id`;
   - any other `lock_mode` MUST be `TX_ERR_PARSE`;
   - If `script_sig_len` is neither `0` nor `32`, reject as `TX_ERR_PARSE`.
   - If `script_sig_len = 32` (claim path):
     - require `SHA3-256(script_sig) = hash`; otherwise reject as `TX_ERR_SIG_INVALID`;
     - witness public key hash MUST equal `claim_key_id`; otherwise reject as `TX_ERR_SIG_INVALID`.
   - If `script_sig_len = 0` (refund path):
     - witness public key hash MUST equal `refund_key_id`; otherwise reject as `TX_ERR_SIG_INVALID`;
     - `lock_mode = 0x00`: require `height(B) ≥ lock_value`;
     - `lock_mode = 0x01`: require `timestamp(B) ≥ lock_value`;
     - if lock condition is not met, reject with `TX_ERR_TIMELOCK_NOT_MET`.
5. If `o.covenant_type = CORE_VAULT_V1`:
   - parse `owner_key_id || spend_delay || lock_mode || lock_value || recovery_key_id` with backward compatibility:
     - `covenant_data_len = 73`: parse legacy form and set `spend_delay = 0`.
     - `covenant_data_len = 81`: parse extended form.
   - any other `lock_mode` MUST be `TX_ERR_PARSE`;
   - If witness public key hash equals `owner_key_id` (owner path):
     - If `spend_delay = 0`: accept (legacy behavior).
     - Else require `height(B) ≥ o.creation_height + spend_delay`; if not met, reject with `TX_ERR_TIMELOCK_NOT_MET`.
   - Else if witness public key hash equals `recovery_key_id` (recovery path):
     - `lock_mode = 0x00`: require `height(B) ≥ lock_value`;
     - `lock_mode = 0x01`: require `timestamp(B) ≥ lock_value`;
     - if lock condition is not met, reject with `TX_ERR_TIMELOCK_NOT_MET`.
   - Else reject as `TX_ERR_SIG_INVALID`.
6. If `o.covenant_type = CORE_HTLC_V2`:
   - If deployment `htlc_anchor_v1` is NOT ACTIVE at `height(B)`: reject as `TX_ERR_DEPLOYMENT_INACTIVE`.
   - `script_sig_len` MUST be `0`; otherwise reject as `TX_ERR_PARSE`.
   - parse `hash || lock_mode || lock_value || claim_key_id || refund_key_id` (105 bytes);
     if `covenant_data_len != 105`, reject as `TX_ERR_PARSE`;
     if `claim_key_id = refund_key_id`, reject as `TX_ERR_PARSE`;
     any `lock_mode` other than `0x00` or `0x01` MUST be `TX_ERR_PARSE`.
   - Determine path by scanning ANCHOR envelopes:
     - Let `matching` = { output `a` in tx outputs : `a.covenant_type = CORE_ANCHOR` AND `|a.anchor_data| = 54` AND `a.anchor_data[0:22] = ASCII("RUBINv1-htlc-preimage/")` }.
     - If `|matching| >= 2`: reject as `TX_ERR_PARSE` (ambiguous preimage — non-deterministic).
     - If `|matching| = 1` (claim path):
       - `preimage32 = matching[0].anchor_data[22:54]`.
       - Require `SHA3-256(preimage32) = hash`; otherwise reject as `TX_ERR_SIG_INVALID`.
       - Witness public key hash MUST equal `claim_key_id`; otherwise reject as `TX_ERR_SIG_INVALID`.
     - If `|matching| = 0` (refund path):
       - Witness public key hash MUST equal `refund_key_id`; otherwise reject as `TX_ERR_SIG_INVALID`.
       - `lock_mode = 0x00`: require `height(B) ≥ lock_value`.
       - `lock_mode = 0x01`: require `timestamp(B) ≥ lock_value`.
       - If lock condition is not met: reject as `TX_ERR_TIMELOCK_NOT_MET`.
7. If `o.covenant_type = CORE_ANCHOR`: this output is non-spendable and MUST NOT
   appear as an input. If reached, reject as `TX_ERR_MISSING_UTXO`.
8. If `o.covenant_type = CORE_RESERVED_FUTURE`, reject as `TX_ERR_COVENANT_TYPE_INVALID`.
9. Any other covenant type is rejected by `TX_ERR_COVENANT_TYPE_INVALID`.

For each block:

1. Header checks (including PoW bound and height linkage)
2. Transaction-level checks above
3. Anchor/RETL field checks (see §7)
4. Weight limits

Header checks (Normative minimum set):

1. If PoW is invalid (§5.1), reject `BLOCK_ERR_POW_INVALID`.
2. If `target` does not match the expected value per §6.4, reject `BLOCK_ERR_TARGET_INVALID`.
3. If `prev_block_hash` linkage is invalid per §5.1.2, reject `BLOCK_ERR_LINKAGE_INVALID`.
4. If `merkle_root` is invalid per §5.1.1, reject `BLOCK_ERR_MERKLE_INVALID`.

### 4.2 Sighash v1 (Normative)

```
preimage_tx_sig =
  ASCII("RUBINv1-sighash/") ||
  chain_id ||
  version ||
  tx_nonce ||
  hash_of_all_prevouts ||
  hash_of_all_sequences ||
  input_index ||
  prev_txid ||
  prev_vout ||
  input_value ||
  sequence ||
  hash_of_all_outputs ||
  locktime

digest = SHA3-256(preimage_tx_sig)
hash_of_all_prevouts = SHA3-256(concat(inputs[i].prev_txid || u32le(inputs[i].prev_vout) for i in [0..input_count-1]))
hash_of_all_sequences = SHA3-256(concat(u32le(inputs[i].sequence) for i in [0..input_count-1]))
hash_of_all_outputs = SHA3-256(concat(outputs[j] in TxOutput wire order for j in [0..output_count-1]))
```

All fields in `preimage_tx_sig` are taken from the transaction `T` being signed (not the block header), except `input_value`.
`input_value` is the `value` of the spendable UTXO entry referenced by this input's `(prev_txid, prev_vout)`.
In particular, `version` means `T.version`.

When `output_count = 0` (valid per §3.1), `hash_of_all_outputs = SHA3-256("")` (the SHA3-256 digest of the empty byte string). Implementations MUST handle this edge case.
Conformance: CV-SIGHASH SIGHASH-06.

Serialization table (Normative):

| Field | Serialization |
|---|---|
| domain_tag | ASCII("RUBINv1-sighash/") |
| chain_id | bytes32 |
| version | u32le |
| tx_nonce | u64le |
| hash_of_all_prevouts | bytes32 |
| hash_of_all_sequences | bytes32 |
| input_index | u32le (0-based) |
| prev_txid | bytes32 |
| prev_vout | u32le |
| input_value | u64le |
| sequence | u32le |
| hash_of_all_outputs | bytes32 |
| locktime | u32le |

For coinbase transactions, sighash is not computed (no witness).

Signatures MUST be verified over `digest`. No legacy/pre-v1.1 sighash format is valid in v1.1 consensus.

### 4.3 Weight formula (Normative)

Weight is computed per §11.
Each block MUST satisfy `Σ weight(T) ≤ MAX_BLOCK_WEIGHT`.

### 4.4 Signature suite policy (Normative)

- Allowed `suite_id` for key-based covenant spending: `0x01` (ML-DSA-87).
- `suite_id = 0x02` (SLH-DSA-SHAKE-256f) is reserved for key-based covenant spending pending future VERSION_BITS activation.
- RETL sequencer signatures (§7) use `suite_id = 0x02` under separate deployment policy; this is not a key-based covenant spend.
- `suite_id = 0x00` (sentinel) is permitted only for keyless covenants (`CORE_TIMELOCK_V1`) and MUST NOT be used for key-based covenant spends.

Weight and fee checks are normative:

1. For each transaction: `weight(T)` MUST be computed as in §4.3.
2. For each block: `Σ weight(T) ≤ MAX_BLOCK_WEIGHT`.

### 4.5 Coinbase and Subsidy (Normative)

- The first transaction in a block MUST be exactly one coinbase transaction.
  Any missing coinbase or additional coinbase transaction(s) MUST be rejected as `BLOCK_ERR_COINBASE_INVALID`.
- Coinbase outputs are bounded by:

```
sum(outputs.value) ≤ block_subsidy(height) + Σ fees(tx in transactions excluding coinbase)
```

- **Genesis exception (normative):** for height `0` (the genesis block), the coinbase output
  bound is not evaluated. Genesis outputs are chain-instance allocations fixed by the published
  genesis bytes and are not constrained by `block_subsidy(0)` or fees.

- If the coinbase bound is violated, the block MUST be rejected as `BLOCK_ERR_SUBSIDY_EXCEEDED`.
- `block_subsidy(height)` is a deterministic epoch schedule defined below; it is part of consensus
  constants for this spec version and MUST be computed identically by all implementations.

**Subsidy formula:**

Let `epoch = floor(height / SUBSIDY_HALVING_INTERVAL)`.

```
block_subsidy(height) = BLOCK_SUBSIDY_INITIAL >> epoch,  for epoch ≤ 33
block_subsidy(height) = 0,                               for epoch > 33
```

Arithmetic MUST use integer right-shift (floor division by 2^epoch), not floating-point.
Overflow is impossible: `BLOCK_SUBSIDY_INITIAL = 5_000_000_000` fits in u64; each halving
reduces the value; epoch 32 yields 1 base unit; epoch 33+ yields 0.

Total mined emission (subsidy-only; excluding any genesis allocations) is capped so that the
sum of emitted subsidy never exceeds `MAX_SUPPLY`.
Non-normative note: the discrete halving schedule yields a total mined emission of
`2_099_999_997_690_000` base units, which is `2_310_000` base units below `MAX_SUPPLY`.
Conformance: CV-COINBASE.

### 4.6 Value conservation (Normative)

For each non-coinbase transaction `T`:

1. Let `sum_in` be the sum of referenced input values:

   ```
   sum_in = Σ value(UTXO(T.inputs[i].prevout)) over all inputs i
   ```

2. Let `sum_out` be the sum of output values:

   ```
   sum_out = Σ T.outputs[j].value over all outputs j
   ```

3. If `sum_out > sum_in`, reject as `TX_ERR_VALUE_CONSERVATION`.
4. Arithmetic MUST be exact. Implementations MUST use checked arithmetic and reject any overflow as `TX_ERR_PARSE`.

## 5. Hashing and Signatures

Definitions (consensus-critical):

- `txid = SHA3-256(TxNoWitnessBytes(T))` where `TxNoWitnessBytes` excludes the `witness` section.
- `block_hash = SHA3-256(BlockHeaderBytes(B))`
- `anchor_commitment = SHA3-256(anchor_data)`

**Definition — `anchor_data`:** the exact raw byte string stored in a `CORE_ANCHOR` output's
covenant data payload, committed on-chain via `anchor_commitment`. No additional encoding
layer exists; the payload bytes are represented only by `anchor_data` itself.
See §3.6 for `CORE_ANCHOR` covenant type. Size constraints: §1.2 (`MAX_ANCHOR_PAYLOAD_SIZE`).

### 5.1 BlockHeader (Normative)

```
BlockHeader = {
  version: u32le
  prev_block_hash: bytes32
  merkle_root: bytes32
  timestamp: u64le
  target: bytes32   // big-endian integer when compared
  nonce: u64le
}
```

`BlockHeaderBytes(B)` serialize fields in the order above; integer fields use little-endian except `target`, which is serialized as raw 32-byte big-endian.

Proof-of-Work rule:

```
block_hash = SHA3-256(BlockHeaderBytes(B))
Valid iff integer(block_hash, big-endian) < integer(target, big-endian)
```

### 5.1.1 Merkle Tree (Normative)

```
Leaf   = SHA3-256(0x00 || txid)
Node   = SHA3-256(0x01 || left || right)
```

If the number of elements at any tree level is odd, the lone element is
promoted to the next level without hashing. Duplication of the last leaf
is forbidden (prevents CVE-2012-2459 mutation attacks).

`merkle_root` is the final root after full binary reduction over all txid in block order.

### 5.1.2 Chain linkage and block height (Normative)

Chain linkage validity:

1. For genesis block `B_0`:
   - `B_0.prev_block_hash` MUST be 32 zero bytes.
2. For any non-genesis block `B_h` with `h > 0` being validated as the next block on a chain tip `B_{h-1}`:
   - `B_h.prev_block_hash` MUST equal `block_hash(B_{h-1})`.
   - If this rule is violated, the block MUST be rejected as `BLOCK_ERR_LINKAGE_INVALID`.

Block height definition:

1. `height(B_0) = 0` for genesis.
2. For any block `B_h` with `h > 0` that satisfies chain linkage above, define:

```
height(B_h) = height(parent(B_h)) + 1
```

where `parent(B_h)` is the unique block whose `block_hash` equals `B_h.prev_block_hash`.

Height is a derived property; it is not carried as a header field.

### 5.2 Witness Item Validation (Normative)

Witness item validation is performed during step 8 ("Signature verification") of the
validation order in §4. For each non-sentinel witness item (i.e. `suite_id ≠ 0x00`):

1. Unknown `suite_id` is rejected as `TX_ERR_SIG_ALG_INVALID`.
2. `sig_length = 0` is non-canonical and MUST be rejected as `TX_ERR_SIG_NONCANONICAL`.
3. If `suite_id = 0x01`, `sig_length` MUST equal 4_627 and `pubkey_length` MUST equal 2_592; any violation MUST be rejected as `TX_ERR_SIG_NONCANONICAL`.
4. If `suite_id = 0x02`, `0 < sig_length ≤ MAX_SLH_DSA_SIG_BYTES` and `pubkey_length` MUST equal 64; any violation MUST be rejected as `TX_ERR_SIG_NONCANONICAL`.
5. If `suite_id = 0x02` is used for a key-based covenant spend (`CORE_P2PK`, `CORE_HTLC_V1`, `CORE_HTLC_V2`, `CORE_VAULT_V1`) before explicit migration activation, reject as `TX_ERR_DEPLOYMENT_INACTIVE`.
6. If the witness item is well-formed and canonical-length but signature verification fails, reject as `TX_ERR_SIG_INVALID`.

**Security assumptions (normative prerequisites):**

- SHA3-256 has collision resistance under the stated query budget.
- ML-DSA-87 and SLH-DSA are EUF-CMA secure under their respective operational domains.
- Signature verification uses canonical preimage hashing; raw preimage signing is forbidden.

### 5.3 Batch Verification (Normative)

Implementations MAY use batch verification for ML-DSA-87 signatures within a single block.
Batch verification MUST produce the same accept/reject outcome as individual verification
for every signature in the batch. If batch verification rejects, the implementation MUST
fall back to individual verification to identify the invalid signature(s) and produce the
correct per-transaction error code.

### 5.4 Signature Canonical Form (Normative)

ML-DSA-87 signing SHOULD use deterministic signing mode (FIPS 204 pure mode).

Consensus validation MUST enforce:

1. If `pubkey_length != 2_592` or `sig_length != 4_627`, reject as `TX_ERR_SIG_NONCANONICAL`.
2. If lengths are canonical but ML-DSA-87 Verify fails, reject as `TX_ERR_SIG_INVALID`.

SLH-DSA-SHAKE-256f MAY use randomized signing. A signature is canonical if and only if
`0 < sig_length ≤ MAX_SLH_DSA_SIG_BYTES` and `pubkey_length = 64`. Consensus validation MUST enforce:

1. If `pubkey_length != 64` or `sig_length = 0` or `sig_length > MAX_SLH_DSA_SIG_BYTES`, reject as `TX_ERR_SIG_NONCANONICAL`.
2. If lengths are canonical but SLH-DSA Verify fails, reject as `TX_ERR_SIG_INVALID`.

Implementations MUST NOT impose additional structural constraints beyond length bounds and verification.

## 6. Fork Choice and Finality Input

### 6.1 Chainwork

```
work(B) = ⌊2^256 / target(B)⌋
ChainWork(chain) = Σ work(B_i)
```

Canonical chain is the valid chain with maximal `ChainWork` among candidates at each height.

### 6.2 PoW validity

For block `B`:

```
block_hash = SHA3-256(BlockHeaderBytes(B))
```

`B` is PoW-valid iff the big-endian integer value of `block_hash` is strictly less than the big-endian integer value of `target(B)`.

### 6.3 Tie-break

When `ChainWork` is equal, the winner is selected by lexicographic comparison:

- `block_hash` is compared as raw bytes in big-endian byte order.

### 6.4 Difficulty update

Let:

    T_actual   = timestamp_last_block_in_window
                 − timestamp_first_block_in_window

    T_expected = TARGET_BLOCK_INTERVAL × WINDOW_SIZE

If T_actual ≤ 0, set T_actual = 1.

```
target_new =
    clamp(
        floor(target_old × T_actual / T_expected),
        max(1, floor(target_old / 4)),
        target_old × 4
    )
```

Window boundaries and applicability (Normative):

1. Let block height be `h` (genesis has `h = 0`).
2. For `h = 0`, the expected `target(B_0)` is the `target` field encoded in the genesis header bytes published by the chain-instance profile.
3. For `h > 0` and `h % WINDOW_SIZE != 0`, the expected `target(B_h)` MUST equal `target(B_{h-1})`.
4. For `h > 0` and `h % WINDOW_SIZE = 0` (a retarget boundary), define the preceding window as blocks:

   - first block in window: `B_{h-WINDOW_SIZE}`
   - last block in window: `B_{h-1}`

   Then:

   - `target_old = target(B_{h-1})`
   - `timestamp_first_block_in_window = timestamp(B_{h-WINDOW_SIZE})`
   - `timestamp_last_block_in_window  = timestamp(B_{h-1})`
   - `target(B_h)` MUST equal `target_new` as computed by the formula above.

5. Any block whose `target` field does not match the expected value MUST be rejected as invalid (`BLOCK_ERR_TARGET_INVALID`).

This is a consensus rule and MUST be deterministic.
All division in this rule is integer division with floor.
Intermediate products (`target_old × T_actual` and `target_old × 4`) MUST be computed using at least 320-bit (or arbitrary-precision) unsigned integer arithmetic. Silent truncation of intermediate values is non-conforming and will cause consensus splits between implementations using different integer widths.
Conformance: CV-BLOCK BLOCK-09.

### 6.5 Header Time Rules (Consensus-Critical)

1. timestamp is a 64-bit unsigned integer representing seconds since UNIX epoch.

2. For block `B_h` with `h > 0`:

   Let `k = min(11, h)` and define the multiset:

   ```
   S_h = { timestamp(B_{h-1}), timestamp(B_{h-2}), ..., timestamp(B_{h-k}) }
   ```

   Let `median(S_h)` be defined as:

   - sort `S_h` in non-decreasing order;
   - select the element at index `floor((|S_h| - 1)/2)` (the lower median).

   Then `timestamp(B_h)` MUST be strictly greater than `median(S_h)`.
   If this rule is violated, the block MUST be rejected as `BLOCK_ERR_TIMESTAMP_OLD`.

   For genesis (`h = 0`), this rule is not evaluated.

3. timestamp(B_h) MUST NOT exceed local_time + MAX_FUTURE_DRIFT, where
   local_time is implementation system time in seconds since UNIX epoch,
   and MAX_FUTURE_DRIFT is a consensus constant.
   If this rule is violated, the block MUST be rejected as `BLOCK_ERR_TIMESTAMP_FUTURE`.

4. All timestamp arithmetic MUST use integer math with floor division.

### 6.6 Chain Selection Rule (Non-Validation Procedure)

Fork choice is a node-level selection rule and NOT part of block validity.

A node selects the canonical chain as the chain with highest cumulative work.
If cumulative work is equal, the chain whose tip block_hash is lexicographically
smaller (bytewise big-endian comparison) is selected.

### 6.7 Finality (Probabilistic)

For economic finality:

- A transaction is safe for L1 settlement when it has
  `K_CONFIRM_L1` descendant blocks.
- The default value `K_CONFIRM_L1 = 8` is in §1.2.

For bridge/gateway-sensitive operations:

- Bridge settlement SHOULD require `K_CONFIRM_BRIDGE = 12` descendants.

For governance-sensitive transitions:

- Governance-related effects SHOULD require `K_CONFIRM_GOV = 16` descendants.

These parameters are non-consensus operational values unless otherwise referenced by VERSION_BITS.

## 7. RETL and ANCHOR Semantics Boundary

**ANCHOR format constraints are consensus-level.**  
**RETL semantics are application-level.**

Protocol-level constraints:

- Domain identifier:

```
retl_domain_id = SHA3-256("RUBINv1-retl-domain/" || chain_id || descriptor_bytes)
```

#### 7.0.1 `descriptor_bytes` (Normative, stable serialization)

`descriptor_bytes` MUST be the canonical serialization of:

```
RETLDomainDescriptorV1 = {
  version: u8 = 1
  sequencer_suite_id: u8
  sequencer_pubkey_length: CompactSize
  sequencer_pubkey: bytes[sequencer_pubkey_length]
  flags: u32le
}
```

where:

1. `sequencer_suite_id` MUST be `0x02` (SLH-DSA-SHAKE-256f) for public RETL domains.
2. `sequencer_pubkey_length` MUST equal 64 for `sequencer_suite_id = 0x02`.
3. `flags` is reserved for future application-layer semantics and MUST be `0` in v1.1.

- Bond:
  - must reference a spendable UTXO
  - MIN_RETL_BOND is an application-layer policy parameter.
  - L1 consensus does not validate bond amount or enforce bond slashing.
  - Bond enforcement is outside consensus.
  - if no active bond, domain is inactive

- Batch:

```
RETLBatch {
  retl_domain_id
  batch_number
  prev_batch_hash
  state_root
  tx_data_root
  withdrawals_root
  sequencer_sig
}

`sequencer_sig` is a `WitnessItem` with mandatory `suite_id = 0x02` (SLH-DSA-SHAKE-256f) and is signed over:

`"RUBIN-RETL-v1" || chain_id || retl_domain_id || batch_number || prev_batch_hash || state_root || tx_data_root || withdrawals_root`.
```

#### 7.0.2 RETLBatch field types and signing serialization (Application-layer, interoperability)

RETL semantics are application-level; however, for interoperability between RETL implementations, the following
field types and signing serialization are specified:

1. `retl_domain_id`: bytes32
2. `batch_number`: u64le
3. `prev_batch_hash`: bytes32
4. `state_root`: bytes32
5. `tx_data_root`: bytes32
6. `withdrawals_root`: bytes32

Signing preimage (bytes):

```
ASCII("RUBIN-RETL-v1") ||
chain_id ||
retl_domain_id ||
u64le(batch_number) ||
prev_batch_hash ||
state_root ||
tx_data_root ||
withdrawals_root
```

Interop note (non-consensus):
- A recommended `anchor_data` envelope for RETLBatch interoperability (including `sequencer_sig`) is defined in `operational/RUBIN_RETL_INTEROP_FREEZE_CHECKLIST_v1.1.md §2.2.1`.

Consensus requirements for anchor_data in a block:

- Per-output constraint:

    |anchor_data| ≤ MAX_ANCHOR_PAYLOAD_SIZE

- Per-block constraint:

    Σ over all ANCHOR outputs in block of |anchor_data|
    ≤ MAX_ANCHOR_BYTES_PER_BLOCK

If this per-block constraint is violated, the block MUST be rejected as `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED`.

Limits apply strictly to anchor_data bytes only.
Other output fields are not counted toward anchor_data limits.

### 7.1 ANCHOR Design Intent (Non-Normative)

ANCHOR is a conservative, consensus-bounded byte-commitment channel intended for publishing compact commitments
(e.g., roots, hashes, and succinct bridge/bond commitments). It is NOT a full data-availability (DA) layer for
rollups in v1.1.

Accordingly:

1. L2 systems (including RETL) SHOULD publish only commitments (e.g., `state_root`, `tx_data_root`,
   `withdrawals_root`, or a bridge/bond commitment root) in `anchor_data`, and distribute any bulk calldata
   off-chain (external DA, P2P overlay, or application-specific dissemination).
2. Cross-chain and bond-bridge use-cases are supported by anchoring commitments, not by embedding full
   cross-chain data in L1.
3. Any increase of `MAX_ANCHOR_PAYLOAD_SIZE` or `MAX_ANCHOR_BYTES_PER_BLOCK` changes block validity and therefore
   MUST be performed via a consensus upgrade (VERSION_BITS deployment) and conformance re-baselining.

Coinbase transactions MAY include `CORE_ANCHOR` outputs, subject to the same per-output and per-block `anchor_data`
limits as any other transaction.

L1 does not execute RETL state transition logic and does not parse RETL transactions beyond envelope constraints.

## 8. VERSION_BITS State Monotonicity

State:

`S ∈ { DEFINED, STARTED, LOCKED_IN, ACTIVE, FAILED }`

For a deployment `D`, define:

- `D.bit` as the bit index in `BlockHeader.version` used for signaling.
- `D.start_height` as the first height at which signaling is evaluated.
- `D.signal_window` as the window size in blocks (for v1.1 this is `SIGNAL_WINDOW`).
- `D.threshold` as the minimum number of signaled blocks required (for v1.1 this is `THRESHOLD`).

Signals are counted per `window_index`:

```
window_index = floor((height - max(VERSION_BITS_START_HEIGHT, D.start_height)) / D.signal_window)
signal_count = |{ b in window : ((b.version >> D.bit) & 1) = 1 }|
```

Transition:

`if signal_count ≥ D.threshold then LOCKED_IN`.

For a fixed chain history, transitions are monotone and never decrease.

#### 8.0.1 Full FSM transitions (Normative)

For a deployment `D` with parameters `(bit, start_height, timeout_height, signal_window, threshold)`, define:

1. A *window boundary* height `h` is any height such that:

```
(h - max(VERSION_BITS_START_HEIGHT, D.start_height)) % D.signal_window = 0
```

2. Signaling is evaluated over completed windows. Let a completed window end at height `h-1` where `h` is a window boundary.

State transitions at a window boundary height `h`:

1. `DEFINED -> STARTED`:
   - if `h >= D.start_height`.
2. `STARTED -> LOCKED_IN`:
   - if the immediately preceding completed window has `signal_count >= D.threshold`.
3. `STARTED -> FAILED`:
   - if `h >= D.timeout_height` and state is not `LOCKED_IN`.
4. `LOCKED_IN -> ACTIVE`:
   - at the next window boundary after entering `LOCKED_IN`.
5. `ACTIVE` and `FAILED` are terminal.

Transitions are evaluated in the numbered order above at each window boundary. If transition 2 (LOCKED_IN) fires at a boundary, transition 3 (FAILED) MUST NOT be evaluated for that same boundary.
Conformance: CV-DEP DEP-05.

v1.1 deployment registry:

- No consensus deployments are ACTIVE by default in this spec revision.
- Any activation schedule (bit assignments, start heights, and timeouts) is chain-instance and revision-specific and MUST be specified in a future canonical revision before any new behavior is permitted.
 
Development status P0 (future release blockers):

1. A concrete chain-instance profile MUST be published for any public network (devnet/testnet/mainnet) fixing exact genesis bytes so all clients derive the same `chain_id`.
2. Any consensus feature activation via VERSION_BITS MUST publish a populated deployment table (schema in §8.1) before release.
3. Any change to consensus weight accounting (including `VERIFY_COST_*`) MUST be accompanied by updated conformance vectors covering boundary blocks and weight computation determinism.

#### 8.1 Deployment table format (Normative schema)

Any future consensus deployment schedule MUST be published as a table with the following columns:

| deployment_id | bit | start_height | timeout_height | signal_window | threshold | state_machine | feature_summary |
|---|---:|---:|---:|---:|---:|---|---|

Normative requirements:

1. `deployment_id` MUST be unique and stable within a chain-instance.
2. `bit` MUST be in `[0, 28]` (reserved higher bits are not used in v1.1).
3. `start_height` and `timeout_height` MUST be absolute heights for the target chain-instance.
4. `signal_window` MUST equal `SIGNAL_WINDOW` unless an explicit future revision defines otherwise.
5. `threshold` MUST be an integer in `[0, signal_window]`.
6. `state_machine` MUST be the v1.1 FSM in §8 unless explicitly revised.
7. `feature_summary` MUST describe the exact new consensus behavior gated by this deployment.

## 9. Consensus Invariants (Normative)

The following invariants are part of consensus semantics:

1. **Deterministic validation**: For fixed state and block bytes, `ApplyBlock` returns a unique valid/invalid outcome and unique final state if valid.
2. **Value conservation**: non-coinbase outputs do not exceed canonical inputs; coinbase outputs are bounded by block subsidy + fees.
3. **Non-spendable exclusion**: non-spendable covenant outputs are excluded from spendable UTXO creation.
4. **Monotonic VERSION_BITS per chain**: no backwards transitions of the per-chain deployment state.
5. **Canonical selection**: nodes use chain selection exactly as specified in §6.6.

## 10. Release Gates (Consensus)

A protocol release is admissible only if:

1. All conformance vectors pass.
2. `CV-PARSE`/`CV-BIND`/`CV-UTXO`/`CV-DEP`/`CV-BLOCK`/`CV-REORG`/`CV-COINBASE` gates are `PASS`.
3. Cross-client parity is deterministic under identical inputs.
4. Deterministic serialization and consensus invariants are mechanically reproduced.
5. Conformance gate definitions are authoritative in `spec/RUBIN_L1_CONFORMANCE_MANIFEST_v1.1.md`.

## 11. Weight and Fee Accounting (Normative)

For transaction:

```
base_size = |TxNoWitnessBytes(T)|
wit_size  = |WitnessBytes(T.witness)|
ml_count  = count inputs with witness suite_id=0x01
slh_count = count inputs with witness suite_id=0x02
sig_cost  = ml_count * VERIFY_COST_ML_DSA + slh_count * VERIFY_COST_SLH_DSA
weight(T) = 4 * base_size + wit_size + sig_cost
```

For block:

```
Σ weight(T in block) ≤ MAX_BLOCK_WEIGHT
```

If the block constraint is violated, the block MUST be rejected as `BLOCK_ERR_WEIGHT_EXCEEDED`.

For any non-coinbase transaction:

```
fee(T) = Σ inputs.value - Σ outputs.value
```

`fee(T) ≥ 0` is guaranteed by the value conservation invariant (§9, invariant 2).

`min_fee` is a policy parameter derived from `weight(T)` and `MIN_RELAY_FEE_RATE`:

```
min_fee(T) = max(1, weight(T) * MIN_RELAY_FEE_RATE)
```

Relay policy may enforce higher local floors above this base formula.
Consensus does not define fee schedules directly.

`WitnessBytes(WitnessSection)` is the canonical witness serialization:

```
WitnessBytes(W) = CompactSize(W.witness_count) || concat( WitnessItemBytes(w) for each w in W.witnesses in order )
WitnessItemBytes(w) = u8(w.suite_id) || CompactSize(w.pubkey_length) || w.pubkey || CompactSize(w.sig_length) || w.signature
```

### 11.1 Mempool and relay policy (Non-consensus)

These are non-consensus operational constraints:

Default operator guidance for v1.1 is collected in:
- `../operational/RUBIN_NODE_POLICY_DEFAULTS_v1.1.md` (non-consensus; safe to change without network-wide upgrade).

1. A relay node MUST reject transactions that do not meet local minimum fee floor computed from
   `min_fee(T)` and current node policy multiplier.
2. Mempool ordering MUST prioritize higher `fee/weight` ratio.
3. Mempool eviction MUST remove lowest priority entries to enforce node local memory caps.
4. A relay node MUST reject any transaction that violates consensus parsing limits, including
   `witness.witness_count > MAX_WITNESS_ITEMS` or `|WitnessBytes(T.witness)| > MAX_WITNESS_BYTES_PER_TX`
   (both `TX_ERR_WITNESS_OVERFLOW`).
5. A relay node MAY additionally reject transactions where any single witness item exceeds a node-local byte cap such as `MAX_WITNESS_ITEM_BYTES` when measured over `WitnessItemBytes(w)` from §11.

Operational policy MAY include:

1. anti-starvation backoff,
2. peer-bucket rate limits,
3. per-peer message admission quotas.

## 12. Inline Test Vectors (Hex Fixtures)

### Conformance Vector Contract (Normative)

1. Informative vectors in this section are illustrative only and are not normative fixtures.
2. All normative testing is driven by the external conformance YAML bundle.
3. Implementations MUST use one deterministic validator test manifest that contains:
   - `CV-PARSE`, `CV-BIND`, `CV-UTXO`, `CV-DEP`, `CV-BLOCK`, `CV-REORG`.
4. Missing entries in that manifest are a release-blocking condition.

### TV-01 invalid CompactSize

```
raw_tx = "0001fd00"
Expected: TX_ERR_PARSE
```

The following vectors are illustrative examples and are NOT normative fixtures.
Authoritative conformance vectors are defined in the separate YAML test suite.

### TV-02 invalid signature

The following vectors are illustrative examples and are NOT normative fixtures.
Authoritative conformance vectors are defined in the separate YAML test suite.

This test is given as structured fields to avoid non-canonical raw-dump assumptions:

```text
fixture:
  version: 1
  tx_nonce: 42
  input_count: 1
  inputs:
  - prevout: non-zero txid and vout=0
    script_sig_len: 0
    sequence: 0
  output_count: 1
  outputs:
  - value: 1
    covenant_type: CORE_P2PK (0x0000)
    covenant_data: 01 || 32-byte-zero key_id
  witness:
    witness_count: 1
    witnesses:
    - suite_id: 0x01
      pubkey_length: 0
      pubkey: empty
      sig_length: 0
      signature: empty
  locktime: 0xffffffff
Expected: TX_ERR_SIG_INVALID
```

### TV-03 invalid binding

The following vectors are illustrative examples and are NOT normative fixtures.
Authoritative conformance vectors are defined in the separate YAML test suite.

This test is provided as fixture schema (not a raw byte vector):

```
fixture:
  preloaded_UTXO:
    covenant_type: CORE_RESERVED_FUTURE (0x00ff)
    value: 1000
    covenant_data: <any valid-sized blob>
  tx:
    type: non-coinbase spend of preloaded_UTXO
    witness:
      witness_count: 1
      witnesses: well-formed syntax
Expected: TX_ERR_COVENANT_TYPE_INVALID
```

### TV-04 anchor overflow

```
anchor_data = 00 repeated 65537 bytes
Expected: BLOCK_ERR_ANCHOR_BYTES_EXCEEDED
```

### TV-05 double spend

```
block_1:
  tx1 spends outpoint O
  tx2 also spends outpoint O in same block
Expected: TX_ERR_MISSING_UTXO
```

## 13. Non-Normative Guidance

- Block height is not stored in `BlockHeader`; it is derived from chain linkage (`prev_block_hash` traversal). This is by design: height is a property of the chain position, not of the header itself.
- This file excludes probabilistic security derivations, UC proofs, and operational governance details.
- Formal proofs and assumptions are in `../formal/RUBIN_FORMAL_APPENDIX_v1.1.md`.
- Measurement and incident governance are in `../operational/RUBIN_OPERATIONAL_SECURITY_v1.1.md`.
- Formal key format and address binding are in `spec/RUBIN_L1_KEY_MANAGEMENT_v1.1.md`.
- Coinbase/subsidy rules are in `spec/RUBIN_L1_COINBASE_AND_REWARDS_v1.1.md` (auxiliary) and normatively in `§4.5`.

## 14. Threat Model and Deployment Assumptions

Assumptions:

1. Adversary may control up to 49% of public network bandwidth and hash power.
2. Adversary can observe and relay all public messages and can delay them temporarily.
3. PQ adversary can attack at quantum level subject to standard NIST security reductions for ML-DSA-87 and SLH-DSA-SHAKE-256f.

Operationally, consensus-critical code MUST reject all non-minimal/ambiguous encodings and use only fixed domain-separated hashes defined in this file.

### 14.1 Miner and Relay Policy Abuse Considerations (Non-Normative)

RUBIN distinguishes:
- **Consensus rules** (this file): determine what is valid.
- **Node relay/miner policies** (operator-local): determine what is propagated and what gets included first.

#### 14.1.1 Acknowledged risks

Miners and relays MAY abuse local policy for:
- transaction censorship (selective inclusion or delay),
- MEV-style extraction (re-ordering within a block),
- self-preferencing (prioritizing own flows).

#### 14.1.2 Consensus protections (cannot be violated)

Even with adversarial policy, miners and relays cannot:
- spend funds without valid signatures,
- include invalid blocks (PoW + deterministic validation),
- bypass covenant/timelock enforcement (once a transaction is included, validity is objective and verifiable).

#### 14.1.3 Mitigations and limits

Mitigations are economic/operational, not absolute:
- competition: miners compete for fees; prolonged censorship is costly and observable,
- propagation: a transaction can be rebroadcast via diverse peers and alternative relay paths; mempools are not identical, so diversity matters,
- transparency: public mempools and on-chain inclusion behavior are observable; operator policies that impact users should be documented,
- time: users can wait for a different miner to include the transaction.

RETL/L2 note:
- L2 users can always construct an L1-valid exit transaction, but inclusion still requires a miner; “sovereign exit” means *no L2 sequencer permission is required*, not that miners cannot delay inclusion.

#### 14.1.4 User recommendations (non-normative)

- time-sensitive transactions: use higher fees (and fee bumping where supported by wallet policy),
- censorship-resistance: rebroadcast across multiple peers and avoid single relay dependencies,
- MEV minimization: avoid broadcasting sensitive intent early; consider alternative dissemination paths (including private relay services) if available in your environment.

### 14.2 Eclipse and Network Attacks on Light Clients (Non-Normative)

Light clients and SPV nodes present a distinct attack surface from full nodes because they
do not independently validate the full chain — they rely on the header chain and Merkle proofs
supplied by connected peers. An adversary who controls all of a light client's peers can feed
it a false view of the chain.

#### 14.2.1 Eclipse attack model

An **eclipse attack** isolates a target node by filling all of its peer slots with adversary-
controlled nodes. For a light client this is particularly dangerous because:

1. The adversary can present a valid-PoW but fraudulent header chain (longer fake chain
   or selectively withheld blocks).
2. The adversary can suppress transactions or block confirmations, causing the light client
   to believe a payment is unconfirmed or double-spent.
3. The adversary can feed stale or selectively filtered `merkleblock`/`anchorproof` responses,
   causing the client to accept fabricated inclusion proofs against a fork.

RUBIN-specific amplifier: because block headers do not contain the UTXO commitment or any
state root (by design — RUBIN is UTXO-minimal), a light client has no in-header state anchor
to detect UTXO fraud. Its only protections are PoW and Merkle inclusion.

#### 14.2.2 Consensus properties that hold under eclipse

Even under a complete eclipse (all peers adversarial), the following hold for an honest
light client that correctly implements RUBIN v1.1:

1. **PoW integrity**: the adversary cannot present a header with less cumulative work than
   the real chain tip *if the client has any out-of-band knowledge of chain tip PoW*
   (e.g., a trusted checkpoint). Without checkpoints, the adversary can present an
   alternative chain with equal or greater PoW, which the client cannot distinguish.
2. **Merkle proof integrity**: given a valid `block_header.merkle_root`, a Merkle inclusion
   proof cannot be forged (SHA3-256 collision resistance, T-013). An eclipsed client that
   accepts a fraudulent header may accept a fraudulent Merkle proof — but only against that
   fraudulent header, not against the honest chain.
3. **Signature integrity**: a light client that verifies transaction signatures (e.g., for
   received payments) cannot be deceived about whether a given output was created by a valid
   PQ signature. Adversary cannot forge ML-DSA-87 or SLH-DSA signatures.
4. **Covenant binding**: the covenant type and `key_id` binding are consensus-enforced;
   an eclipsed light client cannot be shown a covenant spend that violates binding rules
   *within the fraudulent chain* it has been fed (binding is deterministic from tx data).

#### 14.2.3 What an eclipse can achieve

Against a light client without checkpoints or diverse peers:

- **Double-spend attack**: show the client a confirmation on fork A, while the real chain
  is on fork B where the transaction is absent or reversed.
- **Withheld block attack**: suppress a confirmed block to delay payment detection.
- **ANCHOR spoofing**: feed a fraudulent `anchorproof` against a fake header to falsely
  confirm an HTLC preimage or key-migration shadow-binding that does not exist on the real chain.
- **Chain tip lag**: serve a stale tip to keep the client operating on an old chain view,
  enabling time-based covenant attacks (e.g., HTLC refund window manipulation).

#### 14.2.4 Mitigations for light clients

Items 2 and 6 below are normatively specified in
`spec/RUBIN_L1_LIGHT_CLIENT_SECURITY_v1.1.md`. The remaining items are operational
recommendations.

1. **Multiple diverse peers**: connect to ≥ 3 peers across independent operators/subnets.
   See `spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md §7.1` (anti-eclipse heuristics).

2. **Checkpoints** *(normative — see LIGHT_CLIENT_SECURITY §2)*: hard-coded block hashes
   at known heights. A chain conflicting with any checkpoint MUST be rejected as
   `ECLIPSE_ERR_CHECKPOINT_MISMATCH`. Build-time embedding required for mainnet.
   Checkpoint hygiene (non-genesis): heights MUST be ≥ `COINBASE_MATURITY` blocks behind the tip
   at publish time. Gap limit: `MAX_CHECKPOINT_GAP = 100_800` blocks.

3. **Difficulty anomaly detection**: reject headers whose difficulty drops beyond the
   expected retarget bound in a single window (CANONICAL §6.4).

4. **Median-time consistency**: enforce header `timestamp` rules (CANONICAL §6.5).

5. **Out-of-band tip verification**: periodically query a trusted HTTPS endpoint or
   DNS seed for the current chain tip hash.

6. **`anchorproof` multi-peer confirmation** *(normative — see LIGHT_CLIENT_SECURITY §3)*:
   for HTLC claims and key-migration operations, require `MIN_ANCHORPROOF_PEERS = 2`
   independent peers to return agreeing `anchorproof` responses before acting.
   Minimum confirmation depth: `MIN_ANCHORPROOF_DEPTH = 6` blocks.

7. **Connection-layer diversity**: for mobile/embedded clients, prefer Tor or independent
   transport to prevent network-layer adversaries from rerouting all connections.

#### 14.2.5 RUBIN-specific risk: ANCHOR-based eclipse

Because `CORE_ANCHOR` outputs are used for HTLC preimage delivery (§3.6, §4 rule 4a),
key-migration shadow-bindings (CRYPTO_AGILITY §5.1), and RETL batch commitments (§7),
an eclipsed light client that accepts fraudulent `anchorproof` messages faces application-
layer consequences beyond simple payment fraud:

- A fraudulent HTLC preimage anchor causes the client to believe a hashlock condition
  is satisfied when it is not (or vice versa), enabling HTLC theft or lock-in.
- A fraudulent shadow-binding anchor causes the client to accept a key rotation that
  did not occur on-chain, enabling key replacement attacks.

Mitigation: all ANCHOR-based application logic MUST require multi-peer confirmation
and confirmation depth ≥ `MIN_ANCHORPROOF_DEPTH` blocks before treating an anchor as
authoritative. Full normative specification:
`spec/RUBIN_L1_LIGHT_CLIENT_SECURITY_v1.1.md §3`
(see also KEY_MANAGEMENT §3.1 timelock recommendation).

P2P minimum requirements (normative, non-consensus) are specified in §15.

## 15. P2P Minimum Requirements (Normative, non-consensus)

This section defines the minimum P2P interoperability profile for RUBIN v1.1. These
requirements are NOT consensus rules (they do not affect block validity), but conforming
implementations MUST meet them to interoperate at the network layer.

### 15.1 Peer Discovery and Handshake Exchange

Node peers MUST implement peer discovery and peer-version handshake sufficient to exchange:
- `version`, `verack`, `wtxid` (relayed via `inv/getdata` `inv_type = 2`), `ping`, `pong`,
- headers, compact headers, inv/msg getdata, blocks, and txs.

### 15.2 Shared Header Wire and Header-Chain Validation

`BlockHeader` wire is shared by all peers; chain state is validated with PoW, difficulty, and header chain rules.

### 15.3 SPV Inclusion Proof Requirements

SPV validation requires proof of inclusion as:
- merkle_path (binary proof with siblings at each depth),
- block_header with valid work/target and timestamp rules,
- witness-free txid and explicit tx index.

### 15.4 Transport Envelope Minimum

Minimum required P2P transport envelope is 24-byte fixed prefix:
- magic (4 bytes), command (12 bytes, ASCII, zero padded), payload_length (4 bytes), checksum (4 bytes).

### 15.5 Peer Discovery Baseline

Peer discovery is non-consensus and at minimum supports address relay and stale-peer eviction.

### 15.6 Oversized Message Rejection

A node MUST reject oversized protocol messages above negotiated caps from network policy to resist DoS.

### 15.7 Handshake Required Fields

Handshake message MUST include:
- network magic via the 24-byte transport prefix (magic is not duplicated in the version payload),
- `protocol_version`,
- `chain_id`,
- `peer_services`.

### 15.8 Minimum Required Message Families

`msg_inv`, `msg_getdata`, and `msg_headers` are minimum required message families.

### 15.9 Mempool Inventory Helpers

Nodes MUST support `mempool` and `getmempool` for relay-aware peers and `light` role nodes.

### 15.10 Light Client Header-Chain Rejection Rules

Light clients MUST reject headers chains with inconsistent median-time and PoW checks at each step.

### 15.11 Connection Caps and Bandwidth Ceilings

Nodes MAY enforce connection caps and per-peer bandwidth ceilings to resist eclipse/DoS attacks.

### 15.12 Maximum Message Size

Maximum message size is `MAX_RELAY_MSG_BYTES`.

### 15.13 Full P2P Protocol Reference

Full peer transport and light-client profile is specified in `spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md`.

## 16. Crypto Agility and Upgrade Path (Normative)

1. `suite_id` selects exact signature primitive; parsing is explicit.
2. No algorithm swap without deployment state via VERSION_BITS.
3. During migration, both old/new `suite_id` MAY be accepted only when activation rules transition to ACTIVE.
4. If migration leaves unknown `suite_id` in active consensus field, block validity is rejected.
5. Unsupported `suite_id` in consensus-relevant witness data MUST be `TX_ERR_SIG_ALG_INVALID`.
6. In a mixed-policy period, L1 can gate algorithm acceptance by deployment bit and height.
7. Full rollout/rollback behavior is in `spec/RUBIN_L1_CRYPTO_AGILITY_UPGRADE_v1.1.md`.
