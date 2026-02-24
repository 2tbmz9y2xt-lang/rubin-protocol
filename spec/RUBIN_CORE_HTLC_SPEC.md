# RUBIN CORE HTLC SPECIFICATION

**Document:** `RUBIN_CORE_HTLC_SPEC.md`  
**Covenant type:** `CORE_HTLC` (`0x0100`)  
**Status:** ACTIVE — activated from genesis in `RUBIN_L1_CANONICAL.md`  
**Formal verification:** in-repo baseline in `rubin-formal/` (`status=proved` on model-level; executable/byte-accurate refinement pending)

---

## 1. Overview

`CORE_HTLC` implements a Hash Time-Locked Contract at the L1 consensus layer.
It supports two spend paths:

- **Claim path:** spender presents a preimage `P` such that `SHA3-256(P) = hash`,
  and provides a valid signature from `claim_key_id`.
- **Refund path:** spender provides a valid signature from `refund_key_id`,
  after the locktime condition is satisfied.

`CORE_HTLC` is a single-signature covenant (one signature is required per spend).
It consumes **2 WitnessItems** from the witness cursor: a spend-path selector and
the signature for the selected path.
It has no
destination whitelist — output routing is unrestricted, subject to standard
value conservation rules (Section 20, RUBIN_L1_CANONICAL.md).

---

## 2. Covenant Data Format

`covenant_data` for `CORE_HTLC` is exactly `MAX_HTLC_COVENANT_DATA` bytes,
encoded as:

```
hash          : bytes32        -- SHA3-256 preimage hash (claim condition)
lock_mode     : u8             -- 0x00 = block height, 0x01 = timestamp
lock_value    : u64le          -- locktime threshold
claim_key_id  : bytes32        -- SHA3-256(claim_pubkey)
refund_key_id : bytes32        -- SHA3-256(refund_pubkey)
```

**Total:** `32 + 1 + 8 + 32 + 32 = 105 bytes`

`MAX_HTLC_COVENANT_DATA = 105`

---

## 3. Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_HTLC_COVENANT_DATA` | 105 | covenant_data byte length (exact) |
| `MAX_HTLC_PREIMAGE_BYTES` | 256 | maximum preimage length in witness |
| `LOCK_MODE_HEIGHT` | 0x00 | locktime in block height |
| `LOCK_MODE_TIMESTAMP` | 0x01 | locktime in Unix seconds |

---

## 4. Creation Rules (CheckTx — output validation)

When a transaction output has `covenant_type = 0x0100 (CORE_HTLC)`:

1. `covenant_data_len MUST equal MAX_HTLC_COVENANT_DATA (105)`.
   Otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.

2. `lock_mode MUST be 0x00 or 0x01`.
   Otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.

3. `claim_key_id MUST NOT equal refund_key_id`.
   Otherwise reject as `TX_ERR_PARSE`.

4. `value MUST be > 0`.
   Otherwise reject as `TX_ERR_COVENANT_TYPE_INVALID`.

5. `CORE_HTLC` outputs ARE spendable and MUST be added to the UTXO set on creation.

---

## 5. Spend Rules (CheckTx — input validation)

### 5.1 Witness Structure

`CORE_HTLC` consumes exactly **2 WitnessItems** from the witness cursor (Section 16,
RUBIN_L1_CANONICAL.md):

```
WitnessItem[W+0] : spend_path_item  -- encodes which path is taken
WitnessItem[W+1] : sig_item         -- signature from the appropriate key
```

`witness_slots(CORE_HTLC) = 2`

**spend_path_item** is a **meta witness** item (CANONICAL §5.4) and MUST NOT be used for cryptographic verification.

It is encoded as a standard `WitnessItem`:

```
suite_id         = SUITE_ID_SENTINEL (0x00)
pubkey_length    = 32
pubkey           = key_id (bytes32)  -- binds path to claim_key_id or refund_key_id
sig_length       = 1 (refund) OR 3..(3+MAX_HTLC_PREIMAGE_BYTES) (claim)
signature bytes  = selector payload (see below)
```

Selector payload encoding (inside `signature` bytes):

- `signature[0]` is `path_id`:
  - `0x00` = claim path
  - `0x01` = refund path
  - any other value MUST be rejected as `TX_ERR_PARSE`

- For the **claim path** (`path_id = 0x00`):
  - `signature[1:3]` is `u16le(preimage_len)`
  - `signature[3:]` is `preimage` (`preimage_len` bytes)
  - `preimage_len MUST be <= MAX_HTLC_PREIMAGE_BYTES`; otherwise reject as `TX_ERR_PARSE`.
  - `sig_length MUST equal 3 + preimage_len`; otherwise reject as `TX_ERR_PARSE`.

- For the **refund path** (`path_id = 0x01`):
  - `sig_length MUST equal 1`; otherwise reject as `TX_ERR_PARSE`.

**sig_item** is a standard `WitnessItem` (CANONICAL §5.4) carrying a cryptographic signature:
- `suite_id        : u8` — MUST be `SUITE_ID_ML_DSA_87 (0x01)` or `SUITE_ID_SLH_DSA_SHAKE_256F (0x02)`
- `pubkey_length   : CompactSize`
- `pubkey          : bytes[pubkey_length]`
- `sig_length      : CompactSize`
- `signature       : bytes[sig_length]`

Byte-level canonical constraints for these suites (pubkey/sig lengths) are defined in CANONICAL §5.4.

### 5.2 Claim Path Validation

When `spend_path_item.signature[0] = 0x00`:

1. **Preimage check:**
   Let `preimage_len = u16le(spend_path_item.signature[1:3])` and `preimage = spend_path_item.signature[3:]`.
   `SHA3-256(preimage) MUST equal hash` from `covenant_data`.
   Otherwise reject as `TX_ERR_SIG_INVALID`.

2. **Selector binding:**
   `spend_path_item.pubkey MUST equal claim_key_id` from `covenant_data`.
   Otherwise reject as `TX_ERR_SIG_INVALID`.

3. **Key binding:**
   `SHA3-256(sig_item.pubkey) MUST equal claim_key_id` from `covenant_data`.
   Otherwise reject as `TX_ERR_SIG_INVALID`.

4. **Signature verification:**
   `verify_sig(sig_item.suite_id, sig_item.pubkey, sig_item.signature, digest) MUST be true`
   where `digest` is the sighash v1 digest (Section 12, RUBIN_L1_CANONICAL.md)
   with `input_index` bound to this input's position in the transaction.
   Otherwise reject as `TX_ERR_SIG_INVALID`.

5. **SLH-DSA gate:** if `sig_item.suite_id = SUITE_ID_SLH_DSA_SHAKE_256F (0x02)` and
   `block_height < SLH_DSA_ACTIVATION_HEIGHT`, reject as `TX_ERR_SIG_ALG_INVALID`.

### 5.3 Refund Path Validation

When `spend_path_item.signature[0] = 0x01`:

1. **Locktime check:**
   - If `lock_mode = LOCK_MODE_HEIGHT (0x00)`:
     `block_height MUST be >= lock_value`.
     Otherwise reject as `TX_ERR_TIMELOCK_NOT_MET`.
   - If `lock_mode = LOCK_MODE_TIMESTAMP (0x01)`:
     `MTP(prev_k_blocks) MUST be >= lock_value` where:
     - `k = min(11, block_height)`, and
     - `MTP(prev_k_blocks)` is the median timestamp defined in Section 22 of
       `RUBIN_L1_CANONICAL.md` for the block being validated.
     Otherwise reject as `TX_ERR_TIMELOCK_NOT_MET`.

2. **Selector binding:**
   `spend_path_item.pubkey MUST equal refund_key_id` from `covenant_data`.
   Otherwise reject as `TX_ERR_SIG_INVALID`.

3. **Key binding:**
   `SHA3-256(sig_item.pubkey) MUST equal refund_key_id` from `covenant_data`.
   Otherwise reject as `TX_ERR_SIG_INVALID`.

4. **Signature verification:**
   `verify_sig(sig_item.suite_id, sig_item.pubkey, sig_item.signature, digest) MUST be true`
   where `digest` is per Section 12, RUBIN_L1_CANONICAL.md.
   Otherwise reject as `TX_ERR_SIG_INVALID`.

5. **SLH-DSA gate:** same as claim path rule 5 above.

### 5.4 Invalid Path

Any value of `spend_path_item.signature[0]` other than `0x00` or `0x01` MUST be
rejected as `TX_ERR_PARSE`.

---

## 6. Error Code Summary

| Condition | Error |
|---|---|
| `covenant_data_len ≠ 105` | `TX_ERR_COVENANT_TYPE_INVALID` |
| `lock_mode ∉ {0x00, 0x01}` | `TX_ERR_COVENANT_TYPE_INVALID` |
| `claim_key_id = refund_key_id` | `TX_ERR_PARSE` |
| `value = 0` at creation | `TX_ERR_COVENANT_TYPE_INVALID` |
| `preimage_len > MAX_HTLC_PREIMAGE_BYTES` | `TX_ERR_PARSE` |
| Unknown spend path (`spend_path_item.signature[0] ∉ {0x00, 0x01}`) | `TX_ERR_PARSE` |
| `SHA3-256(preimage) ≠ hash` | `TX_ERR_SIG_INVALID` |
| `SHA3-256(pubkey) ≠ claim_key_id or refund_key_id` | `TX_ERR_SIG_INVALID` |
| Signature verification failure | `TX_ERR_SIG_INVALID` |
| Locktime condition not satisfied | `TX_ERR_TIMELOCK_NOT_MET` |
| SLH-DSA used before activation height | `TX_ERR_SIG_ALG_INVALID` |

Error priority follows the global ordering defined in Section 13 of RUBIN_L1_CANONICAL.md.
Structural/parse errors MUST be returned before signature verification is attempted.

---

## 7. Value Conservation

`CORE_HTLC` inputs are subject to standard value conservation rules
(Section 20, RUBIN_L1_CANONICAL.md): `sum_out <= sum_in` for any
transaction spending one or more HTLC inputs (along with any other input types).

There is no fee-preservation rule (unlike `CORE_VAULT`). The spender may
route funds to any output and may pay any fee to the miner.

Value preservation for both the claim and refund paths follows from the global non-coinbase
value conservation rules in `RUBIN_L1_CANONICAL.md` (Section 20).

---

## 8. Conformance Vectors

See `conformance/fixtures/CV-HTLC.json`. Required coverage:

| ID | Path | Condition | Expected |
|---|---|---|---|
| CV-HTLC-01 | creation | `claim_key_id = refund_key_id` | `TX_ERR_PARSE` |
| CV-HTLC-02 | creation | `lock_mode = 0x02` (invalid) | `TX_ERR_COVENANT_TYPE_INVALID` |
| CV-HTLC-03 | creation | `covenant_data_len ≠ 105` | `TX_ERR_COVENANT_TYPE_INVALID` |
| CV-HTLC-04 | claim | hash mismatch | `TX_ERR_SIG_INVALID` |
| CV-HTLC-05 | claim | key_id mismatch | `TX_ERR_SIG_INVALID` |
| CV-HTLC-06 | refund | key_id mismatch | `TX_ERR_SIG_INVALID` |
| CV-HTLC-07 | refund | locktime not met (height mode) | `TX_ERR_TIMELOCK_NOT_MET` |
| CV-HTLC-08 | refund | locktime not met (timestamp mode) | `TX_ERR_TIMELOCK_NOT_MET` |
| CV-HTLC-09 | claim | `preimage_len > 256` | `TX_ERR_PARSE` |
| CV-HTLC-10 | spend | unknown spend path (`suite_id = 0x02`) | `TX_ERR_PARSE` |

---

## 9. Integration with CANONICAL

**Status:** integrated.

`RUBIN_L1_CANONICAL.md` already treats `CORE_HTLC (0x0100)` as consensus-active from genesis block 0
and normatively defers spend semantics to this document.

This section is kept only to document that the integration step has been completed and to avoid
stale “reserved / not integrated” wording in external audit packs.

---

## 10. Security Notes

**Preimage privacy:** The preimage `P` is revealed on-chain when the claim path
is taken. This is by design — HTLC is a payment primitive, not a privacy primitive.
L2 protocols using HTLC SHOULD rotate keys and hashes per payment.

**Locktime granularity:** Height-based locks (`LOCK_MODE_HEIGHT`) are precise to
one block (~120 seconds). Timestamp-based locks (`LOCK_MODE_TIMESTAMP`) use MTP
as defined in CANONICAL Section 22 (with `k = min(11, h)` predecessors) — consistent
with the deterministic timestamp model.

**Key separation:** `claim_key_id ≠ refund_key_id` is enforced at creation.
Using the same key for both paths would allow the refund key holder to claim
without presenting a preimage by constructing a valid claim-path witness —
this ambiguity is eliminated at the protocol level.

**No amount restrictions:** Unlike `CORE_VAULT`, HTLC imposes no whitelist on
output destinations or amounts. Applications requiring destination constraints
SHOULD combine HTLC with off-chain coordination or use `CORE_VAULT`.
