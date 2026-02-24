# RUBIN — CORE_VAULT 2FA (Draft for Audit)

Status: **DRAFT / NOT YET INTEGRATED** (non-consensus until merged into `RUBIN_L1_CANONICAL.md`).

Goal: describe a **simple, deterministic, audit-friendly** redesign of `CORE_VAULT` where:
- `CORE_VAULT` is a **safe** (not operational wallet).
- Spending a vault requires **owner authorization + vault-factor authorization** (2FA).
- Outputs are constrained by an immutable **destination whitelist** (last-resort guardrail).
- Fee sponsorship is forbidden: **only the owner** may provide non-vault inputs in a vault-spend transaction.

This draft is intended to be attached to audit discussions before making a consensus-critical change.

**НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА:** integration of this draft changes consensus (wire + validity + error mapping).

---

## 1. Definitions

### 1.1 OutputDescriptorBytes

Reuse CANONICAL §18.3:

```text
OutputDescriptorBytes(output) =
    u16le(output.covenant_type) ||
    CompactSize(output.covenant_data_len) ||
    output.covenant_data
```

`output.value` is intentionally excluded.

### 1.2 Owner Lock ID (`owner_lock_id`)

We define a unified owner identifier that works for both `CORE_P2PK` and `CORE_MULTISIG` owners:

```text
owner_lock_id = SHA3-256(OutputDescriptorBytes(owner_output_descriptor))
```

Where `owner_output_descriptor` is a *descriptor* of the owner lock (either P2PK or MULTISIG) expressed as:

```text
owner_output_descriptor =
    u16le(owner_covenant_type) ||
    CompactSize(owner_covenant_data_len) ||
    owner_covenant_data
```

Notes:
- This binds vault ownership to a specific lock policy (P2PK key-id or MULTISIG policy).
- For P2PK, `owner_covenant_data` is the standard P2PK covenant data (CANONICAL §14 registry).
- For MULTISIG, `owner_covenant_data` is the standard multisig covenant data (CANONICAL §14 registry).

### 1.3 Referenced-input lock id (`lock_id(e)`)

For any referenced UTXO entry `e` (from the input outpoint):

```text
lock_id(e) = SHA3-256(u16le(e.covenant_type) || CompactSize(len(e.covenant_data)) || e.covenant_data)
```

This is exactly `SHA3-256(OutputDescriptorBytes(out))` applied to the referenced UTXO’s covenant fields.

---

## 2. CORE_VAULT v2 covenant_data (Draft)

### 2.1 Wire format

Proposed `CORE_VAULT` covenant data format becomes versioned:

```text
CORE_VAULT_v2.covenant_data =
  vault_version:u8 (=2) ||
  owner_lock_id:bytes32 ||
  vault_threshold:u8 ||
  vault_key_count:u8 ||
  vault_keys[vault_key_count]:bytes32 ||
  whitelist_count:u16le ||
  whitelist[whitelist_count]:bytes32
```

Where:
- `vault_keys[i] = SHA3-256(vault_pubkey_i)` (same key-id convention as other covenants).
- `whitelist[j] = SHA3-256(OutputDescriptorBytes(output_j))` (same whitelist convention as v1).

### 2.2 Constraints at creation (CheckTx / output validation)

For any output `out` with `out.covenant_type = CORE_VAULT` and `vault_version = 2`:

- `out.value MUST be > 0`.
- `1 <= vault_key_count <= MAX_VAULT_KEYS`.
- `1 <= vault_threshold <= vault_key_count`.
- `vault_keys[] MUST be strictly lexicographically sorted (ascending) with no duplicates`.
- `1 <= whitelist_count <= MAX_VAULT_WHITELIST_ENTRIES`.
- `whitelist[] MUST be strictly lexicographically sorted (ascending) with no duplicates`.

Additional 2FA-specific invariants:

- **Owner destination forbidden:** `owner_lock_id MUST NOT be present in whitelist[]`.
  - Rationale: prevents the “safe” from whitelisting direct spend back into the same owner lock.

- **Owner authorization required to create a vault:**
  - Any transaction `T` that creates at least one `CORE_VAULT_v2` output with `owner_lock_id = X`
    MUST contain at least one input whose referenced UTXO entry `e` satisfies `lock_id(e) = X`.
  - Rationale: vault cannot be created without the owner authorizing the transaction via an owner-controlled input.

Error mapping (draft; final mapping belongs to CANONICAL error registry):
- If format/constraints fail: `TX_ERR_COVENANT_TYPE_INVALID`.
- If “owner destination forbidden” fails: `TX_ERR_COVENANT_TYPE_INVALID`.
- If “owner authorization required” fails: `TX_ERR_COVENANT_TYPE_INVALID`.

---

## 3. Spend semantics (Draft)

This draft defines a **vault-spend transaction** as any transaction `T` where at least one input spends a
referenced UTXO entry with `covenant_type = CORE_VAULT` and `vault_version = 2`.

### 3.1 Vault-factor signatures (M-of-N)

For each input spending `CORE_VAULT_v2`, the input MUST satisfy the vault signature threshold:
- The witness cursor assigns `vault_key_count` WitnessItems to the vault input.
- Signatures are verified against `vault_keys[]`.
- Require `valid >= vault_threshold`.

Signature digest is per CANONICAL §12 with `input_index` bound.

### 3.2 Whitelist enforcement

For each output `out` in the spending transaction `T`:
- Compute `h = SHA3-256(OutputDescriptorBytes(out))`.
- Require `h` present in the vault’s `whitelist[]`.
- If violated: reject as `TX_ERR_COVENANT_TYPE_INVALID`.

### 3.3 Fee sponsorship forbidden (owner-only non-vault inputs)

Let `X` be the `owner_lock_id` of the spent `CORE_VAULT_v2`.

Rules for any vault-spend transaction `T`:

1) **Owner input required:** `T` MUST include at least one input whose referenced UTXO entry `e` satisfies
   `lock_id(e) = X`.
   - Rationale: ensures every vault-spend is explicitly owner-authorized even if fee is zero.

2) **No third-party fee sponsorship:** For every input in `T` whose referenced covenant type is *not* `CORE_VAULT`,
   its referenced UTXO entry `e` MUST satisfy `lock_id(e) = X`.
   - Rationale: non-vault inputs (used for fee funding) must be owned by the same owner lock.

Error mapping (draft):
- If violated: `TX_ERR_COVENANT_TYPE_INVALID`.

### 3.4 Value conservation (vault value must not fund fee)

Let:
- `sum_in_vault` = sum of referenced input values whose covenant type is `CORE_VAULT`.
- `sum_out` = sum of output values.

Rule:
- If `T` spends at least one vault input and `sum_out < sum_in_vault`, reject as `TX_ERR_VALUE_CONSERVATION`.

Rationale:
- Prevents burning vault value as fee.
- Fee is funded only by non-vault (owner) inputs: `fee = sum_in - sum_out`.

---

## 4. Optional simplification (Policy / possible consensus rule)

To keep the model maximally simple (“vaults are self-contained safes”), it may be desirable to enforce:

- **At most one vault input per transaction.**

This is **not required** for correctness of whitelist enforcement (intersection already prevents bypass),
but it simplifies user-space behavior and reduces complex edge cases in wallets.

**НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА** if this is made consensus-critical.

---

## 5. Conformance plan (Draft)

Minimum executable vectors to add before claiming audit-readiness:

- `VAULT2-CREATE-01`: create vault2 without owner input → reject.
- `VAULT2-CREATE-02`: create vault2 with owner P2PK input → ok.
- `VAULT2-CREATE-03`: create vault2 with owner MULTISIG input → ok.
- `VAULT2-CREATE-04`: whitelist contains owner_lock_id → reject.

- `VAULT2-SPEND-01`: spend vault2 without owner input → reject.
- `VAULT2-SPEND-02`: spend vault2 with non-owner fee input → reject.
- `VAULT2-SPEND-03`: spend vault2 with owner fee input, whitelist ok, vault sig threshold ok → ok.
- `VAULT2-SPEND-04`: spend vault2 with output not in whitelist → reject.
- `VAULT2-SPEND-05`: attempt to fund fee from vault (`sum_out < sum_in_vault`) → reject.

---

## 6. Security notes (Draft)

- The whitelist is the last-resort guardrail: even if owner+vault keys are compromised, funds can only flow
  to pre-authorized output descriptors.
- Owner loss is catastrophic by design: owner authorization is always required; there is no recovery bypass.
- Fee sponsorship is forbidden to keep the vault-spend model simple and to avoid introducing third-party inputs
  into vault transactions.

