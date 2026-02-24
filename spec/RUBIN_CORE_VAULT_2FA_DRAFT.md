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

## 0. Design summary (Informational)

### 0.1 Problem statement

We want a “safe-mode vault” that remains secure under common failure modes:

- If the owner key is compromised: attacker still cannot move vault funds without a second factor.
- If the vault factor is compromised: attacker still cannot move vault funds without the owner.
- If both are compromised: the immutable whitelist still restricts where funds can go.

### 0.2 Non-goals

- This draft does **not** introduce “recovery without owner”. If the owner lock is lost, funds are unrecoverable
  by design (same as a standard wallet).
- This draft does **not** attempt to make vault spends “operational” (batching, arbitrary change, arbitrary
  destinations). Those belong to the owner wallet outside the vault.

### 0.3 Threat model (Informational)

Attacker capabilities considered:
- Can steal some keys (owner, vault-factor, or both).
- Can craft arbitrary transactions and choose arbitrary fees and input sets.
- Can attempt to bypass destination policy by mixing inputs/outputs.

Security goals:
- Vault funds MUST NOT be redirected to non-whitelisted destinations by any combination of inputs/outputs.
- Vault funds MUST NOT be burned as fee (no “melt the safe into miner fee”).
- Vault spends MUST be explicitly owner-authorized and 2FA-authorized.

## 0.4 Scope choice for Phase‑0 / devnet (Informational)

This draft assumes a **clean replace-before-genesis** model:
- There are no “live” legacy vault UTXOs.
- The specification defines exactly **one** `CORE_VAULT` covenant_data format (no dual support).
- Any `CORE_VAULT` output not matching the specified format MUST be rejected.

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

### 1.1.1 Why value is excluded (Informational)

Excluding `output.value` allows whitelisting *destinations/policies* independent of transfer amounts:
- A single whitelist entry can allow “send to operational wallet” for any amount.
- Vault cannot enforce per-destination amounts on L1 (this is out of scope by design).

### 1.2 Owner Lock ID (`owner_lock_id`)

We define a unified owner identifier that works for both `CORE_P2PK` and `CORE_MULTISIG` owners:

```text
owner_lock_id = SHA3-256(owner_output_descriptor)
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

### 1.2.1 Owner is a lock policy, not a “name” (Informational)

We intentionally bind a vault to an owner **lock policy** (P2PK or MULTISIG) rather than a free-form “owner id”:
- deterministic and machine-checkable,
- supports both single-key and org multisig owners,
- avoids introducing a second “identity system” in consensus.

### 1.3 Referenced-input lock id (`lock_id(e)`)

For any referenced UTXO entry `e` (from the input outpoint):

```text
lock_id(e) = SHA3-256(u16le(e.covenant_type) || CompactSize(len(e.covenant_data)) || e.covenant_data)
```

This is exactly `SHA3-256(OutputDescriptorBytes(out))` applied to the referenced UTXO’s covenant fields.

### 1.3.1 Owner-authorization primitive (Informational)

If a transaction contains an input that spends a referenced UTXO entry `e` with `lock_id(e) = owner_lock_id`,
then (under standard covenant rules) the transaction is necessarily authorized by that owner lock.

This is the core mechanism used in this draft for:
- “vault cannot be created without the owner”,
- “vault cannot be spent without the owner”,
- “no fee sponsorship (no third-party inputs)”.

---

## 2. CORE_VAULT covenant_data (Draft, single-format)

### 2.1 Wire format

```text
CORE_VAULT.covenant_data =
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

### 2.1.1 Rationale (Informational)

This is a **clean replace-before-genesis** format (single format, no migration).
- `owner_lock_id` makes “owner binding” explicit and enables consensus-level owner checks.
- `vault_keys[]` provide the second factor (M-of-N).
- `whitelist[]` is the last-resort guardrail if keys are compromised.

### 2.2 Constraints at creation (CheckTx / output validation)

For any output `out` with `out.covenant_type = CORE_VAULT`:

- `out.value MUST be > 0`.
- `1 <= vault_key_count <= MAX_VAULT_KEYS`.
- `1 <= vault_threshold <= vault_key_count`.
- `vault_keys[] MUST be strictly lexicographically sorted (ascending) with no duplicates`.
- `1 <= whitelist_count <= MAX_VAULT_WHITELIST_ENTRIES`.
- `whitelist[] MUST be strictly lexicographically sorted (ascending) with no duplicates`.

Length rule (single deterministic formula):

```text
covenant_data_len MUST equal 32 + 1 + 1 + 32*vault_key_count + 2 + 32*whitelist_count
```

Additional 2FA-specific invariants:

- **Owner destination forbidden:** `owner_lock_id MUST NOT be present in whitelist[]`.
  - Rationale: prevents the “safe” from whitelisting direct spend back into the same owner lock.

- **Owner authorization required to create a vault:**
  - Any transaction `T` that creates at least one `CORE_VAULT` output with `owner_lock_id = X`
    MUST contain at least one input whose referenced UTXO entry `e` satisfies `lock_id(e) = X`.
  - Additionally, at least one such authorizing input MUST reference a UTXO whose covenant type is
    either `CORE_P2PK` or `CORE_MULTISIG` (owner lock types).
  - Rationale: vault cannot be created without the owner authorizing the transaction via an owner-controlled input.

### 2.3 Error mapping at creation (Draft)

This draft assumes **audit-friendly mapping** (requires error-registry update):
- Invalid covenant_data / constraints: `TX_ERR_COVENANT_TYPE_INVALID`
- Whitelist contains owner lock: `TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN`
- Missing owner-authorized input on vault creation: `TX_ERR_VAULT_OWNER_AUTH_REQUIRED`

Fallback (not recommended for audit-grade integrations):
- Any creation-time violation rejects as `TX_ERR_COVENANT_TYPE_INVALID`.

**НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА** to introduce new error codes in CANONICAL.

---

## 3. Spend semantics (Draft)

This draft defines a **vault-spend transaction** as any transaction `T` where at least one input spends a
referenced UTXO entry with `covenant_type = CORE_VAULT`.

### 3.0 Safe-only rule (one vault per transaction)

A vault-spend transaction MUST NOT include more than one input spending `CORE_VAULT`.

Rationale:
- Vault is a safe, not an operational wallet.
- Batching is performed by many outputs within a single-vault transaction, or by multiple transactions (one per vault).

### 3.1 Vault-factor signatures (M-of-N)

For each input spending `CORE_VAULT`, the input MUST satisfy the vault signature threshold:
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

Let `X` be the `owner_lock_id` of the spent `CORE_VAULT`.

Rules for any vault-spend transaction `T`:

1) **Owner input required:** `T` MUST include at least one input whose referenced UTXO entry `e` satisfies
   `lock_id(e) = X`.
   - Rationale: ensures every vault-spend is explicitly owner-authorized even if fee is zero.

2) **No third-party fee sponsorship:** For every input in `T` whose referenced covenant type is *not* `CORE_VAULT`,
   its referenced UTXO entry `e` MUST satisfy `lock_id(e) = X`.
   - Rationale: non-vault inputs (used for fee funding) must be owned by the same owner lock.

### 3.3.1 Error mapping (Draft)

Audit-friendly mapping (proposal; requires error-registry update):
- Missing owner input in vault-spend: `TX_ERR_VAULT_OWNER_AUTH_REQUIRED`
- Non-owner non-vault input present: `TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN`
- More than one vault input present: `TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN`

Fallback (not recommended for audit-grade integrations):
- If violated: `TX_ERR_COVENANT_TYPE_INVALID`.

**НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА** to introduce new error codes in CANONICAL.

### 3.4 Value conservation (vault value must not fund fee)

Let:
- `sum_in_vault` = sum of referenced input values whose covenant type is `CORE_VAULT`.
- `sum_out` = sum of output values.

Rule:
- If `T` spends at least one vault input and `sum_out < sum_in_vault`, reject as `TX_ERR_VALUE_CONSERVATION`.

Rationale:
- Prevents burning vault value as fee.
- Fee is funded only by non-vault (owner) inputs: `fee = sum_in - sum_out`.

### 3.5 User-space operational model (Informational)

This section explains how wallets should use the vault to keep the model “safe-only”.

#### 3.5.1 VaultCreateTx (owner-authorized create)

Vault creation is a normal transaction that:
- spends at least one owner-controlled input (P2PK or MULTISIG),
- creates a `CORE_VAULT` output (the safe),
- may create normal change outputs to the owner (creation is not a vault-spend),
- pays fee as usual.

Wallet UX:
- Owner selects/approves “Create vault”.
- Wallet collects guardian pubkeys (vault factor) and whitelist destinations.
- Wallet constructs and signs the creation transaction with owner credentials.

#### 3.5.2 VaultSpendTx (2FA spend)

Vault spend is a normal transaction that:
- spends a `CORE_VAULT` input (requires vault-factor signatures),
- includes at least one owner-controlled input (owner authorization),
- **all outputs must be whitelisted** (safe destinations),
- fee is funded by owner-controlled non-vault inputs only (no sponsorship).

Practical implication:
- A wallet MUST maintain a small “gas-UTXO” set for the owner lock (many small owner UTXOs) to fund vault fees
  without requiring a “change output” back to the owner inside the vault-spend transaction.
- The owner wallet remains the operational wallet: batching, arbitrary change, arbitrary destinations happen
  after funds arrive to the operational wallet via a whitelisted destination.

---

## 4. Vault is not operational (Informational)

This draft intentionally treats `CORE_VAULT` as a **safe-only** primitive:
- Do not use vault inputs for arbitrary operational batching and coin selection.
- Perform operational batching in the owner wallet after funds arrive to a whitelisted operational destination.

---

## 4.1 Controller decisions (Draft)

Even under “clean replace-before-genesis”, three consensus choices must be fixed. This draft assumes the
following controller decisions (to be confirmed before CANONICAL integration):

1) **Value rule for vault spends:** `sum_out >= sum_in_vault`.
   - Rationale: vault value cannot fund fee; owner may additionally route owner funds to whitelisted operational destinations.
   - Note: this does not allow arbitrary “change” to non-whitelisted destinations inside a vault spend.

2) **Error mapping policy:** audit-friendly mapping (explicit vault error codes).
   - Rationale: improves debuggability and conformance precision for external integrators/auditors.

3) **At most one vault input per transaction:** consensus-critical запрет (safe-only vault model).
   - Rationale: vault is not an operational wallet; batching is done via multiple transactions (one per vault),
     with many outputs per transaction.

**НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА** to finalize these in CANONICAL.

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
- `VAULT2-SPEND-07`: attempt to spend 2 vault inputs in one transaction → reject.

Additions recommended for audit-grade coverage:
- `VAULT2-CREATE-05`: create vault2 where owner_lock_id corresponds to MULTISIG policy; ensure creation requires
  spending that MULTISIG-owned input (not just any P2PK).
- `VAULT2-SPEND-06`: spend vault2 where owner is MULTISIG; ensure non-vault inputs must match that MULTISIG owner lock id.

---

## 6. Security notes (Draft)

- The whitelist is the last-resort guardrail: even if owner+vault keys are compromised, funds can only flow
  to pre-authorized output descriptors.
- Owner loss is catastrophic by design: owner authorization is always required; there is no recovery bypass.
- Fee sponsorship is forbidden to keep the vault-spend model simple and to avoid introducing third-party inputs
  into vault transactions.
