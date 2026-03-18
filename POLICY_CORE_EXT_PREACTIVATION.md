# Policy: CORE_EXT pre-activation guardrails (non-consensus)

Consensus permits `CORE_EXT` spends pre-activation as anyone-can-spend.
This file documents the required **policy-only** guardrails to prevent accidental fund loss before an intended
deployment profile is ACTIVE.

## Guardrails (recommended defaults)

1. **Wallet policy (mandatory for user safety):**
   - Wallets MUST NOT create transactions that produce `CORE_EXT` outputs until the intended `ext_id` profile is known
     ACTIVE under CANONICAL §23.2.2.

2. **Mempool/relay policy (non-standard):**
   - Nodes SHOULD reject (as non-standard) transactions that create or spend `CORE_EXT` while the relevant profile is
     not ACTIVE.

3. **Miner template policy:**
   - Miners SHOULD exclude such transactions from block templates to avoid including anyone-can-spend funds by mistake.

4. **Strict mode:**
   - Production profiles SHOULD default to strict mode ON (fail-closed).

## Current implementation status

`rubin-node` is a minimal node and does not yet implement a full tx mempool/relay or wallet.
The currently implemented guardrail is **miner template filtering**:

- By default, `Miner` excludes any transaction that creates a `CORE_EXT` output or spends a `CORE_EXT` UTXO.
- This is policy-only and does not change consensus validity.

## Rationale

If `CORE_EXT` outputs are created pre-activation, they may be spent by anyone under consensus rules (no signature),
which is indistinguishable from user error after the fact. Policy guardrails must block creation, not only spend.

---

## Cross-References (updated 2026-03-15)

The normative CORE_EXT profile framework is defined in:

- **rubin-spec-private:** `spec/RUBIN_CORE_EXT_EXTENSION_FRAMEWORK.md`
  (approved per COUNCIL_CORE_EXT_FRAMEWORK_20260315)
- **rubin-core-ext-lab:** `RUBIN_CORE_EXT_EXTENSION_FRAMEWORK.md`
  (mirrored; lab design space)

Relevant CANONICAL sections:
- `RUBIN_L1_CANONICAL.md §23.2.2` — CORE_EXT Covenant-Type Activation Preconditions
- `RUBIN_L1_CANONICAL.md §12.5` — `verify_sig_ext` Binding (Normative)
- `RUBIN_L1_CANONICAL.md §14` — Covenant Type Registry (CORE_EXT wire format)

**CORE_EXT scope boundary:** CORE_EXT is for business logic and institutional
compliance profiles only. It MUST NOT be used as a native cryptographic suite
replacement mechanism (COUNCIL_NATIVE_ROTATION_ARCH_20260315). Native suite
lifecycle is governed by `RUBIN_NATIVE_CRYPTO_ROTATION_SPEC_v1.md`.

**Implementation prerequisites before activating any profile:**
1. Deployment descriptor wire format alignment with CANONICAL §23.2
2. `EXT_BASE_COST` numeric value supported by devnet-style measurement
3. `conformance/fixtures/CV-EXT.json` produced and passing on both Go and Rust clients

Current baseline:

- `EXT_BASE_COST = 64` (see `clients/go/consensus/constants.go` and
  `clients/rust/crates/rubin-consensus/src/constants.rs`; evidence captured under `Q-IMPL-CORE-EXT-COST-01`).
