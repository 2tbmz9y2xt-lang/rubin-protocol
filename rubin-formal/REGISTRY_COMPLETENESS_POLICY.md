# Registry Completeness Policy

**Effective:** 2026-07-24
**Applies to:** `proof_coverage.json`, `refinement_bridge.json`
**Validator:** `tools/check_formal_registry_truth.py`

## 1. Scope

The formal registries are the machine-readable claim layer of rubin-formal.
They track which spec sections have formal coverage, at what evidence level,
and which theorems back each claim.

This policy defines what MUST be registered, what is explicitly excluded,
and how to evaluate a candidate theorem.

### Imported-source rebind

The current imported-source obligation is 102 paths: the original 109-path
inventory minus exactly seven `DROP_STALE_SOURCE` paths:

- `RubinFormal/ConsensusConstantsBehavioral.lean`
- `RubinFormal/FormalGap03.lean`
- `RubinFormal/TxWireTxPayloadContract.lean`
- `RubinFormal/TxWireTxWithWitnessContract.lean`
- `RubinFormal/TxWireTxAfterDaCoreContract.lean`
- `RubinFormal/TxWireTxBodyContract.lean`
- `RubinFormal/TxWireTxContract.lean`

Pinned provenance:

- `source_oid`: `2d9f1024f1d0b1bfb3fe6a8b727762e7a979b3a0`
- `inventory_sha256`: `77c9bac4f36c0bbce260388baad93216cd2b231e12c2a7edfc170ec3070596d6`
- `byte_exact_path_count`: 79 (`BYTE_EXACT`)
- `reconcile_current_protocol_path_count`: 14 (`RECONCILE_CURRENT_PROTOCOL`):
  - `RubinFormal/Conformance/CVVaultLifecycleReplay.lean`
  - `RubinFormal/ConnectBlockStrong.lean`
  - `RubinFormal/CovenantRegistryExhaustive.lean`
  - `RubinFormal/ErrorPriority.lean`
  - `RubinFormal/HtlcSpendStructuralLiveBridge.lean`
  - `RubinFormal/PerTxStateMachine.lean`
  - `RubinFormal/RefinementBridgeV1.lean`
  - `RubinFormal/RotationPrelude.lean`
  - `RubinFormal/SighashAssumptionBridge.lean`
  - `RubinFormal/SpendGateLiveBridge.lean`
  - `RubinFormal/StructuralRulesBehavioral.lean`
  - `RubinFormal/TxWireTxAfterDaCoreStep.lean`
  - `RubinFormal/TxWireTxFinalizeContract.lean`
  - `RubinFormal/VaultStateMachine.lean`
- `import_adapt_single_owner_path_count`: 1 (`IMPORT_ADAPT_SINGLE_OWNER`) —
  `REGISTRY_COMPLETENESS_POLICY.md`
- `transplant_check_logic_path_count`: 1 (`TRANSPLANT_CHECK_LOGIC`) —
  `scripts/check.sh`
- `import_package_check_or_test_path_count`: 7
  (`IMPORT_PACKAGE_CHECK_OR_TEST`), listed below

The provenance arithmetic is
`active_partition_equation = "79 + 14 + 1 + 1 + 7 = 102"` and
`original_inventory_equation = "102 + 7 = 109"`. Byte equality is
lifecycle/provenance evidence against the pinned external source. Local
checkers validate this recorded manifest and the reachable registry; they do
not reconstruct the external OID's bytes.

The excluded paths cannot support current registry claims. Reintroducing or
replacing any of them is a separately authorized follow-up. The frozen RUB-1024
inventory also classifies seven paths within the same 102-path active count as
`IMPORT_PACKAGE_CHECK_OR_TEST`:

- `tests/test_check_formal_registry_truth.py`
- `tests/test_integration.py`
- `tests/test_path_resolution.py`
- `tests/test_registry_extraction.py`
- `tests/test_scope_and_names.py`
- `tests/test_strip_lean_comments.py`
- `tests/test_validation.py`

These are repository-valid package-test import adaptations, not theorem
evidence and not additional active paths. The RUB-959 section-hash digest remains
`c21c234f6380f9421a10481958993ba23ec31277217fcdd6d5d4d4d613df74a3`.

## 2. Registration Tiers

### MUST register (mandatory)

A theorem MUST appear in `proof_coverage.json` or `refinement_bridge.json` if it
satisfies ALL of:

1. **Class is LIVE or BRIDGE** — proves a property of a live consensus function,
   or proves equivalence between a model and a live function.
2. **Claim-bearing** — the theorem makes or supports a claim about a spec section
   (§N in RUBIN_L1_CANONICAL.md).
3. **Non-trivial** — the proof is not `rfl`, `rfl`-chain, or `exact ⟨rfl, ...⟩`
   on constant definitions.

### SHOULD register (recommended)

- MODEL theorems that are the sole formal evidence for a spec section and no
  LIVE/BRIDGE theorem exists yet. These should be registered with
  `evidence_level: "machine_checked_model"` to honestly represent coverage.
- Conformance vector replay theorems (`cv_*_vectors_pass`) — always registered
  as `machine_checked_contract`.

### MUST NOT register (excluded)

- **Helpers/lemmas** used only as proof steps (e.g., `bytearray_ne_of_size_lt`,
  `bne_false_eq`, `bool_gate_pass`).
- **Wrappers** — projections, specializations, aliases, trivial corollaries.
- **Legacy/deprecated** theorems in `*Legacy*.lean` files.
- **Cursor/parser internals** — `Cursor.getBytes_advances`, `getBytes_preserves_bs`,
  etc., unless they are the sole evidence for a spec section.
- **Tautologies** — `f x = f x` (determinism of pure functions), constant equalities.
- **Private** theorems (`private theorem`).
- **Test** theorems that exist only for compile-time validation.

### MAY register (discretionary)

- Arithmetic safety theorems (overflow guards, saturation bounds) — register if
  they back a spec section claim.
- FSM/activation theorems — register if they back a spec section claim about
  feature deployment.

## 3. Registration Checklist

Before adding a theorem to the registry:

1. Verify the theorem exists: `grep -r "theorem <name>" RubinFormal/`
2. Classify: LIVE / BRIDGE / MODEL / WRAPPER
3. Identify spec section: which §N does it cover?
4. Determine evidence level: `machine_checked_universal`, `machine_checked_behavioral`,
   `machine_checked_contract`, `machine_checked_model`, or
   `machine_checked_assumption_backed`
5. Verify no name collision with existing entries
6. Run `tools/check_formal_registry_truth.py` after edit

## 4. Evidence Level Taxonomy

| Level | Meaning |
|-------|---------|
| `machine_checked_universal` | Inductive proof over all inputs (∀ x, P x) |
| `machine_checked_behavioral` | Behavioral property on specific function paths |
| `machine_checked_contract` | Conformance vector replay (finite test set) |
| `machine_checked_model` | Property of a model/helper, no live bridge |
| `machine_checked_assumption_backed` | Universal reduction/proof whose ceiling depends on explicitly named assumptions |

## 5. Audit

The registry is auditable via:

- `tools/check_formal_registry_truth.py` — validates all paths, theorem names,
  and evidence level parity between registries.
- The gap between total theorems (code) and registered theorems (registry) is
  intentional and governed by this policy. Not every theorem needs registration.

## 6. Current Metrics

As of 2026-07-24, recomputed from the current registries and Lean tree:

- Lean source tree: 1,063 public theorem declarations, 1,063 unique theorem names
- `proof_coverage.json`: 566 references, 543 unique theorem names
- `refinement_bridge.json`: 164 references, 158 unique theorem names
- Registry union: 550 unique theorem names
- Unregistered: 513 unique theorem names (mostly helpers, wrappers, internals per policy §2)

Reference counts count every row occurrence. Unique counts deduplicate fully
qualified public theorem names; private declarations are excluded per §2 and
the unregistered count is `1,063 - 550`.
