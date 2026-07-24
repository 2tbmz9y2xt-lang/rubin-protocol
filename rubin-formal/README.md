# RUBIN Formal (Lean 4)

Machine-checked formal proof surface for the RUBIN L1 blockchain protocol.

## Contents

- Lean 4 package `RubinFormal`
- `proof_coverage.json` — machine-readable coverage registry with 32 section entries
- Each registry entry carries explicit `evidence_level`, `notes`, and `limitations` so that public claims never outrun the actual proof boundary

## Source rebind: 109 → 102

The active imported-source obligation is 102 paths: the original 109-path
inventory minus exactly these seven `DROP_STALE_SOURCE` paths:

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

The recorded arithmetic is
`active_partition_equation = "79 + 14 + 1 + 1 + 7 = 102"` and
`original_inventory_equation = "102 + 7 = 109"`. Byte equality is
lifecycle/provenance evidence against the pinned external source. Local
checkers validate this recorded manifest and the reachable registry; they do
not reconstruct the external OID's bytes.

Those paths are excluded from current source and claim coverage. Reintroducing
or replacing them requires a separately authorized follow-up and does not form
part of the present registry claims.

Within the same 102 active paths, seven adaptations are classified
`IMPORT_PACKAGE_CHECK_OR_TEST` (they do not add to the path count):

- `tests/test_check_formal_registry_truth.py`
- `tests/test_integration.py`
- `tests/test_path_resolution.py`
- `tests/test_registry_extraction.py`
- `tests/test_scope_and_names.py`
- `tests/test_strip_lean_comments.py`
- `tests/test_validation.py`

They make the imported package tests resolve their own `tools` package from
both repository-root and package-root discovery, without changing proof
claims. The RUB-959 section-hash digest remains
`c21c234f6380f9421a10481958993ba23ec31277217fcdd6d5d4d4d613df74a3`.

## Claim boundary (critical)

This proof pack is an executable replay/refinement surface for the non-`CV-PV-*`
conformance fixtures whose replay modules are imported by
`RubinFormal.Conformance.Index`, plus live Lean theorems over select canonical
sections. It provides reproducible machine-checked evidence but **is not** a
universal formal verification of the entire CANONICAL spec.

Current machine-readable status: `proof_level=refinement`, `claim_level=refined`.

Permitted claim formulations (OK):

- "Lean executable semantics replay the non-`CV-PV-*` conformance fixtures
  represented by modules imported by `RubinFormal.Conformance.Index`"
- "Bridge evidence is op-scoped and mixed; the bounded imported Go-trace ID
  contract is claimed only for `parse_tx`, while other rows use their named
  universal, assumption-backed, behavioral, or CV-contract theorem surfaces"
- "Pinned-section coverage is machine-readable with explicit evidence levels: universal, behavioral, assumption-backed, and contract-level"

Prohibited claim formulations (NOT OK):

- "formal verification of RUBIN consensus / CANONICAL"
- "bit-exact wire/serialization proven"
- "universal mechanized equivalence between spec text and Go/Rust implementations"

Source of truth for claim boundary: `proof_coverage.json` (`proof_level`, `claims`).
`claim_level` (`toy|byte|refined`) is CI-validated for consistency against `proof_level`.

Wire model notes:

- `RubinFormal.ByteWireV2` — real CompactSize / byte-accurate proof surface for current wire claims
- `RubinFormal.ByteWireLegacy` — toy bootstrap model for single-byte CompactSize only (`n < 253`) and `TxMini`

## Risk model / CI gate

- Documentation: `RISK_MODEL.md`
- Lean validation (in-tree package): `lake build`
- Registry/claims linting: protocol-root tooling from `tools/`

## What this means

- This is **not** a freeze-ready package at the level of "universal byte-accurate wire + state transition model for all sections"
- Consensus rules are not changed by this formal package
- The formal coverage registry currently contains 32 machine-checked section entries
- Registry status counts: 28 `proved`, 4 `proved_with_axiom`, 0 `stated`, 0 `deferred`
- Claim strength breakdown: 27 universal, 4 assumption-backed, 1 model-level
- Registry theorem counts: 575 references and 552 unique theorem names
- Machine-checked status does not imply uniform claim strength — the honest boundary is set by `status`, `evidence_level`, and `limitations`
- Extra formal-only theorems are not counted as pinned-section claims unless registered in the machine-readable registry

## Local build

```bash
export PATH="$HOME/.elan/bin:$PATH"
lake env lean --version
lake build
```

Integrated workspace wrapper:

```bash
cd .. && scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake build'
```

## Roadmap

1. Keep `proof_coverage.json`, public narrative, and closeout evidence in sync
2. Do not elevate formal-only extra theorems to public pinned-section claims without an explicit registry update
3. Theorem-level traceability (`theorem_refs`) is tracked as a separate hygiene/improvement effort, not mixed with truth-correction
