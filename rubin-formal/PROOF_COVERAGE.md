# Proof Coverage

Источник: `spec/SECTION_HASHES.json`  
Машинный реестр: `rubin-formal/proof_coverage.json`

Текущее состояние: machine-readable source-of-truth (`proof_coverage.json`) фиксирует
`proof_level=refinement`, `claim_level=refined`, полный registry по 32 current coverage entries и явные
`notes` / `limitations` для non-universal claims. Conformance-фикстуры
Lean replay/refinement слой покрывает non-`CV-PV-*` conformance fixtures,
представленные модулями, импортированными `RubinFormal.Conformance.Index`.
Runtime/parallel-only `CV-PV-*` gates в этот Lean replay scope не входят.

## Source rebind: 109 → 102

Текущий imported-source obligation содержит `102` активных пути: исходный
109-path inventory минус ровно семь `DROP_STALE_SOURCE` путей:

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

Проверенная арифметика provenance:
`active_partition_equation = "79 + 14 + 1 + 1 + 7 = 102"` и
`original_inventory_equation = "102 + 7 = 109"`. Byte equality —
lifecycle/provenance evidence с pinned external source. Локальные checkers
валидируют записанный manifest и достижимый registry, но не реконструируют
байты внешнего OID.

Эти семь путей не входят в текущую source/claim поверхность. Их возможное
восстановление или замена — только отдельно авторизованный follow-up, а не
часть текущих proof claims.

Внутри тех же 102 активных путей семь адаптаций классифицированы как
`IMPORT_PACKAGE_CHECK_OR_TEST` (это не дополнительные пути):

- `tests/test_check_formal_registry_truth.py`
- `tests/test_integration.py`
- `tests/test_path_resolution.py`
- `tests/test_registry_extraction.py`
- `tests/test_scope_and_names.py`
- `tests/test_strip_lean_comments.py`
- `tests/test_validation.py`

Они фиксируют repository-valid Python import path для package tests и не
усиливают theorem claims. RUB-959 section-hash digest остаётся
`c21c234f6380f9421a10481958993ba23ec31277217fcdd6d5d4d4d613df74a3`.

## Термины (важно)

- `proof_level=refinement` означает: в репо есть исполняемый Lean replay-слой и
  op-scoped executable bridge evidence для критических ops. В зависимости от
  surface это может быть Go-trace replay, CV replay, LIVE/BRIDGE theorem layer
  на Lean transcription, или их честная комбинация. Это **не** означает один
  uniform trace-based Go(reference) → Lean refinement слой для всех critical ops.
- `claim_level` фиксирует допустимый публичный уровень заявлений:
  - `toy` (только model-baseline),
  - `byte` (byte-accurate слой),
  - `refined` (refinement to executable path).
- `status=proved/proved_with_axiom` относится к конкретной registry entry **в рамках указанного `proof_level`**.
- `status=proved_with_axiom` означает: proof закрывает секцию, но опирается на явно названные криптографические или модельные допущения, поэтому честный ceiling такой записи — `machine_checked_assumption_backed`, а не unconditional `universal`.
- `evidence_level` — главный public-facing taxonomy field. Именно он различает universal / behavioral / assumption-backed / contract-level ceiling.

Внешний аудит / freeze-ready коммуникации **НЕ ДОЛЖНЫ** трактовать текущий `proof_level=refinement`
как “formal verification of CANONICAL for all inputs/sections”.

Связка с hash-pinning:

- `proof_coverage.json` сейчас содержит 32 machine-checked registry entries.
- Status counts: `28` `proved`, `4` `proved_with_axiom`, `0` `stated`, `0` `deferred`.
- Registry counts: `575` theorem references и `552` unique theorem names.
- Не все 32 entries равны по силе claims: честная граница определяется `evidence_level` и `limitations`.
- Extra formal-only theorems не считаются pinned-section coverage,
  если они не внесены отдельной registry entry.

## Текущая раскладка evidence levels

- `machine_checked_universal`: 27
- `machine_checked_assumption_backed`: 4
- `machine_checked_model`: 1

## Lean ↔ Go/Rust bridge ceiling

- `refinement_bridge.json` — op-scoped bridge map, а не repo-wide equivalence claim.
- Для разных executable critical ops честный ceiling сейчас разный:
  `machine_checked_universal`, `machine_checked_assumption_backed`,
  `machine_checked_behavioral`, или `machine_checked_contract`.
- Часть ops опирается на Go-trace / CV replay по pinned fixtures, часть — на
  LIVE/BRIDGE theorems о Lean transcriptions с явно названной human-reviewed
  parity к Go/Rust.
- Следовательно, текущий refinement слой **не** даёт права заявлять uniform
  machine-checked Lean↔Go/Rust equivalence или uniform Go-trace refinement для
  всего critical-op surface.

## Путь к freeze-ready

1. Держать матрицу покрытия в синхроне с public narrative и closeout evidence.
2. Углублять non-universal entries там, где это реально снижает consensus-risk или audit ambiguity.
3. Не смешивать truth-correction с отдельными hygiene lanes вроде theorem traceability.

## Risk scoring / gates

Профили готовности (Phase‑0/devnet/audit/freeze) и правила CI описаны в `rubin-formal/RISK_MODEL.md`.
Registry/claims lint запускаются из protocol-root tooling в `tools/`.

Локально:

```bash
export PATH="$HOME/.elan/bin:$PATH"
lake build
```

Integrated workspace:

```bash
cd .. && scripts/dev-env.sh -- python3 tools/check_formal_coverage.py
cd .. && scripts/dev-env.sh -- python3 tools/check_formal_risk_gate.py --profile phase0
cd .. && scripts/dev-env.sh -- python3 tools/check_formal_refinement_bridge.py
cd .. && scripts/dev-env.sh -- python3 tools/check_formal_claims_lint.py
```
