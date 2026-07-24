# Formal risk model (Phase‑0 / devnet)

Цель: дать **воспроизводимую, машинно‑проверяемую** оценку того, *что именно* покрыто формальным пакетом (`rubin-formal/`),
и как это влияет на “готовность” для разных стадий (Phase‑0/devnet vs внешний аудит vs freeze).

Важно: это **не** про изменение консенсуса. Это про **коммуникацию рисков** и предотвращение overclaim.

## Входные данные (source of truth)

- `rubin-formal/proof_coverage.json`
  - `proof_level`: уровень строгости/реализма семантики доказательств
  - `coverage[]`: pinned‑секции из `spec/SECTION_HASHES.json` и их статусы
  - `claims.allowed` / `claims.forbidden`: рамка допустимых публичных формулировок (обязательно)

## Source rebind: 109 → 102

Текущий imported-source obligation — `102` пути: исходный 109-path inventory
минус ровно семь `DROP_STALE_SOURCE` путей:

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

Арифметика provenance:
`active_partition_equation = "79 + 14 + 1 + 1 + 7 = 102"` и
`original_inventory_equation = "102 + 7 = 109"`. Byte equality является
lifecycle/provenance evidence против pinned external source. Локальные checkers
проверяют записанный manifest и достижимый registry, но не реконструируют байты
внешнего OID.

Удалённые пути не являются текущим evidence. Их возможное восстановление или
замена — отдельно авторизованный follow-up.

Внутри тех же 102 активных путей семь test-path адаптаций имеют disposition
`IMPORT_PACKAGE_CHECK_OR_TEST` и не увеличивают path count:

- `tests/test_check_formal_registry_truth.py`
- `tests/test_integration.py`
- `tests/test_path_resolution.py`
- `tests/test_registry_extraction.py`
- `tests/test_scope_and_names.py`
- `tests/test_strip_lean_comments.py`
- `tests/test_validation.py`

Эта классификация относится только к воспроизводимому package-test import
routing и не является новым formal evidence. RUB-959 section-hash digest остаётся
`c21c234f6380f9421a10481958993ba23ec31277217fcdd6d5d4d4d613df74a3`.

## Термины

- **Pinned section**: секция из `spec/SECTION_HASHES.json`, которая hash‑pin’ится и должна быть синхронна со спекой.
- `status=proved`: утверждения для pinned‑секции доказаны в рамках текущего `proof_level`.
- `status=proved_with_axiom`: утверждения доказаны, но proof опирается на один или более явно названных допущений. Для hash/commitment-секций это обычно означает reduction к collision resistance, а не аксиомо-свободную невозможность коллизии.
- `status=stated`: резервный статус для будущих registry rows без machine-checked доказательства. В текущем registry таких строк нет.
- `status=deferred`: резервный статус для сознательно не покрытой секции. В текущем registry таких строк нет.
- `evidence_level`: главный truth-correction field для честного public claim ceiling. Он отделяет universal, behavioral, assumption-backed и contract-level entries даже когда registry status уже `proved`.

## Уровни доказательств (`proof_level`)

- `toy-model`: модельный baseline (ранняя форма инвариантов). **Не** байтовая и **не** эквивалентность с Go/Rust.
- `spec-model`: модель уже явно отражает ключевые определения из CANONICAL (ещё не bit‑exact wire).
- `byte-model`: доказательства привязаны к byte‑accurate wire/serialization формулам.
- `refinement`: есть слой уточнения “модель → исполняемая семантика”.
  В текущем `rubin-formal` это op-scoped bridge map из `rubin-formal/refinement_bridge.json`:
  часть ops закрыта Go-trace / CV replay, часть — LIVE/BRIDGE theorem surface
  на Lean transcription с explicit parity boundary к Go/Rust. Это **не**
  uniform machine-checked equivalence между Lean и Go/Rust по всему critical-op
  surface.

## Профили готовности (CI gate)

В protocol repository gate-логика реализована в
`tools/check_formal_risk_gate.py` и
`tools/check_formal_coverage.py`.

### `phase0` (по умолчанию)

Для Phase‑0/devnet достаточно:
- baseline существует и консистентен;
- **нет** pinned‑секций со `status=deferred`;
- `claims.allowed/forbidden` присутствуют (anti‑overclaim).

`proof_level=toy-model` разрешён (как baseline).

### `devnet`

То же что `phase0`. (Профиль выделен, чтобы позже ужесточить без ломки tooling.)

### `audit`

Для внешнего аудита claims о “formal verification” недопустимы при `proof_level=toy-model`.
Требование:
- нет `deferred`;
- `proof_level != toy-model`.

### `freeze`

Минимальный “freeze‑adjacent” профиль:
- `proof_level ∈ {byte-model, refinement}`;
- `stated=0` и `deferred=0`.

## Текущая truth snapshot

На текущем refinement-срезе registry содержит:

- `28` rows со статусом `proved`;
- `4` rows со статусом `proved_with_axiom`;
- `27` universal entries;
- `4` assumption-backed entries;
- `1` model-level entry;
- `0` stated rows;
- `0` deferred rows.
- `575` theorem references и `552` unique theorem names.

Это сильнее старого bootstrap narrative, но всё ещё не даёт права заявлять universal proof of full CANONICAL semantics.

Отдельно по Lean ↔ Go/Rust bridge ceiling:

- источник истины: `rubin-formal/refinement_bridge.json`
- ceiling op-scoped, не repo-wide
- допустимы mixed ceilings (`machine_checked_universal`,
  `machine_checked_assumption_backed`, `machine_checked_behavioral`,
  `machine_checked_contract`)
- недопустима формулировка, будто весь critical-op layer uniformly backed by
  Go-trace refinement или machine-checked Lean↔Go/Rust equivalence

## Risk scoring (информативно)

`tools/formal_risk_score.py` вычисляет простой монотонный score и tier (LOW/MEDIUM/HIGH) для прозрачного статуса.
Это **не** консенсус‑гейт; используется для отчётов и dashboard.
