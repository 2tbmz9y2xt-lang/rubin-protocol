# RUBIN Formal (Lean4) — bootstrap

Этот каталог содержит in-repo formal proof-pack baseline для RUBIN.

## Что есть сейчас

- Lean4-пакет `RubinFormal`
- `proof_coverage.json` с machine-readable coverage registry (текущая явная формальная матрица: 13 pinned section keys)
- модельные теоремы (`status=proved`) для pinned секций в `RubinFormal/PinnedSections.lean`

## Граница claims (критично)

Этот proof-pack — executable replay/refinement coverage для conformance-фикстур (CV-*.json) и baseline-слой
для дальнейшей формализации. Он нужен для воспроизводимого "якоря", но **не** является универсальной
формальной верификацией CANONICAL.
Текущий machine-readable статус: `proof_level=refinement`, `claim_level=refined`.

Разрешённые формулировки (OK):

- "Lean executable semantics replay all conformance fixtures (CV-*.json)"
- "Go(reference) → Lean refinement is checked for critical ops over conformance fixture set"

Запрещённые формулировки (NOT OK):

- "formal verification of RUBIN consensus / CANONICAL"
- "bit-exact wire/serialization proven"
- "universal mechanized equivalence between spec text and Go/Rust implementations"

Источник истины по границе claims — `rubin-formal/proof_coverage.json` (`proof_level`, `claims`).
Дополнительно используется `claim_level` (`toy|byte|refined`) с CI-валидацией консистентности относительно `proof_level`.

## Risk model / CI gate

- Док: `rubin-formal/RISK_MODEL.md`
- Скрипты:
  - `tools/formal_risk_score.py`
  - `tools/check_formal_risk_gate.py --profile phase0`
  - `tools/check_formal_refinement_bridge.py`
  - `tools/check_formal_claims_lint.py`

## Что это значит

- Это **не** полный freeze-ready пакет уровня "универсальная байтовая модель wire + state transition для всех секций".
- Консенсусные правила не меняются.
- Формальный coverage registry сейчас явно отражает 13 pinned section keys; остальные pinned keys
  покрываются conformance/CI и должны коммуницироваться как такой coverage (без overclaim).

## Локальный запуск

```bash
scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake env lean --version'
scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake build'
```

## Дальше

1. Расширить формальный coverage registry с 13 до полного набора pinned section keys.
2. Углубить универсальные теоремы beyond-fixtures поверх текущего refinement слоя.
3. Поддерживать `proof_coverage.json` в синхроне со `spec/SECTION_HASHES.json` и narrative в `rubin-spec`.
