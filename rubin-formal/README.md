# RUBIN Formal (Lean4) — bootstrap

Этот каталог содержит in-repo formal proof-pack baseline для RUBIN.

## Что есть сейчас

- Lean4-пакет `RubinFormal`
- `proof_coverage.json` с baseline-покрытием всех pinned секций из `spec/SECTION_HASHES.json`
- модельные теоремы (`status=proved`) для pinned секций в `RubinFormal/PinnedSections.lean`

## Граница claims (критично)

Этот proof-pack — **toy/model baseline**. Он нужен для воспроизводимого “якоря” и ранних инвариантов,
но **не** является freeze-ready формальной верификацией CANONICAL.
Текущий machine-readable статус: `proof_level=toy-model`, `claim_level=toy`.

Разрешённые формулировки (OK):
- “model-level proved baseline for pinned sections”
- “toy/model invariants proved; refinement to byte-accurate/executable semantics is pending”

Запрещённые формулировки (NOT OK):
- “formal verification of RUBIN consensus / CANONICAL”
- “bit-exact wire/serialization proven”
- “proved equivalence between spec and Go/Rust implementations”

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

- Это **не** полный formal freeze-ready пакет уровня “бит-в-бит байтовая модель wire + state transition”.
- Консенсусные правила не меняются.
- Цель текущего шага — зафиксировать воспроизводимый in-repo baseline с модельно-доказанными инвариантами.

## Локальный запуск

```bash
cd rubin-formal
lake env lean --version
lake build
```

## Дальше

1. Углубить модель до байтовой/сериализационной эквивалентности с CANONICAL.
2. Разделить модельные и implementation-refinement доказательства.
3. Поддерживать `proof_coverage.json` в синхроне со `spec/SECTION_HASHES.json`.
