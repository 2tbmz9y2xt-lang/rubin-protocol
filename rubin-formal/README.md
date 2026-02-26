# RUBIN Formal (Lean4) — bootstrap

Этот каталог содержит in-repo formal proof-pack baseline для RUBIN.

## Что есть сейчас

- Lean4-пакет `RubinFormal`
- `proof_coverage.json` с baseline-покрытием всех pinned секций из `spec/SECTION_HASHES.json`
- модельные теоремы (`status=proved`) для pinned секций в `RubinFormal/PinnedSections.lean`

## Граница claims (критично)

Этот proof-pack — **byte-level replay coverage** для conformance-фикстур (CV-*.json) и baseline-слой
для дальнейшей формализации. Он нужен для воспроизводимого “якоря”, но **не** является freeze-ready
универсальной формальной верификацией CANONICAL.
Текущий machine-readable статус: `proof_level=byte-model`, `claim_level=byte`.

Разрешённые формулировки (OK):
- “byte-level executable replay coverage for all conformance fixtures (CV-*.json) via Lean native_decide”
- “refinement to Go/Rust executable path equivalence is pending”

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

- Это **не** полный freeze-ready пакет уровня “универсальная байтовая модель wire + state transition + refinement”.
- Консенсусные правила не меняются.
- Цель текущего шага — зафиксировать воспроизводимый in-repo baseline с byte-level replay покрытием фикстур.

## Локальный запуск

```bash
scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake env lean --version'
scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake build'
```

## Дальше

1. Углубить модель до байтовой/сериализационной эквивалентности с CANONICAL.
2. Разделить модельные и implementation-refinement доказательства.
3. Поддерживать `proof_coverage.json` в синхроне со `spec/SECTION_HASHES.json`.
