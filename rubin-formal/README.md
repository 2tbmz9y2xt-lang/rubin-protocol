# RUBIN Formal (Lean4) — bootstrap

Этот каталог содержит in-repo formal proof-pack baseline для RUBIN.

## Что есть сейчас

- Lean4-пакет `RubinFormal`
- `proof_coverage.json` с baseline-покрытием всех pinned секций из `spec/SECTION_HASHES.json`
- модельные теоремы (`status=proved`) для pinned секций в `RubinFormal/PinnedSections.lean`

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
