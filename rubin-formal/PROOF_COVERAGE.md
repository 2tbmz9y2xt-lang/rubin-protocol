# Proof Coverage (bootstrap)

Источник: `spec/SECTION_HASHES.json`  
Машинный реестр: `rubin-formal/proof_coverage.json`

Текущее состояние: все pinned секции заведены со статусом `proved` (модельный baseline).

## Путь к freeze-ready

1. Углубить доказательства до байтовой эквивалентности формул из CANONICAL.
2. Для consensus-critical safety-инвариантов добавить refinement-слой (model → executable path).
3. Держать матрицу покрытия в синхроне с hash-pinning CANONICAL.
