# Proof Coverage (bootstrap)

Источник: `spec/SECTION_HASHES.json`  
Машинный реестр: `rubin-formal/proof_coverage.json`

Текущее состояние: все pinned секции заведены со статусом `proved` **в рамках `proof_level=toy-model`**.

## Термины (важно)

- `proof_level=toy-model` означает: доказательства относятся к упрощённой/модельной семантике и служат baseline-слоем,
  а не байтовой (wire) или исполняемой (Go/Rust) эквивалентности.
- `status=proved/stated/deferred` относится к конкретной pinned-секции **в рамках указанного `proof_level`**.

Внешний аудит / freeze-ready коммуникации **НЕ ДОЛЖНЫ** трактовать `status=proved` как “formal verification of CANONICAL”.

## Путь к freeze-ready

1. Углубить доказательства до байтовой эквивалентности формул из CANONICAL.
2. Для consensus-critical safety-инвариантов добавить refinement-слой (model → executable path).
3. Держать матрицу покрытия в синхроне с hash-pinning CANONICAL.
