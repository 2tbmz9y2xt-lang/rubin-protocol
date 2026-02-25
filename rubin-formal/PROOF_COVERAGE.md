# Proof Coverage (bootstrap)

Источник: `spec/SECTION_HASHES.json`  
Машинный реестр: `rubin-formal/proof_coverage.json`

Текущее состояние: все pinned секции заведены со статусом `proved` **в рамках `proof_level=toy-model`**.

## Термины (важно)

- `proof_level=toy-model` означает: доказательства относятся к упрощённой/модельной семантике и служат baseline-слоем,
  а не байтовой (wire) или исполняемой (Go/Rust) эквивалентности.
- `claim_level` фиксирует допустимый публичный уровень заявлений:
  - `toy` (только model-baseline),
  - `byte` (byte-accurate слой),
  - `refined` (refinement to executable path).
- `status=proved/stated/deferred` относится к конкретной pinned-секции **в рамках указанного `proof_level`**.

Внешний аудит / freeze-ready коммуникации **НЕ ДОЛЖНЫ** трактовать `status=proved` как “formal verification of CANONICAL”.

## Путь к freeze-ready

1. Углубить доказательства до байтовой эквивалентности формул из CANONICAL.
2. Для consensus-critical safety-инвариантов добавить refinement-слой (model → executable path).
3. Держать матрицу покрытия в синхроне с hash-pinning CANONICAL.

## Risk scoring / gates

Профили готовности (Phase‑0/devnet/audit/freeze) и правила CI описаны в `rubin-formal/RISK_MODEL.md`.

Локально:

```bash
python3 tools/formal_risk_score.py
python3 tools/check_formal_risk_gate.py --profile phase0
python3 tools/check_formal_refinement_bridge.py
python3 tools/check_formal_claims_lint.py
```
