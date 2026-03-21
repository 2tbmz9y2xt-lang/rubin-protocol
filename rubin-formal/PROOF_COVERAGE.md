# Proof Coverage (bootstrap summary)

Источник: `spec/SECTION_HASHES.json`  
Authoritative machine-readable source: standalone `rubin-formal/proof_coverage.json`  
In-repo summary: `rubin-protocol/rubin-formal/proof_coverage.json`

Текущее состояние: authoritative standalone source-of-truth фиксирует `proof_level=refinement`,
`claim_level=refined`, полный registry по 17 pinned section keys и явные `notes` / `limitations`
для thin или partial entries. Файл в `rubin-protocol` — это summary subset для local CI/tooling;
он не должен расходиться по top-level claim boundary и hash baseline, но может не содержать полный registry.

## Термины (важно)

- `proof_level=refinement` означает: в репо есть исполняемый Lean replay-слой и trace-based
  Go(reference) → Lean refinement checks для критических ops на conformance-наборе.
- `claim_level` фиксирует допустимый публичный уровень заявлений:
  - `toy` (только model-baseline),
  - `byte` (byte-accurate слой),
  - `refined` (refinement to executable path).
- `status=proved/stated/deferred` относится к конкретной pinned-секции **в рамках указанного `proof_level`**.

Внешний аудит / freeze-ready коммуникации **НЕ ДОЛЖНЫ** трактовать `proof_level=refinement`
как “formal verification of CANONICAL for all inputs/sections”.

Связка с hash-pinning:

- `spec/SECTION_HASHES.json` сейчас содержит 17 pinned section keys.
- summary `proof_coverage.json` обязан совпадать с authoritative standalone файлом по
  `proof_level`, `claim_level`, `spec_section_hashes_sha3_256` и по смысловой границе claims
  для тех секций, которые он перечисляет.
- Если standalone registry ослабляет секционный claim до `stated`, summary не имеет права
  оставлять для той же секции более сильный статус.

## Путь к freeze-ready

1. Держать summary в синхроне с standalone `rubin-formal` реестром и с hash-pinning CANONICAL.
2. Расширить protocol tooling так, чтобы summary всё меньше отличался от authoritative registry.
3. Для consensus-critical safety-инвариантов добавлять более сильный beyond-fixtures proof surface.

## Risk scoring / gates

Профили готовности (Phase‑0/devnet/audit/freeze) и правила CI описаны в `rubin-formal/RISK_MODEL.md`.

Локально:

```bash
scripts/dev-env.sh -- python3 tools/formal_risk_score.py
scripts/dev-env.sh -- python3 tools/check_formal_risk_gate.py --profile phase0
scripts/dev-env.sh -- python3 tools/check_formal_refinement_bridge.py
scripts/dev-env.sh -- python3 tools/check_formal_claims_lint.py
```
