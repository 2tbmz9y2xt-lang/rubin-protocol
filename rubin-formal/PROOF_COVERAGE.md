# Proof Coverage (bootstrap summary)

Источник: `spec/SECTION_HASHES.json`  
Authoritative machine-readable source: standalone `rubin-formal/proof_coverage.json`  
In-repo summary: `rubin-protocol/rubin-formal/proof_coverage.json`

Текущее состояние: in-repo summary фиксирует `proof_level=refinement`,
`claim_level=refined`, registry по 18 section rows и явные `notes` / `limitations`
для thin или partial entries. В `coverage_summary` зафиксированы текущие счетчики:
11 `proved`, 7 `stated`, 0 `deferred`, 29 theorem references, 23 unique theorem names.
Повтор theorem name в нескольких section rows является coverage reference reuse, а не
дополнительным уникальным доказательством.

## Термины (важно)

- `proof_level=refinement` означает: в репо есть исполняемый Lean replay-слой и trace-based
  Go(reference) → Lean refinement checks для критических ops на conformance-наборе.
- `claim_level` фиксирует допустимый публичный уровень заявлений:
  - `toy` (только model-baseline),
  - `byte` (byte-accurate слой),
  - `refined` (refinement to executable path).
- `status=proved/stated/deferred` относится к конкретной pinned-секции **в рамках указанного `proof_level`**.
- `coverage_summary.theorem_references` считает ссылки из section rows; для уникального
  числа theorem names использовать `coverage_summary.unique_theorem_names`.

Внешний аудит / freeze-ready коммуникации **НЕ ДОЛЖНЫ** трактовать `proof_level=refinement`
как “formal verification of CANONICAL for all inputs/sections”.

## Critical op bridge

`rubin-formal/refinement_bridge.json` describes executable trace-op evidence. Its
`evidence_level=fixture_trace_refinement` means Go trace replay over the committed
replay-covered fixture traces for that gate plus the named bounded Lean theorem.
It does **not** mean a universal proof for every possible input.

Current bridge rows:

| op | gate | model theorem | scope |
| --- | --- | --- | --- |
| `parse_tx` | `CV-PARSE` | `RubinFormal.transaction_wire_proved` | listed trace IDs `PARSE-01`, `PARSE-16` plus bounded transaction wire theorem |
| `sighash_v1` | `CV-SIGHASH` | `RubinFormal.sighash_v1_proved` | listed trace IDs `SIGHASH-01`..`SIGHASH-05` plus bounded sighash theorem; no cryptographic security proof |
| `retarget_v1` | `CV-POW` | `RubinFormal.difficulty_update_proved` | listed retarget trace IDs plus bounded arithmetic/clamp invariants |
| `utxo_apply_basic` | `CV-UTXO-BASIC` | `RubinFormal.value_conservation_proved` | listed UTXO trace IDs plus bounded value-conservation statements; known trace drift allowances remain explicit |

Known deferred proof-expansion follow-ups:

- RUB-580: scope a universal `parse_tx` proof beyond fixture trace replay.
- RUB-581: verify and scope the byte-wire trace bridge residual.

Связка с hash-pinning:

- `spec/SECTION_HASHES.json` baseline представлен `spec_section_hashes_sha3_256` в
  `rubin-formal/proof_coverage.json`; current coverage registry contains 18 rows,
  including `parallel_validation_equivalence`.
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
