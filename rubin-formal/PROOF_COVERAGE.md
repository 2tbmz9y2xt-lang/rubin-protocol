# Proof Coverage

Источник: `spec/SECTION_HASHES.json`  
Машинный реестр: `rubin-formal/proof_coverage.json`

Текущее состояние: machine-readable source-of-truth (`proof_coverage.json`) фиксирует
`proof_level=refinement`, `claim_level=refined`, `package_maturity=experimental_pending_reverification`, полный registry по 32 current coverage entries и явные
`notes` / `limitations` для non-universal claims. Conformance-фикстуры
Lean replay/refinement слой покрывает non-`CV-PV-*` conformance fixtures,
представленные модулями, импортированными `RubinFormal.Conformance.Index`.
Runtime/parallel-only `CV-PV-*` gates в этот Lean replay scope не входят.

## Source rebind: 116 original → 102 active (4 `DROP_RETIRED_GENERATED_SOURCE` + 3 `DROP_RETIRED_SOURCE` + 7 `DROP_STALE_SOURCE`; `CoreExtRefinement.lean` is separately `SEMANTIC_THEOREM_RECONCILIATION`-retired)

## Термины (важно)

- `proof_level=refinement` означает: в репо есть исполняемый Lean replay-слой и
  op-scoped executable bridge evidence для критических ops. В зависимости от
  surface это может быть Go-trace replay, CV replay, LIVE/BRIDGE theorem layer
  на Lean transcription, или их честная комбинация. Это **не** означает один
  uniform trace-based Go(reference) → Lean refinement слой для всех critical ops.
- `claim_level` фиксирует допустимый публичный уровень заявлений:
  - `toy` (только model-baseline),
  - `byte` (byte-accurate слой),
  - `refined` (refinement to executable path).
- `status=proved/proved_with_axiom` относится к конкретной registry entry **в рамках указанного `proof_level`**.
- `status=proved_with_axiom` означает: proof закрывает секцию, но опирается на явно названные криптографические или модельные допущения, поэтому честный ceiling такой записи — `machine_checked_assumption_backed`, а не unconditional `universal`.
- `evidence_level` remains the public claim taxonomy.
- `proof_trust=kernel_checked`: compiled registered theorem closures do not report `Lean.ofReduceBool`; this does not claim absence of ordinary Lean foundations such as `propext`, `Quot.sound`, or `Classical.choice`.
- `proof_trust=compiler_trusted`: at least one registered theorem closure reports `Lean.ofReduceBool`, so the trusted base includes Lean compiler/evaluator behavior.

Внешний аудит / freeze-ready коммуникации **НЕ ДОЛЖНЫ** трактовать текущий `proof_level=refinement`
как “formal verification of CANONICAL for all inputs/sections”.

Связка с hash-pinning:

- `proof_coverage.json` сейчас содержит 32 machine-checked registry entries.
- Status counts: `25` `proved`, `4` `proved_with_axiom`, `3` `stated`, `0` `deferred`.
- Не все 32 entries равны по силе claims: честная граница определяется `evidence_level` и `limitations`.
- Extra formal-only theorems не считаются pinned-section coverage,
  если они не внесены отдельной registry entry.

## Текущая раскладка evidence levels

- `machine_checked_universal`: 24
- `machine_checked_assumption_backed`: 4
- `machine_checked_model`: 3
- `machine_checked_contract`: 1

## Lean ↔ Go/Rust bridge ceiling

- `refinement_bridge.json` — op-scoped bridge map, а не repo-wide equivalence claim.
- Для разных executable critical ops честный ceiling сейчас разный:
  `machine_checked_universal`, `machine_checked_assumption_backed`,
  `machine_checked_behavioral`, или `machine_checked_contract`.
- Статистика `refinement_bridge.json` считается отдельно от `proof_coverage.json`:
  12 operations = 6 `machine_checked_universal`, 5 `machine_checked_contract`,
  1 `machine_checked_behavioral`, 0 `machine_checked_assumption_backed`.
- Часть ops опирается на Go-trace / CV replay по pinned fixtures, часть — на
  LIVE/BRIDGE theorems о Lean transcriptions с явно названной human-reviewed
  parity к Go/Rust.
- Следовательно, текущий refinement слой **не** даёт права заявлять uniform
  machine-checked Lean↔Go/Rust equivalence или uniform Go-trace refinement для
  всего critical-op surface.

## Путь к freeze-ready

1. Держать матрицу покрытия в синхроне с public narrative и closeout evidence.
2. Углублять non-universal entries там, где это реально снижает consensus-risk или audit ambiguity.
3. Не смешивать truth-correction с отдельными hygiene lanes вроде theorem traceability.

## Risk scoring / gates

Профили готовности (Phase‑0/devnet/audit/freeze) и правила CI описаны в `rubin-formal/RISK_MODEL.md`.
Registry/claims lint запускаются из protocol-root tooling в `tools/`.

Локально:

```bash
export PATH="$HOME/.elan/bin:$PATH"
lake build
```

Integrated workspace:

```bash
cd .. && scripts/dev-env.sh -- python3 tools/check_formal_coverage.py
cd .. && scripts/dev-env.sh -- python3 tools/check_formal_risk_gate.py --profile phase0
cd .. && scripts/dev-env.sh -- python3 tools/check_formal_refinement_bridge.py
cd .. && scripts/dev-env.sh -- python3 tools/check_formal_claims_lint.py
```
