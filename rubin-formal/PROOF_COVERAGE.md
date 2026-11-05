# Proof Coverage

Источник: `spec/SECTION_HASHES.json`  
Машинный реестр: `rubin-formal/proof_coverage.json`

Текущее состояние: machine-readable source-of-truth (`proof_coverage.json`) фиксирует
`proof_level=refinement`, `claim_level=refined`, `package_maturity=experimental_pending_reverification`, полный registry по 34 current coverage entries и явные
`notes` / `limitations` для non-universal claims. Lean replay/refinement evidence
is bounded by the models imported by `RubinFormal.Conformance.Index`;
runtime/parallel-only `CV-PV-*` gates remain outside this scope.

Native-rotation replay is a manual legacy bounded stub, not output of current
generators. Its `*-02` JSON rows use `create_height=100`, `height=199`,
`suite_id=2`, `expect_ok=true`; Lean uses `spendHeight=200`, `expectOk=false`.
The CLI `rotation_spend_suite_check` ignores `covenant_type` after parsing;
these labels prove neither individual covenant spends nor full JSON/manual-stub
semantic equivalence. The bounded registry/UTXO models reject `0x0105`;
their replay evidence does not prove
live-client correctness or Go/Rust parity.

`SECTION_HASHES` manifest membership and formal `coverage[]` registry membership
are independent sets, not a one-to-one mapping. The registry has exactly 34
formal coverage entries. A `section_heading` is a registry row label: some
values are exact specification headings; others identify residual, bridge,
model, or other bounded formal scopes. Row status, evidence, and claims apply
to that registered row, not automatically to a manifest member. An unregistered
manifest H2 is not thereby formally proved, and a registered formal row need
not remain an independent manifest member.

The single manifest digest is a disposition of the exact approved locally
prepared covenant-registry snapshot, not proof of applicability, canonical
validity or client parity. Local spec preparation precedes spec draft
publication, then metadata human merge, then spec merge. The prepared spec is
noncanonical until its human merge; old canonical spec/new pin comparison
necessarily rejects between the metadata and matching spec merges.

The new `canonical_utxo_state_model` row is `stated/machine_checked_model`,
with the single kernel-checked `StateConsensusV1.state_consensus_contract`.
It models proposed PR 441 at `500dbe9dc58351832847fa1da4492110c4535996`,
CANONICAL §§4/13/18/23/25 and state machine §§2/2.5. C01-C10 distinguish
accounting/cap/growth/root order, genesis, exact-parent suffixes and inverse
exclusions. Earlier validation, complete valid membership/unique outpoints,
read/integrity outcomes and root equality are supplied premises. Scalar
100→50 is arithmetic only; a complete nonempty map cannot total 50 bytes.
No result transfers to existing rows, actual root bytes, clients, storage,
IMAGE history or physical qualification. The proposal, separate metadata
pin and human adoption remain separate; the original source census is unchanged.

Конечный CV replay — это compiled conformance evidence. Теорема
`cv_*_vectors_pass` section-registered только там, где она является
claim-bearing `machine_checked_contract` evidence; она не является
universal/model section proof evidence.

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

- `proof_coverage.json` сейчас содержит 34 machine-checked registry entries.
- Status counts: `23` `proved`, `5` `proved_with_axiom`, `6` `stated`, `0` `deferred`.
- Не все 34 entries равны по силе claims: честная граница определяется `evidence_level` и `limitations`.
- Extra formal-only theorems do not establish a registered formal coverage row
  unless they are represented by a registry entry.

`RubinFormal.ForkChoiceJournalDecision`, imported by the package root, contains
additional unregistered finite decision assertions against proposed
rubin-spec#441@500dbe9dc58351832847fa1da4492110c4535996 (§23 and MEMPOOL
§6.4.1.4). It derives candidate qualification, strict work/raw32 preference,
operation-domain completeness, journal use and protected-basis refusal
from explicit abstract header/path/state/source/context premises. Intermediate
SAME/DIFFERENT scope is assumed from its qualified external owner on the exact
consumer basis, including full provenance; Context labels alone prove no scope.
Final independence and the winner are computed by the model. Initial and
continued imported states retain original b0/H0/E0 and conditional assurance;
actual T is compared separately from a heavier scheduling header. Its pure
consumer retains public state and source-owned observations. These assertions
prove neither premise acquisition/authenticity nor journal producers, P/H1,
persistence, runtime refinement, collision freedom, publication or READY.
Existing registered theorem/file/trust/status/evidence scope and the six-positive
CV bridge remain unchanged. PR3801 separately owns the merge-only Part A pin;
the proposed source and this evidence are not canonical adoption or whole-§23
closure.

## Текущая раскладка evidence levels

- `machine_checked_universal`: 22
- `machine_checked_assumption_backed`: 5
- `machine_checked_model`: 6
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
