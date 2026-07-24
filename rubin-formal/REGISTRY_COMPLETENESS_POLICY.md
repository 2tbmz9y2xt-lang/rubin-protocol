# Registry Completeness Policy

**Effective:** 2026-07-24
**Applies to:** `proof_coverage.json`, `refinement_bridge.json`
**Validator:** `tools/check_formal_registry_truth.py`

## 1. Scope

The formal registries are the machine-readable claim layer of rubin-formal.
They track which spec sections have formal coverage, at what evidence level,
and which theorems back each claim.

This policy defines what MUST be registered, what is explicitly excluded,
and how to evaluate a candidate theorem.

### Imported-source rebind: 116 original → 102 active (14 standalone `DROP_STALE_SOURCE` retirements; `CoreExtRefinement.lean` is separately `SEMANTIC_THEOREM_RECONCILIATION`-retired)

## 2. Registration Tiers

### MUST register (mandatory)

A theorem MUST appear in `proof_coverage.json` or `refinement_bridge.json` if it
satisfies ALL of:

1. **Class is LIVE or BRIDGE** — proves a property of a live consensus function,
   or proves equivalence between a model and a live function.
2. **Claim-bearing** — the theorem makes or supports a claim about a spec section
   (§N in RUBIN_L1_CANONICAL.md).
3. **Non-trivial** — the proof is not `rfl`, `rfl`-chain, or `exact ⟨rfl, ...⟩`
   on constant definitions.

### SHOULD register (recommended)

- MODEL theorems that are the sole formal evidence for a spec section and no
  LIVE/BRIDGE theorem exists yet. These should be registered with
  `evidence_level: "machine_checked_model"` to honestly represent coverage.
- Conformance vector replay theorems (`cv_*_vectors_pass`) — always registered
  as `machine_checked_contract`.

### MUST NOT register (excluded)

- **Helpers/lemmas** used only as proof steps (e.g., `bytearray_ne_of_size_lt`,
  `bne_false_eq`, `bool_gate_pass`).
- **Wrappers** — projections, specializations, aliases, trivial corollaries.
- **Legacy/deprecated** theorems in `*Legacy*.lean` files.
- **Cursor/parser internals** — `Cursor.getBytes_advances`, `getBytes_preserves_bs`,
  etc., unless they are the sole evidence for a spec section.
- **Tautologies** — `f x = f x` (determinism of pure functions), constant equalities.
- **Private** theorems (`private theorem`).
- **Test** theorems that exist only for compile-time validation.

### MAY register (discretionary)

- Arithmetic safety theorems (overflow guards, saturation bounds) — register if
  they back a spec section claim.
- FSM/activation theorems — register if they back a spec section claim about
  feature deployment.

## 3. Registration Checklist

Before adding a theorem to the registry:

1. Verify the theorem exists: `grep -r "theorem <name>" RubinFormal/`
2. Classify: LIVE / BRIDGE / MODEL / WRAPPER
3. Identify spec section: which §N does it cover?
4. Determine evidence level: `machine_checked_universal`, `machine_checked_behavioral`,
   `machine_checked_contract`, `machine_checked_model`, or
   `machine_checked_assumption_backed`
5. Verify no name collision with existing entries
6. Run `tools/check_formal_registry_truth.py` after edit

## 4. Evidence Level Taxonomy

| Level | Meaning |
|-------|---------|
| `machine_checked_universal` | Inductive proof over all inputs (∀ x, P x) |
| `machine_checked_behavioral` | Behavioral property on specific function paths |
| `machine_checked_contract` | Conformance vector replay (finite test set) |
| `machine_checked_model` | Property of a model/helper, no live bridge |
| `machine_checked_assumption_backed` | Universal reduction/proof whose ceiling depends on explicitly named assumptions |

## 5. Audit

The registry is auditable via:

- `tools/check_formal_registry_truth.py` — validates all paths, theorem names,
  and evidence level parity between registries.
- The gap between total theorems (code) and registered theorems (registry) is
  intentional and governed by this policy. Not every theorem needs registration.
