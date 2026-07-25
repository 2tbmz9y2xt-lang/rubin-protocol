# RUBIN Formal (Lean 4)

Machine-checked formal proof surface for the RUBIN L1 blockchain protocol.

## Contents

- Lean 4 package `RubinFormal`
- `proof_coverage.json` — machine-readable coverage registry with 32 section entries
- Each registry entry carries explicit `evidence_level`, `proof_trust`, `notes`, and `limitations` so that public claims never outrun the actual proof boundary

## Source rebind: 116 original → 102 active (4 `DROP_RETIRED_GENERATED_SOURCE` + 3 `DROP_RETIRED_SOURCE` + 7 `DROP_STALE_SOURCE`; `CoreExtRefinement.lean` is separately `SEMANTIC_THEOREM_RECONCILIATION`-retired)

## Claim boundary (critical)

This proof pack is an executable replay/refinement surface for the non-`CV-PV-*`
conformance fixtures whose replay modules are imported by
`RubinFormal.Conformance.Index`, plus live Lean theorems over select canonical
sections. It provides reproducible machine-checked evidence but **is not** a
universal formal verification of the entire CANONICAL spec.

Current machine-readable status: `proof_level=refinement`, `claim_level=refined`, `package_maturity=experimental_pending_reverification`.

Finite CV replay is compiled conformance evidence. A `cv_*_vectors_pass` theorem
is section-registered only where it is claim-bearing `machine_checked_contract`
evidence; it is not universal/model section proof evidence.

Permitted claim formulations (OK):

- "Lean executable semantics replay the non-`CV-PV-*` conformance fixtures
  represented by modules imported by `RubinFormal.Conformance.Index`"
- "Bridge evidence is op-scoped Lean evidence; Go/Rust correspondence remains human-reviewed"
- "Pinned-section coverage is machine-readable with explicit evidence levels: universal, behavioral, assumption-backed, contract-level, and model-level"

Prohibited claim formulations (NOT OK):

- "formal verification of RUBIN consensus / CANONICAL"
- "bit-exact wire/serialization proven"
- "universal mechanized equivalence between spec text and Go/Rust implementations"

Source of truth for claim boundary: `proof_coverage.json` (`proof_level`, `package_maturity`, `claims`, and row-level `proof_trust`).
`claim_level` (`toy|byte|refined`) is CI-validated for consistency against `proof_level`.

Wire model notes:

- `RubinFormal.ByteWireV2` — real CompactSize / byte-accurate proof surface for current wire claims
- `RubinFormal.ByteWireLegacy` — toy bootstrap model for single-byte CompactSize only (`n < 253`) and `TxMini`

## Risk model / CI gate

- Documentation: `RISK_MODEL.md`
- Lean validation (in-tree package): `lake build`
- Registry/claims linting: protocol-root tooling from `tools/`

## What this means

- This is **not** a freeze-ready package at the level of "universal byte-accurate wire + state transition model for all sections"
- Consensus rules are not changed by this formal package
- The formal coverage registry currently contains 32 machine-checked section entries
- Registry status counts: 25 `proved`, 4 `proved_with_axiom`, 3 `stated`, 0 `deferred`
- Claim strength breakdown: 24 universal, 4 assumption-backed, 3 model-level, 1 contract-level
- Machine-checked status does not imply uniform claim strength — the honest boundary is set by `status`, `evidence_level`, and `limitations`
- Extra formal-only theorems are not counted as pinned-section claims unless registered in the machine-readable registry

## Local build

```bash
export PATH="$HOME/.elan/bin:$PATH"
lake env lean --version
lake build
```

Integrated workspace wrapper:

```bash
cd .. && scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake build'
```

## Roadmap

1. Keep `proof_coverage.json`, public narrative, and closeout evidence in sync
2. Do not elevate formal-only extra theorems to public pinned-section claims without an explicit registry update
3. Theorem-level traceability (`theorem_refs`) is tracked as a separate hygiene/improvement effort, not mixed with truth-correction
