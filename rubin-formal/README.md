# RUBIN Formal (Lean 4)

Machine-checked formal proof surface for the RUBIN L1 blockchain protocol.

## Contents

- Lean 4 package `RubinFormal`
- `proof_coverage.json` — machine-readable registry with exactly 31 formal coverage entries
- Each registry entry carries explicit `evidence_level`, `proof_trust`, `notes`, and `limitations` so that public claims never outrun the actual proof boundary

## Source rebind: 116 original → 102 active (4 `DROP_RETIRED_GENERATED_SOURCE` + 3 `DROP_RETIRED_SOURCE` + 7 `DROP_STALE_SOURCE`; `CoreExtRefinement.lean` is separately `SEMANTIC_THEOREM_RECONCILIATION`-retired)

## Claim boundary (critical)

This proof pack contains bounded executable replay/refinement evidence for the
models imported by `RubinFormal.Conformance.Index`, plus Lean theorems over
their registered scopes. It provides reproducible machine-checked evidence but
**is not** a universal formal verification of the entire CANONICAL spec.

Current machine-readable status: `proof_level=refinement`, `claim_level=refined`, `package_maturity=experimental_pending_reverification`.

Finite CV replay is compiled conformance evidence. A `cv_*_vectors_pass` theorem
is section-registered only where it is claim-bearing `machine_checked_contract`
evidence; it is not universal/model section proof evidence.

Permitted claim formulations (OK):

- "Lean executable evidence covers the bounded model lists imported by
  `RubinFormal.Conformance.Index`; runtime/parallel-only `CV-PV-*` is excluded"
- "Bridge evidence is op-scoped Lean evidence; Go/Rust correspondence remains human-reviewed"
- "Formal coverage is machine-readable with explicit evidence levels: universal, behavioral, assumption-backed, contract-level, and model-level"

`spec/SECTION_HASHES.json` manifest membership and formal `coverage[]` registry
membership are independent sets, not a one-to-one mapping. A `section_heading`
is a registry row label: some labels are exact specification headings; others
identify residual, bridge, model, or other bounded formal scopes. Row status,
evidence, and claims apply to that registered row, not automatically to a
manifest member. An unregistered manifest H2 is not thereby formally proved,
and a registered formal row need not remain an independent manifest member.

The single `spec_section_hashes_sha3_256` pins the exact approved locally prepared
retirement manifest as a disposition; it proves no model applicability, canonical
validity or client parity. The static Lean registry model classifies
every non-assigned tag, including `0x00FF`, `0x0102` and `0x0105`, as invalid,
and the UTXO model refuses every non-retained tag. These bounded model changes do not establish live-client
correctness or Go/Rust parity.
Local spec preparation precedes metadata human merge, then spec first
publication/merge, then client removal. Old canonical spec/new pin comparison
necessarily rejects between the metadata and matching spec merges.

Native-rotation replay uses a manual legacy bounded stub, unwritten by current
generators. Its `*-02` JSON rows have `create_height=100`, `height=199`,
`suite_id=2`, `expect_ok=true`; Lean uses `spendHeight=200`, `expectOk=false`.
The CLI `rotation_spend_suite_check` ignores `covenant_type` after parsing, so
these labels do not prove individual covenant spends or full JSON/manual-stub
semantic equivalence. Removing its three retired rows proves no live covenant spend.

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
- The formal coverage registry currently contains exactly 31 machine-checked entries
- Registry status counts: 23 `proved`, 5 `proved_with_axiom`, 3 `stated`, 0 `deferred`
- Claim strength breakdown: 22 universal, 5 assumption-backed, 3 model-level, 1 contract-level
- Machine-checked status does not imply uniform claim strength — the honest boundary is set by `status`, `evidence_level`, and `limitations`
- Extra formal-only theorems do not establish a registered formal coverage row unless registered in the machine-readable registry

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
2. Do not elevate formal-only extra theorems to public formal-coverage claims without an explicit registry update
3. Theorem-level traceability (`theorem_refs`) is tracked as a separate hygiene/improvement effort, not mixed with truth-correction
