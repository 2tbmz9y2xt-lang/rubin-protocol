# RUBIN Formal (Lean 4)

Machine-checked formal proof surface for the RUBIN L1 blockchain protocol.

## Contents

- Lean 4 package `RubinFormal`
- `proof_coverage.json` — machine-readable registry with exactly 36 formal coverage entries
- Each registry entry carries explicit `evidence_level`, `proof_trust`, `notes`, and `limitations` so that public claims never outrun the actual proof boundary

## Source rebind: 116 original → 102 active (4 `DROP_RETIRED_GENERATED_SOURCE` + 3 `DROP_RETIRED_SOURCE` + 7 `DROP_STALE_SOURCE`; `CoreExtRefinement.lean` is separately `SEMANTIC_THEOREM_RECONCILIATION`-retired)

## Claim boundary (critical)

This proof pack contains bounded executable replay/refinement evidence for the
models imported by `RubinFormal.Conformance.Index`, plus Lean theorems over
their registered scopes. It provides reproducible machine-checked evidence but
**is not** a universal formal verification of the entire CANONICAL spec.

Current machine-readable status: `proof_level=refinement`, `claim_level=refined`, `package_maturity=experimental_pending_reverification`.

Finite CV replay is compiled conformance evidence. A `cv_*_vectors_pass`
theorem is section-registered as claim-bearing `machine_checked_contract`
evidence. The sole model-row exception here is
`deterministic_parse_error_mapping`: its `cv_parse_vectors_pass` component
retains that finite evidence scope for the pinned generated CV-PARSE set,
alongside separate parse-stage model declarations. It is not universal/model
section proof evidence and does not promote the row's evidence level.

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
covenant-registry manifest as a disposition; it proves no model applicability, canonical
validity or client parity. The static Lean registry model classifies
every non-assigned tag, including `0x00FF`, `0x0102` and `0x0105`, as invalid,
and the UTXO model refuses every non-retained tag. These bounded model changes do not establish live-client
correctness or Go/Rust parity.
Local spec preparation precedes spec draft publication, then metadata human
merge, then spec merge. Old canonical spec/new pin comparison
necessarily rejects between the metadata and matching spec merges.

`canonical_utxo_state_model` registers the separate `StateConsensusV1` bounded
model of proposed spec PR 441 at `500dbe9dc58351832847fa1da4492110c4535996`
(CANONICAL §§4/13/18/23/25, state machine §§2/2.5). Its kernel-checked theorem
characterizes final-map accounting, first-result order and private-candidate
release for later comparison. It does not adopt the proposal or publish state.
Complete valid map membership/unique real outpoints, typed read/integrity
outcomes and root equality are supplied premises. Scalar 100→50 tests only the
signed-growth arithmetic; the complete-map shrink example is 100→56.
Root bytes, Go/Rust parity, storage, inverse/LAG local checks and physical
effects remain outside this row. The separate manifest pin and original
116→102 source census are unchanged; the new model is local source.

The existing `fork_choice` row also registers the single
`RubinFormal.RecoveryCore.recovery_core_contract` in
`ForkChoiceJournalDecision.lean`. Its seven named finite groups model RUB-1795's
selected proposed recovery-only R1–R7: structural predicate, scoped qualification,
filter-before-rank selection, bounded proof capture, independent P/native
disposition, actual-R/SAME-D H1 preservation and unchanged public observations.
Expectations are fixed independently at those computed model owners. Canonical
premises bind rubin-spec `c5e701492940c407a9267be9e194f98e54241149`; the proposed
rule is not adopted by this registration. Parse/header/root authenticity,
historical meaning, complete immutable source/census and actual native readback
remain assumptions. Arithmetic bounds prove no physical fit or crash recovery.
Actual ordered public C04, client/native C19 and future C20 publication X/D→X
remain external. Old `JournalChoice` assertions in the same file remain
unregistered. The row stays `stated/compiler_trusted/machine_checked_model`.
Neither local model registration nor refinement changes the bridge,
source-manifest disposition or manifest pin. The separate publication update
in this PR advances `spec_section_hashes_sha3_256` in `proof_coverage.json`
to the reviewed specification-manifest digest.

The existing `utxo_state_model` row also registers the single
`RubinFormal.RootPathComparisonV1.root_path_comparison_contract` in
`RootPathComparisonV1.lean`, a kernel-checked property of a bounded model of the
proposed comparison of an obtained committed root and committed path nodes of
U_parent with the outpoints resolved present. Over abstract 288-bit keys,
positions, node identities and sequences of obtained results, consumptions and
unavailable reads it states: on a canonical tree holding the key, the canonical
node and the child on the key's side of every branch with its prefix pass; passing
positions reach the key's leaf within 288 branches; the listed wrong roots and
nodes fail; and the first failing obtain or unavailable read decides, unaffected
by consumptions. It has no bridge to Go or Rust code and does not prove hashing,
root bytes, the derivation of Root(U_candidate), store reads, how a result comes
to identify a node or any client behavior. Registration adds one theorem
reference and one unique theorem name; the row stays
`proved/compiler_trusted/machine_checked_universal` for its other theorems. The
critical operations of the refinement bridge and the pin
`spec_section_hashes_sha3_256` are unchanged; both copies of the active-path
manifest (`source_rebind.active_path_manifest` in `proof_coverage.json` and in
`refinement_bridge.json`) carry the hash of the edited registry-truth checker.

The `utxo_state_model` row also registers the single
`RubinFormal.OutpointInsertionV1.outpoint_insertion_contract` in
`OutpointInsertionV1.lean`, a kernel-checked property of a bounded model of the
proposed rule on the single insertion of an outpoint and of the proposed failed
check for a parent-view entry or leaf at an inserted outpoint. Over abstract
cores, identifier functions, chains, outpoint sets and read-event sequences it
states: under the premise that equal identifiers have equal cores, applied
identifiers are distinct, every insertion finds its outpoint absent and none
follows a removal of it; a premise break gives no result from its block on;
and the first unavailable read or failing obtain decides, a block without a
result having no outcome. Of the failed checks of the store it represents only the
proposed one; no other failed check, including the cross-row consistency check, is
represented, and where one fails the model's value need not be the specification's
outcome. It has no bridge to Go or Rust code and does not
prove hashing, bytes, the transaction encoding, store reads, the derivation of
Root(U_candidate), how a result comes to identify a leaf, the rules the model
does not represent or any client behavior. Registration adds one theorem
reference and one unique theorem name; the row stays
`proved/compiler_trusted/machine_checked_universal` for its other theorems. The
pin `spec_section_hashes_sha3_256` is unchanged; both manifest copies carry the
hash of the edited registry-truth checker.

Native-rotation replay uses a manual legacy bounded stub, unwritten by current
generators. Its `*-02` JSON rows have `create_height=100`, `height=199`,
`suite_id=2`, `expect_ok=true`; Lean uses `spendHeight=200`, `expectOk=false`.
The CLI `rotation_spend_suite_check` ignores `covenant_type` after parsing, so
these labels do not prove individual covenant spends or full JSON/manual-stub
semantic equivalence.

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
- The formal coverage registry currently contains exactly 36 machine-checked entries
- Registry status counts: 23 `proved`, 5 `proved_with_axiom`, 8 `stated`, 0 `deferred`
- Claim strength breakdown: 22 universal, 5 assumption-backed, 8 model-level, 1 contract-level
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
