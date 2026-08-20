# Conformance (Go reference, Rust parity)

This directory contains machine-executable conformance fixtures and a runner that checks:

1) **Go as reference**: the Go client (`clients/go`) is the reference implementation for parity.
2) **Rust parity**: the Rust client (`clients/rust`) MUST match Go behavior for every executable gate.
3) **Spec compliance**: fixtures encode expected behavior derived from the normative spec; Go is also checked
   against fixture expectations to prevent “both clients drift together”.

Normative authority remains `spec/RUBIN_L1_CANONICAL.md` (consensus validity) and
`spec/RUBIN_COMPACT_BLOCKS.md` (normative P2P). This folder is a testing harness.

## Run

Run all local commands via `scripts/dev-env.sh` (stable PATH/OpenSSL/Lean toolchain wiring):

Run full bundle:

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
```

List gates:

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py --list-gates
```

Run a single gate:

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py --only-gates CV-COMPACT
```

## Coverage matrix

`conformance/MATRIX.md` is a generated coverage overview (gates/vectors/ops; local-only vs executable).

Regenerate:

```bash
scripts/dev-env.sh -- python3 tools/gen_conformance_matrix.py
```

Check (CI):

```bash
scripts/dev-env.sh -- python3 tools/gen_conformance_matrix.py --check
```

## Error expectation fields in vectors

Most ops use the `expect_err` field: the expected final error code returned by
the runtime for that vector.

The `CV-VALIDATION-ORDER` gate uses a separate `expect_first_err` field: the
expected **first** error code from the deterministic-order simulator
(nested/conflict cases). The final runtime error code (`expect_err`) and
`expect_first_err` may intentionally differ.

## Edge-pack baseline (critical domains)

`conformance/EDGE_PACK_BASELINE.json` pins the minimum required edge coverage
by domain:

- parse
- weight
- sighash
- covenants
- difficulty
- runtime_reorg
- DA
- mempool policy
- DA fee-floor policy

`runtime_reorg` coverage is not a new consensus fixture gate. The
`runtime_reorg` edge-pack domain is pinned using evidence from the existing
`CV-FORK-CHOICE` and `CV-TIMESTAMP` gates. Declared runtime source/test names
are metadata only in this slice; checker enforcement, source-boundary checks,
and reachability hardening are tracked separately.

Mempool/DA fee-floor domains are accounting-only here: they cite committed
executable CV vector IDs and replay evidence, but do not claim fuzz or formal
coverage. `tools/check_conformance_edge_pack.py` fails closed on fuzz/formal
`present`, `covered`, or `complete` claims until a later PR adds concrete
evidence validation.

Local/CI check:

```bash
scripts/dev-env.sh -- python3 tools/check_conformance_edge_pack.py
```

The gate fails when:

- a required domain gate or fixture is missing;
- a domain vector count is below the baseline;
- required edge vector IDs from the baseline are missing;
- `proof_coverage.json` claims fuzz/formal coverage for an edge/property domain
  before the checker supports concrete evidence validation.

## Fixture governance (manual-only)

`clients/go/cmd/gen-conformance-fixtures` — **manual-only tool**.

Rules:

1. The generator mutating mode **MUST NOT** run from CI (`ci.yml` or any other workflow).
2. Fixture regeneration is manual-only through the reproducible env:
   - `scripts/dev-env.sh -- bash -lc 'cd clients/go && go run ./cmd/gen-conformance-fixtures'`
3. Any change to `conformance/fixtures/CV-*.json` must update
   `conformance/fixtures/CHANGELOG.md` with what changed, why, and which tool was used.
4. Focused deterministic fixtures may use a dedicated generator:
   - `scripts/dev-env.sh -- python3 tools/gen_cv_da_integrity.py`

CI guard:

```bash
scripts/dev-env.sh -- python3 tools/check_conformance_fixtures_policy.py
```

### Check-only `--output-dir` mode

`gen-conformance-fixtures` supports a non-mutating mode: with an absolute
`--output-dir <path>`, the generator writes candidate fixtures **only** under
`<path>` and does not touch `conformance/fixtures/**`. Source data is still read
from committed `conformance/fixtures/**`.

```bash
scripts/dev-env.sh -- bash -lc \
  'cd clients/go && go run ./cmd/gen-conformance-fixtures --output-dir /tmp/candidate-fixtures'
```

Check-only mode properties:

- ML-DSA-87 keys are deterministic and embedded under
  `clients/go/cmd/gen-conformance-fixtures/testdata/keys/*.der`
  (committed conformance test material, not production keys);
- signing uses `(*consensus.MLDSA87Keypair).SignDigest32ForConformanceFixture`
  (FIPS 204 deterministic ML-DSA); the package-level caller-grep guard in
  `consensus/openssl_signer_conformance_fixture_test.go` restricts use to this generator;
- two runs with different `--output-dir` values produce **byte-identical** output
  (`TestGenerator_DeterministicOutputDir`);
- `--output-dir` must be absolute; committed `conformance/fixtures` and paths
  under it are forbidden;
- the production signing path (`SignDigest32`, hedged ML-DSA) **does not** change.

CI drift gate (`Q-CONF-FIXTURE-DRIFT-CHECK-01`):

```bash
scripts/dev-env.sh -- python3 tools/check_conformance_fixtures_drift.py
```

The script runs `gen-conformance-fixtures --output-dir <isolated-temp>`, then
byte-compares every generated file with committed `conformance/fixtures/**`.
Exit `0` means no drift, exit `1` means drift, and exit `2` means usage or
environment error. The script **never** writes under `conformance/fixtures/**`
(auto-regeneration in CI is forbidden); manual regeneration remains the
authoritative path.

## Canonical publication observables corpus (RUB-922 / C01)

`conformance/fixtures/protocol/canonical_pipeline_v1.json` freezes the external authority for
canonical-pipeline results and effects. It is generator-owned by `clients/go/cmd/gen-conformance-fixtures`,
byte-guarded by the drift gate, kept outside the auto-executed top-level `CV-*.json` glob, and
defined field by field (`kind`, `pending_owner`, `coverage_receipt`) by
`conformance/schemas/cv-canonical-pipeline-v1.json` (schema version 1). The artifact's own
`pending_owner` fields are the current map; the 2026-08-17 `conformance/fixtures/CHANGELOG.md` entry
records it at freeze (RUB-1195 owns section-19 relay; RUB-893 owns inbound-budget identities, budget
races and reservation overflow; RUB-910 owns permit/LOCAL_BUSY, retry-slot races, reclaimed-hash
inventory and the orphan-pool result classification — duplicate / oversize / source-51 refusal). It is
**INERT**: its only executors are the RUB-923 Go adapter, the RUB-926 acceptance gate, the RUB-924
Rust adapter and the RUB-901 comparator, none of which exists yet, so no canonical-publication slice
may claim it as a passing gate.

### The BUILDING C01-R2 successor pair (RUB-1207 / RUB-1208)

`conformance/fixtures/protocol/canonical_pipeline_v2.json` + `conformance/schemas/cv-canonical-pipeline-v2.json`
(schema version 2). Status: **BUILDING** — not an authority, and no C02/C02A/C03/C04 consumer may bind it.
The v1 pair above stays the inert authority and a byte-frozen read-only parent until RUB-1204 activates v2
and deletes it in the same PR. `_meta.closure_epoch` pins the corrected RUB-1206 closure epoch v8 and
`row_registry` freezes the 79 `row_id -> kind` identities. RUB-1208 migrates exactly 8 publication/image
rows with 24 cases, including the 12-case DA cleanup classifier and the ordered canonical-applied summaries;
the remaining registered rows stay unmigrated for RUB-1209..RUB-1212, and RUB-1204 completes the revision.

The artifact is generated, never hand-edited. Its single authoring source is
`clients/go/cmd/gen-conformance-fixtures/canonical_pipeline_v2_authority.json`, which the generator embeds
and pins by SHA-256 on both sides (`cp2AuthoritySourceSHA256` and `_meta.authority_source_sha256`); the
frozen `image_manifest` and `summary_manifest` are copied from it into the artifact and cross-pinned as
schema `const`s, so the authority file is the one place either is edited. Regenerate in place with
`scripts/dev-env.sh -- bash -lc 'cd clients/go && go run ./cmd/gen-conformance-fixtures'`.

What actually executes, and where:

| checked | validator | test |
| --- | --- | --- |
| schema validity, `row_registry` as an exact 79-entry map, closure-epoch and parent pins as `const`, and one single-dimension rejection per assigned mutation | `conformance/schemas/cv-canonical-pipeline-v2.json` | `CanonicalPipelineV2SchemaTests` and `CanonicalPipelineV2RUB1208Tests` in `tools/tests/test_check_conformance_fixtures_drift.py` |
| row/case census (8 rows, 24 cases), obligation forward-and-reverse receipts, and the image/summary/DA relations | `validate_canonical_pipeline_v2_semantics` in `tools/check_conformance_fixtures_drift.py` | `test_semantic_gate_accepts_the_committed_artifact`, `test_obligation_receipts_reject_a_census_preserving_edit` |
| the same image/summary/DA relations on the generating side (the obligation forward/reverse receipts are checker-side by design), plus the authority byte pin and the manifest hashes | `cp2ValidateR1208Payload` / `cp2ValidateR1208Expected` in `clients/go/cmd/gen-conformance-fixtures/runtime.go` | `TestCanonicalPipelineV2R1208ValidatorFailsClosed`, `TestCanonicalPipelineV2AuthorityPinIsExact`, `TestCanonicalPipelineV2DirectFieldsMatchTheManifest` |
| the shipped single-dimension hostile controls (substituted `block_hash`, dropped/duplicated DA occurrence, stale CHAIN tip, stale OWNER `stable_tip`, renamed/moved obligation id, and the rest) | `assert_canonical_pipeline_v2_negative_controls` in `tools/check_conformance_fixtures_drift.py`, run by the drift gate | `test_shipped_semantic_negative_controls_all_redden` |
| generator byte identity | the conformance fixture drift gate above | `TestCanonicalPipelineV2CorpusIsByteDeterministic` |

Four identity bindings make a same-shape substitution red. The control names below are the drift-checker
labels in `assert_canonical_pipeline_v2_negative_controls` (`test_shipped_semantic_negative_controls_all_redden`);
the generator runs its twin of each in `TestCanonicalPipelineV2R1208ValidatorFailsClosed`.

| binding | validator (generator / checker) | executed controls |
| --- | --- | --- |
| the published summary blocks are the blocks the case's own inputs state: the pre-stored side branch in canonical order, the block a genesis pack or stimulus names, or the equal-work candidate the stated `/input/candidate_hash_relation` selects — that relation itself re-derived from the two candidates' hash fixtures | `cp2StatedBranchBlocks` / `_stated_branch_blocks` | `summary block substituted for another stated block`, `genesis summary block substituted`, `equal-work winner substituted`, `equal-work hash relation contradicts the candidates` |
| the published CHAIN tip is the last canonical-applied block; the entry below the disconnected tip on a standalone disconnect; the stated prestate chain tip wherever the published CHAIN image is not `new` — and all three CHAIN direct fields (`tip_hash`, `height`, `utxo_count`) are read from that one tip block fixture, so a UTXO count belonging to another block is a substituted identity | `cp2ValidateChainTip` with `cp2PrestateChainBlock` / the same relations with `_prestate_chain_block` | `stale CHAIN tip with a consistent owner`, `post-disconnect tip rolled to genesis`, `non-NEW chain tip rolled back one block`, `chain utxo_count off the tip block` |
| an `unchanged` or `old` image republishes the stated prestate, so seven counters come from it rather than from the author: `record_count`, `tx_count`, `used_bytes`, `set_count`, `claim_count` and `pinned_payload_bytes` as exact equalities — the last one summed over stated `COMPLETE_SET` sets only, every other set state contributing zero per RUBIN_COMPACT_BLOCKS §5.1 — plus `last_admission_seq` as a LOWER BOUND, because the manifest makes it a monotonic high-water whose named mutation (M15) is a rewind: an evicted higher seq legally leaves the published watermark above the stated maximum. The two direct fields derived from no stated input are `orphan_bytes` (wireBytes accounting the manifest excludes from the image by rule) and `current_mempool_min_fee_rate` (independent standard state the snapshot carries beside its entries) | `cp2DerivedCounts` / `_derived_counts` | `stale standard used_bytes`, `stale retained set_count`, `stale owner claim_count`, `stale retained pinned_payload_bytes`, `rewound last_admission_seq`, `prestate sizes overflow the used-bytes total` |
| where a case states grouped `/input/block_included_set_identities`, each group binds exactly one summary row and every summary row is bound by exactly one group | `cp2IncludedSetDAIDs` / `_included_set_da_ids` | `one grouped included-set entry omitted`, `two grouped keys bind one summary row`, `grouped key matches no summary row`, `grouped key matches two summary rows` |

Two conventions the shape does not state by itself. `release_requirements[go|rust]` is a set of
(issue, surface) blocking obligations, not a set of issues: one issue legitimately appears more than once
with different surfaces. Where a case carries its own block, that block is the case's complete blocking set
and replaces the row-level default, exactly as `$defs/case.release_requirements` in the schema states. A `sources[]` entry resolves against `_meta.governing_spec_oid` for a spec citation, an
in-repo path for a fixture citation, the bound closure snapshot `rubin-c01-design-closure-v8` for a design
citation, and the obligation census for an `OBL-` id. The schema is the SINGLE owner of the fields the
generator's typed decode deliberately ignores — the `obligation_ids` grammar, `sources`,
`release_requirements` shape and unknown or retired keys — so those carry no generator-side mirror check
and are proven by `CanonicalPipelineV2SchemaTests` alone. Enforcement of the remaining `effects` relations
(`connected_block_decay_events`, `relay_authority`, `intermediate_tip_rows`, `external_visibility`, and a
closed effect-key vocabulary) is deferred to RUB-1204 with the rest of the deferred closure work.

## Fuzz crash promotion (manual-only)

Nightly fuzz jobs are discovery jobs only. They upload crash artifacts and
metadata for manual triage; CI MUST NOT commit, push, regenerate fixtures, or
open issues automatically.

Each fuzz artifact bundle must include enough metadata to reproduce a crash:

- target name;
- seed, corpus, or crash artifact path;
- exact local command;
- commit SHA;
- workflow run id/attempt when produced by GitHub Actions.

Per-target metadata uses explicit path keys:

- Go metadata includes `corpus_path`, `artifacts_path`, and legacy `seed_path`.
  The Go fuzz engine stores committed corpus inputs and crash/minimized outputs
  under the same target directory, so all three keys point to
  `clients/go/<package>/testdata/fuzz/<FuzzTarget>/`.
- Rust metadata includes `corpus_path` for committed seed promotion and
  `artifacts_path` for crash artifacts under `clients/rust/fuzz/artifacts/`.

Manual promotion flow:

1. Download the failed workflow artifact and read its `run-metadata.env` plus the
   matching `<target>.metadata.env`.
   Metadata files are shell-quoted dotenv files, so they can be inspected as
   text or sourced by a local shell without executing command field contents.
   Go consensus fuzz files are uploaded directly under
   `clients/go/consensus/testdata/fuzz/**`. Go `node/p2p` fuzz files are in
   `.artifacts/fuzz-stage2/go-fuzz-testdata.tgz`; extract that archive before
   following a `clients/go/node/p2p/testdata/fuzz/<FuzzTarget>/` metadata path.
2. Reproduce the crash at the recorded commit SHA using the recorded command.
   For Go targets this is the `go test -run=^$ -fuzz=...` command under
   `clients/go`; for Rust targets this is the `cargo fuzz run ...` command under
   `clients/rust`.
3. Dedup before opening or updating an issue: check existing committed fuzz
   seeds/tests, open issues, and recent nightly failures for the same target and
   crash signature.
4. Promote only a reproduced protocol crash. Add the minimized input as a
   committed regression seed or a focused regression test in the target's normal
   test surface. Do not promote one-off infrastructure flakes.
5. Close the issue only after the PR contains either the committed seed/test that
   fails before the fix and passes after it, or explicit false-positive evidence
   explaining why no protocol regression exists.

Manual seed destinations:

- Go fuzz seeds: `clients/go/<package>/testdata/fuzz/<FuzzTarget>/`
- Rust fuzz seeds: `clients/rust/fuzz/corpus/<target>/`. That corpus directory
  is gitignored by default, so commit selected regression seeds with
  `git add -f clients/rust/fuzz/corpus/<target>/<seed-file>`.

Fuzz artifact upload alone is not a regression closeout. It is only triage
evidence until a human reproduction and seed/test promotion decision exists.
