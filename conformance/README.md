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
- runtime reorg
- DA
- mempool policy
- DA fee-floor policy

Runtime reorg coverage is not a new consensus fixture gate. It records the
existing helper/direct-context `CV-FORK-CHOICE` and `CV-TIMESTAMP` edge domain
without claiming checker-enforced node runtime source/test evidence. Follow-up
checker hardening is tracked separately for declared runtime source/test
validation.

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
