# Fuzzing (Phase‑0 hardening)

This repo keeps fuzzing **out of default PR CI** (time/cost), but provides deterministic fuzz targets for manual and nightly runs.

All commands below should be run via `scripts/dev-env.sh` to avoid local PATH drift.

## Go (native fuzzing)

Targets live in `clients/go/consensus/*_test.go` (Go 1.18+):

- CompactSize: `FuzzReadCompactSize`
- TX parser: `FuzzParseTx`
- Block parser: `FuzzParseBlockBytes`
- Covenant rules (stage-2): `FuzzValidateTxCovenantsGenesis`
- Signature verify determinism (stage-2): `FuzzVerifySigDeterminism`
- Retarget arithmetic determinism (stage-2): `FuzzRetargetV1Arithmetic`
- DA parser paths (stage-2): `FuzzParseTxDAKinds`
- UTXO apply paths (stage-2): `FuzzApplyNonCoinbaseTxBasic`
- Parallel validation determinism (Q-PV-17): `FuzzConnectBlockParallelDeterminism` — seq vs parallel same verdict/digest; seed preserved for replay.

Examples:

```bash
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -fuzz=FuzzReadCompactSize -fuzztime=30s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -fuzz=FuzzParseTx -fuzztime=30s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -fuzz=FuzzParseBlockBytes -fuzztime=30s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -run=^$ -fuzz=FuzzValidateTxCovenantsGenesis -fuzztime=45s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -run=^$ -fuzz=FuzzVerifySigDeterminism -fuzztime=45s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -run=^$ -fuzz=FuzzRetargetV1Arithmetic -fuzztime=45s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -run=^$ -fuzz=FuzzParseTxDAKinds -fuzztime=45s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -run=^$ -fuzz=FuzzApplyNonCoinbaseTxBasic -fuzztime=45s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -run=^$ -fuzz=FuzzConnectBlockParallelDeterminism -fuzztime=30s'
```

**Deterministic replay (Q-PV-17):** On failure the fuzz engine writes a seed to `testdata/fuzz/`. Re-run with that seed to reproduce:
`go test -run='FuzzConnectBlockParallelDeterminism/<seed>' -v ./consensus`

**Race detector (Q-PV-17):** `go test -race -run TestConnectBlockParallelSigVerify_Race ./consensus`

## Rust (cargo-fuzz / libFuzzer)

Targets live in `clients/rust/fuzz/fuzz_targets/` (one per file); the nightly-wired set is `scripts/ci/rust_fuzz_targets.txt`. Examples:

- `parse_tx`
- `parse_block_bytes`
- `compactsize`

One-time setup:

```bash
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo install cargo-fuzz --locked'
```

Run examples:

```bash
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo fuzz run parse_tx -- -max_total_time=30'
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo fuzz run parse_block_bytes -- -max_total_time=30'
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo fuzz run compactsize -- -max_total_time=30'
```

Notes:
- Fuzz artifacts/corpora are ignored via `clients/rust/fuzz/.gitignore`.
- Keep fuzz runs bounded (`-max_total_time=...`) for reproducibility during triage.

## Nightly fuzz run (CI)

Nightly workflow: `.github/workflows/fuzz-nightly.yml`. This section mirrors the
live implementation; on any doubt the cited files are the authority.

Fan-out (single-source lists, derived at run time by the `prepare` job):

- Go: one matrix job per `pkg:Target` from
  `scripts/ci/run_fuzz_stage2.sh --list-json`; the single source is the
  `TARGETS` array in that script.
- Rust: `scripts/ci/rust_fuzz_targets.txt` (blank/`#` lines skipped), chunked
  into groups of 5 — the chunking amortises the per-job nightly-toolchain +
  cargo-fuzz + fuzz-crate build cost while keeping wall clock flat.
- Adding a target is therefore a list edit only, never a workflow edit.

Budgets (deliberate, overridable via `workflow_dispatch` inputs):

- Go: `FUZZ_TIME` default `300s` per target, `FUZZ_MINIMIZE_TIME=5s`.
- Rust: `RUST_FUZZ_TIME` default `300` seconds per target (`-max_total_time`).
- The Go runner passes an explicit `go test -timeout` of fuzztime + 600s
  (`scripts/ci/run_fuzz_stage2.sh`): the margin covers baseline-coverage
  gathering, minimisation, coordinator shutdown, and runner starvation;
  without it the default 10m `go test` timeout would become the binding kill
  once fuzztime reaches minutes.

Go verdict classification (`scripts/ci/run_fuzz_stage2.sh` +
`scripts/ci/classify_go_fuzz_exit.sh`) — red only on defect evidence:

- Zero exit (#2731): PASS only with fuzz-execution evidence (a
  `fuzz: elapsed:` log line). Otherwise, if the test binary's own `-list`
  output proves the target exists, the run is a loud `SKIP_FUZZ_SETUP` and
  the job stays green (setup `f.Skipf()`, e.g. unavailable ML-DSA backend;
  repair owned by RUB-1064); a missing target or failed `-list` probe is red.
- Non-zero exit: red unless the classifier proves the benign fuzztime-expiry
  shutdown race; the summary then records `PASS_AFTER_BENIGN_DEADLINE`. All
  four conjuncts must hold:
  1. exactly one FAIL block in the log, benign-shaped
     (`--- FAIL: <target> (<N>s)`), whose bare `context deadline exceeded`
     line is followed immediately by the package `FAIL` verdict;
  2. the recorded duration is at least the fuzztime budget (an early deadline
     means the fuzz coverage was not delivered — red);
  3. none of the crash/instability markers anywhere in the log (failing input
     written, hung/terminated worker, worker communication error, internal
     fuzz-engine failure, `panic:`, `fatal error:`);
  4. the sorted file list under the target's `testdata/fuzz/<Target>/` corpus
     dir is unchanged (no crasher was recorded).

The classifier is Go-only by design: libFuzzer exits cleanly when
`-max_total_time` expires, while the suppressed race lives in the go1.26.5
fuzz coordinator shutdown (`src/internal/fuzz/fuzz.go:129`; the coordinator
can observe the fuzztime deadline before its own context reports it). Rust
chunk jobs are plain per-target pass/fail.

Scope of the suppression: the classification turns a non-zero exit green for
exactly one named upstream race signature, and a zero exit green-with-warning
for exactly one `-list`-proven setup-skip shape — nothing else.

Artifacts: Go jobs upload `.artifacts/fuzz-stage2/**` plus the
`testdata/fuzz/**` trees (consensus, node, node/p2p); Rust chunk jobs upload
`.artifacts/fuzz-rust/**` and `clients/rust/fuzz/artifacts/` — crash evidence
survives a failing target. A final `verdict` job fails unless both matrices
ended in exact `success`.
