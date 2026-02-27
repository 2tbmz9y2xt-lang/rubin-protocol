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
```

## Rust (cargo-fuzz / libFuzzer)

Targets live in `clients/rust/fuzz/fuzz_targets/`:

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

## Nightly stage-2 fuzz run (CI)

Nightly workflow:

- `.github/workflows/fuzz-nightly.yml`

Runner script:

- `scripts/ci/run_fuzz_stage2.sh`

Behavior:

- runs timeboxed stage-2 Go targets (covenant/sig/retarget/DA/UTXO);
- uploads artifacts (`.artifacts/fuzz-stage2/**` and `clients/go/consensus/testdata/fuzz/**`);
- preserves crash/regression evidence even when fuzz target fails.
