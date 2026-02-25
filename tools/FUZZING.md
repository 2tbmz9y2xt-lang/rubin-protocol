# Fuzzing (Phase‑0 hardening)

This repo keeps fuzzing **out of default CI** (time/cost), but provides deterministic fuzz targets for manual runs.

All commands below should be run via `scripts/dev-env.sh` to avoid local PATH drift.

## Go (native fuzzing)

Targets live in `clients/go/consensus/*_test.go` (Go 1.18+):

- CompactSize: `FuzzReadCompactSize`
- TX parser: `FuzzParseTx`
- Block parser: `FuzzParseBlockBytes`

Examples:

```bash
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -fuzz=FuzzReadCompactSize -fuzztime=30s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -fuzz=FuzzParseTx -fuzztime=30s'
scripts/dev-env.sh -- bash -lc 'cd clients/go/consensus && go test -fuzz=FuzzParseBlockBytes -fuzztime=30s'
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

