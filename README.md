<!--
RUBIN public code repository.

Consensus-critical normative specifications are maintained in private repository:
  - github.com/2tbmz9y2xt-lang/rubin-spec (private)

This repository keeps implementations, conformance runner, and formal toolchain.
-->

# rubin-protocol (Genesis = Canonical Transaction Wire)

This repository contains:

- minimal reference implementations (Go + Rust),
- a cross-client conformance runner (parity gate),
- Lean4 formal toolchain and replay gates.

**What this means:** the chain starts at genesis with one canonical transaction
serialization format (including `tx_kind`, TXID/WTXID rules, and DA fields).
There is no delayed wire-activation mechanism.

## Structure

- `rubin-spec` (private repository) holds canonical specs
- `./clients/go/` Go reference consensus library + CLI
- `./clients/rust/` Rust reference consensus library + CLI
- `./conformance/` fixtures + runner (Go↔Rust parity)
- `./rubin-formal/` Lean4 proof-pack bootstrap (formal coverage baseline)
- `./ARCHITECTURE_MAP.md` architecture map (spec → fixtures → clients → CI)

Quick references:

- Architecture & change path map: `./ARCHITECTURE_MAP.md`
- Conformance harness overview: `./conformance/README.md`

## Quick Start (Local)

Clone and run unit tests:

```bash
git clone https://github.com/2tbmz9y2xt-lang/rubin-protocol.git
cd rubin-protocol

( cd clients/go && go test ./... )
( cd clients/rust && cargo test --workspace )
```

Run cross-client conformance (builds local CLIs into `./conformance/bin/`):

```bash
python3 conformance/runner/run_cv_bundle.py
python3 conformance/runner/run_cv_bundle.py --only-gates CV-COMPACT
```

## Adding Conformance Vectors

1. Add a new fixture file: `./conformance/fixtures/CV-<GATE>.json`.
2. If the vector needs a new operation, implement it in both CLIs:
   - `./clients/go/cmd/rubin-consensus-cli/main.go`
   - `./clients/rust/crates/rubin-consensus-cli/src/main.rs`
3. Teach the runner to route/validate the op:
   - `./conformance/runner/run_cv_bundle.py`

The runner requires Go and Rust to return identical `ok/err` behavior and identical outputs for each op.

## Notes

- Local orchestration/queue files live outside the repository and MUST NOT be committed.
