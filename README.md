# rubin-protocol (Genesis = Wire v1)

This repository contains:

- the consensus-critical L1 specification (CANONICAL),
- minimal reference implementations (Go + Rust),
- a cross-client conformance runner (parity gate).

**What "Genesis = Wire v1" means:** the chain starts at genesis using the current
transaction serialization format ("Transaction Wire (version 1)") including TXID/WTXID
rules. There is no on-chain activation for this; nodes must implement Wire v1 to
validate the chain.

## Structure

- `./spec/` specs (see `./spec/README.md`)
- `./clients/go/` Go reference consensus library + CLI
- `./clients/rust/` Rust reference consensus library + CLI
- `./conformance/` fixtures + runner (Go↔Rust parity)

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
