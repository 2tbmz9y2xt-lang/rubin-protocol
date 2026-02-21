# rubin-protocol (Genesis = Wire v2)

This repository contains:

- the consensus-critical L1 specification (CANONICAL),
- minimal reference implementations (Go + Rust),
- a cross-client conformance runner (parity gate).

Legacy snapshot:
- branch: `legacy/v1.1`
- tag: `legacy-v1.1-freeze-2026-02-21`

## Structure

- `/Users/gpt/Documents/rubin-protocol/spec/` specs (see `spec/README.md`)
- `/Users/gpt/Documents/rubin-protocol/clients/go/` Go reference consensus library + CLI
- `/Users/gpt/Documents/rubin-protocol/clients/rust/` Rust reference consensus library + CLI
- `/Users/gpt/Documents/rubin-protocol/conformance/` fixtures + runner (Go↔Rust parity)

## Quick Start (Local)

Run unit tests:

```bash
cd /Users/gpt/Documents/rubin-protocol/clients/go
go test ./...

cd /Users/gpt/Documents/rubin-protocol/clients/rust
cargo test --workspace
```

Run cross-client conformance:

```bash
cd /Users/gpt/Documents/rubin-protocol
python3 conformance/runner/run_cv_bundle.py
```

## Adding Conformance Vectors

1. Add a new fixture file: `/Users/gpt/Documents/rubin-protocol/conformance/fixtures/CV-<GATE>.json`.
2. If the vector needs a new operation, implement it in both CLIs:
   - `/Users/gpt/Documents/rubin-protocol/clients/go/cmd/rubin-consensus-cli/main.go`
   - `/Users/gpt/Documents/rubin-protocol/clients/rust/crates/rubin-consensus-cli/src/main.rs`
3. Teach the runner to route/validate the op:
   - `/Users/gpt/Documents/rubin-protocol/conformance/runner/run_cv_bundle.py`

The runner requires Go and Rust to return identical `ok/err` behavior and identical outputs for each op.

## Notes

- Local orchestration files live outside the repo (e.g. `/Users/gpt/Documents/inbox/QUEUE.md`) and MUST NOT be committed.
