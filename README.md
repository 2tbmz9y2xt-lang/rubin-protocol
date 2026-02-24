<!--
RUBIN SPEC FREEZE HEADER (informational)

This repository contains consensus-critical and normative specifications.
Consensus source-of-truth: RUBIN_L1_CANONICAL.md.

Precedence (normative):
  1) RUBIN_L1_CANONICAL.md     (consensus validity)
  2) RUBIN_COMPACT_BLOCKS.md   (normative P2P behavior)
  3) RUBIN_NETWORK_PARAMS.md   (reference summary; derived; CANONICAL prevails)
  4) AUX / operational docs

Integrity:
  - SECTION_HASHES.json pins consensus-critical section hashes of RUBIN_L1_CANONICAL.md.
  - Any change to a pinned section MUST update SECTION_HASHES.json deterministically
    (per canonicalization rules in SECTION_HASHES.json).
-->

# rubin-protocol (Genesis = Canonical Transaction Wire)

This repository contains:

- the consensus-critical L1 specification (CANONICAL),
- minimal reference implementations (Go + Rust),
- a cross-client conformance runner (parity gate).

**What this means:** the chain starts at genesis with one canonical transaction
serialization format (including `tx_kind`, TXID/WTXID rules, and DA fields).
There is no delayed wire-activation mechanism.

## Structure

- `./spec/` specs (see `./spec/README.md`)
- `./clients/go/` Go reference consensus library + CLI
- `./clients/rust/` Rust reference consensus library + CLI
- `./conformance/` fixtures + runner (Go↔Rust parity)
- `./rubin-formal/` Lean4 proof-pack bootstrap (formal coverage baseline)

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

Spec tooling (HTML + diff + explainer):

```bash
npm ci
npm run spec:all
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
