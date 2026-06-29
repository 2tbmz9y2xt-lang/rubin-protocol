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
- `./clients/go/cmd/rubin-node/` Go node skeleton entrypoint (daemon bootstrap)
- `./clients/rust/` Rust reference consensus library + CLI
- `./conformance/` fixtures + runner (Go↔Rust parity)
- `./rubin-formal/` Lean4 formal proof surface used by CI and local replay
  - Authoritative standalone repository: `https://github.com/2tbmz9y2xt-lang/rubin-formal`
- `./ARCHITECTURE_MAP.md` architecture map (spec → fixtures → clients → CI)

Quick references:

- Spec location (private): `./SPEC_LOCATION.md`
- Architecture & change path map: `./ARCHITECTURE_MAP.md`
- Conformance harness overview: `./conformance/README.md`
- Combined-load benchmark SLO/evidence lane: `./scripts/benchmarks/COMBINED_LOAD_SLO.md`

## Quick Start (Local)

Clone and run unit tests:

```bash
git clone https://github.com/2tbmz9y2xt-lang/rubin-protocol.git
cd rubin-protocol

scripts/dev-env.sh -- bash -lc 'cd clients/go && go test ./...'
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo test --workspace'
scripts/dev-env.sh -- scripts/security/precheck.sh --local
```

Run cross-client conformance (builds local CLIs into `./conformance/bin/`):

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py --only-gates CV-COMPACT
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
- CI blocks sensitive assets from entering public repo (`tools/check_sensitive_files.py`).
- PR merge gate includes `validator` check, which is an aggregate status over `policy` + `security_ai` + `formal` + `test` + `formal_refinement`.
- Auto-merge is allowed only when the `validator` check-run exists and finishes with `success`.

## Policy Guardrails (Non-consensus)

`CORE_EXT` (`covenant_type=0x0102`) is **unassigned** per CANONICAL §14: consensus rejects it as
`TX_ERR_COVENANT_TYPE_INVALID` at both creation and spend (RUB-585; spec RUB-517). The earlier
pre-activation anyone-can-spend framework has been retired. The Go node retains a defensive
mempool/miner guardrail that independently excludes transactions creating or spending `CORE_EXT`
outputs — now redundant with consensus rejection, kept as defense in depth:

- Implemented by `rejectUnsupportedCoreExtNodeRuntime(...)` (`clients/go/node`), invoked on the miner-template and mempool-admission paths to exclude any transaction that creates or spends a `CORE_EXT` output.
- This guardrail is now redundant with consensus rejection (consensus rejects 0x0102 unconditionally) and is retained as defense in depth.
