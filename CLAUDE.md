# CLAUDE.md — AI Assistant Guide for rubin-protocol

## Project Overview

Rubin Protocol is a blockchain protocol with dual reference implementations (Go + Rust), a cross-client conformance harness, and a Lean4 formal verification toolchain. Consensus-critical specs live in a private repository (`rubin-spec`); this repo holds implementations, conformance testing, and formal proofs.

**Authority chain:** `rubin-spec` (private) is the source of truth.
**Normative precedence:** CANONICAL > COMPACT_BLOCKS > NETWORK_PARAMS.

## Repository Structure

```
clients/go/              Go reference implementation (consensus authority for parity)
  consensus/             Core consensus library (~12k LoC)
  node/                  Node: miner, mempool, p2p, blockstore, chainstate
  cmd/                   CLIs: rubin-consensus-cli, rubin-node, rubin-txgen, formal-trace, gen-conformance-fixtures
clients/rust/            Rust parity implementation (Cargo workspace)
  crates/rubin-consensus/      Core consensus library (~8.5k LoC)
  crates/rubin-consensus-cli/  CLI matching Go behavior
  crates/rubin-node/           Node skeleton
  fuzz/                        Fuzzing harness
conformance/             Cross-client conformance testing
  fixtures/CV-*.json     Conformance vectors (spec-derived expected behavior)
  runner/run_cv_bundle.py  Parity runner (Go vs fixtures, Rust vs Go)
rubin-formal/            Lean4 formal verification (Lake project, leanprover/lean4:4.6.0)
scripts/                 Dev environment, benchmarks, security, crypto tooling
tools/                   Policy checks, audit, formal coverage, conformance validation
.github/workflows/       CI pipeline (ci.yml + 10 other workflows)
```

## Languages and Toolchain Versions

- **Go:** 1.24.13
- **Rust:** stable (edition 2021), with `rustfmt` and `clippy`
- **Node.js:** 24.14.0 (tooling only)
- **Python 3:** conformance runner + policy tools (no venv needed)
- **Lean 4:** 4.6.0 (via elan)
- **OpenSSL:** 3.5.5 (required for post-quantum crypto: ML-DSA-87, FIPS support)

## Build and Test Commands

All local commands should be run via `scripts/dev-env.sh` for consistent PATH/OpenSSL wiring:

```bash
# Go tests
scripts/dev-env.sh -- bash -lc 'cd clients/go && go test ./...'

# Rust tests
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo test --workspace'

# Conformance bundle (builds both CLIs, runs all gates)
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py

# Single conformance gate
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py --only-gates CV-COMPACT

# Security precheck
scripts/dev-env.sh -- scripts/security/precheck.sh --local

# Formal verification (Lean build)
scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake build'

# Audit snapshot check
scripts/dev-env.sh -- python3 tools/gen_audit_snapshot.py --check
scripts/dev-env.sh -- python3 tools/check_audit_snapshot.py
```

## Formatting and Linting

- **Go:** `gofmt` — CI fails on any unformatted Go code (`test -z "$(gofmt -l .)"`)
- **Rust:** `cargo fmt -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`
- **No eslint/prettier** — JS/TS/Python analyzers are disabled in Codacy; these languages are tooling-only

Run before submitting:
```bash
cd clients/go && gofmt -w .
cd clients/rust && cargo fmt && cargo clippy --workspace --all-targets -- -D warnings
```

## CI Pipeline (ci.yml)

The `validator` job is the merge gate. It requires ALL of these jobs to succeed:

1. **policy** — sensitive file check, mainnet genesis guard, keygen security, OpenSSL CVE response
2. **security_ai** — Semgrep, gosec, govulncheck, cargo-audit, security precheck
3. **formal** — Lean build, formal coverage/refinement/claims checks, risk gate
4. **test** — Go fmt/test/vet/vulncheck, Rust fmt/test/clippy/audit, conformance bundle, strict JSON parse
5. **formal_refinement** — Go trace generation → Lean expected outputs → Go→Lean refinement check

Additional non-blocking/nightly workflows: `combined-load-nightly.yml`, `fuzz-nightly.yml`, `fips-only-nightly.yml`, `kani.yml`, `sbom.yml`.

## Key Conventions

### Dual-Implementation Parity
- **Go is the reference.** Rust must match Go at the behavior level for every executable conformance gate.
- Any protocol change must be implemented in both clients.
- Conformance fixtures prevent "both clients drift together" — Go is checked against fixtures first.

### Conformance Fixtures Are Manual-Only
- `clients/go/cmd/gen-conformance-fixtures` is **never** run in CI.
- Regenerate locally: `scripts/dev-env.sh -- bash -lc 'cd clients/go && go run ./cmd/gen-conformance-fixtures'`
- Any change to `conformance/fixtures/CV-*.json` must update `conformance/fixtures/CHANGELOG.md`.

### Change Path (Protocol-Affecting Changes)
1. Update spec in private `rubin-spec`
2. Update/extend `conformance/fixtures/CV-*.json`
3. Implement behavior in both Go + Rust clients
4. Run conformance runner and local checks
5. Refresh audit/formal metadata if needed
6. Ensure CI-equivalent checks pass before merge

### Security
- OpenSSL 3.5+ is mandatory (post-quantum ML-DSA-87 support).
- `tools/check_sensitive_files.py` blocks secrets/sensitive assets from the public repo.
- Crypto modules are CODEOWNERS-protected (Go: `openssl_signer.go`, Rust: `hash.rs`/`sighash.rs`).
- Duplication is preferred over abstraction in security-critical consensus code.

### Code Quality
- Codacy duplication target: <5% for both Go and Rust client code.
- Minimum clone detection: 25 lines (CLI dispatchers excluded).
- Tests are intentionally repetitive — excluded from duplication analysis.
- Generated files (`*.gen.go`, `*_generated.rs`) are excluded from coverage.

### Policy Guardrails (Non-Consensus)
- **CORE_EXT pre-activation:** Miner defaults to rejecting CORE_EXT txs before activation (`PolicyRejectCoreExtPreActivation = true`).
- **DA anchor anti-abuse:** Template budget cap and fee surcharge policies.
- These are relay/miner policies, not consensus rules.

## Files That Must Not Be Committed
- Local orchestration: `scripts/orchestration/`, `operational/orchestration/`
- Vault drafts, agent execution docs, implementation roadmaps (see `.gitignore`)
- `*.invalid.*.json` guard artifacts
- Anything matching `.claude/`, `.codex/`, `artifacts/`

## Entry Points for Common Tasks

| Task | Start Here |
|------|-----------|
| Consensus logic (Go) | `clients/go/consensus/` |
| Consensus logic (Rust) | `clients/rust/crates/rubin-consensus/src/` |
| Node behavior (Go) | `clients/go/node/` |
| CLI operations | `clients/go/cmd/rubin-consensus-cli/main.go`, `clients/rust/crates/rubin-consensus-cli/src/main.rs` |
| Add conformance vector | `conformance/fixtures/CV-*.json` + both CLIs + runner |
| Formal proofs | `rubin-formal/RubinFormal/` |
| CI pipeline | `.github/workflows/ci.yml` |
| Policy checks | `tools/check_*.py` |
| Dev environment | `scripts/dev-env.sh` |
