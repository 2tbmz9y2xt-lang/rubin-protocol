# RUBIN Parallel Validation — Implementation Plan (Deterministic, Implementation-Only)

## 1. Purpose

This plan defines how to implement deterministic parallel block validation in `rubin-protocol`
without changing consensus semantics.

Core contract:

- parallelize only read-only validation work;
- keep final block verdict election deterministic;
- keep commit/state mutation strictly sequential in canonical block order;
- preserve canonical first-error behavior;
- preserve witness assignment determinism.

## 2. Scope and Non-Goals

### In scope

- deterministic tx-context precompute;
- deterministic dependency graph for same-block relations;
- read-only validation worker pool;
- deterministic reducer for final error election;
- sequential commit stage;
- shadow-mode rollout (`off|shadow|on`);
- parity fixtures and replay harness;
- formal refinement package;
- benchmark evidence and promotion gates.

### Out of scope

- consensus rule changes;
- wire format changes;
- new covenant semantics;
- policy-as-consensus behavior;
- speculative concurrent state mutation.

## 3. Repository-Accurate Placement

This section replaces draft path assumptions like `internal/parallel` and `tests/parallel`.

### Go implementation

- `clients/go/consensus/connect_block_parallel.go` (orchestrator, reducer hooks)
- `clients/go/consensus/connect_block_parallel_*.go` (new modules by concern)
- `clients/go/consensus/*_test.go` (unit/integration parity tests)
- `clients/go/cmd/rubin-node/` (runtime flags and shadow mode wiring)

### Rust implementation (parity path)

- `clients/rust/crates/rubin-consensus/src/` (parallel parity modules)
- `clients/rust/crates/rubin-consensus/src/tests/` (determinism/parity tests)
- `clients/rust/crates/rubin-node/src/` (runtime flags and shadow mode wiring)

### Conformance and fixtures

- `conformance/fixtures/CV-PV-*.json` (parallel-validation fixture families)
- `conformance/runner/run_cv_bundle.py` (routing + checks)
- `tools/gen_conformance_matrix.py` (matrix coverage updates)

### Formal package

- `rubin-formal/RubinFormal/Refinement/` (refinement theorems)
- `rubin-formal/proof_coverage.json` (coverage updates)
- `rubin-formal/PROOF_COVERAGE.md` (human-readable summary)

### Documentation

- repository root markdowns:
  - `RUBIN_PARALLEL_VALIDATION_IMPLEMENTATION_PLAN.md` (this file)
  - `RUBIN_PARALLEL_VALIDATION_AGENT_TZ.md` (agent execution contract)
  - `RUBIN_PARALLEL_VALIDATION_OPERATOR_RUNBOOK.md` (operational rollout)
  - `RUBIN_PARALLEL_VALIDATION_SECURITY_NOTES.md` (risk and controls)
  - `RUBIN_PARALLEL_VALIDATION_BENCHMARK_PLAN.md` (benchmark protocol)

## 4. Work Breakdown (Q-PV Program)

Program track: `Q-PV-01..Q-PV-20`.

Execution order is dependency-driven (not pure numeric order). The queue rows define exact
`depends=` constraints.

### Foundation

- `Q-PV-01`: scope lock + wording hardening (parallel validation, not parallel execution)
- `Q-PV-02`: tx-context precompute
- `Q-PV-03`: witness cursor module extraction
- `Q-PV-04`: dependency graph v2
- `Q-PV-05`: bounded worker pool skeleton
- `Q-PV-06`: immutable UTXO snapshot read layer

### Validation pipeline

- `Q-PV-07`: parallel ML-DSA verification pool
- `Q-PV-08`: parallel DA jobs
- `Q-PV-09`: tx-local validation workers
- `Q-PV-10`: deterministic reducer
- `Q-PV-11`: sequential commit stage

### Rollout and observability

- `Q-PV-12`: shadow mode (`off|shadow|on`)
- `Q-PV-13`: telemetry contract + counters

### Verification completeness

- `Q-PV-14`: unit tests (coverage floor/target policy)
- `Q-PV-15`: integration parity suite
- `Q-PV-16`: fixtures package (full)
- `Q-PV-17`: fuzz + race harness
- `Q-PV-18`: benchmark evidence package
- `Q-PV-19`: formal refinement package (full)
- `Q-PV-20`: promotion gates and staged rollout

## 5. Determinism and Safety Invariants

The following MUST hold for every Q-PV implementation PR:

1. Canonical validity behavior is unchanged.
2. First applicable error remains canonical.
3. Witness digest equality holds (sequential vs parallel).
4. Post-state digest equality holds (sequential vs parallel).
5. No worker mutates consensus state.
6. No reducer rule depends on scheduling order.
7. Shadow mismatches never affect node verdict.

## 6. Validation Gates

Mandatory per-stack gates:

- Go tests: `scripts/dev-env.sh -- bash -lc 'cd clients/go && go test ./...'`
- Rust tests: `scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo test --workspace'`
- Conformance: `scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py`
- Determinism replay (sequential == parallel verdict/error/state/witness)
- Race/sanitizer suites
- Fuzz smoke gate
- Formal artifact presence + theorem checks

Coverage policy for new parallel-validation code:

- hard floor: `>= 80%`
- target: `>= 95%`
- if branch is unreachable from public/runtime surface, annotate explicitly with rationale.

## 7. Fixture Completeness Contract

Required fixture families:

- `CV-PV-CURSOR-*`
- `CV-PV-DAG-*`
- `CV-PV-ERR-*`
- `CV-PV-DA-*`
- `CV-PV-CACHE-*`
- `CV-PV-MIXED-*`
- `CV-PV-STRESS-*`

Each vector must pin:

- expected validity
- expected canonical error
- first invalid tx index (if invalid)
- witness digest
- post-state digest

All vectors must run on Go and Rust with parity.

## 8. Formal Completeness Contract

Minimum theorem/artifact set:

- witness cursor determinism
- dependency graph soundness (`same-prevout`, `parent-child`)
- validation purity (worker side effects forbidden)
- reducer returns canonical first invalid tx
- reject/accept equivalence vs sequential
- commit equivalence vs sequential

Formal artifacts must be committed in the same stack as the implementation changes they validate.

## 9. Merge/Promotion Contract

A parallel-validation stack is merge-ready only when:

- all correctness gates are green;
- no canonical/spec integrity drift is introduced;
- deterministic parity is 100%;
- fixture and formal packages are complete for the delivered scope;
- benchmark evidence shows non-negative practical benefit for target hardware profiles.

Promotion to broader rollout follows staged shadow evidence and operator readiness.
