# Q Template

Use this template for `tools/agent_tasks/<Q-ID>.json` plus the human task brief
that travels with the branch. Keep one branch/PR on one `Q-*` unless a
controller-approved bundle says otherwise.

## Q-ID

- `Q-ID:`
- `Owner area:`

## Allowed Files

- Exact files:
- Allowed globs:

## Forbidden Files

Default runtime-Q forbidden globs unless the manifest explicitly narrows scope
for tooling/docs/CI:

- `.cursor/**`
- `.claude/**`
- `.github/workflows/**`
- `tools/**`
- `docs/**`
- unrelated Go/Rust files outside the declared runtime slice

## Target Diff

- `target_production_loc:`
- `hard_production_loc:`

## Acceptance Criteria

- Behavior change:
- Explicit non-goals:
- Exact proof boundary:

## Invariant Table

Fill this before the first edit.

- `scope:`
- `state_ownership:`
- `lock_io:`
- `failure_atomicity:`
- `go_rust_parity:`
- `caller_fuzz_test_sweep:`
- `test_stability:`

## Required Commands

- `tools/rubin_q_preflight.sh tools/agent_tasks/<Q-ID>.json`
- Additional local checks:

## Final Self-Check

- One `Q-*` only:
- Exact changed files confirmed:
- Each change mapped to one invariant:
- No adjacent cleanup:
- No hidden test knobs / brittle tests / file:line comment anchors:
