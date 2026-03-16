# RUBIN Parallel Validation — Extended Agent TZ

This document is an execution contract for agents implementing `Q-PV-*` tasks.

## 1. Mission and Hard Boundaries

Mission:

- deliver deterministic parallel validation acceleration;
- preserve consensus-equivalent behavior bit-for-bit.

Hard boundaries:

- no consensus semantics changes;
- no new canonical error paths;
- no concurrent state mutation;
- no shortcuts that treat policy hints as consensus truth.

## 2. Execution Model

Each agent works on one `Q-PV-*` task at a time.

Required flow:

1. read queue row and dependency rows;
2. validate baseline (`origin/main`) and referenced files;
3. implement only task-local scope;
4. run task-local tests + parity checks;
5. provide evidence package in PR description;
6. hand off to next dependency-ready task.

## 3. Mandatory Inputs Before Coding

For every `Q-PV-*` task:

- queue row ID and dependency list (`depends=...`);
- linked issue body and acceptance list;
- current `origin/main` SHA for `rubin-protocol`;
- relevant invariants from:
  - `ARCHITECTURE_MAP.md`
  - `README.md`
  - `RUBIN_PARALLEL_VALIDATION_IMPLEMENTATION_PLAN.md`

## 4. Required Deliverables per Task

Every task output must include:

- code changes (Go and/or Rust as scoped);
- tests tied to acceptance criteria;
- fixture or formal updates when required;
- short evidence block:
  - commands run
  - PASS/FAIL summary
  - parity result
  - known limitations.

## 5. Determinism Checklist (Must Pass)

Before declaring task complete:

1. parallel and sequential paths return same verdict;
2. first canonical error matches;
3. witness digest matches;
4. post-state digest matches;
5. result independent of worker scheduling perturbation.

If any check fails: task is `BLOCKED`, not `DONE`.

## 6. Testing Contract

### Minimum

- task-local unit tests;
- integration parity test for touched path;
- deterministic replay check.

### Program-level

- full Go and Rust suites for merged stacks;
- conformance bundle checks;
- race/sanitizer checks for concurrent paths;
- fuzz smoke for newly introduced reducers/graph logic.

Coverage requirement for new parallel-validation code:

- floor: `>=80%`
- target: `>=95%`

## 7. Fixture Contract

For fixture-related tasks (`Q-PV-16`, plus dependent tasks):

- add deterministic fixture IDs with stable expected outputs;
- verify fixture runs on both clients;
- ensure no wall-clock/randomness dependence in expected results.

## 8. Formal Contract

For formal-related tasks (`Q-PV-19`, plus dependent tasks):

- add/refresh theorems in `rubin-formal/RubinFormal/Refinement/`;
- update `rubin-formal/proof_coverage.json`;
- include theorem artifact evidence in PR notes.

No "proof placeholder" completion without executable artifacts.

## 9. Telemetry and Shadow Rollout Contract

For `Q-PV-12..Q-PV-13` and rollout tasks:

- `shadow` mode must not alter node truth path;
- mismatch logs must be bounded;
- telemetry must avoid sensitive payload leakage;
- rollback to `off` must be straightforward and documented.

## 10. Agent Handoff Template

Use this exact handoff structure:

```text
QID: Q-PV-XX
Scope completed:
- ...

Evidence:
- command: ...
- result: PASS/FAIL

Parity:
- seq_vs_parallel verdict: ...
- first_error: ...
- witness_digest: ...
- post_state_digest: ...

Open risks:
- ...

Next dependency-ready tasks:
- Q-PV-YY
```

## 11. Completion Rule

A `Q-PV-*` task can be marked complete only when:

- acceptance criteria are demonstrably met;
- required tests for the touched scope are green;
- evidence is attached to issue/PR;
- dependency chain remains logically consistent in queue.
