# RUBIN Agent Execution TZ (Anti-Drift Contract)

**Status:** Active  
**Date:** 2026-02-22

This is the mandatory execution contract for all coding/audit agents working on
`rubin-protocol`.

## 1. Purpose

Prevent scope drift, mixed interpretations, and partial parity changes.

## 2. Task Packet Requirements (from coordinator)

No agent may start implementation without a task packet containing:

1. Task ID and objective.
2. In-scope files and out-of-scope files.
3. Normative references (exact spec sections).
4. Acceptance tests (exact commands).
5. Expected error-code behavior (if relevant).
6. Deliverable format (report/PR requirements).

If any item is missing, the agent must stop and request clarification.

## 3. Hard Rules (MUST)

1. For consensus logic, implement Go and Rust in the same task unless explicitly split.
2. Do not change consensus semantics silently through docs-only edits.
3. Do not merge behavior-changing code without matching conformance vectors.
4. Do not edit unrelated files to satisfy formatting or cleanup preferences.
5. Do not reinterpret constants from NETWORK_PARAMS when CANONICAL states otherwise.
6. Do not bypass controller approval for consensus-level design changes.

## 4. File Boundaries

By default, task changes must stay within:

- `clients/go/**`
- `clients/rust/**`
- `conformance/**`
- `spec/**` (only for spec tasks)

Changing automation, inbox, queue, or local orchestration files is forbidden unless
the task is explicitly orchestration-only.

## 5. Parity Contract

For every covered operation:

1. Same validity result (`ok/err`) in Go and Rust.
2. Same consensus error code class.
3. Same deterministic output bytes for defined CLI operations.

Any mismatch is a failed task, even if one client "looks correct".

## 6. Validation Matrix (MUST RUN)

Minimum mandatory checks:

```bash
( cd clients/go && go test ./... )
( cd clients/rust && cargo test --workspace )
python3 conformance/runner/run_cv_bundle.py
```

For conformance/runner tasks:

- Add gate-specific run commands and show pass/fail for each touched gate.

For spec tasks:

- Show cross-file consistency checks for touched constants and section references.

## 7. Reporting Format (MUST)

Each task report must contain:

1. Scope completed.
2. Files changed.
3. Normative rules implemented (by section).
4. Test commands executed and outcomes.
5. Known gaps or deferred follow-ups.

Missing any report field means task is not done.

## 8. Definition of Done

A task is `DONE` only when all are true:

1. Code/spec changes are merged or review-ready in a single coherent PR.
2. Required tests are green.
3. Parity checks are green for touched behavior.
4. Conformance coverage exists for new normative behavior.
5. Report is published in the expected location.

## 9. Escalation Conditions

Stop and escalate immediately if:

1. Spec sections conflict and change semantics.
2. Go and Rust behavior cannot be reconciled within task scope.
3. A required normative rule cannot be tested with current runner architecture.
4. The task requires consensus changes not present in the approved roadmap.

