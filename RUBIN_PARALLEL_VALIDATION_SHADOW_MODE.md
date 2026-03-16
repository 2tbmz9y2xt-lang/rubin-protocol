# RUBIN Parallel Validation — Shadow Mode Contract

## Purpose

`shadow` mode validates production safety before enabling parallel verdicts.

In shadow mode:

- sequential path remains authoritative;
- parallel path computes comparison artifacts;
- mismatches are telemetry/diagnostic only.

## Comparison Surface

For each validated block compare:

- final verdict
- first canonical error code
- first invalid tx index
- witness digest
- post-state digest

## Safety Guarantees

Shadow mode MUST guarantee:

- no change to externally observed node verdict;
- bounded diagnostic logging;
- deterministic mismatch reproduction input bundle.

## Required Instrumentation

- mismatch counters by category
- digest-level mismatch detail
- replay bundle ID and block reference
- worker/scheduler metadata snapshot

## Exit Criteria

A rollout phase exits shadow only when:

- mismatch count is zero for required soak window;
- no unresolved deterministic replay discrepancy remains open;
- promotion checklist (`Q-PV-20`) is satisfied.
