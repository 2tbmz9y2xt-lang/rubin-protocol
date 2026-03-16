# RUBIN Parallel Validation — Security Notes

## Threat Focus

Parallel validation introduces implementation risk, not new consensus semantics.

Primary hazards:

1. nondeterministic first-error election
2. witness slice misassignment
3. incomplete parent-child dependency graph
4. cache poisoning / false positive cache reuse
5. policy leakage into consensus-equivalent path
6. shadow mismatch flood and operator blindness

## Controls

- deterministic reducer with canonical priority table
- sequential witness precompute and explicit boundary checks
- explicit DAG edges (`same-prevout`, `producer->consumer`)
- positive-only bounded cache with canonical keying
- strict separation of policy checks from consensus-equivalent engine
- bounded mismatch telemetry and rollback-to-off procedure

## Verification Surfaces

- deterministic replay harness
- race/sanitizer suites
- fuzz perturbation on scheduler/reducer paths
- fixture parity and digest equality checks
- formal refinement artifacts for reducer/graph/cursor invariants

## Security Review Checklist

- no worker mutates consensus state
- reducer output is schedule-independent
- first canonical error preserved
- mismatch diagnostics do not leak sensitive payloads
- rollback path is tested and documented
