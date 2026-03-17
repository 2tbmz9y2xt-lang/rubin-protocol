# RUBIN Parallel Validation — Operator Runbook

## 1. Runtime Modes

Parallel validation exposes three modes:

- `off`: sequential validation only (default-safe mode)
- `shadow`: sequential is authoritative, parallel runs for comparison only
- `on`: parallel validation path enabled with deterministic reducer + sequential commit

## 2. Rollout Order

1. local lab (`off`)
2. CI parity checks
3. devnet `shadow`
4. testnet `shadow`
5. opt-in testnet `on`
6. mainnet default remains `off` until: ≥30 days zero-mismatch soak on testnet, all conformance vectors green, formal bridge proof complete

## 3. Observability Signals

Monitor:

- mode and worker count
- shadow mismatch totals (verdict/error/state/witness)
- scheduler queue depth
- validation/commit latency
- signature cache hit ratio

## 4. Mismatch Procedure (Shadow)

If mismatch is detected in `shadow` mode:

1. keep sequential verdict as source of truth;
2. capture block ID, tx index, error code, digest deltas;
3. persist diagnostic bundle for replay;
4. open incident task and block promotion;
5. investigate reducer/graph/cursor assumptions first.

## 5. Emergency Rollback

Immediate fallback path:

- switch mode to `off`;
- keep telemetry enabled;
- resume only after root-cause fix and replay parity confirmation.

## 6. Go/No-Go for Promotion

Promotion to broader rollout is allowed only when:

- zero unresolved shadow mismatches for ≥72 hours (soak window);
- all parity conformance fixtures pass (`run_cv_bundle` exit 0);
- formal Lean bridge proofs type-check (`lake build` exit 0);
- parallel validation benchmark shows ≤5% latency regression vs sequential.
