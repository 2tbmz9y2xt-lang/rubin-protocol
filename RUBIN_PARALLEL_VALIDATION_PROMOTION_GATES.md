# RUBIN Parallel Validation — Promotion Gates

## 1. Purpose

This document defines the staged rollout governance for parallel
validation. Each stage has mandatory evidence thresholds that must
be met before promotion to the next stage.

## 2. Mismatch Definition

A **mismatch** is any divergence between the sequential (truth) path
and the parallel path in one or more of these four fields:

| Field | Description |
|-------|-------------|
| verdict | accept vs reject |
| first_err | canonical error code + tx index |
| post_state_digest | SHA3-256 of UTXO set after block |
| witness_digest | SHA3-256 of witness assignments |

Any single-field divergence constitutes a mismatch.
Shadow mode mismatches never affect the node verdict.

## 3. Promotion Stages

| Stage | Mode | Min blocks | Min hours | Mismatch threshold | Gate |
|-------|------|-----------|-----------|-------------------|------|
| 0. Local dev | off | 10 000 | — | 0 | manual |
| 1. CI (per-PR) | shadow | CV-PV-* + 1 000 replay | — | 0 | automated |
| 2. Devnet shadow | shadow | 50 000 | 48 | 0 | manual |
| 3. Testnet shadow | shadow | 100 000 | 168 (7d) | 0 | manual |
| 4. Opt-in on | on | 500 000 | 720 (30d) | 0 | manual |
| 5. Default on | on | — | — | — | controller sign-off |

Zero tolerance: **one mismatch = stage FAIL, no promotion**.

## 4. Evidence Format

Each stage produces a soak report in JSON format. Schema:

```json
{
  "schema_version": 1,
  "stage": "ci | devnet | testnet-shadow | opt-in",
  "start_height": 0,
  "end_height": 0,
  "blocks_validated": 0,
  "duration_hours": 0.0,
  "mismatches": [
    {
      "height": 0,
      "tx_index": 0,
      "field": "verdict | first_err | post_state_digest | witness_digest",
      "sequential_value": "",
      "parallel_value": ""
    }
  ],
  "mismatch_count": 0,
  "verdict": "PASS | FAIL",
  "go_commit": "",
  "rust_commit": "",
  "timestamp_utc": ""
}
```

Reports are stored in `conformance/evidence/pv-soak/`.

## 5. CI Enforcement Gate

The CI gate runs on every PR that touches `clients/go/consensus/connect_block_parallel*.go`
or `clients/rust/crates/rubin-consensus/src/parallel*`:

1. Run all CV-PV-* conformance fixtures
2. Execute 1000-block shadow replay
3. Generate soak report
4. Assert `mismatch_count == 0`
5. Exit 0 on PASS, exit 1 on FAIL

Script: `scripts/pv-soak-ci-gate.sh`

## 6. Rollback Policy

Mismatch detected at any stage triggers:

1. Immediate rollback to `off` mode
2. Diagnostic bundle captured (block, tx, digests, error)
3. GitHub issue created automatically with diagnostics
4. Re-promotion requires restart from Stage 0 (local dev)
5. Root-cause fix must include regression test in CV-PV-* fixtures

## 7. Dependencies

This gate structure requires completion of:

- Q-PV-12: shadow mode implementation (DONE)
- Q-PV-13: mismatch diagnostics (DONE)
- Q-PV-15: PV integration suite (DONE)
- Q-PV-16: conformance fixtures (DONE)
- Q-PV-18: benchmark evidence package (DONE)
- Q-PV-19: formal refinement package (DONE — PR#745 + rubin-formal#151)

## 8. Acceptance Criteria

- [ ] Zero mismatches over defined soak windows before each promotion
- [ ] Operator runbook updated with stage-specific procedures
- [ ] Rollback path tested and documented
- [ ] Promotion criteria tied to formal + fixture + benchmark evidence
- [ ] CI soak gate integrated and passing
