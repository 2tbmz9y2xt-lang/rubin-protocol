# RUBIN Parallel Validation — Fixture Specification

## 1. Fixture Families

Parallel-validation fixtures use `CV-PV-*` namespaces:

- `CV-PV-CURSOR-*`
- `CV-PV-DAG-*`
- `CV-PV-ERR-*`
- `CV-PV-DA-*`
- `CV-PV-CACHE-*`
- `CV-PV-MIXED-*`
- `CV-PV-STRESS-*`

## 2. Minimal Vector Schema

Each vector must include deterministic expected values:

```json
{
  "id": "CV-PV-ERR-01",
  "block_hex": "...",
  "utxo_snapshot_id": "...",
  "expect_valid": false,
  "expect_err": "TX_ERR_PARSE",
  "expect_first_invalid_tx_index": 2,
  "expect_witness_digest": "...",
  "expect_state_digest": "..."
}
```

## 3. Determinism Rules

- no wall-clock or random expected outputs;
- fixture IDs and dataset references are stable;
- vector outcome is invariant to worker scheduling perturbations.

## 4. Runner Contract

Fixture bundle execution must prove:

1. Go matches fixture expectations;
2. Rust matches Go behavior (parity);
3. sequential and parallel digests are equal for required vectors.

## 5. Coverage Expectations

The fixture set must collectively cover:

- first-error election edge cases;
- witness cursor boundary cases;
- parent-child DAG dependencies;
- DA-heavy and signature-heavy stress profiles.
