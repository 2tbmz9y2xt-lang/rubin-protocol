# Conformance Runner

Status: DEVELOPMENT

Planned behavior:

1. Load fixtures from `../fixtures/`
2. Invoke Rust client and Go client validators
3. Compare outputs:
   - `txid`
   - `sighash` digest
   - `error_code`
   - (later) block validity and state hash

## Current runner (CV-SIGHASH)

From repo root:

```bash
python3 conformance/runner/run_cv_sighash.py
```

Notes:
- The runner prefers `chain_id_hex` from each test vector and passes it via `--chain-id-hex` to avoid depending on chain-instance Markdown profiles.
- `--profile` is kept only as a fallback for fixtures that do not embed `chain_id_hex`.
