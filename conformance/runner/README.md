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
