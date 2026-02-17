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

## Strict wolfcrypt mode (CI / production tooling)

To force the runner to use the wolfcrypt shim (no DevStd fallback), set:

```bash
export RUBIN_WOLFCRYPT_STRICT=1
export RUBIN_WOLFCRYPT_SHIM_PATH=/path/to/librubin_wc_shim.*
export RUBIN_WOLFCRYPT_SHIM_SHA3_256=<sha3-256 hex>

export RUBIN_CONFORMANCE_RUST_NO_DEFAULT=1
export RUBIN_CONFORMANCE_RUST_FEATURES=wolfcrypt-dylib
export RUBIN_CONFORMANCE_GO_TAGS=wolfcrypt_dylib
```
