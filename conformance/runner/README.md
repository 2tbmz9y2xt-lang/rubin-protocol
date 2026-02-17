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

## Current runner (CV-SIGHASH / CV-SIGCHECK)

From repo root:

```bash
python3 conformance/runner/run_cv_sighash.py
python3 conformance/runner/run_cv_bundle.py
```

Notes:
- The runner prefers `chain_id_hex` from each test vector and passes it via `--chain-id-hex` to avoid depending on chain-instance Markdown profiles.
- `--profile` is kept only as a fallback for fixtures that do not embed `chain_id_hex`.

## Additional runners

```bash
python3 conformance/runner/run_cv_compactsize.py
python3 conformance/runner/run_cv_parse.py
python3 conformance/runner/run_cv_bind.py
python3 conformance/runner/run_cv_utxo.py
python3 conformance/runner/run_cv_dep.py
python3 conformance/runner/run_cv_block.py
python3 conformance/runner/run_cv_reorg.py
```

Notes:
- `CV-COMPACTSIZE` and `CV-PARSE` now perform cross-client checks.
- `CV-SIGHASH` and `CV-SIGCHECK` are now cross-client in the bundle runner.
- `CV-BIND`, `CV-UTXO`, `CV-DEP`, `CV-BLOCK`, `CV-REORG` are runner shells and currently return a clear `NOT RUN` reason until node-layer APIs are implemented.

## Bundle runner (WIP)

```bash
python3 conformance/runner/run_cv_bundle.py
```

`run_cv_bundle.py` runs gates from `RUBIN_L1_CONFORMANCE_BUNDLE_v1.1.yaml` where CLI parity exists:

- `CV-COMPACTSIZE` via `compactsize`
- `CV-SIGHASH` via `txid` + `sighash`
- `CV-SIGCHECK` via `verify`
- `CV-PARSE` using fixture context builders (`tx_hex` when present, fallback synthesis otherwise)

It emits explicit `SKIP` lines for unsupported/unrunnable gates and unsupported fixtures.

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
