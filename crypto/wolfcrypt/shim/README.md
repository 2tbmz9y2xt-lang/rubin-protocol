# External RUBIN wolfCrypt Shim Source

This directory contains the trackable external shim source used to build
`librubin_wc_shim.*` for client runtime loading.

## Build contract

- Input library: wolfSSL/wolfCrypt built with PQC (ML-DSA mandatory, SLH-DSA optional)
- Output shared library:
  - `librubin_wc_shim.dylib` (macOS)
  - `librubin_wc_shim.so` (Linux)

The shared object must export:

- `rubin_wc_sha3_256`
- `rubin_wc_verify_mldsa87`
- `rubin_wc_verify_slhdsa_shake_256f`

Return code convention:

- `1` — success
- `0` — signature invalid
- `<0` — provider/internal error

## Local build (single command)

From repo root:

```bash
RUBIN_WOLFSSL_PREFIX=/tmp/rubin-wolfcrypt/install \
RUBIN_WOLFCRYPT_WORKROOT=/tmp/rubin-wolfcrypt \
./crypto/wolfcrypt/shim/build_wolfcrypt_shim.sh
```

Result:

- macOS: `${RUBIN_WOLFCRYPT_WORKROOT}/wolfcrypt-shim/librubin_wc_shim.dylib`
- Linux: `${RUBIN_WOLFCRYPT_WORKROOT}/wolfcrypt-shim/librubin_wc_shim.so`

For runtime loading, set:

```bash
export RUBIN_WOLFCRYPT_SHIM_PATH=/custom/path/librubin_wc_shim.dylib   # macOS
# export RUBIN_WOLFCRYPT_SHIM_PATH=/custom/path/librubin_wc_shim.so    # Linux
```

## Go/Rust native integration status

Current production profile is shim-based only:
- Go/Rust clients load PQC functions from `librubin_wc_shim.*` at runtime via `RUBIN_WOLFCRYPT_SHIM_PATH`.

Native direct PQC bindings for Go and Rust are currently unavailable (no native bindings are implemented yet) and are planned for a later integration milestone after this shim path is fully validated in compliant deployments.

Notes:

- The script is intended for operational/build pipelines.
- Binary artifacts are excluded via `.gitignore` and must not be committed.
