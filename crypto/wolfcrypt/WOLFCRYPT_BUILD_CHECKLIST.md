# wolfCrypt Build Checklist (single-step, macOS/Linux)

Date: 2026-02-16  
Profile: development + operator onboarding

Purpose: one command to build wolfCrypt from a pinned upstream tag (FIPS-oriented PQC profile) and run a minimal smoke test.

For CI/operator matrix reference (linux/macOS + compiler combinations), see:
[`MATRIX.md`](./MATRIX.md).

## Pinned versions

- `WOLFSSL_REPO`: `https://github.com/wolfSSL/wolfssl.git`
- `WOLFSSL_TAG`: `v5.8.4-stable` (edit intentionally only on profile change)

## One-step execution (CI-equivalent)

From repository root (operator-local reproducibility entrypoint):

```bash
cd /Users/gpt/Documents/rubin-protocol
RUBIN_WOLFSSL_TAG=v5.8.4-stable \
RUBIN_WOLFCRYPT_WORKROOT=/tmp/rubin-wolfcrypt \
RUBIN_WOLFSSL_PREFIX=/tmp/rubin-wolfcrypt/install \
RUBIN_WOLFCRYPT_SHIM_OUT=/tmp/rubin-wolfcrypt/wolfcrypt-shim \
CC=gcc-12 \
./scripts/wolfcrypt-build.sh
```

If your local `scripts/wolfcrypt-build.sh` is unavailable, run the identical workflow step from:
`.github/workflows/wolfcrypt-build.yml`
(same env vars and commands).

Defaults (if env vars omitted):

- `RUBIN_WOLFSSL_TAG=v5.8.4-stable`
- `RUBIN_WOLFCRYPT_WORKROOT=/tmp/rubin-wolfcrypt`
- `RUBIN_WOLFSSL_PREFIX=/tmp/rubin-wolfcrypt/install`
- `RUBIN_WOLFCRYPT_SHIM_OUT=/tmp/rubin-wolfcrypt/wolfcrypt-shim`
- `CC=cc`

For CI-like runs, set:

- `CC=gcc-12` (Linux GNU)
- `CC=clang-14` (Linux LLVM)
- `CC=clang` (macOS default toolchain)

Alternative shim-only override (if required by CI or compliance chain):

- `RUBIN_WOLFCRYPT_SHIM_OUT=/custom/path/wolfcrypt-shim`

## What the command does

1. Checkout pin:
   - clone or refresh `wolfSSL/wolfSSL` from:
     `https://github.com/wolfSSL/wolfssl.git`
   - checkout the pinned tag: `${RUBIN_WOLFSSL_TAG}`
2. Build with pinned PQC flags:
   - `--prefix=${RUBIN_WOLFSSL_PREFIX}`
   - ML-DSA flag:
     - `--enable-ml-dsa` (if supported by this wolfSSL tag),
     - otherwise fallback to `--enable-dilithium`
   - Optional SLH-DSA flag, if available:
     - `--enable-slh-dsa` or `--enable-sphincs+` / `--enable-sphincs`
   - `--enable-shared`
   - `--disable-examples`
   - `--disable-tests`
   - `--disable-demos`
3. Install to `${RUBIN_WOLFSSL_PREFIX}`
4. Build external shim:
   - `crypto/wolfcrypt/shim/build_wolfcrypt_shim.sh`
   - Output:
     - `${RUBIN_WOLFCRYPT_WORKROOT}/wolfcrypt-shim/librubin_wc_shim.dylib` (macOS)
     - `${RUBIN_WOLFCRYPT_WORKROOT}/wolfcrypt-shim/librubin_wc_shim.so` (Linux)
   - Runtime usage:
     - `RUBIN_WOLFCRYPT_SHIM_PATH=${RUBIN_WOLFCRYPT_SHIM_OUT}/librubin_wc_shim.<dylib|so}`
5. Run smoke tests:
   - compile and run a SHA3-256 hash sanity binary against installed wolfCrypt
   - verify successful runtime linkage and successful digest path
   - compile and run a shim-ABI sanity binary that checks `rubin_wc_sha3_256`
     returns `1` for a known message.

## Required host dependencies

- `git`
- C toolchain (`cc`, `make`)
- `pkg-config` is optional
- `nproc` (Linux) or `sysctl` (macOS) available for parallel build detection

## Acceptance for this checklist run

- build finishes without errors
- no unintended third-party build-system references in build artifacts/config
- native Go/Rust PQC path is currently unavailable in this repository (no native PQC bindings are wired yet); this run validates shim-based deployment only.
- smoke binary prints: `wolfCrypt SHA3-256 smoke test OK`
- shim smoke succeeds (returns success code and prints: `rubin_wc_shim smoke OK`)
- generated library exists:
  - macOS: `${RUBIN_WOLFSSL_PREFIX}/lib/libwolfssl.dylib`
  - Linux: `${RUBIN_WOLFSSL_PREFIX}/lib/libwolfssl.so`
- generated shim exists:
  - macOS: `${RUBIN_WOLFCRYPT_SHIM_OUT}/librubin_wc_shim.dylib`
  - Linux: `${RUBIN_WOLFCRYPT_SHIM_OUT}/librubin_wc_shim.so`

## Notes

- This checklist is an operational document only. It does not change consensus rules.
- For production hardening, keep artifacts immutable and log:
  - `${RUBIN_WOLFSSL_TAG}`
  - compiler ID + flags
  - host OS/arch
  - `uname -a`
  - build log hash
- This build profile is self-contained and uses only the configured wolfSSL build flags.
- SLH-DSA build is optional. If unavailable in the selected wolfSSL tag, build completes with a warning and continues with ML-DSA only.
