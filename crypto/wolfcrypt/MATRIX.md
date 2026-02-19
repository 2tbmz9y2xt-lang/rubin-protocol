# wolfCrypt CI Matrix Guide (Linux/macOS)

## Purpose

Provide a stable local matrix for running `scripts/wolfcrypt-build.sh` in CI and operator environments.

Canonical invocation uses the following environment and command pattern:

- `RUBIN_WOLFSSL_TAG=v5.8.4-stable`
- `RUBIN_WOLFCRYPT_WORKROOT=/tmp/rubin-wolfcrypt`
- `RUBIN_WOLFSSL_PREFIX=/tmp/rubin-wolfcrypt/install`
- set `CC` from the matrix

For v1.1, this is the normative matrix for FIPS-oriented runs: the active provider path is wolfCrypt + shim.

## Recommended CI Matrix

| CI job            | OS / Runner   | `CC`          | Expected toolchain       | Check command                  | Notes |
|-------------------|---------------|---------------|-------------------------|-------------------------------|-------|
| `build profile (ubuntu-22.04, gcc-12)` | `ubuntu-22.04` | `gcc-12`      | GCC 12.x                  | `gcc-12 --version`            | Linux baseline GNU compiler path |
| `build profile (ubuntu-22.04, clang-14)` | `ubuntu-22.04` | `clang-14`    | Clang 14.x                | `clang-14 --version`          | Linux LLVM baseline path |
| `build profile (macos-14, clang)` | `macos-14`    | `clang`       | Apple Clang (system)       | `clang --version`             | Uses macOS SDK + Apple Clang |

## Why `CC` is important

`scripts/wolfcrypt-build.sh` respects `CC` if set, otherwise uses default `cc`.
The CI scenario must set explicit `CC` from matrix to ensure reproducible compiler selection.

## PQC flag profile (per pinned wolfSSL tag)

- ML-DSA is mandatory: build script auto-selects `--enable-ml-dsa` when available,
  otherwise falls back to `--enable-dilithium`.
- SLH-DSA is optional: build script enables it only if the pinned tag supports
  `--enable-slh-dsa` or `--enable-sphincs+` / `--enable-sphincs`.
- External PQC providers are not enabled in this profile.

## Local one-off equivalent run

```bash
CC=gcc-12 \
RUBIN_WOLFSSL_TAG=v5.8.4-stable \
RUBIN_WOLFCRYPT_WORKROOT=/tmp/rubin-wolfcrypt \
RUBIN_WOLFSSL_PREFIX=/tmp/rubin-wolfcrypt/install \
./scripts/wolfcrypt-build.sh
```

```bash
CC=clang-14 \
RUBIN_WOLFSSL_TAG=v5.8.4-stable \
RUBIN_WOLFCRYPT_WORKROOT=/tmp/rubin-wolfcrypt \
RUBIN_WOLFSSL_PREFIX=/tmp/rubin-wolfcrypt/install \
./scripts/wolfcrypt-build.sh
```

```bash
CC=clang \
RUBIN_WOLFSSL_TAG=v5.8.4-stable \
RUBIN_WOLFCRYPT_WORKROOT=/tmp/rubin-wolfcrypt \
RUBIN_WOLFSSL_PREFIX=/tmp/rubin-wolfcrypt/install \
./scripts/wolfcrypt-build.sh
```

## Version policy

- `v5.8.4-stable` is the pinned wolfSSL tag for this profile.
- If toolchain versions change by runner image update, either:
  - update OS image in workflow matrix, or
  - pin package versions and use explicit `CC` binaries.
- All matrix entries are non-consensus operational guidance.
