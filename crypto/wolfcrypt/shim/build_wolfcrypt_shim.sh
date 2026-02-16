#!/usr/bin/env bash

# Build RUBIN external wolfCrypt shim using an installed wolfSSL prefix.

set -euo pipefail

WORKROOT="${RUBIN_WOLFCRYPT_SHIM_WORKROOT:-${RUBIN_WOLFCRYPT_WORKROOT:-/tmp/rubin-wolfcrypt}}"
WOLFSSL_PREFIX="${RUBIN_WOLFSSL_PREFIX:-${WORKROOT}/install}"
SHIM_DIR="${WORKROOT}/rubin-wc-shim"
OUT_DIR="${RUBIN_WOLFCRYPT_SHIM_OUT:-${WORKROOT}/wolfcrypt-shim}"
SRC="${RUBIN_WOLFCRYPT_SHIM_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rubin_wc_shim.c}"
OS="$(uname -s)"

if [[ -z "${CC:-}" ]]; then
  CC=cc
fi

if [[ ! -f "${SRC}" ]]; then
  echo "source not found: ${SRC}" >&2
  exit 1
fi

mkdir -p "${SHIM_DIR}" "${OUT_DIR}"
cp -f "${SRC}" "${SHIM_DIR}/rubin_wc_shim.c"

if [[ "${OS}" == "Darwin" ]]; then
  OUT="${OUT_DIR}/librubin_wc_shim.dylib"
  FLAGS=(-dynamiclib)
elif [[ "${OS}" == "Linux" ]]; then
  OUT="${OUT_DIR}/librubin_wc_shim.so"
  FLAGS=(-shared -Wl,-soname,librubin_wc_shim.so)
else
  echo "unsupported OS: ${OS}" >&2
  exit 1
fi

"${CC}" -std=c11 -O2 -fPIC \
  -I"${WOLFSSL_PREFIX}/include" \
  -o "${OUT}" \
  "${SHIM_DIR}/rubin_wc_shim.c" \
  -L"${WOLFSSL_PREFIX}/lib" -lwolfssl -lm "${FLAGS[@]}" \
  -Wl,-rpath,"${WOLFSSL_PREFIX}/lib"

echo "built: ${OUT}"

