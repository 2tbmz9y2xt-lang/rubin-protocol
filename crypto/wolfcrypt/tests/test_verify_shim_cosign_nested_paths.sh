#!/usr/bin/env bash
set -euo pipefail

# Dev regression test: ensure verify_shim_cosign.sh accepts SHA3SUMS entries whose
# file path includes directories (e.g. "shim/librubin_wc_shim.so") and matches by basename.
#
# This test intentionally skips cosign verification:
#   RUBIN_WOLFCRYPT_DEV_SKIP_COSIGN=1

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
script="${root_dir}/crypto/wolfcrypt/verify_shim_cosign.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

mkdir -p "${tmp}/out/shim"
shim="${tmp}/out/shim/librubin_wc_shim.so"
printf 'rubin-wc-shim-test' > "${shim}"

hash="$(python3 -c 'import hashlib, sys; print(hashlib.sha3_256(open(sys.argv[1], "rb").read()).hexdigest())' "${shim}")"
sums="${tmp}/out/shim/SHA3SUMS.txt"

# Nested path in sums (matches basename).
echo "${hash}  shim/$(basename "${shim}")" > "${sums}"

# Should pass (skip cosign; still enforces hash membership).
RUBIN_WOLFCRYPT_DEV_SKIP_COSIGN=1 "${script}" "${sums}" "${shim}" >/dev/null

# Negative: wrong name in sums should fail.
echo "${hash}  shim/not_the_shim.so" > "${sums}"
if RUBIN_WOLFCRYPT_DEV_SKIP_COSIGN=1 "${script}" "${sums}" "${shim}" >/dev/null 2>/dev/null; then
  echo "expected failure for mismatched basename, but verify succeeded" >&2
  exit 1
fi

echo "OK"

