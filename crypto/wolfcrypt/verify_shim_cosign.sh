#!/usr/bin/env bash
set -euo pipefail

# Verify SHA3SUMS.txt produced by CI with cosign keyless signature.
# Optional: verify a specific shim binary and emit export commands.
# Usage:
#   ./crypto/wolfcrypt/verify_shim_cosign.sh /path/to/SHA3SUMS.txt [/path/to/librubin_wc_shim.*] [--export-env]
# If --export-env is set, prints export lines for:
#   RUBIN_WOLFCRYPT_SHIM_PATH
#   RUBIN_WOLFCRYPT_SHIM_SHA3_256
#   RUBIN_WOLFCRYPT_STRICT=1

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign not found in PATH" >&2
  exit 1
fi

SUMS="${1:-}"
SHIM=""
EXPORT=0

shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --export-env) EXPORT=1 ;;
    *) if [ -z "${SHIM}" ]; then SHIM="$1"; else echo "unexpected arg: $1" >&2; exit 1; fi ;;
  esac
  shift
done

if [ -z "${SUMS}" ] || [ ! -f "${SUMS}" ]; then
  echo "usage: $0 /path/to/SHA3SUMS.txt [/path/to/librubin_wc_shim.*] [--export-env]" >&2
  exit 1
fi

SIG="${SUMS}.sig"
CRT="${SUMS}.crt"

if [ ! -f "${SIG}" ] || [ ! -f "${CRT}" ]; then
  echo "expected ${SIG} and ${CRT} next to SHA3SUMS.txt" >&2
  exit 1
fi

COSIGN_EXPERIMENTAL=1 COSIGN_YES=true cosign verify-blob \
  --certificate "${CRT}" \
  --signature "${SIG}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp '^https://github.com/2tbmz9y2xt-lang/rubin-protocol/.github/workflows/wolfcrypt-build.yml@refs/(heads/.+|pull/.+/.+)$' \
  "${SUMS}"

echo "cosign verification OK for ${SUMS}"

if [ -n "${SHIM}" ]; then
  if [ ! -f "${SHIM}" ]; then
    echo "shim file not found: ${SHIM}" >&2
    exit 1
  fi
  HASH=$(python - <<'PY'
import hashlib, sys
path = sys.argv[1]
with open(path, "rb") as f:
    h = hashlib.sha3_256(f.read()).hexdigest()
print(h)
PY
"${SHIM}")
  name=$(basename "${SHIM}")
  if ! grep -q "${HASH}  ${name}" "${SUMS}"; then
    echo "hash mismatch for ${name}: ${HASH} not in ${SUMS}" >&2
    exit 1
  fi
  echo "hash match: ${name} ${HASH}"
  if [ ${EXPORT} -eq 1 ]; then
    echo "export RUBIN_WOLFCRYPT_SHIM_PATH=\"${SHIM}\""
    echo "export RUBIN_WOLFCRYPT_SHIM_SHA3_256=${HASH}"
    echo "export RUBIN_WOLFCRYPT_STRICT=1"
  fi
fi
