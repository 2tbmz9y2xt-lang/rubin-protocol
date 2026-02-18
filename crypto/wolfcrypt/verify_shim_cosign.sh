#!/usr/bin/env bash
set -euo pipefail

# Verify SHA3SUMS.txt produced by CI with cosign keyless signature.
# Optional: verify a specific shim binary and emit export commands.
# Usage:
#   ./crypto/wolfcrypt/verify_shim_cosign.sh /path/to/SHA3SUMS.txt [/path/to/librubin_wc_shim.*] [--export-env]
# Dev mode:
#   RUBIN_WOLFCRYPT_DEV_SKIP_COSIGN=1
#   - skip cosign/.sig/.crt verification, keep hash membership verification.
# If --export-env is set, prints export lines for:
#   RUBIN_WOLFCRYPT_SHIM_PATH
#   RUBIN_WOLFCRYPT_SHIM_SHA3_256
#   RUBIN_WOLFCRYPT_STRICT=1

DEV_SKIP_RAW="${RUBIN_WOLFCRYPT_DEV_SKIP_COSIGN:-0}"
DEV_SKIP_NORM="$(printf '%s' "${DEV_SKIP_RAW}" | tr '[:upper:]' '[:lower:]')"
case "${DEV_SKIP_NORM}" in
  1|true|yes) DEV_SKIP_COSIGN=1 ;;
  0|false|no|"") DEV_SKIP_COSIGN=0 ;;
  *)
    echo "invalid RUBIN_WOLFCRYPT_DEV_SKIP_COSIGN=${DEV_SKIP_RAW} (expected 0/1/true/false)" >&2
    exit 1
    ;;
esac

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

if [ "${DEV_SKIP_COSIGN}" -eq 0 ]; then
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign not found in PATH" >&2
    exit 1
  fi

  if [ ! -f "${SIG}" ] || [ ! -f "${CRT}" ]; then
    echo "expected ${SIG} and ${CRT} next to SHA3SUMS.txt" >&2
    exit 1
  fi

  COSIGN_EXPERIMENTAL=1 COSIGN_YES=true cosign verify-blob \
    --certificate "${CRT}" \
    --signature "${SIG}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --certificate-identity-regexp '^https://github.com/2tbmz9y2xt-lang/rubin-protocol/.+@refs/(heads/.+|pull/.+/.+|tags/.+)$' \
    "${SUMS}"

  echo "cosign verification OK for ${SUMS}" >&2
else
  echo "dev mode: skipping cosign verification for ${SUMS}" >&2
fi

if [ -n "${SHIM}" ]; then
  if [ ! -f "${SHIM}" ]; then
    echo "shim file not found: ${SHIM}" >&2
    exit 1
  fi
  HASH=$(python3 -c 'import hashlib, sys; print(hashlib.sha3_256(open(sys.argv[1], "rb").read()).hexdigest())' "${SHIM}")
  name=$(basename "${SHIM}")
  if ! awk -v want_hash="${HASH}" -v want_name="${name}" '
    {
      if (tolower($1) != tolower(want_hash)) next
      path = $2
      sub(/^\*/, "", path)    # support checksum style with leading "*"
      n = split(path, parts, "/")
      base = parts[n]
      if (base == want_name) { found = 1; exit 0 }
    }
    END { exit(found ? 0 : 1) }
  ' "${SUMS}"; then
    echo "hash mismatch for ${name}: ${HASH} not in ${SUMS} (basename-aware)" >&2
    exit 1
  fi
  echo "hash match: ${name} ${HASH}" >&2
  if [ ${EXPORT} -eq 1 ]; then
    echo "export RUBIN_WOLFCRYPT_SHIM_PATH=\"${SHIM}\""
    echo "export RUBIN_WOLFCRYPT_SHIM_SHA3_256=${HASH}"
    echo "export RUBIN_WOLFCRYPT_STRICT=1"
  fi
fi
