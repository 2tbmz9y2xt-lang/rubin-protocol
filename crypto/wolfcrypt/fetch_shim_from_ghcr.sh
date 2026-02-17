#!/usr/bin/env bash
set -euo pipefail

# Fetch wolfcrypt shim artifact from GHCR, verify cosign signatures, and optionally emit env exports.
# Usage:
#   ./crypto/wolfcrypt/fetch_shim_from_ghcr.sh ghcr.io/<owner>/wolfcrypt-shim:<os>-<cc_bin> [/tmp/outdir] [--export-env]
#
# Steps:
# 1) oras pull all files into target dir (default: ./shim-download)
# 2) verify SHA3SUMS.txt with cosign (keyless)
# 3) verify shim file hash against SHA3SUMS.txt
# 4) if --export-env is passed, print export lines for RUBIN_WOLFCRYPT_SHIM_PATH, RUBIN_WOLFCRYPT_SHIM_SHA3_256, RUBIN_WOLFCRYPT_STRICT=1

REF="${1:-}"
OUTDIR="${2:-shim-download}"
EXPORT=0
if [ "${2:-}" = "--export-env" ] || [ "${3:-}" = "--export-env" ]; then
  EXPORT=1
fi

if [ -z "${REF}" ]; then
  echo "usage: $0 ghcr.io/<owner>/wolfcrypt-shim:<tag> [outdir] [--export-env]" >&2
  exit 1
fi

if ! command -v oras >/dev/null 2>&1; then
  echo "oras not found in PATH" >&2
  exit 1
fi
if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign not found in PATH" >&2
  exit 1
fi

mkdir -p "${OUTDIR}"
oras pull "${REF}" -o "${OUTDIR}"

SUMS=$(find "${OUTDIR}" -type f -name "SHA3SUMS.txt" | sort | head -n1 || true)
if [ -z "${SUMS}" ]; then
  echo "missing SHA3SUMS.txt in pulled artifact" >&2
  exit 1
fi

# Pick first shim file
SHIM=$(find "${OUTDIR}" -type f -name "librubin_wc_shim.*" | sort | head -n1 || true)
if [ -z "${SHIM}" ]; then
  echo "shim binary not found in artifact" >&2
  exit 1
fi

./crypto/wolfcrypt/verify_shim_cosign.sh "${SUMS}" "${SHIM}" $( [ ${EXPORT} -eq 1 ] && echo "--export-env" )
