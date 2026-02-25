#!/usr/bin/env bash
set -euo pipefail

# fips-preflight.sh
#
# Purpose:
# - Provide a deterministic, reproducible check for "FIPS-only mode" readiness.
# - This does NOT claim FIPS validation; it only checks that the OpenSSL runtime can load the
#   `fips` provider module and that required algorithms are visible through that provider.
#
# Inputs (env):
# - RUBIN_OPENSSL_FIPS_MODE:
#     - off   (default): print summary only, exit 0
#     - ready: attempt to load fips provider, but do not fail if unavailable
#     - only : require fips provider + ML-DSA + SLH-DSA, otherwise exit non-zero
#
# Expected usage:
#   scripts/dev-env.sh -- scripts/crypto/openssl/fips-preflight.sh
#

MODE="${RUBIN_OPENSSL_FIPS_MODE:-off}"
FIPS_CONF="${RUBIN_OPENSSL_CONF:-${OPENSSL_CONF:-}}"
FIPS_MODULES="${RUBIN_OPENSSL_MODULES:-${OPENSSL_MODULES:-}}"

if [[ -n "${FIPS_MODULES}" ]]; then
  export OPENSSL_MODULES="${FIPS_MODULES}"
fi
if [[ -n "${FIPS_CONF}" ]]; then
  export OPENSSL_CONF="${FIPS_CONF}"
fi

echo "[fips-preflight] mode=${MODE}"
echo "[fips-preflight] openssl=$(command -v openssl || echo missing)"
echo "[fips-preflight] OPENSSL_MODULES=${OPENSSL_MODULES:-<unset>}"
echo "[fips-preflight] OPENSSL_CONF=${OPENSSL_CONF:-<unset>}"
openssl version -a | sed -n '1,20p' || true
echo

echo "[fips-preflight] providers(active):"
openssl list -providers || true
echo

if [[ "${MODE}" == "off" ]]; then
  exit 0
fi

echo "[fips-preflight] trying to load provider=fips..."
if ! openssl list -providers -provider fips >/dev/null 2>&1; then
  if [[ "${MODE}" == "only" ]]; then
    echo "ERROR: OpenSSL cannot load provider=fips (module missing or misconfigured)." >&2
    echo "Hint: set OPENSSL_MODULES / OPENSSL_CONF (see scripts/dev-env.sh overrides)." >&2
    exit 1
  fi
  echo "WARN: provider=fips not available (ok in mode=ready)." >&2
  exit 0
fi

echo "[fips-preflight] providers(with fips):"
openssl list -providers -provider fips || true
echo

echo "[fips-preflight] signature algos in provider=fips (filtered):"
openssl list -signature-algorithms -provider fips 2>/dev/null | grep -Eai 'ml-dsa|mldsa|slh-dsa|slh' || true
echo

if [[ "${MODE}" == "only" ]]; then
  # Require at least one ML-DSA and one SLH-DSA algorithm to be visible from fips provider.
  if ! openssl list -signature-algorithms -provider fips 2>/dev/null | grep -Eai 'ml-dsa|mldsa' >/dev/null; then
    echo "ERROR: ML-DSA not visible via provider=fips." >&2
    exit 1
  fi
  if ! openssl list -signature-algorithms -provider fips 2>/dev/null | grep -Eai 'slh-dsa|slh' >/dev/null; then
    echo "ERROR: SLH-DSA not visible via provider=fips." >&2
    exit 1
  fi
  if ! openssl list -signature-algorithms -propquery 'fips=yes' 2>/dev/null | grep -Eai 'ml-dsa|mldsa' >/dev/null; then
    echo "ERROR: ML-DSA not fetchable with propquery=fips=yes." >&2
    exit 1
  fi
  if ! openssl list -signature-algorithms -propquery 'fips=yes' 2>/dev/null | grep -Eai 'slh-dsa|slh' >/dev/null; then
    echo "ERROR: SLH-DSA not fetchable with propquery=fips=yes." >&2
    exit 1
  fi
fi

echo "OK: fips-preflight passed for mode=${MODE}"
