#!/usr/bin/env bash
set -euo pipefail

# Launch helper that ensures wolfcrypt shim is fetched & verified before starting rubin-node.
# Usage:
#   scripts/launch_rubin_node.sh <rust|go> <ghcr_ref>
# Example:
#   scripts/launch_rubin_node.sh rust ghcr.io/myorg/wolfcrypt-shim:ubuntu-22.04-gcc-12

CLIENT="${1:-}"
REF="${2:-}"

if [ -z "${CLIENT}" ] || [ -z "${REF}" ]; then
  echo "usage: $0 <rust|go> ghcr.io/<owner>/wolfcrypt-shim:<tag>" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="${ROOT}/crypto/wolfcrypt/shim"
mkdir -p "${OUTDIR}"

echo "[shim] pulling and verifying ${REF}..."
source <("${ROOT}/crypto/wolfcrypt/fetch_shim_from_ghcr.sh" "${REF}" "${OUTDIR}" --export-env)

if [ "${CLIENT}" = "rust" ]; then
  echo "[run] cargo run -p rubin-node -- chain-id"
  (cd "${ROOT}" && cargo run -p rubin-node -- chain-id)
elif [ "${CLIENT}" = "go" ]; then
  echo "[run] go run ./clients/go/node chain-id"
  (cd "${ROOT}" && go run ./clients/go/node chain-id)
else
  echo "unknown client: ${CLIENT} (expected rust|go)" >&2
  exit 1
fi
