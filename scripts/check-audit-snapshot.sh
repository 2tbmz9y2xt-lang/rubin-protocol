#!/usr/bin/env bash
set -euo pipefail

#
# check-audit-snapshot.sh
#
# Purpose:
# - Validate that the spec-side audit snapshot (private spec repo) is consistent with:
#   - the spec-side AUDIT_CONTEXT.md
#   - the code-side CI enforcement (rubin-protocol/.github/workflows/ci.yml)
#   - the code-side formal proof_coverage.json (rubin-protocol/rubin-formal/proof_coverage.json)
#
# Usage:
#   scripts/check-audit-snapshot.sh /abs/path/to/rubin-spec-private
#

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /abs/path/to/rubin-spec-private" >&2
  exit 2
fi

SPEC_ROOT="$1"
if [[ ! -d "${SPEC_ROOT}" ]]; then
  echo "ERROR: spec root not found: ${SPEC_ROOT}" >&2
  exit 2
fi

"${REPO_ROOT}/scripts/dev-env.sh" -- \
  python3 "${REPO_ROOT}/tools/check_audit_snapshot.py" \
    --context-root "${SPEC_ROOT}" \
    --code-root "${REPO_ROOT}"

