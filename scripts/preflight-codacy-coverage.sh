#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$repo_root/scripts/local-codacy-coverage-check.sh" "$@"
"$repo_root/scripts/local-codacy-variation-parity.sh" "$@"
