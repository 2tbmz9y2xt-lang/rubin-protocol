#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# RUB-444: assert the Rust compact+DA combined soak aggregation is fail-closed —
# a combined PASS requires BOTH child smokes to be PASS; any non-PASS child
# yields combined NO_DATA with a non-zero exit. The soak's `--self-test` mode
# exercises the aggregation with synthetic child reports (no nodes spawned), so
# this test is hermetic and fast.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOAK_SCRIPT="${REPO_ROOT}/scripts/devnet-rust-compact-da-soak.sh"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[[ -x "${SOAK_SCRIPT}" ]] || { echo "soak script missing or non-executable: ${SOAK_SCRIPT}" >&2; exit 1; }

# Static guard: the aggregation must be fail-closed (combined PASS only when both
# child verdicts are PASS) so the self-test cannot pass against a permissive impl.
python3 - "${SOAK_SCRIPT}" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
if not re.search(
    r'combined\s*=\s*"PASS"\s+if\s+cv\s*==\s*"PASS"\s+and\s+dv\s*==\s*"PASS"\s+else\s+"NO_DATA"',
    text,
):
    raise SystemExit("fail-closed aggregation rule not found in soak script")
if "--self-test" not in text:
    raise SystemExit("soak script does not expose --self-test")
# Schema consistency: both the aggregated and the early fail-closed report paths
# must emit the same source-bound shape (source + artifact_paths + verdicts).
def body(fn):
    m = re.search(rf"{fn}\(\) \{{(.*?)\n\}}\n", text, re.S)
    if not m:
        raise SystemExit(f"function not found: {fn}")
    return m.group(1)
for fn in ("aggregate_and_write", "emit_combined_unavailable"):
    b = body(fn)
    for key in ('"source"', '"artifact_paths"', '"combined_verdict"'):
        if key not in b:
            raise SystemExit(f"{fn} is missing {key}: combined report schema would diverge")
PY

out="$("${SOAK_SCRIPT}" --self-test)" || { echo "soak --self-test failed:" >&2; echo "${out}" >&2; exit 1; }
case "${out}" in
  PASS:*) ;;
  *) echo "unexpected --self-test output: ${out}" >&2; exit 1 ;;
esac

echo "PASS: compact+DA soak fail-closed aggregation is tested for compact!=PASS and da!=PASS"
