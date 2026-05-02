#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/artifacts/combined-load}"

mkdir -p "$OUT_DIR"

RAW_OUT="$OUT_DIR/combined_load_benchmark.txt"
JSON_OUT="$OUT_DIR/combined_load_metrics.json"
SUMMARY_OUT="$OUT_DIR/combined_load_summary.md"
SLO_FILE="$ROOT_DIR/scripts/benchmarks/combined_load_slo.json"

BENCH_ITERS="${RUBIN_COMBINED_LOAD_BENCH_ITERS:-1}"

echo "[combined-load] running Go benchmark (iters=${BENCH_ITERS}x)"

set +e
"$ROOT_DIR/scripts/dev-env.sh" -- bash -lc "
  cd '$ROOT_DIR/clients/go'
  go test ./consensus \
    -run '^$' \
    -bench '^BenchmarkValidateBlockBasicCombinedLoad$' \
    -benchmem \
    -count=1 \
    -benchtime='${BENCH_ITERS}x'
" | tee "$RAW_OUT"
pipe_status=("${PIPESTATUS[@]}")
bench_status=${pipe_status[0]}
tee_status=${pipe_status[1]:-0}
set -e

if (( tee_status != 0 )); then
  echo "ERROR: failed to write combined-load benchmark output: $RAW_OUT" >&2
  exit "$tee_status"
fi

if (( bench_status != 0 )); then
  echo "[combined-load] benchmark command failed with status ${bench_status}; emitting advisory no_data artifact" >&2
fi

python3 "$ROOT_DIR/scripts/benchmarks/parse_go_bench.py" \
  --input "$RAW_OUT" \
  --slo "$SLO_FILE" \
  --output "$JSON_OUT" \
  --summary "$SUMMARY_OUT" \
  --producer-exit-code "$bench_status"

echo "[combined-load] artifacts:"
echo "  - $RAW_OUT"
echo "  - $JSON_OUT"
echo "  - $SUMMARY_OUT"
