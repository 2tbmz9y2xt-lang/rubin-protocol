#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_ref="${1:-origin/main}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/rubin-codacy-preflight.XXXXXX")"
base_worktree="$tmp_dir/base"
artifact_dir="$tmp_dir/base-artifacts"
head_go="${HEAD_GO_COVERAGE:-$tmp_dir/head-go.coverage.out}"
head_rust="${HEAD_RUST_LCOV:-$tmp_dir/head-rust.lcov.info}"
head_coverage_sha="${HEAD_COVERAGE_SHA:-}"
base_go="$tmp_dir/base-go.coverage.out"
base_rust="$tmp_dir/base-rust.lcov.info"

cleanup() {
  git -C "$repo_root" worktree remove --force "$base_worktree" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

download_base_coverage_from_artifacts() {
  local repo merge_base tmp_json run_id
  repo="$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null || true)"
  if [[ -z "$repo" ]]; then
    return 1
  fi

  tmp_json="$tmp_dir/codacy-main-runs.json"
  if ! gh run list \
    --repo "$repo" \
    --workflow codacy-coverage.yml \
    --branch main \
    --event push \
    --json databaseId,headSha,conclusion \
    --limit 30 >"$tmp_json" 2>/dev/null; then
    return 1
  fi

  merge_base="$1"
  run_id="$(python3 - "$tmp_json" "$merge_base" <<'PY'
import json, sys
path, merge_base = sys.argv[1], sys.argv[2]
runs = json.load(open(path))
exact = [r for r in runs if r.get("conclusion") == "success" and r.get("headSha") == merge_base]
if exact:
    print(exact[0]["databaseId"])
    raise SystemExit
PY
)"
  if [[ -z "$run_id" ]]; then
    return 1
  fi

  mkdir -p "$artifact_dir"
  if ! gh run download "$run_id" --repo "$repo" --dir "$artifact_dir" >/dev/null 2>&1; then
    return 1
  fi

  local found_go found_rust
  found_go="$(find "$artifact_dir" -type f -name coverage.out | head -n 1)"
  found_rust="$(find "$artifact_dir" -type f -name lcov.info | head -n 1)"
  if [[ -z "$found_go" || -z "$found_rust" ]]; then
    return 1
  fi

  cp "$found_go" "$base_go"
  cp "$found_rust" "$base_rust"
  echo "Using baseline coverage artifacts from run $run_id" >&2
  return 0
}

if [[ "$(git -C "$repo_root" rev-parse --is-shallow-repository)" == "true" ]]; then
  git -C "$repo_root" fetch --prune --unshallow origin
else
  git -C "$repo_root" fetch origin
fi
merge_base="$(git -C "$repo_root" merge-base HEAD "$base_ref")"
current_head="$(git -C "$repo_root" rev-parse HEAD)"

if [[ -n "$head_coverage_sha" && "$head_coverage_sha" == "$current_head" && -s "$head_go" && -s "$head_rust" ]]; then
  echo "Reusing existing head coverage artifacts from current workspace"
else
  if [[ -n "$head_coverage_sha" && "$head_coverage_sha" != "$current_head" ]]; then
    echo "Ignoring stale head coverage artifacts: expected $current_head, got $head_coverage_sha"
  fi
  echo "Generating head coverage against $(git -C "$repo_root" rev-parse --short "$current_head")"
  GO_COVER_OUT="$head_go" \
  RUST_LCOV_OUT="$head_rust" \
  "$repo_root/scripts/dev-env.sh" -- \
  "$repo_root/scripts/run-codacy-coverage.sh" "$repo_root"
fi

if [[ "${GITHUB_ACTIONS:-}" == "true" ]] && download_base_coverage_from_artifacts "$merge_base"; then
  echo "Baseline coverage restored from GitHub artifacts for $(git -C "$repo_root" rev-parse --short "$merge_base")"
else
  git -C "$repo_root" worktree add --detach "$base_worktree" "$merge_base" >/dev/null
  echo "Generating base coverage against $(git -C "$repo_root" rev-parse --short "$merge_base")"
  GO_COVER_OUT="$base_go" \
  RUST_LCOV_OUT="$base_rust" \
  "$base_worktree/scripts/dev-env.sh" -- \
  "$base_worktree/scripts/run-codacy-coverage.sh" "$base_worktree"
fi

python3 "$repo_root/tools/check_codacy_coverage.py" \
  --repo-root "$repo_root" \
  --base-ref "$merge_base" \
  --base-go "$base_go" \
  --base-rust "$base_rust" \
  --head-go "$head_go" \
  --head-rust "$head_rust"
