#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_ref="${1:-origin/main}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/rubin-codacy-parity.XXXXXX")"
artifact_dir="$tmp_dir/base-artifacts"
head_go="${HEAD_GO_COVERAGE:-$tmp_dir/head-go.coverage.out}"
head_rust="${HEAD_RUST_LCOV:-$tmp_dir/head-rust.lcov.info}"
head_coverage_sha="${HEAD_COVERAGE_SHA:-}"
base_go="$tmp_dir/base-go.coverage.out"
base_rust="$tmp_dir/base-rust.lcov.info"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

require_gh() {
  if ! command -v gh >/dev/null 2>&1; then
    echo "FAIL: gh CLI is required for Codacy variation parity preflight" >&2
    exit 1
  fi
}

fetch_origin() {
  if [[ "$(git -C "$repo_root" rev-parse --is-shallow-repository)" == "true" ]]; then
    git -C "$repo_root" fetch --prune --unshallow origin
  else
    git -C "$repo_root" fetch origin
  fi
}

detect_repo() {
  gh repo view --json nameWithOwner --jq '.nameWithOwner'
}

detect_pr_number() {
  if [[ -n "${CODACY_PR_NUMBER:-}" ]]; then
    printf '%s\n' "$CODACY_PR_NUMBER"
    return 0
  fi

  if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" && -n "${GITHUB_EVENT_PATH:-}" ]]; then
    python3 - "$GITHUB_EVENT_PATH" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    event = json.load(fh)
print(event["number"])
PY
    return 0
  fi

  local repo branch
  repo="$(detect_repo 2>/dev/null || true)"
  branch="$(git -C "$repo_root" branch --show-current)"
  if [[ -z "$repo" || -z "$branch" ]]; then
    return 1
  fi

  gh pr view "$branch" --repo "$repo" --json number --jq '.number' 2>/dev/null
}

codacy_common_ancestor_for_pr() {
  local repo pr_number
  repo="$1"
  pr_number="$2"
  python3 - "$repo" "$pr_number" <<'PY'
import json
import sys
import urllib.request

repo = sys.argv[1]
pr_number = sys.argv[2]
owner, name = repo.split("/", 1)
url = (
    "https://app.codacy.com/api/v3/analysis/organizations/gh/"
    f"{owner}/repositories/{name}/pull-requests/{pr_number}/coverage/status"
)
with urllib.request.urlopen(url, timeout=20) as response:
    data = json.load(response)

ancestor = data["data"]["commonAncestorCommit"]
sha = ancestor.get("commitSha")
processed_reports = [r for r in ancestor.get("reports", []) if r.get("status") == "Processed"]
if not sha or not processed_reports:
    raise SystemExit(1)
print(sha)
PY
}

download_main_commit_artifacts() {
  local repo target_sha tmp_json run_id found_go found_rust
  repo="$1"
  target_sha="$2"
  tmp_json="$tmp_dir/codacy-main-runs.json"

  gh run list \
    --repo "$repo" \
    --workflow codacy-coverage.yml \
    --branch main \
    --event push \
    --json databaseId,headSha,conclusion \
    --limit 30 >"$tmp_json"

  run_id="$(python3 - "$tmp_json" "$target_sha" <<'PY'
import json, sys
runs = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
target_sha = sys.argv[2]
for run in runs:
    if run.get("conclusion") == "success" and run.get("headSha") == target_sha:
        print(run["databaseId"])
        break
PY
)"
  if [[ -z "$run_id" ]]; then
    echo "FAIL: no successful main codacy-coverage artifact found for baseline $target_sha" >&2
    return 1
  fi

  mkdir -p "$artifact_dir"
  gh run download "$run_id" --repo "$repo" --dir "$artifact_dir" >/dev/null

  found_go="$(find "$artifact_dir" -type f -name coverage.out | head -n 1)"
  found_rust="$(find "$artifact_dir" -type f -name lcov.info | head -n 1)"
  if [[ -z "$found_go" || -z "$found_rust" ]]; then
    echo "FAIL: baseline artifact for $target_sha is missing coverage.out or lcov.info" >&2
    return 1
  fi

  cp "$found_go" "$base_go"
  cp "$found_rust" "$base_rust"
  echo "Using Codacy variation baseline artifact from main commit $target_sha (run $run_id)" >&2
}

fetch_origin
require_gh

repo="$(detect_repo)"
merge_base="$(git -C "$repo_root" merge-base HEAD "$base_ref")"
current_head="$(git -C "$repo_root" rev-parse HEAD)"
target_baseline_sha="$merge_base"
pr_number="$(detect_pr_number || true)"

if [[ -n "$pr_number" ]]; then
  codacy_ancestor="$(codacy_common_ancestor_for_pr "$repo" "$pr_number" || true)"
  if [[ -n "$codacy_ancestor" ]]; then
    target_baseline_sha="$codacy_ancestor"
    echo "Codacy PR #$pr_number common ancestor baseline: $target_baseline_sha" >&2
  else
    echo "Codacy PR #$pr_number baseline unavailable; falling back to local merge-base $merge_base" >&2
  fi
fi

if [[ -n "$head_coverage_sha" && "$head_coverage_sha" == "$current_head" && -s "$head_go" && -s "$head_rust" ]]; then
  echo "Reusing existing head coverage artifacts from current workspace" >&2
else
  if [[ -n "$head_coverage_sha" && "$head_coverage_sha" != "$current_head" ]]; then
    echo "Ignoring stale head coverage artifacts: expected $current_head, got $head_coverage_sha" >&2
  fi
  echo "Generating head coverage against $(git -C "$repo_root" rev-parse --short "$current_head")" >&2
  GO_COVER_OUT="$head_go" \
  RUST_LCOV_OUT="$head_rust" \
  "$repo_root/scripts/dev-env.sh" -- \
  "$repo_root/scripts/run-codacy-coverage.sh" "$repo_root"
fi

download_main_commit_artifacts "$repo" "$target_baseline_sha"

python3 "$repo_root/tools/check_codacy_coverage.py" \
  --summary-title "Codacy variation parity" \
  --repo-root "$repo_root" \
  --base-ref "$target_baseline_sha" \
  --base-go "$base_go" \
  --base-rust "$base_rust" \
  --head-go "$head_go" \
  --head-rust "$head_rust" \
  --min-diff-coverage 0
