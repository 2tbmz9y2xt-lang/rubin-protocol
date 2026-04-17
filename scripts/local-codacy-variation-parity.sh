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
  if command -v gh >/dev/null 2>&1; then
    gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null && return 0
  fi

  local remote_url
  remote_url="$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)"
  if [[ -z "$remote_url" ]]; then
    return 1
  fi

  python3 - "$remote_url" <<'PY'
import re
import sys

remote = sys.argv[1].strip()
patterns = [
    r'github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+?)(?:\.git)?$',
]
for pattern in patterns:
    match = re.search(pattern, remote)
    if match:
        print(f"{match.group('owner')}/{match.group('repo')}")
        raise SystemExit(0)
raise SystemExit(1)
PY
}

github_pr_head_sha() {
  local repo pr_number
  repo="$1"
  pr_number="$2"
  if ! command -v gh >/dev/null 2>&1; then
    return 1
  fi
  gh pr view "$pr_number" --repo "$repo" --json headRefOid --jq '.headRefOid'
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
  if ! command -v gh >/dev/null 2>&1; then
    return 1
  fi
  repo="$(detect_repo 2>/dev/null || true)"
  branch="$(git -C "$repo_root" branch --show-current)"
  if [[ -z "$repo" || -z "$branch" ]]; then
    return 1
  fi

  gh pr view "$branch" --repo "$repo" --json number --jq '.number' 2>/dev/null
}

codacy_pr_coverage_status_json() {
  local repo pr_number
  repo="$1"
  pr_number="$2"
  local owner name url
  owner="${repo%%/*}"
  name="${repo#*/}"
  url="https://app.codacy.com/api/v3/analysis/organizations/gh/${owner}/repositories/${name}/pull-requests/${pr_number}/coverage/status"
  curl -fsSL "$url"
}

extract_codacy_common_ancestor() {
  local status_json
  status_json="$1"
  if [[ -z "$status_json" ]]; then
    return 0
  fi

  python3 - "$status_json" <<'PY' 2>/dev/null || true
import json
import sys

data = json.loads(sys.argv[1])
ancestor = data["data"]["commonAncestorCommit"]
sha = ancestor.get("commitSha")
processed_reports = [r for r in ancestor.get("reports", []) if r.get("status") == "Processed"]
if sha and processed_reports:
    print(sha)
PY
}

find_successful_main_run_id() {
  local repo target_sha owner name page tmp_json run_id page_size
  repo="$1"
  target_sha="$2"
  owner="${repo%%/*}"
  name="${repo#*/}"
  page_size=100

  for page in $(seq 1 20); do
    tmp_json="$tmp_dir/codacy-main-runs-page-${page}.json"
    gh api "/repos/${owner}/${name}/actions/workflows/codacy-coverage.yml/runs?branch=main&event=push&status=completed&per_page=${page_size}&page=${page}" >"$tmp_json"

    run_id="$(python3 - "$tmp_json" "$target_sha" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
target_sha = sys.argv[2]
for run in payload.get("workflow_runs", []):
    if run.get("conclusion") == "success" and run.get("head_sha") == target_sha:
        print(run["id"])
        break
PY
)"
    if [[ -n "$run_id" ]]; then
      printf '%s\n' "$run_id"
      return 0
    fi

    if [[ "$(python3 - "$tmp_json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
print(len(payload.get("workflow_runs", [])))
PY
)" -lt "$page_size" ]]; then
      break
    fi
  done

  return 1
}

download_main_commit_artifacts() {
  local repo target_sha run_id found_go found_rust
  repo="$1"
  target_sha="$2"

  run_id="$(find_successful_main_run_id "$repo" "$target_sha" || true)"
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
merge_base="$(git -C "$repo_root" merge-base HEAD "$base_ref")"
current_head="$(git -C "$repo_root" rev-parse HEAD)"
target_baseline_sha="$merge_base"
pr_number="$(detect_pr_number || true)"
repo=""
codacy_status_json=""

if [[ -n "$pr_number" ]]; then
  repo="$(detect_repo)"
  if [[ -z "$repo" ]]; then
    echo "FAIL: could not determine GitHub repository for PR parity check" >&2
    exit 1
  fi
  codacy_status_json="$(codacy_pr_coverage_status_json "$repo" "$pr_number" || true)"
  codacy_ancestor="$(extract_codacy_common_ancestor "$codacy_status_json")"
  if [[ -n "$codacy_ancestor" ]]; then
    target_baseline_sha="$codacy_ancestor"
    echo "Codacy PR #$pr_number common ancestor baseline: $target_baseline_sha" >&2
  else
    echo "Codacy PR #$pr_number baseline unavailable; falling back to local merge-base $merge_base" >&2
  fi
fi

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "Codacy variation parity"
  echo "  mode:           local metadata parity"
  echo "  local merge-base: $merge_base"
  if [[ -z "$pr_number" ]]; then
    echo "  open PR:        none"
    echo "PASS: no open PR; external Codacy parity will be checked in CI once a PR exists"
    exit 0
  fi

  remote_pr_head="$(github_pr_head_sha "$repo" "$pr_number" || true)"
  if [[ -z "$codacy_status_json" ]]; then
    echo "  codacy ancestor: unavailable"
    echo "  github PR head:  ${remote_pr_head:-missing}"
    echo "PASS: Codacy metadata unavailable; local merge-base fallback remains $merge_base"
    exit 0
  fi
  local_head_ahead=0
  if [[ -n "$remote_pr_head" ]] && git -C "$repo_root" merge-base --is-ancestor "$remote_pr_head" "$current_head" 2>/dev/null; then
    local_head_ahead=1
  fi
  python3 - "$codacy_status_json" "$merge_base" "$remote_pr_head" "$current_head" "$local_head_ahead" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])
local_merge_base = sys.argv[2]
remote_pr_head = sys.argv[3]
local_head = sys.argv[4]
local_head_ahead = sys.argv[5] == "1"
ancestor = data["data"]["commonAncestorCommit"]
head = data["data"]["headCommit"]
ancestor_sha = ancestor.get("commitSha")
head_sha = head.get("commitSha")
ancestor_reports = ancestor.get("reports", [])
head_reports = head.get("reports", [])

print(f"  codacy ancestor: {ancestor_sha or 'missing'}")
print(f"  github PR head:  {remote_pr_head or 'missing'}")
print(f"  codacy PR head:  {head_sha or 'missing'}")
print(f"  ancestor reports processed: {sum(1 for r in ancestor_reports if r.get('status') == 'Processed')}")
print(f"  head reports processed:     {sum(1 for r in head_reports if r.get('status') == 'Processed')}")

if remote_pr_head and local_head and remote_pr_head != local_head and local_head_ahead:
    print(
        f"PASS: local HEAD {local_head} is ahead of GitHub PR head {remote_pr_head}; "
        "Codacy ancestor still reflects the published head and will be revalidated after push"
    )
    raise SystemExit(0)
if not ancestor_sha:
    print("FAIL: Codacy did not return a common ancestor baseline", file=sys.stderr)
    raise SystemExit(1)
if ancestor_sha != local_merge_base:
    print(
        f"FAIL: local merge-base {local_merge_base} differs from Codacy common ancestor {ancestor_sha}",
        file=sys.stderr,
    )
    raise SystemExit(1)
print("PASS: Codacy baseline matches local merge-base")
PY
  exit 0
fi

require_gh
repo="${repo:-$(detect_repo)}"
if [[ -z "$repo" ]]; then
  echo "FAIL: could not determine GitHub repository for CI parity check" >&2
  exit 1
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
