#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_ref="${1:-origin/main}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/rubin-codacy-preflight.XXXXXX")"
base_worktree="$tmp_dir/base"
head_go="$tmp_dir/head-go.coverage.out"
head_rust="$tmp_dir/head-rust.lcov.info"
base_go="$tmp_dir/base-go.coverage.out"
base_rust="$tmp_dir/base-rust.lcov.info"

cleanup() {
  git -C "$repo_root" worktree remove --force "$base_worktree" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

git -C "$repo_root" fetch origin
merge_base="$(git -C "$repo_root" merge-base HEAD "$base_ref")"
git -C "$repo_root" worktree add --detach "$base_worktree" "$merge_base" >/dev/null

echo "Generating head coverage against $(git -C "$repo_root" rev-parse --short HEAD)"
GO_COVER_OUT="$head_go" \
RUST_LCOV_OUT="$head_rust" \
"$repo_root/scripts/dev-env.sh" -- \
"$repo_root/scripts/run-codacy-coverage.sh" "$repo_root"

echo "Generating base coverage against $(git -C "$repo_root" rev-parse --short "$merge_base")"
GO_COVER_OUT="$base_go" \
RUST_LCOV_OUT="$base_rust" \
"$base_worktree/scripts/dev-env.sh" -- \
"$repo_root/scripts/run-codacy-coverage.sh" "$base_worktree"

python3 "$repo_root/tools/check_codacy_coverage.py" \
  --repo-root "$repo_root" \
  --base-ref "$merge_base" \
  --base-go "$base_go" \
  --base-rust "$base_rust" \
  --head-go "$head_go" \
  --head-rust "$head_rust"
