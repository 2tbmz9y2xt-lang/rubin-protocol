#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
repo_root="$(cd "$repo_root" && pwd)"
go_cover_out="${GO_COVER_OUT:-$repo_root/clients/go/coverage.out}"
rust_lcov_out="${RUST_LCOV_OUT:-$repo_root/clients/rust/lcov.info}"
rust_lcov_dir="$(dirname "$rust_lcov_out")"

mkdir -p "$(dirname "$go_cover_out")" "$rust_lcov_dir"
rm -f "$go_cover_out" "$rust_lcov_out" "$rust_lcov_dir/lcov.info"

run_go_coverage() {
  if [[ "${RUBIN_SKIP_GO:-0}" = "1" ]]; then
    # Caller (typically local-codacy-coverage-check.sh on HEAD when there
    # are no Go file diffs vs base) asked us to skip running `go test`.
    # Emit a valid-but-empty Go cover file so downstream consumers don't
    # bail on parse errors. After both runs, the orchestrator overlays the
    # HEAD artifact with the BASE artifact so head==base for Go (delta=0);
    # that base artifact may be real coverage or an empty placeholder,
    # depending on the skip settings used for the base run.
    printf 'mode: set\n' > "$go_cover_out"
    echo "go coverage: SKIPPED (RUBIN_SKIP_GO=1) — empty placeholder at $go_cover_out"
    return 0
  fi
  cd "$repo_root/clients/go"
  # Keep the Codacy gate scoped to runtime libraries plus the entrypoints
  # added in the devnet RPC track. Unrelated cmd/* tools stay out of scope.
  pkgs="$(
    {
      go list ./... | grep -v '/cmd/'
      printf '%s\n' ./cmd/rubin-node ./cmd/rubin-txgen
    } | sort -u
  )"
  # shellcheck disable=SC2086
  go test -coverprofile="$go_cover_out" $pkgs
}

run_rust_coverage() {
  if [[ "${RUBIN_SKIP_RUST:-0}" = "1" ]]; then
    # Symmetric to RUBIN_SKIP_GO: minimal valid lcov placeholder.
    printf 'TN:\nend_of_record\n' > "$rust_lcov_out"
    echo "rust lcov: SKIPPED (RUBIN_SKIP_RUST=1) — empty placeholder at $rust_lcov_out"
    return 0
  fi
  cd "$repo_root/clients/rust"
  cargo tarpaulin --workspace \
    --exclude rubin-consensus-cli \
    --exclude-files crates/rubin-node/src/lib.rs \
    --exclude-files crates/rubin-node/src/blockstore.rs \
    --exclude-files crates/rubin-node/src/chainstate.rs \
    --exclude-files crates/rubin-node/src/coinbase.rs \
    --exclude-files crates/rubin-node/src/genesis.rs \
    --exclude-files crates/rubin-node/src/io_utils.rs \
    --exclude-files crates/rubin-node/src/main.rs \
    --exclude-files crates/rubin-node/src/p2p_runtime.rs \
    --exclude-files crates/rubin-node/src/sync.rs \
    --exclude-files crates/rubin-node/src/bin/* \
    --exclude-files crates/rubin-consensus-cli/src/* \
    --out Lcov \
    --output-dir "$rust_lcov_dir"
}

run_go_coverage &
go_pid=$!
run_rust_coverage &
rust_pid=$!

go_rc=0
rust_rc=0
wait "$go_pid" || go_rc=$?
wait "$rust_pid" || rust_rc=$?

if [[ "$go_rc" -ne 0 || "$rust_rc" -ne 0 ]]; then
  if [[ "$go_rc" -ne 0 ]]; then
    echo "Go coverage failed with exit code $go_rc" >&2
  fi
  if [[ "$rust_rc" -ne 0 ]]; then
    echo "Rust coverage failed with exit code $rust_rc" >&2
  fi
  exit 1
fi

# Tarpaulin always writes to $rust_lcov_dir/lcov.info; rename to caller's
# requested path. Skip when RUBIN_SKIP_RUST=1 (placeholder already at
# $rust_lcov_out, no tarpaulin output to rename).
if [[ "${RUBIN_SKIP_RUST:-0}" != "1" && "$rust_lcov_dir/lcov.info" != "$rust_lcov_out" ]]; then
  mv "$rust_lcov_dir/lcov.info" "$rust_lcov_out"
fi

echo "go coverage: $go_cover_out"
echo "rust lcov: $rust_lcov_out"
