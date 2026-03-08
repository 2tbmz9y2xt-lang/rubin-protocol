#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
repo_root="$(cd "$repo_root" && pwd)"
go_cover_out="${GO_COVER_OUT:-$repo_root/clients/go/coverage.out}"
rust_lcov_out="${RUST_LCOV_OUT:-$repo_root/clients/rust/lcov.info}"
rust_lcov_dir="$(dirname "$rust_lcov_out")"

mkdir -p "$(dirname "$go_cover_out")" "$rust_lcov_dir"
rm -f "$go_cover_out" "$rust_lcov_out" "$rust_lcov_dir/lcov.info"

(
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
)

(
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
)

if [[ "$rust_lcov_dir/lcov.info" != "$rust_lcov_out" ]]; then
  mv "$rust_lcov_dir/lcov.info" "$rust_lcov_out"
fi

echo "go coverage: $go_cover_out"
echo "rust lcov: $rust_lcov_out"
