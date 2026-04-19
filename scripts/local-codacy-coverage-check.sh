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

# Per-language skip detection: if HEAD has no diff vs merge_base in a
# language, skip running its test suite on HEAD (we'll copy the base file
# in as the head file after base coverage runs, so the comparator sees
# delta=0 for that language). This keeps Rust-only PRs from paying the
# cost of (and getting blocked by flakes in) the Go integration suite,
# and vice-versa. Honor explicit force-overrides.
#
# IMPORTANT: auto-skip is gated on `GITHUB_ACTIONS != "true"` so it only
# fires for LOCAL preflight runs. In CI (`codacy-coverage.yml`), the
# generated head artifacts (`clients/go/coverage.out`, `clients/rust/lcov.info`)
# are also consumed by the downstream "Upload to Codacy" step — we MUST
# NOT overlay them with base data, or Codacy receives stale/placeholder
# coverage and reports the wrong PR delta on its own dashboard. CI runs
# the full suite end-to-end on every push (no local-flake exposure
# anyway), so the skip provides no value there. To force-skip in CI for
# debugging, set `RUBIN_FORCE_SKIP_IN_CI=1` explicitly.
head_skip_go=0
head_skip_rust=0
auto_skip_eligible=1
if [[ "${GITHUB_ACTIONS:-}" == "true" && "${RUBIN_FORCE_SKIP_IN_CI:-0}" != "1" ]]; then
  auto_skip_eligible=0
  echo "Auto-skip: disabled in CI (GITHUB_ACTIONS=true) so HEAD coverage artifacts stay authoritative for Codacy upload"
fi
if [[ "$auto_skip_eligible" = "1" ]]; then
  # Capture diff output AND exit status separately so a failing `git diff`
  # (bad ref, unsupported pathspec, lstat failure, etc.) is NOT silently
  # interpreted as "no diff → skip". Without this, the previous form
  # `if ! git diff ... | grep -q .` was fail-open: pipefail isn't set
  # in this shell context, the pipeline drops `git diff`'s exit code,
  # and a git-level error reads as empty output → skip.
  #
  # Pathspecs use plain directory shape (`clients/go/`, `clients/rust/`)
  # rather than `clients/go/**`: directory pathspecs reliably match
  # every file under the tree across all supported git versions and
  # also catch non-`.go`/non-`.rs` content under the same tree (e.g.
  # embedded JSON fixtures like `live_binding_policy_v1_embedded.json`).
  if [[ "${RUBIN_FORCE_GO_COVERAGE:-0}" != "1" ]]; then
    set +e
    go_diff_output="$(git -C "$repo_root" diff --name-only "$merge_base" HEAD -- '*.go' 'clients/go/' 2>&1)"
    go_diff_rc=$?
    set -e
    if [[ "$go_diff_rc" -ne 0 ]]; then
      echo "Error: failed to compute Go diff against $merge_base (rc=$go_diff_rc):" >&2
      echo "$go_diff_output" >&2
      echo "Refusing to silently skip Go coverage; aborting." >&2
      exit 1
    fi
    if [[ -z "$go_diff_output" ]]; then
      head_skip_go=1
    fi
  fi
  if [[ "${RUBIN_FORCE_RUST_COVERAGE:-0}" != "1" ]]; then
    set +e
    rust_diff_output="$(git -C "$repo_root" diff --name-only "$merge_base" HEAD -- '*.rs' 'clients/rust/' 2>&1)"
    rust_diff_rc=$?
    set -e
    if [[ "$rust_diff_rc" -ne 0 ]]; then
      echo "Error: failed to compute Rust diff against $merge_base (rc=$rust_diff_rc):" >&2
      echo "$rust_diff_output" >&2
      echo "Refusing to silently skip Rust coverage; aborting." >&2
      exit 1
    fi
    if [[ -z "$rust_diff_output" ]]; then
      head_skip_rust=1
    fi
  fi
fi
if [[ "$head_skip_go" = "1" ]]; then
  echo "Auto-skip: HEAD has no Go diff vs $merge_base — skipping Go coverage on HEAD (use RUBIN_FORCE_GO_COVERAGE=1 to override)"
fi
if [[ "$head_skip_rust" = "1" ]]; then
  echo "Auto-skip: HEAD has no Rust diff vs $merge_base — skipping Rust coverage on HEAD (use RUBIN_FORCE_RUST_COVERAGE=1 to override)"
fi

if [[ -n "$head_coverage_sha" && "$head_coverage_sha" == "$current_head" && -s "$head_go" && -s "$head_rust" ]]; then
  echo "Reusing existing head coverage artifacts from current workspace"
else
  if [[ -n "$head_coverage_sha" && "$head_coverage_sha" != "$current_head" ]]; then
    echo "Ignoring stale head coverage artifacts: expected $current_head, got $head_coverage_sha"
  fi
  echo "Generating head coverage against $(git -C "$repo_root" rev-parse --short "$current_head")"
  GO_COVER_OUT="$head_go" \
  RUST_LCOV_OUT="$head_rust" \
  RUBIN_SKIP_GO="$head_skip_go" \
  RUBIN_SKIP_RUST="$head_skip_rust" \
  "$repo_root/scripts/dev-env.sh" -- \
  "$repo_root/scripts/run-codacy-coverage.sh" "$repo_root"
fi

if [[ "${GITHUB_ACTIONS:-}" == "true" ]] && download_base_coverage_from_artifacts "$merge_base"; then
  echo "Baseline coverage restored from GitHub artifacts for $(git -C "$repo_root" rev-parse --short "$merge_base")"
else
  git -C "$repo_root" worktree add --detach "$base_worktree" "$merge_base" >/dev/null
  echo "Generating base coverage against $(git -C "$repo_root" rev-parse --short "$merge_base")"
  # Symmetric per-lang skip on the BASE worktree: if HEAD has no diff in
  # a language, base coverage for that language is identical to head (no
  # change in that language). Skip the language to avoid running its
  # (potentially flaky) test suite on the base side too — the head-side
  # placeholder is then overlay-copied from the base placeholder so the
  # comparator sees delta=0 for the skipped language.
  #
  # Trade-off vs Codacy upstream gate (per Codex P1, 2026-04-19):
  # both base and head exclude the skipped language's lines from totals,
  # so absolute coverage % differs from Codacy's measurement. Variation
  # math (per-language delta) still resolves to 0 for the skipped
  # language and to the real measurement for the changed language; diff
  # coverage gate (≥85%) still fires on the changed language's actual
  # changed lines. Override per-PR with RUBIN_FORCE_<LANG>_COVERAGE=1
  # if you suspect a totals-vs-Codacy divergence in your specific case.
  #
  # The base worktree is checked out at merge_base, which may be from
  # before the per-lang skip patch landed — so we COPY the patched
  # scripts into the base worktree before running.
  cp "$repo_root/scripts/run-codacy-coverage.sh" "$base_worktree/scripts/run-codacy-coverage.sh"
  cp "$repo_root/scripts/local-codacy-coverage-check.sh" "$base_worktree/scripts/local-codacy-coverage-check.sh"
  GO_COVER_OUT="$base_go" \
  RUST_LCOV_OUT="$base_rust" \
  RUBIN_SKIP_GO="$head_skip_go" \
  RUBIN_SKIP_RUST="$head_skip_rust" \
  "$base_worktree/scripts/dev-env.sh" -- \
  "$base_worktree/scripts/run-codacy-coverage.sh" "$base_worktree"
fi

# Per-language skip overlay: if HEAD coverage was skipped for a
# language, copy the base file in as the head file so the comparator
# sees identical base/head for that language (delta=0). This must run
# AFTER both base and head coverage generation. The check still
# validates the language that DID change against its real measurements.
if [[ "$head_skip_go" = "1" ]]; then
  cp "$base_go" "$head_go"
  echo "Per-lang skip overlay: head Go coverage = base Go coverage (delta=0)"
fi
if [[ "$head_skip_rust" = "1" ]]; then
  cp "$base_rust" "$head_rust"
  echo "Per-lang skip overlay: head Rust coverage = base Rust coverage (delta=0)"
fi

python3 "$repo_root/tools/check_codacy_coverage.py" \
  --repo-root "$repo_root" \
  --base-ref "$merge_base" \
  --base-go "$base_go" \
  --base-rust "$base_rust" \
  --head-go "$head_go" \
  --head-rust "$head_rust"
