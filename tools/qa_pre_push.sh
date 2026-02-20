#!/usr/bin/env bash
set -euo pipefail

# QA gate to run before pushing. Designed to catch:
# - formatting/lint errors
# - failing unit tests
# - conformance regressions
# - accidental tracked artifacts and conflict markers
#
# Usage:
#   tools/qa_pre_push.sh            # default (fast enough, still strict)
#   RUBIN_QA_FULL=1 tools/qa_pre_push.sh   # includes npm/spec tooling and semgrep-auto

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FULL="${RUBIN_QA_FULL:-0}"

fail() {
  echo "QA-PRE-PUSH: FAIL: $*" >&2
  exit 1
}

section() {
  echo
  echo "== $* =="
}

section "Repo Sanity"

# Unresolved merge conflicts / patch whitespace errors
if rg -n "^(<<<<<<<|=======|>>>>>>>)" -S . >/dev/null 2>&1; then
  rg -n "^(<<<<<<<|=======|>>>>>>>)" -S . >&2 || true
  fail "conflict markers found"
fi

git diff --check >/dev/null || fail "git diff --check failed (whitespace/conflict artifacts)"

section "Tracked Artifact Guard"

# Guard: these must never be committed (tracked) to the repo.
for pat in \
  ".claude/" \
  ".codex/" \
  "node_modules/" \
  "analysis/" \
  "clients/go/target/" \
  "clients/rust/target/" \
  "target-validator/" \
  "target-validator-tests/" \
; do
  if git ls-files "$pat" | rg -n "." >/dev/null 2>&1; then
    echo "Tracked files under forbidden path: $pat" >&2
    git ls-files "$pat" >&2 || true
    fail "forbidden tracked artifacts detected"
  fi
done

# Guard: known output artifacts that sometimes get accidentally committed.
for pat in \
  "**/coverage*.out" \
  "**/coverage*.txt" \
  "**/gosec_output.json" \
  "**/semgrep_output.json" \
  "**/cargo_audit.json" \
; do
  if git ls-files "$pat" | rg -n "." >/dev/null 2>&1; then
    echo "Tracked forbidden artifact pattern: $pat" >&2
    git ls-files "$pat" >&2 || true
    fail "forbidden tracked artifacts detected"
  fi
done

section "Go Format + Tests"

test -z "$(gofmt -l clients/go | tee /dev/stderr)" || fail "gofmt check failed"
(cd clients/go && go test ./... ) || fail "go test failed"
(cd clients/go && go test -tags wolfcrypt_dylib ./... ) || fail "go test (wolfcrypt_dylib) failed"

section "Rust Format + Tests"

cargo fmt --manifest-path clients/rust/Cargo.toml --all -- --check || fail "cargo fmt --check failed"
cargo test --manifest-path clients/rust/Cargo.toml -q || fail "cargo test failed"

section "Conformance"

python3 conformance/runner/run_cv_bundle.py || fail "conformance bundle failed"

if [[ "$FULL" == "1" ]]; then
  section "Spec Tooling (FULL)"
  npm ci || fail "npm ci failed"
  npm run -s spec:all || fail "npm run spec:all failed"

  section "Semgrep SAST (FULL)"
  # In CI we use semgrep --config=auto; locally this is optional because it can be slow/noisy.
  python3 -m pip install semgrep --quiet || fail "pip install semgrep failed"
  semgrep scan --config=auto --error \
    clients/go clients/rust/crates conformance/runner \
    --exclude='*.lock' --exclude='target/' 2>&1 || fail "semgrep failed"
fi

section "OK"
echo "QA-PRE-PUSH: PASS"

