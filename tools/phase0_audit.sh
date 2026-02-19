#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() { echo "❌ $*" >&2; exit 1; }
ok()   { echo "✅ $*"; }
warn() { echo "⚠️  $*" >&2; }

echo "== Phase-0 audit (spec ↔ Go ↔ tests) =="

# Cleanup temp files (best-effort).
TMPFILES=()
cleanup() {
  for f in "${TMPFILES[@]:-}"; do
    rm -f "$f" 2>/dev/null || true
  done
}
trap cleanup EXIT

# ---- 0) Required files / structure ----
[[ -f "spec/RUBIN_L1_CANONICAL_v1.1.md" ]] || fail "Missing spec/RUBIN_L1_CANONICAL_v1.1.md"
[[ -f "clients/go/go.mod" ]] || fail "Missing clients/go/go.mod"
[[ -f "clients/go/go.sum" ]] || fail "Missing clients/go/go.sum"
[[ -f ".gitignore" ]] || warn "No .gitignore in repo root (you said it exists — check path)"
[[ -f ".env.example" ]] || warn "No .env.example in repo root (ok if not needed, but you said it exists)"

ok "Base files present"

# ---- 1) Phase-0 semantic anchors: spec ↔ code must mention HTLC_V2 + DEPLOYMENT gate ----
if ! grep -q "CORE_HTLC_V2" "spec/RUBIN_L1_CANONICAL_v1.1.md"; then
  fail "Spec does not mention CORE_HTLC_V2 (Phase-0 requires it to be specified even if inactive)"
fi
if ! grep -q "TX_ERR_DEPLOYMENT_INACTIVE" "spec/RUBIN_L1_CANONICAL_v1.1.md"; then
  warn "Spec does not mention TX_ERR_DEPLOYMENT_INACTIVE explicitly (verify codes around deployments)"
fi

if ! grep -R -n "CORE_HTLC_V2" "clients/go" >/dev/null; then
  fail "Go code does not contain CORE_HTLC_V2"
fi
if ! grep -R -n "TX_ERR_DEPLOYMENT_INACTIVE" "clients/go" >/dev/null; then
  fail "Go code does not reference TX_ERR_DEPLOYMENT_INACTIVE"
fi

ok "Spec/Go contain HTLC_V2 + deployment-inactive error token (existence check)"

# ---- 2) Go module hygiene ----
(
  cd clients/go
  ok "Go: go mod tidy check"
  go mod tidy
  if ! git diff --exit-code -- go.mod go.sum >/dev/null; then
    fail "go mod tidy created diff in go.mod/go.sum"
  fi

  ok "Go: gofmt check"
  if [[ -n "$(gofmt -l .)" ]]; then
    echo "Files needing gofmt:"
    gofmt -l .
    fail "gofmt needed"
  fi

  ok "Go: unit tests"
  go test ./... -count=1

  # Phase-0 is consensus correctness. Do not couple the phase-0 gate to CLI/node/crypto package coverage.
  ok "Go: consensus coverage"
  rm -f coverage_consensus.out coverage_consensus.txt
  go test ./consensus -count=1 -coverprofile=coverage_consensus.out -covermode=atomic
  go tool cover -func=coverage_consensus.out | tee coverage_consensus.txt

  TOTAL_LINE_RAW="$(go tool cover -func=coverage_consensus.out | tail -n 1)"
  TOTAL_LINE="$(printf '%s' "$TOTAL_LINE_RAW" | grep -Eo '[0-9]+([.][0-9]+)?%' | tail -n 1 | tr -d '%')"
  if [[ -z "${TOTAL_LINE}" ]] || ! printf '%s' "${TOTAL_LINE}" | grep -Eq '^[0-9]+([.][0-9]+)?$'; then
    fail "Failed to parse consensus coverage percentage from: ${TOTAL_LINE_RAW}"
  fi
  awk -v x="$TOTAL_LINE" 'BEGIN{ if (x+0 < 70.0) exit 1; }' || fail "Consensus coverage < 70% (raise threshold per Phase-0 target)"
)

# ---- 3) Optional security/static analysis ----
if command -v golangci-lint >/dev/null 2>&1; then
  (cd clients/go && ok "golangci-lint" && golangci-lint run ./... )
else
  warn "golangci-lint not installed (skip)"
fi

if command -v govulncheck >/dev/null 2>&1; then
  (cd clients/go && ok "govulncheck" && govulncheck ./... )
else
  warn "govulncheck not installed (skip)"
fi

if command -v gosec >/dev/null 2>&1; then
  (
    cd clients/go
    ok "gosec"
    set +e
    gosec ./...
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      warn "gosec reported issues (non-blocking in Phase-0 audit); fix or suppress explicitly before production"
    fi
  )
else
  warn "gosec not installed (skip)"
fi

if command -v semgrep >/dev/null 2>&1; then
  ok "semgrep"
  SEMGREP_LOG="$(mktemp -t rubin-phase0-semgrep.XXXXXX.log)"
  TMPFILES+=("$SEMGREP_LOG")
  if ! semgrep --config p/ci --config p/security-audit --config p/secrets . >"$SEMGREP_LOG" 2>&1; then
    if grep -E -q "HTTP 401|connection error|failed to download" "$SEMGREP_LOG"; then
      warn "semgrep remote config fetch failed (no network / 401), fallback to local config tools/semgrep_phase0_local.yml"
      set +e
      semgrep --config tools/semgrep_phase0_local.yml .
      semgrep_exit=$?
      set -e
      if [[ $semgrep_exit -ne 0 ]]; then
        warn "semgrep local config returned exit=$semgrep_exit (findings present); Phase-0 audit does not fail on this by default"
      fi
    else
      cat "$SEMGREP_LOG"
      fail "semgrep failed for unexpected reason"
    fi
  fi
else
  warn "semgrep not installed (skip)"
fi

# ---- 4) Conformance presence checks (name-agnostic) ----
if [[ -d "conformance" ]]; then
  ok "Conformance dir exists"
  echo "Conformance YAML files:"
  find conformance -maxdepth 2 -type f \( -name "*.yml" -o -name "*.yaml" \) -print | sed 's|^|  - |'
  if ! grep -R -i -n "HTLC" conformance >/dev/null 2>&1; then
    warn "No 'HTLC' token found in conformance directory (verify you have CV-HTLC-V2 vectors)"
  fi
else
  warn "No conformance/ directory found (Phase-0 usually requires it)"
fi

# ---- 5) Lean/formal (если есть в монорепо) ----
if [[ -f "formal/lakefile.lean" ]] || [[ -f "lakefile.lean" ]]; then
  if command -v lake >/dev/null 2>&1; then
    ok "Lean: lake build"
    lake build
  else
    warn "lake not installed (skip Lean build)"
  fi
fi

ok "Phase-0 audit finished"
